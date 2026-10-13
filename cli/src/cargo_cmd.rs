use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::time::Instant;

use async_process::{Command, ExitStatus};
use futures_util::future::{BoxFuture, FutureExt as _, Shared};
use serde::{Deserialize, Serialize};
use stow_types::artifact::{ArtifactKind, RustCrateType};
use stow_types::bundle::{STOW_PROC_MACRO_MEDIA_TYPE, STOW_RLIB_MEDIA_TYPE, STOW_RMETA_MEDIA_TYPE};
use stow_types::error::Context;
use stow_types::platform::{PanicStrategy, Profile};
use stow_types::public_cache::UnitShape;
use tempfile::TempDir;
use zenwave::{Client, ResponseExt};

use crate::budget::CacheBudget;
use crate::cache_policy::{self, CachePolicyEntry};
use crate::cli_args::CargoCommandArgs;
use crate::config::StowConfig;
use crate::fetch::{FetchRequest, SemanticFetchRequest};
use crate::index;
use crate::inject;
use crate::lockfile_resolver;
use crate::log_nonfatal_result;
use crate::prefetch::{self, PrefetchArtifact};
use crate::resolve;
use crate::rustc_args::{self, STOW_PUBLIC_CACHE_RUSTC_VERSION_ENV, STOW_PUBLIC_CACHE_TARGET_ENV};
use crate::state_db::StateDb;
use crate::stats;
use crate::workspace_deps::{
    self, ExpandedDependencyGraph, PackageKey, SelectedRegistryDependency,
};
use crate::{
    STOW_ENABLE_SEMANTIC_FALLBACK_ENV, STOW_EXPANDED_GRAPH_PATH_ENV,
    STOW_PREFETCH_ARTIFACTS_PATH_ENV,
};
use crate::{detect_wrapper_commands, write_stdout};
use stow_types::api::{
    AdmissionRequest, DependencyGraphEntry, EnqueueAdmission, ResolvedDependencyGraphEntry,
};
use stow_types::versioning::is_semver_compatible_upgrade;
use tracing::Instrument as _;

#[tracing::instrument(name = "stow.cargo_cmd.run", skip_all, fields(cargo_command = command))]
pub async fn run(
    command: &str,
    args: CargoCommandArgs,
    state_db: &StateDb,
) -> stow_types::error::Result<ExitStatus> {
    Box::pin(run_inner(command, args, state_db)).await
}

/// mold is mandatory on Linux — provisioning starts the moment the
/// project's target is known and its linker probes run alongside the
/// graph analysis in `run_inner` rather than in front of it (stow#347).
/// The selection resolves before any cargo invocation, whatever path
/// the build ends up taking through this driver. `check` is gated with
/// `build` and `test`: a check still compiles proc-macro dependencies
/// in full and compiles and runs build scripts, and both of those
/// link. When the cargo config does not already select a reachable
/// mold, the managed install is selected for this invocation only —
/// `stow setup` is not required.
fn mold_provision(
    pending: &PendingProjectContext,
    config: Option<&StowConfig>,
) -> impl std::future::Future<Output = stow_types::error::Result<Vec<String>>> + Send + 'static {
    let target = pending.target.clone();
    // The target cargo was given — `--target` or `CARGO_BUILD_TARGET`
    // or `build.target` — decides whether this build links for the
    // host at all (stow#551).
    let explicit_target = pending.resolved_target.clone();
    let dir = pending.current_dir.clone();
    let config = config.cloned();
    let rustc_vv = pending.rustc_vv.clone();
    let cargo_config = pending.cargo_config.clone();
    let build_rustc = pending.build_rustc.clone();
    async move {
        crate::mold::provision(
            target,
            explicit_target.as_deref(),
            &dir,
            config.as_ref(),
            &rustc_vv,
            cargo_config,
            &build_rustc,
        )
        .instrument(tracing::debug_span!("stow.precargo.mold_provision"))
        .await
    }
}

/// The selection a real build carries: provisioning runs beside the
/// rest of the pre-cargo work exactly as it always has (stow#653).
fn spawn_mold_provision(
    pending: &PendingProjectContext,
    config: Option<&StowConfig>,
) -> MoldSelection {
    MoldSelection::started(mold_provision(pending, config))
}

/// The selection a context that assembles no cargo build carries —
/// provisioning with no reader is work nothing consumes (stow#653).
fn defer_mold_provision(pending: &PendingProjectContext) -> MoldSelection {
    MoldSelection::deferred(mold_provision(pending, None))
}

/// The invocation's stow config, if one is configured — with the state
/// DB pool's open already started beside whatever runs next: the pool
/// opens lazily and its first query is the lite analysis's
/// expanded-graph read, so connecting now keeps it off the cargo spawn's
/// critical path (stow#517). The open goes through the process's handle,
/// so the close at the end of the command waits for it (stow#682).
fn load_stow_config(state_db: &StateDb) -> Option<StowConfig> {
    let config = match StowConfig::load(state_db.clone()) {
        Ok(config) => config,
        Err(error) => {
            tracing::debug!(%error, "stow config unavailable, skipping graph analysis");
            return None;
        }
    };
    let state_db = state_db.clone();
    let cache_dir = config.cache_dir.clone();
    tokio::spawn(async move {
        let _ = state_db.pool(&cache_dir).await;
    });
    Some(config)
}

/// The provisioning behind a [`MoldSelection`], shaped like
/// [`SharedEnvBase`]: `Shared` so every clone of the context awaits
/// the one resolution (stow#653).
type MoldProvision =
    Shared<BoxFuture<'static, Result<std::sync::Arc<[String]>, std::sync::Arc<String>>>>;

/// The cargo `--config` values a build needs so its Linux units link
/// with mold, still being resolved: the only way to read them is to
/// await the provisioning, so no cargo build can be assembled before
/// it has finished (stow#653). `Shared`, so a cloned `ProjectContext`
/// — a mirror build — awaits the one resolution.
#[derive(Clone)]
pub struct MoldSelection(MoldProvision);

impl std::fmt::Debug for MoldSelection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MoldSelection")
    }
}

impl MoldSelection {
    /// Provisioning spawned beside the rest of the pre-cargo work, so
    /// the await in [`config_args`](Self::config_args) is a take rather
    /// than a wait. A join error and a provisioning error both surface
    /// as the `Err` every reader sees.
    fn started(
        provision: impl std::future::Future<Output = stow_types::error::Result<Vec<String>>>
        + Send
        + 'static,
    ) -> Self {
        let task = tokio::spawn(provision);
        Self(
            async move {
                match task.await {
                    Ok(args) => args
                        .map(std::sync::Arc::<[String]>::from)
                        .map_err(|error| std::sync::Arc::new(error.to_string())),
                    Err(error) => Err(std::sync::Arc::new(format!(
                        "join mold provisioning task: {error}"
                    ))),
                }
            }
            .boxed()
            .shared(),
        )
    }

    /// Provisioning that runs only when the selection is read — for a
    /// context that assembles no cargo build, where spawning it would
    /// be work nothing consumes.
    fn deferred(
        provision: impl std::future::Future<Output = stow_types::error::Result<Vec<String>>>
        + Send
        + 'static,
    ) -> Self {
        Self(
            provision
                .map(|args| {
                    args.map(std::sync::Arc::<[String]>::from)
                        .map_err(|error| std::sync::Arc::new(error.to_string()))
                })
                .boxed()
                .shared(),
        )
    }

    /// The resolved `--config` values — the await is the contract: a
    /// caller holding them has the provisioning behind it (stow#653).
    async fn config_args(&self) -> stow_types::error::Result<std::sync::Arc<[String]>> {
        self.0
            .clone()
            .await
            .map_err(|error| stow_types::stow_error!("provision mold for this build: {error}"))
    }

    /// An already-answered selection, for test fixtures — no
    /// provisioning ran and none is needed.
    #[cfg(test)]
    pub fn resolved(args: Vec<String>) -> Self {
        Self(
            futures_util::future::ready(Ok::<_, std::sync::Arc<String>>(
                std::sync::Arc::<[String]>::from(args),
            ))
            .boxed()
            .shared(),
        )
    }
}

/// The workspace layout, rustc probes, mold provisioning and the
/// supervisor env base of a build, started together so every independent
/// probe runs beside the others (stow#608). The finished context
/// carries the mold selection — still resolving — so no cargo build
/// can be assembled before it answers (stow#653).
async fn begin_project(
    config: Option<&StowConfig>,
    invocation: &CargoInvocation,
) -> stow_types::error::Result<ProjectContext> {
    let pending = tracing::debug_span!("stow.precargo.project_context")
        .in_scope(|| ProjectContext::begin(invocation))?;
    let mold = spawn_mold_provision(&pending, config);
    let env_base = spawn_env_base(config, &pending);
    let mut project = pending.finish(mold, enter_foreground_hold()).await?;
    project.env_base = env_base;
    Ok(project)
}

/// The command's claim on the package-cache lock's next holder: while
/// it is held, no miss drain starts a derivation cargo of its own, and
/// entering stops every derivation already running (stow#667). The
/// gate directory is the cargo home's, because the lock is.
async fn enter_foreground_hold() -> stow_types::error::Result<crate::derive_gate::ForegroundHold> {
    let gate_dir = crate::config::cargo_home()
        .ok_or_else(|| {
            stow_types::stow_error!(
                "resolve the cargo home — neither $CARGO_HOME nor a home directory is available"
            )
        })?
        .join("stow");
    crate::derive_gate::ForegroundHold::enter(&gate_dir).await
}

async fn run_inner(
    command: &str,
    args: CargoCommandArgs,
    state_db: &StateDb,
) -> stow_types::error::Result<ExitStatus> {
    let invocation = CargoInvocation::new(command, args);
    let config =
        tracing::debug_span!("stow.precargo.config_load").in_scope(|| load_stow_config(state_db));
    let project = begin_project(config.as_ref(), &invocation).await?;
    let public_cache_mode = PublicCacheMode::for_rustc(&project.rustc_version);
    if let PublicCacheMode::Disabled { message, .. } = &public_cache_mode {
        write_stdout(&format!("{message}\n"))?;
    }

    if let Some(status) = run_divergent_profile_passthrough(&project, &invocation)
        .instrument(tracing::debug_span!("stow.precargo.profile_guard"))
        .await?
    {
        return Ok(status);
    }

    if let Some(status) = Box::pin(try_resolver_fast_path(
        config.as_ref(),
        &project,
        &invocation,
        &public_cache_mode,
    ))
    .instrument(tracing::debug_span!("stow.precargo.resolver_fast_path"))
    .await
    {
        return Ok(status);
    }

    let maybe_analysis = analyze_or_warn(config.as_ref(), &project, &public_cache_mode)
        .instrument(tracing::debug_span!("stow.precargo.lite_analysis"))
        .await;
    if let Some(status) = run_uncovered_passthrough(
        config.as_ref(),
        &project,
        &invocation,
        maybe_analysis.as_ref(),
    )
    .instrument(tracing::debug_span!("stow.precargo.uncovered_check"))
    .await?
    {
        return Ok(status);
    }

    // Load the Sigstore trust root before the clock starts. It is a
    // one-time cost of well over a second and has nothing to do with how
    // many artifacts this build warms, so paying it inside a budget of
    // 150ms per artifact would spend the whole allowance on setup and
    // leave the fetches to the per-invocation path — which is exactly what
    // it did.
    if let Some(config) = config.as_ref()
        && maybe_analysis
            .as_ref()
            .is_some_and(|analysis| !analysis.prefetch_artifacts.is_empty())
    {
        log_nonfatal_result(
            "failed to load the sigstore trust root before prefetch",
            crate::verify::resolve_trust(config)
                .instrument(tracing::debug_span!("stow.precargo.trust_root"))
                .await
                .map(|_| ()),
        );
    }

    // One allowance for every phase between here and cargo's launch, sized by
    // the number of units the cache says it can serve. See `budget`.
    let budget = CacheBudget::for_covered_units(
        maybe_analysis
            .as_ref()
            .map_or(0, |analysis| analysis.prefetch_artifacts.len()),
    );

    let selected = select_upgrades(
        maybe_analysis.as_ref(),
        invocation.silent_compatible_upgrades,
    )
    .instrument(tracing::debug_span!("stow.precargo.select_upgrades"))
    .await?;
    if selected.is_empty() {
        run_original_workspace_build(
            config.as_ref(),
            &project,
            &invocation,
            &public_cache_mode,
            maybe_analysis,
            &budget,
            state_db,
        )
        .await
    } else {
        Box::pin(run_mirrored_upgrade_build(
            config.as_ref(),
            &project,
            &invocation,
            &public_cache_mode,
            &budget,
            &selected,
            state_db,
        ))
        .await
    }
}

/// No-slowdown floor, part 1: a workspace whose dev profile turns on LTO
/// compiles every dependency with `-C linker-plugin-lto`, which no cache
/// identity expresses, so no unit can ever hit. Detect that early, skip the
/// entire resolver/analysis/prefetch machinery, and behave exactly like
/// cargo. Every other profile knob is part of the compile identity and is
/// served when the pool holds artifacts built under it. Returns
/// `Some` with cargo's exit status when the passthrough ran.
async fn run_divergent_profile_passthrough(
    project: &ProjectContext,
    invocation: &CargoInvocation,
) -> stow_types::error::Result<Option<ExitStatus>> {
    let Some(divergence) =
        crate::profile_guard::dev_profile_divergence(&project.workspace_root).await?
    else {
        return Ok(None);
    };
    tracing::info!(
        %divergence,
        "workspace dev profile enables LTO, which no cache identity expresses; \
         running plain cargo (no acceleration possible for this workspace)"
    );
    run_cargo_passthrough(
        project,
        &invocation.action,
        &invocation.cargo_args,
        project.current_dir(),
    )
    .await
    .map(Some)
}

/// Phase 0: stow-resolver fast path. When `--no-stow-resolver` is NOT set
/// and the edge can synthesize a cache-optimized `Cargo.lock` that cargo
/// itself accepts under `--locked`, skip cargo's resolver entirely. The
/// dry-run inside `try_stow_resolver` is the correctness gate — cargo
/// rejects anything semver/features-incompatible, and we fall back to the
/// conservative "suggest `Cargo.toml` upgrades, let cargo resolve" flow.
/// Returns `Some` with cargo's exit status when the resolver path ran
/// cargo and `run` is done — `Some` even when that status is a failure.
async fn try_resolver_fast_path(
    config: Option<&StowConfig>,
    project: &ProjectContext,
    invocation: &CargoInvocation,
    public_cache_mode: &PublicCacheMode,
) -> Option<ExitStatus> {
    // The resolver path exists only where a `StowConfig` gives it a
    // cached slice to pin against, and only while the user has not opted
    // out with `--no-stow-resolver` (stow#608).
    if !public_cache_mode.is_enabled() || !invocation.use_stow_resolver {
        return None;
    }
    let config = config?;
    match Box::pin(try_stow_resolver(config, project, invocation)).await {
        Ok(served) => {
            if served.is_none() {
                tracing::info!(
                    "stow resolver could not produce a cargo-accepted lockfile; \
                     falling back to graph analysis of the workspace's own lockfile"
                );
            }
            served
        }
        Err(error) => {
            tracing::warn!(
                %error,
                "stow resolver path errored; falling back to cargo's own resolver"
            );
            None
        }
    }
}

/// Run the edge dependency-graph analysis when the public cache can serve
/// this workspace, downgrading failures to a warning because plain cargo
/// still works without it.
async fn analyze_or_warn(
    config: Option<&StowConfig>,
    project: &ProjectContext,
    public_cache_mode: &PublicCacheMode,
) -> Option<WorkspacePrediction> {
    if !public_cache_mode.is_enabled() {
        return None;
    }
    let config = config?;
    match analyze_workspace_prediction_lite(project, config).await {
        Ok(analysis) => Some(analysis),
        Err(error) => {
            tracing::warn!(
                error = %error,
                "compatible upgrade analysis failed, running original cargo command"
            );
            warn_when_no_index_covers_the_toolchain(config, project).await;
            None
        }
    }
}

/// Say so when the cache holds no index for this toolchain at all.
///
/// The index is published per target and rustc version, and a toolchain
/// one release behind the current stable has none — so the resolver finds
/// nothing, every lookup misses, and the build pays stow's overhead for no
/// possible benefit. That was silent: it looked exactly like a cache that
/// had simply covered nothing, and the only way to tell the two apart was
/// `RUST_LOG=stow_cli=debug`. A benchmark ran twice against a toolchain
/// with no index before anyone noticed.
async fn warn_when_no_index_covers_the_toolchain(config: &StowConfig, project: &ProjectContext) {
    let cached = index::cached_slice(config, &project.target, &project.rustc_version).await;
    if matches!(cached, Ok(Some(_))) {
        return;
    }
    log_nonfatal_result(
        "failed to report the missing index slice",
        write_stdout(&format!(
            "stow: no public cache index for rustc {} on {}; nothing can be served for this build\n",
            project.rustc_version, project.target
        )),
    );
}

/// No-slowdown floor, part 2: with no cached coverage for this graph,
/// every per-rustc wrapper call would look up the same crates and miss,
/// so behave exactly like cargo — no wrapper, no per-invocation latency.
/// The exception is a configured build: the supervisor's compile
/// observations are the build's miss list, minted after cargo finishes
/// (stow#317), so the wrapper rides even when nothing is servable.
///
/// This decision belongs here and not one phase earlier. The resolver
/// answers a different question: "is there a *different*, more-cached
/// lockfile cargo would also accept?". A workspace whose own lockfile is
/// already fully covered is precisely the case where the resolver has
/// nothing to improve, so treating its empty answer as "nothing is cached"
/// turned the best case into a plain cargo run. Returns `Some` with
/// cargo's exit status when the passthrough ran.
async fn run_uncovered_passthrough(
    config: Option<&StowConfig>,
    project: &ProjectContext,
    invocation: &CargoInvocation,
    analysis: Option<&WorkspacePrediction>,
) -> stow_types::error::Result<Option<ExitStatus>> {
    if invocation.silent_compatible_upgrades
        || analysis.is_some_and(|analysis| !analysis.prefetch_artifacts.is_empty())
        || config.is_some()
    {
        // With a config the build runs under the supervisor even when
        // nothing is servable: the supervisor's compile observations are
        // the build's miss list, posted once cargo finishes (stow#317).
        return Ok(None);
    }
    tracing::info!("no cached artifacts cover this dependency graph; running plain cargo");
    run_cargo_passthrough(
        project,
        &invocation.action,
        &invocation.cargo_args,
        project.current_dir(),
    )
    .await
    .map(Some)
}

/// The no-upgrades path: cargo runs in the real workspace with the cache
/// plan the analysis produced. Returns cargo's own exit status.
async fn run_original_workspace_build(
    config: Option<&StowConfig>,
    project: &ProjectContext,
    invocation: &CargoInvocation,
    public_cache_mode: &PublicCacheMode,
    analysis: Option<WorkspacePrediction>,
    budget: &CacheBudget,
    state_db: &StateDb,
) -> stow_types::error::Result<ExitStatus> {
    let unit_nodes = analysis
        .as_ref()
        .and_then(|analysis| analysis.unit_nodes.clone());
    let prefetch_artifacts = analysis
        .as_ref()
        .map(|analysis| analysis.prefetch_artifacts.clone());
    let semantic_fallback_enabled = unit_nodes
        .as_ref()
        .is_some_and(|table| !table.nodes.is_empty());
    let servable_units = analysis
        .as_ref()
        .and_then(|analysis| analysis.servable_units.clone());
    let cache_policy_entries = deferred_cache_policy(config, public_cache_mode, analysis.as_ref());
    let prefetch_artifacts = prefetch_artifacts.as_deref();
    let covered_units = prefetch_artifacts.map_or(0, <[PrefetchArtifact]>::len);
    // The top-crate fast path pays its own graph resolve plus a
    // prefetch warm, so it only exists when the filesystem pass already
    // proved the graph servable — on an all-miss build it can only burn
    // seconds to reach the same "nothing to serve" the serve map already
    // holds (stow#347).
    let anything_servable = servable_units
        .as_ref()
        .is_some_and(|map| !map.target.is_empty() || !map.host.is_empty());
    if let Some(config) = config
        && public_cache_mode.is_enabled()
        && anything_servable
    {
        match try_run_top_crate_with_cached_dependencies(
            config,
            project,
            &invocation.action,
            &invocation.cargo_args,
            cache_policy_entries.as_deref(),
            prefetch_artifacts,
            budget,
        )
        .await
        {
            // `Some` ends the command even on a failing status — see
            // `try_run_top_crate_with_cached_dependencies`.
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    %error,
                    "stow top-crate cached-deps acceleration unavailable; falling back to vanilla cargo"
                );
            }
        }
    }
    run_cargo(&CargoRunPlan {
        project,
        config,
        state_db,
        action: &invocation.action,
        cargo_args: &invocation.cargo_args,
        source_root: &project.workspace_root,
        current_dir: project.current_dir(),
        cache_policy_entries: cache_policy_entries.as_deref(),
        public_cache_mode,
        unit_nodes: unit_nodes.as_ref(),
        prefetch_artifacts,
        servable_units: servable_units.as_ref(),
        // A configured build's facts came from the filesystem-only pass:
        // the full graph analysis is owed to the build while cargo runs.
        deferred_analysis: config.is_some(),
        semantic_fallback_enabled,
        extra_rustflags: &[],
        covered_units,
    })
    .await
}

/// The upgrades path: apply the selected upgrades inside a mirror
/// workspace, re-analyze the upgraded graph, then run cargo there.
/// Returns cargo's own exit status.
async fn run_mirrored_upgrade_build(
    config: Option<&StowConfig>,
    project: &ProjectContext,
    invocation: &CargoInvocation,
    public_cache_mode: &PublicCacheMode,
    budget: &CacheBudget,
    selected: &[CompatibleUpgrade],
    state_db: &StateDb,
) -> stow_types::error::Result<ExitStatus> {
    let mirror = create_workspace_mirror(project, &project.workspace_root).await?;
    apply_selected_upgrades(project, &mirror, selected).await?;
    let mirror_args = rewrite_args_for_mirror(&invocation.cargo_args, project, &mirror)?;
    let mirror_manifest_path = mirror_manifest_path(project, &mirror)?;

    // After applying upgrades, re-analyze the mirror so the wrapper's exact +
    // semantic paths get the post-upgrade transitive graph + prefetch list,
    // and so the strict top-crate cached-deps fast path can engage when every
    // (now-upgraded) direct dep is fully covered. Without this, the upgrade
    // branch ran the mirror with no cache plumbing and saw 0 hits — the
    // primary cause of the predict-vs-runtime gap reported on populated mocks.
    let mirror_project = build_mirror_project_context(project, &mirror)?;
    let mirror_analysis = match config {
        Some(config) => match analyze_workspace_prediction(
            &mirror_project,
            mirror_project.current_dir(),
            &mirror_project.manifest_path,
            config,
            None,
        )
        .await
        {
            Ok(analysis) => Some(analysis),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "post-upgrade mirror graph analysis failed; running cargo without prefetch"
                );
                None
            }
        },
        None => None,
    };
    let mirror_unit_nodes = mirror_analysis
        .as_ref()
        .and_then(|analysis| analysis.unit_nodes.clone());
    let mirror_prefetch = mirror_analysis
        .as_ref()
        .map(|analysis| analysis.prefetch_artifacts.clone());
    let mirror_semantic_fallback = mirror_unit_nodes
        .as_ref()
        .is_some_and(|table| !table.nodes.is_empty());
    let mirror_servable = mirror_analysis
        .as_ref()
        .and_then(|analysis| analysis.servable_units.clone());

    let cache_policy_entries = prepare_build_cache_plan(
        config,
        project,
        &mirror.current_dir(),
        &mirror_manifest_path,
        public_cache_mode,
        mirror_analysis,
        budget,
    )
    .await?;

    if let Some(config) = config
        && public_cache_mode.is_enabled()
    {
        match try_run_top_crate_with_cached_dependencies(
            config,
            &mirror_project,
            &invocation.action,
            &mirror_args,
            cache_policy_entries.as_deref(),
            mirror_prefetch.as_deref(),
            budget,
        )
        .await
        {
            // `Some` ends the command even on a failing status — see
            // `try_run_top_crate_with_cached_dependencies`.
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    %error,
                    "post-upgrade top-crate cached-deps acceleration unavailable; falling back to vanilla cargo"
                );
            }
        }
    }

    let mirror_current_dir = mirror.current_dir();
    run_cargo(&CargoRunPlan {
        project,
        config,
        state_db,
        action: &invocation.action,
        cargo_args: &mirror_args,
        source_root: mirror.root(),
        current_dir: &mirror_current_dir,
        cache_policy_entries: cache_policy_entries.as_deref(),
        public_cache_mode,
        unit_nodes: mirror_unit_nodes.as_ref(),
        prefetch_artifacts: mirror_prefetch.as_deref(),
        servable_units: mirror_servable.as_ref(),
        deferred_analysis: false,
        semantic_fallback_enabled: mirror_semantic_fallback,
        extra_rustflags: &[],
        covered_units: mirror_prefetch.as_ref().map_or(0, Vec::len),
    })
    .await
}

fn build_mirror_project_context(
    project: &ProjectContext,
    mirror: &WorkspaceMirror,
) -> stow_types::error::Result<ProjectContext> {
    let workspace_root = mirror.root().to_path_buf();
    let current_dir = mirror.current_dir();
    let manifest_path = mirror_manifest_path(project, mirror)?;
    let current_dir_relative =
        pathdiff::diff_paths(&current_dir, &workspace_root).unwrap_or_default();
    // The mirror queries the mirror's own manifest: spelled
    // `--manifest-path` (either form) rewrites to the mirror path —
    // forwarding the user's absolute path would resolve the user's
    // lockfile graph under the mirror's key (stow#551).
    let mut metadata_args = project.metadata_args.clone();
    metadata_args.manifest_path = Some(manifest_path.clone());
    Ok(ProjectContext {
        action: project.action.clone(),
        cargo_args: rewrite_args_for_mirror(&project.cargo_args, project, mirror)?,
        workspace_root,
        current_dir,
        current_dir_relative,
        manifest_path,
        metadata_args,
        target: project.target.clone(),
        target_given: project.target_given,
        rustc_version: project.rustc_version.clone(),
        mold: project.mold.clone(),
        env_base: project.env_base.clone(),
        build_rustc: project.build_rustc.clone(),
        foreground: project.foreground.clone(),
    })
}

#[tracing::instrument(name = "stow.cargo_cmd.predict", skip_all)]
/// `stow predict`: report this workspace's cache coverage.
///
/// Read-only, and that is the whole contract: the dependency graph never
/// leaves the machine, nothing is posted, and nothing is enqueued.
pub async fn predict(args: CargoCommandArgs, state_db: &StateDb) -> stow_types::error::Result<()> {
    let Some(analysis) = analyze_for_prediction(args, state_db).await? else {
        return Ok(());
    };
    write_stdout(&render_prediction_summary(&analysis))
}

/// The coverage analysis behind `predict`. `Ok(None)` means the public
/// cache cannot serve this toolchain at all and the reason has been
/// printed.
async fn analyze_for_prediction(
    args: CargoCommandArgs,
    state_db: &StateDb,
) -> stow_types::error::Result<Option<WorkspacePrediction>> {
    let invocation = CargoInvocation::new("predict", args);
    let project = ProjectContext::load(&invocation).await?;
    let public_cache_mode = PublicCacheMode::for_rustc(&project.rustc_version);
    if let PublicCacheMode::Disabled { message, .. } = &public_cache_mode {
        write_stdout(&format!("{message}\n"))?;
        return Ok(None);
    }

    // Unlike `check`/`build`, `predict` has no cargo run to protect: an
    // analysis it cannot compute is the command failing, and callers rely
    // on the exit status saying so.
    let config = StowConfig::load(state_db.clone()).map_err(|error| {
        stow_types::stow_error!(
            "stow predict is unavailable because stow is not configured.\nreason: {error}"
        )
    })?;
    analyze_workspace_prediction(
        &project,
        project.current_dir(),
        &project.manifest_path,
        &config,
        None,
    )
    .await
    .map(Some)
    .map_err(|error| {
        stow_types::stow_error!("{}", render_prediction_failure(&config, &error).trim_end())
    })
}

#[derive(Debug, Clone)]
struct CargoInvocation {
    action: String,
    cargo_args: Vec<OsString>,
    silent_compatible_upgrades: bool,
    use_stow_resolver: bool,
}

impl CargoInvocation {
    fn new(action: &str, args: CargoCommandArgs) -> Self {
        Self {
            action: action.to_owned(),
            cargo_args: args.cargo_args,
            silent_compatible_upgrades: args.silent_compatible_upgrades,
            // Default ON. cargo's own `--locked` dry-run inside
            // `try_stow_resolver` is the semver/features correctness gate.
            // Users opt out with `--no-stow-resolver` when they specifically
            // want cargo's own resolver to pick versions.
            use_stow_resolver: !args.no_stow_resolver,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProjectContext {
    /// The wrapped action (`check`, `build`, `test`, `predict`, …) —
    /// picks the cargo subcommand the unit-graph query re-runs.
    pub action: String,
    /// The user's own cargo arguments, forwarded verbatim to the
    /// `--unit-graph` re-run so cargo computes selection, features and
    /// platform cfg exactly as it does for the real build.
    pub cargo_args: Vec<OsString>,
    pub workspace_root: PathBuf,
    pub current_dir: PathBuf,
    pub(crate) current_dir_relative: PathBuf,
    pub manifest_path: PathBuf,
    pub(crate) metadata_args: MetadataArgs,
    pub target: String,
    /// Cargo was given a target — `--target`, `CARGO_BUILD_TARGET`, or
    /// `build.target` — so its unit graph splits host and target units.
    pub target_given: bool,
    pub rustc_version: String,
    /// The cargo `--config` values this build needs so its Linux units
    /// link with mold — empty on non-Linux, and empty when the cargo
    /// configuration already selects a reachable mold (the setup path).
    /// Resolved once by [`crate::mold::provision`] and read by every
    /// cargo build invocation through [`MoldSelection::config_args`],
    /// so the effective selection — and therefore the compile keys — is
    /// identical whether it came from `--config` or from a written
    /// config file.
    pub(crate) mold: MoldSelection,
    /// The supervisor's wrapper base, still computing while the driver's
    /// other work proceeds — `Shared` so every `run_cargo` the context
    /// reaches awaits the one task rather than letting the first
    /// facade's `compiled` re-probe on cargo's critical path (stow#608).
    /// `None` on the paths that never had a `StowConfig` to build it
    /// from; the lazy load then behaves exactly as before.
    pub(crate) env_base: Option<SharedEnvBase>,
    /// The build's rustc — the configured `RUSTC`/`build.rustc` when
    /// set, else the toolchain's — the executable every driver-side
    /// probe names (stow#608).
    pub(crate) build_rustc: rustc_args::BuildRustc,
    /// The hold keeping miss drains' derivation cargo off the
    /// package-cache lock while this command's cargo may need it —
    /// taken where the context is begun, released once cargo's
    /// resolution is over (stow#667).
    pub(crate) foreground: crate::derive_gate::ForegroundHold,
}

/// The build's target triple while rustc is still answering: `Shared` so
/// the project context and the mold provisioning task can both await the
/// one probe (stow#517).
type SharedTargetProbe = Shared<BoxFuture<'static, Result<String, String>>>;

/// The wrapper environment base the driver's supervisor seeds, still
/// computing — `Shared` so a cloned `ProjectContext` (a mirrored
/// upgrade build) awaits the same task rather than a second one.
/// A failed probe is an `Err` here, not a silent `None`: the build
/// fails on the driver's timeline with the probe's own error instead
/// of hiding the failure behind a lazy re-probe (stow#608).
type SharedEnvBase = Shared<
    BoxFuture<
        'static,
        Result<Option<std::sync::Arc<crate::WrapperEnvBase>>, std::sync::Arc<String>>,
    >,
>;

/// Spawn the supervisor's base build on the driver's own timeline —
/// the shared `rustc -vV` fact probe, the `rustc --print sysroot`
/// executable probe and `prepare_local_cache` overlap the context's
/// remaining work and mold's provisioning, so `run_cargo` finds them
/// already answered (stow#608). No `StowConfig` means nothing to build
/// and no task to await.
fn spawn_env_base(
    config: Option<&StowConfig>,
    pending: &PendingProjectContext,
) -> Option<SharedEnvBase> {
    let config = config.cloned()?;
    let shared_vv = pending.rustc_vv.clone();
    let build_rustc = pending.build_rustc.clone();
    let task = tokio::spawn(
        async move {
            crate::supervisor_env_base(&config, &shared_vv, &build_rustc)
                .await
                .map(|base| base.map(std::sync::Arc::new))
                .map_err(|error| std::sync::Arc::new(error.to_string()))
        }
        .instrument(tracing::debug_span!("stow.precargo.env_base")),
    );
    Some(
        async move {
            match task.await {
                Ok(base) => base,
                Err(error) => Err(std::sync::Arc::new(format!(
                    "join supervisor env base task: {error}"
                ))),
            }
        }
        .boxed()
        .shared(),
    )
}

/// The seeded base, joined: `Some` awaits the shared task and
/// propagates a probe failure as the build's own error (stow#608).
async fn join_env_base(
    shared: Option<&SharedEnvBase>,
) -> stow_types::error::Result<Option<std::sync::Arc<crate::WrapperEnvBase>>> {
    match shared {
        Some(shared) => shared.clone().await.map_err(|error| {
            stow_types::stow_error!("build the supervisor environment base: {error}")
        }),
        None => Ok(None),
    }
}

/// The half of a [`ProjectContext`] that never waits on rustc: the
/// invocation's workspace layout, and the rustc probes themselves,
/// already spawned. `run_inner` hands the pending context to
/// [`spawn_mold_provision`] so mold's probes run beside rustc's rather
/// than after them, then `finish` joins what the probes answered
/// (stow#517).
struct PendingProjectContext {
    action: String,
    cargo_args: Vec<OsString>,
    workspace_root: PathBuf,
    current_dir: PathBuf,
    current_dir_relative: PathBuf,
    manifest_path: PathBuf,
    metadata_args: MetadataArgs,
    target: SharedTargetProbe,
    /// The first of the targets cargo was given, whatever the source —
    /// `None` for a native (host-triple) build.
    resolved_target: Option<String>,
    /// The one `rustc -vV` every rustc-facts consumer shares — the
    /// host-triple answer, the release version, the supervisor
    /// base's facts and the link-resolution key — so pre-cargo rustc
    /// spawns about rustc itself are exactly `-vV` and `--print
    /// sysroot`, and they probe the build's rustc (stow#608).
    rustc_vv: crate::rustc_args::SharedRustcVv,
    rustc_version: Shared<BoxFuture<'static, Result<String, String>>>,
    /// The cargo config chain, loaded once here: the link resolution,
    /// the target chain and the supervisor base all read this one
    /// answer rather than re-parsing the same documents (stow#608).
    cargo_config: cargo_config2::Config,
    /// The build's rustc as cargo resolves it — `RUSTC`/`build.rustc`
    /// when configured, else the toolchain's `rustc`: the executable
    /// the shared `-vV`, the sysroot probe and the link key all name.
    build_rustc: rustc_args::BuildRustc,
}

impl ProjectContext {
    /// Everything `load` resolves without waiting on rustc: the workspace
    /// layout, and both probes already running beside it.
    fn begin(invocation: &CargoInvocation) -> stow_types::error::Result<PendingProjectContext> {
        let invocation_dir = std::env::current_dir().wrap_err("resolve current directory")?;
        let metadata_args = MetadataArgs::parse(&invocation_dir, &invocation.cargo_args)?;
        // Cargo's target chain: spelled `--target`(s), then
        // `--config build.target` — the one config input
        // `cargo-config2` does not model, which cargo gives precedence
        // over environment variables and files — then
        // `CARGO_BUILD_TARGET` and `build.target` in the config chain,
        // both resolved by `build_target_for_cli`, then the host
        // triple (stow#551). stow serves the first resolved target;
        // `given` records that cargo was told one at all — the
        // difference between split and shared units.
        let cargo_config = crate::mold::cargo_config(&invocation_dir, None)
            .map_err(|error| stow_types::stow_error!("load cargo config: {error}"))?;
        // The one rustc every driver-side probe names: the configured
        // `RUSTC`/`build.rustc` when set — cargo hands that spelling to
        // its wrapper — else the toolchain's `rustc` (stow#608).
        let build_rustc = rustc_args::BuildRustc::from_cargo_config(&cargo_config);
        let resolved_targets = cargo_config
            .build_target_for_cli(
                metadata_args.targets.iter().chain(
                    crate::mold::config_arg_build_target(&invocation_dir, &invocation.cargo_args)
                        .iter()
                        .flatten(),
                ),
            )
            .map_err(|error| stow_types::stow_error!("resolve cargo build target: {error}"))?;
        let resolved_target = resolved_targets.first().cloned();
        // One `rustc -vV`, shared by every consumer of rustc facts —
        // the host triple below, the release version, the supervisor
        // base and the link-resolution key (stow#608).
        let rustc_vv = crate::rustc_args::shared_rustc_vv(build_rustc.executable().to_os_string());
        let target: SharedTargetProbe = resolved_targets.into_iter().next().map_or_else(
            || {
                if let Some(target) = crate::rustc_args::configured_public_cache_target() {
                    return futures_util::future::ready(Ok(target)).boxed().shared();
                }
                let vv = rustc_vv.clone();
                async move { vv.await.and_then(|vv| crate::rustc_args::vv_host(&vv)) }
                    .boxed()
                    .shared()
            },
            |target| futures_util::future::ready(Ok(target)).boxed().shared(),
        );
        let rustc_version: Shared<BoxFuture<'static, Result<String, String>>> =
            crate::rustc_args::configured_public_cache_rustc_version().map_or_else(
                || {
                    let vv = rustc_vv.clone();
                    async move { vv.await.and_then(|vv| crate::rustc_args::vv_release(&vv)) }
                        .boxed()
                        .shared()
                },
                |version| futures_util::future::ready(Ok(version)).boxed().shared(),
            );
        let layout = tracing::debug_span!("stow.precargo.workspace_layout").in_scope(|| {
            workspace_deps::resolve_workspace_layout(
                &invocation_dir,
                metadata_args.manifest_path.as_deref(),
            )
        })?;
        let workspace_root = layout.workspace_root;
        let current_dir = if invocation_dir.starts_with(&workspace_root) {
            invocation_dir
        } else {
            workspace_root.clone()
        };
        let manifest_path = layout.manifest_path;
        let current_dir_relative =
            pathdiff::diff_paths(&current_dir, &workspace_root).unwrap_or_else(PathBuf::new);
        Ok(PendingProjectContext {
            action: invocation.action.clone(),
            cargo_args: invocation.cargo_args.clone(),
            workspace_root,
            current_dir,
            current_dir_relative,
            manifest_path,
            metadata_args,
            target,
            resolved_target,
            rustc_vv,
            rustc_version,
            cargo_config,
            build_rustc,
        })
    }

    #[tracing::instrument(name = "stow.project.context", skip_all)]
    async fn load(invocation: &CargoInvocation) -> stow_types::error::Result<Self> {
        let pending = Self::begin(invocation)?;
        // `predict` assembles no cargo build, so a started provisioning
        // would be work nothing reads — the deferred selection runs
        // only if something awaits it (stow#653).
        let mold = defer_mold_provision(&pending);
        pending.finish(mold, enter_foreground_hold()).await
    }

    fn current_dir(&self) -> &Path {
        &self.current_dir
    }
}

impl PendingProjectContext {
    /// Join the probes `begin` spawned and the foreground hold being
    /// taken beside them; `mold` is the selection the caller chose —
    /// started for a build, deferred for a context that assembles no
    /// cargo build (stow#653).
    async fn finish(
        self,
        mold: MoldSelection,
        foreground: impl std::future::Future<
            Output = stow_types::error::Result<crate::derive_gate::ForegroundHold>,
        >,
    ) -> stow_types::error::Result<ProjectContext> {
        let (target, rustc_version, foreground) =
            tokio::join!(self.target, self.rustc_version, foreground);
        let target =
            target.map_err(|error| stow_types::stow_error!("detect rustc host target: {error}"))?;
        let rustc_version = rustc_version
            .map_err(|error| stow_types::stow_error!("detect rustc version: {error}"))?;
        let foreground = foreground?;
        Ok(ProjectContext {
            action: self.action,
            cargo_args: self.cargo_args,
            workspace_root: self.workspace_root,
            current_dir: self.current_dir,
            current_dir_relative: self.current_dir_relative,
            manifest_path: self.manifest_path,
            metadata_args: self.metadata_args,
            target,
            target_given: self.resolved_target.is_some(),
            rustc_version,
            mold,
            env_base: None,
            build_rustc: self.build_rustc,
            foreground,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct MetadataArgs {
    pub(crate) manifest_path: Option<PathBuf>,
    /// Every spelled `--target` in order — cargo compiles all of them.
    pub(crate) targets: Vec<String>,
    pub(crate) features: Vec<String>,
    pub(crate) all_features: bool,
    pub(crate) no_default_features: bool,
}

impl MetadataArgs {
    fn parse(current_dir: &Path, cargo_args: &[OsString]) -> stow_types::error::Result<Self> {
        let mut parsed = Self::default();
        let mut iter = cargo_args.iter();

        while let Some(arg) = iter.next() {
            let Some(arg) = arg.to_str() else {
                continue;
            };

            if let Some(value) = arg.strip_prefix("--manifest-path=") {
                parsed.manifest_path = Some(resolve_user_path(current_dir, value));
                continue;
            }
            if let Some(value) = arg.strip_prefix("--target=") {
                parsed.targets.push(value.to_owned());
                continue;
            }
            if let Some(value) = arg.strip_prefix("--features=") {
                parsed.features.extend(split_features(value));
                continue;
            }
            if let Some(value) = arg.strip_prefix("-F")
                && !value.is_empty()
            {
                parsed.features.extend(split_features(value));
                continue;
            }

            match arg {
                "--manifest-path" => {
                    let value = iter
                        .next()
                        .and_then(|value| value.to_str())
                        .ok_or_else(|| {
                            stow_types::stow_error!("missing value after --manifest-path")
                        })?;
                    parsed.manifest_path = Some(resolve_user_path(current_dir, value));
                }
                "--target" => {
                    let value = iter
                        .next()
                        .and_then(|value| value.to_str())
                        .ok_or_else(|| stow_types::stow_error!("missing value after --target"))?;
                    parsed.targets.push(value.to_owned());
                }
                "--features" | "-F" => {
                    let value = iter
                        .next()
                        .and_then(|value| value.to_str())
                        .ok_or_else(|| stow_types::stow_error!("missing value after {arg}"))?;
                    parsed.features.extend(split_features(value));
                }
                "--all-features" => parsed.all_features = true,
                "--no-default-features" => parsed.no_default_features = true,
                _ => {}
            }
        }
        Ok(parsed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ResolvedDependency {
    package_key: PackageKey,
    crate_name: String,
    version: semver::Version,
    features: Vec<String>,
    depth: usize,
}

#[derive(Debug, Clone)]
struct WorkspacePrediction {
    current_cached: usize,
    current_total: usize,
    expanded_cached: usize,
    expanded_total: usize,
    /// The build's unit graph as a per-side node table — what the
    /// wrapper's decision path resolves each compiled unit's cargo
    /// feature set and side from (stow#615). `None` when the lite pass
    /// ran with no expanded graph.
    unit_nodes: Option<crate::unit_node::UnitNodeTable>,
    candidates: Vec<CompatibleUpgrade>,
    missing_current: Vec<ResolvedDependency>,
    prefetch_artifacts: Vec<PrefetchArtifact>,
    cache_policy_entries: Vec<CachePolicyEntry>,
    /// The serve map this build's facades answer from — `None` when it
    /// could not be built and every invocation takes the plan path.
    servable_units: Option<crate::facade::ServeMap>,
}

impl WorkspacePrediction {
    /// The lite pass's answer when no expanded graph is cached: the
    /// serve map alone, with nothing counted and nothing ranked.
    /// Counting is the full pass's work, and on this build nothing
    /// reads counts the lite pass could fill — `select_upgrades`
    /// returns on the empty `candidates`, the build reads only the map,
    /// and every counter's consumer lives on the `predict` path
    /// (stow#608).
    const fn serve_map_only(servable_units: crate::facade::ServeMap) -> Self {
        Self {
            current_cached: 0,
            current_total: 0,
            expanded_cached: 0,
            expanded_total: 0,
            unit_nodes: None,
            candidates: Vec::new(),
            missing_current: Vec::new(),
            prefetch_artifacts: Vec::new(),
            cache_policy_entries: Vec::new(),
            servable_units: Some(servable_units),
        }
    }
}

#[derive(Debug, Clone)]
struct CompatibleUpgrade {
    package_key: PackageKey,
    crate_name: String,
    from_version: semver::Version,
    to_version: semver::Version,
    depth: usize,
    current_artifact_count: u32,
    upgraded_artifact_count: u32,
    is_root_candidate: bool,
}

#[derive(Debug)]
struct CachedDependencyPlan {
    bundles: BTreeMap<String, crate::artifact_cache::CachedArtifactBundle>,
    direct_externs: Vec<CachedDirectExtern>,
}

#[derive(Debug)]
struct CachedDirectExtern {
    extern_name: String,
    c_metadata: String,
}

#[derive(Debug)]
struct CachedDependencyShape {
    candidates: Vec<CachedDependencyArtifactShape>,
    direct_preferred_media_types: Vec<&'static str>,
}

#[derive(Debug)]
struct CachedDependencyArtifactShape {
    emit: Vec<String>,
    kind: ArtifactKind,
    crate_types: Vec<RustCrateType>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct DependencyCMetadataIdentity {
    crate_name: String,
    c_metadata: String,
}

async fn analyze_workspace_prediction(
    project: &ProjectContext,
    _current_dir: &Path,
    manifest_path: &Path,
    config: &StowConfig,
    resolution_done: Option<&crate::ResolutionDone>,
) -> stow_types::error::Result<WorkspacePrediction> {
    // Resolution never leaves the machine: the verified index slice is
    // the only catalog consulted, and the graph walk runs in-process.
    // The resolve and the slice fetch are independent — the slice
    // fetch's registry round trip does not wait on cargo's resolution
    // gate (stow#608).
    let (expanded, slices) = tokio::join!(
        expanded_graph(config, project, manifest_path, resolution_done),
        ensure_consumer_slices(config, project),
    );
    let expanded = expanded?;
    let (slice, host_slice) = slices?;
    analyze_workspace_prediction_from(
        project,
        config,
        AnalysisInputs {
            slice: Some(slice),
            host_slice,
            expanded: Some(expanded),
            slice_pending: false,
        },
    )
    .await
}

/// The filesystem-only workspace prediction: the serve map the full
/// pass would compute, read only from what is already verified on disk —
/// the expanded-graph cache, the cached index slices and the local
/// artifact listing. No registry fetch and no `cargo metadata` stands
/// between the driver and cargo: what this pass cannot prove servable
/// compiles locally and gets journaled, and the in-build enrichment
/// rewrites the serve map with the full pass's answer (stow#347). With
/// no cached graph the answer is the serve map alone — nothing is
/// counted and nothing is ranked — and the lockfile's registry packages
/// are read, once on a blocking thread, only when the local listing
/// holds units a missing graph cannot name (stow#608).
async fn analyze_workspace_prediction_lite(
    project: &ProjectContext,
    config: &StowConfig,
) -> stow_types::error::Result<WorkspacePrediction> {
    let (expanded, slices) = tokio::join!(
        expanded_graph_cached(config, project)
            .instrument(tracing::debug_span!("stow.precargo.expanded_graph_load")),
        cached_consumer_slices(config, project)
            .instrument(tracing::debug_span!("stow.precargo.cached_slices")),
    );
    let expanded = expanded?;
    let (slice, host_slice, slice_pending) = slices?;
    analyze_workspace_prediction_from(
        project,
        config,
        AnalysisInputs {
            slice,
            host_slice,
            expanded,
            slice_pending,
        },
    )
    .await
}

/// The artifact cache's own listing of covered units. A broken local
/// listing loses the local pairs only — the index answer still stands,
/// and the facades whose units nothing covers still skip the plan path
/// (stow#347) — so the failure warns and yields `None`.
async fn locally_covered_units_or_warn(
    config: &StowConfig,
    rustc_version: &str,
) -> Option<Vec<(String, String, String)>> {
    match crate::artifact_cache::locally_covered_units(config, rustc_version)
        .instrument(tracing::debug_span!("stow.precargo.local_units"))
        .await
    {
        Ok(units) => Some(units),
        Err(error) => {
            tracing::warn!(
                error = %error,
                "could not enumerate local coverage; the serve map carries index units only"
            );
            None
        }
    }
}

/// What the lite and full prediction passes each already read before the
/// shared analysis runs: the verified index slices and the expanded
/// graph when one is available. See [`analyze_workspace_prediction_lite`]
/// for what `slice_pending` marks (stow#347).
struct AnalysisInputs {
    slice: Option<index::IndexSlice>,
    host_slice: Option<index::IndexSlice>,
    expanded: Option<ExpandedDependencyGraph>,
    slice_pending: bool,
}

async fn analyze_workspace_prediction_from(
    project: &ProjectContext,
    config: &StowConfig,
    inputs: AnalysisInputs,
) -> stow_types::error::Result<WorkspacePrediction> {
    let local_units = locally_covered_units_or_warn(config, &project.rustc_version)
        .await
        .unwrap_or_default();
    // Everything past the local listing is synchronous work over the
    // index slices, the unit graph and the lockfile — input that grows
    // with the project and the published index — so it runs on a
    // blocking thread, under the caller's span (stow#624).
    let project = project.clone();
    let span = tracing::Span::current();
    smol::unblock(move || span.in_scope(|| predict_from_inputs(&project, inputs, &local_units)))
        .await
}

/// [`analyze_workspace_prediction_from`]'s synchronous half: the lockfile
/// read, the serve map's set algebra, the dependency-graph resolve and
/// the bookkeeping over its answer.
fn predict_from_inputs(
    project: &ProjectContext,
    inputs: AnalysisInputs,
    local_units: &[(String, String, String)],
) -> stow_types::error::Result<WorkspacePrediction> {
    let AnalysisInputs {
        slice,
        host_slice,
        expanded,
        slice_pending,
    } = inputs;
    let expanded_in = expanded
        .as_ref()
        .map_or_else(Vec::new, |expanded| expanded.entries.clone());
    // The lockfile's registry packages exist only to name this build's
    // units for the serve map's local half, and a unit graph names them
    // better — so the file is read, ahead of the map build, only when
    // there is no graph and the local listing holds units to admit
    // (stow#617). A build whose lockfile cargo has not written yet, and
    // one with nothing local to admit, never opens the file (stow#608).
    let lockfile_packages = if expanded.is_none() && !local_units.is_empty() {
        workspace_deps::lockfile_registry_packages(&project.workspace_root)?.unwrap_or_default()
    } else {
        BTreeSet::new()
    };
    let rows = slice.map(|slice| slice.index.rows).unwrap_or_default();
    let mut map = tracing::debug_span!("stow.precargo.serve_map_build").in_scope(|| {
        build_serve_map(
            project,
            &rows,
            host_slice.as_ref(),
            &expanded_in,
            local_units,
            &lockfile_packages,
        )
    });
    map.pending = slice_pending;
    let Some(expanded) = expanded else {
        // No expanded graph on disk — a cold cache cannot have one — so
        // the lite pass cannot rank semantic upgrades; it answers with
        // the serve map alone, which needs no expanded entries, and the
        // in-build enrichment resolves the full analysis (stow#347).
        return Ok(WorkspacePrediction::serve_map_only(map));
    };
    let servable_units = Some(map);
    // The requested entries are the unit graph's direct registry
    // dependencies: cargo's own recorded feature sets, and only the
    // deps this target actually compiles (stow#551).
    let dependencies = direct_unit_dependencies(&expanded.direct_dependencies);
    let entries = dependencies
        .iter()
        .cloned()
        .map(into_api_dependency)
        .collect::<stow_types::error::Result<Vec<_>>>()?;
    let analysis =
        resolve::analyze_dependency_graph(&rows, &entries, &expanded_in, resolve::host_glibc())?;

    // The wrapper's decision path resolves each compiled unit against
    // the per-side node table — the entries' cargo-resolved feature sets
    // plus whether the graph's invocation spelled `--target` (stow#615).
    let unit_nodes = Some(crate::unit_node::UnitNodeTable::from_expanded(
        &expanded.entries,
        project.target_given,
    ));
    let mut analysis_by_key = index_analysis_entries(analysis.entries)?;
    let (current_cached, missing_current, mut candidates) =
        apply_dependency_analyses(dependencies, &mut analysis_by_key)?;
    // Ranking walks the unit graph's own reverse edges — the
    // lockfile resolve that used to build this map is gone from the
    // analysis path (stow#551).
    let parents_by_package = workspace_deps::parents_by_package(&expanded.entries);
    rank_upgrade_candidates(&mut candidates, &parents_by_package);
    let (prefetch_artifacts, cache_policy_entries) = prediction_fetch_lists(
        &project.target,
        &project.rustc_version,
        analysis.prefetch_artifacts,
    );
    let servable_units = servable_units.map(|mut map| {
        prefetch_servable_wildcards(&mut map, &prefetch_artifacts);
        map
    });
    Ok(WorkspacePrediction {
        current_cached,
        current_total: entries.len(),
        expanded_cached: analysis.expanded_cached,
        expanded_total: analysis.expanded_total,
        unit_nodes,
        candidates,
        missing_current,
        prefetch_artifacts,
        cache_policy_entries,
        servable_units,
    })
}

/// The serve map the facades answer from: the `(crate, version)` pairs
/// this build could serve at all — the resolved units an index slice
/// covers plus the ones the local cache holds — per side of the unit
/// graph (stow#347). Entries whose version is `"*"` are wildcards: the
/// crate may serve under another version — semantic fallback candidates,
/// prefetch ledger entries, and name-scoped local hits — so the facade
/// still asks the plan path for them.
///
/// The pair set errs on covering: a unit the map wrongly includes costs a
/// plan round trip, while a unit it wrongly excludes compiles despite an
/// artifact being available.
///
/// The two halves admit against different sets. Index rows still
/// intersect the expanded graph's own per-side units — index coverage
/// claims a feature set and a side only the graph proves — so with no
/// cached graph they contribute nothing. The local half asks for less:
/// the exact-key local lookup the plan path runs needs neither a graph
/// nor a slice, so a locally stored unit is admitted whenever the
/// build's units name it *as far as known* — the graph's per-side sets
/// when a graph is cached, `lockfile_packages` on both sides when it is
/// not (stow#617). Without the graph the side is unknowable, and a
/// wrong side costs the round trip the map already tolerates; the
/// unit's side itself still comes from its row's platform. The caller
/// reads the lockfile only when the local listing holds units to admit
/// (stow#608), and a lockfile cargo has not written yet reads as an
/// empty set — no local half, no error — so the in-build enrichment
/// covers such a build as today.
fn build_serve_map(
    project: &ProjectContext,
    consumer_rows: &[stow_types::index::ArtifactIndexRow],
    host: Option<&index::IndexSlice>,
    expanded_entries: &[ResolvedDependencyGraphEntry],
    local_units: &[(String, String, String)],
    lockfile_packages: &BTreeSet<(String, semver::Version)>,
) -> crate::facade::ServeMap {
    let host_glibc = resolve::host_glibc();
    let unit_pairs = |host_side: bool| -> BTreeSet<(String, String)> {
        expanded_entries
            .iter()
            .filter(|entry| entry.host_side == host_side)
            .map(|entry| {
                (
                    crate::canonical_crate_name(entry.crate_name.as_str()),
                    entry.version.to_string(),
                )
            })
            .collect()
    };
    let index_pairs = |rows: &[stow_types::index::ArtifactIndexRow]| -> BTreeSet<(String, String)> {
        rows.iter()
            .filter(|row| resolve::row_servable_on_host(row, host_glibc))
            .map(|row| {
                (
                    crate::canonical_crate_name(row.crate_name.as_str()),
                    row.version.to_string(),
                )
            })
            .collect()
    };
    // The set a facade consults is keyed on whether ITS invocation spells
    // `--target`, and cargo spells it for consumer units only when the
    // user asked. On a `--target` build the split is the unit graph's two
    // sides; on a native build every unit arrives unspelled, so the whole
    // servable graph sits on the host side — the consumer slice and the
    // host slice are the same rows there.
    let consumer_spelled = project.target_given;
    // Unspelled units look up the slice for the build's own host triple:
    // the consumer slice on a native build, the fetched host slice on a
    // `--target` build — and none when no host slice was fetched.
    let host_target = stow_types::api::runner_family(&project.target)
        .map(|family| family.host_triple().to_owned());
    let host_rows: &[stow_types::index::ArtifactIndexRow] = match (host_target.as_deref(), host) {
        (Some(host_target), _) if host_target == project.target => consumer_rows,
        (_, Some(host_slice)) => &host_slice.index.rows,
        _ => &[],
    };
    let consumer_index_pairs = index_pairs(consumer_rows);
    let host_index_pairs = index_pairs(host_rows);
    let consumer_index_names: BTreeSet<&String> =
        consumer_index_pairs.iter().map(|(name, _)| name).collect();
    let host_index_names: BTreeSet<&String> =
        host_index_pairs.iter().map(|(name, _)| name).collect();
    let consumer_units = unit_pairs(false);
    let host_units = unit_pairs(true);
    // The units this build compiles as far as the map can prove: the
    // expanded graph's own sets when one is cached — the index half
    // reads them alone — and the lockfile's registry packages on both
    // sides when it is not (stow#617).
    let lockfile_units = canonical_lockfile_packages(lockfile_packages);
    let (consumer_known, host_known) = if expanded_entries.is_empty() {
        (&lockfile_units, &lockfile_units)
    } else {
        (&consumer_units, &host_units)
    };
    let consumer_servable: BTreeSet<(String, String)> = consumer_units
        .intersection(&consumer_index_pairs)
        .cloned()
        .collect();
    let host_servable: BTreeSet<(String, String)> = host_units
        .intersection(&host_index_pairs)
        .cloned()
        .collect();
    let (mut target, mut host) = if consumer_spelled {
        (consumer_servable, host_servable)
    } else {
        (
            BTreeSet::new(),
            consumer_servable.union(&host_servable).cloned().collect(),
        )
    };
    for (crate_name, crate_version, unit_target) in local_units {
        let pair = (
            crate::canonical_crate_name(crate_name),
            crate_version.clone(),
        );
        if unit_target == &project.target && consumer_known.contains(&pair) {
            if consumer_spelled {
                target.insert(pair.clone());
            } else {
                host.insert(pair.clone());
            }
        }
        if Some(unit_target.as_str()) == host_target.as_deref() && host_known.contains(&pair) {
            host.insert(pair.clone());
        }
    }
    serve_map_wildcards(
        &mut target,
        &mut host,
        consumer_spelled,
        expanded_entries,
        local_units,
        &project.target,
        host_target.as_deref(),
        &consumer_index_names,
        &host_index_names,
        consumer_known,
        host_known,
    );
    crate::facade::ServeMap {
        target: target.into_iter().collect(),
        host: host.into_iter().collect(),
        pending: false,
    }
}

/// The lockfile's registry packages as the serve map's canonical
/// `(name, version)` pairs — the local half's unit set when no
/// expanded graph is cached (stow#617).
fn canonical_lockfile_packages(
    lockfile_packages: &BTreeSet<(String, semver::Version)>,
) -> BTreeSet<(String, String)> {
    lockfile_packages
        .iter()
        .map(|(name, version)| {
            (
                crate::canonical_crate_name(name.as_str()),
                version.to_string(),
            )
        })
        .collect()
}

/// The wildcard half of the serve map: a `("name", "*")` entry says this
/// crate may serve under another version, so the facade still asks the
/// plan path. Covers the units an exact pair cannot name — semantic
/// fallback candidates and name-scoped local hits.
///
/// `consumer_known`/`host_known` are the build's units as far as the
/// map can prove them — the expanded graph's sets when one is cached,
/// the lockfile's registry packages on both sides when it is not
/// (stow#617).
#[allow(clippy::too_many_arguments)]
fn serve_map_wildcards(
    target: &mut BTreeSet<(String, String)>,
    host: &mut BTreeSet<(String, String)>,
    consumer_spelled: bool,
    expanded_entries: &[ResolvedDependencyGraphEntry],
    local_units: &[(String, String, String)],
    project_target: &str,
    host_target: Option<&str>,
    consumer_index_names: &BTreeSet<&String>,
    host_index_names: &BTreeSet<&String>,
    consumer_known: &BTreeSet<(String, String)>,
    host_known: &BTreeSet<(String, String)>,
) {
    // The side a unit's invocation arrives on: spelled `--target` units
    // read `target`, every unspelled unit reads `host` — which is all of
    // them on a native build.
    let mut wildcard = |host_side: bool, name: String| {
        if host_side || !consumer_spelled {
            host.insert((name, "*".to_owned()));
        } else {
            target.insert((name, "*".to_owned()));
        }
    };
    // A non-empty expanded graph is what `semantic_fallback_enabled`
    // means downstream: a unit the index covers under another compatible
    // version may still serve, so its name wildcards its side.
    let semantic_fallback = !expanded_entries.is_empty();
    for entry in expanded_entries {
        let name = crate::canonical_crate_name(entry.crate_name.as_str());
        let index_names = if entry.host_side {
            host_index_names
        } else {
            consumer_index_names
        };
        if semantic_fallback && index_names.contains(&name) {
            wildcard(entry.host_side, name);
        }
    }
    // A local serve answers by name — the store's version key is not
    // one a facade can reproduce — so every known unit the local cache
    // holds at all wildcards the side it would run on.
    for (crate_name, _, unit_target) in local_units {
        let name = crate::canonical_crate_name(crate_name);
        if unit_target == project_target && consumer_known.iter().any(|(n, _)| *n == name) {
            wildcard(false, name.clone());
        }
        if Some(unit_target.as_str()) == host_target && host_known.iter().any(|(n, _)| *n == name) {
            wildcard(true, name);
        }
    }
}

/// The prefetch ledger's crate names as serve-map wildcards on both
/// invocation spellings: a prefetched unit serves by content key, which
/// no facade-side version can reproduce, and the wrong side costs only
/// a plan round trip.
fn prefetch_servable_wildcards(
    servable_units: &mut crate::facade::ServeMap,
    prefetch_artifacts: &[PrefetchArtifact],
) {
    for artifact in prefetch_artifacts {
        let name = crate::canonical_crate_name(&artifact.crate_name);
        servable_units.target.push((name.clone(), "*".to_owned()));
        servable_units.host.push((name, "*".to_owned()));
    }
}

/// Fetch the index slices a consumer's lookups read: the project's own
/// target slice plus — when the consumer's family host differs — the
/// host slice the wrapper resolves host units from (a host unit's
/// `env.target` is the host triple, so its lookup reads
/// `cached_slice(host_triple)`; without the fetch every host dep
/// compiles locally even when published). The two fetches run
/// concurrently. The target slice's failure propagates; a host slice
/// that cannot be fetched warns and the build degrades to local
/// compiles the miss lane reports (stow#367).
async fn ensure_consumer_slices(
    config: &StowConfig,
    project: &ProjectContext,
) -> stow_types::error::Result<(index::IndexSlice, Option<index::IndexSlice>)> {
    let host_target = stow_types::api::runner_family(&project.target)
        .map(|family| family.host_triple().to_owned())
        .filter(|host| *host != project.target);
    let host_fetch = async {
        match host_target.as_deref() {
            Some(target) => index::ensure_slice(config, target, &project.rustc_version)
                .await
                .map(Some),
            None => Ok(None),
        }
    };
    let (slice, host) = tokio::join!(
        index::ensure_slice(config, &project.target, &project.rustc_version),
        host_fetch,
    );
    let host_slice = match host {
        Ok(host_slice) => host_slice,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "could not fetch the host-side index slice; host deps will compile locally"
            );
            None
        }
    };
    Ok((slice?, host_slice))
}

/// The filesystem half of [`ensure_consumer_slices`]: the verified cached
/// slices only, never the network. The paths that must not stand between
/// the driver and cargo — the resolver attempt and the lite prediction —
/// read these and treat absence as "nothing proven servable yet" rather
/// than paying the pull and the signature verification for rows the
/// in-build enrichment fetches anyway (stow#347).
async fn cached_consumer_slices(
    config: &StowConfig,
    project: &ProjectContext,
) -> stow_types::error::Result<(Option<index::IndexSlice>, Option<index::IndexSlice>, bool)> {
    let host_target = stow_types::api::runner_family(&project.target)
        .map(|family| family.host_triple().to_owned())
        .filter(|host| *host != project.target);
    let host_slice_expected = host_target.is_some();
    let host_fetch = async {
        match host_target.as_deref() {
            Some(target) => index::cached_slice(config, target, &project.rustc_version).await,
            None => Ok(None),
        }
    };
    let (slice, host) = tokio::join!(
        index::cached_slice(config, &project.target, &project.rustc_version),
        host_fetch,
    );
    let host_slice = match host {
        Ok(host_slice) => host_slice,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "could not read the cached host-side index slice; host deps will compile locally"
            );
            None
        }
    };
    let slice = slice?;
    // A slice the cache does not hold is one the enrichment's fetch will
    // land mid-build: the map the lite pass writes stays provisional
    // until that answer replaces it (stow#347).
    let pending = slice.is_none() || (host_slice_expected && host_slice.is_none());
    Ok((slice, host_slice, pending))
}

/// Ask the scheduler to build the misses this build compiled locally.
///
/// Misses mint only from observations of the build that just ran: each
/// local compile recorded the identity its rustc invocation actually
/// used — the argv `--cfg` feature set, the real platform (the host
/// triple for host units, to which cargo passes no `--target`), and
/// the `--extern` deps as each dep's own recorded identity (stow#317).
/// The caller owns failure handling: a supervised run leaves the
/// observations in the journal so a later drain retries them; a drain
/// restores the journal on error.
/// Mint this build's locally-compiled units as misses: resolve each
/// unit's `--extern` deps to their recorded identities, post the
/// observed graph to `/api/v1/admissions` and drain what the edge mints.
/// The caller's journal keeps the observations on failure so a later
/// drain retries them (stow#317).
pub async fn admit_observed_misses(
    config: &StowConfig,
    consumer_target: &str,
    rustc_version: &str,
    build_host: &str,
    consumer_spelled_target: bool,
    observations: &[crate::artifact_cache::ObservedUnit],
    expanded: &ExpandedDependencyGraph,
) -> stow_types::error::Result<()> {
    if observations.is_empty() {
        return Ok(());
    }
    let Some(family) = stow_types::api::runner_family(consumer_target) else {
        tracing::info!(
            target = %consumer_target,
            "consumer target is not a CI target; not minting misses"
        );
        return Ok(());
    };
    // A `--target` anywhere in the observations proves the consumer
    // spelled one, whatever the journal's flag says.
    let consumer_spelled_target = consumer_spelled_target
        || observations
            .iter()
            .any(|observation| observation.explicit_target.is_some());
    let extern_metadatas = observations
        .iter()
        .flat_map(|observation| {
            observation
                .externs
                .iter()
                .map(|extern_dep| extern_dep.c_metadata.clone())
        })
        .collect::<BTreeSet<_>>();
    let mut dep_identities = crate::artifact_cache::load_artifact_dep_identities(
        config,
        rustc_version,
        &extern_metadatas,
    )
    .await?;
    // A dep node's side comes from the dep's own published shape when
    // the index carries one — stamped off the consumer and host slices
    // (the dep's recorded target keys into one of them). One physical
    // unit may publish rows on both sides — a crate a consumer links
    // and a build script links share their bytes — and such a dep's
    // edge has to fall back to the invocation's own semantics, so only
    // rows that agree on a single side pin it.
    let mut published_shapes: BTreeMap<String, (Option<UnitShape>, bool)> = BTreeMap::new();
    for slice_target in [consumer_target, build_host] {
        if let Some(slice) = index::cached_slice(config, slice_target, rustc_version).await? {
            for row in slice.index.rows {
                published_shapes
                    .entry(row.c_metadata.as_str().to_owned())
                    .and_modify(|(shape, consistent)| match (*shape, row.unit_shape) {
                        (Some(seen), Some(current)) if seen.side != current.side => {
                            *consistent = false;
                        }
                        (None, current) => *shape = current,
                        _ => {}
                    })
                    .or_insert((row.unit_shape, true));
            }
        }
    }
    let published_shapes: BTreeMap<String, Option<UnitShape>> = published_shapes
        .into_iter()
        .map(|(c_metadata, (shape, consistent))| {
            (c_metadata, consistent.then_some(shape).flatten())
        })
        .collect();
    for (c_metadata, dep) in &mut dep_identities {
        dep.unit_shape = published_shapes.get(c_metadata).copied().flatten();
    }
    // Host units classify against the build's probed host — the
    // triple cargo never passes `--target` for — not the family's
    // host; the family's host stays where host nodes mint (stow#317).
    // The misses' subgraphs project off the build's own unit graph
    // (stow#588) — the persisted expanded graph the drain recorded.
    let task_units = expanded.task_units(
        consumer_spelled_target.then_some(consumer_target),
        family.host_triple(),
    )?;
    let resolved = stow_types::unit_graph::resolved_task_graph(
        &task_units,
        &stow_types::identity::WireRustcVersion::parse(rustc_version)
            .wrap_err("parse rustc_version")?,
    )?;
    let graph = workspace_deps::observed_miss_graph(
        observations,
        &dep_identities,
        consumer_spelled_target,
        &resolved,
    )?;
    if graph.roots.is_empty() {
        return Ok(());
    }
    let minted = query_admissions(
        config,
        consumer_target,
        rustc_version,
        &graph.roots,
        &graph.expanded,
    )
    .await?;
    let mut admissions = crate::admission::AdmissionCollector::default();
    admissions.record(config, minted);
    admissions.drain(config).await;
    Ok(())
}

/// Post the graph to `/api/v1/admissions` and return the enqueue
/// admissions the edge mints for its misses. This is the only call that
/// ships the dependency graph off the machine — the catalog lookup itself
/// is local.
async fn query_admissions(
    config: &StowConfig,
    target: &str,
    rustc_version: &str,
    entries: &[DependencyGraphEntry],
    expanded_entries: &[ResolvedDependencyGraphEntry],
) -> stow_types::error::Result<Vec<EnqueueAdmission>> {
    let url = format!(
        "{}/api/v1/admissions",
        config.edge_url.trim_end_matches('/')
    );
    let request = AdmissionRequest {
        target: stow_types::identity::TargetTriple::parse(target).wrap_err("encode target")?,
        rustc_version: stow_types::identity::WireRustcVersion::parse(rustc_version)
            .wrap_err("encode rustc_version")?,
        entries: entries.to_vec(),
        expanded_entries: expanded_entries.to_vec(),
    };
    let mut client = crate::edge_client::client(config);
    let response = client
        .post(&url)?
        .json_body(&request)?
        .await
        .map_err(|error| stow_types::stow_error!("query admissions {url}: {error}"))?;
    response
        .into_json::<Vec<EnqueueAdmission>>()
        .await
        .map_err(|error| stow_types::stow_error!("parse admissions {url} response: {error}"))
}

/// The expanded (transitive) dependency graph for this invocation: the
/// on-disk cache entry when present, a live `cargo --unit-graph` query on
/// miss or load error (with the result written back best-effort).
async fn expanded_graph(
    config: &StowConfig,
    project: &ProjectContext,
    manifest_path: &Path,
    resolution_done: Option<&crate::ResolutionDone>,
) -> stow_types::error::Result<ExpandedDependencyGraph> {
    let expanded_cache_key = expanded_graph_cache_key(project).await?;
    match crate::lockfile_graph_cache::load(config, &expanded_cache_key).await {
        Ok(Some(graph)) => {
            tracing::debug!(
                cache_key = %expanded_cache_key,
                entries = graph.entries.len(),
                "lockfile_graph_cache hit"
            );
            return Ok(graph);
        }
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(%error, "lockfile_graph_cache load failed; falling back to live resolve");
        }
    }
    // Host-side units mint at the runner family's host triple — the
    // same platform the host slice and the scheduler key on (stow#588).
    let host_triple = stow_types::api::runner_family(&project.target)
        .map_or(project.target.as_str(), |family| family.host_triple());
    let graph = resolve_after_cargo_resolution(
        resolution_done,
        workspace_deps::resolve_exact_dependency_graph(
            manifest_path,
            &project.action,
            &project.cargo_args,
            project.target_given.then_some(project.target.as_str()),
            &project.current_dir,
            host_triple,
            &stow_types::identity::WireRustcVersion::parse(project.rustc_version.as_str())
                .wrap_err("parse rustc_version")?,
        ),
    )
    .await?;
    if let Err(error) =
        crate::lockfile_graph_cache::store(config, &expanded_cache_key, &graph).await
    {
        tracing::warn!(%error, "lockfile_graph_cache store failed; continuing");
    }
    Ok(graph)
}

/// `resolve` runs only once cargo's own resolution is over. A missed
/// `lockfile_graph_cache` has the in-build enrichment spawning a
/// second cargo at the moment the build's starts, and whichever takes
/// the package-cache lock first makes the other's resolve wait —
/// printed on the user's build as `Blocking waiting for file lock on
/// package cache` (stow#608). `None` — a caller with no concurrent
/// cargo — resolves at once.
async fn resolve_after_cargo_resolution<T, F>(
    resolution_done: Option<&crate::ResolutionDone>,
    resolve: F,
) -> stow_types::error::Result<T>
where
    F: std::future::Future<Output = stow_types::error::Result<T>>,
{
    if let Some(done) = resolution_done {
        done.wait().await;
    }
    resolve.await
}

/// The filesystem half of [`expanded_graph`]: the persisted graph cache
/// only. `Ok(None)` means no usable snapshot is on disk — a path that
/// must not block cargo's start does not pay the `--unit-graph` re-run
/// to refill it; the in-build enrichment resolves it live instead
/// (stow#347).
async fn expanded_graph_cached(
    config: &StowConfig,
    project: &ProjectContext,
) -> stow_types::error::Result<Option<ExpandedDependencyGraph>> {
    let expanded_cache_key = expanded_graph_cache_key(project).await?;
    match crate::lockfile_graph_cache::load(config, &expanded_cache_key).await {
        Ok(graph) => Ok(graph),
        Err(error) => {
            tracing::warn!(%error, "lockfile_graph_cache load failed; treating as no cached graph");
            Ok(None)
        }
    }
}

/// [`crate::lockfile_graph_cache::cache_key`] on a blocking thread: the
/// key reads and hashes the lockfile, whose size is the project's
/// package count (stow#624).
async fn expanded_graph_cache_key(project: &ProjectContext) -> stow_types::error::Result<String> {
    let project = project.clone();
    smol::unblock(move || crate::lockfile_graph_cache::cache_key(&project)).await
}

/// The unit graph's direct registry dependencies as depth-1
/// `ResolvedDependency` rows — cargo's own recorded feature sets and
/// only the deps the wrapped target compiles (stow#551).
fn direct_unit_dependencies(
    direct: &[workspace_deps::SelectedRegistryDependency],
) -> Vec<ResolvedDependency> {
    // The unit graph records the edge per member per side; identical
    // (crate, version, features) rows are one compiled unit — fold
    // them or the analysis index would reject the duplicate (stow#551).
    let mut seen = BTreeSet::new();
    direct
        .iter()
        .filter(|dependency| {
            seen.insert((
                dependency.crate_name.clone(),
                dependency.version.clone(),
                dependency.features.clone(),
            ))
        })
        .map(|dependency| ResolvedDependency {
            package_key: PackageKey {
                crate_name: dependency.crate_name.clone(),
                version: dependency.version.clone(),
                source: Some(workspace_deps::CRATES_IO_SOURCE.to_owned()),
            },
            crate_name: dependency.crate_name.clone(),
            version: dependency.version.clone(),
            features: dependency.features.clone(),
            depth: 1,
        })
        .collect()
}

/// Per-dependency analysis rows keyed by (crate name, version, features).
type AnalysisByKey = BTreeMap<
    (
        stow_types::identity::CrateName,
        semver::Version,
        Vec<String>,
    ),
    resolve::AnalysisEntry,
>;

/// Per-dependency analysis rows indexed by (crate name, version, features).
/// A duplicate key means the resolver emitted two rows for one request
/// entry — a bug — so this fails.
fn index_analysis_entries(
    entries: Vec<resolve::AnalysisEntry>,
) -> stow_types::error::Result<AnalysisByKey> {
    let mut analysis_by_key = AnalysisByKey::new();
    for entry in entries {
        validate_analysis_entry(&entry)?;
        let key = (
            entry.dependency.crate_name.clone(),
            entry.dependency.version.clone(),
            entry.dependency.features.clone(),
        );
        if analysis_by_key.insert(key.clone(), entry).is_some() {
            return Err(stow_types::stow_error!(
                "resolver produced duplicate dependency analysis for {} {}",
                key.0,
                key.1
            ));
        }
    }
    Ok(analysis_by_key)
}

/// Match each requested dependency to its analysis row: count current-cache
/// coverage, collect upgrade candidates, and gather the deps with no cached
/// artifact sorted for display. The resolver emits exactly one row per
/// requested entry, so an omitted or extra row is a bug, and this fails.
fn apply_dependency_analyses(
    dependencies: Vec<ResolvedDependency>,
    analysis_by_key: &mut AnalysisByKey,
) -> stow_types::error::Result<(usize, Vec<ResolvedDependency>, Vec<CompatibleUpgrade>)> {
    let mut current_cached = 0usize;
    let mut missing_current = Vec::new();
    let mut candidates = Vec::new();
    for dependency in dependencies {
        let key_crate_name = stow_types::identity::CrateName::parse(dependency.crate_name.as_str())
            .map_err(|error| {
                stow_types::stow_error!(
                    "invalid analysis dependency crate_name `{}`: {error}",
                    dependency.crate_name
                )
            })?;
        let key = (
            key_crate_name,
            dependency.version.clone(),
            dependency.features.clone(),
        );
        let entry = analysis_by_key.remove(&key).ok_or_else(|| {
            stow_types::stow_error!(
                "resolver produced no dependency analysis for {} {}",
                dependency.crate_name,
                dependency.version
            )
        })?;
        if entry.current_artifact_count > 0 {
            current_cached = current_cached.saturating_add(1);
        } else {
            missing_current.push(dependency.clone());
        }
        if let Some(recommended) = entry.recommended {
            candidates.push(CompatibleUpgrade {
                package_key: dependency.package_key.clone(),
                crate_name: dependency.crate_name.clone(),
                from_version: dependency.version.clone(),
                to_version: recommended.version,
                depth: dependency.depth,
                current_artifact_count: entry.current_artifact_count,
                upgraded_artifact_count: recommended.artifact_count,
                is_root_candidate: false,
            });
        }
    }

    if !analysis_by_key.is_empty() {
        return Err(stow_types::stow_error!(
            "resolver produced {} unexpected dependency analyses",
            analysis_by_key.len()
        ));
    }

    missing_current.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.version.cmp(&right.version))
            .then(left.features.cmp(&right.features))
    });
    Ok((current_cached, missing_current, candidates))
}

/// Rank upgrade candidates by artifact gain (then version, then name),
/// dedup identical rows, and flag root-eligible ones.
fn rank_upgrade_candidates(
    candidates: &mut Vec<CompatibleUpgrade>,
    parents_by_package: &BTreeMap<PackageKey, Vec<PackageKey>>,
) {
    candidates.sort_by(|left, right| {
        right
            .upgraded_artifact_count
            .cmp(&left.upgraded_artifact_count)
            .then(right.to_version.cmp(&left.to_version))
            .then(left.crate_name.cmp(&right.crate_name))
    });
    let mut seen_candidates = BTreeSet::<(String, semver::Version, semver::Version)>::new();
    candidates.retain(|candidate| {
        seen_candidates.insert((
            candidate.crate_name.clone(),
            candidate.from_version.clone(),
            candidate.to_version.clone(),
        ))
    });
    mark_root_candidates(candidates, parents_by_package);
}

/// The prefetch-artifact and cache-policy lists the prediction carries,
/// built from the resolver's prefetch rows, each sorted and deduplicated.
fn prediction_fetch_lists(
    target: &str,
    rustc_version: &str,
    prefetch_artifacts: Vec<resolve::PrefetchArtifactRow>,
) -> (Vec<PrefetchArtifact>, Vec<CachePolicyEntry>) {
    let mut artifacts = prefetch_artifacts
        .iter()
        .map(|artifact| PrefetchArtifact {
            crate_name: artifact.crate_name.as_str().to_owned(),
            c_metadata: artifact.c_metadata.as_str().to_owned(),
            bundle_digest: artifact.bundle_digest.clone(),
            target: target.to_owned(),
            rustc_version: rustc_version.to_owned(),
            depth: 0,
        })
        .collect::<Vec<_>>();
    artifacts.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.c_metadata.cmp(&right.c_metadata))
    });
    artifacts.dedup_by(|left, right| {
        left.crate_name == right.crate_name && left.c_metadata == right.c_metadata
    });
    let mut cache_policy_entries = prefetch_artifacts
        .into_iter()
        .map(|artifact| CachePolicyEntry {
            target: target.to_owned(),
            crate_name: artifact.crate_name.into_inner(),
        })
        .collect::<Vec<_>>();
    cache_policy_entries.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then(left.crate_name.cmp(&right.crate_name))
    });
    cache_policy_entries
        .dedup_by(|left, right| left.target == right.target && left.crate_name == right.crate_name);
    (artifacts, cache_policy_entries)
}

async fn try_stow_resolver(
    config: &StowConfig,
    project: &ProjectContext,
    invocation: &CargoInvocation,
) -> stow_types::error::Result<Option<ExitStatus>> {
    let Some(stow_lockfile_toml) = synthesize_lockfile(config, project).await? else {
        return Ok(None);
    };

    let public_cache_mode = PublicCacheMode::for_rustc(&project.rustc_version);
    let Some(pinned) = prepare_pinned_mirror(project, invocation, &stow_lockfile_toml).await?
    else {
        return Ok(None);
    };
    let Some(mirror_analysis) = analyze_pinned_mirror(config, &pinned.project).await else {
        return Ok(None);
    };

    Box::pin(run_pinned_mirror_build(
        config,
        project,
        invocation,
        &pinned,
        &public_cache_mode,
        mirror_analysis,
    ))
    .await
}

/// Ask the local resolver for a cache-optimized lockfile covering
/// `project`'s direct dependencies, resolved against the cached verified
/// index slice. Returns `None` — after logging the reason — when the
/// project has no direct dependencies or no consistent cache-pinned
/// assignment exists. The resolver's internal candidate budget bounds the
/// work; there is no network round trip to deadline — only the
/// filesystem's slice is consulted, so a cold cache skips the attempt
/// outright instead of paying the registry pull and signature
/// verification in front of a resolve that has nothing to resolve
/// against (stow#347). The in-build enrichment's live fetch is what
/// brings a fresher index to a running build.
async fn synthesize_lockfile(
    config: &StowConfig,
    project: &ProjectContext,
) -> stow_types::error::Result<Option<String>> {
    // The resolver needs a cached slice to pin against — read it first,
    // so a cold cache skips the manifest walk entirely (stow#608).
    let Some(slice) = cached_consumer_slices(config, project)
        .instrument(tracing::debug_span!("stow.precargo.cached_slices"))
        .await?
        .0
    else {
        tracing::info!("no cached index slice; nothing for the resolver to pin to");
        return Ok(None);
    };
    let direct = collect_user_direct_dependencies(
        &project.manifest_path,
        &project.workspace_root,
        &project.metadata_args,
    )
    .await?;
    if direct.is_empty() {
        return Ok(None);
    }
    let outcome = {
        let rows = slice.index.rows;
        tokio::task::spawn_blocking(move || lockfile_resolver::resolve_lockfile(&rows, &direct))
            .await
            .wrap_err("join lockfile resolver")??
    };
    let Some(stow_lockfile_toml) = outcome.lockfile_toml else {
        tracing::info!(
            uncovered_direct = ?outcome.uncovered_direct,
            candidates_considered = outcome.candidates_considered,
            seed_diagnostics = ?outcome.seed_diagnostics,
            "stow resolver found no consistent cache-optimized assignment; falling back"
        );
        return Ok(None);
    };
    tracing::info!(
        candidates_considered = outcome.candidates_considered,
        "stow resolver produced a synthesized cache-optimized lockfile; running cargo --locked dry-run gate"
    );
    Ok(Some(stow_lockfile_toml))
}

/// A workspace mirror prepared for a resolver-pinned build: the synthesized
/// lockfile is installed and cargo's own resolver already accepted it.
struct PinnedMirror {
    mirror: WorkspaceMirror,
    args: Vec<OsString>,
    manifest_path: PathBuf,
    project: ProjectContext,
}

/// Mirror `project`, install the synthesized lockfile, and run cargo's
/// `--locked` dry-run correctness gate. Returns `None` when the gate
/// rejects the lockfile.
async fn prepare_pinned_mirror(
    project: &ProjectContext,
    invocation: &CargoInvocation,
    stow_lockfile_toml: &str,
) -> stow_types::error::Result<Option<PinnedMirror>> {
    let mirror = create_workspace_mirror(project, &project.workspace_root).await?;
    write_lockfile_into_mirror(&mirror, stow_lockfile_toml).await?;

    // Note: we do NOT add `--locked` here. The synthesized lockfile
    // covers only the runtime graph the resolver could cache-pin from
    // the artifacts table. Manifest-declared optional/dev/build deps
    // that the user's project doesn't enable for `cargo check` may not
    // appear in the lockfile, and `--locked` would block cargo from
    // augmenting those missing entries — failing the build with a
    // "lock file needs to be updated" error. Without `--locked`, cargo
    // preserves every cache-hit pin (matching versions never get
    // rewritten unless the manifest forbids them) and only consults
    // the local index for the gaps the resolver intentionally omitted.
    let args = rewrite_args_for_mirror(&invocation.cargo_args, project, &mirror)?;
    let manifest_path = mirror_manifest_path(project, &mirror)?;
    let mirror_project = build_mirror_project_context(project, &mirror)?;

    // Correctness gate: cargo's own resolver verifies the synthesized
    // lockfile against the workspace's `Cargo.toml`. Under `--locked`,
    // cargo rejects any lockfile that violates a declared semver
    // requirement OR mismatches feature unification. Anything it accepts
    // here is provably semver-compatible — anything it rejects we fall
    // back from, so the takeover never produces a less-correct build than
    // cargo would on its own.
    if !validate_pinned_lockfile(&mirror_project).await? {
        tracing::info!(
            "cargo --locked dry-run rejected stow-synthesized lockfile; falling back to cargo's resolver"
        );
        return Ok(None);
    }
    Ok(Some(PinnedMirror {
        mirror,
        args,
        manifest_path,
        project: mirror_project,
    }))
}

/// Analyze the pinned mirror's graph. Returns `None` on failure: the
/// mirror lockfile is the runtime closure only — dev/build dep pins are
/// intentionally absent, the lockfile walk in mirror mode hydrates ALL dep
/// kinds and fails when those pins are missing, and continuing would feed
/// that broken lockfile to a real build invocation downstream.
async fn analyze_pinned_mirror(
    config: &StowConfig,
    mirror_project: &ProjectContext,
) -> Option<WorkspacePrediction> {
    match analyze_workspace_prediction(
        mirror_project,
        mirror_project.current_dir(),
        &mirror_project.manifest_path,
        config,
        None,
    )
    .await
    {
        Ok(analysis) => {
            tracing::info!(
                expanded_cached = analysis.expanded_cached,
                expanded_total = analysis.expanded_total,
                prefetch_artifacts = analysis.prefetch_artifacts.len(),
                "post-pin mirror graph analysis succeeded"
            );
            Some(analysis)
        }
        Err(error) => {
            tracing::info!(
                %error,
                "post-pin mirror graph analysis failed; falling back to vanilla cargo passthrough"
            );
            None
        }
    }
}

/// Run cargo against a `PinnedMirror` whose analysis succeeded: the
/// top-crate cached-deps fast path when it applies, otherwise cargo under
/// the wrapper with the pinned graph's cache plan. `Some` carries cargo's
/// own exit status — success or not (stow#652).
async fn run_pinned_mirror_build(
    config: &StowConfig,
    project: &ProjectContext,
    invocation: &CargoInvocation,
    pinned: &PinnedMirror,
    public_cache_mode: &PublicCacheMode,
    mirror_analysis: WorkspacePrediction,
) -> stow_types::error::Result<Option<ExitStatus>> {
    let mirror_unit_nodes = mirror_analysis.unit_nodes.clone();
    let mirror_prefetch = mirror_analysis.prefetch_artifacts.clone();
    let mirror_servable = mirror_analysis.servable_units.clone();
    let mirror_semantic_fallback = mirror_unit_nodes
        .as_ref()
        .is_some_and(|table| !table.nodes.is_empty());

    // The resolver path builds its own graph analysis for the pinned mirror,
    // so it sizes its own allowance from that.
    let budget = CacheBudget::for_covered_units(mirror_prefetch.len());

    let cache_policy_entries = prepare_build_cache_plan(
        Some(config),
        project,
        &pinned.mirror.current_dir(),
        &pinned.manifest_path,
        public_cache_mode,
        Some(mirror_analysis),
        &budget,
    )
    .await?;

    match try_run_top_crate_with_cached_dependencies(
        config,
        &pinned.project,
        &invocation.action,
        &pinned.args,
        cache_policy_entries.as_deref(),
        Some(&mirror_prefetch),
        &budget,
    )
    .await
    {
        // `Some` ends the command even on a failing status — see
        // `try_run_top_crate_with_cached_dependencies`.
        Ok(Some(status)) => return Ok(Some(status)),
        Ok(None) => {
            tracing::info!(
                "top-crate cached-deps fast path not applicable; running cargo with wrapper injection"
            );
        }
        Err(error) => {
            tracing::info!(
                %error,
                "top-crate cached-deps fast path unsatisfied; running cargo with wrapper injection"
            );
        }
    }

    let mirror_current_dir = pinned.mirror.current_dir();
    run_cargo(&CargoRunPlan {
        project,
        config: Some(config),
        state_db: &config.state_db,
        action: &invocation.action,
        cargo_args: &pinned.args,
        source_root: pinned.mirror.root(),
        current_dir: &mirror_current_dir,
        cache_policy_entries: cache_policy_entries.as_deref(),
        public_cache_mode,
        unit_nodes: mirror_unit_nodes.as_ref(),
        prefetch_artifacts: Some(&mirror_prefetch),
        servable_units: mirror_servable.as_ref(),
        deferred_analysis: false,
        semantic_fallback_enabled: mirror_semantic_fallback,
        extra_rustflags: &[],
        covered_units: mirror_prefetch.len(),
    })
    .await
    .map(Some)
}

async fn collect_user_direct_dependencies(
    manifest_path: &Path,
    workspace_root: &Path,
    metadata_args: &MetadataArgs,
) -> stow_types::error::Result<Vec<lockfile_resolver::DirectDependency>> {
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::<String>::new();

    // Always read the project's selected manifest (the entry-point Cargo.toml).
    collect_dependencies_from_manifest(manifest_path, metadata_args, &mut out, &mut seen).await?;

    // For workspace projects, every member contributes direct deps from the
    // user's perspective — the root manifest typically only carries
    // `[workspace]` and shared `[workspace.dependencies]`. Walk every
    // `members` entry so we capture e.g. clap_builder/clap_derive deps when
    // running `stow check` from the workspace root.
    // Collect the member patterns into owned strings up front: the parsed
    // toml document holds non-Send iterators, so it must be dropped before
    // the per-member awaits below.
    let workspace_root_manifest = workspace_root.join("Cargo.toml");
    let member_patterns: Vec<String> = if let Ok(text) =
        async_fs::read_to_string(&workspace_root_manifest).await
        && let Ok(document) = text.parse::<toml_edit::DocumentMut>()
        && let Some(workspace_table) = document
            .get("workspace")
            .and_then(toml_edit::Item::as_table_like)
        && let Some(members_array) = workspace_table
            .get("members")
            .and_then(|item| item.as_array())
    {
        members_array
            .iter()
            .filter_map(|entry| entry.as_str().map(str::to_owned))
            .collect()
    } else {
        Vec::new()
    };
    for member_pattern in member_patterns {
        let resolved_members = expand_member_pattern(workspace_root, &member_pattern);
        for member_dir in resolved_members {
            let manifest = member_dir.join("Cargo.toml");
            if !manifest.exists() {
                continue;
            }
            if let Err(error) =
                collect_dependencies_from_manifest(&manifest, metadata_args, &mut out, &mut seen)
                    .await
            {
                tracing::debug!(
                    manifest = %manifest.display(),
                    %error,
                    "skipping workspace member with unreadable manifest"
                );
            }
        }
    }
    // Workspace-level [workspace.dependencies] is not directly the
    // user's compile graph (members opt in via `dep = { workspace = true }`),
    // so we don't unconditionally include it; the per-member walk above
    // catches whatever members actually use.

    Ok(out)
}

async fn collect_dependencies_from_manifest(
    manifest_path: &Path,
    metadata_args: &MetadataArgs,
    out: &mut Vec<lockfile_resolver::DirectDependency>,
    seen: &mut std::collections::BTreeSet<String>,
) -> stow_types::error::Result<()> {
    let manifest_text = async_fs::read_to_string(manifest_path)
        .await
        .map_err(|error| {
            stow_types::stow_error!("read manifest {}: {error}", manifest_path.display())
        })?;
    let document = manifest_text
        .parse::<toml_edit::DocumentMut>()
        .wrap_err_with(|| format!("parse manifest {}", manifest_path.display()))?;
    // Optional deps: an optional dep is in cargo's lockfile iff it is
    // activated by some feature in the active feature set. We resolve
    // the manifest's feature graph (default features unless the user
    // passed `--no-default-features`) once per manifest and use that to
    // decide whether each optional ships to the resolver.
    let enabled_optional_deps =
        match workspace_deps::enabled_optional_dependency_names(manifest_path, metadata_args) {
            Ok(set) => set,
            Err(error) => {
                tracing::debug!(
                    manifest = %manifest_path.display(),
                    %error,
                    "feature graph parse failed; skipping optional-dep activation check"
                );
                std::collections::BTreeSet::new()
            }
        };
    // Only `[dependencies]` participate in the resolver's seed search.
    // `[build-dependencies]` compile under a separate context with their
    // own c_metadata chains; a binary preheat captures only the runtime
    // closure, so mixing them in here makes find_seed_artifact reject
    // every otherwise-valid candidate. Build-deps still get handled by
    // cargo's own resolver in the fall-back path.
    let Some(table) = document
        .get("dependencies")
        .and_then(toml_edit::Item::as_table_like)
    else {
        return Ok(());
    };
    for (name, item) in table.iter() {
        let Some(req) = extract_dependency_req(item) else {
            continue;
        };
        // Optional dep that no active feature activates? cargo doesn't
        // pin it in `Cargo.lock`, so the resolver shouldn't seed-search
        // for a candidate either — its absence from the closure is
        // intentional. Including it would reject every otherwise-valid
        // seed (e.g., bat's `execute` is gated by the `lessopen`
        // feature, which `default` does not activate; preheat closures
        // skip it, and so should the resolver request).
        if dependency_is_optional(item) && !enabled_optional_deps.contains(name) {
            continue;
        }
        let Ok(crate_name) = stow_types::identity::CrateName::parse(name) else {
            continue;
        };
        if !seen.insert(crate_name.as_str().to_owned()) {
            continue;
        }
        let features = extract_dependency_features(item);
        out.push(lockfile_resolver::DirectDependency {
            crate_name,
            req,
            features,
        });
    }
    Ok(())
}

fn dependency_is_optional(item: &toml_edit::Item) -> bool {
    match item {
        toml_edit::Item::Value(toml_edit::Value::InlineTable(table)) => table
            .get("optional")
            .and_then(toml_edit::Value::as_bool)
            .unwrap_or(false),
        toml_edit::Item::Table(table) => table
            .get("optional")
            .and_then(|item| item.as_value())
            .and_then(toml_edit::Value::as_bool)
            .unwrap_or(false),
        _ => false,
    }
}

/// Resolve a `[workspace] members = ["..."]` glob entry into concrete
/// directories. Supports literal names and a single trailing `*` wildcard
/// — the two patterns Cargo's own resolver actually uses in practice. More
/// exotic globs fall back to "treat as literal", which is harmless: the
/// caller will simply skip the missing manifest.
fn expand_member_pattern(workspace_root: &Path, pattern: &str) -> Vec<PathBuf> {
    if !pattern.contains('*') {
        return vec![workspace_root.join(pattern)];
    }
    let prefix = pattern.trim_end_matches('*').trim_end_matches('/');
    let dir = if prefix.is_empty() {
        workspace_root.to_path_buf()
    } else {
        workspace_root.join(prefix)
    };
    let mut entries = Vec::new();
    let Ok(read_dir) = std::fs::read_dir(&dir) else {
        return entries;
    };
    for child in read_dir.flatten() {
        if child.file_type().is_ok_and(|kind| kind.is_dir()) {
            entries.push(child.path());
        }
    }
    entries
}

fn extract_dependency_req(item: &toml_edit::Item) -> Option<String> {
    match item {
        toml_edit::Item::Value(toml_edit::Value::String(value)) => Some(value.value().clone()),
        toml_edit::Item::Value(toml_edit::Value::InlineTable(table)) => table
            .get("version")
            .and_then(|value| value.as_str())
            .map(str::to_owned),
        toml_edit::Item::Table(table) => table
            .get("version")
            .and_then(|item| item.as_str())
            .map(str::to_owned),
        _ => None,
    }
}

fn extract_dependency_features(item: &toml_edit::Item) -> Vec<String> {
    let (features_array, default_features_default) = match item {
        toml_edit::Item::Value(toml_edit::Value::String(_)) => return vec!["default".to_owned()],
        toml_edit::Item::Value(toml_edit::Value::InlineTable(table)) => (
            table.get("features").and_then(|value| value.as_array()),
            table
                .get("default-features")
                .and_then(toml_edit::Value::as_bool)
                .unwrap_or(true),
        ),
        toml_edit::Item::Table(table) => (
            table.get("features").and_then(|item| item.as_array()),
            table
                .get("default-features")
                .and_then(|item| item.as_value())
                .and_then(toml_edit::Value::as_bool)
                .unwrap_or(true),
        ),
        _ => return Vec::new(),
    };
    let mut features = Vec::new();
    if default_features_default {
        features.push("default".to_owned());
    }
    if let Some(array) = features_array {
        for entry in array {
            if let Some(value) = entry.as_str() {
                features.push(value.to_owned());
            }
        }
    }
    features.sort();
    features.dedup();
    features
}

async fn write_lockfile_into_mirror(
    mirror: &WorkspaceMirror,
    lockfile_toml: &str,
) -> stow_types::error::Result<()> {
    let target = mirror.root().join("Cargo.lock");
    async_fs::write(&target, lockfile_toml)
        .await
        .map_err(|error| {
            stow_types::stow_error!(
                "write pinned lockfile to mirror {}: {error}",
                target.display()
            )
        })
}

/// Run `cargo metadata --locked --no-deps --offline` against the pinned
/// mirror. cargo's resolver loads `Cargo.lock` strictly under `--locked`
/// and rejects anything that violates the workspace `Cargo.toml`'s semver
/// or feature requirements at the root level. A non-zero exit means the
/// candidate lockfile is incompatible — caller falls back to passthrough.
///
/// `--no-deps` skips the heavy transitive-graph hydration; we only need
/// cargo to confirm the resolver can satisfy the root constraints under
/// `--locked`. We deliberately do NOT hydrate dev-dependencies/
/// build-dependencies here — the resolver synthesizes a runtime-graph
/// lockfile, and forcing dev-dep coverage would reject every project
/// with a `[dev-dependencies]` table even though `cargo check` works
/// fine without those pins. The downstream pipeline catches incomplete
/// pins via `try_run_top_crate_with_cached_dependencies` /
/// `analyze_workspace_prediction`, and falls back to passthrough then.
async fn validate_pinned_lockfile(
    mirror_project: &ProjectContext,
) -> stow_types::error::Result<bool> {
    let mut command = async_process::Command::new("cargo");
    command
        .arg("metadata")
        .arg("--locked")
        .arg("--no-deps")
        .arg("--offline")
        .arg("--format-version")
        .arg("1")
        .arg("--manifest-path")
        .arg(&mirror_project.manifest_path)
        .stdout(async_process::Stdio::null())
        .stderr(async_process::Stdio::piped());
    let output = command.output().await.map_err(|error| {
        stow_types::stow_error!("invoke cargo metadata --locked dry-run: {error}")
    })?;
    if output.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    tracing::debug!(
        status = %output.status,
        manifest = %mirror_project.manifest_path.display(),
        %stderr,
        "cargo metadata --locked rejected pinned lockfile"
    );
    Ok(false)
}

/// `Some` carries cargo's own exit status — success or not — because a
/// path that ran cargo has finished the command: a failing status is
/// the command's answer, never a "not served" that may fall through to
/// a second cargo run (stow#652). `None` is the fast path declining to
/// run cargo at all.
async fn try_run_top_crate_with_cached_dependencies(
    config: &StowConfig,
    project: &ProjectContext,
    action: &str,
    cargo_args: &[OsString],
    cache_policy_entries: Option<&[CachePolicyEntry]>,
    prefetch_artifacts: Option<&[PrefetchArtifact]>,
    budget: &CacheBudget,
) -> stow_types::error::Result<Option<ExitStatus>> {
    let Some(shape) = cached_dependency_shape(action) else {
        return Ok(None);
    };
    if !prebuilt_deps_path_enabled() {
        return Ok(None);
    }
    if budget.is_exhausted() {
        tracing::info!(
            budget_ms = budget.total().as_millis(),
            "pre-cargo cache budget spent; handing over to cargo without the prebuilt-deps path"
        );
        return Ok(None);
    }
    // Warm the local cache with one batched fetch before the closure walk:
    // the walk itself only reads locally, and filling it one artifact at a
    // time through per-crate GETs is the dominant cost of a fresh run.
    if let Some(artifacts) = prefetch_artifacts
        && !artifacts.is_empty()
        && let Err(error) = prefetch::warm_exact_artifacts(config, artifacts, budget).await
    {
        // A cold local cache just means the closure walk below finds nothing
        // and this path declines; it must not fail the build.
        tracing::warn!(%error, "prefetch for the prebuilt-deps path failed");
        return Ok(None);
    }
    // The selected packages' direct registry externs ride the same
    // `--unit-graph` resolve as the expanded graph (and its cache), so
    // the top-crate path pays no second resolution.
    let expanded = expanded_graph(config, project, &project.manifest_path, None).await?;
    if expanded.direct_dependencies.is_empty() {
        return Ok(None);
    }
    // Host-side units mint at the runner family's host triple — the same
    // platform `expanded_graph` resolves with.
    let host_triple = stow_types::api::runner_family(&project.target)
        .map_or(project.target.as_str(), |family| family.host_triple());
    let build_script_packages = build_script_packages(&expanded.task_units(
        project.target_given.then_some(project.target.as_str()),
        host_triple,
    )?);
    let plan =
        resolve_cached_dependency_plan(config, project, &expanded.direct_dependencies, &shape)
            .await?;

    let target_dir = resolved_target_dir(project, cargo_args, &project.current_dir);
    let prebuilt_dir = target_dir.join("stow-prebuilt").join(action).join("deps");
    refuse_build_script_dependencies(action, &plan, &build_script_packages)?;
    materialize_cached_dependency_plan(&prebuilt_dir, &plan).await?;
    // Every bundle in the plan replaces one dependency compilation; make the
    // acceleration visible in `stow status` exactly like wrapper-level hits.
    for bundle in plan.bundles.values() {
        log_nonfatal_result(
            "failed to record rust cache hit stats",
            crate::stats::record_hit(config, &bundle.crate_name).await,
        );
    }
    let rustflags = top_crate_rustflags(&prebuilt_dir, &plan, &shape)?;

    let mirror = create_workspace_mirror(project, &project.workspace_root).await?;
    strip_selected_manifest_dependencies(project, &mirror).await?;
    regenerate_mirror_lockfile(project, &mirror).await?;
    let mirror_args = rewrite_args_for_mirror(cargo_args, project, &mirror)?;
    let mirror_current_dir = mirror.current_dir();
    run_cargo(&CargoRunPlan {
        project,
        config: Some(config),
        state_db: &config.state_db,
        action,
        cargo_args: &mirror_args,
        source_root: &project.workspace_root,
        current_dir: &mirror_current_dir,
        cache_policy_entries,
        public_cache_mode: &PublicCacheMode::for_rustc(&project.rustc_version),
        unit_nodes: None,
        prefetch_artifacts: None,
        servable_units: None,
        deferred_analysis: false,
        semantic_fallback_enabled: false,
        extra_rustflags: &rustflags,
        covered_units: plan.bundles.len(),
    })
    .await
    .map(Some)
}

/// Opt-in for the prebuilt-deps path, off by default.
///
/// The path compiles the top crate alone against a closure of cached rlibs,
/// stripping `[dependencies]` from a mirrored manifest and passing
/// `--extern` plus `-Ldependency=<prebuilt>`. It is fast when it works, but
/// it has produced two distinct classes of broken build: stripping
/// `[build-dependencies]` left `build.rs` unable to compile, and keeping them
/// puts the same crate in both cargo's `deps` directory and the prebuilt one,
/// so rustc reports "multiple candidates for rlib dependency". Getting it
/// right needs exact control of rustc's search path for the whole transitive
/// closure, not just the direct externs. A `build` against it refuses any
/// cached dependency whose package has a build script, since this path runs
/// none.
///
/// The per-rustc wrapper reaches the same artifacts without any of that: it
/// serves each unit in place, under cargo's own unit graph. On the twelve
/// projects in `docs/acceleration-audit.md` it lands within noise of this
/// path where both work. Until the search-path handling is right, correctness
/// wins — a broken build is worse than a slow one.
fn prebuilt_deps_path_enabled() -> bool {
    std::env::var_os("STOW_ENABLE_PREBUILT_DEPS").is_some_and(|value| value != "0")
}

fn cached_dependency_shape(action: &str) -> Option<CachedDependencyShape> {
    match action {
        "check" => Some(CachedDependencyShape {
            candidates: vec![
                rlib_dependency_shape(vec!["dep-info", "metadata"]),
                proc_macro_dependency_shape(),
                rlib_dependency_shape(vec!["dep-info", "link", "metadata"]),
            ],
            direct_preferred_media_types: vec![
                STOW_RMETA_MEDIA_TYPE,
                STOW_RLIB_MEDIA_TYPE,
                STOW_PROC_MACRO_MEDIA_TYPE,
            ],
        }),
        "build" => Some(CachedDependencyShape {
            candidates: vec![
                rlib_dependency_shape(vec!["dep-info", "link", "metadata"]),
                proc_macro_dependency_shape(),
            ],
            direct_preferred_media_types: vec![
                STOW_RLIB_MEDIA_TYPE,
                STOW_RMETA_MEDIA_TYPE,
                STOW_PROC_MACRO_MEDIA_TYPE,
            ],
        }),
        _ => None,
    }
}

fn rlib_dependency_shape(emit: Vec<&str>) -> CachedDependencyArtifactShape {
    CachedDependencyArtifactShape {
        emit: emit.into_iter().map(str::to_owned).collect(),
        kind: ArtifactKind::Rlib,
        crate_types: vec![RustCrateType::Lib],
    }
}

fn proc_macro_dependency_shape() -> CachedDependencyArtifactShape {
    CachedDependencyArtifactShape {
        emit: vec!["dep-info".to_owned(), "link".to_owned()],
        kind: ArtifactKind::ProcMacro,
        crate_types: vec![RustCrateType::ProcMacro],
    }
}

async fn resolve_cached_dependency_plan(
    config: &StowConfig,
    project: &ProjectContext,
    direct_dependencies: &[SelectedRegistryDependency],
    shape: &CachedDependencyShape,
) -> stow_types::error::Result<CachedDependencyPlan> {
    let mut bundles = BTreeMap::<String, crate::artifact_cache::CachedArtifactBundle>::new();
    let mut direct_externs = Vec::with_capacity(direct_dependencies.len());
    // One unit may carry several extern names — a renamed dependency
    // beside the plain one, or a dep used on both sides — so rows fold
    // on the compile identity and emit every name the members recorded
    // (stow#551).
    let mut seen = BTreeSet::new();
    for dependency in direct_dependencies {
        if !seen.insert((
            dependency.crate_name.clone(),
            dependency.version.clone(),
            dependency.features.clone(),
        )) {
            continue;
        }
        let candidates =
            load_cached_dependency_bundle_candidates(config, project, dependency, shape).await?;
        let mut candidate_errors = Vec::new();
        let mut selected_c_metadata = None;
        for candidate in candidates {
            let c_metadata = candidate.c_metadata.clone();
            match collect_cached_bundle_closure(config, project, candidate, &mut bundles).await {
                Ok(()) => {
                    selected_c_metadata = Some(c_metadata);
                    break;
                }
                Err(error) => {
                    candidate_errors.push(error.to_string());
                }
            }
        }
        let c_metadata = selected_c_metadata.ok_or_else(|| {
            let reason = if candidate_errors.is_empty() {
                "no matching local semantic cache candidates".to_owned()
            } else {
                candidate_errors.join("; ")
            };
            stow_types::stow_error!(
                "direct dependency {} {} cannot be satisfied from cached artifacts: {}",
                dependency.crate_name,
                dependency.version,
                reason
            )
        })?;
        direct_externs.extend(dependency.extern_names.iter().map(|extern_name| {
            CachedDirectExtern {
                extern_name: extern_name.clone(),
                c_metadata: c_metadata.clone(),
            }
        }));
    }

    Ok(CachedDependencyPlan {
        bundles,
        direct_externs,
    })
}

async fn load_cached_dependency_bundle_candidates(
    config: &StowConfig,
    project: &ProjectContext,
    dependency: &SelectedRegistryDependency,
    shape: &CachedDependencyShape,
) -> stow_types::error::Result<Vec<crate::artifact_cache::CachedArtifactBundle>> {
    let features_json = serde_json::to_string(&dependency.features)?;
    let mut bundles = BTreeMap::<String, crate::artifact_cache::CachedArtifactBundle>::new();
    for candidate in &shape.candidates {
        let request = SemanticFetchRequest {
            crate_name: dependency.crate_name.clone(),
            version: dependency.version.to_string(),
            features_json: features_json.clone(),
            dependency_c_metadata_json: String::new(),
            target: project.target.clone(),
            rustc_version: project.rustc_version.clone(),
            profile: cached_dependency_profile(),
            emit: candidate.emit.clone(),
            kind: candidate.kind.clone(),
            crate_types: candidate.crate_types.clone(),
        };
        for bundle in
            crate::artifact_cache::load_semantic_cached_bundle_candidates(config, &request).await?
        {
            if bundle.crate_version != dependency.version.to_string() {
                continue;
            }
            bundles.entry(bundle.c_metadata.clone()).or_insert(bundle);
        }
    }
    Ok(bundles.into_values().collect())
}

async fn collect_cached_bundle_closure(
    config: &StowConfig,
    project: &ProjectContext,
    root: crate::artifact_cache::CachedArtifactBundle,
    bundles: &mut BTreeMap<String, crate::artifact_cache::CachedArtifactBundle>,
) -> stow_types::error::Result<()> {
    let mut stack = vec![root];
    let mut candidate_c_metadata = BTreeSet::<String>::new();
    let mut candidate_bundles = Vec::new();
    while let Some(bundle) = stack.pop() {
        let c_metadata = bundle.c_metadata.clone();
        if bundles.contains_key(&c_metadata) || candidate_c_metadata.contains(&c_metadata) {
            continue;
        }
        let dependencies = cached_bundle_dependencies(&bundle)?;
        candidate_c_metadata.insert(c_metadata.clone());
        for dependency in dependencies {
            if bundles.contains_key(&dependency.c_metadata)
                || candidate_c_metadata.contains(&dependency.c_metadata)
            {
                continue;
            }
            let dependency_bundle = crate::artifact_cache::load_cached_bundle(
                config,
                &FetchRequest {
                    target: &project.target,
                    rustc_version: &project.rustc_version,
                    c_metadata: &dependency.c_metadata,
                },
            )
            .await?
            .ok_or_else(|| {
                stow_types::stow_error!(
                    "cached artifact dependency {} ({}) referenced by {} is missing locally",
                    dependency.crate_name,
                    dependency.c_metadata,
                    c_metadata
                )
            })?;
            stack.push(dependency_bundle);
        }
        candidate_bundles.push(bundle);
    }
    for bundle in candidate_bundles {
        bundles.insert(bundle.c_metadata.clone(), bundle);
    }
    Ok(())
}

fn cached_bundle_dependencies(
    bundle: &crate::artifact_cache::CachedArtifactBundle,
) -> stow_types::error::Result<Vec<DependencyCMetadataIdentity>> {
    serde_json::from_str(&bundle.dependency_c_metadata_json).wrap_err_with(|| {
        format!(
            "parse cached dependency metadata for {} {} ({})",
            bundle.crate_name, bundle.crate_version, bundle.c_metadata
        )
    })
}

/// The profile the generic top-crate pool is built under: cargo's default
/// `dev` profile (`debug = true`, i.e. `debuginfo == 2`).
///
/// The prebuilt-dependency plan is matched verbatim against the stored
/// `profile_json` in the local semantic cache, so it serves only artifacts
/// from that pool; a workspace that tunes its dev profile takes its hits
/// through the per-unit wrapper path, which derives the profile from the
/// real rustc arguments.
fn cached_dependency_profile() -> Profile {
    Profile {
        opt_level: "0".to_owned(),
        debuginfo: 2,
        debug_assertions: true,
        overflow_checks: true,
        panic: PanicStrategy::Unwind,
        strip: stow_types::platform::StripLevel::None,
    }
}

async fn materialize_cached_dependency_plan(
    prebuilt_dir: &Path,
    plan: &CachedDependencyPlan,
) -> stow_types::error::Result<()> {
    async_fs::create_dir_all(prebuilt_dir)
        .await
        .wrap_err_with(|| format!("create prebuilt dependency dir {}", prebuilt_dir.display()))?;
    for bundle in plan.bundles.values() {
        for output in &bundle.outputs {
            let source_path = bundle.output_source_path(output);
            let output_path = prebuilt_dir.join(&output.file_name);
            inject::write_cached_output(
                &source_path,
                &output_path,
                Some(&output.sha256),
                inject::OutputDirWriters::StowOnly,
            )
            .await?;
        }
    }
    Ok(())
}

/// The `(crate name, version)` of every package in the unit graph that has
/// a build script — a `RunBuildScript` unit exists exactly for those.
fn build_script_packages(units: &[stow_types::unit_graph::TaskUnit]) -> BTreeSet<(String, String)> {
    units
        .iter()
        .filter(|unit| unit.key.kind == stow_types::unit_graph::TaskUnitKind::RunBuildScript)
        .map(|unit| (unit.name.clone(), unit.version.clone()))
        .collect()
}

/// The prebuilt-deps path compiles the top crate alone and runs no build
/// script at all, so `build` cannot use a cached dependency whose package
/// has one — its `cargo:` directives and `OUT_DIR` products would never be
/// produced. `check` links nothing, so the set does not apply there.
fn refuse_build_script_dependencies(
    action: &str,
    plan: &CachedDependencyPlan,
    build_script_packages: &BTreeSet<(String, String)>,
) -> stow_types::error::Result<()> {
    if action != "build" {
        return Ok(());
    }

    for bundle in plan.bundles.values() {
        if build_script_packages
            .contains(&(bundle.crate_name.clone(), bundle.crate_version.clone()))
        {
            return Err(stow_types::stow_error!(
                "the prebuilt-deps path cannot build against {} {}: the crate has a build script, and this path runs none",
                bundle.crate_name,
                bundle.crate_version
            ));
        }
    }

    Ok(())
}

fn top_crate_rustflags(
    prebuilt_dir: &Path,
    plan: &CachedDependencyPlan,
    shape: &CachedDependencyShape,
) -> stow_types::error::Result<Vec<String>> {
    let mut flags = vec![format!(
        "-Ldependency={}",
        path_as_rustflag(prebuilt_dir, "prebuilt dependency dir")?
    )];
    for direct in &plan.direct_externs {
        let bundle = plan.bundles.get(&direct.c_metadata).ok_or_else(|| {
            stow_types::stow_error!(
                "missing cached bundle for direct extern {}",
                direct.extern_name
            )
        })?;
        let output = preferred_direct_output(bundle, &shape.direct_preferred_media_types)
            .ok_or_else(|| {
                stow_types::stow_error!(
                    "cached bundle for direct extern {} has no usable output; preferred media types: {}",
                    direct.extern_name,
                    shape.direct_preferred_media_types.join(", ")
                )
            })?;
        let output_path = prebuilt_dir.join(&output.file_name);
        let output_path = path_as_rustflag(&output_path, "prebuilt dependency output")?;
        flags.push(format!("--extern={}={output_path}", direct.extern_name));
    }
    Ok(flags)
}

fn preferred_direct_output<'a>(
    bundle: &'a crate::artifact_cache::CachedArtifactBundle,
    media_types: &[&str],
) -> Option<&'a stow_types::bundle::ArtifactBundleFile> {
    media_types.iter().find_map(|media_type| {
        bundle
            .outputs
            .iter()
            .find(|output| output.media_type == *media_type)
    })
}

fn path_as_rustflag(path: &Path, label: &str) -> stow_types::error::Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| stow_types::stow_error!("{label} {} is not UTF-8", path.display()))?;
    if value.chars().any(char::is_whitespace) {
        return Err(stow_types::stow_error!(
            "{label} {} contains whitespace and cannot be passed through RUSTFLAGS",
            path.display()
        ));
    }
    Ok(value.to_owned())
}

fn into_api_dependency(
    dependency: ResolvedDependency,
) -> stow_types::error::Result<DependencyGraphEntry> {
    let crate_name = stow_types::identity::CrateName::parse(dependency.crate_name.as_str())
        .map_err(|error| {
            stow_types::stow_error!(
                "invalid resolved dependency crate_name `{}`: {error}",
                dependency.crate_name
            )
        })?;
    Ok(DependencyGraphEntry {
        crate_name,
        version: dependency.version,
        features: dependency.features,
    })
}

fn validate_analysis_entry(entry: &resolve::AnalysisEntry) -> stow_types::error::Result<()> {
    let current_artifact_count = u32::try_from(entry.current_artifacts.len()).map_err(|_| {
        stow_types::stow_error!(
            "resolver produced more than u32::MAX exact artifacts for {} {}",
            entry.dependency.crate_name,
            entry.dependency.version
        )
    })?;
    if entry.current_artifact_count != current_artifact_count {
        return Err(stow_types::stow_error!(
            "resolver produced inconsistent exact artifact count for {} {}",
            entry.dependency.crate_name,
            entry.dependency.version
        ));
    }
    if let Some(recommended) = &entry.recommended {
        if !is_semver_compatible_upgrade(&entry.dependency.version, &recommended.version) {
            return Err(stow_types::stow_error!(
                "resolver produced invalid upgrade for {}: {} -> {}",
                entry.dependency.crate_name,
                entry.dependency.version,
                recommended.version
            ));
        }
        if recommended.artifact_count <= entry.current_artifact_count {
            return Err(stow_types::stow_error!(
                "resolver produced non-improving upgrade for {}: {} -> {}",
                entry.dependency.crate_name,
                entry.current_artifact_count,
                recommended.artifact_count
            ));
        }
    }
    Ok(())
}

async fn prefetch_graph_artifacts(
    config: &StowConfig,
    artifacts: &[PrefetchArtifact],
    budget: &CacheBudget,
) -> stow_types::error::Result<()> {
    if artifacts.is_empty() {
        return Ok(());
    }
    let summary = prefetch::warm_exact_artifacts(config, artifacts, budget).await?;
    if summary.failed > 0 {
        tracing::warn!(
            failed = summary.failed,
            total = summary.total(),
            "some exact graph artifact prefetches failed; cargo will continue and runtime fetch may still be needed"
        );
    }
    Ok(())
}

async fn prepare_build_cache_plan(
    config: Option<&StowConfig>,
    project: &ProjectContext,
    current_dir: &Path,
    manifest_path: &Path,
    public_cache_mode: &PublicCacheMode,
    precomputed_analysis: Option<WorkspacePrediction>,
    budget: &CacheBudget,
) -> stow_types::error::Result<Option<Vec<CachePolicyEntry>>> {
    let Some(config) = config else {
        return Ok(None);
    };
    if !public_cache_mode.is_enabled() {
        return Ok(None);
    }

    let analysis = match precomputed_analysis {
        Some(analysis) => analysis,
        None => {
            match analyze_workspace_prediction(project, current_dir, manifest_path, config, None)
                .await
            {
                Ok(analysis) => analysis,
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        current_dir = %current_dir.display(),
                        manifest_path = %manifest_path.display(),
                        "failed to analyze build graph for exact artifact prefetch"
                    );
                    return Ok(None);
                }
            }
        }
    };

    // Never fatal. Prefetch is an optimization: the per-rustc wrapper fetches
    // whatever is missing on demand, and cargo compiles whatever it cannot
    // fetch. Propagating the error here meant a degraded edge - one HTTP 500
    // on one batch - failed `stow build` outright, which is not "slower than
    // cargo", it is broken.
    if let Err(error) = prefetch_graph_artifacts(config, &analysis.prefetch_artifacts, budget).await
    {
        tracing::warn!(
            %error,
            manifest_path = %manifest_path.display(),
            "exact graph artifact prefetch failed; the build continues and the \
             wrapper will fetch on demand"
        );
    }

    if analysis.cache_policy_entries.is_empty() {
        return Ok(None);
    }

    Ok(Some(analysis.cache_policy_entries))
}

/// The allow entries a deferred-analysis build starts cargo with: none
/// yet. They come from the graph analysis, which now runs while cargo
/// builds and commits them through the enrichment's
/// `write_policy_entries`; the supervisor and the facades read the
/// directory per plan call, so markers land mid-build and gate the units
/// they name from the write onward (stow#347).
///
/// An empty directory denies every public-cache serve until the
/// enrichment commits — the conservative answer, and the right one for
/// an all-miss build, where nothing is servable anyway. Only a build
/// whose lite pass already found coverage (`analysis` is `Some`) gets a
/// policy at all; `None` leaves the wrapper treating every invocation
/// as allowed.
fn deferred_cache_policy(
    config: Option<&StowConfig>,
    public_cache_mode: &PublicCacheMode,
    analysis: Option<&WorkspacePrediction>,
) -> Option<Vec<CachePolicyEntry>> {
    (config.is_some() && public_cache_mode.is_enabled() && analysis.is_some()).then(Vec::new)
}

async fn select_upgrades(
    analysis: Option<&WorkspacePrediction>,
    silent_compatible_upgrades: bool,
) -> stow_types::error::Result<Vec<CompatibleUpgrade>> {
    let Some(analysis) = analysis else {
        return Ok(Vec::new());
    };
    if analysis.candidates.is_empty() {
        return Ok(Vec::new());
    }
    if silent_compatible_upgrades {
        return Ok(root_candidate_upgrades(analysis));
    }

    if !io::stdin().is_terminal() {
        return Ok(Vec::new());
    }

    let summary = render_upgrade_summary(analysis);
    write_stdout(&summary)?;
    write_stdout("Apply all recommended compatible upgrades for this run? [y/N] ")?;
    smol::unblock(read_confirmation).await.map(|yes| {
        if yes {
            analysis.candidates.clone()
        } else {
            Vec::new()
        }
    })
}

fn render_upgrade_summary(analysis: &WorkspacePrediction) -> String {
    let mut lines = Vec::new();
    let upgraded_cached = predicted_cached_after_upgrades(analysis);
    lines.push(format!(
        "stow found {} compatible upgrade candidates that can improve semantic cache coverage ({} / {} -> {} / {}).",
        analysis.candidates.len(),
        analysis.current_cached,
        analysis.current_total,
        upgraded_cached,
        analysis.current_total,
    ));
    for candidate in analysis.candidates.iter().take(12) {
        lines.push(format!(
            "  {} {} -> {} ({} -> {} cached artifacts)",
            candidate.crate_name,
            candidate.from_version,
            candidate.to_version,
            candidate.current_artifact_count,
            candidate.upgraded_artifact_count
        ));
    }
    if analysis.candidates.len() > 12 {
        lines.push(format!("  ... and {} more", analysis.candidates.len() - 12));
    }
    format!("{}\n", lines.join("\n"))
}

fn root_candidate_upgrades(analysis: &WorkspacePrediction) -> Vec<CompatibleUpgrade> {
    let roots = analysis
        .candidates
        .iter()
        .filter(|candidate| candidate.is_root_candidate)
        .cloned()
        .collect::<Vec<_>>();
    if roots.is_empty() {
        return analysis.candidates.clone();
    }
    roots
}

fn render_prediction_summary(analysis: &WorkspacePrediction) -> String {
    let mut lines = vec![
        "stow semantic cache prediction for this workspace:".to_owned(),
        format!(
            "  index has rows for: {} / {} transitive dependencies ({:.1}%)",
            analysis.expanded_cached,
            analysis.expanded_total,
            percentage(analysis.expanded_cached, analysis.expanded_total),
        ),
        format!(
            "  direct deps fully covered (top-crate fast path): {} / {} ({:.1}%)",
            analysis.current_cached,
            analysis.current_total,
            percentage(analysis.current_cached, analysis.current_total),
        ),
        "    NOTE: 'index has rows for' is an upper bound — the runtime additionally requires the"
            .to_owned(),
        "    cached artifact's dependency_c_metadata_json to match the user's lockfile-resolved"
            .to_owned(),
        "    transitive graph. Realized hits track the 'top-crate fast path' line, which engages"
            .to_owned(),
        "    only when EVERY direct dep has a cached artifact (otherwise stow falls back to"
            .to_owned(),
        "    vanilla cargo). For arbitrary projects, populate the cache with `stow-admin"
            .to_owned(),
        "    preheat top-binaries` against the matching binary lockfile.".to_owned(),
    ];

    if !analysis.candidates.is_empty() {
        let upgraded_cached = predicted_cached_after_upgrades(analysis);
        lines.push(format!(
            "  recommended compatible upgrades: {} / {} direct deps would gain cached artifacts ({:.1}%)",
            upgraded_cached,
            analysis.current_total,
            percentage(upgraded_cached, analysis.current_total),
        ));
    }

    if !analysis.missing_current.is_empty() {
        lines.push("top currently uncached dependencies:".to_owned());
        for dep in analysis.missing_current.iter().take(12) {
            lines.push(format!("  {} {}", dep.crate_name, dep.version));
        }
        if analysis.missing_current.len() > 12 {
            lines.push(format!(
                "  ... and {} more",
                analysis.missing_current.len() - 12
            ));
        }
    }

    if !analysis.candidates.is_empty() {
        lines.push(String::new());
        lines.push(render_upgrade_summary(analysis).trim_end().to_owned());
    }

    format!("{}\n", lines.join("\n"))
}

fn render_prediction_failure(config: &StowConfig, error: &stow_types::error::Error) -> String {
    let reason = error.to_string();
    let networkish = [
        "Connection refused",
        "timed out",
        "network error",
        "Connection reset",
        "os error",
    ];
    if networkish.iter().any(|pattern| reason.contains(pattern)) {
        return format!(
            "stow predict could not reach the cache catalog at {}.\nThe workspace is still buildable, but cache prediction is unavailable right now.\nreason: {}\n",
            config.edge_url, reason,
        );
    }

    format!("stow predict could not compute cache coverage for this workspace.\nreason: {reason}\n")
}

fn read_confirmation() -> stow_types::error::Result<bool> {
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .wrap_err("read upgrade confirmation from stdin")?;
    Ok(matches!(input.trim(), "y" | "Y" | "yes" | "YES"))
}

fn predicted_cached_after_upgrades(analysis: &WorkspacePrediction) -> usize {
    analysis
        .candidates
        .iter()
        .fold(analysis.current_cached, |cached, candidate| {
            if candidate.upgraded_artifact_count > candidate.current_artifact_count {
                cached.saturating_add(1)
            } else {
                cached
            }
        })
}

fn mark_root_candidates(
    candidates: &mut [CompatibleUpgrade],
    parents_by_package: &BTreeMap<PackageKey, Vec<PackageKey>>,
) {
    let candidate_keys = candidates
        .iter()
        .map(|candidate| candidate.package_key.clone())
        .collect::<BTreeSet<_>>();
    for candidate in candidates {
        candidate.is_root_candidate =
            !has_candidate_ancestor(&candidate.package_key, &candidate_keys, parents_by_package);
    }
}

fn has_candidate_ancestor(
    package_key: &PackageKey,
    candidate_keys: &BTreeSet<PackageKey>,
    parents_by_package: &BTreeMap<PackageKey, Vec<PackageKey>>,
) -> bool {
    let mut stack = parents_by_package
        .get(package_key)
        .cloned()
        .unwrap_or_default();
    let mut visited = BTreeSet::<PackageKey>::new();
    while let Some(parent) = stack.pop() {
        if !visited.insert(parent.clone()) {
            continue;
        }
        if candidate_keys.contains(&parent) {
            return true;
        }
        if let Some(next_parents) = parents_by_package.get(&parent) {
            stack.extend(next_parents.iter().cloned());
        }
    }
    false
}

#[derive(Debug)]
struct WorkspaceMirror {
    tempdir: TempDir,
    current_dir_relative: PathBuf,
}

impl WorkspaceMirror {
    fn root(&self) -> &Path {
        self.tempdir.path()
    }

    fn current_dir(&self) -> PathBuf {
        self.root().join(&self.current_dir_relative)
    }
}

async fn create_workspace_mirror(
    project: &ProjectContext,
    source_root: &Path,
) -> stow_types::error::Result<WorkspaceMirror> {
    let workspace_root = source_root.to_path_buf();
    let current_dir_relative = project.current_dir_relative.clone();
    smol::unblock(move || {
        let tempdir = TempDir::new().wrap_err("create workspace mirror tempdir")?;
        let mirror_root = tempdir.path().to_path_buf();

        for entry in std::fs::read_dir(&workspace_root)
            .wrap_err_with(|| format!("read workspace root {}", workspace_root.display()))?
        {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();
            if matches!(file_name_str.as_ref(), ".git" | "target") {
                continue;
            }

            let source_path = entry.path();
            let destination_path = mirror_root.join(&file_name);
            if file_name_str == "Cargo.lock" {
                std::fs::copy(&source_path, &destination_path).wrap_err_with(|| {
                    format!(
                        "copy {} into workspace mirror {}",
                        source_path.display(),
                        destination_path.display()
                    )
                })?;
                continue;
            }

            symlink_path(&source_path, &destination_path).wrap_err_with(|| {
                format!(
                    "symlink {} into workspace mirror {}",
                    source_path.display(),
                    destination_path.display()
                )
            })?;
        }

        Ok(WorkspaceMirror {
            tempdir,
            current_dir_relative,
        })
    })
    .await
}

/// Replace every symlink on `manifest_path`'s chain inside the mirror with
/// a real entry, so rewriting the mirror manifest can never reach the
/// user's workspace.
///
/// The mirror is a directory of symlinks into the source workspace, so
/// `mirror/<member>/Cargo.toml` resolves through the `mirror/<member>`
/// link into the real member directory — a `remove_file` + `write` on it
/// would delete and rewrite the user's own `Cargo.toml`. A directory link
/// on the path is swapped for a real directory whose children re-point at
/// the originals, and the manifest link itself for a real file copy; only
/// the entries on the path are materialized, everything else stays a link.
async fn materialize_mirror_manifest(
    mirror: &WorkspaceMirror,
    manifest_path: &Path,
) -> stow_types::error::Result<()> {
    let mirror_root = mirror.root().to_path_buf();
    let manifest_path = manifest_path.to_path_buf();
    smol::unblock(move || {
        let relative = manifest_path.strip_prefix(&mirror_root).map_err(|_| {
            stow_types::stow_error!(
                "manifest {} is outside workspace mirror {}",
                manifest_path.display(),
                mirror_root.display()
            )
        })?;
        let mut current = mirror_root.clone();
        let mut components = relative.components().peekable();
        while let Some(component) = components.next() {
            current.push(component.as_os_str());
            let is_symlink = std::fs::symlink_metadata(&current)
                .wrap_err_with(|| format!("stat mirror entry {}", current.display()))?
                .file_type()
                .is_symlink();
            if !is_symlink {
                continue;
            }
            let target = resolve_mirror_symlink(&current)?;
            if components.peek().is_some() {
                materialize_mirror_directory(&current, &target)?;
            } else {
                remove_mirror_symlink(&current, false)
                    .wrap_err_with(|| format!("remove manifest symlink {}", current.display()))?;
                reflink::reflink_or_copy(&target, &current).wrap_err_with(|| {
                    format!(
                        "copy manifest {} into workspace mirror {}",
                        target.display(),
                        current.display()
                    )
                })?;
            }
        }
        Ok(())
    })
    .await
}

/// Read a mirror symlink's target, resolving relative links against the
/// link's own directory.
fn resolve_mirror_symlink(link: &Path) -> stow_types::error::Result<PathBuf> {
    let target = std::fs::read_link(link)
        .wrap_err_with(|| format!("read mirror symlink {}", link.display()))?;
    if target.is_absolute() {
        return Ok(target);
    }
    let parent = link.parent().ok_or_else(|| {
        stow_types::stow_error!("mirror symlink {} has no parent", link.display())
    })?;
    Ok(parent.join(target))
}

/// Swap `link` — a symlink to the real directory `target` — for a real
/// directory whose children are symlinks to `target`'s entries.
fn materialize_mirror_directory(link: &Path, target: &Path) -> stow_types::error::Result<()> {
    let entries = std::fs::read_dir(target)
        .wrap_err_with(|| format!("read directory {}", target.display()))?
        .collect::<Result<Vec<_>, io::Error>>()
        .wrap_err_with(|| format!("read directory {}", target.display()))?;
    remove_mirror_symlink(link, true)
        .wrap_err_with(|| format!("remove directory symlink {}", link.display()))?;
    std::fs::create_dir(link)
        .wrap_err_with(|| format!("create real directory {}", link.display()))?;
    for entry in entries {
        let destination = link.join(entry.file_name());
        symlink_path(&entry.path(), &destination).wrap_err_with(|| {
            format!(
                "symlink {} into materialized mirror directory {}",
                entry.path().display(),
                destination.display()
            )
        })?;
    }
    Ok(())
}

/// Remove `link` itself without touching its target. Unix `unlink`s every
/// symlink kind; Windows splits directory symlinks into `remove_dir`.
fn remove_mirror_symlink(link: &Path, target_is_dir: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        let _ = target_is_dir;
        std::fs::remove_file(link)
    }
    #[cfg(windows)]
    {
        if target_is_dir {
            std::fs::remove_dir(link)
        } else {
            std::fs::remove_file(link)
        }
    }
}

async fn apply_selected_upgrades(
    project: &ProjectContext,
    mirror: &WorkspaceMirror,
    selected: &[CompatibleUpgrade],
) -> stow_types::error::Result<()> {
    let started = Instant::now();
    let mut ordered = selected.to_vec();
    ordered.sort_by(|left, right| {
        left.depth
            .cmp(&right.depth)
            .then(
                right
                    .upgraded_artifact_count
                    .cmp(&left.upgraded_artifact_count),
            )
            .then(left.crate_name.cmp(&right.crate_name))
            .then(left.to_version.cmp(&right.to_version))
    });
    let manifest_path = mirror_manifest_path(project, mirror)?;
    let lockfile_path = mirror.root().join("Cargo.lock");
    let mut current_versions = load_current_lockfile_versions(&lockfile_path).await?;
    let mut applied = 0usize;
    let mut already_satisfied = 0usize;
    let mut source_absent = 0usize;
    let mut skipped_conflicts = 0usize;
    let mut pending = ordered;
    while !pending.is_empty() {
        let mut made_progress = false;
        let mut deferred = Vec::new();
        for upgrade in pending {
            let attempt =
                try_apply_upgrade(mirror, &manifest_path, &current_versions, &upgrade).await?;
            match attempt {
                UpgradeAttempt::Applied => {
                    applied = applied.saturating_add(1);
                    made_progress = true;
                }
                UpgradeAttempt::AlreadySatisfied => {
                    already_satisfied = already_satisfied.saturating_add(1);
                }
                UpgradeAttempt::SourceAbsent => {
                    source_absent = source_absent.saturating_add(1);
                }
                UpgradeAttempt::Deferred => deferred.push(upgrade),
            }
            if matches!(attempt, UpgradeAttempt::Applied | UpgradeAttempt::Deferred) {
                current_versions = load_current_lockfile_versions(&lockfile_path).await?;
            }
        }

        if deferred.is_empty() {
            break;
        }
        if !made_progress {
            skipped_conflicts = skipped_conflicts.saturating_add(deferred.len());
            for upgrade in deferred {
                tracing::warn!(
                    crate_name = %upgrade.crate_name,
                    from_version = %upgrade.from_version,
                    to_version = %upgrade.to_version,
                    "skipping compatible upgrade because cargo could not resolve it after retrying the remaining upgrade set"
                );
            }
            break;
        }
        pending = deferred;
    }

    tracing::info!(
        total_candidates = selected.len(),
        applied,
        already_satisfied,
        source_absent,
        skipped_conflicts,
        elapsed_ms = started.elapsed().as_millis(),
        "applied compatible dependency upgrades for this stow run"
    );

    Ok(())
}

/// The outcome of one `cargo update --precise` attempt against the mirror.
enum UpgradeAttempt {
    /// The pin moved; the lockfile changed and progress was made.
    Applied,
    /// A previous update already landed the target version.
    AlreadySatisfied,
    /// The source version is gone from the lockfile entirely.
    SourceAbsent,
    /// Cargo could not resolve this pin in the current lockfile state;
    /// retry after the rest of the set makes progress.
    Deferred,
}

/// One `cargo update --precise` attempt for `upgrade` against the mirror's
/// current lockfile state.
async fn try_apply_upgrade(
    mirror: &WorkspaceMirror,
    manifest_path: &Path,
    current_versions: &BTreeMap<String, BTreeSet<semver::Version>>,
    upgrade: &CompatibleUpgrade,
) -> stow_types::error::Result<UpgradeAttempt> {
    let current = current_versions
        .get(&upgrade.crate_name)
        .cloned()
        .unwrap_or_default();
    if !current.contains(&upgrade.from_version) {
        if current.contains(&upgrade.to_version) {
            tracing::info!(
                crate_name = %upgrade.crate_name,
                from_version = %upgrade.from_version,
                to_version = %upgrade.to_version,
                "compatible upgrade already satisfied by a previous cargo update"
            );
            return Ok(UpgradeAttempt::AlreadySatisfied);
        }
        tracing::info!(
            crate_name = %upgrade.crate_name,
            from_version = %upgrade.from_version,
            to_version = %upgrade.to_version,
            "skipping compatible upgrade because source version is no longer present in the current lockfile"
        );
        return Ok(UpgradeAttempt::SourceAbsent);
    }

    let package_spec = format!("{}@{}", upgrade.crate_name, upgrade.from_version);
    let output = Command::new("cargo")
        .arg("update")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(manifest_path)
        .arg("-p")
        .arg(&package_spec)
        .arg("--precise")
        .arg(upgrade.to_version.to_string())
        .current_dir(mirror.current_dir())
        .output()
        .await
        .wrap_err_with(|| format!("run cargo update for {package_spec}"))?;
    if output.status.success() {
        return Ok(UpgradeAttempt::Applied);
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    tracing::warn!(
        crate_name = %upgrade.crate_name,
        from_version = %upgrade.from_version,
        to_version = %upgrade.to_version,
        status = %output.status,
        stderr,
        "deferring compatible upgrade because cargo could not resolve it in the current lockfile state"
    );
    Ok(UpgradeAttempt::Deferred)
}

async fn load_current_lockfile_versions(
    lockfile_path: &Path,
) -> stow_types::error::Result<BTreeMap<String, BTreeSet<semver::Version>>> {
    let lockfile_path = lockfile_path.to_path_buf();
    smol::unblock(move || {
        let lockfile = cargo_lock::Lockfile::load(&lockfile_path).map_err(|error| {
            stow_types::stow_error!("load lockfile {}: {error}", lockfile_path.display())
        })?;
        let mut versions = BTreeMap::<String, BTreeSet<semver::Version>>::new();
        for package in lockfile.packages {
            if package.source.is_none() {
                continue;
            }
            versions
                .entry(package.name.to_string())
                .or_default()
                .insert(package.version);
        }
        Ok(versions)
    })
    .await
}

fn mirror_manifest_path(
    project: &ProjectContext,
    mirror: &WorkspaceMirror,
) -> stow_types::error::Result<PathBuf> {
    relative_path(&project.workspace_root, &project.manifest_path)
        .map(|relative| mirror.root().join(relative))
}

fn rewrite_args_for_mirror(
    cargo_args: &[OsString],
    project: &ProjectContext,
    mirror: &WorkspaceMirror,
) -> stow_types::error::Result<Vec<OsString>> {
    rewrite_args_for_root(cargo_args, project, mirror.root())
}

fn rewrite_args_for_root(
    cargo_args: &[OsString],
    project: &ProjectContext,
    root: &Path,
) -> stow_types::error::Result<Vec<OsString>> {
    let mut rewritten = Vec::with_capacity(cargo_args.len());
    let mut iter = cargo_args.iter();
    let mut saw_manifest_path = false;

    while let Some(arg) = iter.next() {
        let Some(arg_str) = arg.to_str() else {
            rewritten.push(arg.clone());
            continue;
        };

        if let Some(path) = arg_str.strip_prefix("--manifest-path=") {
            let rewritten_path = rewrite_path_for_root(
                project,
                root,
                &resolve_user_path(project.current_dir(), path),
            )?;
            rewritten.push(OsString::from(format!(
                "--manifest-path={}",
                rewritten_path.display()
            )));
            saw_manifest_path = true;
            continue;
        }

        rewritten.push(arg.clone());
        if arg_str == "--manifest-path" {
            let value = iter
                .next()
                .ok_or_else(|| stow_types::stow_error!("missing value after --manifest-path"))?;
            let value_str = value
                .to_str()
                .ok_or_else(|| stow_types::stow_error!("manifest path is not valid UTF-8"))?;
            let rewritten_path = rewrite_path_for_root(
                project,
                root,
                &resolve_user_path(project.current_dir(), value_str),
            )?;
            rewritten.push(rewritten_path.into_os_string());
            saw_manifest_path = true;
            continue;
        }

        if arg_str == "--target" {
            let value = iter
                .next()
                .ok_or_else(|| stow_types::stow_error!("missing value after --target"))?;
            rewritten.push(value.clone());
        }
    }

    if !saw_manifest_path {
        let manifest_path = rewrite_path_for_root(project, root, &project.manifest_path)?;
        rewritten.push(OsString::from("--manifest-path"));
        rewritten.push(manifest_path.into_os_string());
    }

    Ok(rewritten)
}

fn rewrite_path_for_root(
    project: &ProjectContext,
    root: &Path,
    path: &Path,
) -> stow_types::error::Result<PathBuf> {
    let relative = relative_path(&project.workspace_root, path)?;
    Ok(root.join(relative))
}

fn relative_path(root: &Path, path: &Path) -> stow_types::error::Result<PathBuf> {
    // Both sides through the same lossy canonicalization: the spelled
    // manifest often does not exist yet, while the root always does, so
    // a plain `canonicalize` + fallback resolves one side through a
    // symlink (macOS `/var -> /private/var`, Windows short-name temp
    // dirs) and leaves the other spelled — the prefix check then fails
    // on a path that is inside the root.
    crate::workspace_deps::canonicalize_or_original(path)
        .strip_prefix(crate::workspace_deps::canonicalize_or_original(root))
        .map(Path::to_path_buf)
        .map_err(|_| {
            stow_types::stow_error!(
                "path {} is outside workspace root {}",
                path.display(),
                root.display()
            )
        })
}

/// Transparent cargo pass-through with no `RUSTC_WRAPPER` and no env mutations.
///
/// Used by the resolver-failed fast fallback so `stow check` cannot be slower
/// than `cargo check` — which means it must look exactly like `cargo check`
/// to the toolchain. Returns cargo's own exit status, success or not (stow#652).
async fn run_cargo_passthrough(
    project: &ProjectContext,
    action: &str,
    cargo_args: &[OsString],
    current_dir: &Path,
) -> stow_types::error::Result<ExitStatus> {
    let status = passthrough_command(project, action, cargo_args, current_dir)
        .await?
        .status()
        .await
        .wrap_err_with(|| format!("run cargo {action} (passthrough)"))?;
    // Cargo's status is back, so its resolution — the only stretch that
    // needs the package-cache lock exclusively — is over: drains may
    // derive again (stow#667).
    project.foreground.release();
    Ok(status)
}

/// The passthrough's cargo invocation: the action, the build's mold
/// selection as `--config` arguments — awaited before the command is
/// built, so no cargo build assembles ahead of the provisioning
/// (stow#653) — then the user's own arguments.
async fn passthrough_command(
    project: &ProjectContext,
    action: &str,
    cargo_args: &[OsString],
    current_dir: &Path,
) -> stow_types::error::Result<Command> {
    let mold_args = project.mold.config_args().await?;
    let mut command = Command::new("cargo");
    command.arg(action);
    for config_arg in mold_args.iter() {
        command.arg("--config").arg(config_arg);
    }
    command.args(cargo_args).current_dir(current_dir);
    if std::env::var_os("CARGO_TARGET_DIR").is_none() && !has_explicit_target_dir(cargo_args) {
        command.env(
            "CARGO_TARGET_DIR",
            project.workspace_root.join("target").into_os_string(),
        );
    }
    Ok(command)
}

/// The launch plan for one cargo invocation under the stow wrapper: the
/// resolved workspace context plus the cache inputs earlier phases
/// computed for this build.
struct CargoRunPlan<'a> {
    project: &'a ProjectContext,
    config: Option<&'a StowConfig>,
    /// The process's state-database handle — `config`'s own when there
    /// is one — for the configs the build's supervisor loads itself
    /// (stow#682).
    state_db: &'a StateDb,
    action: &'a str,
    cargo_args: &'a [OsString],
    source_root: &'a Path,
    current_dir: &'a Path,
    /// `Some` means the build's cache-policy directory must exist before
    /// cargo starts — inside the build's scratch directory — and carries
    /// the allow markers to seed it with: the mirror paths' completed
    /// analysis, or an empty list on the deferred path, whose entries
    /// the in-build enrichment commits later (stow#347, stow#630).
    cache_policy_entries: Option<&'a [CachePolicyEntry]>,
    public_cache_mode: &'a PublicCacheMode,
    /// The build's per-side unit node table — the lib nodes' `(crate,
    /// version, side, cargo-resolved feature set)` plus the spelled
    /// `--target` fact — for the wrapper's semantic identity and miss
    /// path (stow#615). `None` carries no graph.
    unit_nodes: Option<&'a crate::unit_node::UnitNodeTable>,
    prefetch_artifacts: Option<&'a [PrefetchArtifact]>,
    /// The serve map the facades answer their uncovered checks from —
    /// `None` exports no map file and every invocation plans.
    servable_units: Option<&'a crate::facade::ServeMap>,
    /// The analysis deferral: `true` when the facts this build starts
    /// with came from the filesystem-only pass and the full graph
    /// analysis is owed to the build while cargo runs (stow#347).
    /// `false` on the mirror paths: they already paid the full analysis
    /// for their pinned graph.
    deferred_analysis: bool,
    semantic_fallback_enabled: bool,
    extra_rustflags: &'a [String],
    covered_units: usize,
}

/// The build's cargo run under the wrapper. Returns cargo's own exit
/// status, success or not — the status travels up to the caller that
/// owns what the build leaves behind, and only the top of the command
/// turns it into the process's exit (stow#652).
async fn run_cargo(plan: &CargoRunPlan<'_>) -> stow_types::error::Result<ExitStatus> {
    let CargoRunPlan {
        project,
        config,
        state_db,
        action,
        cargo_args,
        current_dir,
        cache_policy_entries,
        public_cache_mode,
        covered_units,
        ..
    } = *plan;
    // Every file this build generates — the serve map, the graph
    // tables, the extra-args list, the cache-policy markers — lives in
    // one directory the build owns, beside the supervisor's socket
    // directory in the system temp directory, and the build removes it
    // when it ends (stow#630).
    let scratch = tempfile::Builder::new()
        .prefix("stow-build-")
        .tempdir()
        .wrap_err("create the build scratch directory")?;
    let wrappers =
        tracing::debug_span!("stow.precargo.detect_wrappers").in_scope(detect_wrapper_commands)?;
    let mut command = cargo_command(plan).await?;

    let cache_policy_path = seed_cache_policy(scratch.path(), cache_policy_entries)
        .instrument(tracing::debug_span!("stow.precargo.policy_dir"))
        .await;

    // The serve map lands as a file — small enough to write atomically
    // and large enough that an env blob on every rustc process's
    // environment was the wrong transport (stow#347). A map still
    // `pending` arms the waiters' signal alongside: facades whose units
    // it cannot cover ask the supervisor to hold them until the final
    // write lands rather than compiling what the in-flight fetch may
    // cover.
    let serve_map_ready = std::sync::Arc::new(crate::facade::ServeMapSignal::pending());
    let (serve_map_path, serve_waiters) =
        write_initial_serve_map(scratch.path(), plan.servable_units, &serve_map_ready)
            .instrument(tracing::debug_span!("stow.precargo.serve_map_write"))
            .await?;
    export_wrapper_env(
        &mut command,
        plan,
        &wrappers,
        serve_map_path.as_deref(),
        cache_policy_path.as_deref(),
        scratch.path(),
    )
    .instrument(tracing::debug_span!("stow.precargo.export_env"))
    .await?;

    // Every rustc invocation this cargo run spawns is a facade that asks
    // this process what to do, so the whole build shares one transport —
    // one pooled connection, one QUIC endpoint. The `STOW_*` context lands
    // on cargo's environment, so the deciding process holds the resolved
    // values itself (stow#347).
    let analysis_cell = analysis_cell(plan);
    // The driver-built wrapper base lands here: the task spawned in
    // `run_inner` has been running beside mold's provisioning and the
    // analysis, so this await is almost always an immediate take (stow#608).
    let env_base = join_env_base(project.env_base.as_ref()).await?;
    // The supervisor completes this on the first facade frame that
    // describes a real compile unit — the moment cargo's resolution is
    // over — so the package-cache lock always goes to the real build
    // first (stow#608).
    let resolution_done = crate::ResolutionDone::pending();
    // The foreground hold's release task: `ResolutionDone` is the
    // moment cargo holds the package-cache lock only shared, so a
    // drain's cargo can no longer make this build wait — and a `stow
    // run` that stays up for hours must not keep every drain shut
    // (stow#667). It is stopped with cargo below.
    let release_hold = spawn_hold_release(resolution_done.clone(), project.foreground.clone());
    // The supervisor and the handler share the build's in-flight unit
    // registry: the server marks and completes flights, the post-compiles
    // wait on them before resolving dependency identities (stow#618).
    let in_flight = crate::supervisor::server::InFlightUnits::default();
    let handler = std::sync::Arc::new(crate::BuildSupervisor::new(
        crate::BuildContext {
            policy_dir: cache_policy_path.clone(),
            public_cache_target: Some(project.target.clone()),
            public_cache_disabled: public_cache_mode.disable_reason().is_some(),
            analysis: std::sync::Arc::clone(&analysis_cell),
            serve_map_ready: std::sync::Arc::clone(&serve_map_ready),
            in_flight: in_flight.clone(),
        },
        env_base,
        resolution_done.clone(),
        state_db.clone(),
    ));
    let mut supervisor = tracing::debug_span!("stow.precargo.supervisor_start")
        .in_scope(|| crate::supervisor::server::start(handler.clone(), in_flight))
        .map_err(|error| stow_types::stow_error!("start the build supervisor: {error}"))?;
    command.envs(supervisor.env());

    let before = CoverageSnapshot::capture(config)
        .instrument(tracing::debug_span!("stow.precargo.coverage_snapshot"))
        .await;

    // The full graph analysis — the verified index fetch and the live
    // `--unit-graph` resolve — runs while cargo builds rather than in
    // front of it: its answers land in the serve map file the facades
    // read and the cell the supervisor's plan path reads, mid-build
    // (stow#347).
    let enricher = if plan.deferred_analysis
        && let Some(config) = config
    {
        // Aborted at cargo's exit, below: what the analysis commits for
        // this build — the map, the policy markers, the facts — lands
        // while cargo runs, and whatever is still running when cargo
        // returns is warming this build can no longer use; the plan path
        // fetches on demand.
        Some(spawn_build_enrichment(BuildEnrichment {
            project: project.clone(),
            config: config.clone(),
            cell: analysis_cell,
            map_path: serve_map_path.clone(),
            policy_dir: cache_policy_path.clone(),
            readiness: serve_waiters,
            resolution_done,
        }))
    } else {
        None
    };

    tracing::debug!("stow.precargo.cargo_spawn");
    let status = command.status().await;
    // The analysis stops with cargo, whichever way cargo ended: its
    // future is dropped here — and with it the `kill_on_drop` cargo
    // children it may still be driving — before anything else runs
    // (stow#624). The release task stops too — a hold released after
    // this build ends would open the gate on a lie.
    if let Some(enricher) = enricher {
        stop_build_task(enricher).await;
    }
    stop_build_task(release_hold).await;
    let status = status.wrap_err_with(|| format!("run cargo {action}"))?;
    // Cargo has exited, so every facade has: stop accepting and drain the
    // last connections' post-compile bookkeeping before the runtime goes
    // away — the last unit's store is inside that tail, and so is its
    // miss observation (stow#618).
    supervisor.shutdown().await;
    if let Some(config) = config {
        if status.success() {
            report_cache_coverage(config, before, covered_units).await;
        }
        // The build's compile observations are its miss list (stow#317)
        // — a failed build's units are real misses too, whatever its
        // last unit did. They land in the same journal a plain-cargo
        // wrapper writes, and a detached drain posts the admission —
        // this command returns as soon as cargo does. The hold is
        // given up first: the drain this build spawns must find the
        // gate open (stow#667).
        project.foreground.release();
        journal_and_drain_misses(project, cargo_args, current_dir, &handler.observations());
    }
    // Nothing writes into the scratch directory any more — cargo has
    // exited, the analysis is gone and the supervisor has drained — so
    // it is removed here rather than at drop: `close` reports a removal
    // failure a `TempDir` drop would swallow (stow#630).
    if let Err(error) = scratch.close() {
        tracing::warn!(%error, "could not remove the build scratch directory");
    }
    Ok(status)
}

/// The cargo invocation the build runs: the action, the build's mold
/// selection as `--config` arguments — awaited, so the command cannot
/// be assembled before the provisioning answers (stow#653) — then the
/// user's own arguments.
async fn cargo_command(plan: &CargoRunPlan<'_>) -> stow_types::error::Result<Command> {
    let mold_args = plan.project.mold.config_args().await?;
    let mut command = Command::new("cargo");
    command.arg(plan.action);
    for config_arg in mold_args.iter() {
        command.arg("--config").arg(config_arg);
    }
    command.args(plan.cargo_args).current_dir(plan.current_dir);
    Ok(command)
}

/// The cell the supervisor's plan path reads the analysis's facts from:
/// filled here when the analysis ran before cargo, left for the in-build
/// enrichment to fill when it is deferred (stow#347).
fn analysis_cell(
    plan: &CargoRunPlan<'_>,
) -> std::sync::Arc<std::sync::OnceLock<crate::AnalysisFacts>> {
    let cell = std::sync::Arc::new(std::sync::OnceLock::new());
    if !plan.deferred_analysis {
        cell.set(crate::AnalysisFacts {
            semantic_fallback_enabled: plan.semantic_fallback_enabled,
            unit_nodes: plan.unit_nodes.cloned(),
            prefetch_candidates: plan
                .prefetch_artifacts
                .map_or_else(BTreeMap::new, |artifacts| {
                    crate::prefetch_candidate_c_metadatas(
                        artifacts.iter().map(|artifact| {
                            (artifact.crate_name.clone(), artifact.c_metadata.clone())
                        }),
                    )
                }),
        })
        .expect(
            "the analysis cell is written once per build; the pre-cargo fill is its only \
             writer when the analysis is not deferred",
        );
    }
    cell
}

/// Create the build's cache-policy directory inside its scratch
/// directory and write `entries`' allow markers into it; `None` entries
/// are a build with no policy. The directory exists before cargo does:
/// the supervisor writes local-build provenance markers into it during
/// the build, and the facades read it per plan call (stow#347).
///
/// `None` also when it cannot be written: without a policy the wrapper
/// treats every invocation as allowed, which costs lookups but still
/// builds. Failing here would not.
async fn seed_cache_policy(
    scratch_dir: &Path,
    entries: Option<&[CachePolicyEntry]>,
) -> Option<PathBuf> {
    let entries = entries?;
    let seeded = async {
        let dir = cache_policy::create_policy_dir(scratch_dir).await?;
        cache_policy::write_policy_entries(&dir, entries).await?;
        Ok::<_, stow_types::error::Error>(dir)
    };
    match seeded.await {
        Ok(dir) => Some(dir),
        Err(error) => {
            tracing::warn!(
                %error,
                "failed to write the cache policy; the build continues without one"
            );
            None
        }
    }
}

/// The task `run_cargo` stops with cargo: release the foreground hold
/// the moment `resolution_done` fires (stow#667).
fn spawn_hold_release(
    resolution_done: crate::ResolutionDone,
    foreground: crate::derive_gate::ForegroundHold,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        resolution_done.wait().await;
        foreground.release();
    })
}

/// Abort a build-scoped task — the in-build analysis, the foreground
/// hold's release — and return once its future is gone, so nothing of
/// it outlives the build: no write into the scratch directory, no
/// cargo child. A panic inside it is the build's panic.
async fn stop_build_task(task: tokio::task::JoinHandle<()>) {
    task.abort();
    match task.await {
        Ok(()) => {}
        Err(error) if error.is_cancelled() => {}
        Err(error) => std::panic::resume_unwind(error.into_panic()),
    }
}

/// The `STOW_*` contract a cargo run's wrappers read: the toolchain
/// shims, the resolved config blob, the graph-fact file paths, the
/// serve map file path the facades answer from, and the cache policy —
/// everything a wrapper would otherwise load itself on every invocation
/// (stow#347). Build-sized payloads travel as files: one environment
/// string past Linux's `MAX_ARG_STRLEN` fails the whole `execve`, which
/// a workspace-sized graph or ledger clears (stow#625).
async fn export_wrapper_env(
    command: &mut Command,
    plan: &CargoRunPlan<'_>,
    wrappers: &crate::commands::WrapperCommands,
    serve_map_path: Option<&Path>,
    cache_policy_path: Option<&Path>,
    scratch_dir: &Path,
) -> stow_types::error::Result<()> {
    let CargoRunPlan {
        project,
        config,
        cargo_args,
        source_root,
        public_cache_mode,
        unit_nodes,
        prefetch_artifacts,
        semantic_fallback_enabled,
        extra_rustflags,
        ..
    } = *plan;
    command.env("RUSTC_WRAPPER", &wrappers.rustc);
    // The shims ride the `cc` crate's target-scoped keys for this build's
    // target rather than bare CC/CXX, the same scope `stow setup` writes —
    // other targets keep the toolchain cc-rs resolves for them. An
    // explicitly configured compiler is recorded so the shims exec it; a
    // target with nothing configured leaves the shims resolving the
    // platform toolchain per invocation.
    let scoped = project.target.replace(['-', '.'], "_");
    command.env(format!("CC_{scoped}"), &wrappers.cc_compiler);
    command.env(format!("CXX_{scoped}"), &wrappers.cxx_compiler);
    if let Some(real_cc) = crate::commands::configured_c_compiler(&project.target) {
        command.env("STOW_REAL_CC", real_cc);
    }
    if let Some(real_cxx) = crate::commands::configured_cxx_compiler(&project.target) {
        command.env("STOW_REAL_CXX", real_cxx);
    }
    command.env("CMAKE_C_COMPILER_LAUNCHER", &wrappers.cc_launcher);
    command.env("CMAKE_CXX_COMPILER_LAUNCHER", &wrappers.cc_launcher);
    // The extra rustc arguments ride a build file like the other
    // workspace-sized payloads — on the prebuilt-deps path the list is
    // one `--extern` per direct dependency (stow#625) — and a build with
    // no stow config still writes this one.
    let extra_args = rustc_wrapper_extra_args(source_root, extra_rustflags)?;
    let extra_args_path =
        write_build_json_table(scratch_dir, "rustc-extra-args", extra_args).await?;
    command.env(
        rustc_args::STOW_RUSTC_EXTRA_ARGS_FILE_ENV,
        extra_args_path.as_os_str(),
    );
    command.env(STOW_PUBLIC_CACHE_RUSTC_VERSION_ENV, &project.rustc_version);
    command.env(STOW_PUBLIC_CACHE_TARGET_ENV, &project.target);
    // Pass the parent's already-resolved StowConfig as a JSON env blob so the
    // rustc wrapper does not re-read ~/.config/stow/config.toml on every
    // invocation. See `StowConfig::from_env_blob`.
    if let Some(cfg) = config {
        command.env(crate::config::STOW_CONFIG_BLOB_ENV, cfg.to_env_blob()?);
    }
    command.env(
        STOW_ENABLE_SEMANTIC_FALLBACK_ENV,
        if semantic_fallback_enabled { "1" } else { "0" },
    );
    // The per-side node table every wrapper invocation resolves its
    // unit's cargo feature set and side against — the argv scan is
    // compile-key evidence, never the semantic label (stow#615) — and
    // the prefetch ledger. Both travel as files beside the serve map,
    // inside the build's scratch directory; with nothing to write no
    // variable is exported (stow#625).
    if let Some(unit_nodes) = unit_nodes {
        let path =
            write_build_json_table(scratch_dir, "expanded-graph", unit_nodes.clone()).await?;
        command.env(STOW_EXPANDED_GRAPH_PATH_ENV, path.as_os_str());
    }
    if let Some(prefetch_artifacts) = prefetch_artifacts {
        let rows = prefetch_artifact_rows(prefetch_artifacts)?;
        let path = write_build_json_table(scratch_dir, "prefetch-artifacts", rows).await?;
        command.env(STOW_PREFETCH_ARTIFACTS_PATH_ENV, path.as_os_str());
    }
    if let Some(path) = serve_map_path {
        command.env(crate::facade::STOW_SERVE_MAP_FILE_ENV, path.as_os_str());
    }
    if let Some(path) = cache_policy_path {
        let (key, value) = cache_policy::cache_policy_env(path);
        command.env(key, value);
    }
    if let Some(reason) = public_cache_mode.disable_reason() {
        command.env("STOW_DISABLE_PUBLIC_CACHE", reason);
    }
    if std::env::var_os("CARGO_TARGET_DIR").is_none() && !has_explicit_target_dir(cargo_args) {
        command.env(
            "CARGO_TARGET_DIR",
            project.workspace_root.join("target").into_os_string(),
        );
    }
    Ok(())
}

/// The serve map a build starts cargo with, written atomically: the
/// facades read this file on every rustc invocation, so it lands in the
/// build's scratch directory complete or not at all. The build's
/// enrichment rewrites the same path with the full analysis's map
/// (stow#347).
async fn write_initial_serve_map(
    scratch_dir: &Path,
    map: Option<&crate::facade::ServeMap>,
    serve_map_ready: &std::sync::Arc<crate::facade::ServeMapSignal>,
) -> stow_types::error::Result<(Option<PathBuf>, Option<crate::facade::ServeMapWaiters>)> {
    let Some(map) = map else {
        return Ok((None, None));
    };
    // Arm the waiters' guard before the map that announces it: a facade
    // that reads `pending` asks the supervisor to hold it — the signal
    // exists by construction, so there is no bind to fail here. An
    // empty pending map waits on nothing (stow#347).
    let waiters = (map.pending && !map.is_empty())
        .then(|| crate::facade::ServeMapWaiters::new(std::sync::Arc::clone(serve_map_ready)));
    let path = write_build_json_table(scratch_dir, "serve-map", map.clone()).await?;
    Ok((Some(path), waiters))
}

/// One build-scoped JSON table, `{name}.json` in the build's scratch
/// directory — the serve map, the expanded unit graph, the prefetch
/// ledger and the rustc extra-args list share the directory and the
/// write discipline; the graph tables joined the serve map when they
/// outgrew the environment strings they rode on (stow#625). The
/// directory is one build's, so the name needs nothing to tell builds
/// apart (stow#630). Returns the path the caller exports on the
/// environment.
async fn write_build_json_table(
    scratch_dir: &Path,
    name: &str,
    table: impl serde::Serialize + Send + 'static,
) -> stow_types::error::Result<PathBuf> {
    let path = scratch_dir.join(format!("{name}.json"));
    write_build_json_file(&path, table).await?;
    Ok(path)
}

/// Write `table` to `path` as JSON through a tmp file + rename — a
/// reader catching the file mid-rewrite must never see a torn payload.
///
/// The payload grows with the workspace, so it is serialized on a
/// blocking thread (stow#624). The install stays on the calling task —
/// one write and one rename of the finished bytes: the in-build analysis
/// rewrites the serve map through here, and aborting that task must
/// leave no write in flight into a directory the build is about to
/// remove (stow#630).
async fn write_build_json_file(
    path: &Path,
    table: impl serde::Serialize + Send + 'static,
) -> stow_types::error::Result<()> {
    let json = smol::unblock(move || serde_json::to_vec(&table))
        .await
        .map_err(|error| stow_types::stow_error!("serialize {}: {error}", path.display()))?;
    let tmp = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(OsStr::to_str).unwrap_or_default(),
        std::process::id()
    ));
    std::fs::write(&tmp, &json)
        .map_err(|error| stow_types::stow_error!("write {}: {error}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .map_err(|error| stow_types::stow_error!("install {}: {error}", path.display()))
}

/// What the in-build enrichment needs: the project and config the full
/// analysis resolves, and the three places its answer lands — the
/// supervisor's fact cell, the serve map file the facades read, and the
/// policy directory the allow markers gate (stow#347).
struct BuildEnrichment {
    project: ProjectContext,
    config: StowConfig,
    cell: std::sync::Arc<std::sync::OnceLock<crate::AnalysisFacts>>,
    map_path: Option<PathBuf>,
    policy_dir: Option<PathBuf>,
    /// The pending serve map's completion guard: held until this task
    /// has written the final map — and its drop releases the facades
    /// waiting on `AwaitServeMap` whichever way the analysis ends
    /// (stow#347).
    readiness: Option<crate::facade::ServeMapWaiters>,
    /// Held until the supervisor's first compile-unit frame says
    /// cargo's resolution is over: only then may this task's own
    /// `--unit-graph` cargo take the package-cache lock — before that
    /// it would queue the user's real build behind a whole second
    /// resolve (stow#608).
    resolution_done: crate::ResolutionDone,
}

/// Run the full graph analysis while cargo builds and commit what it
/// proves. Failures degrade, never fail the build: the serve map keeps
/// its filesystem-only answer, the policy directory keeps denying, and
/// the plan path keeps its conservative defaults.
fn spawn_build_enrichment(work: BuildEnrichment) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn(async move {
        if let Err(error) = Box::pin(run_build_enrichment(work)).await {
            tracing::warn!(
                error = %error,
                "background build analysis failed; the build keeps its filesystem-only plan"
            );
        }
    })
}

async fn run_build_enrichment(mut work: BuildEnrichment) -> stow_types::error::Result<()> {
    // A `pending` map's facades are waiting on the supervisor for the
    // final map: answer them as soon as coverage is knowable — the
    // fresh slice landed, the filesystem pass rebuilt with it — rather
    // than after the metadata resolve and the prefetch. The write
    // clears `pending` (the cached slices now exist) and the guard's
    // drop releases the waiters; an early return releases them the
    // same way (stow#347).
    if work.readiness.is_some()
        && let Some(map_path) = &work.map_path
    {
        ensure_consumer_slices(&work.config, &work.project).await?;
        let lite = analyze_workspace_prediction_lite(&work.project, &work.config).await?;
        write_build_json_file(map_path, lite.servable_units.unwrap_or_default()).await?;
        drop(work.readiness.take());
    }
    let analysis = analyze_workspace_prediction(
        &work.project,
        work.project.current_dir(),
        &work.project.manifest_path,
        &work.config,
        Some(&work.resolution_done),
    )
    .await?;
    if let Some(map_path) = &work.map_path {
        let map = analysis.servable_units.clone().unwrap_or_default();
        write_build_json_file(map_path, map).await?;
    }
    if let Some(policy_dir) = &work.policy_dir {
        cache_policy::write_policy_entries(policy_dir, &analysis.cache_policy_entries).await?;
    }
    work.cell
        .set(crate::AnalysisFacts {
            semantic_fallback_enabled: analysis
                .unit_nodes
                .as_ref()
                .is_some_and(|table| !table.nodes.is_empty()),
            unit_nodes: analysis.unit_nodes.clone(),
            prefetch_candidates: crate::prefetch_candidate_c_metadatas(
                analysis
                    .prefetch_artifacts
                    .iter()
                    .map(|artifact| (artifact.crate_name.clone(), artifact.c_metadata.clone())),
            ),
        })
        .expect(
            "the analysis cell is written once per build; a deferred build's enrichment is its \
             only writer",
        );
    // The prefetch is the last step and best-effort: the artifacts it
    // warms are what the plan path serves, and a unit reached before its
    // artifact lands still fetches on demand.
    let budget = CacheBudget::for_covered_units(analysis.prefetch_artifacts.len());
    if let Err(error) =
        prefetch_graph_artifacts(&work.config, &analysis.prefetch_artifacts, &budget).await
    {
        tracing::warn!(
            %error,
            "exact graph artifact prefetch failed during the build; the plan path fetches on demand"
        );
    }
    Ok(())
}

/// Leave this build's compile observations in the miss journal a plain
/// `cargo build` writes, and kick the detached drain that posts the
/// admission — `stow build` returns as soon as cargo does (stow#317).
fn journal_and_drain_misses(
    project: &ProjectContext,
    cargo_args: &[OsString],
    current_dir: &Path,
    observations: &[crate::artifact_cache::ObservedUnit],
) {
    let target_dir = resolved_target_dir(project, cargo_args, current_dir);
    // The drain mints each miss's dependency subgraph off the build's
    // persisted expanded graph when it can load it, and off the
    // journal's context sidecar when it cannot (stow#588).
    let expanded_cache_key =
        crate::lockfile_graph_cache::cache_key(project).unwrap_or_else(|error| {
            tracing::warn!(error = %error, "could not key the expanded graph for the miss journal");
            String::new()
        });
    let env = std::env::vars_os().collect::<Vec<_>>();
    let key_inputs = crate::lockfile_graph_cache::KeyInputs {
        action: &project.action,
        cargo_args: &project.cargo_args,
        current_dir: &project.current_dir,
        manifest_path: &project.manifest_path,
        workspace_root: &project.workspace_root,
        target: &project.target,
        target_given: project.target_given,
        rustc_version: &project.rustc_version,
        env: &env,
    };
    let consumer = crate::miss_journal::JournalConsumer {
        manifest_dir: project
            .manifest_path
            .parent()
            .unwrap_or(project.current_dir.as_path()),
        key: &key_inputs,
    };
    crate::miss_journal::journal_supervised(
        project.build_rustc.executable(),
        &consumer,
        observations,
        &target_dir,
        &expanded_cache_key,
    );
    crate::miss_journal::spawn_drain(&target_dir);
}

/// The `PrefetchArtifactRow`s `STOW_PREFETCH_ARTIFACTS_PATH`'s file
/// carries to the rustc wrapper, validated into their newtypes.
fn prefetch_artifact_rows(
    prefetch_artifacts: &[PrefetchArtifact],
) -> stow_types::error::Result<Vec<resolve::PrefetchArtifactRow>> {
    prefetch_artifacts
        .iter()
        .map(|artifact| {
            let crate_name = stow_types::identity::CrateName::parse(artifact.crate_name.as_str())
                .map_err(|error| {
                stow_types::stow_error!(
                    "invalid prefetch crate_name `{}`: {error}",
                    artifact.crate_name
                )
            })?;
            let c_metadata = stow_types::identity::CMetadata::parse(artifact.c_metadata.as_str())
                .map_err(|error| {
                stow_types::stow_error!(
                    "invalid prefetch c_metadata `{}`: {error}",
                    artifact.c_metadata
                )
            })?;
            Ok::<_, stow_types::error::Error>(resolve::PrefetchArtifactRow {
                crate_name,
                c_metadata,
                bundle_digest: artifact.bundle_digest.clone(),
            })
        })
        .collect()
}

/// What the cache counters held before cargo ran.
///
/// Every one of them is cumulative across stow invocations, so a single
/// build's coverage only exists as a delta.
struct CoverageSnapshot {
    stats: stats::StatsSummary,
    errors: std::collections::BTreeMap<String, u64>,
    divergence: Option<stats::ProfileDivergence>,
}

impl CoverageSnapshot {
    async fn capture(config: Option<&StowConfig>) -> Self {
        let Some(config) = config else {
            return Self {
                stats: stats::StatsSummary::default(),
                errors: std::collections::BTreeMap::new(),
                divergence: None,
            };
        };
        Self {
            stats: stats::read_summary(config)
                .instrument(tracing::debug_span!("stow.precargo.stats_summary"))
                .await
                .unwrap_or_default(),
            errors: stats::read_error_counts(config)
                .instrument(tracing::debug_span!("stow.precargo.stats_errors"))
                .await
                .unwrap_or_default(),
            divergence: stats::read_profile_divergence(config)
                .instrument(tracing::debug_span!("stow.precargo.stats_divergence"))
                .await
                .unwrap_or_default(),
        }
    }
}

/// Print what the cache actually served, at default verbosity.
///
/// Without this the only signal that stow is working is the clock, and a
/// cache serving nothing looks exactly like a cache serving everything. Every
/// defect in `docs/acceleration-audit.md` was silent until someone measured.
async fn report_cache_coverage(
    config: &StowConfig,
    before: CoverageSnapshot,
    covered_units: usize,
) {
    let Ok(after) = stats::read_summary(config).await else {
        return;
    };
    let delta = after.since(before.stats);
    if delta.rust_lookups() == 0 && covered_units == 0 {
        return;
    }
    // An errored unit resolved a cached artifact and then could not use
    // it — the expensive failure, since the fetch was paid for and the
    // crate was compiled anyway. The wrapper explains each one, but not at
    // default verbosity, so the count alone leaves nothing to act on.
    let errored_crates = if delta.rust_errors > 0 {
        stats::read_error_counts(config)
            .await
            .map(|after| stats::newly_errored(&before.errors, &after))
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    log_nonfatal_result(
        "failed to print stow cache coverage",
        write_stdout(&delta.summary_line(covered_units, &errored_crates)),
    );
    let divergence_after = stats::read_profile_divergence(config)
        .await
        .unwrap_or_default();
    if let Some(line) =
        stats::profile_divergence_line(before.divergence.as_ref(), divergence_after.as_ref())
    {
        log_nonfatal_result(
            "failed to print the profile divergence",
            write_stdout(&line),
        );
    }
}

fn has_explicit_target_dir(cargo_args: &[OsString]) -> bool {
    cargo_args.iter().any(|arg| {
        arg == "--target-dir"
            || arg
                .to_str()
                .is_some_and(|value| value.starts_with("--target-dir="))
    })
}

/// The directory cargo resolves as this run's target dir — an
/// inherited `CARGO_TARGET_DIR`, a spelled `--target-dir`, else the
/// workspace's own `target/`; a relative value resolves against
/// `current_dir`, the directory cargo runs in.
fn resolved_target_dir(
    project: &ProjectContext,
    cargo_args: &[OsString],
    current_dir: &Path,
) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .map_or_else(
            || cargo_target_dir(&project.workspace_root, cargo_args, current_dir),
            |dir| {
                if dir.is_absolute() {
                    dir
                } else {
                    current_dir.join(dir)
                }
            },
        )
}

fn cargo_target_dir(workspace_root: &Path, cargo_args: &[OsString], current_dir: &Path) -> PathBuf {
    let mut iter = cargo_args.iter();
    while let Some(arg) = iter.next() {
        let Some(arg_str) = arg.to_str() else {
            continue;
        };
        if let Some(value) = arg_str.strip_prefix("--target-dir=") {
            return resolve_user_path(current_dir, value);
        }
        if arg_str == "--target-dir"
            && let Some(value) = iter.next().and_then(|value| value.to_str())
        {
            return resolve_user_path(current_dir, value);
        }
    }
    workspace_root.join("target")
}

async fn strip_selected_manifest_dependencies(
    project: &ProjectContext,
    mirror: &WorkspaceMirror,
) -> stow_types::error::Result<()> {
    let manifest_path = mirror_manifest_path(project, mirror)?;
    let source_manifest = async_fs::read_to_string(&project.manifest_path)
        .await
        .wrap_err_with(|| format!("read Cargo.toml {}", project.manifest_path.display()))?;
    let mut document = source_manifest
        .parse::<toml_edit::DocumentMut>()
        .wrap_err_with(|| format!("parse Cargo.toml {}", project.manifest_path.display()))?;
    let dependency_keys = collect_dependency_feature_references(document.as_table());
    remove_dependency_tables(document.as_table_mut());
    remove_dependency_feature_references(document.as_table_mut(), &dependency_keys);
    materialize_mirror_manifest(mirror, &manifest_path).await?;
    async_fs::remove_file(&manifest_path)
        .await
        .wrap_err_with(|| format!("remove mirrored manifest {}", manifest_path.display()))?;
    async_fs::write(&manifest_path, document.to_string())
        .await
        .wrap_err_with(|| format!("write top-crate-only manifest {}", manifest_path.display()))
}

struct DependencyFeatureReferences {
    all: BTreeSet<String>,
    optional: BTreeSet<String>,
}

fn collect_dependency_feature_references(table: &toml_edit::Table) -> DependencyFeatureReferences {
    let mut references = DependencyFeatureReferences {
        all: BTreeSet::new(),
        optional: BTreeSet::new(),
    };
    collect_dependency_feature_references_from_table_like(table, &mut references);
    if let Some(targets) = table.get("target").and_then(toml_edit::Item::as_table_like) {
        for (_, item) in targets.iter() {
            if let Some(target_table) = item.as_table_like() {
                collect_dependency_feature_references_from_table_like(
                    target_table,
                    &mut references,
                );
            }
        }
    }
    references
}

fn collect_dependency_feature_references_from_table_like(
    table: &dyn toml_edit::TableLike,
    references: &mut DependencyFeatureReferences,
) {
    for section_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(section) = table
            .get(section_name)
            .and_then(toml_edit::Item::as_table_like)
        else {
            continue;
        };
        for (key, item) in section.iter() {
            references.all.insert(key.to_owned());
            if dependency_item_is_optional(item) {
                references.optional.insert(key.to_owned());
            }
        }
    }
}

fn dependency_item_is_optional(item: &toml_edit::Item) -> bool {
    item.as_table_like()
        .and_then(|table| table.get("optional"))
        .and_then(toml_edit::Item::as_bool)
        .unwrap_or(false)
}

async fn regenerate_mirror_lockfile(
    project: &ProjectContext,
    mirror: &WorkspaceMirror,
) -> stow_types::error::Result<()> {
    let manifest_path = mirror_manifest_path(project, mirror)?;
    let output = Command::new("cargo")
        .arg("generate-lockfile")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .current_dir(mirror.current_dir())
        .output()
        .await
        .wrap_err("regenerate top-crate-only mirror lockfile")?;
    if output.status.success() {
        return Ok(());
    }
    Err(stow_types::stow_error!(
        "regenerate top-crate-only mirror lockfile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn remove_dependency_feature_references(
    table: &mut toml_edit::Table,
    dependency_keys: &DependencyFeatureReferences,
) {
    let Some(features) = table
        .get_mut("features")
        .and_then(toml_edit::Item::as_table_like_mut)
    else {
        return;
    };
    for (_, item) in features.iter_mut() {
        let Some(array) = item.as_array_mut() else {
            continue;
        };
        array.retain(|value| {
            value
                .as_str()
                .is_none_or(|feature| !feature_references_dependency(feature, dependency_keys))
        });
    }
}

fn feature_references_dependency(
    feature: &str,
    dependency_keys: &DependencyFeatureReferences,
) -> bool {
    if let Some(dependency) = feature.strip_prefix("dep:") {
        return dependency_keys.all.contains(dependency);
    }
    if let Some((dependency, _)) = feature.split_once('/') {
        return dependency_keys
            .all
            .contains(dependency.trim_end_matches('?'));
    }
    dependency_keys.optional.contains(feature)
}

/// Strip the dependency tables the prebuilt closure replaces, and only those.
///
/// `[build-dependencies]` stays: the closure supplies runtime `--extern`
/// flags for the crate being compiled, and nothing at all for `build.rs`,
/// which cargo still compiles and runs. Removing them left hyperfine's build
/// script unable to find `clap_complete` and failed the build outright.
///
/// `[dev-dependencies]` stays for the same reason — a target that needs them
/// is compiled by cargo, not served from the closure.
fn remove_dependency_tables(table: &mut toml_edit::Table) {
    table.remove("dependencies");
    if let Some(targets) = table
        .get_mut("target")
        .and_then(toml_edit::Item::as_table_like_mut)
    {
        for (_, item) in targets.iter_mut() {
            if let Some(target_table) = item.as_table_like_mut() {
                target_table.remove("dependencies");
            }
        }
    }
}

fn resolve_user_path(current_dir: &Path, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        current_dir.join(path)
    }
}

fn split_features(raw: &str) -> Vec<String> {
    raw.split([',', ' '])
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

// Crate counts stay far below 2^52, so the usize -> f64 conversion is exact.
#[allow(clippy::cast_precision_loss)]
fn percentage(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 * 100.0 / denominator as f64
    }
}

#[derive(Debug, Clone)]
enum PublicCacheMode {
    Enabled,
    Disabled {
        reason: &'static str,
        message: String,
    },
}

impl PublicCacheMode {
    fn for_rustc(rustc_version: &str) -> Self {
        let Some(reason) = unsupported_public_cache_reason(rustc_version) else {
            return Self::Enabled;
        };

        Self::Disabled {
            reason,
            message: format!(
                "warning: stow public cache is disabled for rustc `{rustc_version}` because only the most recent two stable toolchains are supported. {reason} toolchains currently invalidate public cache."
            ),
        }
    }

    const fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled)
    }

    const fn disable_reason(&self) -> Option<&'static str> {
        match self {
            Self::Enabled => None,
            Self::Disabled { reason, .. } => Some(reason),
        }
    }
}

fn unsupported_public_cache_reason(rustc_version: &str) -> Option<&'static str> {
    if rustc_version.contains("-nightly") {
        Some("nightly")
    } else if rustc_version.contains("-beta") {
        Some("beta")
    } else if rustc_version.contains("-dev") {
        Some("dev")
    } else {
        None
    }
}

/// The rustc arguments a supervised run appends to every unit: the
/// workspace path remap plus any flags the run itself selected. They
/// travel through the file [`rustc_args::STOW_RUSTC_EXTRA_ARGS_FILE_ENV`]
/// names — which the rustc wrapper appends to each unit's argv — rather
/// than `RUSTFLAGS`, where cargo's precedence rules would discard the
/// user's `.cargo/config.toml` `target.*.rustflags` for the whole build.
fn rustc_wrapper_extra_args(
    source_root: &Path,
    extra_rustflags: &[String],
) -> stow_types::error::Result<Vec<String>> {
    let source_root = source_root.to_str().ok_or_else(|| {
        stow_types::stow_error!("workspace root {} is not UTF-8", source_root.display())
    })?;
    let remap_flag = format!("--remap-path-prefix={source_root}=stow-ci://workspace");
    Ok(std::iter::once(remap_flag)
        .chain(extra_rustflags.iter().cloned())
        .collect())
}

#[cfg(unix)]
fn symlink_path(source: &Path, destination: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(source, destination)
}

#[cfg(windows)]
fn symlink_path(source: &Path, destination: &Path) -> io::Result<()> {
    let metadata = std::fs::metadata(source)?;
    if metadata.is_dir() {
        std::os::windows::fs::symlink_dir(source, destination)
    } else {
        std::os::windows::fs::symlink_file(source, destination)
    }
}

#[cfg(test)]
mod tests {
    use super::build_serve_map;
    use super::{
        CachedDependencyPlan, CargoRunPlan, MetadataArgs, MoldSelection, ProjectContext,
        PublicCacheMode, WorkspaceMirror, build_script_packages, cached_dependency_profile,
        feature_references_dependency, refuse_build_script_dependencies, relative_path,
        rewrite_args_for_mirror, rewrite_args_for_root,
    };
    #[cfg(unix)]
    use super::{create_workspace_mirror, strip_selected_manifest_dependencies};
    use crate::prefetch::PrefetchArtifact;
    use std::collections::BTreeSet;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    fn test_config(cache_dir: &Path) -> crate::config::StowConfig {
        crate::config::StowConfig {
            edge_url: "http://127.0.0.1:9".to_owned(),
            registry_base_url: "http://127.0.0.1:9/v2/stow".to_owned(),
            cache_dir: cache_dir.to_path_buf(),
            request_timeout: std::time::Duration::from_millis(200),
            negative_cache_ttl: std::time::Duration::ZERO,
            circuit_reset_after: std::time::Duration::ZERO,
            circuit_trip_threshold: 1,
            artifact_cache_max_bytes: 0,
            index_refresh_interval: std::time::Duration::ZERO,
            verify_mode: crate::config::VerifyMode::GithubCi,
            state_db: crate::state_db::StateDb::default(),
            trust_material: std::sync::Arc::default(),
            registry_http: std::sync::Arc::default(),
            artifact_cache_staging: std::sync::Arc::default(),
        }
    }

    fn project_context() -> ProjectContext {
        ProjectContext {
            action: "check".to_owned(),
            cargo_args: Vec::new(),
            workspace_root: PathBuf::from("/workspace"),
            current_dir: PathBuf::from("/workspace"),
            current_dir_relative: PathBuf::new(),
            manifest_path: PathBuf::from("/workspace/Cargo.toml"),
            metadata_args: MetadataArgs::default(),
            target: "aarch64-apple-darwin".to_owned(),
            target_given: false,
            rustc_version: "1.91.1".to_owned(),
            mold: MoldSelection::resolved(Vec::new()),
            env_base: None,
            build_rustc: crate::rustc_args::BuildRustc::ToolchainDefault,
            foreground: crate::derive_gate::ForegroundHold::detached(),
        }
    }

    fn as_strings(values: &[OsString]) -> Vec<String> {
        values
            .iter()
            .map(|value| value.to_str().expect("utf8 arg").to_owned())
            .collect()
    }

    /// The live `--unit-graph` resolve must not start while the real
    /// cargo still holds the package-cache lock — it waits on
    /// `ResolutionDone`, and an unarmed caller resolves at once
    /// (stow#608).
    #[tokio::test]
    async fn the_live_resolve_waits_for_cargos_resolution() {
        let resolution_done = crate::ResolutionDone::pending();
        let started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = started.clone();
        let gated = tokio::spawn({
            let resolution_done = resolution_done.clone();
            async move {
                super::resolve_after_cargo_resolution(Some(&resolution_done), async move {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok::<_, stow_types::error::Error>(())
                })
                .await
            }
        });
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            !started.load(std::sync::atomic::Ordering::SeqCst),
            "the unit-graph resolve ran before cargo's resolution was over"
        );
        resolution_done.complete();
        gated.await.expect("gated resolve task").unwrap();
        assert!(started.load(std::sync::atomic::Ordering::SeqCst));

        // A caller with no concurrent cargo resolves at once.
        super::resolve_after_cargo_resolution(None, async {
            Ok::<_, stow_types::error::Error>(())
        })
        .await
        .unwrap();
    }

    #[test]
    fn rewrite_args_for_root_keeps_manifest_path_but_does_not_force_target() {
        let project = project_context();
        let rewritten = rewrite_args_for_root(
            &[
                OsString::from("--manifest-path"),
                OsString::from("Cargo.toml"),
            ],
            &project,
            Path::new("/mirror"),
        )
        .expect("rewrite args");

        assert_eq!(
            as_strings(&rewritten),
            vec![
                "--manifest-path".to_owned(),
                Path::new("/mirror")
                    .join("Cargo.toml")
                    .to_string_lossy()
                    .into_owned(),
            ]
        );
    }

    /// A spelled absolute `--manifest-path` is the user's own
    /// manifest: forwarding it would make the mirror query the user's
    /// workspace and store that graph under the mirror's key — it must
    /// be replaced with the mirror's copy (stow#551).
    #[test]
    fn rewrite_args_for_mirror_replaces_an_absolute_manifest_path() {
        let workspace = tempfile::tempdir().expect("workspace tempdir");
        let mirror_dir = tempfile::tempdir().expect("mirror tempdir");
        let project = ProjectContext {
            workspace_root: workspace.path().to_path_buf(),
            manifest_path: workspace.path().join("Cargo.toml"),
            ..project_context()
        };
        let mirror = WorkspaceMirror {
            tempdir: mirror_dir,
            current_dir_relative: PathBuf::new(),
        };
        let mirror_manifest = mirror.root().join("Cargo.toml");
        let rewritten = rewrite_args_for_mirror(
            &[
                OsString::from("--manifest-path"),
                project.manifest_path.clone().into_os_string(),
            ],
            &project,
            &mirror,
        )
        .expect("rewrite args");
        assert_eq!(
            as_strings(&rewritten),
            vec![
                "--manifest-path".to_owned(),
                mirror_manifest.to_string_lossy().into_owned(),
            ]
        );
        let rewritten = rewrite_args_for_mirror(
            &[OsString::from(format!(
                "--manifest-path={}",
                workspace.path().join("sub/Cargo.toml").display()
            ))],
            &project,
            &mirror,
        )
        .expect("rewrite args");
        assert_eq!(
            as_strings(&rewritten),
            vec![format!(
                "--manifest-path={}",
                mirror.root().join("sub").join("Cargo.toml").display()
            )],
        );
    }

    /// Both sides of `relative_path`'s prefix check go through the same
    /// lossy canonicalization — resolving only the root through a
    /// symlink leaves the spelled path on the link's spelling and the
    /// check fails on a path that is inside the root (the macOS
    /// `/var -> /private/var` merge-queue failure).
    #[cfg(unix)]
    #[test]
    fn relative_path_matches_spelled_and_canonical_sides() {
        let base = tempfile::tempdir().expect("base");
        let real = base.path().join("real");
        std::fs::create_dir_all(&real).expect("real dir");
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let canonical_root = std::fs::canonicalize(&link).expect("canonical root");
        // A manifest that does not exist yet, spelled through the link.
        let spelled = link.join("member").join("Cargo.toml");
        let relative = relative_path(&canonical_root, &spelled).expect("inside root");
        assert_eq!(relative, Path::new("member").join("Cargo.toml"));
    }

    /// A manifest spelled before it exists still compares under the
    /// root — the missing tail must not break the prefix check.
    #[test]
    fn relative_path_keeps_missing_tail_components() {
        let root = tempfile::tempdir().expect("root");
        let spelled = root.path().join("sub").join("member").join("Cargo.toml");
        let relative = relative_path(root.path(), &spelled).expect("inside root");
        assert_eq!(relative, Path::new("sub").join("member").join("Cargo.toml"));
    }

    /// The mirror rewrite resolves the same way: a workspace under a
    /// symlink must accept an absolute `--manifest-path` spelled
    /// through the link (the reported failure shape).
    #[cfg(unix)]
    #[test]
    fn rewrite_args_for_mirror_resolves_through_symlinked_root() {
        let base = tempfile::tempdir().expect("base");
        let real = base.path().join("real");
        std::fs::create_dir_all(&real).expect("real dir");
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let project = ProjectContext {
            workspace_root: std::fs::canonicalize(&link).expect("canonical root"),
            manifest_path: link.join("Cargo.toml"),
            ..project_context()
        };
        let mirror = WorkspaceMirror {
            tempdir: tempfile::tempdir().expect("mirror"),
            current_dir_relative: PathBuf::new(),
        };
        let rewritten = rewrite_args_for_mirror(
            &[
                OsString::from("--manifest-path"),
                link.join("Cargo.toml").into_os_string(),
            ],
            &project,
            &mirror,
        )
        .expect("rewrite args");
        assert_eq!(
            as_strings(&rewritten),
            vec![
                "--manifest-path".to_owned(),
                mirror
                    .root()
                    .join("Cargo.toml")
                    .to_string_lossy()
                    .into_owned(),
            ]
        );
    }

    /// A plan whose only bundle is a `serde` cached artifact.
    fn single_serde_bundle_plan() -> CachedDependencyPlan {
        CachedDependencyPlan {
            bundles: [(
                "build-script-dep".to_owned(),
                crate::artifact_cache::CachedArtifactBundle {
                    provenance: crate::artifact_cache::ArtifactProvenance::Remote,
                    oci_reference: String::new(),
                    oci_digest: String::new(),
                    compile_key: String::new(),
                    crate_name: "serde".to_owned(),
                    crate_version: "1.0.228".to_owned(),
                    c_metadata: "build-script-dep".to_owned(),
                    features_json: String::new(),
                    dependency_c_metadata_json: "[]".to_owned(),
                    dependency_compile_keys_json: "[]".to_owned(),
                    compile_millis: 0,
                    size_bytes: 0,
                    profile: cached_dependency_profile(),
                    emit: Vec::new(),
                    kind: stow_types::artifact::ArtifactKind::Rlib,
                    crate_types: vec![stow_types::artifact::RustCrateType::Lib],
                    outputs: Vec::new(),
                    sigstore_signatures: Vec::new(),
                    entry_dir: PathBuf::new(),
                    rustc_version: "1.91.1".to_owned(),
                    cache_key: String::new(),
                    verified_marker_version: None,
                    verified_marker_policy: None,
                    _lease_lock: tempfile::tempfile().expect("temp lease"),
                },
            )]
            .into(),
            direct_externs: Vec::new(),
        }
    }

    #[test]
    fn top_crate_check_accepts_a_build_script_dependency() {
        let plan = single_serde_bundle_plan();
        let build_script_packages = BTreeSet::from([("serde".to_owned(), "1.0.228".to_owned())]);

        refuse_build_script_dependencies("check", &plan, &build_script_packages)
            .expect("check links nothing, so a build-script dependency is fine");
    }

    #[test]
    fn top_crate_build_refuses_a_build_script_dependency() {
        let plan = single_serde_bundle_plan();
        let build_script_packages = BTreeSet::from([("serde".to_owned(), "1.0.228".to_owned())]);

        let error = refuse_build_script_dependencies("build", &plan, &build_script_packages)
            .expect_err("build must refuse a dependency whose package has a build script");
        assert!(error.to_string().contains("serde 1.0.228"), "{error}");

        refuse_build_script_dependencies("build", &plan, &BTreeSet::new())
            .expect("no build-script packages means nothing to refuse");
    }

    #[test]
    fn build_script_packages_names_run_build_script_packages() {
        let unit = |kind: stow_types::unit_graph::TaskUnitKind, name: &str, version: &str| {
            stow_types::unit_graph::TaskUnit {
                key: stow_types::unit_graph::TaskUnitKey {
                    pkg: format!(
                        "registry+https://github.com/rust-lang/crates.io-index#{name}@{version}"
                    ),
                    platform: "aarch64-apple-darwin".to_owned(),
                    side: stow_types::unit_graph::TaskUnitSide::Target,
                    kind,
                },
                name: name.to_owned(),
                version: version.to_owned(),
                features: Vec::new(),
                is_crates_io: true,
                deps: Vec::new(),
            }
        };
        let units = vec![
            unit(
                stow_types::unit_graph::TaskUnitKind::Lib,
                "serde",
                "1.0.228",
            ),
            unit(
                stow_types::unit_graph::TaskUnitKind::BuildScript,
                "serde",
                "1.0.228",
            ),
            unit(
                stow_types::unit_graph::TaskUnitKind::RunBuildScript,
                "serde",
                "1.0.228",
            ),
        ];

        assert_eq!(
            build_script_packages(&units),
            BTreeSet::from([("serde".to_owned(), "1.0.228".to_owned())])
        );
        assert!(build_script_packages(&units[..2]).is_empty());
    }

    #[test]
    fn manifest_feature_pruning_keeps_local_feature_matching_required_dependency() {
        let dependency_keys = super::DependencyFeatureReferences {
            all: BTreeSet::from(["std".to_owned(), "serde".to_owned()]),
            optional: BTreeSet::from(["serde".to_owned()]),
        };

        assert!(!feature_references_dependency("std", &dependency_keys));
        assert!(feature_references_dependency("serde", &dependency_keys));
        assert!(feature_references_dependency("dep:std", &dependency_keys));
        assert!(feature_references_dependency(
            "std?/alloc",
            &dependency_keys
        ));
    }

    /// The mirror's `member` entry is a symlink into the real workspace, so
    /// a naive rewrite of `mirror/member/Cargo.toml` lands in the user's
    /// own manifest. The strip must materialize the path inside the mirror
    /// first: the member entry becomes a real directory and the manifest a
    /// real file, and the original bytes stay untouched.
    #[cfg(unix)]
    #[tokio::test]
    async fn manifest_strip_never_writes_through_the_mirror_symlink() {
        let temp = tempfile::tempdir().expect("temp workspace");
        let workspace = temp.path();
        std::fs::write(
            workspace.join("Cargo.toml"),
            "[workspace]\nmembers = [\"member\"]\n",
        )
        .expect("write workspace manifest");
        let member = workspace.join("member");
        std::fs::create_dir(&member).expect("create member dir");
        let manifest_source =
            "[package]\nname = \"member\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\n";
        std::fs::write(member.join("Cargo.toml"), manifest_source).expect("write member manifest");

        let project = ProjectContext {
            action: "check".to_owned(),
            cargo_args: Vec::new(),
            workspace_root: workspace.to_path_buf(),
            current_dir: member.clone(),
            current_dir_relative: PathBuf::from("member"),
            manifest_path: member.join("Cargo.toml"),
            metadata_args: MetadataArgs::default(),
            target: "aarch64-apple-darwin".to_owned(),
            target_given: false,
            rustc_version: "1.91.1".to_owned(),
            mold: MoldSelection::resolved(Vec::new()),
            env_base: None,
            build_rustc: crate::rustc_args::BuildRustc::ToolchainDefault,
            foreground: crate::derive_gate::ForegroundHold::detached(),
        };
        let mirror = create_workspace_mirror(&project, &project.workspace_root)
            .await
            .expect("create workspace mirror");

        strip_selected_manifest_dependencies(&project, &mirror)
            .await
            .expect("strip manifest in mirror");

        assert_eq!(
            std::fs::read_to_string(member.join("Cargo.toml")).expect("read member manifest"),
            manifest_source,
            "the user's real manifest must be untouched"
        );
        let mirror_member = mirror.root().join("member");
        assert!(
            std::fs::symlink_metadata(&mirror_member)
                .expect("mirror member metadata")
                .is_dir(),
            "mirror member must be materialized as a real directory"
        );
        let mirror_manifest = mirror_member.join("Cargo.toml");
        assert!(
            !std::fs::symlink_metadata(&mirror_manifest)
                .expect("mirror manifest metadata")
                .file_type()
                .is_symlink(),
            "mirror manifest must be a real file, not a link into the workspace"
        );
        let stripped = std::fs::read_to_string(&mirror_manifest).expect("read mirror manifest");
        assert!(stripped.contains("[package]"));
        assert!(
            !stripped.contains("serde"),
            "mirror manifest lost its dependency table: {stripped}"
        );
    }

    /// A `MoldSelection` a test completes by hand: the provisioning is
    /// the oneshot's send, so the reader waits exactly until the test
    /// releases it.
    fn hand_completed_selection() -> (tokio::sync::oneshot::Sender<Vec<String>>, MoldSelection) {
        let (release, selected) = tokio::sync::oneshot::channel();
        let selection = MoldSelection::deferred(async move {
            selected.await.map_err(|error| {
                stow_types::stow_error!("the test's mold selection channel closed: {error}")
            })
        });
        (release, selection)
    }

    /// stow#653: the passthrough's cargo command cannot be assembled
    /// before the mold selection resolves — the `--config` arguments
    /// exist only behind the provisioning's await.
    #[tokio::test]
    async fn a_passthrough_command_waits_for_the_mold_selection() {
        let (release, mold) = hand_completed_selection();
        let project = ProjectContext {
            mold,
            ..project_context()
        };
        let cargo_args = vec![OsString::from("--offline")];
        let command = tokio::spawn(async move {
            super::passthrough_command(&project, "build", &cargo_args, project.current_dir()).await
        });
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            !command.is_finished(),
            "the passthrough command assembled before the mold selection resolved"
        );
        release
            .send(vec![
                "target.x86_64-unknown-linux-gnu.linker=\"clang\"".to_owned(),
            ])
            .expect("release the mold selection");
        let command = command
            .await
            .expect("passthrough command task")
            .expect("passthrough command");
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_str().expect("utf8 arg").to_owned())
            .collect();
        assert_eq!(
            args,
            vec![
                "build".to_owned(),
                "--config".to_owned(),
                "target.x86_64-unknown-linux-gnu.linker=\"clang\"".to_owned(),
                "--offline".to_owned(),
            ]
        );
    }

    /// stow#653: the supervised path's cargo command waits on the same
    /// selection — `cargo_command` reads it at assembly like the
    /// passthrough does.
    #[tokio::test]
    async fn a_supervised_cargo_command_waits_for_the_mold_selection() {
        let (release, mold) = hand_completed_selection();
        let project = ProjectContext {
            mold,
            ..project_context()
        };
        let cargo_args = vec![OsString::from("--offline")];
        let command = tokio::spawn(async move {
            let plan = CargoRunPlan {
                project: &project,
                config: None,
                state_db: &crate::state_db::StateDb::default(),
                action: "check",
                cargo_args: &cargo_args,
                source_root: &project.workspace_root,
                current_dir: &project.current_dir,
                cache_policy_entries: None,
                public_cache_mode: &PublicCacheMode::Enabled,
                unit_nodes: None,
                prefetch_artifacts: None,
                servable_units: None,
                deferred_analysis: false,
                semantic_fallback_enabled: false,
                extra_rustflags: &[],
                covered_units: 0,
            };
            super::cargo_command(&plan).await
        });
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            !command.is_finished(),
            "the supervised cargo command assembled before the mold selection resolved"
        );
        release
            .send(vec![
                "target.x86_64-unknown-linux-gnu.linker=\"clang\"".to_owned(),
            ])
            .expect("release the mold selection");
        let command = command
            .await
            .expect("cargo command task")
            .expect("cargo command");
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_str().expect("utf8 arg").to_owned())
            .collect();
        assert_eq!(
            args,
            vec![
                "check".to_owned(),
                "--config".to_owned(),
                "target.x86_64-unknown-linux-gnu.linker=\"clang\"".to_owned(),
                "--offline".to_owned(),
            ]
        );
    }

    /// A selection that resolves to an error assembles no cargo
    /// command: the build fails on the provisioning's error rather
    /// than running without the linker selection (stow#653).
    #[tokio::test]
    async fn a_failed_provisioning_fails_the_command() {
        let project = ProjectContext {
            mold: MoldSelection::deferred(async {
                Err(stow_types::stow_error!("mold is not installable here"))
            }),
            ..project_context()
        };
        let error = super::passthrough_command(&project, "build", &[], project.current_dir())
            .await
            .expect_err("a failed provisioning must not assemble a cargo command");
        assert!(
            error.to_string().contains("mold is not installable here"),
            "the provisioning error is the command's error: {error}"
        );
    }

    /// A deferred selection runs its provisioning only when read —
    /// nothing polls it for a context that assembles no cargo build
    /// (stow#653).
    #[tokio::test]
    async fn a_deferred_selection_runs_only_when_read() {
        let polled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = polled.clone();
        let selection = MoldSelection::deferred(async move {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(vec!["selected".to_owned()])
        });
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            !polled.load(std::sync::atomic::Ordering::SeqCst),
            "a deferred selection's provisioning ran without a reader"
        );
        selection.config_args().await.expect("read the selection");
        assert!(polled.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// stow#652: a failing cargo hands its exit status back to the
    /// mirror's owner instead of exiting inside it — the test process
    /// surviving the call is the point, and the dropped mirror removes
    /// its directory. The passthrough is the cargo run a unit test can
    /// make without touching the per-user wrapper tools.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_failing_cargo_returns_to_the_mirrors_owner() {
        let temp = tempfile::tempdir().expect("temp workspace");
        let workspace = temp.path();
        std::fs::write(
            workspace.join("Cargo.toml"),
            "[workspace]\nmembers = [\"member\"]\n",
        )
        .expect("write workspace manifest");
        let member = workspace.join("member");
        std::fs::create_dir(&member).expect("create member dir");
        std::fs::write(
            member.join("Cargo.toml"),
            "[package]\nname = \"member\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("write member manifest");
        let src = member.join("src");
        std::fs::create_dir(&src).expect("create member src dir");
        std::fs::write(src.join("lib.rs"), "pub fn f() -> u32 { \"x\" }\n")
            .expect("write a lib that does not compile");

        let project = ProjectContext {
            action: "build".to_owned(),
            workspace_root: workspace.to_path_buf(),
            current_dir: member.clone(),
            current_dir_relative: PathBuf::from("member"),
            manifest_path: member.join("Cargo.toml"),
            ..project_context()
        };
        let mirror = create_workspace_mirror(&project, &project.workspace_root)
            .await
            .expect("create workspace mirror");
        let target_dir = tempfile::tempdir().expect("target dir");
        let cargo_args = vec![
            OsString::from("--target-dir"),
            target_dir.path().as_os_str().to_os_string(),
            OsString::from("--offline"),
        ];
        let status =
            super::run_cargo_passthrough(&project, "build", &cargo_args, &mirror.current_dir())
                .await
                .expect("run cargo");
        // 101 is cargo's own exit code for a build that did not compile:
        // the status is cargo's, not a wrapper's or a spawn failure's.
        assert_eq!(
            status.code(),
            Some(101),
            "a lib that does not compile ended with {status}"
        );
        let mirror_root = mirror.root().to_path_buf();
        drop(mirror);
        assert!(
            !mirror_root.exists(),
            "the mirror's directory survived its owner: {}",
            mirror_root.display()
        );
    }

    /// A `(crate, version)` unit-graph entry for `build_serve_map`'s
    /// expanded-graph input.
    fn graph_entry(
        name: &str,
        version: &str,
        host_side: bool,
    ) -> stow_types::api::ResolvedDependencyGraphEntry {
        stow_types::api::ResolvedDependencyGraphEntry {
            crate_name: stow_types::identity::CrateName::parse(name).expect("crate name"),
            version: semver::Version::parse(version).expect("version"),
            features: Vec::new(),
            host_side,
            dependencies: Vec::new(),
            dependency_subgraph: stow_types::api::TaskSubgraph::default(),
        }
    }

    /// The map `build_serve_map` produces with no index rows — these
    /// tests exercise the local half's unit set alone.
    fn local_only_map(
        project: &ProjectContext,
        expanded_entries: &[stow_types::api::ResolvedDependencyGraphEntry],
        local_units: &[(&str, &str, &str)],
        lockfile_packages: &[(&str, &str)],
    ) -> crate::facade::ServeMap {
        let local_units = local_units
            .iter()
            .map(|(name, version, target)| {
                (name.to_string(), version.to_string(), target.to_string())
            })
            .collect::<Vec<_>>();
        let lockfile_packages = lockfile_packages
            .iter()
            .map(|(name, version)| {
                (
                    (*name).to_owned(),
                    semver::Version::parse(version).expect("version"),
                )
            })
            .collect();
        build_serve_map(
            project,
            &[],
            None,
            expanded_entries,
            &local_units,
            &lockfile_packages,
        )
    }

    /// stow#608: with no cached graph and no local units the lite
    /// answer never opens the lockfile — a workspace root whose
    /// `Cargo.lock` cargo has not written yet is not an error, and the
    /// map's local half is empty.
    #[tokio::test]
    async fn no_graph_and_no_local_units_never_reads_the_lockfile() {
        let workspace = tempfile::tempdir().expect("workspace");
        let cache = tempfile::tempdir().expect("cache");
        // No Cargo.toml and no Cargo.lock: there is nothing to read.
        let config = test_config(cache.path());
        let project = ProjectContext {
            workspace_root: workspace.path().to_path_buf(),
            manifest_path: workspace.path().join("Cargo.toml"),
            ..project_context()
        };
        let prediction = super::analyze_workspace_prediction_from(
            &project,
            &config,
            super::AnalysisInputs {
                slice: None,
                host_slice: None,
                expanded: None,
                slice_pending: false,
            },
        )
        .await
        .expect("an absent lockfile is not an error");
        let map = prediction.servable_units.expect("a serve map");
        assert!(map.is_empty(), "nothing local to admit: {map:?}");
    }

    /// stow#617 through the real pass: no cached graph and a locally
    /// stored unit the lockfile's registry packages name — the read runs
    /// and the map's local half covers it.
    #[tokio::test]
    async fn a_lockfile_named_local_unit_lands_in_the_serve_map() {
        let workspace = tempfile::tempdir().expect("workspace");
        let cache = tempfile::tempdir().expect("cache");
        std::fs::write(
            workspace.path().join("Cargo.lock"),
            "version = 4\n\n\
             [[package]]\nname = \"probe\"\nversion = \"0.1.0\"\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        )
        .expect("write lockfile");
        let config = test_config(cache.path());
        let pool = config.state_db_pool().await.expect("state db pool");
        sqlx::query(sqlx::AssertSqlSafe(
            "INSERT INTO artifact_cache_entries \
             (rustc_version, cache_key, relative_dir, size_bytes, last_accessed_ms, \
              oci_reference, oci_digest, crate_name, crate_version, target, provenance) \
             VALUES ('1.91.1', 'key', 'dir', 0, 0, '', '', 'cfg-if', '1.0.0', \
              'aarch64-apple-darwin', 'local')",
        ))
        .execute(&pool)
        .await
        .expect("seed the local unit");
        let project = ProjectContext {
            workspace_root: workspace.path().to_path_buf(),
            manifest_path: workspace.path().join("Cargo.toml"),
            ..project_context()
        };
        let prediction = super::analyze_workspace_prediction_from(
            &project,
            &config,
            super::AnalysisInputs {
                slice: None,
                host_slice: None,
                expanded: None,
                slice_pending: false,
            },
        )
        .await
        .expect("analysis");
        let map = prediction.servable_units.expect("a serve map");
        assert_eq!(map.target, Vec::<(String, String)>::new());
        assert_eq!(
            map.host,
            vec![
                ("cfg_if".to_owned(), "*".to_owned()),
                ("cfg_if".to_owned(), "1.0.0".to_owned()),
            ]
        );
    }

    /// stow#617: with no expanded graph on disk the lockfile's registry
    /// packages name the build's units — a locally stored one of them
    /// serves whether the graph was ever resolved, and one the lockfile
    /// does not name stays out.
    #[test]
    fn a_local_unit_serves_without_an_expanded_graph() {
        let project = project_context();
        let map = local_only_map(
            &project,
            &[],
            &[
                ("a", "1.0.0", "aarch64-apple-darwin"),
                ("c", "3.0.0", "aarch64-apple-darwin"),
            ],
            &[("a", "1.0.0"), ("b", "2.0.0")],
        );
        // A native build spells no `--target`: every unit arrives
        // unspelled, so the covered pair and the name wildcard both
        // land on the host list.
        assert_eq!(map.target, Vec::<(String, String)>::new());
        assert_eq!(
            map.host,
            vec![
                ("a".to_owned(), "*".to_owned()),
                ("a".to_owned(), "1.0.0".to_owned())
            ]
        );
    }

    /// The same admission under a spelled `--target`: a row whose
    /// platform is the build's host triple lands on the host list, and
    /// a consumer-platform row lands on the target list (stow#617).
    #[test]
    fn a_host_platform_row_lands_on_the_host_list() {
        let project = ProjectContext {
            target: "aarch64-apple-ios".to_owned(),
            target_given: true,
            ..project_context()
        };
        let map = local_only_map(
            &project,
            &[],
            &[
                ("a", "1.0.0", "aarch64-apple-darwin"),
                ("b", "2.0.0", "aarch64-apple-ios"),
                ("c", "3.0.0", "aarch64-apple-ios"),
            ],
            &[("a", "1.0.0"), ("b", "2.0.0")],
        );
        assert_eq!(
            map.host,
            vec![
                ("a".to_owned(), "*".to_owned()),
                ("a".to_owned(), "1.0.0".to_owned())
            ]
        );
        assert_eq!(
            map.target,
            vec![
                ("b".to_owned(), "*".to_owned()),
                ("b".to_owned(), "2.0.0".to_owned())
            ]
        );
    }

    /// With a cached expanded graph nothing changes: the local half is
    /// still gated on the graph's own per-side unit sets, and a locally
    /// stored crate the graph does not name stays out.
    #[test]
    fn a_cached_graph_still_gates_the_local_half() {
        let project = project_context();
        let entries = [
            graph_entry("a", "1.0.0", false),
            graph_entry("d", "4.0.0", true),
        ];
        let map = local_only_map(
            &project,
            &entries,
            &[
                ("a", "1.0.0", "aarch64-apple-darwin"),
                ("d", "4.0.0", "aarch64-apple-darwin"),
                ("b", "2.0.0", "aarch64-apple-darwin"),
            ],
            &[],
        );
        assert_eq!(map.target, Vec::<(String, String)>::new());
        assert_eq!(
            map.host,
            vec![
                ("a".to_owned(), "*".to_owned()),
                ("a".to_owned(), "1.0.0".to_owned()),
                ("d".to_owned(), "*".to_owned()),
                ("d".to_owned(), "4.0.0".to_owned()),
            ]
        );
    }

    /// stow#625: the tables a workspace-sized build carries — the unit
    /// graph, the prefetch ledger, the extra rustc args — travel as
    /// files, so every environment value `export_wrapper_env` sets must
    /// stay a path or a flag, never the payload.
    struct TableExport {
        _cache: tempfile::TempDir,
        env: Vec<(OsString, OsString)>,
        table: crate::unit_node::UnitNodeTable,
        ledger: Vec<PrefetchArtifact>,
    }

    fn stow_config(cache_dir: &Path) -> crate::config::StowConfig {
        crate::config::StowConfig {
            edge_url: "http://127.0.0.1:1".to_owned(),
            registry_base_url: "http://127.0.0.1:1/v2/mock".to_owned(),
            cache_dir: cache_dir.to_path_buf(),
            request_timeout: std::time::Duration::from_secs(1),
            negative_cache_ttl: std::time::Duration::from_secs(1),
            circuit_reset_after: std::time::Duration::from_secs(1),
            circuit_trip_threshold: 1,
            artifact_cache_max_bytes: 1,
            index_refresh_interval: std::time::Duration::from_secs(1),
            verify_mode: crate::config::VerifyMode::GithubCi,
            state_db: crate::state_db::StateDb::default(),
            trust_material: std::sync::Arc::default(),
            registry_http: std::sync::Arc::default(),
            artifact_cache_staging: std::sync::Arc::default(),
        }
    }

    fn unit_table(nodes: usize) -> crate::unit_node::UnitNodeTable {
        crate::unit_node::UnitNodeTable {
            consumer_spelled_target: true,
            nodes: (0..nodes)
                .map(|index| crate::unit_node::UnitNode {
                    crate_name: stow_types::identity::CrateName::parse(format!("crate-{index}"))
                        .expect("crate name"),
                    version: semver::Version::new(1, (index / 100) as u64, (index % 100) as u64),
                    host_side: index % 2 == 0,
                    features: vec![
                        "default".to_owned(),
                        format!("feature-{index}"),
                        format!("a-longer-feature-name-{index}"),
                    ],
                })
                .collect(),
        }
    }

    fn prefetch_ledger(rows: usize) -> Vec<PrefetchArtifact> {
        (0..rows)
            .map(|index| PrefetchArtifact {
                crate_name: format!("crate-{index}"),
                c_metadata: format!("{index:016x}"),
                bundle_digest: format!("sha256:{index:064x}"),
                target: "aarch64-apple-darwin".to_owned(),
                rustc_version: "1.91.1".to_owned(),
                depth: index,
            })
            .collect()
    }

    fn row_identity(row: &crate::resolve::PrefetchArtifactRow) -> (&str, &str, &str) {
        (
            row.crate_name.as_str(),
            row.c_metadata.as_str(),
            row.bundle_digest.as_str(),
        )
    }

    /// Run `export_wrapper_env` against a `nodes`-entry unit table and a
    /// `ledger_rows`-entry prefetch ledger, collecting the environment
    /// it hands cargo.
    fn exported_wrapper_env(nodes: usize, ledger_rows: usize) -> TableExport {
        let cache = tempfile::tempdir().expect("cache dir");
        let workspace = cache.path().join("ws");
        let project = ProjectContext {
            workspace_root: workspace.clone(),
            current_dir: workspace.clone(),
            manifest_path: workspace.join("Cargo.toml"),
            ..project_context()
        };
        let config = stow_config(cache.path());
        let table = unit_table(nodes);
        let ledger = prefetch_ledger(ledger_rows);
        let wrappers = crate::commands::WrapperCommands {
            rustc: "/tools/stow-rustc-wrapper".to_owned(),
            cc_launcher: "/tools/stow-cc-launcher".to_owned(),
            cc_compiler: "/tools/stow-cc".to_owned(),
            cxx_compiler: "/tools/stow-cxx".to_owned(),
        };
        let plan = CargoRunPlan {
            project: &project,
            config: Some(&config),
            state_db: &config.state_db,
            action: "check",
            cargo_args: &[],
            source_root: &project.workspace_root,
            current_dir: &project.current_dir,
            cache_policy_entries: None,
            public_cache_mode: &PublicCacheMode::Enabled,
            unit_nodes: Some(&table),
            prefetch_artifacts: Some(&ledger),
            servable_units: None,
            semantic_fallback_enabled: true,
            deferred_analysis: false,
            extra_rustflags: &[],
            covered_units: ledger.len(),
        };
        let mut command = async_process::Command::new("cargo");
        smol::block_on(super::export_wrapper_env(
            &mut command,
            &plan,
            &wrappers,
            None,
            None,
            cache.path(),
        ))
        .expect("export wrapper env");
        let env = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_os_string(),
                    value
                        .expect("an exported variable carries a value")
                        .to_os_string(),
                )
            })
            .collect();
        TableExport {
            _cache: cache,
            env,
            table,
            ledger,
        }
    }

    #[test]
    fn build_sized_tables_ride_files_not_environment_strings() {
        let export = exported_wrapper_env(3_000, 3_000);
        for (key, value) in &export.env {
            assert!(
                value.len() <= 4_096,
                "{} holds {} bytes; a build-sized payload must travel as a file path",
                key.to_string_lossy(),
                value.len()
            );
        }
        let path_of = |name: &str| -> PathBuf {
            PathBuf::from(
                export
                    .env
                    .iter()
                    .find(|(key, _)| key.as_os_str() == name)
                    .unwrap_or_else(|| panic!("{name} was not exported"))
                    .1
                    .clone(),
            )
        };
        let graph: crate::unit_node::UnitNodeTable = crate::read_build_json_table(
            &path_of(crate::STOW_EXPANDED_GRAPH_PATH_ENV),
            crate::STOW_EXPANDED_GRAPH_PATH_ENV,
        )
        .expect("read back the expanded graph file");
        assert_eq!(
            serde_json::to_vec(&graph).expect("encode read-back table"),
            serde_json::to_vec(&export.table).expect("encode source table"),
            "the file round-trips the unit table"
        );
        let read_rows: Vec<crate::resolve::PrefetchArtifactRow> = crate::read_build_json_table(
            &path_of(crate::STOW_PREFETCH_ARTIFACTS_PATH_ENV),
            crate::STOW_PREFETCH_ARTIFACTS_PATH_ENV,
        )
        .expect("read back the prefetch ledger file");
        let read: Vec<_> = read_rows.iter().map(row_identity).collect();
        let expected_rows = super::prefetch_artifact_rows(&export.ledger).expect("expected rows");
        let expected: Vec<_> = expected_rows.iter().map(row_identity).collect();
        assert_eq!(read, expected, "the file round-trips the prefetch ledger");
    }

    /// stow#625's control: a single environment value past Linux's
    /// `MAX_ARG_STRLEN` fails `execve` outright — the failure mode the
    /// file transport removes.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_exported_environment_survives_execve_where_an_inline_table_cannot() {
        let export = exported_wrapper_env(3_000, 3_000);
        let status = std::process::Command::new("/bin/true")
            .env_clear()
            .envs(export.env.iter().map(|(key, value)| (key, value)))
            .status()
            .expect("spawn /bin/true with the build's environment");
        assert!(status.success());

        let error = std::process::Command::new("/bin/true")
            .env_clear()
            .env("STOW_INLINE_TABLE", "x".repeat(200_000))
            .spawn()
            .expect_err("a 200,000-byte environment value cannot pass execve");
        assert_eq!(error.raw_os_error(), Some(libc::E2BIG));
    }
}
