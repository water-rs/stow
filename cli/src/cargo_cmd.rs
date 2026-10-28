use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::time::Instant;

use async_process::{Command, ExitStatus};
use futures_util::future::{BoxFuture, FutureExt as _, Shared};
use stow_types::error::Context;
use stow_types::public_cache::UnitShape;
use tempfile::TempDir;
use zenwave::{Client, ResponseExt};

use crate::budget::CacheBudget;
use crate::cache_policy::{self, CachePolicyEntry};
use crate::cli_args::CargoCommandArgs;
use crate::config::StowConfig;
use crate::index;
use crate::lockfile_resolver;
use crate::log_nonfatal_result;
use crate::prefetch::{self, PrefetchArtifact};
use crate::resolve;
use crate::rustc_args::{self, STOW_PUBLIC_CACHE_RUSTC_VERSION_ENV, STOW_PUBLIC_CACHE_TARGET_ENV};
use crate::state_db::StateDb;
use crate::stats;
use crate::workspace_deps::{self, ExpandedDependencyGraph, PackageKey};
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
    let mut invocation = CargoInvocation::new(command, args);
    let config =
        tracing::debug_span!("stow.precargo.config_load").in_scope(|| load_stow_config(state_db));
    invocation.sandbox = resolve_sandbox_request(&invocation, config.as_ref())?;
    let project = begin_project(config.as_ref(), &invocation).await?;
    let mut public_cache_mode = PublicCacheMode::for_rustc(&project.rustc_version);
    if let PublicCacheMode::Disabled { message, .. } = &public_cache_mode {
        write_stdout(&format!("{message}\n"))?;
    }

    // Dev-profile LTO used to mean no cache could serve this build —
    // `-C linker-plugin-lto` had no identity. Now the flag keys into
    // extra-codegen, so the workspace keeps its *local* cache and loses
    // only the remote half: every unit is local-only by construction
    // (stow#1006).
    if public_cache_mode.is_enabled()
        && let Some(divergence) =
            crate::profile_guard::dev_profile_divergence(&project.workspace_root).await?
    {
        let message = format!(
            "warning: stow public cache is disabled for this build because {divergence}; \
             the local cache still serves its own entries"
        );
        write_stdout(&format!("{message}\n"))?;
        public_cache_mode = PublicCacheMode::Disabled {
            reason: "profile",
            message,
        };
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
        invocation.sandbox,
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
        inexact_entries: analysis
            .as_ref()
            .map(|analysis| analysis.inexact_entries.as_slice()),
        // A configured build's facts came from the filesystem-only pass:
        // the full graph analysis is owed to the build while cargo runs.
        deferred_analysis: config.is_some(),
        semantic_fallback_enabled,
        covered_units,
        sandbox: invocation.sandbox,
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
    // semantic paths get the post-upgrade transitive graph + prefetch list.
    // Without this, the upgrade branch ran the mirror with no cache plumbing
    // and saw 0 hits — the primary cause of the predict-vs-runtime gap
    // reported on populated mocks.
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
    let mirror_inexact = mirror_analysis
        .as_ref()
        .map(|analysis| analysis.inexact_entries.clone());

    let cache_policy_entries = Box::pin(prepare_build_cache_plan(
        config,
        project,
        &mirror.current_dir(),
        &mirror_manifest_path,
        public_cache_mode,
        mirror_analysis,
        budget,
    ))
    .await?;

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
        inexact_entries: mirror_inexact.as_deref(),
        deferred_analysis: false,
        semantic_fallback_enabled: mirror_semantic_fallback,
        covered_units: mirror_prefetch.as_ref().map_or(0, Vec::len),
        sandbox: invocation.sandbox,
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
        host_target: project.host_target.clone(),
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
    let Some(analysis) = Box::pin(analyze_for_prediction(args, state_db)).await? else {
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
    /// The resolved sandbox request — `None` unless the flags or the
    /// config opted in (stow#779). `new` carries the flags' answer,
    /// which `run_inner` merges with the config's `experimental` table.
    sandbox: Option<crate::sandbox::SandboxNetwork>,
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
            sandbox: crate::sandbox::SandboxNetwork::from_flags(
                args.sandbox.sandbox,
                args.sandbox.sandbox_deny_network,
            ),
        }
    }
}

/// Merge the invocation's `--sandbox*` flags with the config's
/// `experimental` table: either source turns the sandbox on, and either
/// source's deny switch makes it deny-all (which implies sandbox). A
/// `--sandbox` invocation on a platform heel has no backend for fails
/// the command here, before any cargo runs (stow#779).
fn resolve_sandbox_request(
    invocation: &CargoInvocation,
    config: Option<&StowConfig>,
) -> stow_types::error::Result<Option<crate::sandbox::SandboxNetwork>> {
    let sandbox = crate::sandbox::SandboxNetwork::merge(
        invocation.sandbox,
        config.and_then(|config| {
            crate::sandbox::SandboxNetwork::from_flags(
                config.experimental.sandbox,
                config.experimental.sandbox_deny_network,
            )
        }),
    );
    if sandbox.is_none() {
        return Ok(None);
    }
    if !crate::sandbox::SANDBOX_SUPPORTED {
        return Err(stow_types::stow_error!(
            "--sandbox is not supported on {}: the heel sandbox backend exists for Linux, macOS and Windows",
            std::env::consts::OS
        ));
    }
    Ok(sandbox)
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
    /// The compiling rustc's real `host:` triple — where build scripts
    /// and proc macros compile, which is not the consumer target under
    /// a `--target` build (stow#317) and not a target-to-runner mapping.
    pub host_target: String,
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
        let (target, rustc_version, host_vv, foreground) =
            tokio::join!(self.target, self.rustc_version, self.rustc_vv, foreground);
        let target =
            target.map_err(|error| stow_types::stow_error!("detect rustc host target: {error}"))?;
        let rustc_version = rustc_version
            .map_err(|error| stow_types::stow_error!("detect rustc version: {error}"))?;
        // The compiling rustc's own `host:` — build scripts and proc
        // macros compile for it — out of the shared `-vV` the build's
        // other facts already came from (stow#317).
        let host_target = host_vv
            .and_then(|vv| crate::rustc_args::vv_host(&vv))
            .map_err(|error| stow_types::stow_error!("detect rustc host target: {error}"))?;
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
            host_target,
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
    /// Direct-dep entries above an inexactly-served node (stow#882) —
    /// the exact chain the inexact-hit admission asks the scheduler to
    /// build. Empty when nothing is served by a superset.
    inexact_entries: Vec<DependencyGraphEntry>,
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
            inexact_entries: Vec::new(),
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
/// are read, once on a blocking thread, only when the map has units a
/// missing graph cannot name: the local listing's units or a slice's
/// index rows (stow#608, stow#617, stow#805).
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

/// stow#882: the inexact report's entries — the direct-dep entries
/// above every inexactly-served node. `inexact_keys` names the nodes
/// the analysis could only serve through a superset; the report is
/// the exact chain, each such node and everything above it — posted
/// as `entries` + the full expanded graph, which the edge re-derives
/// into the enqueue set and the scheduler merge dedups against
/// coverage.
fn inexact_report_entries(
    entries: &[DependencyGraphEntry],
    expanded: &[ResolvedDependencyGraphEntry],
    inexact_keys: &BTreeSet<(resolve::PackageKey, String)>,
) -> stow_types::error::Result<Vec<DependencyGraphEntry>> {
    if inexact_keys.is_empty() {
        return Ok(Vec::new());
    }
    let requested_features = |features_json: &str| {
        serde_json::from_str::<Vec<String>>(features_json).map_err(|error| {
            stow_types::stow_error!("inexact features_json `{features_json}`: {error}")
        })
    };
    // Nodes whose only coverage is a superset, by expanded-graph
    // position — then parents up to the direct-dep entries.
    let mut inexact_at = Vec::new();
    for (index, node) in expanded.iter().enumerate() {
        for (pkg, features_json) in inexact_keys {
            if pkg.crate_name == node.crate_name
                && pkg.version == node.version
                && requested_features(features_json)? == node.features
            {
                inexact_at.push(index);
                break;
            }
        }
    }
    // Reverse dep edges, keyed like `dependencies` entries — a package
    // may appear once per side, so host_side rides the key.
    let mut parents = BTreeMap::<(&str, &semver::Version, bool), Vec<usize>>::new();
    for (index, node) in expanded.iter().enumerate() {
        for dep in &node.dependencies {
            parents
                .entry((dep.crate_name.as_str(), &dep.version, dep.host_side))
                .or_default()
                .push(index);
        }
    }
    let mut roots = Vec::new();
    let mut seen = BTreeSet::new();
    let mut frontier = inexact_at;
    while let Some(index) = frontier.pop() {
        if !seen.insert(index) {
            continue;
        }
        let node = &expanded[index];
        if let Some(entry) = entries.iter().find(|entry| {
            entry.crate_name == node.crate_name
                && entry.version == node.version
                && entry.features == node.features
        }) {
            roots.push(entry.clone());
            continue;
        }
        frontier.extend(
            parents
                .get(&(node.crate_name.as_str(), &node.version, node.host_side))
                .into_iter()
                .flatten()
                .copied(),
        );
    }
    Ok(roots)
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
    // units for the serve map, and a unit graph names them better — so
    // the file is read, ahead of the map build, only when there is no
    // graph and the map has units to name: the local listing's units
    // (stow#617) or a slice's index rows (stow#805). A build whose
    // lockfile cargo has not written yet, and one with nothing to
    // admit, never opens the file (stow#608).
    let slices_carry_rows = [&slice, &host_slice]
        .into_iter()
        .flatten()
        .any(|slice| !slice.index.rows.is_empty());
    let lockfile_packages = if expanded.is_none() && (!local_units.is_empty() || slices_carry_rows)
    {
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
    let analysis = resolve::analyze_dependency_graph(
        &rows,
        &entries,
        &expanded_in,
        &project.target,
        &project.rustc_version,
        resolve::host_glibc(),
    )?;

    // The wrapper's decision path resolves each compiled unit against
    // the per-side node table — the entries' cargo-resolved feature sets
    // plus whether the graph's invocation spelled `--target` (stow#615).
    let unit_nodes = Some(crate::unit_node::UnitNodeTable::from_expanded(
        &expanded.entries,
        project.target_given,
    ));
    // stow#882: the inexact report carries the exact chain — each
    // node the analysis marked superset-served plus every direct-dep
    // entry above it (the edge re-derives the enqueue set; the
    // scheduler merge dedups the already-published interior).
    let inexact_entries = inexact_report_entries(&entries, &expanded_in, &analysis.inexact_keys)?;
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
        inexact_entries,
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
/// The two halves admit against the build's units *as far as the map
/// can prove them*: the expanded graph's own per-side unit sets when a
/// graph is cached — index coverage claims a feature set and a side
/// only the graph proves — and `lockfile_packages` on both sides when
/// it is not (stow#617, stow#805). A lockfile cannot tell the sides
/// apart, and the pair set errs on covering: a unit wrongly included
/// costs a plan round trip, a unit wrongly excluded compiles despite an
/// artifact being available. The local half still asks for less than
/// the index half: the exact-key local lookup the plan path runs needs
/// neither a graph nor a slice, so a locally stored unit is admitted
/// whenever the build's units name it. Without the graph the side is
/// unknowable, and a wrong side costs the round trip the map already
/// tolerates; the unit's side itself still comes from its row's
/// platform. The caller reads the lockfile only when the map has units
/// to name (stow#608), and a lockfile cargo has not written yet reads
/// as an empty set — no fallback, no error — so the in-build enrichment
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
    // expanded graph's own sets when one is cached, and the lockfile's
    // registry packages on both sides when it is not (stow#617).
    let lockfile_units = canonical_lockfile_packages(lockfile_packages);
    let (consumer_known, host_known) = if expanded_entries.is_empty() {
        (&lockfile_units, &lockfile_units)
    } else {
        (&consumer_units, &host_units)
    };
    let consumer_servable: BTreeSet<(String, String)> = consumer_known
        .intersection(&consumer_index_pairs)
        .cloned()
        .collect();
    let host_servable: BTreeSet<(String, String)> = host_known
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
) -> Result<(index::IndexSlice, Option<index::IndexSlice>), index::SliceFetchError> {
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
    // "Pending" is a fetch fact, not an absence fact: the enrichment's
    // `ensure_slice` consults the registry whenever the pointer is
    // missing, stale past `index_refresh_interval`, or the interval is
    // 0 — the same rule `fetch_slice` itself applies (stow#788). A
    // stale-but-readable generation is provisional too: the map the
    // lite pass writes from it stays provisional until the fetched
    // answer replaces it.
    let pending = index::slice_fetch_pending(config, &project.target, &project.rustc_version)
        .await?
        || match host_target.as_deref() {
            Some(target) if host_slice_expected => {
                index::slice_fetch_pending(config, target, &project.rustc_version).await?
            }
            _ => false,
        };
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
/// The caller's journal keeps the observations on failure — including
/// an admission the drain could not redeem — so a later drain retries
/// them with a fresh challenge (stow#317, stow#929).
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
    let mut published_shapes: BTreeMap<String, (UnitShape, bool)> = BTreeMap::new();
    for slice_target in [consumer_target, build_host] {
        if let Some(slice) = index::cached_slice(config, slice_target, rustc_version).await? {
            for row in slice.index.rows {
                published_shapes
                    .entry(row.c_metadata.as_str().to_owned())
                    .and_modify(|(shape, consistent)| {
                        if shape.side != row.unit_shape.side {
                            *consistent = false;
                        }
                    })
                    .or_insert((row.unit_shape, true));
            }
        }
    }
    let published_shapes: BTreeMap<String, UnitShape> = published_shapes
        .into_iter()
        .filter_map(|(c_metadata, (shape, consistent))| consistent.then_some((c_metadata, shape)))
        .collect();
    for (c_metadata, dep) in &mut dep_identities {
        dep.unit_shape = published_shapes.get(c_metadata).copied();
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
        stow_types::api::CliAdmissionSource::CacheMiss,
        &graph.roots,
        &graph.expanded,
    )
    .await?;
    redeem_minted(config, minted).await
}

/// Redeem every admission `/api/v1/admissions` minted, failing when any
/// was not redeemed — refused over the difficulty cap, unsolved before
/// the attempt budget ran out, cancelled, or whose enqueue post failed
/// or was not answered with a success status. The caller's journal
/// keeps the entries behind them (stow#929).
async fn redeem_minted(
    config: &StowConfig,
    minted: Vec<EnqueueAdmission>,
) -> stow_types::error::Result<()> {
    let mut admissions = crate::admission::AdmissionCollector::default();
    admissions.record(config, minted);
    let unredeemed = admissions.drain(config).await;
    if !unredeemed.is_empty() {
        return Err(stow_types::stow_error!(
            "{} enqueue admission(s) were not redeemed: {}",
            unredeemed.len(),
            unredeemed.join(", ")
        ));
    }
    Ok(())
}

/// Post an inexact superset-hit report (stow#882): the direct-dep
/// entries above the nodes the analysis could only serve through a
/// superset, plus the build's expanded graph — minted through the same
/// `/api/v1/admissions` proof-of-work a miss takes, carrying the
/// `InexactHit` source the scheduler queues at very low priority.
/// Called from the detached miss drain — the caller keeps its journal
/// line on failure, including an admission the drain could not redeem,
/// so a later drain retries it (stow#929).
pub async fn admit_inexact_report(
    config: &StowConfig,
    consumer_target: &str,
    rustc_version: &str,
    entries: &[DependencyGraphEntry],
    expanded: &ExpandedDependencyGraph,
) -> stow_types::error::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let Some(_family) = stow_types::api::runner_family(consumer_target) else {
        tracing::info!(
            target = %consumer_target,
            "consumer target is not a CI target; not posting the inexact report"
        );
        return Ok(());
    };
    let minted = query_admissions(
        config,
        consumer_target,
        rustc_version,
        stow_types::api::CliAdmissionSource::InexactHit,
        entries,
        &expanded.entries,
    )
    .await?;
    redeem_minted(config, minted).await
}

/// Post the graph to `/api/v1/admissions` and return the enqueue
/// admissions the edge mints for its misses. This is the only call that
/// ships the dependency graph off the machine — the catalog lookup itself
/// is local.
async fn query_admissions(
    config: &StowConfig,
    target: &str,
    rustc_version: &str,
    source: stow_types::api::CliAdmissionSource,
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
        source,
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
            None,
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
    .map(Some)
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
    let (slice, host_slice) = {
        let (slice, host_slice, _) = cached_consumer_slices(config, project)
            .instrument(tracing::debug_span!("stow.precargo.cached_slices"))
            .await?;
        (slice, host_slice)
    };
    let Some(slice) = slice else {
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
        // Host-side rows pin host-only subtrees the same way: on a
        // `--target` build a direct dep can exist only in the host
        // slice (stow#788).
        let mut rows = slice.index.rows;
        if let Some(host_slice) = host_slice {
            rows.extend(host_slice.index.rows);
        }
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

/// Run cargo against a `PinnedMirror` whose analysis succeeded: cargo under
/// the wrapper with the pinned graph's cache plan. Returns cargo's own exit
/// status — success or not (stow#652).
async fn run_pinned_mirror_build(
    config: &StowConfig,
    project: &ProjectContext,
    invocation: &CargoInvocation,
    pinned: &PinnedMirror,
    public_cache_mode: &PublicCacheMode,
    mirror_analysis: WorkspacePrediction,
) -> stow_types::error::Result<ExitStatus> {
    let mirror_unit_nodes = mirror_analysis.unit_nodes.clone();
    let mirror_prefetch = mirror_analysis.prefetch_artifacts.clone();
    let mirror_servable = mirror_analysis.servable_units.clone();
    let mirror_inexact = mirror_analysis.inexact_entries.clone();
    let mirror_semantic_fallback = mirror_unit_nodes
        .as_ref()
        .is_some_and(|table| !table.nodes.is_empty());

    // The resolver path builds its own graph analysis for the pinned mirror,
    // so it sizes its own allowance from that.
    let budget = CacheBudget::for_covered_units(mirror_prefetch.len());

    let cache_policy_entries = Box::pin(prepare_build_cache_plan(
        Some(config),
        project,
        &pinned.mirror.current_dir(),
        &pinned.manifest_path,
        public_cache_mode,
        Some(mirror_analysis),
        &budget,
    ))
    .await?;

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
        inexact_entries: Some(&mirror_inexact),
        deferred_analysis: false,
        semantic_fallback_enabled: mirror_semantic_fallback,
        covered_units: mirror_prefetch.len(),
        sandbox: invocation.sandbox,
    })
    .await
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
/// pins via `analyze_workspace_prediction`, and falls back to passthrough
/// then.
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
            "  direct deps with cached artifacts: {} / {} ({:.1}%)",
            analysis.current_cached,
            analysis.current_total,
            percentage(analysis.current_cached, analysis.current_total),
        ),
        "    NOTE: 'index has rows for' is an upper bound — the runtime additionally requires the"
            .to_owned(),
        "    cached artifact's dependency_c_metadata_json to match the user's lockfile-resolved"
            .to_owned(),
        "    transitive graph. Serving is per unit: every covered unit is injected and the"
            .to_owned(),
        "    rest compile. For arbitrary projects, populate the cache with `stow-admin".to_owned(),
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
    sandbox: Option<crate::sandbox::SandboxNetwork>,
) -> stow_types::error::Result<ExitStatus> {
    if let Some(network) = sandbox {
        return run_cargo_passthrough_sandboxed(project, action, cargo_args, current_dir, network)
            .await;
    }
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

/// The passthrough's sandboxed form (stow#779): no `RUSTC_WRAPPER`, no
/// supervisor — the sandbox alone enforces the boundary. Dependencies
/// are fetched on the host first, then cargo runs `--offline` inside.
/// With no facades there is no IPC router either: a denied-network
/// build's only channel out does not exist, which is the point.
async fn run_cargo_passthrough_sandboxed(
    project: &ProjectContext,
    action: &str,
    cargo_args: &[OsString],
    current_dir: &Path,
    network: crate::sandbox::SandboxNetwork,
) -> stow_types::error::Result<ExitStatus> {
    crate::sandbox::fetch_dependencies(current_dir, cargo_args).await?;
    let mold_args = project.mold.config_args().await?;
    let mut argv = Vec::with_capacity(cargo_args.len() + mold_args.len() * 2 + 2);
    argv.push(OsString::from(action));
    for config_arg in mold_args.iter() {
        argv.push(OsString::from("--config"));
        argv.push(OsString::from(config_arg));
    }
    argv.extend(cargo_args.iter().cloned());
    if !argv
        .iter()
        .any(|arg| arg == "--offline" || arg == "--frozen")
    {
        argv.push(OsString::from("--offline"));
    }
    let mut envs: Vec<(OsString, OsString)> = Vec::new();
    if std::env::var_os("CARGO_TARGET_DIR").is_none() && !has_explicit_target_dir(cargo_args) {
        envs.push((
            OsString::from("CARGO_TARGET_DIR"),
            project.workspace_root.join("target").into_os_string(),
        ));
    }
    let target_dir = resolved_target_dir(project, cargo_args, current_dir);
    let runtime = std::env::current_exe().wrap_err("resolve current executable")?;
    // The workspace root plus the manifest directory `current_dir`
    // walks up to: a member's cargo reads its workspace root manifest,
    // and a mirrored run's sources link into the real workspace — both
    // spellings are covered.
    let mut source_roots = vec![project.workspace_root.clone()];
    let manifest_root = enclosing_manifest_dir(current_dir);
    if !source_roots.contains(&manifest_root) {
        source_roots.push(manifest_root);
    }
    let request = crate::sandbox::SandboxRequest {
        network,
        source_roots: &source_roots,
        target_dir: &target_dir,
        scratch_dir: None,
        shims_dir: None,
        runtime_executable: &runtime,
        rustc_executable: Path::new(project.build_rustc.executable()),
        host_target: project.host_target.as_str(),
        cargo_dir: current_dir,
        cargo_args,
        ipc: None,
    };
    let sandbox = crate::sandbox::BuildSandbox::create(request).await?;
    envs.extend(crate::sandbox::toolchain_envs()?);
    envs.push((
        OsString::from("CARGO_TARGET_DIR"),
        target_dir.into_os_string(),
    ));
    let command = crate::sandbox::SandboxedCommand::new("cargo", &argv, &envs, current_dir)?;
    let status = sandbox
        .status(&command)
        .await
        .wrap_err_with(|| format!("run cargo {action} (sandboxed passthrough)"))?;
    project.foreground.release();
    Ok(status)
}

/// The nearest ancestor of `dir` that holds a `Cargo.toml` — where cargo
/// finds the manifest it walks up to. `dir` itself when none names one.
fn enclosing_manifest_dir(dir: &Path) -> PathBuf {
    let dir = crate::workspace_deps::canonicalize_or_original(dir);
    dir.ancestors()
        .find(|ancestor| ancestor.join("Cargo.toml").exists())
        .map_or_else(|| dir.clone(), Path::to_path_buf)
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
    /// The analysis's inexact superset-hit report — the direct-dep
    /// entries above every superset-served node (stow#882). Journaled
    /// beside the build's misses after cargo exits; a detached drain
    /// posts it behind the same `PoW` admission.
    inexact_entries: Option<&'a [DependencyGraphEntry]>,
    /// The analysis deferral: `true` when the facts this build starts
    /// with came from the filesystem-only pass and the full graph
    /// analysis is owed to the build while cargo runs (stow#347).
    /// `false` on the mirror paths: they already paid the full analysis
    /// for their pinned graph.
    deferred_analysis: bool,
    semantic_fallback_enabled: bool,
    covered_units: usize,
    /// The heel sandbox cargo runs inside, `None` for the default
    /// unsandboxed build (stow#779).
    sandbox: Option<crate::sandbox::SandboxNetwork>,
}

/// The build's cargo run under the wrapper. Returns cargo's own exit
/// status, success or not — the status travels up to the caller that
/// owns what the build leaves behind, and only the top of the command
/// turns it into the process's exit (stow#652).
/// The build's pre-cargo state — everything `run_cargo` lays out before
/// the supervisor and cargo spawn: the scratch directory every generated
/// file lives under (stow#630), the wrapper shims, the argv and `STOW_*`
/// environment cargo reads, the seeded policy dir and the serve map
/// whose `pending` signal holds the facades it cannot yet cover.
struct CargoRunSetup {
    scratch: tempfile::TempDir,
    wrappers: crate::commands::WrapperCommands,
    launch: CargoLaunch,
    cache_policy_path: Option<PathBuf>,
    serve_map_ready: std::sync::Arc<crate::facade::ServeMapSignal>,
    serve_map_path: Option<PathBuf>,
    serve_waiters: Option<crate::facade::ServeMapWaiters>,
}

async fn prepare_cargo_run(plan: &CargoRunPlan<'_>) -> stow_types::error::Result<CargoRunSetup> {
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
    let argv = cargo_argv(plan).await?;

    let cache_policy_path = seed_cache_policy(scratch.path(), plan.cache_policy_entries)
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
    let (serve_map_path, mut serve_waiters) =
        write_initial_serve_map(scratch.path(), plan.servable_units, &serve_map_ready)
            .instrument(tracing::debug_span!("stow.precargo.serve_map_write"))
            .await?;
    arm_or_settle_serve_map_ready(plan, plan.config, &serve_map_ready, &mut serve_waiters);
    let envs = collect_wrapper_env(
        plan,
        &wrappers,
        serve_map_path.as_deref(),
        cache_policy_path.as_deref(),
        scratch.path(),
    )
    .instrument(tracing::debug_span!("stow.precargo.export_env"))
    .await?;
    Ok(CargoRunSetup {
        scratch,
        wrappers,
        launch: CargoLaunch { argv, envs },
        cache_policy_path,
        serve_map_ready,
        serve_map_path,
        serve_waiters,
    })
}

async fn run_cargo(plan: &CargoRunPlan<'_>) -> stow_types::error::Result<ExitStatus> {
    let CargoRunPlan {
        project,
        config,
        state_db,
        action,
        public_cache_mode,
        covered_units,
        ..
    } = *plan;
    let CargoRunSetup {
        scratch,
        wrappers,
        launch,
        cache_policy_path,
        serve_map_ready,
        serve_map_path,
        serve_waiters,
    } = prepare_cargo_run(plan).await?;

    // Every rustc invocation this cargo run spawns is a facade that asks
    // this process what to do, so the whole build shares one transport —
    // one pooled connection, one QUIC endpoint. The `STOW_*` context lands
    // on cargo's environment, so the deciding process holds the resolved
    // values itself (stow#347).
    let analysis_cell = analysis_cell(plan);
    let policy_ready = policy_ready_signal(cache_policy_path.is_some() && plan.deferred_analysis);
    // The driver-built wrapper base lands here: the task spawned in
    // `run_inner` has been running beside mold's provisioning and the
    // analysis, so this await is almost always an immediate take (stow#608).
    let env_base = join_env_base(project.env_base.as_ref()).await?;
    let (resolution_done, release_hold) = spawn_resolution_lease(project);
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
            policy_ready: std::sync::Arc::clone(&policy_ready),
            in_flight: in_flight.clone(),
            registry_sources: crate::RegistrySources::from_lockfile(&project.workspace_root),
        },
        env_base,
        resolution_done.clone(),
        state_db.clone(),
    ));
    let (mut cargo_run, mut supervisor) =
        spawn_cargo_run(plan, &handler, in_flight, &wrappers, launch, scratch.path()).await?;

    let before = coverage_snapshot(config).await;

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
            circuit: handler.circuit(),
            cell: analysis_cell,
            map_path: serve_map_path.clone(),
            policy_dir: cache_policy_path.clone(),
            readiness: serve_waiters,
            policy_ready: (!policy_ready.has_completed())
                .then(|| crate::facade::ServeMapWaiters::new(std::sync::Arc::clone(&policy_ready))),
            resolution_done,
        }))
    } else {
        // No enrichment, so no fetch will ever land a slice: release
        // whatever waits on one before cargo runs, not when it returns
        // (stow#735).
        drop(serve_waiters);
        None
    };

    tracing::debug!("stow.precargo.cargo_spawn");
    let status = cargo_run.status().await;
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
    finish_cargo_run(
        plan,
        CargoRunCleanup { cargo_run, scratch },
        &mut supervisor,
        status,
        before,
        covered_units,
        &handler,
    )
    .await
}

/// What `finish_cargo_run` releases, in order: the run — and with it a
/// sandbox — then the scratch directory the sandbox's grants name.
struct CargoRunCleanup {
    cargo_run: CargoRun,
    scratch: tempfile::TempDir,
}

/// The build's tail once cargo has exited: the supervisor drains — the
/// last unit's store and miss observation are inside it (stow#618) —
/// then coverage reports, the miss journal and the scratch cleanup run
/// in the same order on either transport (stow#317, stow#630, stow#667).
async fn finish_cargo_run(
    plan: &CargoRunPlan<'_>,
    cleanup: CargoRunCleanup,
    supervisor: &mut SupervisorHandle,
    status: ExitStatus,
    before: CoverageSnapshot,
    covered_units: usize,
    handler: &std::sync::Arc<crate::BuildSupervisor>,
) -> stow_types::error::Result<ExitStatus> {
    // Cargo has exited, so every facade has: stop accepting and drain the
    // last connections' post-compile bookkeeping before the runtime goes
    // away — the last unit's store is inside that tail, and so is its
    // miss observation (stow#618).
    supervisor.shutdown().await;
    // The sandbox's grants name the scratch directory, and its drop revokes
    // them, so it goes before the directory does.
    drop(cleanup.cargo_run);
    if let Some(config) = plan.config {
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
        plan.project.foreground.release();
        // The day's usage report posts from the detached drain — never
        // on the build's wall clock — so a due report is a reason to
        // spawn that drain even when this build leaves no journal
        // (stow#889).
        let report_due = crate::report::report_due_today(config).await;
        journal_and_drain_misses(
            plan.project,
            plan.cargo_args,
            plan.current_dir,
            &handler.observations(),
            plan.inexact_entries.unwrap_or(&[]),
            report_due,
        );
        // One supervised run is one build the install ran — counted
        // here rather than by the journal, whose supervised files the
        // drain skips to keep the count single.
        crate::report::bump_build(config).await;
    }
    // Nothing writes into the scratch directory any more — cargo has
    // exited, the analysis is gone and the supervisor has drained — so
    // it is removed here rather than at drop: `close` reports a removal
    // failure a `TempDir` drop would swallow (stow#630).
    if let Err(error) = cleanup.scratch.close() {
        tracing::warn!(%error, "could not remove the build scratch directory");
    }
    Ok(status)
}

/// The build's supervisor, bound beside the handler it shares the
/// in-flight registry with (stow#618). The runtime executable the shims
/// resolve to is passed in — the supervisor exports its identity to
/// cargo so a facade running a different build refuses before a frame is
/// sent (stow#645).
fn start_supervisor(
    handler: &std::sync::Arc<crate::BuildSupervisor>,
    in_flight: crate::supervisor::server::InFlightUnits,
    wrappers: &crate::commands::WrapperCommands,
) -> stow_types::error::Result<crate::supervisor::server::Supervisor> {
    tracing::debug_span!("stow.precargo.supervisor_start")
        .in_scope(|| {
            crate::supervisor::server::start(
                std::sync::Arc::clone(handler),
                in_flight,
                &wrappers.runtime_executable,
            )
        })
        .map_err(|error| stow_types::stow_error!("start the build supervisor: {error}"))
}

/// The cargo invocation the build runs: the action, the build's mold
/// selection as `--config` arguments — awaited, so the command cannot
/// be assembled before the provisioning answers (stow#653) — then the
/// user's own arguments.
#[cfg(test)]
async fn cargo_command(plan: &CargoRunPlan<'_>) -> stow_types::error::Result<Command> {
    let mut command = Command::new("cargo");
    command
        .args(cargo_argv(plan).await?)
        .current_dir(plan.current_dir);
    Ok(command)
}

/// The argv a build's cargo runs with — spelled as a list so both the
/// direct spawn and the sandboxed one assemble from the same value:
/// the action, the mold selection's `--config` pairs, then the user's
/// own arguments.
async fn cargo_argv(plan: &CargoRunPlan<'_>) -> stow_types::error::Result<Vec<OsString>> {
    let mold_args = plan.project.mold.config_args().await?;
    let mut argv = Vec::with_capacity(plan.cargo_args.len() + mold_args.len() * 2 + 1);
    argv.push(OsString::from(plan.action));
    for config_arg in mold_args.iter() {
        argv.push(OsString::from("--config"));
        argv.push(OsString::from(config_arg));
    }
    argv.extend(plan.cargo_args.iter().cloned());
    Ok(argv)
}

/// One build's cargo spawn — a plain child process, or the same launch
/// inside the heel sandbox `--sandbox` asked for (stow#779).
enum CargoRun {
    /// The unsandboxed spawn.
    Plain(Command),
    /// The sandbox and the command it will run; the sandbox itself stays
    /// alive until `status` returns — its drop tears the profile down
    /// around whatever cargo left running.
    Sandboxed(Box<SandboxedRun>),
}

/// The sandboxed spawn — the sandbox stays alive until `status` returns,
/// since its drop tears the profile down around whatever cargo left
/// running.
struct SandboxedRun {
    sandbox: crate::sandbox::BuildSandbox,
    command: crate::sandbox::SandboxedCommand,
}

impl CargoRun {
    async fn status(&mut self) -> stow_types::error::Result<ExitStatus> {
        match self {
            Self::Plain(command) => command.status().await.map_err(Into::into),
            Self::Sandboxed(run) => run.sandbox.status(&run.command).await,
        }
    }
}

/// The supervisor the build exports, by transport: the socket a plain
/// build's facades dial, or the heel-IPC conversation a sandboxed
/// build's facades get — the only outbound channel a `deny network*`
/// profile leaves open (stow#779).
enum SupervisorHandle {
    /// The unix/loopback supervisor.
    Socket(crate::supervisor::server::Supervisor),
    /// The supervisor served over heel's IPC socket inside the sandbox.
    Ipc(crate::supervisor::ipc::SandboxedSupervisor),
}

impl SupervisorHandle {
    async fn shutdown(&mut self) {
        match self {
            Self::Socket(supervisor) => {
                supervisor.shutdown().await;
            }
            Self::Ipc(supervisor) => supervisor.shutdown(),
        }
    }
}

/// How `run_cargo` starts cargo: the supervisor on the transport the
/// facades reach — the socket a plain build's facades dial, or heel's
/// IPC socket inside the sandbox a `--sandbox` build's facades get —
/// then the spawn on the matching command (stow#779).
/// The argv and environment a build's cargo launches with — one value
/// so the plain and sandboxed spawns stay identical below the transport.
struct CargoLaunch {
    argv: Vec<OsString>,
    envs: Vec<(OsString, OsString)>,
}

async fn spawn_cargo_run(
    plan: &CargoRunPlan<'_>,
    handler: &std::sync::Arc<crate::BuildSupervisor>,
    in_flight: crate::supervisor::server::InFlightUnits,
    wrappers: &crate::commands::WrapperCommands,
    mut launch: CargoLaunch,
    scratch: &Path,
) -> stow_types::error::Result<(CargoRun, SupervisorHandle)> {
    match plan.sandbox {
        None => {
            let supervisor = start_supervisor(handler, in_flight, wrappers)?;
            launch.envs.extend(
                supervisor
                    .env()
                    .map(|(key, value)| (OsString::from(key), OsString::from(value))),
            );
            let mut command = Command::new("cargo");
            command
                .args(&launch.argv)
                .current_dir(plan.current_dir)
                .envs(launch.envs.iter().cloned());
            Ok((
                CargoRun::Plain(command),
                SupervisorHandle::Socket(supervisor),
            ))
        }
        Some(network) => {
            sandboxed_cargo_run(plan, network, handler, in_flight, wrappers, launch, scratch).await
        }
    }
}

/// The sandboxed half of `run_cargo`: the dependencies land on the host
/// first — `cargo fetch` needs network and cargo-home writes the
/// sandbox denies — the supervisor is served over heel's IPC socket,
/// and the same argv and env go to a `SandboxedCommand` that runs
/// `--offline`, so no cargo network call can even be attempted.
async fn sandboxed_cargo_run(
    plan: &CargoRunPlan<'_>,
    network: crate::sandbox::SandboxNetwork,
    handler: &std::sync::Arc<crate::BuildSupervisor>,
    in_flight: crate::supervisor::server::InFlightUnits,
    wrappers: &crate::commands::WrapperCommands,
    mut launch: CargoLaunch,
    scratch: &Path,
) -> stow_types::error::Result<(CargoRun, SupervisorHandle)> {
    crate::sandbox::fetch_dependencies(plan.current_dir, plan.cargo_args).await?;
    let (pending, router) = crate::supervisor::ipc::start(
        std::sync::Arc::clone(handler),
        in_flight,
        &wrappers.runtime_executable,
    )
    .map_err(|error| stow_types::stow_error!("start the build supervisor: {error}"))?;
    if !launch
        .argv
        .iter()
        .any(|arg| arg == "--offline" || arg == "--frozen")
    {
        launch.argv.push(OsString::from("--offline"));
    }
    let target_dir = resolved_target_dir(plan.project, plan.cargo_args, plan.current_dir);
    let shims_dir = Path::new(&wrappers.rustc).parent().ok_or_else(|| {
        stow_types::stow_error!("rustc wrapper shim {} has no parent", wrappers.rustc)
    })?;
    // The mirror build compiles inside the mirror, whose sources are
    // links into the real workspace — both must be readable.
    let source_roots: Vec<PathBuf> = if plan.source_root == plan.project.workspace_root {
        vec![plan.source_root.to_path_buf()]
    } else {
        vec![
            plan.source_root.to_path_buf(),
            plan.project.workspace_root.clone(),
        ]
    };
    let request = crate::sandbox::SandboxRequest {
        network,
        source_roots: &source_roots,
        target_dir: &target_dir,
        scratch_dir: Some(scratch),
        shims_dir: Some(shims_dir),
        runtime_executable: &wrappers.runtime_executable,
        rustc_executable: Path::new(plan.project.build_rustc.executable()),
        host_target: plan.project.host_target.as_str(),
        cargo_dir: plan.current_dir,
        cargo_args: plan.cargo_args,
        ipc: Some(router),
    };
    let sandbox = crate::sandbox::BuildSandbox::create(request).await?;
    let endpoint = sandbox.ipc_endpoint().ok_or_else(|| {
        stow_types::stow_error!("the build sandbox's IPC server exposed no endpoint")
    })?;
    let supervisor = pending.finish(endpoint);
    launch.envs.extend(crate::sandbox::toolchain_envs()?);
    // The env passthrough filters `CARGO_TARGET_DIR` — the target dir is
    // a grant the sandbox resolves itself, so it is spelled out here
    // rather than inherited (stow#779).
    launch.envs.push((
        OsString::from("CARGO_TARGET_DIR"),
        target_dir.into_os_string(),
    ));
    launch.envs.extend(
        supervisor
            .env()
            .map(|(key, value)| (OsString::from(key), OsString::from(value))),
    );
    let command = crate::sandbox::SandboxedCommand::new(
        "cargo",
        &launch.argv,
        &launch.envs,
        plan.current_dir,
    )?;
    Ok((
        CargoRun::Sandboxed(Box::new(SandboxedRun { sandbox, command })),
        SupervisorHandle::Ipc(supervisor),
    ))
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

/// The build's pre-cargo coverage snapshot, instrumented as its own
/// span.
async fn coverage_snapshot(config: Option<&StowConfig>) -> CoverageSnapshot {
    CoverageSnapshot::capture(config)
        .instrument(tracing::debug_span!("stow.precargo.coverage_snapshot"))
        .await
}

/// The supervisor completes the latch on the first facade frame that
/// describes a real compile unit — the moment cargo's resolution is
/// over — so the package-cache lock always goes to the real build first
/// (stow#608). The release task rides it: once cargo holds the
/// package-cache lock only shared, a drain's cargo can no longer make
/// this build wait — and a `stow run` that stays up for hours must not
/// keep every drain shut (stow#667). The task is stopped with cargo.
fn spawn_resolution_lease(
    project: &ProjectContext,
) -> (crate::ResolutionDone, tokio::task::JoinHandle<()>) {
    let resolution_done = crate::ResolutionDone::pending();
    let release_hold = spawn_hold_release(resolution_done.clone(), project.foreground.clone());
    (resolution_done, release_hold)
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
/// The environment `run_cargo` exports to its cargo: collected once so
/// the plain spawn's `Command` and the sandboxed `SandboxedCommand`
/// both build on the same list (stow#779).
async fn collect_wrapper_env(
    plan: &CargoRunPlan<'_>,
    wrappers: &crate::commands::WrapperCommands,
    serve_map_path: Option<&Path>,
    cache_policy_path: Option<&Path>,
    scratch: &Path,
) -> stow_types::error::Result<Vec<(OsString, OsString)>> {
    let mut envs = Vec::new();
    export_wrapper_env(
        &mut envs,
        plan,
        wrappers,
        serve_map_path,
        cache_policy_path,
        scratch,
    )
    .await?;
    Ok(envs)
}

/// The shim identity a build exports: `RUSTC_WRAPPER`, the `cc`-scoped
/// compiler keys and the `CMAKE_*_COMPILER_LAUNCHER` variables — extracted because they move
/// together and keep `export_wrapper_env` readable.
fn export_wrapper_shim_envs(
    envs: &mut Vec<(OsString, OsString)>,
    wrappers: &crate::commands::WrapperCommands,
    target: &str,
) {
    envs.push((
        OsString::from("RUSTC_WRAPPER"),
        OsString::from(&wrappers.rustc),
    ));
    // The shims ride the `cc` crate's target-scoped keys for this build's
    // target rather than bare CC/CXX, the same scope `stow setup` writes —
    // other targets keep the toolchain cc-rs resolves for them. An
    // explicitly configured compiler is recorded so the shims exec it; a
    // target with nothing configured leaves the shims resolving the
    // platform toolchain per invocation.
    let scoped = target.replace(['-', '.'], "_");
    envs.push((
        OsString::from(format!("CC_{scoped}")),
        OsString::from(&wrappers.cc_compiler),
    ));
    envs.push((
        OsString::from(format!("CXX_{scoped}")),
        OsString::from(&wrappers.cxx_compiler),
    ));
    if let Some(real_cc) = crate::commands::configured_c_compiler(target) {
        envs.push((OsString::from("STOW_REAL_CC"), OsString::from(real_cc)));
    }
    if let Some(real_cxx) = crate::commands::configured_cxx_compiler(target) {
        envs.push((OsString::from("STOW_REAL_CXX"), OsString::from(real_cxx)));
    }
    envs.push((
        OsString::from("CMAKE_C_COMPILER_LAUNCHER"),
        OsString::from(&wrappers.cc_launcher),
    ));
    envs.push((
        OsString::from("CMAKE_CXX_COMPILER_LAUNCHER"),
        OsString::from(&wrappers.cc_launcher),
    ));
}

async fn export_wrapper_env(
    envs: &mut Vec<(OsString, OsString)>,
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
        ..
    } = *plan;
    export_wrapper_shim_envs(envs, wrappers, &project.target);
    // The extra rustc arguments ride a build file like the run's other
    // generated tables (stow#625) — and a build with no stow config still
    // writes this one.
    let extra_args = rustc_wrapper_extra_args(source_root)?;
    let extra_args_path =
        write_build_json_table(scratch_dir, "rustc-extra-args", extra_args).await?;
    envs.push((
        OsString::from(rustc_args::STOW_RUSTC_EXTRA_ARGS_FILE_ENV),
        OsString::from(extra_args_path.as_os_str()),
    ));
    envs.push((
        OsString::from(STOW_PUBLIC_CACHE_RUSTC_VERSION_ENV),
        OsString::from(&project.rustc_version),
    ));
    envs.push((
        OsString::from(STOW_PUBLIC_CACHE_TARGET_ENV),
        OsString::from(&project.target),
    ));
    // Pass the parent's already-resolved StowConfig as a JSON env blob so the
    // rustc wrapper does not re-read ~/.config/stow/config.toml on every
    // invocation. See `StowConfig::from_env_blob`.
    if let Some(cfg) = config {
        envs.push((
            OsString::from(crate::config::STOW_CONFIG_BLOB_ENV),
            OsString::from(cfg.to_env_blob()?),
        ));
    }
    envs.push((
        OsString::from(STOW_ENABLE_SEMANTIC_FALLBACK_ENV),
        OsString::from(if semantic_fallback_enabled { "1" } else { "0" }),
    ));
    // The per-side node table every wrapper invocation resolves its
    // unit's cargo feature set and side against — the argv scan is
    // compile-key evidence, never the semantic label (stow#615) — and
    // the prefetch ledger. Both travel as files beside the serve map,
    // inside the build's scratch directory; with nothing to write no
    // variable is exported (stow#625).
    if let Some(unit_nodes) = unit_nodes {
        let path =
            write_build_json_table(scratch_dir, "expanded-graph", unit_nodes.clone()).await?;
        envs.push((
            OsString::from(STOW_EXPANDED_GRAPH_PATH_ENV),
            OsString::from(path.as_os_str()),
        ));
    }
    if let Some(prefetch_artifacts) = prefetch_artifacts {
        let rows = prefetch_artifact_rows(prefetch_artifacts)?;
        let path = write_build_json_table(scratch_dir, "prefetch-artifacts", rows).await?;
        envs.push((
            OsString::from(STOW_PREFETCH_ARTIFACTS_PATH_ENV),
            OsString::from(path.as_os_str()),
        ));
    }
    if let Some(path) = serve_map_path {
        envs.push((
            OsString::from(crate::facade::STOW_SERVE_MAP_FILE_ENV),
            OsString::from(path.as_os_str()),
        ));
    }
    if let Some(path) = cache_policy_path {
        let (key, value) = cache_policy::cache_policy_env(path);
        envs.push((OsString::from(key), value));
    }
    if let Some(reason) = public_cache_mode.disable_reason() {
        envs.push((
            OsString::from("STOW_DISABLE_PUBLIC_CACHE"),
            OsString::from(reason),
        ));
    }
    if std::env::var_os("CARGO_TARGET_DIR").is_none() && !has_explicit_target_dir(cargo_args) {
        envs.push((
            OsString::from("CARGO_TARGET_DIR"),
            project.workspace_root.join("target").into_os_string(),
        ));
    }
    Ok(())
}

/// A missing slice is final only once the build's fetch has settled —
/// the same settling `AwaitServeMap` marks — so `serve_map_ready` must
/// complete in lockstep with that fetch or a lookup waits forever
/// (stow#735). When the lite pass produced no map the enrichment still
/// fetches the consumer slices mid-build, so the guard rides with it;
/// when nothing in this build can land a slice the signal settles now —
/// a build that cannot serve must not hold a lookup for a fetch that is
/// never coming.
fn arm_or_settle_serve_map_ready(
    plan: &CargoRunPlan<'_>,
    config: Option<&StowConfig>,
    serve_map_ready: &std::sync::Arc<crate::facade::ServeMapSignal>,
    serve_waiters: &mut Option<crate::facade::ServeMapWaiters>,
) {
    if serve_waiters.is_some() {
        return;
    }
    if plan.deferred_analysis
        && config.is_some()
        && plan.servable_units.as_ref().is_none_or(|map| map.pending)
    {
        *serve_waiters = Some(crate::facade::ServeMapWaiters::new(std::sync::Arc::clone(
            serve_map_ready,
        )));
    } else {
        serve_map_ready.complete();
    }
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
    // exists by construction, so there is no bind to fail here. The
    // guard arms on `pending` alone: an empty map's facades wait on
    // nothing (`map.names` is empty either way), but `pending` still
    // means a slice fetch is in flight, and the slice memo's wait rides
    // the same signal (stow#735).
    let waiters = map
        .pending
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
    /// The build fetch's completion guard: held until the consumer
    /// slices have settled — its drop releases the facades waiting on
    /// `AwaitServeMap` and the slice memo's lookups, whichever way the
    /// analysis ends (stow#347, stow#735).
    readiness: Option<crate::facade::ServeMapWaiters>,
    /// The policy gate's completion guard: dropped right after the
    /// coarse allow commit lands the fetched slices' markers — or by an
    /// early return — so a denied unit waits out the commit once, never
    /// the task's whole lifetime (stow#788).
    policy_ready: Option<crate::facade::ServeMapWaiters>,
    /// Held until the supervisor's first compile-unit frame says
    /// cargo's resolution is over: only then may this task's own
    /// `--unit-graph` cargo take the package-cache lock — before that
    /// it would queue the user's real build behind a whole second
    /// resolve (stow#608).
    resolution_done: crate::ResolutionDone,
    /// The build's circuit handle — tripped when the index fetch finds
    /// the registry unreachable, releasing the plan path and in-flight
    /// downloads to local compile at once (stow#977).
    circuit: crate::circuit::BuildCircuit,
}

/// The policy gate's readiness latch for this build: pending only while
/// a deferred build's enrichment still owes the seeded directory its
/// coarse commit — released by the commit or by the guard dropping with
/// the task; every other build answers a missing marker at once
/// (stow#788).
fn policy_ready_signal(commit_pending: bool) -> std::sync::Arc<crate::facade::ServeMapSignal> {
    std::sync::Arc::new(if commit_pending {
        crate::facade::ServeMapSignal::pending()
    } else {
        crate::facade::ServeMapSignal::settled()
    })
}

/// The policy gate's first commit — every crate the fetched slices
/// name that this build compiles. The marker is name-keyed, so the set
/// is a superset of every marker the full analysis could add, and a
/// crate absent from it can never gain one: that is what makes the
/// commit's `policy_ready` release the final deny answer (stow#788).
/// An over-broad allow costs the plan path one indexed lookup, never a
/// wrong serve. When the compiled-name set is not on disk yet — no
/// lockfile, no cached graph — the commit falls back to every row name
/// rather than wait on the resolve it exists to outrun.
async fn coarse_cache_policy_entries(
    config: &StowConfig,
    project: &ProjectContext,
    slice: &index::IndexSlice,
    host_slice: Option<&index::IndexSlice>,
) -> stow_types::error::Result<(Vec<cache_policy::CachePolicyEntry>, bool)> {
    let row_names: std::collections::BTreeSet<&str> = slice
        .index
        .rows
        .iter()
        .chain(host_slice.iter().flat_map(|slice| slice.index.rows.iter()))
        .map(|row| row.crate_name.as_str())
        .collect();
    let compiled: Option<std::collections::BTreeSet<String>> =
        if let Some(graph) = expanded_graph_cached(config, project).await? {
            Some(
                graph
                    .entries
                    .iter()
                    .map(|entry| entry.crate_name.as_str().to_owned())
                    .collect(),
            )
        } else {
            let workspace_root = project.workspace_root.clone();
            tokio::task::spawn_blocking(move || {
                workspace_deps::lockfile_registry_packages(&workspace_root)
            })
            .await
            .wrap_err("join lockfile registry package read")??
            .map(|packages| packages.into_iter().map(|(name, _)| name).collect())
        };
    // With neither graph nor lockfile on disk the compiled set is not yet
    // written — cargo creates the lockfile during this build's own
    // resolution — so bound the commit to the manifest's direct deps, the
    // lockfile-free answer the build already has (never the whole slice),
    // and report the commit incomplete: the latch stays pending until the
    // analysis writes the exact set.
    let names: Vec<String> = if let Some(compiled) = &compiled {
        row_names
            .into_iter()
            .filter(|name| compiled.contains(*name))
            .map(str::to_owned)
            .collect()
    } else {
        let direct = collect_user_direct_dependencies(
            &project.manifest_path,
            &project.workspace_root,
            &project.metadata_args,
        )
        .await?;
        let direct: std::collections::BTreeSet<String> = direct
            .into_iter()
            .map(|dep| dep.crate_name.as_str().to_owned())
            .collect();
        row_names
            .into_iter()
            .filter(|name| direct.contains(*name))
            .map(str::to_owned)
            .collect()
    };
    Ok((
        names
            .into_iter()
            .map(|crate_name| cache_policy::CachePolicyEntry {
                target: project.target.clone(),
                crate_name,
            })
            .collect(),
        compiled.is_some(),
    ))
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
    // Everything the build consults downstream reads the fetched
    // generation, so the consumer slices are fetched first — the coarse
    // allow commit and the serve map's final write both follow it
    // (stow#788). `ensure_slice` memoizes, so the analysis below reuses
    // this pair.
    let (slice, host_slice) = match ensure_consumer_slices(&work.config, &work.project).await {
        Ok(slices) => slices,
        Err(error) if error.is_transport() => {
            // The registry answered nothing — one diagnostic, not a
            // stall the build re-pays per unit: trip the breaker so the
            // plan path stops offering remote serves and in-flight
            // downloads abandon, then end the enrichment. The guards'
            // drop settles `serve_map_ready` and the policy latch, so
            // every waiter releases at once to local compile (stow#977).
            work.circuit.trip(&work.config).await;
            tracing::warn!(
                registry = %work.config.registry_base_url,
                error = %error,
                "stow index registry is unreachable; this build runs local-only"
            );
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    // The policy gate commits as soon as the rows exist — before the
    // `resolution_done` gate and the second resolve. The marker is
    // name-keyed, so "the crate has any row the fetched slices carry"
    // is already the final allow answer; the guard's drop releases the
    // plan path's waiters, and an early return releases them the same
    // way (stow#788).
    if let Some(policy_dir) = &work.policy_dir {
        let (entries, complete) =
            coarse_cache_policy_entries(&work.config, &work.project, &slice, host_slice.as_ref())
                .await?;
        cache_policy::write_policy_entries(policy_dir, &entries).await?;
        if complete {
            drop(work.policy_ready.take());
        }
    } else {
        drop(work.policy_ready.take());
    }
    // The build's slice waiters — a `pending` map's facades, and the
    // slice memo's lookups (stow#735) — hold until coverage is knowable:
    // the fresh slices landed, the filesystem pass rebuilt the map with
    // them. Answer as soon as the fetch settles rather than after the
    // metadata resolve and the prefetch. The write clears `pending`
    // (the cached slices now exist) and the guard's drop releases the
    // waiters; an early return releases them the same way (stow#347).
    if work.readiness.is_some() {
        if let Some(map_path) = &work.map_path {
            let lite = analyze_workspace_prediction_lite(&work.project, &work.config).await?;
            write_build_json_file(map_path, lite.servable_units.unwrap_or_default()).await?;
        }
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
    // The coarse commit stayed incomplete — no lockfile and no cached
    // graph to bound it — so the analysis's exact allow set is the
    // release-worthy commit for the units still parked on the latch.
    if work.policy_ready.is_some()
        && let Some(policy_dir) = &work.policy_dir
    {
        cache_policy::write_policy_entries(policy_dir, &analysis.cache_policy_entries).await?;
    }
    drop(work.policy_ready.take());
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
    inexact_entries: &[DependencyGraphEntry],
    report_due: bool,
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
        inexact_entries,
    );
    // An all-hit build leaves no journal for `spawn_drain` to find;
    // a due usage report forces the spawn so the day's deltas still
    // leave the machine through the detached lane (stow#889).
    if report_due {
        crate::miss_journal::spawn_drain_unconditional(&target_dir);
    } else {
        crate::miss_journal::spawn_drain(&target_dir);
    }
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
    if delta.rust_lookups() == 0 && delta.rust_local_dependency_builds == 0 && covered_units == 0 {
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

/// The rustc argument a supervised run appends to every unit: the
/// workspace path remap. It travels through the file
/// [`rustc_args::STOW_RUSTC_EXTRA_ARGS_FILE_ENV`] names — which the rustc
/// wrapper appends to each unit's argv — rather than `RUSTFLAGS`, where
/// cargo's precedence rules would discard the user's `.cargo/config.toml`
/// `target.*.rustflags` for the whole build.
fn rustc_wrapper_extra_args(source_root: &Path) -> stow_types::error::Result<Vec<String>> {
    let source_root = source_root.to_str().ok_or_else(|| {
        stow_types::stow_error!("workspace root {} is not UTF-8", source_root.display())
    })?;
    Ok(vec![format!(
        "--remap-path-prefix={source_root}=stow-ci://workspace"
    )])
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
    #[cfg(unix)]
    use super::create_workspace_mirror;
    use super::{
        CargoRunPlan, MetadataArgs, MoldSelection, ProjectContext, PublicCacheMode,
        WorkspaceMirror, relative_path, rewrite_args_for_mirror, rewrite_args_for_root,
    };
    use crate::prefetch::PrefetchArtifact;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    fn test_config(cache_dir: &Path) -> crate::config::StowConfig {
        crate::config::StowConfig {
            edge_url: "http://127.0.0.1:9".to_owned(),
            registry_base_url: "http://127.0.0.1:9".to_owned(),
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
            experimental: crate::config::ExperimentalConfig::default(),
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
            host_target: "aarch64-apple-darwin".to_owned(),
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
        // The gated resolve parks on the latch; from there only the
        // completion lets it run.
        resolution_done.parked(1).await;
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
        // The released `--config` value in the assembled args is the
        // proof the command waited: it exists only behind the
        // selection's await (stow#810).
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
                inexact_entries: None,
                deferred_analysis: false,
                semantic_fallback_enabled: false,
                covered_units: 0,
                sandbox: None,
            };
            super::cargo_command(&plan).await
        });
        // As on the passthrough: the released `--config` value in the
        // assembled args proves the command waited for the selection.
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
        // Nothing but a reader can poll the provisioning: no task was
        // spawned to drive it, so the flag is settled until the read —
        // not merely unset after a few scheduler turns (stow#810).
        assert_eq!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks(),
            0,
            "a deferred selection spawned its provisioning"
        );
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
        let status = super::run_cargo_passthrough(
            &project,
            "build",
            &cargo_args,
            &mirror.current_dir(),
            None,
        )
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
            explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
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
        assert!(
            map.target.is_empty() && map.host.is_empty(),
            "nothing local to admit: {map:?}"
        );
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

    /// An index row naming `name` at `version` — the serve-map tests
    /// need the pair the map intersects, on a row `row_servable_on_host`
    /// admits (`min_glibc: None`).
    fn index_row(name: &str, version: &str) -> stow_types::index::ArtifactIndexRow {
        let mut row = crate::index::index_test_row("deadbeef");
        row.crate_name = stow_types::identity::CrateName::parse(name).expect("crate name");
        row.version = stow_types::identity::CrateVersion::new(
            semver::Version::parse(version).expect("version"),
        );
        row
    }

    /// A verified slice over `rows` — `build_serve_map` and the lite
    /// pass read only `index.rows`, so the pointer fields carry test
    /// constants.
    fn slice_for(rows: Vec<stow_types::index::ArtifactIndexRow>) -> crate::index::IndexSlice {
        crate::index::IndexSlice {
            manifest_digest: Some("sha256:deadbeef".to_owned()),
            index: stow_types::index::ArtifactIndex {
                header: stow_types::index::ArtifactIndexHeader {
                    format_version: stow_types::index::ARTIFACT_INDEX_FORMAT_VERSION,
                    target: stow_types::identity::TargetTriple::parse("aarch64-apple-darwin")
                        .expect("target"),
                    rustc_version: stow_types::identity::WireRustcVersion::parse("1.91.1")
                        .expect("rustc"),
                    generated_at: "2026-10-19T00:00:00Z".to_owned(),
                    generation: 1,
                    row_count: rows.len() as u64,
                },
                rows,
            },
        }
    }

    /// `local_only_map` for the index half: the map `build_serve_map`
    /// produces over index rows, with no expanded graph and no local
    /// units.
    fn index_rows_map(
        project: &ProjectContext,
        consumer_rows: &[stow_types::index::ArtifactIndexRow],
        host_rows: &[stow_types::index::ArtifactIndexRow],
        lockfile_packages: &[(&str, &str)],
    ) -> crate::facade::ServeMap {
        let host_slice = (!host_rows.is_empty()).then(|| slice_for(host_rows.to_vec()));
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
            consumer_rows,
            host_slice.as_ref(),
            &[],
            &[],
            &lockfile_packages,
        )
    }

    /// stow#805: a cold project — no cached expanded graph — serves the
    /// lockfile's registry packages the slice covers. A native build
    /// spells no `--target`, so the covered pair lands on the host list.
    #[test]
    fn a_cold_project_serves_index_units_natively() {
        let project = project_context();
        let consumer_rows = [index_row("a", "1.0.0"), index_row("b", "2.0.0")];
        let map = index_rows_map(
            &project,
            &consumer_rows,
            &[],
            &[("a", "1.0.0"), ("c", "3.0.0")],
        );
        assert_eq!(map.target, Vec::<(String, String)>::new());
        assert_eq!(map.host, vec![("a".to_owned(), "1.0.0".to_owned())]);
    }

    /// stow#805 under a spelled `--target`: a lockfile cannot name a
    /// side, so a package the consumer slice covers lands on the target
    /// list and one the host slice covers on the host list.
    #[test]
    fn a_cold_project_serves_index_units_on_both_sides_of_a_target_build() {
        let project = ProjectContext {
            target: "aarch64-apple-ios".to_owned(),
            target_given: true,
            ..project_context()
        };
        let consumer_rows = [index_row("b", "2.0.0")];
        let host_rows = [index_row("a", "1.0.0")];
        let map = index_rows_map(
            &project,
            &consumer_rows,
            &host_rows,
            &[("a", "1.0.0"), ("b", "2.0.0")],
        );
        assert_eq!(map.target, vec![("b".to_owned(), "2.0.0".to_owned())]);
        assert_eq!(map.host, vec![("a".to_owned(), "1.0.0".to_owned())]);
    }

    /// stow#805 through the real pass: no cached graph and no local
    /// units, but a slice row the lockfile names — the lockfile read
    /// runs for the index half and the map covers it.
    #[tokio::test]
    async fn a_lockfile_named_index_unit_lands_in_the_serve_map() {
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
        let project = ProjectContext {
            workspace_root: workspace.path().to_path_buf(),
            manifest_path: workspace.path().join("Cargo.toml"),
            ..project_context()
        };
        let prediction = super::analyze_workspace_prediction_from(
            &project,
            &config,
            super::AnalysisInputs {
                slice: Some(slice_for(vec![index_row("cfg-if", "1.0.0")])),
                host_slice: None,
                expanded: None,
                slice_pending: false,
            },
        )
        .await
        .expect("analysis");
        let map = prediction.servable_units.expect("a serve map");
        assert_eq!(map.target, Vec::<(String, String)>::new());
        assert_eq!(map.host, vec![("cfg_if".to_owned(), "1.0.0".to_owned())]);
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
            registry_base_url: "http://127.0.0.1:1".to_owned(),
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
            experimental: crate::config::ExperimentalConfig::default(),
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
            runtime_executable: PathBuf::from("/usr/local/bin/stow-cli"),
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
            inexact_entries: None,
            semantic_fallback_enabled: true,
            deferred_analysis: false,
            covered_units: ledger.len(),
            sandbox: None,
        };
        let mut envs = Vec::new();
        smol::block_on(super::export_wrapper_env(
            &mut envs,
            &plan,
            &wrappers,
            None,
            None,
            cache.path(),
        ))
        .expect("export wrapper env");
        let env = envs;
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
