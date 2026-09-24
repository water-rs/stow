use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::time::Instant;

use async_process::Command;
use serde::{Deserialize, Serialize};
use stow_types::artifact::{ArtifactKind, NativeArtifacts, RustCrateType};
use stow_types::bundle::{STOW_PROC_MACRO_MEDIA_TYPE, STOW_RLIB_MEDIA_TYPE, STOW_RMETA_MEDIA_TYPE};
use stow_types::error::Context;
use stow_types::platform::{PanicStrategy, Profile};
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
use crate::rustc_args::{
    self, STOW_PUBLIC_CACHE_RUSTC_VERSION_ENV, STOW_PUBLIC_CACHE_TARGET_ENV,
    detect_rustc_host_target, detect_rustc_version,
};
use crate::stats;
use crate::workspace_deps::{
    self, ExpandedDependencyGraph, PackageKey, SelectedRegistryDependency,
};
use crate::{
    STOW_ENABLE_SEMANTIC_FALLBACK_ENV, STOW_EXPANDED_GRAPH_ENV, STOW_PREFETCH_ARTIFACTS_ENV,
};
use crate::{detect_wrapper_commands, write_stdout};
use stow_types::api::{
    AdmissionRequest, DependencyGraphEntry, EnqueueAdmission, ResolvedDependencyGraphEntry,
};
use stow_types::versioning::is_semver_compatible_upgrade;

#[tracing::instrument(name = "stow.cargo_cmd.run", skip_all, fields(cargo_command = command))]
pub async fn run(command: &str, args: CargoCommandArgs) -> stow_types::error::Result<()> {
    run_inner(command, args).await
}

async fn run_inner(command: &str, args: CargoCommandArgs) -> stow_types::error::Result<()> {
    let invocation = CargoInvocation::new(command, args);
    let mut project = ProjectContext::load(&invocation.cargo_args).await?;
    // mold is mandatory on Linux — provision it before any cargo
    // invocation starts, whatever path the build ends up taking through
    // this driver. `check` is gated with `build` and `test`: a check still
    // compiles proc-macro dependencies in full and compiles and runs
    // build scripts, and both of those link. When the cargo config does
    // not already select a reachable mold, the managed install is
    // selected for this invocation only — `stow setup` is not required.
    project.mold_config_args =
        crate::mold::provision(&project.target, project.current_dir()).await?;
    let public_cache_mode = PublicCacheMode::for_rustc(&project.rustc_version);
    if let PublicCacheMode::Disabled { message, .. } = &public_cache_mode {
        write_stdout(&format!("{message}\n"))?;
    }

    if run_divergent_profile_passthrough(&project, &invocation).await? {
        return Ok(());
    }
    let config = match StowConfig::load() {
        Ok(config) => Some(config),
        Err(error) => {
            tracing::debug!(%error, "stow config unavailable, skipping graph analysis");
            None
        }
    };

    if try_resolver_fast_path(config.as_ref(), &project, &invocation, &public_cache_mode).await {
        return Ok(());
    }

    let maybe_analysis = analyze_or_warn(config.as_ref(), &project, &public_cache_mode).await;
    if run_uncovered_passthrough(
        config.as_ref(),
        &project,
        &invocation,
        maybe_analysis.as_ref(),
    )
    .await?
    {
        return Ok(());
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
            crate::verify::Trust::resolve(config).await.map(|_| ()),
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
    .await?;
    if selected.is_empty() {
        run_original_workspace_build(
            config.as_ref(),
            &project,
            &invocation,
            &public_cache_mode,
            maybe_analysis,
            &budget,
        )
        .await
    } else {
        run_mirrored_upgrade_build(
            config.as_ref(),
            &project,
            &invocation,
            &public_cache_mode,
            &budget,
            &selected,
        )
        .await
    }
}

/// No-slowdown floor, part 1: a workspace whose dev profile turns on LTO
/// compiles every dependency with `-C linker-plugin-lto`, which no cache
/// identity expresses, so no unit can ever hit. Detect that early, skip the
/// entire resolver/analysis/prefetch machinery, and behave exactly like
/// cargo. Every other profile knob is part of the compile identity and is
/// served when the pool holds artifacts built under it. Returns `true`
/// when the passthrough ran.
async fn run_divergent_profile_passthrough(
    project: &ProjectContext,
    invocation: &CargoInvocation,
) -> stow_types::error::Result<bool> {
    let Some(divergence) =
        crate::profile_guard::dev_profile_divergence(&project.workspace_root).await?
    else {
        return Ok(false);
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
    .await?;
    Ok(true)
}

/// Phase 0: stow-resolver fast path. When `--no-stow-resolver` is NOT set
/// and the edge can synthesize a cache-optimized `Cargo.lock` that cargo
/// itself accepts under `--locked`, skip cargo's resolver entirely. The
/// dry-run inside `try_stow_resolver` is the correctness gate — cargo
/// rejects anything semver/features-incompatible, and we fall back to the
/// conservative "suggest `Cargo.toml` upgrades, let cargo resolve" flow.
/// Returns `true` when the resolver path ran cargo and `run` is done.
async fn try_resolver_fast_path(
    config: Option<&StowConfig>,
    project: &ProjectContext,
    invocation: &CargoInvocation,
    public_cache_mode: &PublicCacheMode,
) -> bool {
    if !invocation.use_stow_resolver || !public_cache_mode.is_enabled() {
        return false;
    }
    let Some(config) = config else {
        return false;
    };
    match try_stow_resolver(config, project, invocation).await {
        Ok(served) => {
            if !served {
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
            false
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
    match analyze_workspace_prediction(
        project,
        project.current_dir(),
        &project.manifest_path,
        config,
    )
    .await
    {
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
/// turned the best case into a plain cargo run. Returns `true` when the
/// passthrough ran.
async fn run_uncovered_passthrough(
    config: Option<&StowConfig>,
    project: &ProjectContext,
    invocation: &CargoInvocation,
    analysis: Option<&WorkspacePrediction>,
) -> stow_types::error::Result<bool> {
    if invocation.silent_compatible_upgrades
        || analysis.is_some_and(|analysis| !analysis.prefetch_artifacts.is_empty())
        || config.is_some()
    {
        // With a config the build runs under the supervisor even when
        // nothing is servable: the supervisor's compile observations are
        // the build's miss list, posted once cargo finishes (stow#317).
        return Ok(false);
    }
    tracing::info!("no cached artifacts cover this dependency graph; running plain cargo");
    run_cargo_passthrough(
        project,
        &invocation.action,
        &invocation.cargo_args,
        project.current_dir(),
    )
    .await?;
    Ok(true)
}

/// The no-upgrades path: cargo runs in the real workspace with the cache
/// plan the analysis produced.
async fn run_original_workspace_build(
    config: Option<&StowConfig>,
    project: &ProjectContext,
    invocation: &CargoInvocation,
    public_cache_mode: &PublicCacheMode,
    analysis: Option<WorkspacePrediction>,
    budget: &CacheBudget,
) -> stow_types::error::Result<()> {
    let expanded_graph = analysis
        .as_ref()
        .map(|analysis| analysis.expanded_entries.clone());
    let prefetch_artifacts = analysis
        .as_ref()
        .map(|analysis| analysis.prefetch_artifacts.clone());
    let semantic_fallback_enabled = expanded_graph
        .as_ref()
        .is_some_and(|entries| !entries.is_empty());
    let cache_policy_path = prepare_build_cache_plan(
        config,
        project,
        project.current_dir(),
        &project.manifest_path,
        public_cache_mode,
        analysis,
        budget,
    )
    .await?;
    let expanded_entries = expanded_graph.as_deref();
    let prefetch_artifacts = prefetch_artifacts.as_deref();
    let covered_units = prefetch_artifacts.map_or(0, <[PrefetchArtifact]>::len);
    if let Some(config) = config
        && public_cache_mode.is_enabled()
    {
        match try_run_top_crate_with_cached_dependencies(
            config,
            project,
            &invocation.action,
            &invocation.cargo_args,
            cache_policy_path.as_deref(),
            prefetch_artifacts,
            budget,
        )
        .await
        {
            Ok(true) => return Ok(()),
            Ok(false) => {}
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
        action: &invocation.action,
        cargo_args: &invocation.cargo_args,
        source_root: &project.workspace_root,
        current_dir: project.current_dir(),
        cache_policy_path: cache_policy_path.as_deref(),
        public_cache_mode,
        expanded_entries,
        prefetch_artifacts,
        semantic_fallback_enabled,
        extra_rustflags: &[],
        covered_units,
    })
    .await
}

/// The upgrades path: apply the selected upgrades inside a mirror
/// workspace, re-analyze the upgraded graph, then run cargo there.
async fn run_mirrored_upgrade_build(
    config: Option<&StowConfig>,
    project: &ProjectContext,
    invocation: &CargoInvocation,
    public_cache_mode: &PublicCacheMode,
    budget: &CacheBudget,
    selected: &[CompatibleUpgrade],
) -> stow_types::error::Result<()> {
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
    let mirror_expanded = mirror_analysis
        .as_ref()
        .map(|analysis| analysis.expanded_entries.clone());
    let mirror_prefetch = mirror_analysis
        .as_ref()
        .map(|analysis| analysis.prefetch_artifacts.clone());
    let mirror_semantic_fallback = mirror_expanded
        .as_ref()
        .is_some_and(|entries| !entries.is_empty());

    let cache_policy_path = prepare_build_cache_plan(
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
            cache_policy_path.as_deref(),
            mirror_prefetch.as_deref(),
            budget,
        )
        .await
        {
            Ok(true) => return Ok(()),
            Ok(false) => {}
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
        action: &invocation.action,
        cargo_args: &mirror_args,
        source_root: mirror.root(),
        current_dir: &mirror_current_dir,
        cache_policy_path: cache_policy_path.as_deref(),
        public_cache_mode,
        expanded_entries: mirror_expanded.as_deref(),
        prefetch_artifacts: mirror_prefetch.as_deref(),
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
    Ok(ProjectContext {
        workspace_root,
        current_dir,
        current_dir_relative,
        manifest_path,
        metadata_args: project.metadata_args.clone(),
        target: project.target.clone(),
        rustc_version: project.rustc_version.clone(),
        mold_config_args: project.mold_config_args.clone(),
    })
}

#[tracing::instrument(name = "stow.cargo_cmd.predict", skip_all)]
/// `stow predict`: report this workspace's cache coverage.
///
/// Read-only, and that is the whole contract: the dependency graph never
/// leaves the machine, nothing is posted, and nothing is enqueued.
pub async fn predict(args: CargoCommandArgs) -> stow_types::error::Result<()> {
    let Some(analysis) = analyze_for_prediction(args).await? else {
        return Ok(());
    };
    write_stdout(&render_prediction_summary(&analysis))
}

/// The coverage analysis behind `predict`. `Ok(None)` means the public
/// cache cannot serve this toolchain at all and the reason has been
/// printed.
async fn analyze_for_prediction(
    args: CargoCommandArgs,
) -> stow_types::error::Result<Option<WorkspacePrediction>> {
    let invocation = CargoInvocation::new("predict", args);
    let project = ProjectContext::load(&invocation.cargo_args).await?;
    let public_cache_mode = PublicCacheMode::for_rustc(&project.rustc_version);
    if let PublicCacheMode::Disabled { message, .. } = &public_cache_mode {
        write_stdout(&format!("{message}\n"))?;
        return Ok(None);
    }

    // Unlike `check`/`build`, `predict` has no cargo run to protect: an
    // analysis it cannot compute is the command failing, and callers rely
    // on the exit status saying so.
    let config = StowConfig::load().map_err(|error| {
        stow_types::stow_error!(
            "stow predict is unavailable because stow is not configured.\nreason: {error}"
        )
    })?;
    analyze_workspace_prediction(
        &project,
        project.current_dir(),
        &project.manifest_path,
        &config,
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
struct ProjectContext {
    workspace_root: PathBuf,
    current_dir: PathBuf,
    current_dir_relative: PathBuf,
    manifest_path: PathBuf,
    metadata_args: MetadataArgs,
    target: String,
    rustc_version: String,
    /// The cargo `--config` values this build needs so its Linux units
    /// link with mold — empty on non-Linux, and empty when the cargo
    /// configuration already selects a reachable mold (the setup path).
    /// Resolved once by [`crate::mold::provision`] and applied to every
    /// cargo invocation as command-line overrides, so the effective
    /// selection — and therefore the compile keys — is identical
    /// whether it came from `--config` or from a written config file.
    mold_config_args: Vec<String>,
}

impl ProjectContext {
    #[tracing::instrument(name = "stow.project.context", skip_all)]
    async fn load(cargo_args: &[OsString]) -> stow_types::error::Result<Self> {
        let invocation_dir = std::env::current_dir().wrap_err("resolve current directory")?;
        let metadata_args = MetadataArgs::parse(&invocation_dir, cargo_args)?;
        let layout = workspace_deps::resolve_workspace_layout(
            &invocation_dir,
            metadata_args.manifest_path.as_deref(),
        )?;
        let workspace_root = layout.workspace_root;
        let current_dir = if invocation_dir.starts_with(&workspace_root) {
            invocation_dir
        } else {
            workspace_root.clone()
        };
        let manifest_path = layout.manifest_path;
        let current_dir_relative =
            pathdiff::diff_paths(&current_dir, &workspace_root).unwrap_or_else(PathBuf::new);
        let target = match metadata_args.target.clone() {
            Some(target) => target,
            None => detect_rustc_host_target(std::ffi::OsStr::new("rustc"))
                .await
                .map_err(|error| stow_types::stow_error!("detect rustc host target: {error}"))?,
        };
        let rustc_version = detect_rustc_version(std::ffi::OsStr::new("rustc"))
            .await
            .map_err(|error| stow_types::stow_error!("detect rustc version: {error}"))?;

        Ok(Self {
            workspace_root,
            current_dir,
            current_dir_relative,
            manifest_path,
            metadata_args,
            target,
            rustc_version,
            mold_config_args: Vec::new(),
        })
    }

    fn current_dir(&self) -> &Path {
        &self.current_dir
    }
}

#[derive(Debug, Clone, Default)]
pub struct MetadataArgs {
    pub(crate) manifest_path: Option<PathBuf>,
    pub(crate) target: Option<String>,
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
                parsed.target = Some(value.to_owned());
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
                    parsed.target = Some(value.to_owned());
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
    expanded_entries: Vec<DependencyGraphEntry>,
    candidates: Vec<CompatibleUpgrade>,
    missing_current: Vec<ResolvedDependency>,
    prefetch_artifacts: Vec<PrefetchArtifact>,
    cache_policy_entries: Vec<CachePolicyEntry>,
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
) -> stow_types::error::Result<WorkspacePrediction> {
    let lockfile_graph = workspace_deps::resolve_lockfile_graph(
        &project.workspace_root,
        manifest_path,
        &project.metadata_args,
    )?;
    let expanded = expanded_graph(config, project, manifest_path).await?;
    let dependencies = direct_resolved_dependencies(&lockfile_graph);
    let entries = dependencies
        .iter()
        .cloned()
        .map(into_api_dependency)
        .collect::<stow_types::error::Result<Vec<_>>>()?;

    // Resolution never leaves the machine: the verified index slice is the
    // only catalog consulted, and the graph walk runs in-process.
    let slice = index::ensure_slice(config, &project.target, &project.rustc_version).await?;
    let analysis = {
        let rows = slice.index.rows;
        let entries = entries.clone();
        let expanded_entries = expanded.entries.clone();
        let feature_graphs = expanded.feature_graphs;
        tokio::task::spawn_blocking(move || {
            resolve::analyze_dependency_graph(
                &rows,
                &entries,
                &expanded_entries,
                &feature_graphs,
                resolve::host_glibc(),
            )
        })
        .await
        .wrap_err("join dependency-graph resolver")??
    };

    let expanded_entries = analysis.expanded_entries.clone();
    let mut analysis_by_key = index_analysis_entries(analysis.entries)?;
    let (current_cached, missing_current, mut candidates) =
        apply_dependency_analyses(dependencies, &mut analysis_by_key)?;
    rank_upgrade_candidates(&mut candidates, &lockfile_graph.parents_by_package);
    let (prefetch_artifacts, cache_policy_entries) = prediction_fetch_lists(
        &project.target,
        &project.rustc_version,
        analysis.prefetch_artifacts,
    );

    Ok(WorkspacePrediction {
        current_cached,
        current_total: entries.len(),
        expanded_cached: analysis.expanded_cached,
        expanded_total: analysis.expanded_total,
        expanded_entries,
        candidates,
        missing_current,
        prefetch_artifacts,
        cache_policy_entries,
    })
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
    observations: &[crate::artifact_cache::ObservedUnit],
) -> stow_types::error::Result<()> {
    if observations.is_empty() {
        return Ok(());
    }
    if stow_types::api::runner_family(consumer_target).is_none() {
        tracing::info!(
            target = %consumer_target,
            "consumer target is not a CI target; not minting misses"
        );
        return Ok(());
    }
    let extern_metadatas = observations
        .iter()
        .flat_map(|observation| {
            observation
                .externs
                .iter()
                .map(|extern_dep| extern_dep.c_metadata.clone())
        })
        .collect::<BTreeSet<_>>();
    let dep_identities = crate::artifact_cache::load_artifact_dep_identities(
        config,
        rustc_version,
        &extern_metadatas,
    )
    .await?;
    // Host units classify against the build's probed host — the
    // triple cargo never passes `--target` for — not the family's
    // host; the family's host stays where host nodes mint (stow#317).
    let graph = workspace_deps::observed_miss_graph(
        observations,
        &dep_identities,
        consumer_target,
        build_host,
    );
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

/// The expanded (transitive) dependency graph for this lockfile: the
/// on-disk cache entry when present, a live `cargo metadata` resolve on
/// miss or load error (with the result written back best-effort).
async fn expanded_graph(
    config: &StowConfig,
    project: &ProjectContext,
    manifest_path: &Path,
) -> stow_types::error::Result<ExpandedDependencyGraph> {
    let expanded_cache_key = crate::lockfile_graph_cache::cache_key(
        &project.workspace_root,
        manifest_path,
        &project.target,
        &project.rustc_version,
    )?;
    match crate::lockfile_graph_cache::load(config, &expanded_cache_key).await {
        Ok(Some(graph)) => {
            tracing::debug!(
                cache_key = %expanded_cache_key,
                entries = graph.entries.len(),
                "lockfile_graph_cache hit"
            );
            Ok(graph)
        }
        Ok(None) => {
            let graph = workspace_deps::resolve_exact_dependency_graph(
                &project.workspace_root,
                manifest_path,
                &project.metadata_args,
                &project.target,
            )
            .await?;
            if let Err(error) =
                crate::lockfile_graph_cache::store(config, &expanded_cache_key, &graph).await
            {
                tracing::warn!(%error, "lockfile_graph_cache store failed; continuing");
            }
            Ok(graph)
        }
        Err(error) => {
            tracing::warn!(%error, "lockfile_graph_cache load failed; falling back to live resolve");
            workspace_deps::resolve_exact_dependency_graph(
                &project.workspace_root,
                manifest_path,
                &project.metadata_args,
                &project.target,
            )
            .await
        }
    }
}

/// The lockfile graph's direct dependencies as depth-1
/// `ResolvedDependency` rows for the prediction request.
fn direct_resolved_dependencies(
    lockfile_graph: &workspace_deps::LockfileGraph,
) -> Vec<ResolvedDependency> {
    lockfile_graph
        .direct_dependencies
        .iter()
        .cloned()
        .map(|dependency| ResolvedDependency {
            package_key: PackageKey {
                crate_name: dependency.crate_name.clone(),
                version: dependency.version.clone(),
                source: dependency.source.clone(),
            },
            crate_name: dependency.crate_name,
            version: dependency.version,
            features: dependency.features,
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
) -> stow_types::error::Result<bool> {
    let Some(stow_lockfile_toml) = synthesize_lockfile(config, project).await? else {
        return Ok(false);
    };

    let public_cache_mode = PublicCacheMode::for_rustc(&project.rustc_version);
    let Some(pinned) = prepare_pinned_mirror(project, invocation, &stow_lockfile_toml).await?
    else {
        return Ok(false);
    };
    let Some(mirror_analysis) = analyze_pinned_mirror(config, &pinned.project).await else {
        return Ok(false);
    };

    run_pinned_mirror_build(
        config,
        project,
        invocation,
        &pinned,
        &public_cache_mode,
        mirror_analysis,
    )
    .await
}

/// Ask the local resolver for a cache-optimized lockfile covering
/// `project`'s direct dependencies, resolved against the verified index
/// slice. Returns `None` — after logging the reason — when the project has
/// no direct dependencies or no consistent cache-pinned assignment exists.
/// The resolver's internal candidate budget bounds the work; there is no
/// network round trip to deadline.
async fn synthesize_lockfile(
    config: &StowConfig,
    project: &ProjectContext,
) -> stow_types::error::Result<Option<String>> {
    let direct = collect_user_direct_dependencies(project).await?;
    if direct.is_empty() {
        return Ok(None);
    }
    let slice = index::ensure_slice(config, &project.target, &project.rustc_version).await?;
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
/// intentionally absent, cargo metadata in mirror mode hydrates ALL dep
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
/// the wrapper with the pinned graph's cache plan.
async fn run_pinned_mirror_build(
    config: &StowConfig,
    project: &ProjectContext,
    invocation: &CargoInvocation,
    pinned: &PinnedMirror,
    public_cache_mode: &PublicCacheMode,
    mirror_analysis: WorkspacePrediction,
) -> stow_types::error::Result<bool> {
    let mirror_expanded = mirror_analysis.expanded_entries.clone();
    let mirror_prefetch = mirror_analysis.prefetch_artifacts.clone();
    let mirror_semantic_fallback = !mirror_expanded.is_empty();

    // The resolver path builds its own graph analysis for the pinned mirror,
    // so it sizes its own allowance from that.
    let budget = CacheBudget::for_covered_units(mirror_prefetch.len());

    let cache_policy_path = prepare_build_cache_plan(
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
        cache_policy_path.as_deref(),
        Some(&mirror_prefetch),
        &budget,
    )
    .await
    {
        Ok(true) => return Ok(true),
        Ok(false) => {
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
        action: &invocation.action,
        cargo_args: &pinned.args,
        source_root: pinned.mirror.root(),
        current_dir: &mirror_current_dir,
        cache_policy_path: cache_policy_path.as_deref(),
        public_cache_mode,
        expanded_entries: Some(&mirror_expanded),
        prefetch_artifacts: Some(&mirror_prefetch),
        semantic_fallback_enabled: mirror_semantic_fallback,
        extra_rustflags: &[],
        covered_units: mirror_prefetch.len(),
    })
    .await?;
    Ok(true)
}

async fn collect_user_direct_dependencies(
    project: &ProjectContext,
) -> stow_types::error::Result<Vec<lockfile_resolver::DirectDependency>> {
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::<String>::new();

    // Always read the project's selected manifest (the entry-point Cargo.toml).
    collect_dependencies_from_manifest(
        &project.manifest_path,
        &project.metadata_args,
        &mut out,
        &mut seen,
    )
    .await?;

    // For workspace projects, every member contributes direct deps from the
    // user's perspective — the root manifest typically only carries
    // `[workspace]` and shared `[workspace.dependencies]`. Walk every
    // `members` entry so we capture e.g. clap_builder/clap_derive deps when
    // running `stow check` from the workspace root.
    // Collect the member patterns into owned strings up front: the parsed
    // toml document holds non-Send iterators, so it must be dropped before
    // the per-member awaits below.
    let workspace_root_manifest = project.workspace_root.join("Cargo.toml");
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
        let resolved_members = expand_member_pattern(&project.workspace_root, &member_pattern);
        for member_dir in resolved_members {
            let manifest = member_dir.join("Cargo.toml");
            if !manifest.exists() {
                continue;
            }
            if let Err(error) = collect_dependencies_from_manifest(
                &manifest,
                &project.metadata_args,
                &mut out,
                &mut seen,
            )
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

async fn try_run_top_crate_with_cached_dependencies(
    config: &StowConfig,
    project: &ProjectContext,
    action: &str,
    cargo_args: &[OsString],
    cache_policy_path: Option<&Path>,
    prefetch_artifacts: Option<&[PrefetchArtifact]>,
    budget: &CacheBudget,
) -> stow_types::error::Result<bool> {
    let Some(shape) = cached_dependency_shape(action) else {
        return Ok(false);
    };
    if !prebuilt_deps_path_enabled() {
        return Ok(false);
    }
    if budget.is_exhausted() {
        tracing::info!(
            budget_ms = budget.total().as_millis(),
            "pre-cargo cache budget spent; handing over to cargo without the prebuilt-deps path"
        );
        return Ok(false);
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
        return Ok(false);
    }
    let direct_dependencies = workspace_deps::resolve_selected_registry_dependencies(
        &project.workspace_root,
        &project.manifest_path,
        &project.metadata_args,
        &project.target,
        cargo_args_include_dev_dependencies(cargo_args),
    )
    .await?;
    if direct_dependencies.is_empty() {
        return Ok(false);
    }
    let plan =
        resolve_cached_dependency_plan(config, project, &direct_dependencies, &shape).await?;

    let target_dir = cargo_target_dir(project, cargo_args);
    let prebuilt_dir = target_dir.join("stow-prebuilt").join(action).join("deps");
    validate_top_crate_cached_native_support(action, &plan)?;
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
        action,
        cargo_args: &mirror_args,
        source_root: &project.workspace_root,
        current_dir: &mirror_current_dir,
        cache_policy_path,
        public_cache_mode: &PublicCacheMode::for_rustc(&project.rustc_version),
        expanded_entries: None,
        prefetch_artifacts: None,
        semantic_fallback_enabled: false,
        extra_rustflags: &rustflags,
        covered_units: plan.bundles.len(),
    })
    .await?;
    Ok(true)
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
/// closure, not just the direct externs.
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

fn cargo_args_include_dev_dependencies(cargo_args: &[OsString]) -> bool {
    let mut iter = cargo_args.iter().peekable();
    while let Some(arg) = iter.next() {
        let Some(value) = arg.to_str() else {
            continue;
        };
        if matches!(
            value,
            "--all-targets"
                | "--tests"
                | "--benches"
                | "--examples"
                | "--test"
                | "--bench"
                | "--example"
        ) {
            return true;
        }
        if value.starts_with("--test=")
            || value.starts_with("--bench=")
            || value.starts_with("--example=")
        {
            return true;
        }
        if matches!(value, "--test" | "--bench" | "--example") && iter.peek().is_some() {
            return true;
        }
    }
    false
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
    for dependency in direct_dependencies {
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
        direct_externs.push(CachedDirectExtern {
            extern_name: dependency.extern_name.clone(),
            c_metadata,
        });
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

fn validate_top_crate_cached_native_support(
    action: &str,
    plan: &CachedDependencyPlan,
) -> stow_types::error::Result<()> {
    if action != "build" {
        return Ok(());
    }

    for bundle in plan.bundles.values() {
        let Some(native) = bundle.native.as_ref() else {
            continue;
        };
        if native_requires_link_replay(native) {
            return Err(stow_types::stow_error!(
                "top-crate-only cached dependency build does not support replaying native link directives yet: {} {}",
                bundle.crate_name,
                bundle.crate_version
            ));
        }
    }

    Ok(())
}

fn native_requires_link_replay(native: &NativeArtifacts) -> bool {
    !native.static_libs.is_empty()
        || native
            .cargo_directives
            .iter()
            .any(|directive| cargo_directive_key(directive).is_some_and(is_native_link_directive))
}

fn cargo_directive_key(directive: &str) -> Option<&str> {
    directive
        .strip_prefix("cargo::")
        .or_else(|| directive.strip_prefix("cargo:"))
}

fn is_native_link_directive(key: &str) -> bool {
    key.starts_with("rustc-link-")
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
) -> stow_types::error::Result<Option<PathBuf>> {
    let Some(config) = config else {
        return Ok(None);
    };
    if !public_cache_mode.is_enabled() {
        return Ok(None);
    }

    let analysis = match precomputed_analysis {
        Some(analysis) => analysis,
        None => {
            match analyze_workspace_prediction(project, current_dir, manifest_path, config).await {
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

    match cache_policy::write_policy(config, &analysis.cache_policy_entries).await {
        Ok(path) => Ok(Some(path)),
        // Without a policy the wrapper treats every invocation as allowed,
        // which costs lookups but still builds. Failing here would not.
        Err(error) => {
            tracing::warn!(
                %error,
                current_dir = %current_dir.display(),
                "failed to write the cache policy; the build continues without one"
            );
            Ok(None)
        }
    }
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
    // Canonicalize both sides so paths that traverse macOS's `/tmp -> /private/tmp`
    // (or any other resolvable symlink) compare structurally instead of failing
    // strip_prefix on the symlink boundary.
    let canonical_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let canonical_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    canonical_path
        .strip_prefix(&canonical_root)
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
/// to the toolchain.
async fn run_cargo_passthrough(
    project: &ProjectContext,
    action: &str,
    cargo_args: &[OsString],
    current_dir: &Path,
) -> stow_types::error::Result<()> {
    let mut command = Command::new("cargo");
    command.arg(action);
    for config_arg in &project.mold_config_args {
        command.arg("--config").arg(config_arg);
    }
    command.args(cargo_args).current_dir(current_dir);
    if std::env::var_os("CARGO_TARGET_DIR").is_none() && !has_explicit_target_dir(cargo_args) {
        command.env(
            "CARGO_TARGET_DIR",
            project.workspace_root.join("target").into_os_string(),
        );
    }
    let status = command
        .status()
        .await
        .wrap_err_with(|| format!("run cargo {action} (passthrough)"))?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

/// The launch plan for one cargo invocation under the stow wrapper: the
/// resolved workspace context plus the cache inputs earlier phases
/// computed for this build.
struct CargoRunPlan<'a> {
    project: &'a ProjectContext,
    config: Option<&'a StowConfig>,
    action: &'a str,
    cargo_args: &'a [OsString],
    source_root: &'a Path,
    current_dir: &'a Path,
    cache_policy_path: Option<&'a Path>,
    public_cache_mode: &'a PublicCacheMode,
    expanded_entries: Option<&'a [DependencyGraphEntry]>,
    prefetch_artifacts: Option<&'a [PrefetchArtifact]>,
    semantic_fallback_enabled: bool,
    extra_rustflags: &'a [String],
    covered_units: usize,
}

async fn run_cargo(plan: &CargoRunPlan<'_>) -> stow_types::error::Result<()> {
    let CargoRunPlan {
        project,
        config,
        action,
        cargo_args,
        source_root,
        current_dir,
        cache_policy_path,
        public_cache_mode,
        expanded_entries,
        prefetch_artifacts,
        semantic_fallback_enabled,
        extra_rustflags,
        covered_units,
    } = *plan;
    let wrappers = detect_wrapper_commands()?;
    let mut command = Command::new("cargo");
    command.arg(action);
    for config_arg in &project.mold_config_args {
        command.arg("--config").arg(config_arg);
    }
    command.args(cargo_args).current_dir(current_dir);
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
    command.env(
        rustc_args::STOW_RUSTC_EXTRA_ARGS_ENV,
        rustc_wrapper_extra_args(source_root, extra_rustflags)?,
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
    if let Some(expanded_entries) = expanded_entries {
        let expanded_graph_json = serde_json::to_string(expanded_entries)
            .wrap_err("serialize expanded dependency graph for rustc wrapper")?;
        command.env(STOW_EXPANDED_GRAPH_ENV, expanded_graph_json);
    }
    if let Some(prefetch_artifacts) = prefetch_artifacts {
        command.env(
            STOW_PREFETCH_ARTIFACTS_ENV,
            prefetch_artifacts_env_json(prefetch_artifacts)?,
        );
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

    // Every rustc invocation this cargo run spawns is a facade that asks
    // this process what to do, so the whole build shares one transport —
    // one pooled connection, one QUIC endpoint — instead of opening one
    // per compile unit.
    let handler = std::sync::Arc::new(crate::BuildSupervisor::default());
    let supervisor = crate::supervisor::server::start(handler.clone())
        .map_err(|error| stow_types::stow_error!("start the build supervisor: {error}"))?;
    for (key, value) in supervisor.env() {
        command.env(key, value);
    }

    let before = CoverageSnapshot::capture(config).await;

    let status = command
        .status()
        .await
        .wrap_err_with(|| format!("run cargo {action}"))?;
    drop(supervisor);
    if let Some(config) = config {
        if status.success() {
            report_cache_coverage(config, before, covered_units).await;
        }
        // The build's compile observations are its miss list (stow#317)
        // — a failed build's units are real misses too, whatever its
        // last unit did. They land in the same journal a plain-cargo
        // wrapper writes, and a detached drain posts the admission —
        // this command returns as soon as cargo does.
        journal_and_drain_misses(project, cargo_args, &handler.observations());
    }
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

/// Leave this build's compile observations in the miss journal a plain
/// `cargo build` writes, and kick the detached drain that posts the
/// admission — `stow build` returns as soon as cargo does (stow#317).
fn journal_and_drain_misses(
    project: &ProjectContext,
    cargo_args: &[OsString],
    observations: &[crate::artifact_cache::ObservedUnit],
) {
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| cargo_target_dir(project, cargo_args), PathBuf::from);
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    crate::miss_journal::journal_supervised(
        &rustc,
        &project.target,
        &project.rustc_version,
        observations,
        &target_dir,
    );
    crate::miss_journal::spawn_drain(&target_dir);
}

/// Serialize `prefetch_artifacts` into the `STOW_PREFETCH_ARTIFACTS` env
/// payload the rustc wrapper reads.
fn prefetch_artifacts_env_json(
    prefetch_artifacts: &[PrefetchArtifact],
) -> stow_types::error::Result<String> {
    let prefetch_entries = prefetch_artifacts
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
        .collect::<stow_types::error::Result<Vec<_>>>()?;
    serde_json::to_string(&prefetch_entries)
        .wrap_err("serialize prefetched graph artifacts for rustc wrapper")
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
            stats: stats::read_summary(config).await.unwrap_or_default(),
            errors: stats::read_error_counts(config).await.unwrap_or_default(),
            divergence: stats::read_profile_divergence(config)
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

fn cargo_target_dir(project: &ProjectContext, cargo_args: &[OsString]) -> PathBuf {
    let mut iter = cargo_args.iter();
    while let Some(arg) = iter.next() {
        let Some(arg_str) = arg.to_str() else {
            continue;
        };
        if let Some(value) = arg_str.strip_prefix("--target-dir=") {
            return resolve_user_path(project.current_dir(), value);
        }
        if arg_str == "--target-dir"
            && let Some(value) = iter.next().and_then(|value| value.to_str())
        {
            return resolve_user_path(project.current_dir(), value);
        }
    }
    project.workspace_root.join("target")
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

/// The rustc arguments a supervised run appends to every unit,
/// `\x1f`-encoded like `CARGO_ENCODED_RUSTFLAGS`: the workspace path remap
/// plus any flags the run itself selected. They travel through
/// [`rustc_args::STOW_RUSTC_EXTRA_ARGS_ENV`] — which the rustc wrapper
/// appends to each unit's argv — rather than `RUSTFLAGS`, where cargo's
/// precedence rules would discard the user's `.cargo/config.toml`
/// `target.*.rustflags` for the whole build.
fn rustc_wrapper_extra_args(
    source_root: &Path,
    extra_rustflags: &[String],
) -> stow_types::error::Result<String> {
    let source_root = source_root.to_str().ok_or_else(|| {
        stow_types::stow_error!("workspace root {} is not UTF-8", source_root.display())
    })?;
    let remap_flag = format!("--remap-path-prefix={source_root}=stow-ci://workspace");
    Ok(std::iter::once(remap_flag)
        .chain(extra_rustflags.iter().cloned())
        .collect::<Vec<_>>()
        .join("\x1f"))
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
    use super::{
        CachedDependencyPlan, MetadataArgs, ProjectContext, cached_dependency_profile,
        create_workspace_mirror, feature_references_dependency, native_requires_link_replay,
        rewrite_args_for_root, strip_selected_manifest_dependencies,
        validate_top_crate_cached_native_support,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use stow_types::artifact::NativeArtifacts;

    fn project_context() -> ProjectContext {
        ProjectContext {
            workspace_root: PathBuf::from("/workspace"),
            current_dir: PathBuf::from("/workspace"),
            current_dir_relative: PathBuf::new(),
            manifest_path: PathBuf::from("/workspace/Cargo.toml"),
            metadata_args: MetadataArgs::default(),
            target: "aarch64-apple-darwin".to_owned(),
            rustc_version: "1.91.1".to_owned(),
            mold_config_args: Vec::new(),
        }
    }

    fn as_strings(values: &[OsString]) -> Vec<String> {
        values
            .iter()
            .map(|value| value.to_str().expect("utf8 arg").to_owned())
            .collect()
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

    #[test]
    fn top_crate_check_accepts_cached_dependency_native_metadata() {
        let plan = CachedDependencyPlan {
            bundles: [(
                "native-meta".to_owned(),
                crate::artifact_cache::CachedArtifactBundle {
                    provenance: crate::artifact_cache::ArtifactProvenance::Remote,
                    oci_reference: String::new(),
                    oci_digest: String::new(),
                    compile_key: String::new(),
                    crate_name: "serde".to_owned(),
                    crate_version: "1.0.228".to_owned(),
                    c_metadata: "native-meta".to_owned(),
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
                    native: Some(NativeArtifacts {
                        static_libs: Vec::new(),
                        cargo_directives: vec![
                            "cargo:rustc-cfg=if_docsrs_then_no_serde_core".to_owned(),
                        ],
                        dep_env_vars: BTreeMap::default(),
                        out_dir_files: Vec::new(),
                    }),
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
        };

        validate_top_crate_cached_native_support("check", &plan).expect("check supports metadata");
    }

    #[test]
    fn top_crate_build_rejects_cached_dependency_native_link_replay() {
        let native = NativeArtifacts {
            static_libs: Vec::new(),
            cargo_directives: vec!["cargo:rustc-link-lib=static=ring-core".to_owned()],
            dep_env_vars: BTreeMap::default(),
            out_dir_files: Vec::new(),
        };

        assert!(native_requires_link_replay(&native));
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
            workspace_root: workspace.to_path_buf(),
            current_dir: member.clone(),
            current_dir_relative: PathBuf::from("member"),
            manifest_path: member.join("Cargo.toml"),
            metadata_args: MetadataArgs::default(),
            target: "aarch64-apple-darwin".to_owned(),
            rustc_version: "1.91.1".to_owned(),
            mold_config_args: Vec::new(),
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
}
