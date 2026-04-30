use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::time::Instant;

use async_process::Command;
use serde::{Deserialize, Serialize};
use stow_types::artifact::{ArtifactKind, RustCrateType};
use stow_types::bundle::{STOW_PROC_MACRO_MEDIA_TYPE, STOW_RLIB_MEDIA_TYPE, STOW_RMETA_MEDIA_TYPE};
use stow_types::error::Context;
use stow_types::platform::{PanicStrategy, Profile};
use tempfile::TempDir;
use zenwave::Client;

use crate::cache_policy::{self, CachePolicyEntry};
use crate::cli_args::CargoCommandArgs;
use crate::config::StowConfig;
use crate::fetch::{FetchRequest, SemanticFetchRequest};
use crate::graph_cache;
use crate::inject;
use crate::prefetch::{self, PrefetchArtifact};
use crate::rustc_args::{
    STOW_PUBLIC_CACHE_RUSTC_VERSION_ENV, STOW_PUBLIC_CACHE_TARGET_ENV, detect_rustc_host_target,
    detect_rustc_version,
};
use crate::workspace_deps::{self, PackageKey, SelectedRegistryDependency};
use crate::{
    STOW_ENABLE_SEMANTIC_FALLBACK_ENV, STOW_EXPANDED_GRAPH_ENV, STOW_PREFETCH_ARTIFACTS_ENV,
};
use crate::{detect_wrapper_commands, write_stdout};
use stow_types::api::{
    BatchArtifactRequestEntry, DependencyGraphAnalysisEntry, DependencyGraphArtifact,
    DependencyGraphEntry, DependencyGraphRequest, DependencyGraphResponse,
};
use stow_types::versioning::is_semver_compatible_upgrade;

pub async fn run(command: &str, args: CargoCommandArgs) -> stow_types::error::Result<()> {
    let invocation = CargoInvocation::new(command, args);
    let project = ProjectContext::load(&invocation.cargo_args).await?;
    let public_cache_mode = PublicCacheMode::for_rustc(&project.rustc_version);
    if let PublicCacheMode::Disabled { message, .. } = &public_cache_mode {
        write_stdout(&format!("{message}\n"))?;
    }
    let config = match StowConfig::load() {
        Ok(config) => Some(config),
        Err(error) => {
            tracing::debug!(%error, "stow config unavailable, skipping graph analysis");
            None
        }
    };
    let maybe_analysis = match config.as_ref() {
        Some(config) if public_cache_mode.is_enabled() => match analyze_workspace_prediction(
            &project,
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
                None
            }
        },
        _ => None,
    };

    let selected = select_upgrades(
        maybe_analysis.as_ref(),
        invocation.silent_compatible_upgrades,
    )
    .await?;
    if selected.is_empty() {
        let expanded_graph = maybe_analysis
            .as_ref()
            .map(|analysis| analysis.expanded_entries.clone());
        let prefetch_artifacts = maybe_analysis
            .as_ref()
            .map(|analysis| analysis.prefetch_artifacts.clone());
        let semantic_fallback_enabled = expanded_graph
            .as_ref()
            .is_some_and(|entries| !entries.is_empty());
        let cache_policy_path = prepare_build_cache_plan(
            config.as_ref(),
            &project,
            project.current_dir(),
            &project.manifest_path,
            &public_cache_mode,
            maybe_analysis,
        )
        .await?;
        let expanded_entries = expanded_graph.as_deref();
        let prefetch_artifacts = prefetch_artifacts.as_deref();
        if let Some(config) = config.as_ref()
            && public_cache_mode.is_enabled()
            && try_run_top_crate_with_cached_dependencies(
                config,
                &project,
                &invocation.action,
                &invocation.cargo_args,
                cache_policy_path.as_deref(),
                &public_cache_mode,
            )
            .await?
        {
            return Ok(());
        }
        return run_cargo(
            &project,
            &invocation.action,
            &invocation.cargo_args,
            &project.workspace_root,
            project.current_dir(),
            cache_policy_path.as_deref(),
            &public_cache_mode,
            expanded_entries,
            prefetch_artifacts,
            semantic_fallback_enabled,
            &[],
        )
        .await;
    }

    let mirror = create_workspace_mirror(&project, &project.workspace_root).await?;
    apply_selected_upgrades(&project, &mirror, &selected).await?;
    let mirror_args = rewrite_args_for_mirror(&invocation.cargo_args, &project, &mirror)?;
    let mirror_manifest_path = mirror_manifest_path(&project, &mirror)?;
    let cache_policy_path = prepare_build_cache_plan(
        config.as_ref(),
        &project,
        &mirror.current_dir(),
        &mirror_manifest_path,
        &public_cache_mode,
        None,
    )
    .await?;
    run_cargo(
        &project,
        &invocation.action,
        &mirror_args,
        mirror.root(),
        &mirror.current_dir(),
        cache_policy_path.as_deref(),
        &public_cache_mode,
        None,
        None,
        true,
        &[],
    )
    .await
}

pub async fn predict(args: CargoCommandArgs) -> stow_types::error::Result<()> {
    let invocation = CargoInvocation::new("predict", args);
    let project = ProjectContext::load(&invocation.cargo_args).await?;
    let public_cache_mode = PublicCacheMode::for_rustc(&project.rustc_version);
    if let PublicCacheMode::Disabled { message, .. } = &public_cache_mode {
        write_stdout(&format!("{message}\n"))?;
        return Ok(());
    }

    let config = match StowConfig::load() {
        Ok(config) => config,
        Err(error) => {
            write_stdout(&format!(
                "stow predict is unavailable because stow is not configured.\nreason: {error}\n"
            ))?;
            return Ok(());
        }
    };
    let analysis = match analyze_workspace_prediction(
        &project,
        project.current_dir(),
        &project.manifest_path,
        &config,
    )
    .await
    {
        Ok(analysis) => analysis,
        Err(error) => {
            write_stdout(&render_prediction_failure(&config, &error))?;
            return Ok(());
        }
    };
    write_stdout(&render_prediction_summary(&analysis))?;
    Ok(())
}

#[derive(Debug, Clone)]
struct CargoInvocation {
    action: String,
    cargo_args: Vec<OsString>,
    silent_compatible_upgrades: bool,
}

impl CargoInvocation {
    fn new(action: &str, args: CargoCommandArgs) -> Self {
        Self {
            action: action.to_owned(),
            cargo_args: args.cargo_args,
            silent_compatible_upgrades: args.silent_compatible_upgrades,
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
}

impl ProjectContext {
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
        })
    }

    fn current_dir(&self) -> &Path {
        &self.current_dir
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct MetadataArgs {
    pub(crate) manifest_path: Option<PathBuf>,
    pub(crate) target: Option<String>,
    pub(crate) features: Vec<String>,
    pub(crate) all_features: bool,
    pub(crate) no_default_features: bool,
}

impl MetadataArgs {
    fn parse(current_dir: &Path, cargo_args: &[OsString]) -> stow_types::error::Result<Self> {
        let mut parsed = Self::default();
        let mut iter = cargo_args.iter().peekable();

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
            if let Some(value) = arg.strip_prefix("-F") {
                if !value.is_empty() {
                    parsed.features.extend(split_features(value));
                    continue;
                }
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
    let expanded_entries = workspace_deps::resolve_exact_dependency_graph(
        &project.workspace_root,
        manifest_path,
        &project.metadata_args,
        &project.target,
    )
    .await?;
    let dependencies = lockfile_graph
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
        .collect::<Vec<_>>();
    let request = DependencyGraphRequest {
        target: project.target.clone(),
        rustc_version: project.rustc_version.clone(),
        entries: dependencies
            .iter()
            .cloned()
            .map(into_api_dependency)
            .collect(),
        expanded_entries,
    };
    let response = query_dependency_graph(config, &request).await?;
    let expanded_cached = response.expanded_cached;
    let expanded_total = response.expanded_total;
    let expanded_entries = response.expanded_entries.clone();

    let mut analysis_by_key =
        BTreeMap::<(String, semver::Version, Vec<String>), DependencyGraphAnalysisEntry>::new();
    for entry in response.entries {
        validate_analysis_entry(&entry)?;
        let key = (
            entry.dependency.crate_name.clone(),
            entry.dependency.version.clone(),
            entry.dependency.features.clone(),
        );
        if analysis_by_key.insert(key.clone(), entry).is_some() {
            return Err(stow_types::stow_error!(
                "edge returned duplicate dependency analysis for {} {}",
                key.0,
                key.1
            ));
        }
    }

    let mut current_cached = 0usize;
    let mut missing_current = Vec::new();
    let mut candidates = Vec::new();
    for dependency in dependencies {
        let key = (
            dependency.crate_name.clone(),
            dependency.version.clone(),
            dependency.features.clone(),
        );
        let entry = analysis_by_key.remove(&key).ok_or_else(|| {
            stow_types::stow_error!(
                "edge response is missing dependency analysis for {} {}",
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
            "edge response contained {} unexpected dependencies",
            analysis_by_key.len()
        ));
    }

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
    mark_root_candidates(&mut candidates, &lockfile_graph.parents_by_package);

    missing_current.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.version.cmp(&right.version))
            .then(left.features.cmp(&right.features))
    });
    let mut prefetch_artifacts = response
        .prefetch_artifacts
        .iter()
        .map(|artifact| PrefetchArtifact {
            crate_name: artifact.crate_name.clone(),
            c_metadata: artifact.c_metadata.clone(),
            target: request.target.clone(),
            rustc_version: request.rustc_version.clone(),
            depth: 0,
        })
        .collect::<Vec<_>>();
    prefetch_artifacts.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.c_metadata.cmp(&right.c_metadata))
    });
    prefetch_artifacts.dedup_by(|left, right| {
        left.crate_name == right.crate_name && left.c_metadata == right.c_metadata
    });
    let mut cache_policy_entries = response
        .prefetch_artifacts
        .into_iter()
        .map(|artifact| CachePolicyEntry {
            target: request.target.clone(),
            c_metadata: artifact.c_metadata,
        })
        .collect::<Vec<_>>();
    cache_policy_entries.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then(left.c_metadata.cmp(&right.c_metadata))
    });
    cache_policy_entries
        .dedup_by(|left, right| left.target == right.target && left.c_metadata == right.c_metadata);

    Ok(WorkspacePrediction {
        current_cached,
        current_total: request.entries.len(),
        expanded_cached,
        expanded_total,
        expanded_entries,
        candidates,
        missing_current,
        prefetch_artifacts,
        cache_policy_entries,
    })
}

async fn try_run_top_crate_with_cached_dependencies(
    config: &StowConfig,
    project: &ProjectContext,
    action: &str,
    cargo_args: &[OsString],
    cache_policy_path: Option<&Path>,
    public_cache_mode: &PublicCacheMode,
) -> stow_types::error::Result<bool> {
    let Some(shape) = cached_dependency_shape(action) else {
        return Ok(false);
    };
    let direct_dependencies = workspace_deps::resolve_selected_registry_dependencies(
        &project.workspace_root,
        &project.manifest_path,
        &project.metadata_args,
        &project.target,
    )
    .await?;
    if direct_dependencies.is_empty() {
        return Ok(false);
    }
    let plan =
        resolve_cached_dependency_plan(config, project, &direct_dependencies, &shape).await?;

    let target_dir = cargo_target_dir(project, cargo_args);
    let prebuilt_dir = target_dir.join("stow-prebuilt").join(action).join("deps");
    materialize_cached_dependency_plan(&prebuilt_dir, &plan).await?;
    let rustflags = top_crate_rustflags(&prebuilt_dir, &plan, &shape)?;

    let mirror = create_workspace_mirror(project, &project.workspace_root).await?;
    strip_selected_manifest_dependencies(project, &mirror).await?;
    regenerate_mirror_lockfile(project, &mirror).await?;
    let mirror_args = rewrite_args_for_mirror(cargo_args, project, &mirror)?;
    run_cargo(
        project,
        action,
        &mirror_args,
        &project.workspace_root,
        &mirror.current_dir(),
        cache_policy_path,
        public_cache_mode,
        None,
        None,
        false,
        &rustflags,
    )
    .await?;
    Ok(true)
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
    let mut crate_c_metadata = BTreeMap::<String, String>::new();
    let mut direct_externs = Vec::with_capacity(direct_dependencies.len());
    for dependency in direct_dependencies {
        let candidates =
            load_cached_dependency_bundle_candidates(config, project, dependency, shape).await?;
        let mut candidate_errors = Vec::new();
        let mut selected_c_metadata = None;
        for candidate in candidates {
            let c_metadata = candidate.c_metadata.clone();
            match collect_cached_bundle_closure(
                config,
                project,
                candidate,
                &mut bundles,
                &mut crate_c_metadata,
            )
            .await
            {
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
    crate_c_metadata: &mut BTreeMap<String, String>,
) -> stow_types::error::Result<()> {
    let mut stack = vec![root];
    let mut candidate_c_metadata = BTreeSet::<String>::new();
    let mut candidate_bundles = Vec::new();
    let mut next_crate_c_metadata = crate_c_metadata.clone();
    while let Some(bundle) = stack.pop() {
        let c_metadata = bundle.c_metadata.clone();
        if bundles.contains_key(&c_metadata) || candidate_c_metadata.contains(&c_metadata) {
            continue;
        }
        let crate_identity = cached_bundle_crate_identity(&bundle);
        if let Some(existing) = next_crate_c_metadata.get(&crate_identity) {
            if existing != &c_metadata {
                return Err(stow_types::stow_error!(
                    "cached artifact closure has conflicting metadata for crate {}: {} and {}",
                    crate_identity,
                    existing,
                    c_metadata
                ));
            }
        } else {
            next_crate_c_metadata.insert(crate_identity, c_metadata.clone());
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
                    crate_name: &dependency.crate_name,
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
    *crate_c_metadata = next_crate_c_metadata;
    for bundle in candidate_bundles {
        bundles.insert(bundle.c_metadata.clone(), bundle);
    }
    Ok(())
}

fn cached_bundle_crate_identity(bundle: &crate::artifact_cache::CachedArtifactBundle) -> String {
    bundle.crate_name.replace('-', "_")
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

fn cached_dependency_profile() -> Profile {
    Profile {
        opt_level: "0".to_owned(),
        debuginfo: 1,
        debug_assertions: true,
        overflow_checks: true,
        panic: PanicStrategy::Unwind,
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
            inject::write_cached_output(&source_path, &output_path, Some(&output.sha256)).await?;
        }
        if bundle.native.is_some() {
            return Err(stow_types::stow_error!(
                "top-crate-only cached dependency materialization does not support native build artifacts yet: {} {}",
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

fn into_api_dependency(dependency: ResolvedDependency) -> DependencyGraphEntry {
    DependencyGraphEntry {
        crate_name: dependency.crate_name,
        version: dependency.version,
        features: dependency.features,
    }
}

async fn query_dependency_graph(
    config: &StowConfig,
    request: &DependencyGraphRequest,
) -> stow_types::error::Result<DependencyGraphResponse> {
    if request.entries.is_empty() {
        return Ok(DependencyGraphResponse {
            entries: Vec::new(),
            expanded_cached: 0,
            expanded_total: 0,
            expanded_entries: Vec::new(),
            prefetch_artifacts: Vec::new(),
        });
    }

    if let Some(cached) = graph_cache::load(config, request).await? {
        return Ok(cached);
    }

    let response = query_dependency_graph_batch(config, request).await?;
    graph_cache::store(config, request, &response).await?;
    Ok(response)
}

async fn query_dependency_graph_batch(
    config: &StowConfig,
    request: &DependencyGraphRequest,
) -> stow_types::error::Result<DependencyGraphResponse> {
    let url = format!(
        "{}/api/v1/catalog/graph",
        config.edge_url.trim_end_matches('/')
    );
    let mut client = zenwave::client();
    client
        .post(&url)?
        .json_body(request)?
        .json()
        .await
        .map_err(|error| stow_types::stow_error!("query dependency graph analysis: {error}"))
}

fn validate_c_metadata(value: &str) -> stow_types::error::Result<()> {
    if value.is_empty() || value.len() > 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(stow_types::stow_error!(
            "edge returned invalid c_metadata `{value}`"
        ));
    }
    Ok(())
}

fn validate_analysis_entry(entry: &DependencyGraphAnalysisEntry) -> stow_types::error::Result<()> {
    if entry.current_artifact_count != entry.current_artifacts.len() as u32 {
        return Err(stow_types::stow_error!(
            "edge returned inconsistent exact artifact count for {} {}",
            entry.dependency.crate_name,
            entry.dependency.version
        ));
    }
    validate_exact_artifacts(&entry.current_artifacts)?;
    if let Some(recommended) = &entry.recommended {
        if !is_semver_compatible_upgrade(&entry.dependency.version, &recommended.version) {
            return Err(stow_types::stow_error!(
                "edge returned invalid upgrade for {}: {} -> {}",
                entry.dependency.crate_name,
                entry.dependency.version,
                recommended.version
            ));
        }
        if recommended.artifact_count <= entry.current_artifact_count {
            return Err(stow_types::stow_error!(
                "edge returned non-improving upgrade for {}: {} -> {}",
                entry.dependency.crate_name,
                entry.current_artifact_count,
                recommended.artifact_count
            ));
        }
    }
    Ok(())
}

fn validate_exact_artifacts(
    artifacts: &[DependencyGraphArtifact],
) -> stow_types::error::Result<()> {
    let mut previous: Option<&str> = None;
    for artifact in artifacts {
        validate_c_metadata(&artifact.c_metadata)?;
        if previous.is_some_and(|last| last >= artifact.c_metadata.as_str()) {
            return Err(stow_types::stow_error!(
                "edge returned unsorted or duplicated exact artifacts"
            ));
        }
        previous = Some(artifact.c_metadata.as_str());
    }
    Ok(())
}

async fn prefetch_graph_artifacts(
    config: &StowConfig,
    artifacts: &[PrefetchArtifact],
) -> stow_types::error::Result<()> {
    if artifacts.is_empty() {
        return Ok(());
    }
    let summary = prefetch::warm_exact_artifacts(config, artifacts).await?;
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

    prefetch_graph_artifacts(config, &analysis.prefetch_artifacts)
        .await
        .wrap_err_with(|| {
            format!(
                "prefetch exact graph artifacts for {}",
                manifest_path.display()
            )
        })?;

    if analysis.cache_policy_entries.is_empty() {
        return Ok(None);
    }

    cache_policy::write_policy(config, &analysis.cache_policy_entries)
        .await
        .wrap_err_with(|| format!("write cache policy for workspace {}", current_dir.display()))
        .map(Some)
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
            "  expanded dependency graph: {} / {} cacheable dependencies available ({:.1}%)",
            analysis.expanded_cached,
            analysis.expanded_total,
            percentage(analysis.expanded_cached, analysis.expanded_total),
        ),
    ];

    if !analysis.candidates.is_empty() {
        let upgraded_cached = predicted_cached_after_upgrades(analysis);
        lines.push(format!(
            "  recommended compatible upgrades: {} / {} entries would have cached artifacts ({:.1}%)",
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

    format!(
        "stow predict could not compute cache coverage for this workspace.\nreason: {}\n",
        reason,
    )
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
            let current = current_versions
                .get(&upgrade.crate_name)
                .cloned()
                .unwrap_or_default();
            if !current.contains(&upgrade.from_version) {
                if current.contains(&upgrade.to_version) {
                    already_satisfied = already_satisfied.saturating_add(1);
                    tracing::info!(
                        crate_name = %upgrade.crate_name,
                        from_version = %upgrade.from_version,
                        to_version = %upgrade.to_version,
                        "compatible upgrade already satisfied by a previous cargo update"
                    );
                    continue;
                }
                source_absent = source_absent.saturating_add(1);
                tracing::info!(
                    crate_name = %upgrade.crate_name,
                    from_version = %upgrade.from_version,
                    to_version = %upgrade.to_version,
                    "skipping compatible upgrade because source version is no longer present in the current lockfile"
                );
                continue;
            }

            let package_spec = format!("{}@{}", upgrade.crate_name, upgrade.from_version);
            let output = Command::new("cargo")
                .arg("update")
                .arg("--offline")
                .arg("--manifest-path")
                .arg(&manifest_path)
                .arg("-p")
                .arg(&package_spec)
                .arg("--precise")
                .arg(upgrade.to_version.to_string())
                .current_dir(mirror.current_dir())
                .output()
                .await
                .wrap_err_with(|| format!("run cargo update for {package_spec}"))?;
            if output.status.success() {
                applied = applied.saturating_add(1);
                made_progress = true;
                current_versions = load_current_lockfile_versions(&lockfile_path).await?;
                continue;
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
            deferred.push(upgrade);
            current_versions = load_current_lockfile_versions(&lockfile_path).await?;
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
    let mut iter = cargo_args.iter().peekable();
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
    path.strip_prefix(root).map(Path::to_path_buf).map_err(|_| {
        stow_types::stow_error!(
            "path {} is outside workspace root {}",
            path.display(),
            root.display()
        )
    })
}

async fn run_cargo(
    project: &ProjectContext,
    action: &str,
    cargo_args: &[OsString],
    source_root: &Path,
    current_dir: &Path,
    cache_policy_path: Option<&Path>,
    public_cache_mode: &PublicCacheMode,
    expanded_entries: Option<&[DependencyGraphEntry]>,
    prefetch_artifacts: Option<&[PrefetchArtifact]>,
    semantic_fallback_enabled: bool,
    extra_rustflags: &[String],
) -> stow_types::error::Result<()> {
    let wrappers = detect_wrapper_commands()?;
    let mut command = Command::new("cargo");
    command
        .arg(action)
        .args(cargo_args)
        .current_dir(current_dir);
    command.env("RUSTC_WRAPPER", &wrappers.rustc);
    command.env("CC", &wrappers.cc);
    command.env("CXX", &wrappers.cc);
    command.env("CMAKE_C_COMPILER_LAUNCHER", &wrappers.cc);
    command.env("CMAKE_CXX_COMPILER_LAUNCHER", &wrappers.cc);
    command.env("RUSTFLAGS", merged_rustflags(source_root, extra_rustflags)?);
    command.env(STOW_PUBLIC_CACHE_RUSTC_VERSION_ENV, &project.rustc_version);
    command.env(STOW_PUBLIC_CACHE_TARGET_ENV, &project.target);
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
        let prefetch_entries = prefetch_artifacts
            .iter()
            .map(|artifact| BatchArtifactRequestEntry {
                crate_name: artifact.crate_name.clone(),
                c_metadata: artifact.c_metadata.clone(),
            })
            .collect::<Vec<_>>();
        let prefetch_json = serde_json::to_string(&prefetch_entries)
            .wrap_err("serialize prefetched graph artifacts for rustc wrapper")?;
        command.env(STOW_PREFETCH_ARTIFACTS_ENV, prefetch_json);
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

    let status = command
        .status()
        .await
        .wrap_err_with(|| format!("run cargo {action}"))?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
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
    let mut iter = cargo_args.iter().peekable();
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
    let source_manifest = std::fs::read_to_string(&project.manifest_path)
        .wrap_err_with(|| format!("read Cargo.toml {}", project.manifest_path.display()))?;
    let mut document = source_manifest
        .parse::<toml_edit::DocumentMut>()
        .wrap_err_with(|| format!("parse Cargo.toml {}", project.manifest_path.display()))?;
    remove_dependency_tables(document.as_table_mut());
    std::fs::remove_file(&manifest_path)
        .wrap_err_with(|| format!("remove mirrored manifest {}", manifest_path.display()))?;
    async_fs::write(&manifest_path, document.to_string())
        .await
        .wrap_err_with(|| format!("write top-crate-only manifest {}", manifest_path.display()))
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

fn remove_dependency_tables(table: &mut toml_edit::Table) {
    table.remove("dependencies");
    table.remove("dev-dependencies");
    table.remove("build-dependencies");
    if let Some(targets) = table
        .get_mut("target")
        .and_then(toml_edit::Item::as_table_like_mut)
    {
        for (_, item) in targets.iter_mut() {
            if let Some(target_table) = item.as_table_like_mut() {
                target_table.remove("dependencies");
                target_table.remove("dev-dependencies");
                target_table.remove("build-dependencies");
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

    fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled)
    }

    fn disable_reason(&self) -> Option<&'static str> {
        match self {
            Self::Enabled => None,
            Self::Disabled { reason, .. } => Some(reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MetadataArgs, ProjectContext, rewrite_args_for_root};
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    fn project_context() -> ProjectContext {
        ProjectContext {
            workspace_root: PathBuf::from("/workspace"),
            current_dir: PathBuf::from("/workspace"),
            current_dir_relative: PathBuf::new(),
            manifest_path: PathBuf::from("/workspace/Cargo.toml"),
            metadata_args: MetadataArgs::default(),
            target: "aarch64-apple-darwin".to_owned(),
            rustc_version: "1.91.1".to_owned(),
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
                "/mirror/Cargo.toml".to_owned(),
            ]
        );
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

fn merged_rustflags(
    source_root: &Path,
    extra_rustflags: &[String],
) -> stow_types::error::Result<String> {
    let source_root = source_root.to_str().ok_or_else(|| {
        stow_types::stow_error!("workspace root {} is not UTF-8", source_root.display())
    })?;
    let remap_flag = format!("--remap-path-prefix={source_root}=stow-ci://workspace");
    let mut flags = match std::env::var("RUSTFLAGS") {
        Ok(existing) if !existing.trim().is_empty() => format!("{existing} {remap_flag}"),
        _ => remap_flag,
    };
    for flag in extra_rustflags {
        flags.push(' ');
        flags.push_str(flag);
    }
    Ok(flags)
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
