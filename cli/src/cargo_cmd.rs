use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::time::Instant;

use async_process::Command;
use cargo_metadata::{CargoOpt, Metadata, MetadataCommand, Package, TargetKind};
use eyre::Context;
use tempfile::TempDir;
use zenwave::Client;

use crate::cache_policy::{self, CachePolicyEntry};
use crate::cli_args::CargoCommandArgs;
use crate::config::StowConfig;
use crate::graph_cache;
use crate::prefetch::{self, PrefetchArtifact};
use crate::rustc_args::{
    STOW_PUBLIC_CACHE_RUSTC_VERSION_ENV, STOW_PUBLIC_CACHE_TARGET_ENV, detect_rustc_host_target,
    detect_rustc_version,
};
use crate::{detect_wrapper_commands, write_stdout};
use stow_types::api::{
    DependencyGraphAnalysisEntry, DependencyGraphArtifact, DependencyGraphEntry,
    DependencyGraphRequest, DependencyGraphResponse,
};
use stow_types::versioning::is_semver_compatible_upgrade;

pub async fn run(command: &str, args: CargoCommandArgs) -> eyre::Result<()> {
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
        let cache_policy_path = prepare_build_cache_plan(
            config.as_ref(),
            &project,
            project.current_dir(),
            &project.manifest_path,
            &public_cache_mode,
            maybe_analysis,
        )
        .await?;
        return run_cargo(
            &project,
            &invocation.action,
            &invocation.cargo_args,
            &project.workspace_root,
            project.current_dir(),
            cache_policy_path.as_deref(),
            &public_cache_mode,
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
    )
    .await
}

pub async fn predict(args: CargoCommandArgs) -> eyre::Result<()> {
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
    async fn load(cargo_args: &[OsString]) -> eyre::Result<Self> {
        let invocation_dir = std::env::current_dir().wrap_err("resolve current directory")?;
        let metadata_args = MetadataArgs::parse(&invocation_dir, cargo_args)?;
        let current_metadata = run_metadata(
            &invocation_dir,
            metadata_args.manifest_path.as_deref(),
            &metadata_args,
        )
        .await?;

        let workspace_root = current_metadata.workspace_root.as_std_path().to_path_buf();
        let current_dir = if invocation_dir.starts_with(&workspace_root) {
            invocation_dir
        } else {
            workspace_root.clone()
        };
        let manifest_path = metadata_args
            .manifest_path
            .clone()
            .unwrap_or_else(|| workspace_root.join("Cargo.toml"));
        let current_dir_relative =
            pathdiff::diff_paths(&current_dir, &workspace_root).unwrap_or_else(PathBuf::new);
        let target = match metadata_args.target.clone() {
            Some(target) => target,
            None => detect_rustc_host_target(std::ffi::OsStr::new("rustc"))
                .await
                .map_err(|error| eyre::eyre!("detect rustc host target: {error}"))?,
        };
        let rustc_version = detect_rustc_version(std::ffi::OsStr::new("rustc"))
            .await
            .map_err(|error| eyre::eyre!("detect rustc version: {error}"))?;

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
struct MetadataArgs {
    manifest_path: Option<PathBuf>,
    target: Option<String>,
    features: Vec<String>,
    all_features: bool,
    no_default_features: bool,
}

impl MetadataArgs {
    fn parse(current_dir: &Path, cargo_args: &[OsString]) -> eyre::Result<Self> {
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
                        .ok_or_else(|| eyre::eyre!("missing value after --manifest-path"))?;
                    parsed.manifest_path = Some(resolve_user_path(current_dir, value));
                }
                "--target" => {
                    let value = iter
                        .next()
                        .and_then(|value| value.to_str())
                        .ok_or_else(|| eyre::eyre!("missing value after --target"))?;
                    parsed.target = Some(value.to_owned());
                }
                "--features" | "-F" => {
                    let value = iter
                        .next()
                        .and_then(|value| value.to_str())
                        .ok_or_else(|| eyre::eyre!("missing value after {arg}"))?;
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
    package_id: cargo_metadata::PackageId,
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
    candidates: Vec<CompatibleUpgrade>,
    missing_current: Vec<ResolvedDependency>,
    prefetch_artifacts: Vec<PrefetchArtifact>,
    cache_policy_entries: Vec<CachePolicyEntry>,
}

#[derive(Debug, Clone)]
struct CompatibleUpgrade {
    package_id: cargo_metadata::PackageId,
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
    current_dir: &Path,
    manifest_path: &Path,
    config: &StowConfig,
) -> eyre::Result<WorkspacePrediction> {
    let metadata = run_metadata(current_dir, Some(manifest_path), &project.metadata_args).await?;
    let dependencies = resolve_dependencies(&metadata)?;
    let request = DependencyGraphRequest {
        target: project.target.clone(),
        rustc_version: project.rustc_version.clone(),
        entries: dependencies
            .iter()
            .cloned()
            .map(into_api_dependency)
            .collect(),
    };
    let response = query_dependency_graph(config, &request).await?;
    let expanded_cached = response.expanded_cached;
    let expanded_total = response.expanded_total;

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
            return Err(eyre::eyre!(
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
            eyre::eyre!(
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
                package_id: dependency.package_id.clone(),
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
        return Err(eyre::eyre!(
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
    mark_root_candidates(&mut candidates, &metadata);

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
    prefetch_artifacts
        .dedup_by(|left, right| left.crate_name == right.crate_name && left.c_metadata == right.c_metadata);
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
        candidates,
        missing_current,
        prefetch_artifacts,
        cache_policy_entries,
    })
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
) -> eyre::Result<DependencyGraphResponse> {
    if request.entries.is_empty() {
        return Ok(DependencyGraphResponse {
            entries: Vec::new(),
            expanded_cached: 0,
            expanded_total: 0,
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
) -> eyre::Result<DependencyGraphResponse> {
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
        .map_err(|error| eyre::eyre!("query dependency graph analysis: {error}"))
}

fn validate_c_metadata(value: &str) -> eyre::Result<()> {
    if value.is_empty() || value.len() > 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(eyre::eyre!("edge returned invalid c_metadata `{value}`"));
    }
    Ok(())
}

fn validate_analysis_entry(entry: &DependencyGraphAnalysisEntry) -> eyre::Result<()> {
    if entry.current_artifact_count != entry.current_artifacts.len() as u32 {
        return Err(eyre::eyre!(
            "edge returned inconsistent exact artifact count for {} {}",
            entry.dependency.crate_name,
            entry.dependency.version
        ));
    }
    validate_exact_artifacts(&entry.current_artifacts)?;
    if let Some(recommended) = &entry.recommended {
        if !is_semver_compatible_upgrade(&entry.dependency.version, &recommended.version) {
            return Err(eyre::eyre!(
                "edge returned invalid upgrade for {}: {} -> {}",
                entry.dependency.crate_name,
                entry.dependency.version,
                recommended.version
            ));
        }
        if recommended.artifact_count <= entry.current_artifact_count {
            return Err(eyre::eyre!(
                "edge returned non-improving upgrade for {}: {} -> {}",
                entry.dependency.crate_name,
                entry.current_artifact_count,
                recommended.artifact_count
            ));
        }
    }
    Ok(())
}

fn validate_exact_artifacts(artifacts: &[DependencyGraphArtifact]) -> eyre::Result<()> {
    let mut previous: Option<&str> = None;
    for artifact in artifacts {
        validate_c_metadata(&artifact.c_metadata)?;
        if previous.is_some_and(|last| last >= artifact.c_metadata.as_str()) {
            return Err(eyre::eyre!(
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
) -> eyre::Result<()> {
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
) -> eyre::Result<Option<PathBuf>> {
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
    let cache_policy_path =
        cache_policy::write_policy(config, &analysis.cache_policy_entries).await?;
    let prefetch_config = config.clone();
    let prefetch_artifacts = analysis.prefetch_artifacts.clone();
    let prefetch_current_dir = current_dir.to_path_buf();
    let prefetch_manifest_path = manifest_path.to_path_buf();
    tokio::spawn(async move {
        if let Err(error) = prefetch_graph_artifacts(&prefetch_config, &prefetch_artifacts).await {
            tracing::warn!(
                error = %error,
                current_dir = %prefetch_current_dir.display(),
                manifest_path = %prefetch_manifest_path.display(),
                "exact graph artifact prefetch failed while cargo was running"
            );
        }
    });
    Ok(Some(cache_policy_path))
}

async fn select_upgrades(
    analysis: Option<&WorkspacePrediction>,
    silent_compatible_upgrades: bool,
) -> eyre::Result<Vec<CompatibleUpgrade>> {
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

fn render_prediction_failure(config: &StowConfig, error: &eyre::Report) -> String {
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

fn read_confirmation() -> eyre::Result<bool> {
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

fn mark_root_candidates(candidates: &mut [CompatibleUpgrade], metadata: &Metadata) {
    let Some(resolve) = &metadata.resolve else {
        for candidate in candidates {
            candidate.is_root_candidate = true;
        }
        return;
    };

    let mut parents_by_package =
        BTreeMap::<cargo_metadata::PackageId, Vec<cargo_metadata::PackageId>>::new();
    for node in &resolve.nodes {
        for dep in &node.deps {
            parents_by_package
                .entry(dep.pkg.clone())
                .or_default()
                .push(node.id.clone());
        }
    }

    let candidate_ids = candidates
        .iter()
        .map(|candidate| candidate.package_id.clone())
        .collect::<BTreeSet<_>>();
    for candidate in candidates {
        candidate.is_root_candidate =
            !has_candidate_ancestor(&candidate.package_id, &candidate_ids, &parents_by_package);
    }
}

fn has_candidate_ancestor(
    package_id: &cargo_metadata::PackageId,
    candidate_ids: &BTreeSet<cargo_metadata::PackageId>,
    parents_by_package: &BTreeMap<cargo_metadata::PackageId, Vec<cargo_metadata::PackageId>>,
) -> bool {
    let mut stack = parents_by_package
        .get(package_id)
        .cloned()
        .unwrap_or_default();
    let mut visited = BTreeSet::<cargo_metadata::PackageId>::new();
    while let Some(parent) = stack.pop() {
        if !visited.insert(parent.clone()) {
            continue;
        }
        if candidate_ids.contains(&parent) {
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
) -> eyre::Result<WorkspaceMirror> {
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
) -> eyre::Result<()> {
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
) -> eyre::Result<BTreeMap<String, BTreeSet<semver::Version>>> {
    let lockfile_path = lockfile_path.to_path_buf();
    smol::unblock(move || {
        let lockfile = cargo_lock::Lockfile::load(&lockfile_path)
            .map_err(|error| eyre::eyre!("load lockfile {}: {error}", lockfile_path.display()))?;
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
) -> eyre::Result<PathBuf> {
    relative_path(&project.workspace_root, &project.manifest_path)
        .map(|relative| mirror.root().join(relative))
}

fn rewrite_args_for_mirror(
    cargo_args: &[OsString],
    project: &ProjectContext,
    mirror: &WorkspaceMirror,
) -> eyre::Result<Vec<OsString>> {
    rewrite_args_for_root(cargo_args, project, mirror.root())
}

fn rewrite_args_for_root(
    cargo_args: &[OsString],
    project: &ProjectContext,
    root: &Path,
) -> eyre::Result<Vec<OsString>> {
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
                .ok_or_else(|| eyre::eyre!("missing value after --manifest-path"))?;
            let value_str = value
                .to_str()
                .ok_or_else(|| eyre::eyre!("manifest path is not valid UTF-8"))?;
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
                .ok_or_else(|| eyre::eyre!("missing value after --target"))?;
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
) -> eyre::Result<PathBuf> {
    let relative = relative_path(&project.workspace_root, path)?;
    Ok(root.join(relative))
}

fn relative_path(root: &Path, path: &Path) -> eyre::Result<PathBuf> {
    path.strip_prefix(root).map(Path::to_path_buf).map_err(|_| {
        eyre::eyre!(
            "path {} is outside workspace root {}",
            path.display(),
            root.display()
        )
    })
}

async fn run_metadata(
    current_dir: &Path,
    manifest_path: Option<&Path>,
    args: &MetadataArgs,
) -> eyre::Result<Metadata> {
    let current_dir = current_dir.to_path_buf();
    let manifest_path = manifest_path.map(Path::to_path_buf);
    let args = args.clone();
    smol::unblock(move || {
        let mut command = MetadataCommand::new();
        command.current_dir(current_dir);
        if let Some(manifest_path) = manifest_path {
            command.manifest_path(manifest_path);
        }
        if args.all_features {
            command.features(CargoOpt::AllFeatures);
        }
        if args.no_default_features {
            command.features(CargoOpt::NoDefaultFeatures);
        }
        if !args.features.is_empty() {
            command.features(CargoOpt::SomeFeatures(args.features.clone()));
        }
        if let Some(target) = &args.target {
            command.other_options(vec!["--filter-platform".to_owned(), target.clone()]);
        }
        command.exec().map_err(Into::into)
    })
    .await
}

fn resolve_dependencies(metadata: &Metadata) -> eyre::Result<Vec<ResolvedDependency>> {
    let resolve = metadata
        .resolve
        .as_ref()
        .ok_or_else(|| eyre::eyre!("cargo metadata resolve graph is missing"))?;
    let nodes_by_id = resolve
        .nodes
        .iter()
        .map(|node| (node.id.clone(), node))
        .collect::<BTreeMap<_, _>>();
    let packages_by_id = metadata
        .packages
        .iter()
        .map(|package| (package.id.clone(), package))
        .collect::<BTreeMap<_, _>>();
    let features = metadata
        .resolve
        .as_ref()
        .map(|resolve| {
            resolve
                .nodes
                .iter()
                .map(|node| {
                    (
                        node.id.clone(),
                        node.features.iter().cloned().collect::<BTreeSet<_>>(),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let mut deps = Vec::<ResolvedDependency>::new();
    for workspace_member in &metadata.workspace_members {
        let Some(member_node) = nodes_by_id.get(workspace_member) else {
            continue;
        };
        for dependency in &member_node.deps {
            let Some(package) = packages_by_id.get(&dependency.pkg) else {
                return Err(eyre::eyre!(
                    "dependency package {} is missing from cargo metadata package list",
                    dependency.pkg
                ));
            };
            let Some(source) = package.source.as_ref() else {
                continue;
            };
            if !is_crates_io_source(source) || !has_cacheable_target(package) {
                continue;
            }
            let feature_set = features
                .get(&package.id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .collect::<Vec<_>>();
            deps.push(ResolvedDependency {
                package_id: package.id.clone(),
                crate_name: package.name.clone(),
                version: package.version.clone(),
                features: feature_set,
                depth: 1,
            });
        }
    }
    Ok(deps)
}

fn is_crates_io_source(source: &cargo_metadata::Source) -> bool {
    let repr = source.repr.as_str();
    repr.starts_with("registry+")
        && (repr.contains("crates.io-index") || repr.contains("index.crates.io"))
}

fn has_cacheable_target(package: &Package) -> bool {
    package.targets.iter().any(|target| {
        target.kind.iter().any(|kind| {
            matches!(
                kind,
                TargetKind::Lib
                    | TargetKind::RLib
                    | TargetKind::DyLib
                    | TargetKind::CDyLib
                    | TargetKind::ProcMacro
            )
        })
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
) -> eyre::Result<()> {
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
    command.env("RUSTFLAGS", merged_rustflags(source_root)?);
    command.env(STOW_PUBLIC_CACHE_RUSTC_VERSION_ENV, &project.rustc_version);
    command.env(STOW_PUBLIC_CACHE_TARGET_ENV, &project.target);
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
            &[OsString::from("--manifest-path"), OsString::from("Cargo.toml")],
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

fn merged_rustflags(source_root: &Path) -> eyre::Result<String> {
    let source_root = source_root
        .to_str()
        .ok_or_else(|| eyre::eyre!("workspace root {} is not UTF-8", source_root.display()))?;
    let remap_flag = format!("--remap-path-prefix={source_root}=stow-ci://workspace");
    Ok(match std::env::var("RUSTFLAGS") {
        Ok(existing) if !existing.trim().is_empty() => format!("{existing} {remap_flag}"),
        _ => remap_flag,
    })
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
