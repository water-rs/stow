use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};

use async_process::Command;
use cargo_metadata::{CargoOpt, Metadata, MetadataCommand, Package, TargetKind};
use eyre::Context;
use tempfile::TempDir;
use zenwave::Client;

use crate::config::StowConfig;
use crate::graph_cache;
use crate::rustc_args::{detect_rustc_host_target, detect_rustc_version};
use crate::{detect_wrapper_command, write_stdout};
use stow_types::api::{
    DependencyGraphAnalysisEntry, DependencyGraphEntry, DependencyGraphRequest,
    DependencyGraphResponse,
};
use stow_types::versioning::is_semver_compatible_upgrade;

const DEPENDENCY_GRAPH_BATCH_SIZE: usize = 64;

pub async fn run(command: &str, raw_args: &[OsString]) -> eyre::Result<()> {
    let invocation = CargoInvocation::parse(command, raw_args)?;
    let project = ProjectContext::load(&invocation.cargo_args).await?;
    let public_cache_mode = PublicCacheMode::for_rustc(&project.rustc_version);
    if let PublicCacheMode::Disabled { message, .. } = &public_cache_mode {
        write_stdout(&format!("{message}\n"))?;
    }
    let maybe_analysis = match StowConfig::load() {
        Ok(config) if public_cache_mode.is_enabled() => match analyze_workspace_prediction(&project, &config).await {
            Ok(analysis) => Some(analysis),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "compatible upgrade analysis failed, running original cargo command"
                );
                None
            }
        },
        Ok(_) => None,
        Err(error) => {
            tracing::debug!(%error, "stow config unavailable, skipping upgrade analysis");
            None
        }
    };

    let selected = select_upgrades(maybe_analysis.as_ref(), invocation.silent_compatible_upgrades)
        .await?;

    if selected.is_empty() {
        return run_cargo(
            &project,
            &invocation.action,
            &invocation.cargo_args,
            &project.workspace_root,
            project.current_dir(),
            &public_cache_mode,
        )
        .await;
    }

    let mirror = create_workspace_mirror(&project).await?;
    apply_selected_upgrades(&project, &mirror, &selected).await?;
    let mirror_args = rewrite_args_for_mirror(&invocation.cargo_args, &project, &mirror)?;
    run_cargo(
        &project,
        &invocation.action,
        &mirror_args,
        mirror.root(),
        &mirror.current_dir(),
        &public_cache_mode,
    )
    .await
}

pub async fn predict(raw_args: &[OsString]) -> eyre::Result<()> {
    let invocation = CargoInvocation::parse("predict", raw_args)?;
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
    let analysis = match analyze_workspace_prediction(&project, &config).await {
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
    fn parse(action: &str, raw_args: &[OsString]) -> eyre::Result<Self> {
        let mut cargo_args = Vec::with_capacity(raw_args.len());
        let mut silent_compatible_upgrades = false;
        let mut passthrough_args = false;

        for arg in raw_args {
            if !passthrough_args && arg == "--" {
                passthrough_args = true;
                cargo_args.push(arg.clone());
            } else if !passthrough_args && arg == "--silent-compatible-upgrades" {
                silent_compatible_upgrades = true;
            } else {
                cargo_args.push(arg.clone());
            }
        }

        Ok(Self {
            action: action.to_owned(),
            cargo_args,
            silent_compatible_upgrades,
        })
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
        let current_dir = std::env::current_dir().wrap_err("resolve current directory")?;
        let metadata_args = MetadataArgs::parse(&current_dir, cargo_args)?;
        let current_metadata =
            run_metadata(&current_dir, metadata_args.manifest_path.as_deref(), &metadata_args)
                .await?;

        let workspace_root = current_metadata.workspace_root.as_std_path().to_path_buf();
        let manifest_path = metadata_args
            .manifest_path
            .clone()
            .unwrap_or_else(|| workspace_root.join("Cargo.toml"));
        let current_dir_relative = pathdiff::diff_paths(&current_dir, &workspace_root)
            .unwrap_or_else(PathBuf::new);
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
    crate_name: String,
    version: semver::Version,
    features: Vec<String>,
}

#[derive(Debug, Clone)]
struct WorkspacePrediction {
    current_cached: usize,
    current_total: usize,
    candidates: Vec<CompatibleUpgrade>,
    missing_current: Vec<ResolvedDependency>,
}

#[derive(Debug, Clone)]
struct CompatibleUpgrade {
    crate_name: String,
    from_version: semver::Version,
    to_version: semver::Version,
    current_artifact_count: u32,
    upgraded_artifact_count: u32,
}

async fn analyze_workspace_prediction(
    project: &ProjectContext,
    config: &StowConfig,
) -> eyre::Result<WorkspacePrediction> {
    let metadata =
        run_metadata(project.current_dir(), Some(&project.manifest_path), &project.metadata_args)
            .await?;
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
                crate_name: dependency.crate_name.clone(),
                from_version: dependency.version.clone(),
                to_version: recommended.version,
                current_artifact_count: entry.current_artifact_count,
                upgraded_artifact_count: recommended.artifact_count,
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

    missing_current.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.version.cmp(&right.version))
            .then(left.features.cmp(&right.features))
    });

    Ok(WorkspacePrediction {
        current_cached,
        current_total: request.entries.len(),
        candidates,
        missing_current,
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
        return Ok(DependencyGraphResponse { entries: Vec::new() });
    }

    if let Some(cached) = graph_cache::load(config, request).await? {
        return Ok(cached);
    }

    let mut entries = Vec::with_capacity(request.entries.len());
    for chunk in request.entries.chunks(DEPENDENCY_GRAPH_BATCH_SIZE) {
        let response = query_dependency_graph_batch(
            config,
            &DependencyGraphRequest {
                target: request.target.clone(),
                rustc_version: request.rustc_version.clone(),
                entries: chunk.to_vec(),
            },
        )
        .await?;
        entries.extend(response.entries);
    }

    let response = DependencyGraphResponse { entries };
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

fn validate_analysis_entry(entry: &DependencyGraphAnalysisEntry) -> eyre::Result<()> {
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
        return Ok(analysis.candidates.clone());
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
        lines.push(format!(
            "  ... and {} more",
            analysis.candidates.len() - 12
        ));
    }
    format!("{}\n", lines.join("\n"))
}

fn render_prediction_summary(analysis: &WorkspacePrediction) -> String {
    let mut lines = vec![
        "stow semantic cache prediction for this workspace:".to_owned(),
        format!(
            "  current lockfile graph: {} / {} cacheable dependencies available ({:.1}%)",
            analysis.current_cached,
            analysis.current_total,
            percentage(analysis.current_cached, analysis.current_total),
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
            config.edge_url,
            reason,
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
    analysis.candidates.iter().fold(analysis.current_cached, |cached, candidate| {
        if candidate.upgraded_artifact_count > candidate.current_artifact_count {
            cached.saturating_add(1)
        } else {
            cached
        }
    })
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
) -> eyre::Result<WorkspaceMirror> {
    let workspace_root = project.workspace_root.clone();
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
    let manifest_path = mirror_manifest_path(project, mirror)?;
    for upgrade in selected {
        let package_spec = format!("{}@{}", upgrade.crate_name, upgrade.from_version);
        let status = Command::new("cargo")
            .arg("update")
            .arg("--manifest-path")
            .arg(&manifest_path)
            .arg("-p")
            .arg(&package_spec)
            .arg("--precise")
            .arg(upgrade.to_version.to_string())
            .current_dir(mirror.current_dir())
            .status()
            .await
            .wrap_err_with(|| format!("run cargo update for {package_spec}"))?;
        if !status.success() {
            return Err(eyre::eyre!(
                "cargo update failed for {} -> {} with status {}",
                package_spec,
                upgrade.to_version,
                status
            ));
        }
    }

    Ok(())
}

fn mirror_manifest_path(project: &ProjectContext, mirror: &WorkspaceMirror) -> eyre::Result<PathBuf> {
    relative_path(&project.workspace_root, &project.manifest_path)
        .map(|relative| mirror.root().join(relative))
}

fn rewrite_args_for_mirror(
    cargo_args: &[OsString],
    project: &ProjectContext,
    mirror: &WorkspaceMirror,
) -> eyre::Result<Vec<OsString>> {
    let mut rewritten = Vec::with_capacity(cargo_args.len());
    let mut iter = cargo_args.iter().peekable();

    while let Some(arg) = iter.next() {
        let Some(arg_str) = arg.to_str() else {
            rewritten.push(arg.clone());
            continue;
        };

        if let Some(path) = arg_str.strip_prefix("--manifest-path=") {
            let rewritten_path = rewrite_path_for_mirror(project, mirror, &resolve_user_path(project.current_dir(), path))?;
            rewritten.push(OsString::from(format!(
                "--manifest-path={}",
                rewritten_path.display()
            )));
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
            let rewritten_path = rewrite_path_for_mirror(
                project,
                mirror,
                &resolve_user_path(project.current_dir(), value_str),
            )?;
            rewritten.push(rewritten_path.into_os_string());
        }
    }

    Ok(rewritten)
}

fn rewrite_path_for_mirror(
    project: &ProjectContext,
    mirror: &WorkspaceMirror,
    path: &Path,
) -> eyre::Result<PathBuf> {
    let relative = relative_path(&project.workspace_root, path)?;
    Ok(mirror.root().join(relative))
}

fn relative_path(root: &Path, path: &Path) -> eyre::Result<PathBuf> {
    path.strip_prefix(root)
        .map(Path::to_path_buf)
        .map_err(|_| eyre::eyre!("path {} is outside workspace root {}", path.display(), root.display()))
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
            command.other_options(vec![
                "--filter-platform".to_owned(),
                target.clone(),
            ]);
        }
        command.exec().map_err(Into::into)
    })
    .await
}

fn resolve_dependencies(metadata: &Metadata) -> eyre::Result<Vec<ResolvedDependency>> {
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

    let mut deps = BTreeSet::new();
    for package in &metadata.packages {
        if package.source.is_none() || !has_cacheable_target(package) {
            continue;
        }
        let feature_set = features
            .get(&package.id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();
        deps.insert(ResolvedDependency {
            crate_name: package.name.clone(),
            version: package.version.clone(),
            features: feature_set,
        });
    }
    Ok(deps.into_iter().collect())
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
    public_cache_mode: &PublicCacheMode,
) -> eyre::Result<()> {
    let wrapper_command = detect_wrapper_command()?;
    let mut command = Command::new("cargo");
    command.arg(action).args(cargo_args).current_dir(current_dir);
    command.env("RUSTC_WRAPPER", &wrapper_command);
    command.env("CC", format!("{wrapper_command} cc"));
    command.env("CXX", format!("{wrapper_command} c++"));
    command.env("CMAKE_C_COMPILER_LAUNCHER", &wrapper_command);
    command.env("CMAKE_CXX_COMPILER_LAUNCHER", &wrapper_command);
    command.env("RUSTFLAGS", merged_rustflags(source_root)?);
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
