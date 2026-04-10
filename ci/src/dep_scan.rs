use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use async_process::Command;
use cargo_metadata::{Metadata, Package, PackageId, Target, TargetKind};
use stow_types::api::BuildTaskPayload;
use stow_types::artifact::{ArtifactKind, NativeArtifacts, RustCrateType};
use stow_types::platform::Profile;
use stow_types::public_cache::stable_c_metadata_for_compile_key;
use stow_types::upload_plan::compute_compile_key;

use crate::capture::{self, CapturedRustcArtifact, CapturedRustcOutputKind};
use crate::native;
use crate::task::{BuildWorkspace, CargoFeatureArgs};

pub(crate) async fn scan_artifacts(
    workspace: &BuildWorkspace,
    task: &BuildTaskPayload,
) -> stow_types::error::Result<Vec<ScannedArtifact>> {
    let metadata = cargo_metadata(workspace.manifest_path(), task).await?;
    let build_root = workspace
        .workspace_root()
        .join("target")
        .join(&task.target)
        .join("debug")
        .join("build");
    let rustc_version = task.rustc_version.clone();
    let package_index = package_index(&metadata, task)?;
    let captured_artifacts = capture::load_captured_artifacts(workspace.capture_dir()).await?;
    let authoritative_target_dir = workspace.workspace_root().join("target");

    let mut selected =
        BTreeMap::<(String, String, String, String), SelectedCapturedArtifact>::new();
    for captured in captured_artifacts {
        let Some(package) = package_index.get(captured.crate_name.as_str()) else {
            tracing::debug!(captured_crate = %captured.crate_name, "dep_scan skipped capture because package index had no entry");
            continue;
        };
        let Some(artifact_kind) = artifact_kind_for_capture(&captured) else {
            tracing::debug!(
                captured_crate = %captured.crate_name,
                crate_types = ?captured.crate_types,
                "dep_scan skipped capture — unrecognized crate types"
            );
            continue;
        };
        let key = (
            package.name.clone(),
            captured.c_metadata.clone(),
            artifact_kind.as_str().to_owned(),
            serde_json::to_string(&captured.emit)
                .expect("captured emit serialization must succeed"),
        );
        let candidate = SelectedCapturedArtifact {
            package: package.clone(),
            artifact_kind,
            captured,
        };
        select_captured_artifact(
            &mut selected,
            key,
            candidate,
            &authoritative_target_dir,
            &task.target,
        )?;
    }

    let selected = selected.into_values().collect::<Vec<_>>();
    let output_owners = output_owner_index(&selected)?;
    let mut resolved = BTreeMap::<usize, ResolvedArtifact>::new();
    let mut visiting = BTreeSet::<usize>::new();

    let mut artifacts = Vec::with_capacity(selected.len());
    for index in 0..selected.len() {
        artifacts.push(
            build_scanned_artifact(
                task,
                &rustc_version,
                &selected,
                &output_owners,
                &mut resolved,
                &mut visiting,
                index,
            )
            .await?,
        );
    }
    for artifact in &mut artifacts {
        artifact
            .outputs
            .sort_by(|left, right| left.path.cmp(&right.path));
        artifact.native =
            native::capture_native_artifacts(&build_root, &artifact.crate_name).await?;
    }
    artifacts.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.c_metadata.cmp(&right.c_metadata))
            .then(left.kind.as_str().cmp(right.kind.as_str()))
    });

    Ok(artifacts)
}

fn select_captured_artifact(
    selected: &mut BTreeMap<(String, String, String, String), SelectedCapturedArtifact>,
    key: (String, String, String, String),
    candidate: SelectedCapturedArtifact,
    authoritative_target_dir: &Path,
    requested_target: &str,
) -> stow_types::error::Result<()> {
    let candidate_authority = captured_authority(
        &candidate.captured,
        authoritative_target_dir,
        requested_target,
    );
    let Some(existing) = selected.get(&key) else {
        selected.insert(key, candidate);
        return Ok(());
    };
    let existing_authority = captured_authority(
        &existing.captured,
        authoritative_target_dir,
        requested_target,
    );

    match existing_authority.cmp(&candidate_authority) {
        std::cmp::Ordering::Less => {
            tracing::debug!(
                crate_name = %candidate.captured.crate_name,
                c_metadata = %candidate.captured.c_metadata,
                selected_authority = %candidate_authority.as_str(),
                replacing_out_dir = %candidate.captured.out_dir.display(),
                ignored_out_dir = %existing.captured.out_dir.display(),
                "dep_scan selected higher-authority cargo target outputs"
            );
            selected.insert(key, candidate);
            Ok(())
        }
        std::cmp::Ordering::Greater => {
            tracing::debug!(
                crate_name = %candidate.captured.crate_name,
                c_metadata = %candidate.captured.c_metadata,
                kept_authority = %existing_authority.as_str(),
                authoritative_out_dir = %existing.captured.out_dir.display(),
                ignored_out_dir = %candidate.captured.out_dir.display(),
                "dep_scan ignored lower-authority cargo target outputs"
            );
            Ok(())
        }
        std::cmp::Ordering::Equal => Err(stow_types::stow_error!(
            "captured duplicate artifact {} {} emit {:?} from {} and {} with ambiguous target authority",
            candidate.captured.crate_name,
            candidate.captured.c_metadata,
            candidate.captured.emit,
            existing.captured.out_dir.display(),
            candidate.captured.out_dir.display()
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CapturedAuthority {
    PrePhase,
    FinalHost,
    FinalRequestedTarget,
}

impl CapturedAuthority {
    fn as_str(self) -> &'static str {
        match self {
            Self::PrePhase => "pre-phase",
            Self::FinalHost => "final-host-target",
            Self::FinalRequestedTarget => "final-requested-target",
        }
    }
}

fn captured_authority(
    captured: &CapturedRustcArtifact,
    authoritative_target_dir: &Path,
    requested_target: &str,
) -> CapturedAuthority {
    let Ok(relative_out_dir) = captured.out_dir.strip_prefix(authoritative_target_dir) else {
        return CapturedAuthority::PrePhase;
    };
    let Some(first_component) = relative_out_dir
        .components()
        .next()
        .and_then(|component| component.as_os_str().to_str())
    else {
        return CapturedAuthority::FinalHost;
    };
    if first_component == requested_target {
        CapturedAuthority::FinalRequestedTarget
    } else {
        CapturedAuthority::FinalHost
    }
}

async fn build_scanned_artifact(
    task: &BuildTaskPayload,
    rustc_version: &str,
    selected: &[SelectedCapturedArtifact],
    output_owners: &BTreeMap<PathBuf, usize>,
    resolved: &mut BTreeMap<usize, ResolvedArtifact>,
    visiting: &mut BTreeSet<usize>,
    artifact_index: usize,
) -> stow_types::error::Result<ScannedArtifact> {
    let artifact = selected
        .get(artifact_index)
        .ok_or_else(|| stow_types::stow_error!("selected artifact index {artifact_index} is out of bounds"))?;
    let resolved_artifact = resolve_artifact(
        selected,
        output_owners,
        resolved,
        visiting,
        task,
        rustc_version,
        artifact_index,
    )?;
    let dependencies = resolved_artifact.dependencies.clone();
    let mut outputs = Vec::with_capacity(artifact.captured.outputs.len());
    let mut artifact_size = 0u64;
    for output in &artifact.captured.outputs {
        let metadata = async_fs::metadata(&output.path).await?;
        artifact_size = artifact_size.saturating_add(metadata.len());
        outputs.push(ScannedArtifactOutput {
            kind: parsed_file_kind(output.kind),
            path: output.path.clone(),
        });
    }
    Ok(ScannedArtifact {
        crate_name: artifact.package.name.clone(),
        crate_version: artifact.package.version.to_string(),
        target: artifact
            .captured
            .target
            .clone()
            .unwrap_or_else(|| task.target.clone()),
        rustc_version: rustc_version.to_owned(),
        captured_compile_key: resolved_artifact.compile_key.clone(),
        c_metadata: resolved_artifact.stable_c_metadata.clone(),
        extra_filename: format!("-{}", resolved_artifact.stable_c_metadata),
        profile: artifact.captured.profile.clone(),
        emit: artifact.captured.emit.clone(),
        features_json: resolved_artifact.features_json.clone(),
        dependencies,
        artifact_size,
        kind: artifact.artifact_kind.clone(),
        crate_types: artifact.package.crate_types.clone(),
        outputs,
        native: None,
    })
}

fn resolve_artifact(
    selected: &[SelectedCapturedArtifact],
    output_owners: &BTreeMap<PathBuf, usize>,
    resolved: &mut BTreeMap<usize, ResolvedArtifact>,
    visiting: &mut BTreeSet<usize>,
    task: &BuildTaskPayload,
    rustc_version: &str,
    artifact_index: usize,
) -> stow_types::error::Result<ResolvedArtifact> {
    if let Some(existing) = resolved.get(&artifact_index) {
        return Ok(existing.clone());
    }
    if !visiting.insert(artifact_index) {
        return Err(stow_types::stow_error!(
            "dep_scan detected a cycle while resolving authoritative artifact index {artifact_index}"
        ));
    }

    let artifact = selected
        .get(artifact_index)
        .ok_or_else(|| stow_types::stow_error!("selected artifact index {artifact_index} is out of bounds"))?;
    let dependencies = resolve_dependencies(
        selected,
        output_owners,
        resolved,
        visiting,
        task,
        rustc_version,
        artifact_index,
    )?;
    let features_json = serde_json::to_string(
        &artifact
            .package
            .features
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
    )
    .expect("feature serialization must succeed");
    let compile_key = resolve_scanned_artifact_compile_key(
        &artifact.package,
        &dependencies,
        task,
        rustc_version,
        &artifact.captured.profile,
        &artifact.captured.emit,
        &features_json,
        &artifact.artifact_kind,
    )?;
    let stable_c_metadata = stable_c_metadata_for_compile_key(&compile_key)?;
    visiting.remove(&artifact_index);

    let resolved_artifact = ResolvedArtifact {
        compile_key,
        stable_c_metadata,
        features_json,
        dependencies,
    };
    resolved.insert(artifact_index, resolved_artifact.clone());
    Ok(resolved_artifact)
}

fn resolve_scanned_artifact_compile_key(
    package: &IndexedPackage,
    dependencies: &[ScannedArtifactDependency],
    task: &BuildTaskPayload,
    rustc_version: &str,
    profile: &Profile,
    emit: &[String],
    features_json: &str,
    artifact_kind: &ArtifactKind,
) -> stow_types::error::Result<String> {
    let dependency_c_metadata_json = dependency_c_metadata_json(dependencies)?;
    compute_compile_key(
        &package.name,
        &package.version.to_string(),
        &task.target,
        rustc_version,
        profile,
        &package.crate_types,
        emit,
        features_json,
        &dependency_c_metadata_json,
        artifact_kind,
    )
}

fn resolve_dependencies(
    selected: &[SelectedCapturedArtifact],
    output_owners: &BTreeMap<PathBuf, usize>,
    resolved: &mut BTreeMap<usize, ResolvedArtifact>,
    visiting: &mut BTreeSet<usize>,
    task: &BuildTaskPayload,
    rustc_version: &str,
    artifact_index: usize,
) -> stow_types::error::Result<Vec<ScannedArtifactDependency>> {
    let artifact = selected
        .get(artifact_index)
        .ok_or_else(|| stow_types::stow_error!("selected artifact index {artifact_index} is out of bounds"))?;
    let mut dependencies = Vec::with_capacity(artifact.captured.dependencies.len());
    for dependency in &artifact.captured.dependencies {
        let dependency_index = output_owners.get(&dependency.path).ok_or_else(|| {
            stow_types::stow_error!(
                "dep_scan could not resolve authoritative dependency owner for {} at {} while scanning {}",
                dependency.crate_name,
                dependency.path.display(),
                artifact.captured.crate_name
            )
        })?;
        let resolved_dependency = resolve_artifact(
            selected,
            output_owners,
            resolved,
            visiting,
            task,
            rustc_version,
            *dependency_index,
        )?;
        dependencies.push(ScannedArtifactDependency {
            crate_name: dependency.crate_name.clone(),
            path: dependency.path.clone(),
            compile_key: resolved_dependency.compile_key,
            stable_c_metadata: resolved_dependency.stable_c_metadata,
        });
    }
    dependencies.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.path.cmp(&right.path))
    });
    dependencies
        .dedup_by(|left, right| left.crate_name == right.crate_name && left.path == right.path);
    Ok(dependencies)
}

fn output_owner_index(
    selected: &[SelectedCapturedArtifact],
) -> stow_types::error::Result<BTreeMap<PathBuf, usize>> {
    let mut owners = BTreeMap::new();
    for (index, artifact) in selected.iter().enumerate() {
        for output in &artifact.captured.outputs {
            if let Some(existing) = owners.insert(output.path.clone(), index) {
                let existing_artifact = selected.get(existing).ok_or_else(|| {
                    stow_types::stow_error!("selected artifact index {existing} is out of bounds")
                })?;
                return Err(stow_types::stow_error!(
                    "dep_scan found duplicate authoritative output path {} claimed by {} and {}",
                    output.path.display(),
                    existing_artifact.captured.crate_name,
                    artifact.captured.crate_name
                ));
            }
        }
    }
    Ok(owners)
}

async fn cargo_metadata(manifest_path: &Path, task: &BuildTaskPayload) -> stow_types::error::Result<Metadata> {
    let mut command = Command::new("cargo");
    command
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--manifest-path")
        .arg(manifest_path);
    CargoFeatureArgs::from_task(task)?.apply(&mut command);
    let output = command.output().await?;

    if !output.status.success() {
        return Err(stow_types::stow_error!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    serde_json::from_slice(&output.stdout).map_err(Into::into)
}

fn package_index(
    metadata: &Metadata,
    task: &BuildTaskPayload,
) -> stow_types::error::Result<BTreeMap<String, IndexedPackage>> {
    let resolve_features = resolve_feature_map(metadata);
    metadata
        .packages
        .iter()
        .filter_map(|package| {
            indexed_package(package, resolve_features.get(&package.id), task).transpose()
        })
        .collect::<stow_types::error::Result<Vec<_>>>()
        .map(|packages| {
            packages
                .into_iter()
                .map(|package| (package.lib_target_name.clone(), package))
                .collect()
        })
}

fn resolve_feature_map(metadata: &Metadata) -> BTreeMap<PackageId, BTreeSet<String>> {
    metadata
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
        .unwrap_or_default()
}

fn indexed_package(
    package: &Package,
    features: Option<&BTreeSet<String>>,
    task: &BuildTaskPayload,
) -> stow_types::error::Result<Option<IndexedPackage>> {
    let task_features = task_feature_set(task)?;
    let target = package
        .targets
        .iter()
        .find_map(|target| preferred_target(package, target, &task_features))
        .or_else(|| {
            package
                .targets
                .iter()
                .find_map(|target| candidate_target(target))
        });

    let Some((target, crate_types, artifact_kind)) = target else {
        return Ok(None);
    };

    let resolved_features = features.cloned().unwrap_or_default();
    let features = package_feature_set(
        package.name.as_str(),
        &resolved_features,
        &task_features,
        task,
    );

    Ok(Some(IndexedPackage {
        name: package.name.clone(),
        version: package.version.clone(),
        lib_target_name: target.name.clone(),
        crate_types,
        artifact_kind,
        features,
    }))
}

fn package_feature_set(
    package_name: &str,
    resolved_features: &BTreeSet<String>,
    task_features: &BTreeSet<String>,
    task: &BuildTaskPayload,
) -> BTreeSet<String> {
    if !resolved_features.is_empty() {
        return resolved_features.clone();
    }
    if package_name == task.crate_name {
        return task_features.clone();
    }
    BTreeSet::new()
}

fn preferred_target<'a>(
    package: &Package,
    target: &'a Target,
    task_features: &BTreeSet<String>,
) -> Option<(&'a Target, Vec<RustCrateType>, ArtifactKind)> {
    if target.name != package.name {
        return None;
    }
    if !target_required_features_match(target, task_features) {
        return None;
    }
    candidate_target(target)
}

fn candidate_target(target: &Target) -> Option<(&Target, Vec<RustCrateType>, ArtifactKind)> {
    let crate_types = target
        .kind
        .iter()
        .filter_map(rust_crate_type)
        .collect::<BTreeSet<_>>();
    let artifact_kind = artifact_kind(&crate_types)?;
    Some((
        target,
        crate_types.into_iter().collect::<Vec<_>>(),
        artifact_kind,
    ))
}

fn target_required_features_match(target: &Target, task_features: &BTreeSet<String>) -> bool {
    target.required_features.is_empty()
        || target
            .required_features
            .iter()
            .all(|feature| task_features.contains(feature))
}

fn task_feature_set(task: &BuildTaskPayload) -> stow_types::error::Result<BTreeSet<String>> {
    serde_json::from_str::<Vec<String>>(&task.features_json)
        .map_err(|error| stow_types::stow_error!("parse task features_json in dep_scan: {error}"))
        .map(|features| features.into_iter().collect())
}

fn rust_crate_type(kind: &TargetKind) -> Option<RustCrateType> {
    match kind {
        TargetKind::Lib => Some(RustCrateType::Lib),
        TargetKind::RLib => Some(RustCrateType::Rlib),
        TargetKind::DyLib => Some(RustCrateType::Dylib),
        TargetKind::CDyLib => Some(RustCrateType::Cdylib),
        TargetKind::StaticLib => Some(RustCrateType::Staticlib),
        TargetKind::ProcMacro => Some(RustCrateType::ProcMacro),
        _ => None,
    }
}

fn artifact_kind(crate_types: &BTreeSet<RustCrateType>) -> Option<ArtifactKind> {
    if crate_types.contains(&RustCrateType::ProcMacro) {
        return Some(ArtifactKind::ProcMacro);
    }
    if crate_types.contains(&RustCrateType::Dylib) {
        return Some(ArtifactKind::Dylib);
    }
    if crate_types.contains(&RustCrateType::Lib) || crate_types.contains(&RustCrateType::Rlib) {
        return Some(ArtifactKind::Rlib);
    }
    None
}

fn artifact_kind_for_capture(
    captured: &CapturedRustcArtifact,
) -> Option<ArtifactKind> {
    if captured
        .crate_types
        .iter()
        .any(|crate_type| crate_type == "proc-macro")
    {
        return Some(ArtifactKind::ProcMacro);
    }
    if captured
        .crate_types
        .iter()
        .any(|crate_type| crate_type == "dylib")
    {
        return Some(ArtifactKind::Dylib);
    }
    if captured
        .crate_types
        .iter()
        .any(|crate_type| crate_type == "lib" || crate_type == "rlib")
    {
        return Some(ArtifactKind::Rlib);
    }
    None
}

fn parsed_file_kind(kind: CapturedRustcOutputKind) -> ParsedFileKind {
    match kind {
        CapturedRustcOutputKind::Rlib => ParsedFileKind::Rlib,
        CapturedRustcOutputKind::Rmeta => ParsedFileKind::Rmeta,
        CapturedRustcOutputKind::DynamicLibrary => ParsedFileKind::DynamicLibrary,
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ScannedArtifact {
    pub crate_name: String,
    pub crate_version: String,
    pub target: String,
    pub rustc_version: String,
    pub captured_compile_key: String,
    pub c_metadata: String,
    pub extra_filename: String,
    pub profile: Profile,
    pub emit: Vec<String>,
    pub features_json: String,
    pub dependencies: Vec<ScannedArtifactDependency>,
    pub artifact_size: u64,
    pub kind: ArtifactKind,
    pub crate_types: Vec<RustCrateType>,
    pub outputs: Vec<ScannedArtifactOutput>,
    pub native: Option<NativeArtifacts>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ScannedArtifactOutput {
    pub(crate) kind: ParsedFileKind,
    pub(crate) path: PathBuf,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ScannedArtifactDependency {
    pub(crate) crate_name: String,
    pub(crate) path: PathBuf,
    pub(crate) compile_key: String,
    pub(crate) stable_c_metadata: String,
}

fn dependency_c_metadata_json(dependencies: &[ScannedArtifactDependency]) -> stow_types::error::Result<String> {
    let mut dependency_identities = dependencies
        .iter()
        .map(|dependency| DependencyCMetadataRecord {
            crate_name: dependency.crate_name.clone(),
            c_metadata: dependency.stable_c_metadata.clone(),
        })
        .collect::<Vec<_>>();
    dependency_identities.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.c_metadata.cmp(&right.c_metadata))
    });
    serde_json::to_string(&dependency_identities).map_err(Into::into)
}

#[derive(Debug, Clone, serde::Serialize)]
struct DependencyCMetadataRecord {
    crate_name: String,
    c_metadata: String,
}

#[derive(Debug, Clone)]
struct IndexedPackage {
    name: String,
    version: cargo_metadata::semver::Version,
    lib_target_name: String,
    crate_types: Vec<RustCrateType>,
    artifact_kind: ArtifactKind,
    features: BTreeSet<String>,
}

#[derive(Debug)]
struct SelectedCapturedArtifact {
    package: IndexedPackage,
    artifact_kind: ArtifactKind,
    captured: CapturedRustcArtifact,
}

#[derive(Debug, Clone)]
struct ResolvedArtifact {
    compile_key: String,
    stable_c_metadata: String,
    features_json: String,
    dependencies: Vec<ScannedArtifactDependency>,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub(crate) enum ParsedFileKind {
    Rlib,
    Rmeta,
    DynamicLibrary,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use stow_types::api::BuildTaskPayload;
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::platform::{PanicStrategy, Profile};

    use super::{
        IndexedPackage, ResolvedArtifact, SelectedCapturedArtifact, output_owner_index,
        package_feature_set, resolve_artifact, select_captured_artifact,
    };
    use crate::capture::{
        CapturedDependencyIdentity, CapturedRustcArtifact, CapturedRustcOutput,
        CapturedRustcOutputKind,
    };

    #[test]
    fn authoritative_target_outputs_replace_prephase_outputs() {
        let key = (
            "slug".to_owned(),
            "abc123".to_owned(),
            ArtifactKind::Rlib.as_str().to_owned(),
            "[\"dep-info\",\"link\"]".to_owned(),
        );
        let mut selected = BTreeMap::new();
        let package = super::IndexedPackage {
            name: "slug".to_owned(),
            version: semver::Version::parse("0.1.6").expect("version"),
            lib_target_name: "slug".to_owned(),
            crate_types: vec![RustCrateType::Rlib],
            artifact_kind: ArtifactKind::Rlib,
            features: Default::default(),
        };
        let fallback = SelectedCapturedArtifact {
            package: package.clone(),
            artifact_kind: ArtifactKind::Rlib,
            captured: captured(
                "slug",
                "abc123",
                "/tmp/workspace/target-check/aarch64-apple-darwin/debug/deps",
            ),
        };
        let authoritative = SelectedCapturedArtifact {
            package,
            artifact_kind: ArtifactKind::Rlib,
            captured: captured(
                "slug",
                "abc123",
                "/tmp/workspace/target/aarch64-apple-darwin/debug/deps",
            ),
        };

        select_captured_artifact(
            &mut selected,
            key.clone(),
            fallback,
            &PathBuf::from("/tmp/workspace/target"),
            "aarch64-apple-darwin",
        )
        .expect("select fallback");
        select_captured_artifact(
            &mut selected,
            key.clone(),
            authoritative,
            &PathBuf::from("/tmp/workspace/target"),
            "aarch64-apple-darwin",
        )
        .expect("replace with authoritative");

        let stored = selected.get(&key).expect("selected capture");
        assert!(
            stored
                .captured
                .out_dir
                .starts_with("/tmp/workspace/target/aarch64-apple-darwin/debug/deps")
        );
    }

    #[test]
    fn requested_target_outputs_replace_host_target_outputs() {
        let key = (
            "aho_corasick".to_owned(),
            "ef4a079a8dc04c32".to_owned(),
            ArtifactKind::Rlib.as_str().to_owned(),
            "[\"dep-info\",\"link\",\"metadata\"]".to_owned(),
        );
        let mut selected = BTreeMap::new();
        let package = super::IndexedPackage {
            name: "aho_corasick".to_owned(),
            version: semver::Version::parse("1.1.4").expect("version"),
            lib_target_name: "aho_corasick".to_owned(),
            crate_types: vec![RustCrateType::Rlib],
            artifact_kind: ArtifactKind::Rlib,
            features: Default::default(),
        };
        let host_target = SelectedCapturedArtifact {
            package: package.clone(),
            artifact_kind: ArtifactKind::Rlib,
            captured: captured_with_target(
                "aho_corasick",
                "ef4a079a8dc04c32",
                "/tmp/workspace/target/debug/deps",
                None,
            ),
        };
        let requested_target = SelectedCapturedArtifact {
            package,
            artifact_kind: ArtifactKind::Rlib,
            captured: captured_with_target(
                "aho_corasick",
                "ef4a079a8dc04c32",
                "/tmp/workspace/target/aarch64-apple-darwin/debug/deps",
                Some("aarch64-apple-darwin"),
            ),
        };

        select_captured_artifact(
            &mut selected,
            key.clone(),
            host_target,
            &PathBuf::from("/tmp/workspace/target"),
            "aarch64-apple-darwin",
        )
        .expect("select host target");
        select_captured_artifact(
            &mut selected,
            key.clone(),
            requested_target,
            &PathBuf::from("/tmp/workspace/target"),
            "aarch64-apple-darwin",
        )
        .expect("replace with requested target");

        let stored = selected.get(&key).expect("selected capture");
        assert!(
            stored
                .captured
                .out_dir
                .starts_with("/tmp/workspace/target/aarch64-apple-darwin/debug/deps")
        );
    }

    #[test]
    fn authoritative_dependency_resolution_ignores_captured_stable_metadata_snapshot() {
        let leaf_output = PathBuf::from(
            "/tmp/workspace/target/aarch64-apple-darwin/debug/deps/libitoa-raw.rmeta",
        );
        let leaf = SelectedCapturedArtifact {
            package: IndexedPackage {
                name: "itoa".to_owned(),
                version: semver::Version::parse("1.0.18").expect("version"),
                lib_target_name: "itoa".to_owned(),
                crate_types: vec![RustCrateType::Lib],
                artifact_kind: ArtifactKind::Rlib,
                features: BTreeSet::new(),
            },
            artifact_kind: ArtifactKind::Rlib,
            captured: CapturedRustcArtifact {
                crate_name: "itoa".to_owned(),
                crate_types: vec!["lib".to_owned()],
                emit: vec!["dep-info".to_owned(), "metadata".to_owned()],
                target: Some("aarch64-apple-darwin".to_owned()),
                c_metadata: "leaf-raw".to_owned(),
                extra_filename: "-leaf-raw".to_owned(),
                dependencies: Vec::new(),
                profile: Profile {
                    opt_level: "0".to_owned(),
                    debuginfo: 1,
                    debug_assertions: true,
                    overflow_checks: true,
                    panic: PanicStrategy::Unwind,
                },
                out_dir: PathBuf::from("/tmp/workspace/target/aarch64-apple-darwin/debug/deps"),
                outputs: vec![CapturedRustcOutput {
                    kind: CapturedRustcOutputKind::Rmeta,
                    path: leaf_output.clone(),
                }],
            },
        };
        let consumer = SelectedCapturedArtifact {
            package: IndexedPackage {
                name: "serde_json".to_owned(),
                version: semver::Version::parse("1.0.149").expect("version"),
                lib_target_name: "serde_json".to_owned(),
                crate_types: vec![RustCrateType::Lib],
                artifact_kind: ArtifactKind::Rlib,
                features: ["default".to_owned(), "std".to_owned()]
                    .into_iter()
                    .collect(),
            },
            artifact_kind: ArtifactKind::Rlib,
            captured: CapturedRustcArtifact {
                crate_name: "serde_json".to_owned(),
                crate_types: vec!["lib".to_owned()],
                emit: vec!["dep-info".to_owned(), "metadata".to_owned()],
                target: Some("aarch64-apple-darwin".to_owned()),
                c_metadata: "consumer-raw".to_owned(),
                extra_filename: "-consumer-raw".to_owned(),
                dependencies: vec![CapturedDependencyIdentity {
                    crate_name: "itoa".to_owned(),
                    path: leaf_output.clone(),
                    compile_key: "wrong-captured-compile-key".to_owned(),
                    stable_c_metadata: "wrong-captured-stable".to_owned(),
                }],
                profile: Profile {
                    opt_level: "0".to_owned(),
                    debuginfo: 1,
                    debug_assertions: true,
                    overflow_checks: true,
                    panic: PanicStrategy::Unwind,
                },
                out_dir: PathBuf::from("/tmp/workspace/target/aarch64-apple-darwin/debug/deps"),
                outputs: vec![CapturedRustcOutput {
                    kind: CapturedRustcOutputKind::Rmeta,
                    path: PathBuf::from(
                        "/tmp/workspace/target/aarch64-apple-darwin/debug/deps/libserde_json-raw.rmeta",
                    ),
                }],
            },
        };
        let selected = vec![leaf, consumer];
        let output_owners = output_owner_index(&selected).expect("build output owner index");
        let task = BuildTaskPayload {
            task_id: "task".to_owned(),
            crate_name: "serde_json".to_owned(),
            version: "1.0.149".to_owned(),
            features_json: "[\"default\",\"std\"]".to_owned(),
            target: "aarch64-apple-darwin".to_owned(),
            rustc_version: "1.91.1".to_owned(),
        };
        let mut resolved = BTreeMap::<usize, ResolvedArtifact>::new();
        let mut visiting = BTreeSet::<usize>::new();

        let leaf_resolved = resolve_artifact(
            &selected,
            &output_owners,
            &mut resolved,
            &mut visiting,
            &task,
            "1.91.1",
            0,
        )
        .expect("resolve leaf artifact");
        let consumer_resolved = resolve_artifact(
            &selected,
            &output_owners,
            &mut resolved,
            &mut visiting,
            &task,
            "1.91.1",
            1,
        )
        .expect("resolve consumer artifact");

        assert_eq!(consumer_resolved.dependencies.len(), 1);
        assert_eq!(
            consumer_resolved.dependencies[0].stable_c_metadata,
            leaf_resolved.stable_c_metadata
        );
        assert_eq!(
            consumer_resolved.dependencies[0].compile_key,
            leaf_resolved.compile_key
        );
    }

    fn captured(crate_name: &str, c_metadata: &str, out_dir: &str) -> CapturedRustcArtifact {
        captured_with_target(
            crate_name,
            c_metadata,
            out_dir,
            Some("aarch64-apple-darwin"),
        )
    }

    fn captured_with_target(
        crate_name: &str,
        c_metadata: &str,
        out_dir: &str,
        target: Option<&str>,
    ) -> CapturedRustcArtifact {
        CapturedRustcArtifact {
            crate_name: crate_name.to_owned(),
            crate_types: vec!["rlib".to_owned()],
            emit: vec!["dep-info".to_owned(), "link".to_owned()],
            target: target.map(ToOwned::to_owned),
            c_metadata: c_metadata.to_owned(),
            extra_filename: format!("-{c_metadata}"),
            dependencies: Vec::new(),
            profile: Profile {
                opt_level: "0".to_owned(),
                debuginfo: 1,
                debug_assertions: true,
                overflow_checks: true,
                panic: PanicStrategy::Unwind,
            },
            out_dir: PathBuf::from(out_dir),
            outputs: Vec::new(),
        }
    }

    #[test]
    fn dependency_without_resolved_features_does_not_inherit_root_task_features() {
        let task = BuildTaskPayload {
            task_id: "serde-1.0.228-task".to_owned(),
            crate_name: "serde".to_owned(),
            version: "1.0.228".to_owned(),
            features_json: "[\"default\",\"derive\",\"serde_derive\",\"std\"]".to_owned(),
            target: "aarch64-apple-darwin".to_owned(),
            rustc_version: "1.91.1".to_owned(),
        };
        let task_features = ["default", "derive", "serde_derive", "std"]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();

        assert_eq!(
            package_feature_set("unicode-ident", &BTreeSet::new(), &task_features, &task),
            BTreeSet::new()
        );
        assert_eq!(
            package_feature_set("serde", &BTreeSet::new(), &task_features, &task),
            task_features
        );
    }
}
