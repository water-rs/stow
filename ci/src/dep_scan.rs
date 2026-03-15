use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use async_fs::read_dir;
use async_process::Command;
use cargo_metadata::{Metadata, Package, PackageId, TargetKind};
use futures_lite::StreamExt;
use stow_types::api::BuildTaskPayload;
use stow_types::artifact::{ArtifactKind, NativeArtifacts, RustCrateType};

use crate::native;
use crate::task::BuildWorkspace;

pub async fn scan_artifacts(
    workspace: &BuildWorkspace,
    task: &BuildTaskPayload,
) -> eyre::Result<Vec<ScannedArtifact>> {
    let metadata = cargo_metadata(workspace.manifest_path()).await?;
    let target_dir = workspace
        .workspace_root()
        .join("target")
        .join(&task.target)
        .join("debug")
        .join("deps");
    let build_root = workspace
        .workspace_root()
        .join("target")
        .join(&task.target)
        .join("debug")
        .join("build");
    let rustc_version = rustc_version().await?;
    let package_index = package_index(&metadata);

    let mut artifacts = BTreeMap::<(String, String, String), ScannedArtifact>::new();
    let mut entries = read_dir(&target_dir).await?;
    while let Some(entry) = entries.next().await {
        let entry = entry?;
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };

        let Some(parsed) = parse_artifact_filename(file_name) else {
            continue;
        };
        let Some(package) = package_index.get(parsed.crate_stem.as_str()) else {
            continue;
        };

        if package.name == "stow-build-target" {
            continue;
        }

        let metadata = async_fs::metadata(&path).await?;
        let key = (
            package.name.clone(),
            parsed.hash.clone(),
            package.artifact_kind.as_str().to_owned(),
        );

        let record = artifacts.entry(key).or_insert_with(|| ScannedArtifact {
            crate_name: package.name.clone(),
            crate_version: package.version.to_string(),
            target: task.target.clone(),
            rustc_version: rustc_version.clone(),
            c_metadata: parsed.hash.clone(),
            features_json: serde_json::to_string(&package.features)
                .expect("feature serialization must succeed"),
            artifact_size: 0,
            kind: package.artifact_kind.clone(),
            crate_types: package.crate_types.clone(),
            outputs: Vec::new(),
            native: None,
        });
        record.artifact_size += metadata.len();
        record.outputs.push(ScannedArtifactOutput {
            kind: parsed.file_kind,
            path,
        });
    }

    let mut artifacts = artifacts.into_values().collect::<Vec<_>>();
    for artifact in &mut artifacts {
        artifact
            .outputs
            .sort_by(|left, right| left.path.cmp(&right.path));
        artifact.native = native::capture_native_artifacts(&build_root, &artifact.crate_name).await?;
    }
    artifacts.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.c_metadata.cmp(&right.c_metadata))
            .then(left.kind.as_str().cmp(right.kind.as_str()))
    });

    Ok(artifacts)
}

async fn cargo_metadata(manifest_path: &Path) -> eyre::Result<Metadata> {
    let output = Command::new("cargo")
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--manifest-path")
        .arg(manifest_path)
        .output()
        .await?;

    if !output.status.success() {
        return Err(eyre::eyre!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    serde_json::from_slice(&output.stdout).map_err(Into::into)
}

async fn rustc_version() -> eyre::Result<String> {
    let output = Command::new("rustc")
        .arg("--version")
        .output()
        .await?;

    if !output.status.success() {
        return Err(eyre::eyre!(
            "rustc --version failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let version = String::from_utf8(output.stdout)?;
    version
        .split_whitespace()
        .nth(1)
        .map(str::to_owned)
        .ok_or_else(|| eyre::eyre!("rustc --version output missing semantic version"))
}

fn package_index(metadata: &Metadata) -> BTreeMap<String, IndexedPackage> {
    let resolve_features = resolve_feature_map(metadata);
    metadata
        .packages
        .iter()
        .filter_map(|package| indexed_package(package, resolve_features.get(&package.id)))
        .map(|package| (package.lib_target_name.clone(), package))
        .collect()
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
) -> Option<IndexedPackage> {
    if package.source.is_none() {
        return None;
    }

    let target = package
        .targets
        .iter()
        .find_map(|target| {
            let crate_types = target
                .kind
                .iter()
                .filter_map(rust_crate_type)
                .collect::<BTreeSet<_>>();
            let artifact_kind = artifact_kind(&crate_types)?;
            Some((target, crate_types.into_iter().collect::<Vec<_>>(), artifact_kind))
        })?;

    Some(IndexedPackage {
        name: package.name.clone(),
        version: package.version.clone(),
        lib_target_name: target.0.name.clone(),
        crate_types: target.1,
        artifact_kind: target.2,
        features: features.cloned().unwrap_or_default(),
    })
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

fn parse_artifact_filename(file_name: &str) -> Option<ParsedArtifact> {
    let extension = Path::new(file_name).extension()?.to_str()?;
    let file_kind = match extension {
        "rlib" => ParsedFileKind::Rlib,
        "rmeta" => ParsedFileKind::Rmeta,
        "so" | "dylib" | "dll" => ParsedFileKind::DynamicLibrary,
        _ => return None,
    };

    let stem = Path::new(file_name).file_stem()?.to_str()?;
    let stem = stem.strip_prefix("lib").unwrap_or(stem);
    let (crate_stem, hash) = stem.rsplit_once('-')?;
    if hash.is_empty() {
        return None;
    }

    Some(ParsedArtifact {
        crate_stem: crate_stem.to_owned(),
        hash: hash.to_owned(),
        file_kind,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScannedArtifact {
    pub crate_name: String,
    pub crate_version: String,
    pub target: String,
    pub rustc_version: String,
    pub c_metadata: String,
    pub features_json: String,
    pub artifact_size: u64,
    pub kind: ArtifactKind,
    pub crate_types: Vec<RustCrateType>,
    pub outputs: Vec<ScannedArtifactOutput>,
    pub native: Option<NativeArtifacts>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScannedArtifactOutput {
    pub kind: ParsedFileKind,
    pub path: PathBuf,
}

#[derive(Debug)]
struct IndexedPackage {
    name: String,
    version: cargo_metadata::semver::Version,
    lib_target_name: String,
    crate_types: Vec<RustCrateType>,
    artifact_kind: ArtifactKind,
    features: BTreeSet<String>,
}

#[derive(Debug)]
struct ParsedArtifact {
    crate_stem: String,
    hash: String,
    file_kind: ParsedFileKind,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub(crate) enum ParsedFileKind {
    Rlib,
    Rmeta,
    DynamicLibrary,
}
