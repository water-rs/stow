use std::collections::BTreeSet;
use std::path::PathBuf;

use async_fs::read;
use async_process::Command;
use sha2::{Digest, Sha256};
use stow_types::artifact::{ArtifactKey, ArtifactKind};
use stow_types::crate_info::{CrateId, FeatureSet};
use stow_types::platform::{PanicStrategy, Profile, RustcVersion, Target};
use stow_types::registry::oci_reference;

use crate::dep_scan::ScannedArtifact;

pub async fn build_upload_plan(
    scanned: &[ScannedArtifact],
) -> eyre::Result<Vec<PlannedArtifact>> {
    let rustc_version = rustc_version_verbose().await?;
    let mut plans = Vec::with_capacity(scanned.len());

    for artifact in scanned {
        let key = ArtifactKey {
            crate_id: CrateId {
                name: artifact.crate_name.clone(),
                version: semver::Version::parse(&artifact.crate_version)?,
            },
            features: parse_feature_set(&artifact.features_json)?,
            target: Target(artifact.target.clone()),
            rustc_version: rustc_version.clone(),
            profile: debug_profile(),
            kind: artifact.kind.clone(),
        };

        plans.push(PlannedArtifact {
            crate_name: artifact.crate_name.clone(),
            crate_version: artifact.crate_version.clone(),
            c_metadata: artifact.c_metadata.clone(),
            features_json: artifact.features_json.clone(),
            target: artifact.target.clone(),
            rustc_version: artifact.rustc_version.clone(),
            oci_reference: oci_reference(&key),
            kind: artifact.kind.clone(),
            is_proc_macro: artifact.is_proc_macro,
            artifact_size: artifact.artifact_size,
            rlib_sha256: hash_optional_file(artifact.rlib_path.as_ref()).await?,
            rmeta_sha256: hash_optional_file(artifact.rmeta_path.as_ref()).await?,
            proc_macro_sha256: hash_optional_file(artifact.proc_macro_path.as_ref()).await?,
            rlib_path: artifact.rlib_path.clone(),
            rmeta_path: artifact.rmeta_path.clone(),
            proc_macro_path: artifact.proc_macro_path.clone(),
            native: artifact.native.clone(),
        });
    }

    Ok(plans)
}

async fn hash_optional_file(path: Option<&std::path::PathBuf>) -> eyre::Result<Option<String>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = read(path).await?;
    let digest = Sha256::digest(bytes);
    Ok(Some(hex::encode(digest)))
}

fn parse_feature_set(features_json: &str) -> eyre::Result<FeatureSet> {
    let features = serde_json::from_str::<Vec<String>>(features_json)?;
    Ok(FeatureSet(features.into_iter().collect::<BTreeSet<_>>()))
}

fn debug_profile() -> Profile {
    Profile {
        opt_level: "0".to_owned(),
        debuginfo: 2,
        debug_assertions: true,
        overflow_checks: true,
        panic: PanicStrategy::Unwind,
    }
}

async fn rustc_version_verbose() -> eyre::Result<RustcVersion> {
    let output = Command::new("rustc")
        .arg("--version")
        .arg("--verbose")
        .output()
        .await?;

    if !output.status.success() {
        return Err(eyre::eyre!(
            "rustc --version --verbose failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8(output.stdout)?;
    let mut release = None;
    let mut commit_hash = None;
    let mut llvm_version = None;

    for line in stdout.lines() {
        if let Some(value) = line.strip_prefix("release: ") {
            release = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("commit-hash: ") {
            commit_hash = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("LLVM version: ") {
            llvm_version = Some(value.trim().to_owned());
        }
    }

    Ok(RustcVersion {
        version: semver::Version::parse(
            release
                .as_deref()
                .ok_or_else(|| eyre::eyre!("rustc verbose output missing release"))?,
        )?,
        commit_hash: commit_hash
            .ok_or_else(|| eyre::eyre!("rustc verbose output missing commit-hash"))?,
        llvm_version: llvm_version
            .ok_or_else(|| eyre::eyre!("rustc verbose output missing LLVM version"))?,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PlannedArtifact {
    pub crate_name: String,
    pub crate_version: String,
    pub c_metadata: String,
    pub features_json: String,
    pub target: String,
    pub rustc_version: String,
    pub oci_reference: String,
    pub kind: ArtifactKind,
    pub is_proc_macro: bool,
    pub artifact_size: u64,
    pub rlib_sha256: Option<String>,
    pub rmeta_sha256: Option<String>,
    pub proc_macro_sha256: Option<String>,
    pub rlib_path: Option<PathBuf>,
    pub rmeta_path: Option<PathBuf>,
    pub proc_macro_path: Option<PathBuf>,
    pub native: Option<stow_types::artifact::NativeArtifacts>,
}
