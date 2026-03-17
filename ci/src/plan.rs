use std::collections::BTreeSet;
use std::path::PathBuf;

use async_process::Command;
use sha2::{Digest, Sha256};
use stow_types::artifact::{ArtifactKey, ArtifactKind};
use stow_types::bundle::{
    ArtifactBundleFile, STOW_DYLIB_MEDIA_TYPE, STOW_PROC_MACRO_MEDIA_TYPE, STOW_RLIB_MEDIA_TYPE,
    STOW_RMETA_MEDIA_TYPE,
};
use stow_types::crate_info::{CrateId, FeatureSet};
use stow_types::platform::{PanicStrategy, Profile, RustcVersion, Target};
use stow_types::registry::oci_reference;
use stow_types::upload_plan::{PlannedArtifact, PlannedArtifactOutput};

use crate::dep_scan::{ParsedFileKind, ScannedArtifact, ScannedArtifactOutput};

pub(crate) async fn build_upload_plan(
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
            crate_types: artifact.crate_types.clone(),
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
            oci_reference: oci_reference(&key, &artifact.c_metadata),
            kind: artifact.kind.clone(),
            crate_types: artifact.crate_types.clone(),
            artifact_size: artifact.artifact_size,
            outputs: build_outputs(&artifact.outputs, &artifact.kind).await?,
            native: artifact.native.clone(),
        });
    }

    Ok(plans)
}

async fn build_outputs(
    outputs: &[ScannedArtifactOutput],
    artifact_kind: &ArtifactKind,
) -> eyre::Result<Vec<PlannedArtifactOutput>> {
    let mut planned = Vec::with_capacity(outputs.len());
    for output in outputs {
        let bytes = async_fs::read(&output.path).await?;
        let digest = hex::encode(Sha256::digest(&bytes));
        planned.push(PlannedArtifactOutput {
            path: output.path.clone(),
            bundle_file: ArtifactBundleFile {
                file_name: file_name(&output.path)?,
                media_type: output_media_type(output.kind, artifact_kind)?.to_owned(),
                sha256: digest,
            },
        });
    }
    Ok(planned)
}

fn file_name(path: &PathBuf) -> eyre::Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            eyre::eyre!(
                "artifact path {} is missing a UTF-8 file name",
                path.display()
            )
        })
}

fn output_media_type(
    output_kind: ParsedFileKind,
    artifact_kind: &ArtifactKind,
) -> eyre::Result<&'static str> {
    match output_kind {
        ParsedFileKind::Rlib => Ok(STOW_RLIB_MEDIA_TYPE),
        ParsedFileKind::Rmeta => Ok(STOW_RMETA_MEDIA_TYPE),
        ParsedFileKind::DynamicLibrary => match artifact_kind {
            ArtifactKind::ProcMacro => Ok(STOW_PROC_MACRO_MEDIA_TYPE),
            ArtifactKind::Dylib | ArtifactKind::Rlib => Ok(STOW_DYLIB_MEDIA_TYPE),
        },
    }
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
