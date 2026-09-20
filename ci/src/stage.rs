//! The hand-off between the untrusted build job and the trusted publish job.
//!
//! `stow-build build` runs third-party code and must never see a publish
//! credential, so it leaves everything the publisher needs in one directory
//! that the workflow carries across the job boundary as an artifact:
//!
//! ```text
//! <dir>/task.json          the BuildTaskPayload the builder was given
//! <dir>/scan.json          scanned artifacts, for diagnostics only
//! <dir>/upload-plan.json   Vec<PlannedArtifact>, output paths relative to <dir>
//! <dir>/blobs/<sha256>     every planned output and native archive, content-addressed
//! ```
//!
//! Everything in it is attacker-influenced. The publisher re-derives each
//! blob's digest and compares the task against its own copy before it
//! believes any of it.

use std::path::{Component, Path, PathBuf};

use async_fs::{copy, create_dir_all, read, read_to_string, write};
use sha2::{Digest, Sha256};
use stow_types::api::BuildTaskPayload;
use stow_types::error::Context;
use stow_types::upload_plan::{PlannedArtifact, PlannedArtifactOutput};

use crate::dep_scan::ScanReport;

const TASK_FILE: &str = "task.json";
const SCAN_FILE: &str = "scan.json";
const PLAN_FILE: &str = "upload-plan.json";
const BLOBS_DIR: &str = "blobs";

/// A build job's output, read back with every path made absolute and every
/// blob digest re-derived.
#[derive(Debug)]
pub struct BuildOutput {
    pub task: BuildTaskPayload,
    pub plan: Vec<PlannedArtifact>,
}

/// Write the build job's output directory. Planned output paths are rewritten
/// to `blobs/<sha256>` relative to `dir`, so the plan is self-contained.
pub async fn write_build_output(
    dir: &Path,
    task: &BuildTaskPayload,
    scanned: &ScanReport,
    plan: &[PlannedArtifact],
) -> stow_types::error::Result<()> {
    let blobs_dir = dir.join(BLOBS_DIR);
    create_dir_all(&blobs_dir)
        .await
        .wrap_err_with(|| format!("create build output blobs dir {}", blobs_dir.display()))?;

    let mut relocated = Vec::with_capacity(plan.len());
    for artifact in plan {
        let mut artifact = artifact.clone();
        for output in artifact
            .outputs
            .iter_mut()
            .chain(artifact.native_archive.as_mut())
        {
            let blob_name = blob_name(output)?;
            let destination = blobs_dir.join(&blob_name);
            copy(&output.path, &destination).await.wrap_err_with(|| {
                format!(
                    "copy planned output {} to {}",
                    output.path.display(),
                    destination.display()
                )
            })?;
            // Written with a forward slash so the plan reads the same on every
            // platform; `Path` equality on the read side compares components,
            // not separators.
            output.path = PathBuf::from(format!("{BLOBS_DIR}/{blob_name}"));
        }
        relocated.push(artifact);
    }

    write(dir.join(TASK_FILE), serde_json::to_vec_pretty(task)?).await?;
    write(dir.join(SCAN_FILE), serde_json::to_vec_pretty(scanned)?).await?;
    write(dir.join(PLAN_FILE), serde_json::to_vec_pretty(&relocated)?).await?;
    tracing::info!(
        output_dir = %dir.display(),
        artifacts = relocated.len(),
        "wrote build output"
    );
    Ok(())
}

/// Read a build output directory back. Every planned output path must be a
/// single `blobs/<sha256>` component pair, and the blob's bytes must hash to
/// both that name and the digest the plan records for it.
pub async fn read_build_output(dir: &Path) -> stow_types::error::Result<BuildOutput> {
    let task_json = read_to_string(dir.join(TASK_FILE))
        .await
        .wrap_err_with(|| format!("read {} from {}", TASK_FILE, dir.display()))?;
    let task: BuildTaskPayload =
        serde_json::from_str(&task_json).wrap_err_with(|| format!("parse {TASK_FILE}"))?;
    let plan_json = read_to_string(dir.join(PLAN_FILE))
        .await
        .wrap_err_with(|| format!("read {} from {}", PLAN_FILE, dir.display()))?;
    let mut plan: Vec<PlannedArtifact> =
        serde_json::from_str(&plan_json).wrap_err_with(|| format!("parse {PLAN_FILE}"))?;

    for artifact in &mut plan {
        for output in artifact
            .outputs
            .iter_mut()
            .chain(artifact.native_archive.as_mut())
        {
            let relative = output.path.clone();
            let expected_name = blob_name(output)?;
            if relative != PathBuf::from(BLOBS_DIR).join(&expected_name) {
                return Err(stow_types::stow_error!(
                    "planned output {} for {} is not the content-addressed blob path {}/{}",
                    relative.display(),
                    artifact.oci_reference,
                    BLOBS_DIR,
                    expected_name
                ));
            }
            let absolute = dir.join(&relative);
            let bytes = read(&absolute)
                .await
                .wrap_err_with(|| format!("read build output blob {}", absolute.display()))?;
            let actual = hex::encode(Sha256::digest(&bytes));
            if actual != output.bundle_file.sha256 {
                return Err(stow_types::stow_error!(
                    "build output blob {} hashes to {actual}, but the plan records {} for {}",
                    absolute.display(),
                    output.bundle_file.sha256,
                    output.bundle_file.file_name
                ));
            }
            output.path = absolute;
        }
    }

    Ok(BuildOutput { task, plan })
}

fn blob_name(output: &PlannedArtifactOutput) -> stow_types::error::Result<String> {
    let digest = &output.bundle_file.sha256;
    let well_formed = digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit());
    if !well_formed {
        return Err(stow_types::stow_error!(
            "planned output {} carries a malformed sha256 {digest:?}",
            output.bundle_file.file_name
        ));
    }
    let single_component = Path::new(digest)
        .components()
        .all(|component| matches!(component, Component::Normal(_)));
    if !single_component {
        return Err(stow_types::stow_error!(
            "planned output {} carries a sha256 that is not a plain path component",
            output.bundle_file.file_name
        ));
    }
    Ok(digest.clone())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use sha2::{Digest, Sha256};
    use stow_types::api::BuildTaskPayload;
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::bundle::{
        ArtifactBundleFile, STOW_NATIVE_ARCHIVE_MEDIA_TYPE, STOW_RLIB_MEDIA_TYPE,
    };
    use stow_types::identity::{
        CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, FeaturesJson, TargetTriple,
        WireRustcVersion,
    };
    use stow_types::platform::{PanicStrategy, Profile};
    use stow_types::upload_plan::{PlannedArtifact, PlannedArtifactOutput};

    use super::{read_build_output, write_build_output};
    use crate::dep_scan::ScanReport;

    const EMPTY_SCAN: ScanReport = ScanReport {
        restorable_captures: 0,
        artifacts: Vec::new(),
    };

    fn task() -> BuildTaskPayload {
        BuildTaskPayload {
            task_id: "task".to_owned(),
            attempt: 1,
            crate_name: CrateName::parse("demo").unwrap(),
            version: CrateVersion::new(semver::Version::new(1, 0, 0)),
            features_json: FeaturesJson::default(),
            target: TargetTriple::parse("x86_64-unknown-linux-gnu").unwrap(),
            rustc_version: WireRustcVersion::parse("1.91.1").unwrap(),
            preserve_lockfile: false,
            project_source: None,
        }
    }

    fn planned(path: PathBuf, bytes: &[u8]) -> PlannedArtifact {
        PlannedArtifact {
            compile_key: "0".repeat(64),
            crate_name: CrateName::parse("demo").unwrap(),
            crate_version: CrateVersion::new(semver::Version::new(1, 0, 0)),
            c_metadata: CMetadata::parse("0123456789abcdef").unwrap(),
            extra_filename: "-0123456789abcdef".to_owned(),
            features_json: FeaturesJson::default(),
            dependency_c_metadata_json: DependencyCMetadataJson::default(),
            dependency_compile_keys_json: "[]".to_owned(),
            target: TargetTriple::parse("x86_64-unknown-linux-gnu").unwrap(),
            rustc_version: WireRustcVersion::parse("1.91.1").unwrap(),
            profile: Profile {
                opt_level: "0".to_owned(),
                debuginfo: 0,
                debug_assertions: true,
                overflow_checks: true,
                panic: PanicStrategy::Unwind,
                strip: stow_types::platform::StripLevel::None,
            },
            emit: vec!["link".to_owned()],
            oci_reference: "ghcr.io/water-rs/stow-cache:demo.test".to_owned(),
            kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Lib],
            artifact_size: bytes.len() as u64,
            compile_millis: 0,
            outputs: vec![PlannedArtifactOutput {
                path,
                bundle_file: ArtifactBundleFile {
                    file_name: "libdemo.rlib".to_owned(),
                    media_type: STOW_RLIB_MEDIA_TYPE.to_owned(),
                    sha256: hex::encode(Sha256::digest(bytes)),
                },
            }],
            native: None,
            native_archive: None,
        }
    }

    #[tokio::test]
    async fn round_trips_blobs_content_addressed() {
        let source = tempfile::tempdir().unwrap();
        let output_dir = tempfile::tempdir().unwrap();
        let rlib = source.path().join("libdemo.rlib");
        std::fs::write(&rlib, b"rlib bytes").unwrap();
        let plan = vec![planned(rlib, b"rlib bytes")];

        write_build_output(output_dir.path(), &task(), &EMPTY_SCAN, &plan)
            .await
            .unwrap();
        let output = read_build_output(output_dir.path()).await.unwrap();

        assert_eq!(output.task, task());
        let path = &output.plan[0].outputs[0].path;
        assert!(path.is_absolute());
        assert!(path.starts_with(output_dir.path().join("blobs")));
        assert_eq!(std::fs::read(path).unwrap(), b"rlib bytes");
    }

    #[tokio::test]
    async fn scan_json_records_received_and_planned_capture_counts() {
        // The completeness evidence a reviewer reads back: how many
        // restorable records the collector delivered versus how many
        // artifacts the scan planned.
        let output_dir = tempfile::tempdir().unwrap();
        let report = ScanReport {
            restorable_captures: 7,
            artifacts: Vec::new(),
        };

        write_build_output(output_dir.path(), &task(), &report, &[])
            .await
            .unwrap();

        let scan: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(output_dir.path().join("scan.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(scan["restorable_captures"], 7);
        assert_eq!(scan["artifacts"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn rejects_blob_whose_bytes_do_not_match_the_plan() {
        let source = tempfile::tempdir().unwrap();
        let output_dir = tempfile::tempdir().unwrap();
        let rlib = source.path().join("libdemo.rlib");
        std::fs::write(&rlib, b"rlib bytes").unwrap();
        let plan = vec![planned(rlib, b"rlib bytes")];
        write_build_output(output_dir.path(), &task(), &EMPTY_SCAN, &plan)
            .await
            .unwrap();
        let blob = output_dir
            .path()
            .join("blobs")
            .join(hex::encode(Sha256::digest(b"rlib bytes")));
        std::fs::write(&blob, b"tampered").unwrap();

        let error = read_build_output(output_dir.path()).await.unwrap_err();
        assert!(error.to_string().contains("hashes to"), "{error}");
    }

    #[tokio::test]
    async fn native_archive_is_content_addressed_like_every_output() {
        let source = tempfile::tempdir().unwrap();
        let output_dir = tempfile::tempdir().unwrap();
        let rlib = source.path().join("libdemo.rlib");
        std::fs::write(&rlib, b"rlib bytes").unwrap();
        let archive = source.path().join("native.tar");
        std::fs::write(&archive, b"archive bytes").unwrap();
        let mut artifact = planned(rlib, b"rlib bytes");
        artifact.native_archive = Some(PlannedArtifactOutput {
            path: archive,
            bundle_file: ArtifactBundleFile {
                file_name: "native.tar".to_owned(),
                media_type: STOW_NATIVE_ARCHIVE_MEDIA_TYPE.to_owned(),
                sha256: hex::encode(Sha256::digest(b"archive bytes")),
            },
        });
        write_build_output(output_dir.path(), &task(), &EMPTY_SCAN, &[artifact])
            .await
            .unwrap();

        let output = read_build_output(output_dir.path()).await.unwrap();
        let archive_path = &output.plan[0].native_archive.as_ref().unwrap().path;
        assert!(archive_path.starts_with(output_dir.path().join("blobs")));
        assert_eq!(std::fs::read(archive_path).unwrap(), b"archive bytes");

        std::fs::write(archive_path, b"tampered").unwrap();
        let error = read_build_output(output_dir.path()).await.unwrap_err();
        assert!(error.to_string().contains("hashes to"), "{error}");
    }

    #[tokio::test]
    async fn rejects_plan_path_outside_blobs() {
        let source = tempfile::tempdir().unwrap();
        let output_dir = tempfile::tempdir().unwrap();
        let rlib = source.path().join("libdemo.rlib");
        std::fs::write(&rlib, b"rlib bytes").unwrap();
        let plan = vec![planned(rlib, b"rlib bytes")];
        write_build_output(output_dir.path(), &task(), &EMPTY_SCAN, &plan)
            .await
            .unwrap();
        let plan_path = output_dir.path().join("upload-plan.json");
        let rewritten = std::fs::read_to_string(&plan_path)
            .unwrap()
            .replace("blobs/", "../");
        assert!(
            rewritten.contains("../"),
            "plan path must be written with a forward slash"
        );
        std::fs::write(&plan_path, rewritten).unwrap();

        let error = read_build_output(output_dir.path()).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not the content-addressed blob path"),
            "{error}"
        );
    }
}
