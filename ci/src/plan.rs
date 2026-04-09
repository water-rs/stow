use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use sha2::{Digest, Sha256};
use stow_types::artifact::{ArtifactKey, ArtifactKind};
use stow_types::bundle::{
    ArtifactBundleFile, STOW_DYLIB_MEDIA_TYPE, STOW_PROC_MACRO_MEDIA_TYPE, STOW_RLIB_MEDIA_TYPE,
    STOW_RMETA_MEDIA_TYPE,
};
use stow_types::crate_info::{CrateId, FeatureSet};
use stow_types::platform::{RustcVersion, Target};
use stow_types::registry::oci_reference;
use stow_types::upload_plan::{PlannedArtifact, PlannedArtifactOutput};

use crate::dep_scan::{
    ParsedFileKind, ScannedArtifact, ScannedArtifactDependency, ScannedArtifactOutput,
};

pub(crate) async fn build_upload_plan(
    scanned: &[ScannedArtifact],
) -> eyre::Result<Vec<PlannedArtifact>> {
    validate_dependency_graph(scanned)?;
    let mut plans_by_compile_key = BTreeMap::<(String, String, String), PlannedArtifact>::new();

    for artifact in scanned {
        let key = ArtifactKey {
            crate_id: CrateId {
                name: artifact.crate_name.clone(),
                version: semver::Version::parse(&artifact.crate_version)?,
            },
            features: parse_feature_set(&artifact.features_json)?,
            crate_types: artifact.crate_types.clone(),
            target: Target(artifact.target.clone()),
            rustc_version: parse_rustc_version(&artifact.rustc_version)?,
            profile: artifact.profile.clone(),
            kind: artifact.kind.clone(),
        };

        let plan = PlannedArtifact {
            compile_key: artifact.captured_compile_key.clone(),
            crate_name: artifact.crate_name.clone(),
            crate_version: artifact.crate_version.clone(),
            c_metadata: artifact.c_metadata.clone(),
            extra_filename: artifact.extra_filename.clone(),
            features_json: artifact.features_json.clone(),
            dependency_c_metadata_json: dependency_c_metadata_json(&artifact.dependencies)?,
            dependency_compile_keys_json: dependency_compile_keys_json(&artifact.dependencies)?,
            target: artifact.target.clone(),
            rustc_version: artifact.rustc_version.clone(),
            profile: artifact.profile.clone(),
            emit: artifact.emit.clone(),
            oci_reference: oci_reference(&key, &artifact.c_metadata),
            kind: artifact.kind.clone(),
            crate_types: artifact.crate_types.clone(),
            artifact_size: artifact.artifact_size,
            outputs: build_outputs(&artifact.outputs, &artifact.kind).await?,
            native: artifact.native.clone(),
        };
        let dedup_key = (
            plan.compile_key.clone(),
            plan.target.clone(),
            plan.rustc_version.clone(),
        );
        if let Some(existing) = plans_by_compile_key.get_mut(&dedup_key) {
            reconcile_duplicate_plan(existing, plan)?;
        } else {
            plans_by_compile_key.insert(dedup_key, plan);
        }
    }

    Ok(plans_by_compile_key.into_values().collect())
}

fn validate_dependency_graph(scanned: &[ScannedArtifact]) -> eyre::Result<()> {
    let mut output_owner_by_path = BTreeMap::<PathBuf, usize>::new();
    let mut output_owner_by_compile_key = BTreeMap::<String, usize>::new();
    for (index, artifact) in scanned.iter().enumerate() {
        if let Some(existing) =
            output_owner_by_compile_key.insert(artifact.captured_compile_key.clone(), index)
            && existing != index
        {
            ensure_reconcilable_duplicate_compile_key(&scanned[existing], artifact)?;
        }
        for output in &artifact.outputs {
            if let Some(existing) = output_owner_by_path.insert(output.path.clone(), index)
                && existing != index
            {
                return Err(eyre::eyre!(
                    "output path {} is claimed by both {} and {}",
                    output.path.display(),
                    scanned[existing].crate_name,
                    artifact.crate_name
                ));
            }
        }
    }

    for artifact in scanned {
        for dependency in &artifact.dependencies {
            if output_owner_by_path.contains_key(&dependency.path)
                || output_owner_by_compile_key.contains_key(&dependency.compile_key)
            {
                continue;
            }
            return Err(eyre::eyre!(
                "dependency {} at {} with compile key {} is not produced by any scanned artifact",
                dependency.crate_name,
                dependency.path.display(),
                dependency.compile_key
            ));
        }
    }

    Ok(())
}

fn ensure_reconcilable_duplicate_compile_key(
    existing: &ScannedArtifact,
    candidate: &ScannedArtifact,
) -> eyre::Result<()> {
    if existing.crate_name != candidate.crate_name
        || existing.crate_version != candidate.crate_version
        || existing.captured_compile_key != candidate.captured_compile_key
        || existing.c_metadata != candidate.c_metadata
        || existing.extra_filename != candidate.extra_filename
        || existing.features_json != candidate.features_json
        || dependency_c_metadata_json(&existing.dependencies)?
            != dependency_c_metadata_json(&candidate.dependencies)?
        || dependency_compile_keys_json(&existing.dependencies)?
            != dependency_compile_keys_json(&candidate.dependencies)?
        || existing.target != candidate.target
        || existing.rustc_version != candidate.rustc_version
        || existing.profile != candidate.profile
        || existing.emit != candidate.emit
        || existing.kind != candidate.kind
        || existing.crate_types != candidate.crate_types
    {
        return Err(eyre::eyre!(
            "captured compile key {} is claimed by incompatible artifacts {} and {}",
            existing.captured_compile_key,
            existing.crate_name,
            candidate.crate_name
        ));
    }
    Ok(())
}

fn dependency_c_metadata_json(dependencies: &[ScannedArtifactDependency]) -> eyre::Result<String> {
    let mut dependency_identities = dependencies
        .iter()
        .map(|dependency| DependencyIdentityRecord {
            crate_name: dependency.crate_name.clone(),
            value: dependency.stable_c_metadata.clone(),
        })
        .collect::<Vec<_>>();
    dependency_identities.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.value.cmp(&right.value))
    });
    serde_json::to_string(&dependency_identities).map_err(Into::into)
}

fn dependency_compile_keys_json(
    dependencies: &[ScannedArtifactDependency],
) -> eyre::Result<String> {
    let mut dependency_identities = dependencies
        .iter()
        .map(|dependency| DependencyIdentityRecord {
            crate_name: dependency.crate_name.clone(),
            value: dependency.compile_key.clone(),
        })
        .collect::<Vec<_>>();
    dependency_identities.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.value.cmp(&right.value))
    });
    serde_json::to_string(&dependency_identities).map_err(Into::into)
}

#[derive(Debug, Clone, serde::Serialize)]
struct DependencyIdentityRecord {
    crate_name: String,
    #[serde(rename = "c_metadata")]
    value: String,
}

fn reconcile_duplicate_plan(
    existing: &mut PlannedArtifact,
    candidate: PlannedArtifact,
) -> eyre::Result<()> {
    ensure_duplicate_plan_identity(existing, &candidate)?;

    match plan_preference(existing).cmp(&plan_preference(&candidate)) {
        Ordering::Less => {
            *existing = candidate;
            Ok(())
        }
        Ordering::Greater => Ok(()),
        Ordering::Equal if plans_share_outputs(existing, &candidate) => Ok(()),
        Ordering::Equal => Err(eyre::eyre!(
            "duplicate upload plan artifact {} {} {} remained ambiguous after stable exact identity normalization",
            existing.crate_name,
            existing.target,
            existing.c_metadata
        )),
    }
}

fn ensure_duplicate_plan_identity(
    existing: &PlannedArtifact,
    candidate: &PlannedArtifact,
) -> eyre::Result<()> {
    if existing.compile_key != candidate.compile_key
        || existing.crate_name != candidate.crate_name
        || existing.crate_version != candidate.crate_version
        || existing.c_metadata != candidate.c_metadata
        || existing.extra_filename != candidate.extra_filename
        || existing.features_json != candidate.features_json
        || existing.dependency_c_metadata_json != candidate.dependency_c_metadata_json
        || existing.dependency_compile_keys_json != candidate.dependency_compile_keys_json
        || existing.target != candidate.target
        || existing.rustc_version != candidate.rustc_version
        || existing.profile != candidate.profile
        || existing.emit != candidate.emit
        || existing.oci_reference != candidate.oci_reference
        || existing.kind != candidate.kind
        || existing.crate_types != candidate.crate_types
        || !native_artifacts_match(existing.native.as_ref(), candidate.native.as_ref())
    {
        return Err(eyre::eyre!(
            "duplicate upload plan artifact {} {} {} had inconsistent metadata",
            existing.crate_name,
            existing.target,
            existing.c_metadata
        ));
    }
    Ok(())
}

fn plan_preference(plan: &PlannedArtifact) -> (usize, usize) {
    (
        stable_filename_matches(plan),
        requested_target_output_matches(plan),
    )
}

fn stable_filename_matches(plan: &PlannedArtifact) -> usize {
    plan.outputs
        .iter()
        .filter(|output| output.bundle_file.file_name.contains(&plan.extra_filename))
        .count()
}

fn requested_target_output_matches(plan: &PlannedArtifact) -> usize {
    let needle = format!("/{}/", plan.target);
    plan.outputs
        .iter()
        .filter(|output| output.path.to_string_lossy().contains(&needle))
        .count()
}

fn plans_share_outputs(left: &PlannedArtifact, right: &PlannedArtifact) -> bool {
    left.artifact_size == right.artifact_size
        && left.outputs.len() == right.outputs.len()
        && left
            .outputs
            .iter()
            .zip(&right.outputs)
            .all(|(left_output, right_output)| {
                bundle_files_match(&left_output.bundle_file, &right_output.bundle_file)
                    && left_output.path == right_output.path
            })
}

fn native_artifacts_match(
    left: Option<&stow_types::artifact::NativeArtifacts>,
    right: Option<&stow_types::artifact::NativeArtifacts>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            serde_json::to_string(left).ok() == serde_json::to_string(right).ok()
        }
        _ => false,
    }
}

fn bundle_files_match(left: &ArtifactBundleFile, right: &ArtifactBundleFile) -> bool {
    left.file_name == right.file_name
        && left.media_type == right.media_type
        && left.sha256 == right.sha256
}

async fn build_outputs(
    outputs: &[ScannedArtifactOutput],
    artifact_kind: &ArtifactKind,
) -> eyre::Result<Vec<PlannedArtifactOutput>> {
    let mut planned = Vec::with_capacity(outputs.len());
    let mut seen_file_names = BTreeSet::new();
    for output in outputs {
        let file_name = file_name(&output.path)?;
        if !seen_file_names.insert(file_name.clone()) {
            return Err(eyre::eyre!(
                "upload plan would contain duplicate bundled output file {}",
                file_name
            ));
        }
        let bytes = async_fs::read(&output.path).await?;
        let digest = hex::encode(Sha256::digest(&bytes));
        planned.push(PlannedArtifactOutput {
            path: output.path.clone(),
            bundle_file: ArtifactBundleFile {
                file_name,
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
fn parse_rustc_version(raw: &str) -> eyre::Result<RustcVersion> {
    let version = semver::Version::parse(raw)
        .map_err(|error| eyre::eyre!("invalid rustc version '{raw}': {error}"))?;
    Ok(RustcVersion {
        version,
        commit_hash: "unknown".to_owned(),
        llvm_version: "unknown".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::build_upload_plan;
    use crate::dep_scan::{
        ParsedFileKind, ScannedArtifact, ScannedArtifactDependency, ScannedArtifactOutput,
    };
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::platform::{PanicStrategy, Profile};

    #[tokio::test]
    async fn upload_plan_preserves_captured_exact_identity() {
        let output_path = std::env::temp_dir().join(format!(
            "stow-ci-plan-test-{}-libserde-original.rlib",
            std::process::id()
        ));
        fs::write(&output_path, b"serde-test-artifact").expect("write artifact bytes");
        let scanned = vec![ScannedArtifact {
            crate_name: "serde".to_owned(),
            crate_version: "1.0.228".to_owned(),
            target: "aarch64-apple-darwin".to_owned(),
            rustc_version: "1.91.1".to_owned(),
            captured_compile_key: "original-compile-key".to_owned(),
            c_metadata: "originalmetadata".to_owned(),
            extra_filename: "-originalextra".to_owned(),
            profile: Profile {
                opt_level: "0".to_owned(),
                debuginfo: 1,
                debug_assertions: true,
                overflow_checks: true,
                panic: PanicStrategy::Unwind,
            },
            emit: vec![
                "dep-info".to_owned(),
                "link".to_owned(),
                "metadata".to_owned(),
            ],
            features_json: "[\"default\",\"derive\",\"serde_derive\",\"std\"]".to_owned(),
            dependencies: Vec::new(),
            artifact_size: 123,
            kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Lib],
            outputs: vec![ScannedArtifactOutput {
                kind: ParsedFileKind::Rlib,
                path: output_path.clone(),
            }],
            native: None,
        }];

        let planned = build_upload_plan(&scanned)
            .await
            .expect("build upload plan");
        let plan = planned.first().expect("planned artifact");

        assert_eq!(plan.compile_key, "original-compile-key");
        assert_eq!(plan.c_metadata, "originalmetadata");
        assert_eq!(plan.extra_filename, "-originalextra");
        assert!(
            plan.oci_reference.ends_with("-originalmetadata"),
            "unexpected oci reference {}",
            plan.oci_reference
        );
        fs::remove_file(output_path).expect("remove artifact bytes");
    }

    #[tokio::test]
    async fn upload_plan_preserves_distinct_captured_identities() {
        let stable_output_path = std::env::temp_dir().join(format!(
            "stow-ci-plan-test-{}-libbitflags-dba7ec857b47436d.rlib",
            std::process::id()
        ));
        let unstable_output_path = std::env::temp_dir().join(format!(
            "stow-ci-plan-test-{}-libbitflags-7a82cf810369bb9d.rlib",
            std::process::id()
        ));
        fs::write(&stable_output_path, b"bitflags-stable").expect("write stable artifact bytes");
        fs::write(&unstable_output_path, b"bitflags-unstable")
            .expect("write unstable artifact bytes");

        let scanned = vec![
            scanned_bitflags_artifact("7a82cf810369bb9d", unstable_output_path.clone(), 17),
            scanned_bitflags_artifact("dba7ec857b47436d", stable_output_path.clone(), 29),
        ];

        let planned = build_upload_plan(&scanned)
            .await
            .expect("build upload plan");

        assert_eq!(planned.len(), 2);
        assert!(planned.iter().any(|plan| {
            plan.compile_key == "captured-7a82cf810369bb9d" && plan.c_metadata == "7a82cf810369bb9d"
        }));
        assert!(planned.iter().any(|plan| {
            plan.compile_key == "captured-dba7ec857b47436d" && plan.c_metadata == "dba7ec857b47436d"
        }));

        fs::remove_file(stable_output_path).expect("remove stable artifact bytes");
        fs::remove_file(unstable_output_path).expect("remove unstable artifact bytes");
    }

    fn scanned_bitflags_artifact(
        original_c_metadata: &str,
        output_path: std::path::PathBuf,
        artifact_size: u64,
    ) -> ScannedArtifact {
        ScannedArtifact {
            crate_name: "bitflags".to_owned(),
            crate_version: "2.11.0".to_owned(),
            target: "aarch64-apple-darwin".to_owned(),
            rustc_version: "1.91.1".to_owned(),
            captured_compile_key: format!("captured-{original_c_metadata}"),
            c_metadata: original_c_metadata.to_owned(),
            extra_filename: format!("-{original_c_metadata}"),
            profile: Profile {
                opt_level: "0".to_owned(),
                debuginfo: 1,
                debug_assertions: true,
                overflow_checks: true,
                panic: PanicStrategy::Unwind,
            },
            emit: vec![
                "dep-info".to_owned(),
                "link".to_owned(),
                "metadata".to_owned(),
            ],
            features_json: "[\"std\"]".to_owned(),
            dependencies: Vec::new(),
            artifact_size,
            kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Lib],
            outputs: vec![ScannedArtifactOutput {
                kind: ParsedFileKind::Rlib,
                path: output_path,
            }],
            native: None,
        }
    }

    #[tokio::test]
    async fn upload_plan_preserves_scanned_dependency_identities() {
        let child_output_path = std::env::temp_dir().join(format!(
            "stow-ci-plan-test-{}-libgetrandom-2384b9107b13ade1.rlib",
            std::process::id()
        ));
        let parent_output_path = std::env::temp_dir().join(format!(
            "stow-ci-plan-test-{}-librand_core-d85bb459550a6063.rlib",
            std::process::id()
        ));
        fs::write(&child_output_path, b"getrandom-artifact").expect("write child artifact");
        fs::write(&parent_output_path, b"rand-core-artifact").expect("write parent artifact");

        let scanned = vec![
            ScannedArtifact {
                crate_name: "getrandom".to_owned(),
                crate_version: "0.2.17".to_owned(),
                target: "aarch64-apple-darwin".to_owned(),
                rustc_version: "1.91.1".to_owned(),
                captured_compile_key: "captured-getrandom".to_owned(),
                c_metadata: "2384b9107b13ade1".to_owned(),
                extra_filename: "-2384b9107b13ade1".to_owned(),
                profile: Profile {
                    opt_level: "0".to_owned(),
                    debuginfo: 1,
                    debug_assertions: true,
                    overflow_checks: true,
                    panic: PanicStrategy::Unwind,
                },
                emit: vec![
                    "dep-info".to_owned(),
                    "link".to_owned(),
                    "metadata".to_owned(),
                ],
                features_json: "[]".to_owned(),
                dependencies: Vec::new(),
                artifact_size: 17,
                kind: ArtifactKind::Rlib,
                crate_types: vec![RustCrateType::Lib],
                outputs: vec![ScannedArtifactOutput {
                    kind: ParsedFileKind::Rlib,
                    path: child_output_path.clone(),
                }],
                native: None,
            },
            ScannedArtifact {
                crate_name: "rand_core".to_owned(),
                crate_version: "0.6.4".to_owned(),
                target: "aarch64-apple-darwin".to_owned(),
                rustc_version: "1.91.1".to_owned(),
                captured_compile_key: "captured-rand-core".to_owned(),
                c_metadata: "d85bb459550a6063".to_owned(),
                extra_filename: "-d85bb459550a6063".to_owned(),
                profile: Profile {
                    opt_level: "0".to_owned(),
                    debuginfo: 1,
                    debug_assertions: true,
                    overflow_checks: true,
                    panic: PanicStrategy::Unwind,
                },
                emit: vec![
                    "dep-info".to_owned(),
                    "link".to_owned(),
                    "metadata".to_owned(),
                ],
                features_json: "[]".to_owned(),
                dependencies: vec![ScannedArtifactDependency {
                    crate_name: "getrandom".to_owned(),
                    path: child_output_path.clone(),
                    compile_key: "captured-getrandom".to_owned(),
                    stable_c_metadata: "captured-getrandom".to_owned(),
                }],
                artifact_size: 18,
                kind: ArtifactKind::Rlib,
                crate_types: vec![RustCrateType::Lib],
                outputs: vec![ScannedArtifactOutput {
                    kind: ParsedFileKind::Rlib,
                    path: parent_output_path.clone(),
                }],
                native: None,
            },
        ];

        let planned = build_upload_plan(&scanned)
            .await
            .expect("build upload plan");
        let rand_core = planned
            .iter()
            .find(|plan| plan.crate_name == "rand_core")
            .expect("rand_core plan");
        let getrandom = planned
            .iter()
            .find(|plan| plan.crate_name == "getrandom")
            .expect("getrandom plan");

        assert_eq!(
            rand_core.dependency_c_metadata_json,
            "[{\"crate_name\":\"getrandom\",\"c_metadata\":\"captured-getrandom\"}]"
        );
        assert_eq!(
            rand_core.dependency_compile_keys_json,
            "[{\"crate_name\":\"getrandom\",\"c_metadata\":\"captured-getrandom\"}]"
        );
        assert_eq!(getrandom.c_metadata, "2384b9107b13ade1");

        fs::remove_file(child_output_path).expect("remove child artifact bytes");
        fs::remove_file(parent_output_path).expect("remove parent artifact bytes");
    }
}
