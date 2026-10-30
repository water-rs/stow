use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use stow_types::artifact::{ArtifactKey, ArtifactKind, RustCrateType};
use stow_types::bundle::{
    ArtifactBundleFile, STOW_DYLIB_MEDIA_TYPE, STOW_PROC_MACRO_MEDIA_TYPE, STOW_RLIB_MEDIA_TYPE,
    STOW_RMETA_MEDIA_TYPE,
};
use stow_types::crate_info::{CrateId, FeatureSet};
use stow_types::error::Context;
use stow_types::identity::{
    CMetadata, CrateName, CrateVersion, DependencyCMetadataIdentity, DependencyCMetadataJson,
    DependencyCompileKeyIdentity, FeaturesJson, TargetTriple, WireRustcVersion,
};
use stow_types::node_profile::NodeProfile;
use stow_types::platform::{Profile, RustcVersion, Target};
use stow_types::public_cache::UnitSide;
use stow_types::registry::oci_reference;
use stow_types::upload_plan::{PlannedArtifact, PlannedArtifactOutput};

use crate::dep_scan::{
    ConsumedArtifact, ParsedFileKind, ScannedArtifact, ScannedArtifactDependency,
    ScannedArtifactOutput,
};
use crate::object_arch::{self, ExpectedArch};

pub async fn build_upload_plan(
    scanned: &[ScannedArtifact],
    consumed: &[ConsumedArtifact],
    dependency_task_ids: &[String],
    node_profile: NodeProfile,
) -> stow_types::error::Result<Vec<PlannedArtifact>> {
    validate_dependency_graph(scanned, consumed)?;
    let mut plans_by_compile_key =
        BTreeMap::<(String, TargetTriple, WireRustcVersion), PlannedArtifact>::new();

    for artifact in scanned {
        let crate_name = CrateName::parse(artifact.crate_name.as_str())
            .map_err(|error| stow_types::stow_error!("ci scanned crate_name: {error}"))?;
        let crate_version_typed =
            CrateVersion::new(semver::Version::parse(&artifact.crate_version)?);
        let target_typed = TargetTriple::parse(artifact.target.as_str())
            .map_err(|error| stow_types::stow_error!("ci scanned target: {error}"))?;
        let rustc_version_typed = WireRustcVersion::parse(artifact.rustc_version.as_str())
            .map_err(|error| stow_types::stow_error!("ci scanned rustc_version: {error}"))?;
        let c_metadata_typed = CMetadata::parse(artifact.c_metadata.as_str())
            .map_err(|error| stow_types::stow_error!("ci scanned c_metadata: {error}"))?;
        let features_json_typed = parse_features_json_value(&artifact.features_json)?;

        let key = artifact_key(
            &artifact.crate_name,
            crate_version_typed.as_semver(),
            &features_json_typed,
            &artifact.crate_types,
            &artifact.target,
            &artifact.rustc_version,
            &artifact.profile,
            &artifact.kind,
        )?;

        // The machine this artifact's objects must be for — the host's
        // for a host-side unit, the task target's for a target-side one
        // — computed only when it has files to check: every output's
        // bytes and every `OUT_DIR` file are refused when a compiler for
        // another machine produced them (stow#708).
        let expected = expected_object_arch(artifact)?;
        let plan = PlannedArtifact {
            dependency_task_ids: dependency_task_ids.to_vec(),
            compile_key: artifact.captured_compile_key.clone(),
            crate_name,
            crate_version: crate_version_typed,
            c_metadata: c_metadata_typed.clone(),
            extra_filename: artifact.extra_filename.clone(),
            features_json: features_json_typed,
            dependency_c_metadata_json: dependency_c_metadata_json(&artifact.dependencies)?,
            dependency_compile_keys_json: dependency_compile_keys_json(&artifact.dependencies)?,
            target: target_typed,
            rustc_version: rustc_version_typed,
            profile: artifact.profile.clone(),
            node_profile,
            emit: artifact.emit.clone(),
            oci_reference: oci_reference(&key, &artifact.c_metadata),
            kind: artifact.kind.clone(),
            crate_types: artifact.crate_types.clone(),
            artifact_size: artifact.artifact_size,
            compile_millis: artifact.compile_millis,
            outputs: build_outputs(&artifact.outputs, &artifact.kind, expected)
                .await
                .wrap_err_with(|| format!("artifact {}", artifact.crate_name))?,
            unit_shape: artifact.unit_shape,
            native: artifact.native.clone(),
            native_archive: build_native_archive(artifact, expected)
                .await
                .wrap_err_with(|| format!("artifact {}", artifact.crate_name))?,
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

fn validate_dependency_graph(
    scanned: &[ScannedArtifact],
    consumed: &[ConsumedArtifact],
) -> stow_types::error::Result<()> {
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
                return Err(stow_types::stow_error!(
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
                // A served dependency is produced by no scanned artifact —
                // the capture wrapper wrote its outputs from the verified
                // bundle. The claim still carries the signed index's
                // identity: match it exactly.
                || consumed.iter().any(|served| {
                    (served.compile_key.as_str(), served.c_metadata.as_str())
                        == (
                            dependency.compile_key.as_str(),
                            dependency.stable_c_metadata.as_str(),
                        )
                })
            {
                continue;
            }
            return Err(stow_types::stow_error!(
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
) -> stow_types::error::Result<()> {
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
        return Err(stow_types::stow_error!(
            "captured compile key {} is claimed by incompatible artifacts {} and {}",
            existing.captured_compile_key,
            existing.crate_name,
            candidate.crate_name
        ));
    }
    Ok(())
}

fn dependency_c_metadata_json(
    dependencies: &[ScannedArtifactDependency],
) -> stow_types::error::Result<DependencyCMetadataJson> {
    let mut identities = Vec::with_capacity(dependencies.len());
    for dependency in dependencies {
        let crate_name = CrateName::parse(dependency.crate_name.as_str()).map_err(|error| {
            stow_types::stow_error!(
                "ci scanned dependency crate_name `{}`: {error}",
                dependency.crate_name
            )
        })?;
        let c_metadata =
            CMetadata::parse(dependency.stable_c_metadata.as_str()).map_err(|error| {
                stow_types::stow_error!(
                    "ci scanned dependency c_metadata `{}`: {error}",
                    dependency.stable_c_metadata
                )
            })?;
        identities.push(DependencyCMetadataIdentity {
            crate_name,
            c_metadata,
        });
    }
    DependencyCMetadataJson::canonicalize(identities).map_err(|error| {
        stow_types::stow_error!("canonicalize dependency_c_metadata_json: {error}")
    })
}

fn parse_features_json_value(raw: &str) -> stow_types::error::Result<FeaturesJson> {
    let features: Vec<String> = serde_json::from_str(raw)
        .map_err(|error| stow_types::stow_error!("parse features_json `{raw}`: {error}"))?;
    FeaturesJson::canonicalize(features)
        .map_err(|error| stow_types::stow_error!("canonicalize features_json: {error}"))
}

fn dependency_compile_keys_json(
    dependencies: &[ScannedArtifactDependency],
) -> stow_types::error::Result<String> {
    let dependency_identities = dependencies
        .iter()
        .map(|dependency| {
            Ok(DependencyCompileKeyIdentity {
                crate_name: CrateName::parse(dependency.crate_name.as_str()).map_err(|error| {
                    stow_types::stow_error!(
                        "ci scanned dependency crate_name `{}`: {error}",
                        dependency.crate_name
                    )
                })?,
                compile_key: dependency.compile_key.clone(),
            })
        })
        .collect::<stow_types::error::Result<Vec<_>>>()?;
    let dependency_identities =
        DependencyCompileKeyIdentity::canonicalize_list(dependency_identities);
    serde_json::to_string(&dependency_identities).map_err(Into::into)
}

fn reconcile_duplicate_plan(
    existing: &mut PlannedArtifact,
    candidate: PlannedArtifact,
) -> stow_types::error::Result<()> {
    ensure_duplicate_plan_identity(existing, &candidate)?;

    match plan_preference(existing).cmp(&plan_preference(&candidate)) {
        Ordering::Less => {
            *existing = candidate;
            Ok(())
        }
        Ordering::Greater => Ok(()),
        Ordering::Equal if plans_share_outputs(existing, &candidate) => Ok(()),
        Ordering::Equal => Err(stow_types::stow_error!(
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
) -> stow_types::error::Result<()> {
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
        return Err(stow_types::stow_error!(
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

/// The machine this artifact's objects must be for, when it has any to
/// check: the builder's own for a host-side unit, the artifact's target
/// for a target-side one.
fn expected_object_arch(
    artifact: &ScannedArtifact,
) -> stow_types::error::Result<Option<ExpectedArch>> {
    let has_files = !artifact.outputs.is_empty()
        || artifact
            .native
            .as_ref()
            .is_some_and(|native| !native.out_dir_files.is_empty());
    if !has_files {
        return Ok(None);
    }
    Ok(Some(match artifact.unit_shape.side {
        UnitSide::Host => ExpectedArch::of_host()?,
        UnitSide::Target => ExpectedArch::of_triple(&artifact.target)?,
    }))
}

/// Pack the build script's `OUT_DIR` into a tar beside the artifact's output
/// snapshots, so it travels as a normal zstd-compressed OCI layer.
///
/// The bytes used to ride hex-encoded inside `ArtifactBlobConfig`, which the
/// edge writes twice per bundle and never compresses. For jemalloc-sys that
/// turned a ~333 MB `OUT_DIR` into a 1.27 GB download — more than nine times
/// the compiled output of fd's entire dependency graph.
async fn build_native_archive(
    artifact: &ScannedArtifact,
    expected: Option<ExpectedArch>,
) -> stow_types::error::Result<Option<PlannedArtifactOutput>> {
    let (Some(native), Some(out_dir)) = (
        artifact.native.as_ref(),
        artifact.build_script_out_dir.as_ref(),
    ) else {
        return Ok(None);
    };
    if native.out_dir_files.is_empty() {
        return Ok(None);
    }
    // Snapshots already outlive the build tree, and the upload step reads
    // planned paths from disk possibly in a later process.
    let snapshot_dir = artifact
        .outputs
        .first()
        .and_then(|output| output.source_path.parent())
        .ok_or_else(|| {
            stow_types::stow_error!(
                "artifact {} has native artifacts but no output snapshot to place them beside",
                artifact.crate_name
            )
        })?
        .to_path_buf();
    let file_name = format!("stow-native-{}.tar", artifact.c_metadata);
    let archive_path = snapshot_dir.join(&file_name);

    let out_dir = out_dir.clone();
    let files = native.out_dir_files.clone();
    let archive_path_for_task = archive_path.clone();
    let bytes = smol::unblock(move || {
        // The tree is untrusted build output: open the root without following
        // a symlink and every file relative to it, checked against the digest
        // taken at capture, so a path swapped in between cannot escape.
        let root = stow_types::native_capture::OutDirRoot::open(&out_dir)?.ok_or_else(|| {
            stow_types::stow_error!("native out dir {} is gone since capture", out_dir.display())
        })?;
        let mut builder = tar::Builder::new(Vec::new());
        // `out_dir_files` is already sorted by relative path, so the archive
        // is byte-identical across runs with identical inputs.
        for captured in &files {
            let relative_path = captured.relative_path.as_str();
            let mut file = root.open_verified(relative_path, &captured.sha256)?;
            // What a consumer links out of an `OUT_DIR` is its static
            // libraries; loose objects and helper programs beside them
            // are never on a link line, and a build script may build
            // those for the host.
            if let Some(expected) = expected
                && stow_types::native_capture::is_static_library(Path::new(relative_path))
            {
                let mut contents = Vec::new();
                file.read_to_end(&mut contents).map_err(|error| {
                    stow_types::stow_error!("read native out dir file {relative_path}: {error}")
                })?;
                object_arch::check(&contents, relative_path, expected)?;
                file.seek(std::io::SeekFrom::Start(0)).map_err(|error| {
                    stow_types::stow_error!("rewind native out dir file {relative_path}: {error}")
                })?;
            }
            builder
                .append_file(relative_path, &mut file)
                .map_err(|error| {
                    stow_types::stow_error!(
                        "append native out dir file {relative_path} to archive: {error}"
                    )
                })?;
        }
        let bytes = builder.into_inner().map_err(|error| {
            stow_types::stow_error!(
                "finish native archive {}: {error}",
                archive_path_for_task.display()
            )
        })?;
        std::fs::write(&archive_path_for_task, &bytes).map_err(|error| {
            stow_types::stow_error!(
                "write native archive {}: {error}",
                archive_path_for_task.display()
            )
        })?;
        Ok::<_, stow_types::error::Error>(bytes)
    })
    .await?;

    Ok(Some(PlannedArtifactOutput {
        path: archive_path,
        bundle_file: ArtifactBundleFile {
            file_name,
            media_type: stow_types::bundle::STOW_NATIVE_ARCHIVE_MEDIA_TYPE.to_owned(),
            sha256: hex::encode(Sha256::digest(&bytes)),
        },
    }))
}

async fn build_outputs(
    outputs: &[ScannedArtifactOutput],
    artifact_kind: &ArtifactKind,
    expected: Option<ExpectedArch>,
) -> stow_types::error::Result<Vec<PlannedArtifactOutput>> {
    let mut planned = Vec::with_capacity(outputs.len());
    let mut seen_file_names = BTreeSet::new();
    for output in outputs {
        let file_name = file_name(&output.path)?;
        if !seen_file_names.insert(file_name.clone()) {
            return Err(stow_types::stow_error!(
                "upload plan would contain duplicate bundled output file {}",
                file_name
            ));
        }
        let source_path = output.source_path.clone();
        let expected_sha256 = output.sha256.clone();
        let bytes = smol::unblock(move || {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(
                &mut stow_types::native_capture::open_verified_nofollow(
                    &source_path,
                    &expected_sha256,
                )?,
                &mut bytes,
            )?;
            stow_types::error::Result::Ok(bytes)
        })
        .await?;
        if let Some(expected) = expected {
            object_arch::check(&bytes, &file_name, expected)?;
        }
        let digest = hex::encode(Sha256::digest(&bytes));
        planned.push(PlannedArtifactOutput {
            path: output.source_path.clone(),
            bundle_file: ArtifactBundleFile {
                file_name,
                media_type: output_media_type(output.kind, artifact_kind).to_owned(),
                sha256: digest,
            },
        });
    }
    Ok(planned)
}

fn file_name(path: &Path) -> stow_types::error::Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            stow_types::stow_error!(
                "artifact path {} is missing a UTF-8 file name",
                path.display()
            )
        })
}

const fn output_media_type(
    output_kind: ParsedFileKind,
    artifact_kind: &ArtifactKind,
) -> &'static str {
    match output_kind {
        ParsedFileKind::Rlib => STOW_RLIB_MEDIA_TYPE,
        ParsedFileKind::Rmeta => STOW_RMETA_MEDIA_TYPE,
        ParsedFileKind::DynamicLibrary => match artifact_kind {
            ArtifactKind::ProcMacro => STOW_PROC_MACRO_MEDIA_TYPE,
            ArtifactKind::Dylib | ArtifactKind::Rlib => STOW_DYLIB_MEDIA_TYPE,
        },
    }
}

/// The registry key an artifact is addressed by. The trusted publisher
/// rebuilds it from a plan entry to check that the entry's `oci_reference`
/// is the one its own identity fields produce, so a plan cannot push under a
/// reference that belongs to a different artifact.
#[allow(clippy::too_many_arguments)]
pub fn artifact_key(
    crate_name: &str,
    crate_version: &semver::Version,
    features_json: &FeaturesJson,
    crate_types: &[RustCrateType],
    target: &str,
    rustc_version: &str,
    profile: &Profile,
    kind: &ArtifactKind,
) -> stow_types::error::Result<ArtifactKey> {
    Ok(ArtifactKey {
        crate_id: CrateId {
            name: crate_name.to_owned(),
            version: crate_version.clone(),
        },
        features: FeatureSet(
            features_json
                .features()
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
        ),
        crate_types: crate_types.to_vec(),
        target: Target(target.to_owned()),
        rustc_version: parse_rustc_version(rustc_version)?,
        profile: profile.clone(),
        kind: kind.clone(),
    })
}

/// [`artifact_key`] for an already-planned artifact.
pub fn planned_artifact_key(plan: &PlannedArtifact) -> stow_types::error::Result<ArtifactKey> {
    artifact_key(
        plan.crate_name.as_str(),
        plan.crate_version.as_semver(),
        &plan.features_json,
        &plan.crate_types,
        plan.target.as_str(),
        plan.rustc_version.as_str(),
        &plan.profile,
        &plan.kind,
    )
}
fn parse_rustc_version(raw: &str) -> stow_types::error::Result<RustcVersion> {
    let version = semver::Version::parse(raw)
        .map_err(|error| stow_types::stow_error!("invalid rustc version '{raw}': {error}"))?;
    Ok(RustcVersion {
        version,
        commit_hash: "unknown".to_owned(),
        llvm_version: "unknown".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use sha2::{Digest, Sha256};

    use super::build_upload_plan;
    use crate::dep_scan::{
        ParsedFileKind, ScannedArtifact, ScannedArtifactDependency, ScannedArtifactOutput,
    };
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::platform::{PanicStrategy, Profile};

    /// The leaf preimage — these tests assert plan assembly, not the
    /// build-stage context verification that feeds the real value in.
    fn dependency_task_ids() -> Vec<String> {
        Vec::new()
    }

    #[tokio::test]
    async fn upload_plan_preserves_captured_exact_identity() {
        let output_path = std::env::temp_dir().join(format!(
            "stow-ci-plan-test-{}-libserde-original.rlib",
            std::process::id()
        ));
        fs::write(&output_path, b"serde-test-artifact").expect("write artifact bytes");
        let mut serde_artifact = scanned_lib_artifact(
            "serde",
            "1.0.228",
            "original-compile-key",
            "0123456789abcdef",
            123,
            output_path.clone(),
        );
        serde_artifact.features_json =
            "[\"default\",\"derive\",\"serde_derive\",\"std\"]".to_owned();
        let scanned = vec![serde_artifact];

        let planned = build_upload_plan(
            &scanned,
            &[],
            &dependency_task_ids(),
            stow_types::node_profile::NodeProfile::Dev,
        )
        .await
        .expect("build upload plan");
        let plan = planned.first().expect("planned artifact");

        assert_eq!(plan.compile_key, "original-compile-key");
        assert_eq!(plan.c_metadata.as_str(), "0123456789abcdef");
        assert_eq!(plan.extra_filename, "-0123456789abcdef");
        assert!(
            plan.oci_reference.ends_with("-0123456789abcdef"),
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

        let planned = build_upload_plan(
            &scanned,
            &[],
            &dependency_task_ids(),
            stow_types::node_profile::NodeProfile::Dev,
        )
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

    /// A scanned rlib artifact for `crate_name` carrying the captured
    /// identity (`captured_compile_key`, `c_metadata`) and a single rlib
    /// output at `output_path`.
    fn scanned_lib_artifact(
        crate_name: &str,
        crate_version: &str,
        captured_compile_key: &str,
        c_metadata: &str,
        artifact_size: u64,
        output_path: std::path::PathBuf,
    ) -> ScannedArtifact {
        ScannedArtifact {
            crate_name: crate_name.to_owned(),
            crate_version: crate_version.to_owned(),
            target: "aarch64-apple-darwin".to_owned(),
            rustc_version: "1.91.1".to_owned(),
            captured_compile_key: captured_compile_key.to_owned(),
            c_metadata: c_metadata.to_owned(),
            extra_filename: format!("-{c_metadata}"),
            profile: Profile {
                opt_level: "0".to_owned(),
                debuginfo: 1,
                debug_assertions: true,
                overflow_checks: true,
                panic: PanicStrategy::Unwind,
                strip: stow_types::platform::StripLevel::None,
            },
            emit: vec![
                "dep-info".to_owned(),
                "link".to_owned(),
                "metadata".to_owned(),
            ],
            unit_shape: stow_types::public_cache::UnitShape {
                side: stow_types::public_cache::UnitSide::Target,
                invocation: stow_types::public_cache::UnitInvocation::Target,
                kind: stow_types::public_cache::UnitKind::Linked,
            },
            features_json: "[]".to_owned(),
            dependencies: Vec::new(),
            artifact_size,
            compile_millis: 0,
            kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Lib],
            outputs: vec![ScannedArtifactOutput {
                kind: ParsedFileKind::Rlib,
                path: output_path.clone(),
                sha256: hex::encode(Sha256::digest(
                    std::fs::read(&output_path).expect("read fixture output"),
                )),
                source_path: output_path,
            }],
            build_script_out_dir: None,
            native: None,
        }
    }

    fn scanned_bitflags_artifact(
        original_c_metadata: &str,
        output_path: std::path::PathBuf,
        artifact_size: u64,
    ) -> ScannedArtifact {
        let mut artifact = scanned_lib_artifact(
            "bitflags",
            "2.11.0",
            &format!("captured-{original_c_metadata}"),
            original_c_metadata,
            artifact_size,
            output_path,
        );
        artifact.features_json = "[\"std\"]".to_owned();
        artifact
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

        let mut rand_core = scanned_lib_artifact(
            "rand_core",
            "0.6.4",
            "captured-rand-core",
            "d85bb459550a6063",
            18,
            parent_output_path.clone(),
        );
        rand_core.dependencies = vec![ScannedArtifactDependency {
            crate_name: "getrandom".to_owned(),
            path: child_output_path.clone(),
            compile_key: "captured-getrandom".to_owned(),
            stable_c_metadata: "2384b9107b13ade1".to_owned(),
        }];
        let scanned = vec![
            scanned_lib_artifact(
                "getrandom",
                "0.2.17",
                "captured-getrandom",
                "2384b9107b13ade1",
                17,
                child_output_path.clone(),
            ),
            rand_core,
        ];

        let planned = build_upload_plan(
            &scanned,
            &[],
            &dependency_task_ids(),
            stow_types::node_profile::NodeProfile::Dev,
        )
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
            rand_core.dependency_c_metadata_json.raw(),
            "[{\"crate_name\":\"getrandom\",\"c_metadata\":\"2384b9107b13ade1\"}]"
        );
        assert_eq!(
            rand_core.dependency_compile_keys_json,
            "[{\"crate_name\":\"getrandom\",\"compile_key\":\"captured-getrandom\"}]"
        );
        assert_eq!(getrandom.c_metadata.as_str(), "2384b9107b13ade1");

        fs::remove_file(child_output_path).expect("remove child artifact bytes");
        fs::remove_file(parent_output_path).expect("remove parent artifact bytes");
    }

    /// A dependency edge satisfied by a consumed (served) artifact resolves
    /// against its signed-index identity — the capture's own records are
    /// what the publish stage checks, not a planned output.
    #[tokio::test]
    async fn upload_plan_resolves_dependencies_against_consumed_artifacts() {
        let parent_output_path = std::env::temp_dir().join(format!(
            "stow-ci-plan-test-{}-librand_core-served-d85bb459550a6063.rlib",
            std::process::id()
        ));
        fs::write(&parent_output_path, b"rand-core-artifact").expect("write parent artifact");

        let mut rand_core = scanned_lib_artifact(
            "rand_core",
            "0.6.4",
            "captured-rand-core",
            "d85bb459550a6063",
            18,
            parent_output_path.clone(),
        );
        rand_core.dependencies = vec![ScannedArtifactDependency {
            crate_name: "getrandom".to_owned(),
            path: std::env::temp_dir().join(format!(
                "stow-ci-plan-test-{}-libgetrandom-served-2384b9107b13ade1.rlib",
                std::process::id()
            )),
            compile_key: "served-getrandom".to_owned(),
            stable_c_metadata: "2384b9107b13ade1".to_owned(),
        }];
        let scanned = vec![rand_core];

        let served = vec![crate::dep_scan::ConsumedArtifact {
            crate_name: "getrandom".to_owned(),
            crate_version: "0.2.17".to_owned(),
            compile_key: "served-getrandom".to_owned(),
            c_metadata: "2384b9107b13ade1".to_owned(),
            target: "aarch64-apple-darwin".to_owned(),
            rustc_version: "1.91.1".to_owned(),
            emit: vec!["link".to_owned()],
        }];
        build_upload_plan(
            &scanned,
            &served,
            &dependency_task_ids(),
            stow_types::node_profile::NodeProfile::Dev,
        )
        .await
        .expect("consumed dependency resolves the plan");

        let mut mismatched = served.clone();
        mismatched[0].c_metadata = "ffffffffffffffff".to_owned();
        let error = build_upload_plan(
            &scanned,
            &mismatched,
            &dependency_task_ids(),
            stow_types::node_profile::NodeProfile::Dev,
        )
        .await
        .expect_err("an identity the claim does not carry must not satisfy the edge");
        assert!(
            error
                .to_string()
                .contains("not produced by any scanned artifact")
        );

        fs::remove_file(parent_output_path).expect("remove parent artifact bytes");
    }

    /// stow#708's gate: a build script that compiled C for the wrong
    /// machine is refused at plan time — an `OUT_DIR` static library
    /// takes the same check the published outputs take.
    #[tokio::test]
    async fn a_unit_is_refused_when_its_objects_are_for_another_machine() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out_dir = dir.path().join("out");
        fs::create_dir_all(&out_dir).expect("out dir");
        let object_bytes = crate::object_arch::relocatable_object(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
        );
        let library_bytes = crate::object_arch::gnu_archive(&[("probe.o", &object_bytes)]);
        fs::write(out_dir.join("probe.lib"), &library_bytes).expect("write probe library");
        let output_path = dir.path().join("libwinarm_probe-0123456789abcdef.rlib");
        fs::write(&output_path, b"winarm-probe-artifact").expect("write artifact bytes");

        let mut artifact = scanned_lib_artifact(
            "winarm-probe",
            "1.0.0",
            "captured-winarm-probe",
            "0123456789abcdef",
            20,
            output_path,
        );
        artifact.target = "aarch64-pc-windows-msvc".to_owned();
        artifact.build_script_out_dir = Some(out_dir.clone());
        artifact.native = Some(stow_types::artifact::NativeArtifacts {
            static_libs: Vec::new(),
            cargo_directives: Vec::new(),
            dep_env_vars: std::collections::BTreeMap::new(),
            out_dir_files: vec![stow_types::artifact::OutDirFile {
                relative_path: "probe.lib".to_owned(),
                sha256: hex::encode(Sha256::digest(&library_bytes)),
            }],
            original_out_dir: out_dir,
        });

        let error = build_upload_plan(
            &[artifact],
            &[],
            &dependency_task_ids(),
            stow_types::node_profile::NodeProfile::Dev,
        )
        .await
        .expect_err("an x86-64 object must not publish under an arm64 task");
        let message = error.to_string();
        assert!(
            message.contains("winarm-probe"),
            "names the crate: {message}"
        );
        assert!(
            message.contains("probe.lib(probe.o)"),
            "names the library and its member: {message}"
        );
    }
}
