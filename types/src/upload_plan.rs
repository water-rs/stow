use std::collections::BTreeMap;
use std::path::PathBuf;

use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::api::ArtifactRecord;
use crate::artifact::{ArtifactKind, NativeArtifacts, RustCrateType};
use crate::bundle::ArtifactBundleFile;
use crate::identity::{
    CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, FeaturesJson, TargetTriple,
    WireRustcVersion,
};
use crate::platform::Profile;

/// One artifact CI plans to upload after a build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedArtifact {
    /// Stable hash of the rustc invocation identity.
    pub compile_key: String,
    /// Crate name.
    pub crate_name: CrateName,
    /// Crate version.
    pub crate_version: CrateVersion,
    /// Cargo `-C metadata` value.
    pub c_metadata: CMetadata,
    /// Cargo `-C extra-filename` suffix.
    pub extra_filename: String,
    /// Canonical features list.
    pub features_json: FeaturesJson,
    /// Sorted dependency identities driving the cache key.
    pub dependency_c_metadata_json: DependencyCMetadataJson,
    /// JSON-encoded compile keys of dependencies.
    pub dependency_compile_keys_json: String,
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Cargo profile.
    pub profile: Profile,
    /// Sorted, deduplicated emit modes.
    pub emit: Vec<String>,
    /// OCI reference where this artifact will be pushed.
    pub oci_reference: String,
    /// Artifact kind (rlib / dylib / proc-macro).
    pub kind: ArtifactKind,
    /// Declared crate types.
    pub crate_types: Vec<RustCrateType>,
    /// Size in bytes.
    pub artifact_size: u64,
    /// Files that will be packaged into the bundle.
    pub outputs: Vec<PlannedArtifactOutput>,
    /// Optional native (C/C++) artifacts captured from the build script.
    pub native: Option<NativeArtifacts>,
    /// The packed `OUT_DIR` tree for `native`, pushed as an extra OCI layer
    /// after `outputs`.
    #[serde(default)]
    pub native_archive: Option<PlannedArtifactOutput>,
}

/// One output file from a planned artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedArtifactOutput {
    /// Filesystem path to the output.
    pub path: PathBuf,
    /// Bundle metadata for this file.
    pub bundle_file: ArtifactBundleFile,
}

/// Build `ArtifactRecord` rows for D1 registration from upload plans.
pub fn build_artifact_records(
    plans: &[PlannedArtifact],
    digests_by_reference: &BTreeMap<String, String>,
) -> crate::error::Result<Vec<ArtifactRecord>> {
    let mut records = Vec::with_capacity(plans.len());

    for plan in plans {
        let Some(oci_digest) = digests_by_reference.get(&plan.oci_reference) else {
            return Err(crate::stow_error!(
                "missing OCI digest for reference {}",
                plan.oci_reference
            ));
        };

        records.push(ArtifactRecord {
            compile_key: plan.compile_key.clone(),
            c_metadata: plan.c_metadata.clone(),
            extra_filename: plan.extra_filename.clone(),
            target: plan.target.clone(),
            rustc_version: plan.rustc_version.clone(),
            profile: plan.profile.clone(),
            emit: plan.emit.clone(),
            crate_name: plan.crate_name.clone(),
            version: plan.crate_version.clone(),
            features_json: plan.features_json.clone(),
            dependency_c_metadata_json: plan.dependency_c_metadata_json.clone(),
            oci_reference: plan.oci_reference.clone(),
            oci_digest: oci_digest.clone(),
            has_native: plan.native.is_some(),
            artifact_kind: plan.kind.clone(),
            crate_types: plan.crate_types.clone(),
            artifact_size: plan.artifact_size,
        });
    }

    Ok(records)
}

pub fn compute_compile_key(
    crate_name: &str,
    crate_version: &str,
    target: &str,
    rustc_version: &str,
    profile: &Profile,
    crate_types: &[RustCrateType],
    emit: &[String],
    features_json: &str,
    dependency_c_metadata_json: &str,
    kind: &ArtifactKind,
) -> crate::error::Result<String> {
    let mut hasher = Hasher::new();
    hasher.update(b"stow-compile-key-v1");
    update_str(&mut hasher, crate_name);
    update_str(&mut hasher, crate_version);
    update_str(&mut hasher, target);
    update_str(&mut hasher, rustc_version);
    update_str(&mut hasher, features_json);
    update_str(&mut hasher, dependency_c_metadata_json);
    update_str(&mut hasher, kind.as_str());
    update_str(
        &mut hasher,
        &serde_json::to_string(profile).map_err(|error| {
            crate::stow_error!(
                "serialize compile profile for {} {}: {error}",
                crate_name,
                crate_version
            )
        })?,
    );
    update_str(
        &mut hasher,
        &serde_json::to_string(crate_types).map_err(|error| {
            crate::stow_error!(
                "serialize crate types for {} {}: {error}",
                crate_name,
                crate_version
            )
        })?,
    );
    update_str(
        &mut hasher,
        &serde_json::to_string(emit).map_err(|error| {
            crate::stow_error!(
                "serialize emit kinds for {} {}: {error}",
                crate_name,
                crate_version
            )
        })?,
    );
    Ok(hasher.finalize().to_hex().to_string())
}

fn update_str(hasher: &mut Hasher, value: &str) {
    let len = u32::try_from(value.len()).expect("hash input string length exceeds u32 range");
    hasher.update(&len.to_le_bytes());
    hasher.update(value.as_bytes());
}
