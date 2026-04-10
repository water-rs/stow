use std::collections::BTreeMap;
use std::path::PathBuf;

use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::api::ArtifactRecord;
use crate::artifact::{ArtifactKind, NativeArtifacts, RustCrateType};
use crate::bundle::ArtifactBundleFile;
use crate::platform::Profile;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedArtifact {
    pub compile_key: String,
    pub crate_name: String,
    pub crate_version: String,
    pub c_metadata: String,
    pub extra_filename: String,
    pub features_json: String,
    pub dependency_c_metadata_json: String,
    pub dependency_compile_keys_json: String,
    pub target: String,
    pub rustc_version: String,
    pub profile: Profile,
    pub emit: Vec<String>,
    pub oci_reference: String,
    pub kind: ArtifactKind,
    pub crate_types: Vec<RustCrateType>,
    pub artifact_size: u64,
    pub outputs: Vec<PlannedArtifactOutput>,
    pub native: Option<NativeArtifacts>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedArtifactOutput {
    pub path: PathBuf,
    pub bundle_file: ArtifactBundleFile,
}

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
    hasher.update(&(value.len() as u32).to_le_bytes());
    hasher.update(value.as_bytes());
}
