use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::api::ArtifactRecord;
use crate::artifact::{ArtifactKind, NativeArtifacts, RustCrateType};
use crate::bundle::ArtifactBundleFile;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedArtifact {
    pub crate_name: String,
    pub crate_version: String,
    pub c_metadata: String,
    pub features_json: String,
    pub target: String,
    pub rustc_version: String,
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
) -> eyre::Result<Vec<ArtifactRecord>> {
    let mut records = Vec::with_capacity(plans.len());

    for plan in plans {
        let Some(oci_digest) = digests_by_reference.get(&plan.oci_reference) else {
            return Err(eyre::eyre!(
                "missing OCI digest for reference {}",
                plan.oci_reference
            ));
        };

        records.push(ArtifactRecord {
            c_metadata: plan.c_metadata.clone(),
            target: plan.target.clone(),
            rustc_version: plan.rustc_version.clone(),
            crate_name: plan.crate_name.clone(),
            version: plan.crate_version.clone(),
            features_json: plan.features_json.clone(),
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
