use std::collections::BTreeMap;

use stow_types::api::ArtifactRecord;

use crate::plan::PlannedArtifact;

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
            is_proc_macro: plan.is_proc_macro,
            artifact_size: plan.artifact_size,
        });
    }

    Ok(records)
}
