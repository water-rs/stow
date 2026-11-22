//! One-time migration of legacy `records-*` and `built-*` tags whose
//! signatures live in standalone `sha256-<digest>.sig` images into the
//! inline [`RecordsSignatureEnvelope`] annotation (stow#1627).
//!
//! Like `repack` and `resign`, this module is the only place that reads
//! the retired records `.sig` layout; normal readers (`records.rs`) read
//! the inline annotation alone. No new signature is minted: each legacy
//! tag's existing `.sig` material is verified against the pinned builder
//! identity and embedded verbatim onto `dev.stow.records.signatures`.
//! Deleted once run across active rustc repositories.

use oci_client::manifest::OciImageManifest;
use stow_types::error::Context as _;
use stow_types::records::{
    RECORDS_ARTIFACT_TYPE, RECORDS_SIGNATURES_ANNOTATION, RECORDS_TASK_ID_ANNOTATION,
    RecordsSignature, RecordsSignatureEnvelope, is_records_tag, parse_records_tag, task_id_hash,
};

use crate::artifacts::pull_listed_signature_materials;
use crate::client::RegistrySession;
use crate::records::{parse_signed_records_manifest, records_manifest_with_envelope};
use crate::verify::{Trust, payload_docker_reference, verify_material, verify_materials};

/// What migrating one `records-*` or `built-*` tag did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordsTagMigration {
    /// The tag already carried a valid inline signature envelope.
    Already {
        /// Tagged outer manifest bytes.
        outer_bytes: Vec<u8>,
    },
    /// Legacy `.sig` materials verified and the inline manifest replaced
    /// the tag.
    Migrated {
        /// Newly written outer manifest bytes.
        outer_bytes: Vec<u8>,
    },
}

/// Migrate one listed `records-*` `tag` in place, verifying its signature
/// against `policy` for `identity_reference`.
///
/// # Errors
/// Fails when the manifest cannot be pulled or parsed, no signature
/// verifies under `policy`, or the replacement `PUT` fails.
pub async fn migrate_records_tag(
    session: &RegistrySession,
    trust: &Trust,
    identity_reference: &str,
    tag: &str,
    policy: &(impl sigstore::bundle::verify::policy::VerificationPolicy + Sync),
) -> stow_types::error::Result<RecordsTagMigration> {
    let reference = session.reference(tag)?;
    let (raw_bytes, manifest_digest) = session
        .pull_listed_manifest(&reference)
        .await
        .map_err(|error| stow_types::stow_error!("pull records manifest {reference}: {error}"))?;
    let manifest: OciImageManifest = serde_json::from_slice(&raw_bytes)
        .wrap_err_with(|| format!("decode records manifest {reference}"))?;

    if manifest
        .annotations
        .as_ref()
        .is_some_and(|map| map.contains_key(RECORDS_SIGNATURES_ANNOTATION))
    {
        let (_, signed_digest, envelope, _) = parse_signed_records_manifest(&reference, &manifest)?;
        verify_materials(
            trust,
            identity_reference,
            &signed_digest,
            &envelope.materials(),
            policy,
        )
        .wrap_err_with(|| format!("verify inline records {reference}"))?;
        return Ok(RecordsTagMigration::Already {
            outer_bytes: raw_bytes,
        });
    }

    validate_legacy_records_manifest(&reference, &manifest)?;
    let materials = pull_listed_signature_materials(session, &reference, &manifest_digest).await?;
    let verified: Vec<RecordsSignature> = materials
        .iter()
        .filter(|material| {
            let sig = stow_types::bundle::SigstoreSignature {
                payload_path: material.payload_path.clone(),
                signature: material.signature.clone(),
                certificate_pem: material.certificate_pem.clone(),
                rekor_bundle_json: material.rekor_bundle_json.clone(),
            };
            verify_material(
                trust,
                identity_reference,
                &manifest_digest,
                &sig,
                &material.payload_bytes,
                policy,
            )
            .is_ok()
        })
        .map(RecordsSignature::from_material)
        .collect::<stow_types::error::Result<Vec<_>>>()?;
    if verified.is_empty() {
        return Err(stow_types::stow_error!(
            "legacy records {reference}@{manifest_digest} has no signature verifying for {identity_reference}"
        ));
    }
    let signed_manifest = String::from_utf8(raw_bytes)
        .map_err(|error| stow_types::stow_error!("legacy manifest {reference} UTF-8: {error}"))?;
    let envelope = RecordsSignatureEnvelope {
        signed_manifest,
        signatures: verified,
    };
    let outer_bytes = records_manifest_with_envelope(&envelope)?;
    session
        .put_manifest(&reference, &outer_bytes)
        .await
        .map_err(|error| {
            stow_types::stow_error!("write migrated records manifest {reference}: {error}")
        })?;
    Ok(RecordsTagMigration::Migrated { outer_bytes })
}

/// Migrate one listed `built-<rustc>-<hash>` marker tag to an inline signature.
///
/// If the marker already carries a valid inline signature, it is left
/// untouched; otherwise it is pointed at `newest_records_outer` when the task
/// has a migrated `records-*` tag, or its own `.sig` layer binding a matching
/// `records-<rustc>-<hash>*` tag in `repository` is inlined.
///
/// # Errors
/// Fails when the marker cannot be pulled, verified or updated.
pub async fn migrate_marker_tag(
    session: &RegistrySession,
    trust: &Trust,
    repository: &str,
    rustc_version: &str,
    tag: &str,
    newest_records_outer: Option<&[u8]>,
    policy: &(impl sigstore::bundle::verify::policy::VerificationPolicy + Sync),
) -> stow_types::error::Result<RecordsTagMigration> {
    let reference = session.reference(tag)?;
    let (raw_bytes, manifest_digest) = session
        .pull_listed_manifest(&reference)
        .await
        .map_err(|error| stow_types::stow_error!("pull marker manifest {reference}: {error}"))?;
    let manifest: OciImageManifest = serde_json::from_slice(&raw_bytes)
        .wrap_err_with(|| format!("decode marker manifest {reference}"))?;

    if manifest
        .annotations
        .as_ref()
        .is_some_and(|map| map.contains_key(RECORDS_SIGNATURES_ANNOTATION))
    {
        let (task_id, signed_digest, envelope, _) =
            parse_signed_records_manifest(&reference, &manifest)?;
        let expected_hash = task_id_hash(&task_id);
        let ok = envelope.materials().iter().any(|material| {
            marker_material_matches(
                trust,
                repository,
                rustc_version,
                expected_hash.as_str(),
                &signed_digest,
                material,
                policy,
            )
        });
        if !ok {
            return Err(stow_types::stow_error!(
                "inline marker {reference} carries no valid records signature"
            ));
        }
        return Ok(RecordsTagMigration::Already {
            outer_bytes: raw_bytes,
        });
    }

    if let Some(outer_bytes) = newest_records_outer {
        session
            .put_manifest(&reference, outer_bytes)
            .await
            .map_err(|error| {
                stow_types::stow_error!("write migrated marker {reference}: {error}")
            })?;
        return Ok(RecordsTagMigration::Migrated {
            outer_bytes: outer_bytes.to_vec(),
        });
    }

    let task_id = validate_legacy_records_manifest(&reference, &manifest)?;
    let expected_hash = task_id_hash(&task_id);
    let materials = pull_listed_signature_materials(session, &reference, &manifest_digest).await?;
    let verified: Vec<RecordsSignature> = materials
        .iter()
        .filter(|material| {
            marker_material_matches(
                trust,
                repository,
                rustc_version,
                expected_hash.as_str(),
                &manifest_digest,
                material,
                policy,
            )
        })
        .map(RecordsSignature::from_material)
        .collect::<stow_types::error::Result<Vec<_>>>()?;
    if verified.is_empty() {
        return Err(stow_types::stow_error!(
            "legacy marker {reference}@{manifest_digest} has no matching records signature"
        ));
    }
    let signed_manifest = String::from_utf8(raw_bytes)
        .map_err(|error| stow_types::stow_error!("legacy marker {reference} UTF-8: {error}"))?;
    let envelope = RecordsSignatureEnvelope {
        signed_manifest,
        signatures: verified,
    };
    let outer_bytes = records_manifest_with_envelope(&envelope)?;
    session
        .put_manifest(&reference, &outer_bytes)
        .await
        .map_err(|error| stow_types::stow_error!("write migrated marker {reference}: {error}"))?;
    Ok(RecordsTagMigration::Migrated { outer_bytes })
}

pub(crate) fn validate_legacy_records_manifest(
    reference: &oci_client::Reference,
    manifest: &OciImageManifest,
) -> stow_types::error::Result<String> {
    if manifest.artifact_type.as_deref() != Some(RECORDS_ARTIFACT_TYPE) {
        return Err(stow_types::stow_error!(
            "{reference} is not a records artifact (artifactType {:?})",
            manifest.artifact_type
        ));
    }
    let task_id = manifest
        .annotations
        .as_ref()
        .and_then(|map| map.get(RECORDS_TASK_ID_ANNOTATION))
        .ok_or_else(|| stow_types::stow_error!("{reference} lacks {RECORDS_TASK_ID_ANNOTATION}"))?;
    let [layer] = manifest.layers.as_slice() else {
        return Err(stow_types::stow_error!(
            "records artifact {reference} has {} layers, expected 1",
            manifest.layers.len()
        ));
    };
    if layer.media_type != RECORDS_ARTIFACT_TYPE {
        return Err(stow_types::stow_error!(
            "records artifact {reference} layer is {}, not {RECORDS_ARTIFACT_TYPE}",
            layer.media_type
        ));
    }
    Ok(task_id.clone())
}

pub(crate) fn marker_material_matches(
    trust: &Trust,
    repository: &str,
    rustc_version: &str,
    expected_hash: &str,
    signed_digest: &str,
    material: &stow_types::bundle::BundleSignatureMaterial,
    policy: &(impl sigstore::bundle::verify::policy::VerificationPolicy + Sync),
) -> bool {
    let Some(bound) = payload_docker_reference(&material.payload_bytes) else {
        return false;
    };
    let Some((bound_repo, bound_tag)) = bound.rsplit_once(':') else {
        return false;
    };
    if bound_repo != repository || !is_records_tag(bound_tag) {
        return false;
    }
    let Some(parsed) = parse_records_tag(bound_tag) else {
        return false;
    };
    if parsed.rustc_version != rustc_version || parsed.task_hash != expected_hash {
        return false;
    }
    let sig = stow_types::bundle::SigstoreSignature {
        payload_path: material.payload_path.clone(),
        signature: material.signature.clone(),
        certificate_pem: material.certificate_pem.clone(),
        rekor_bundle_json: material.rekor_bundle_json.clone(),
    };
    verify_material(
        trust,
        &bound,
        signed_digest,
        &sig,
        &material.payload_bytes,
        policy,
    )
    .is_ok()
}
