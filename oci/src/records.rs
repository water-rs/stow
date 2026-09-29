//! The per-task records artifact: a task's `Vec<ArtifactRecord>` pushed,
//! signed and read back as one OCI artifact in the same namespace the
//! bundles use (stow#455). Records are the registry's only mutable
//! record store — the edge's D1 catalog is a read replica synced off
//! these artifacts, never a source of truth.

use std::collections::BTreeMap;

use oci_client::client::{Config, ImageLayer};
use oci_client::manifest::OciImageManifest;
use stow_types::api::ArtifactRecord;
use stow_types::records::{
    RECORDS_ARTIFACT_TYPE, RECORDS_CONFIG_MEDIA_TYPE, RECORDS_TASK_ID_ANNOTATION, is_records_tag,
    records_tag,
};
use stow_types::registry::sha256_digest;

use crate::client::{RegistrySession, canonical_manifest_bytes};
use crate::registry::{
    RegistryBase, RegistryCredentials, pull_blob_verified, pull_tagged_manifest,
};
use crate::sign;

/// What [`push_records`] did: the tag and manifest digest the records
/// artifact landed under.
#[derive(Debug, Clone)]
pub struct RecordsPublishOutcome {
    /// The OCI tag (`records-<rustc>-<task_id hash>`).
    pub tag: String,
    /// Full `registry/repo:tag` reference the artifact signed under.
    pub oci_reference: String,
    /// The manifest digest cosign signed and [`pull_records`] returns.
    pub manifest_digest: String,
}

/// A records artifact read back from the registry.
#[derive(Debug)]
pub struct PulledRecords {
    /// The artifact's rows.
    pub records: Vec<ArtifactRecord>,
    /// Full `registry/repo:tag` reference.
    pub oci_reference: String,
    /// Manifest digest — the input to `pull_signature_materials`.
    pub manifest_digest: String,
    /// The `dev.stow.records.task-id` annotation the manifest carries.
    pub task_id: String,
}

/// Push `records` as `task_id`'s signed records artifact on the
/// production registry.
///
/// One JSON layer, an empty config, the task-id annotation, then the
/// same cosign signature every `build-crate.yml` artifact carries.
///
/// # Errors
///
/// Returns an error when a blob or the manifest push fails, or the cosign
/// signing does.
pub async fn push_records(
    credentials: &RegistryCredentials,
    rustc_version: &str,
    task_id: &str,
    records: &[ArtifactRecord],
) -> stow_types::error::Result<RecordsPublishOutcome> {
    let base = RegistryBase::production()?;
    let session = base.push_session(credentials);
    push_records_with(&session, &base, rustc_version, task_id, records, |reference, digest| async move {
        sign::sign_artifact(&reference, &digest, credentials).await
    })
    .await
}

/// [`push_records`] with the session, registry base and signer supplied —
/// the mock-registry test and the local-CI path sign in-process so no
/// cosign binary is involved.
///
/// # Errors
///
/// Same as [`push_records`].
pub async fn push_records_with<S, Fut>(
    session: &RegistrySession,
    base: &RegistryBase,
    rustc_version: &str,
    task_id: &str,
    records: &[ArtifactRecord],
    sign: S,
) -> stow_types::error::Result<RecordsPublishOutcome>
where
    S: Fn(String, String) -> Fut + Send + Sync,
    Fut: Future<Output = stow_types::error::Result<()>> + Send,
{
    let tag = records_tag(rustc_version, task_id);
    let reference = base.reference(&tag)?;
    let body = serde_json::to_vec(records)
        .map_err(|error| stow_types::stow_error!("encode records for {task_id}: {error}"))?;
    let layer = ImageLayer::new(body, RECORDS_ARTIFACT_TYPE.to_owned(), None);
    let config_bytes = b"{}".to_vec();

    session
        .push_blob(&layer.sha256_digest(), &layer.data)
        .await
        .map_err(|error| stow_types::stow_error!("push records layer {reference}: {error}"))?;
    session
        .push_blob(&sha256_digest(&config_bytes), &config_bytes)
        .await
        .map_err(|error| stow_types::stow_error!("push records config {reference}: {error}"))?;
    let mut manifest = OciImageManifest::build(
        std::slice::from_ref(&layer),
        &Config::new(config_bytes, RECORDS_CONFIG_MEDIA_TYPE.to_owned(), None),
        Some(BTreeMap::from([(
            RECORDS_TASK_ID_ANNOTATION.to_owned(),
            task_id.to_owned(),
        )])),
    );
    manifest.artifact_type = Some(RECORDS_ARTIFACT_TYPE.to_owned());
    let manifest_bytes = canonical_manifest_bytes(&manifest)?;
    let manifest_digest =
        sign::put_signed_manifest(session, &reference, &manifest_bytes, |digest| {
            sign(reference.to_string(), digest)
        })
        .await
        .map_err(|error| stow_types::stow_error!("push records manifest {reference}: {error}"))?;
    tracing::info!(
        oci_reference = %reference,
        digest = %manifest_digest,
        task_id,
        records = records.len(),
        "pushed and signed records artifact"
    );
    Ok(RecordsPublishOutcome {
        tag,
        oci_reference: reference.to_string(),
        manifest_digest,
    })
}

/// Read `task_id`'s records artifact back.
///
/// The manifest under the records tag must declare
/// [`RECORDS_ARTIFACT_TYPE`] and carry the task-id annotation naming the
/// same task, then its single layer — digest-verified — decodes as the
/// `Vec<ArtifactRecord>`.
///
/// # Errors
///
/// Returns an error when the tag is absent, the manifest is not a records
/// artifact, or the layer fails its digest check or decodes wrong.
pub async fn pull_records(
    session: &RegistrySession,
    base: &RegistryBase,
    rustc_version: &str,
    task_id: &str,
) -> stow_types::error::Result<PulledRecords> {
    let pulled = pull_records_by_tag(session, base, &records_tag(rustc_version, task_id)).await?;
    if pulled.task_id != task_id {
        return Err(stow_types::stow_error!(
            "{} carries no {RECORDS_TASK_ID_ANNOTATION} annotation naming {task_id}",
            pulled.oci_reference
        ));
    }
    Ok(pulled)
}

/// Read the records artifact under `tag` back.
///
/// [`pull_records`] by the tag name — the task id is taken from the
/// manifest's annotation rather than recomputed, which is the form
/// `index export` needs when walking `list_records_tags` output.
///
/// # Errors
///
/// Same as [`pull_records`].
pub async fn pull_records_by_tag(
    session: &RegistrySession,
    base: &RegistryBase,
    tag: &str,
) -> stow_types::error::Result<PulledRecords> {
    let reference = base.reference(tag)?;
    let (manifest_digest, manifest) = pull_tagged_manifest(session, &reference).await?;
    if manifest.artifact_type.as_deref() != Some(RECORDS_ARTIFACT_TYPE) {
        return Err(stow_types::stow_error!(
            "{reference} is not a records artifact (artifactType {:?})",
            manifest.artifact_type
        ));
    }
    let annotated_task_id = manifest
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(RECORDS_TASK_ID_ANNOTATION))
        .ok_or_else(|| {
            stow_types::stow_error!(
                "{reference} carries no {RECORDS_TASK_ID_ANNOTATION} annotation"
            )
        })?;
    let descriptor = manifest
        .layers
        .first()
        .ok_or_else(|| stow_types::stow_error!("records artifact {reference} has no layers"))?;
    if descriptor.media_type != RECORDS_ARTIFACT_TYPE {
        return Err(stow_types::stow_error!(
            "records artifact {reference} layer is {}, not {RECORDS_ARTIFACT_TYPE}",
            descriptor.media_type
        ));
    }
    let bytes = pull_blob_verified(session, descriptor).await?;
    let records: Vec<ArtifactRecord> = serde_json::from_slice(&bytes)
        .map_err(|error| stow_types::stow_error!("decode records layer of {reference}: {error}"))?;
    Ok(PulledRecords {
        records,
        oci_reference: reference.to_string(),
        manifest_digest,
        task_id: annotated_task_id.clone(),
    })
}

/// Every `records-*` tag in the session's repository — the export's
/// catalog listing. Pagination is the distribution spec's `n`/`last`
/// continuation.
///
/// # Errors
///
/// Returns [`RegistryError`] on a transport failure or a refusal.
pub async fn list_records_tags(
    session: &RegistrySession,
) -> Result<Vec<String>, crate::client::RegistryError> {
    let tags = session.list_tags().await?;
    Ok(tags.into_iter().filter(|tag| is_records_tag(tag)).collect())
}
