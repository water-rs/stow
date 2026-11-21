//! The per-build records artifact: a build's `BuildRecords` pushed,
//! signed and read back as one OCI artifact in the same namespace the
//! bundles use (stow#455, stow#1627). Each build publishes under its own
//! `records-<rustc>-<task_id hash>-<run_id>-<run_attempt>` tag, so a
//! rebuilt task never overwrites the previous build's artifact
//! (stow#655). Records are the registry's only record store —
//! catalog reads resolve against the signed index slices the
//! records fold into — never against an edge-side replica.
//!
//! Like `<tag>.bundle`, a records manifest embeds its own Sigstore
//! signature material on [`RECORDS_SIGNATURES_ANNOTATION`] over the
//! canonical unsigned records manifest bytes, so neither publishing nor
//! duplicate-dispatch retagging pushes a standalone `.sig` image.

use std::collections::BTreeMap;

use oci_client::client::{Config, ImageLayer};
use oci_client::manifest::OciImageManifest;
use stow_types::bundle::BundleSignatureMaterial;
use stow_types::error::Context as _;
use stow_types::identity::WireRustcVersion;
use stow_types::records::{
    BuildRecords, BuildRun, RECORDS_ARTIFACT_TYPE, RECORDS_CONFIG_MEDIA_TYPE,
    RECORDS_SIGNATURES_ANNOTATION, RECORDS_TASK_ID_ANNOTATION, RecordsSignature,
    RecordsSignatureEnvelope, is_records_tag, parse_records_tag, published_tag, records_tag,
    task_id_hash,
};
use stow_types::registry::{cache_repository, sha256_digest};

use crate::client::{Presence, RegistrySession, canonical_manifest_bytes};
use crate::publisher::Publisher;
use crate::registry::{pull_blob_verified, pull_tagged_manifest_as};
use crate::verify::{Trust, payload_docker_reference, verify_material, verify_materials};

/// What [`push_records`] did: the tag and signed-manifest digest the
/// records artifact landed under.
#[derive(Debug, Clone)]
pub struct RecordsPublishOutcome {
    /// The OCI tag (`records-<rustc>-<task_id hash>-<run_id>-<run_attempt>`).
    pub tag: String,
    /// Full `registry/repo:tag` reference the artifact signed under.
    pub oci_reference: String,
    /// Digest of the canonical unsigned records manifest the embedded
    /// signature binds.
    pub signed_digest: String,
    /// Digest of the tagged outer manifest carrying the inline signature
    /// annotation.
    pub manifest_digest: String,
}

/// A records artifact read back from the registry, with its inline
/// [`RecordsSignatureEnvelope`] checked for structural coherence against
/// the outer manifest and layer descriptor.
///
/// Signature verification against a trust root and policy runs through
/// [`Self::verify`] or [`Self::verify_marker`].
#[derive(Debug, Clone)]
pub struct PulledRecords {
    /// The artifact's rows.
    pub records: BuildRecords,
    /// Full `registry/repo:tag` transport reference.
    pub oci_reference: String,
    /// Digest of the outer tagged manifest.
    pub manifest_digest: String,
    /// Digest of [`RecordsSignatureEnvelope::signed_manifest`] — what
    /// every embedded signature binds.
    pub signed_digest: String,
    /// The `dev.stow.records.task-id` annotation both manifests carry.
    pub task_id: String,
    /// The inline signature envelope carried on the manifest.
    pub envelope: RecordsSignatureEnvelope,
}

impl PulledRecords {
    /// Require an embedded signature whose certificate satisfies `policy`
    /// to bind `identity_reference` at [`Self::signed_digest`].
    ///
    /// # Errors
    /// Fails when no embedded signature verifies.
    pub fn verify(
        &self,
        trust: &Trust,
        identity_reference: &str,
        policy: &(impl sigstore::bundle::verify::policy::VerificationPolicy + Sync),
    ) -> stow_types::error::Result<()> {
        verify_materials(
            trust,
            identity_reference,
            &self.signed_digest,
            &self.envelope.materials(),
            policy,
        )
    }

    /// Whether an embedded signature satisfies `policy` and binds a
    /// `records-<rustc>-<hash>*` tag of `repository` for [`Self::task_id`]
    /// at [`Self::signed_digest`] — the `built-<rustc>-<hash>` marker
    /// check (stow#877, stow#1627).
    #[must_use]
    pub fn verify_marker(
        &self,
        trust: &Trust,
        repository: &str,
        rustc_version: &str,
        policy: &(impl sigstore::bundle::verify::policy::VerificationPolicy + Sync),
    ) -> bool {
        let expected_hash = task_id_hash(&self.task_id);
        self.envelope.materials().iter().any(|material| {
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
            if parsed.rustc_version != rustc_version || parsed.task_hash != expected_hash.as_str() {
                return false;
            }
            let signature = stow_types::bundle::SigstoreSignature {
                payload_path: material.payload_path.clone(),
                signature: material.signature.clone(),
                certificate_pem: material.certificate_pem.clone(),
                rekor_bundle_json: material.rekor_bundle_json.clone(),
            };
            verify_material(
                trust,
                &bound,
                &self.signed_digest,
                &signature,
                &material.payload_bytes,
                policy,
            )
            .is_ok()
        })
    }
}

/// Assemble an outer records manifest from `signed_manifest` and
/// `signatures`.
///
/// # Errors
/// Fails when `signed_manifest` does not decode as a valid records
/// [`OciImageManifest`] or cannot be serialized.
pub fn records_manifest_with_envelope(
    envelope: &RecordsSignatureEnvelope,
) -> stow_types::error::Result<Vec<u8>> {
    let mut outer: OciImageManifest = serde_json::from_str(&envelope.signed_manifest)
        .wrap_err("parse canonical signed records manifest")?;
    let envelope_json =
        serde_json::to_string(envelope).wrap_err("encode records signature envelope")?;
    outer
        .annotations
        .get_or_insert_with(BTreeMap::new)
        .insert(RECORDS_SIGNATURES_ANNOTATION.to_owned(), envelope_json);
    canonical_manifest_bytes(&outer)
}

/// Push `records` as the signed records artifact `task_id`'s `build`
/// produced, on the production registry.
///
/// # Errors
///
/// Returns an error when signing, a blob upload or a manifest push fails.
pub async fn push_records(
    publisher: &Publisher,
    rustc_version: &WireRustcVersion,
    task_id: &str,
    build: BuildRun,
    records: &BuildRecords,
) -> stow_types::error::Result<RecordsPublishOutcome> {
    let session = publisher.session(&cache_repository(rustc_version))?;
    push_records_with(
        &session,
        rustc_version,
        task_id,
        build,
        records,
        |reference, digest| async move {
            publisher.signer().sign_detached(&reference, &digest).await
        },
    )
    .await
}

/// [`push_records`] with the session and detached signer supplied.
///
/// `sign` signs `(oci_reference, signed_manifest_digest)` in memory and
/// publishes nothing itself; the signature rides on the manifest's
/// [`RECORDS_SIGNATURES_ANNOTATION`].
///
/// # Errors
///
/// Same as [`push_records`].
pub async fn push_records_with<S, Fut>(
    session: &RegistrySession,
    rustc_version: &WireRustcVersion,
    task_id: &str,
    build: BuildRun,
    records: &BuildRecords,
    sign: S,
) -> stow_types::error::Result<RecordsPublishOutcome>
where
    S: Fn(String, String) -> Fut + Send + Sync,
    Fut: Future<Output = stow_types::error::Result<BundleSignatureMaterial>> + Send,
{
    let tag = records_tag(rustc_version.as_str(), task_id, build);
    let reference = session.reference(&tag)?;
    let body = serde_json::to_vec(records)
        .map_err(|error| stow_types::stow_error!("encode records for {task_id}: {error}"))?;
    let layer = ImageLayer::new(body, RECORDS_ARTIFACT_TYPE.to_owned(), None);
    let config_bytes = b"{}".to_vec();

    let mut signed_manifest_obj = OciImageManifest::build(
        std::slice::from_ref(&layer),
        &Config::new(
            config_bytes.clone(),
            RECORDS_CONFIG_MEDIA_TYPE.to_owned(),
            None,
        ),
        Some(BTreeMap::from([(
            RECORDS_TASK_ID_ANNOTATION.to_owned(),
            task_id.to_owned(),
        )])),
    );
    signed_manifest_obj.artifact_type = Some(RECORDS_ARTIFACT_TYPE.to_owned());
    let signed_manifest_bytes = canonical_manifest_bytes(&signed_manifest_obj)?;
    let signed_manifest = String::from_utf8(signed_manifest_bytes)
        .map_err(|error| stow_types::stow_error!("canonical records manifest UTF-8: {error}"))?;
    let signed_digest = sha256_digest(signed_manifest.as_bytes());
    let material = sign(reference.to_string(), signed_digest.clone())
        .await
        .map_err(|error| stow_types::stow_error!("sign records manifest {reference}: {error}"))?;
    let envelope = RecordsSignatureEnvelope {
        signed_manifest,
        signatures: vec![RecordsSignature::from_material(&material)?],
    };
    let outer_bytes = records_manifest_with_envelope(&envelope)?;

    session
        .push_blob_pair(
            (&layer.sha256_digest(), &layer.data),
            (&sha256_digest(&config_bytes), &config_bytes),
        )
        .await
        .map_err(|error| stow_types::stow_error!("push records blobs {reference}: {error}"))?;
    let manifest_digest = session
        .put_manifest(&reference, &outer_bytes)
        .await
        .map_err(|error| stow_types::stow_error!("push records manifest {reference}: {error}"))?;
    // The `built-<rustc>-<task_id hash>` marker points at the same
    // manifest (stow#877): a run checking whether the task's signed
    // records already exist fetches one tag.
    let marker_reference = session.reference(&published_tag(rustc_version.as_str(), task_id))?;
    session
        .put_manifest(&marker_reference, &outer_bytes)
        .await
        .map_err(|error| {
            stow_types::stow_error!("push published marker {marker_reference}: {error}")
        })?;
    tracing::info!(
        oci_reference = %reference,
        digest = %manifest_digest,
        signed_digest = %signed_digest,
        task_id,
        records = records.artifacts.len(),
        local_programs = records.local_programs.len(),
        "pushed and signed records artifact"
    );
    Ok(RecordsPublishOutcome {
        tag,
        oci_reference: reference.to_string(),
        signed_digest,
        manifest_digest,
    })
}

/// Re-tag an already-published records manifest under a duplicate run's tag.
///
/// Uses `envelope.signed_manifest`, whose layer and `{}` config blobs are
/// already stored, under the duplicate run's
/// `records-<rustc>-<hash>-<run>-<attempt>` tag, signing it for that tag
/// without uploading any blob or `.sig` image — one manifest `PUT`
/// (stow#877, stow#1627).
///
/// # Errors
/// Fails when detached signing or the manifest `PUT` fails.
pub async fn retag_records_with<S, Fut>(
    session: &RegistrySession,
    rustc_version: &WireRustcVersion,
    task_id: &str,
    build: BuildRun,
    signed_manifest: &str,
    sign: S,
) -> stow_types::error::Result<RecordsPublishOutcome>
where
    S: FnOnce(String, String) -> Fut,
    Fut: Future<Output = stow_types::error::Result<BundleSignatureMaterial>>,
{
    let tag = records_tag(rustc_version.as_str(), task_id, build);
    let reference = session.reference(&tag)?;
    let signed_digest = sha256_digest(signed_manifest.as_bytes());
    let material = sign(reference.to_string(), signed_digest.clone())
        .await
        .map_err(|error| stow_types::stow_error!("sign retagged records {reference}: {error}"))?;
    let envelope = RecordsSignatureEnvelope {
        signed_manifest: signed_manifest.to_owned(),
        signatures: vec![RecordsSignature::from_material(&material)?],
    };
    let outer_bytes = records_manifest_with_envelope(&envelope)?;
    let manifest_digest = session
        .put_manifest(&reference, &outer_bytes)
        .await
        .map_err(|error| stow_types::stow_error!("retag records manifest {reference}: {error}"))?;
    Ok(RecordsPublishOutcome {
        tag,
        oci_reference: reference.to_string(),
        signed_digest,
        manifest_digest,
    })
}

/// Read back the records artifact `task_id`'s `build` pushed.
///
/// # Errors
///
/// Returns an error when the tag is absent, the manifest or inline
/// signature envelope is malformed, or the layer fails its digest check or
/// decodes wrong.
pub async fn pull_records(
    session: &RegistrySession,
    rustc_version: &str,
    task_id: &str,
    build: BuildRun,
) -> stow_types::error::Result<PulledRecords> {
    let pulled = pull_records_by_tag(session, &records_tag(rustc_version, task_id, build)).await?;
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
/// # Errors
///
/// Same as [`pull_records`].
pub async fn pull_records_by_tag(
    session: &RegistrySession,
    tag: &str,
) -> stow_types::error::Result<PulledRecords> {
    pull_records_by_tag_as(session, tag, Presence::Unknown).await
}

/// [`pull_records_by_tag`] returning `Ok(None)` when `tag` does not
/// exist in the registry.
///
/// # Errors
///
/// Fails on transport refusal or when the present manifest or layer is
/// malformed.
pub async fn pull_optional_records_by_tag(
    session: &RegistrySession,
    tag: &str,
) -> stow_types::error::Result<Option<PulledRecords>> {
    let reference = session.reference(tag)?;
    let (raw_bytes, manifest_digest) = match session.pull_manifest(&reference).await {
        Ok(pulled) => pulled,
        Err(error) if error.is_not_found() => return Ok(None),
        Err(error) => {
            return Err(stow_types::stow_error!(
                "pull records manifest {reference}: {error}"
            ));
        }
    };
    let manifest: OciImageManifest = serde_json::from_slice(&raw_bytes)
        .wrap_err_with(|| format!("decode records manifest {reference}"))?;
    let (task_id, signed_digest, envelope, descriptor) =
        parse_signed_records_manifest(&reference, &manifest)?;
    let bytes = pull_blob_verified(session, descriptor).await?;
    let records: BuildRecords = serde_json::from_slice(&bytes)
        .map_err(|error| stow_types::stow_error!("decode records layer of {reference}: {error}"))?;
    Ok(Some(PulledRecords {
        records,
        oci_reference: reference.to_string(),
        manifest_digest,
        signed_digest,
        task_id,
        envelope,
    }))
}

/// [`pull_records_by_tag`] for a tag taken from the registry's tag listing.
///
/// # Errors
///
/// Same as [`pull_records`].
pub async fn pull_listed_records_by_tag(
    session: &RegistrySession,
    tag: &str,
) -> stow_types::error::Result<PulledRecords> {
    pull_records_by_tag_as(session, tag, Presence::Listed).await
}

/// Validate a records [`OciImageManifest`]'s outer structure and inline
/// [`RecordsSignatureEnvelope`], returning `(task_id, signed_digest, envelope, layer_descriptor)`.
pub fn parse_signed_records_manifest<'a>(
    reference: &oci_client::Reference,
    manifest: &'a OciImageManifest,
) -> stow_types::error::Result<(
    String,
    String,
    RecordsSignatureEnvelope,
    &'a oci_client::manifest::OciDescriptor,
)> {
    if manifest.artifact_type.as_deref() != Some(RECORDS_ARTIFACT_TYPE) {
        return Err(stow_types::stow_error!(
            "{reference} is not a records artifact (artifactType {:?})",
            manifest.artifact_type
        ));
    }
    let annotations = manifest
        .annotations
        .as_ref()
        .ok_or_else(|| stow_types::stow_error!("{reference} carries no annotations"))?;
    let annotated_task_id = annotations.get(RECORDS_TASK_ID_ANNOTATION).ok_or_else(|| {
        stow_types::stow_error!("{reference} carries no {RECORDS_TASK_ID_ANNOTATION} annotation")
    })?;
    let envelope_json = annotations
        .get(RECORDS_SIGNATURES_ANNOTATION)
        .ok_or_else(|| {
            stow_types::stow_error!(
                "{reference} carries no {RECORDS_SIGNATURES_ANNOTATION} annotation"
            )
        })?;
    let envelope: RecordsSignatureEnvelope = serde_json::from_str(envelope_json)
        .wrap_err_with(|| format!("decode {RECORDS_SIGNATURES_ANNOTATION} of {reference}"))?;
    if envelope.signatures.is_empty() {
        return Err(stow_types::stow_error!(
            "{reference} carries an empty {RECORDS_SIGNATURES_ANNOTATION} envelope"
        ));
    }
    let [descriptor] = manifest.layers.as_slice() else {
        return Err(stow_types::stow_error!(
            "records artifact {reference} has {} layers, expected 1",
            manifest.layers.len()
        ));
    };
    if descriptor.media_type != RECORDS_ARTIFACT_TYPE {
        return Err(stow_types::stow_error!(
            "records artifact {reference} layer is {}, not {RECORDS_ARTIFACT_TYPE}",
            descriptor.media_type
        ));
    }

    // Require the signed inner manifest to commit to the exact task id,
    // artifactType and layer descriptor the outer manifest serves.
    let inner: OciImageManifest = serde_json::from_str(&envelope.signed_manifest)
        .wrap_err_with(|| format!("decode signed inner manifest of {reference}"))?;
    if inner.artifact_type.as_deref() != Some(RECORDS_ARTIFACT_TYPE) {
        return Err(stow_types::stow_error!(
            "signed inner manifest of {reference} has artifactType {:?}",
            inner.artifact_type
        ));
    }
    let inner_task_id = inner
        .annotations
        .as_ref()
        .and_then(|map| map.get(RECORDS_TASK_ID_ANNOTATION))
        .ok_or_else(|| {
            stow_types::stow_error!(
                "signed inner manifest of {reference} lacks {RECORDS_TASK_ID_ANNOTATION}"
            )
        })?;
    if inner_task_id != annotated_task_id {
        return Err(stow_types::stow_error!(
            "signed inner manifest of {reference} names task {inner_task_id}, outer names {annotated_task_id}"
        ));
    }
    let [inner_layer] = inner.layers.as_slice() else {
        return Err(stow_types::stow_error!(
            "signed inner manifest of {reference} has {} layers, expected 1",
            inner.layers.len()
        ));
    };
    if inner_layer.media_type != descriptor.media_type
        || inner_layer.digest != descriptor.digest
        || inner_layer.size != descriptor.size
    {
        return Err(stow_types::stow_error!(
            "signed inner manifest of {reference} commits to layer {} ({} B), outer serves {} ({} B)",
            inner_layer.digest,
            inner_layer.size,
            descriptor.digest,
            descriptor.size,
        ));
    }
    let signed_digest = sha256_digest(envelope.signed_manifest.as_bytes());
    Ok((
        annotated_task_id.clone(),
        signed_digest,
        envelope,
        descriptor,
    ))
}

async fn pull_records_by_tag_as(
    session: &RegistrySession,
    tag: &str,
    presence: Presence,
) -> stow_types::error::Result<PulledRecords> {
    let reference = session.reference(tag)?;
    let (manifest_digest, manifest) =
        pull_tagged_manifest_as(session, &reference, presence).await?;
    let (task_id, signed_digest, envelope, descriptor) =
        parse_signed_records_manifest(&reference, &manifest)?;
    let bytes = pull_blob_verified(session, descriptor).await?;
    let records: BuildRecords = serde_json::from_slice(&bytes)
        .map_err(|error| stow_types::stow_error!("decode records layer of {reference}: {error}"))?;
    Ok(PulledRecords {
        records,
        oci_reference: reference.to_string(),
        manifest_digest,
        signed_digest,
        task_id,
        envelope,
    })
}

/// Every `records-*` tag in the session's repository — the export's
/// catalog listing, selected from the repository's full tag listing.
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
