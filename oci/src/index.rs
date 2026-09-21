use std::collections::BTreeMap;

use oci_client::Reference;
use oci_client::client::{Client, Config, ImageLayer};
use oci_client::errors::{OciDistributionError, OciErrorCode};
use oci_client::manifest::{OciImageManifest, OciManifest};
use oci_client::secrets::RegistryAuth;
use stow_types::bundle::sigstore_signature_tag;
use stow_types::index::{STOW_INDEX_CONFIG_MEDIA_TYPE, STOW_INDEX_MEDIA_TYPE, index_tag};
use stow_types::registry::GHCR_BASE;

use crate::registry::{RegistryCredentials, registry_client};
use crate::sign;

/// Manifest annotation carrying the index's content digest — the
/// `content_sha256` of everything except the wall-clock `generated_at`.
/// Publishing compares it to decide whether the slice changed; the blob
/// digest can never signal that because `generated_at` makes every
/// export's bytes unique.
const INDEX_CONTENT_SHA256_ANNOTATION: &str = "dev.stow.index.content-sha256";

/// What `publish_index` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexPublishOutcome {
    /// The index was pushed and signed.
    Published {
        /// Digest of the manifest the tag now resolves to.
        manifest_digest: String,
    },
    /// The published tag already carries this exact content digest —
    /// nothing was pushed or re-signed.
    Unchanged {
        /// Digest of the manifest the tag resolves to.
        manifest_digest: String,
    },
    /// The published tag already carries this exact content digest but
    /// its `sha256-<digest>.sig` tag was missing, so the existing
    /// manifest was signed again without a push.
    Resigned {
        /// Digest of the manifest the tag resolves to.
        manifest_digest: String,
    },
}

/// Whether the registry holds a signature manifest for `manifest_digest`
/// under the tag the CLI reads.
///
/// # Errors
///
/// Returns an error when the signature reference does not parse or the
/// registry answers anything other than found / not found.
async fn signature_present(
    client: &Client,
    auth: &RegistryAuth,
    reference: &Reference,
    manifest_digest: &str,
) -> stow_types::error::Result<bool> {
    let signature_reference: Reference = format!(
        "{}/{}:{}",
        reference.registry(),
        reference.repository(),
        sigstore_signature_tag(manifest_digest)
    )
    .parse()
    .map_err(|error| stow_types::stow_error!("parse signature reference: {error}"))?;
    match client
        .fetch_manifest_digest(&signature_reference, auth)
        .await
    {
        Ok(_) => Ok(true),
        Err(error) if manifest_not_found(&error) => Ok(false),
        Err(error) => Err(stow_types::stow_error!(
            "fetch signature manifest {signature_reference}: {error}"
        )),
    }
}

/// The `content-sha256` annotation of the manifest the tag currently
/// carries, and that manifest's digest — `None` when the tag does not
/// exist yet or carries no annotation.
///
/// # Errors
///
/// Returns an error when the reference does not parse, the pull fails,
/// or the tag resolves to an image index instead of an image manifest.
pub async fn published_index_content_sha256(
    client: &Client,
    auth: &RegistryAuth,
    reference: &str,
) -> stow_types::error::Result<Option<(String, String)>> {
    let reference: Reference = reference
        .parse()
        .map_err(|error| stow_types::stow_error!("parse index reference {reference}: {error}"))?;
    match client.pull_manifest(&reference, auth).await {
        Ok((OciManifest::Image(manifest), digest)) => {
            let content_sha256 = manifest
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(INDEX_CONTENT_SHA256_ANNOTATION).cloned());
            Ok(content_sha256.map(|sha256| (sha256, digest)))
        }
        Ok((OciManifest::ImageIndex(_), _)) => Err(stow_types::stow_error!(
            "index reference {reference} resolves to an image index, not an image manifest"
        )),
        Err(error) if manifest_not_found(&error) => Ok(None),
        Err(error) => Err(stow_types::stow_error!(
            "pull index manifest {reference}: {error}"
        )),
    }
}

/// Push `index_bytes` as the single-layer index artifact under the slice's
/// tag and sign it with cosign.
///
/// The manifest carries `dev.stow.index.content-sha256` so a later publish
/// of byte-identical content — a re-export of unchanged rows — skips the
/// push. The signature is skipped only when its `.sig` tag is actually
/// there: a slice whose signature never landed (or landed in a layout the
/// CLI does not read) is signed again in place.
///
/// # Errors
///
/// Returns an error when the manifest pull/push, the digest fetch, or the
/// cosign signature fails.
pub async fn publish_index(
    credentials: &RegistryCredentials,
    index_bytes: &[u8],
    target: &str,
    rustc_version: &str,
    content_sha256: &str,
) -> stow_types::error::Result<IndexPublishOutcome> {
    let (client, auth) = registry_client(credentials);
    let reference = format!("{GHCR_BASE}:{}", index_tag(target, rustc_version));
    let parsed_reference: Reference = reference
        .parse()
        .map_err(|error| stow_types::stow_error!("parse index reference {reference}: {error}"))?;

    if let Some((published_sha256, manifest_digest)) =
        published_index_content_sha256(&client, &auth, &reference).await?
        && published_sha256 == content_sha256
    {
        if signature_present(&client, &auth, &parsed_reference, &manifest_digest).await? {
            tracing::info!(
                %reference,
                %manifest_digest,
                "published index already carries this content; skipping push"
            );
            return Ok(IndexPublishOutcome::Unchanged { manifest_digest });
        }
        tracing::warn!(
            %reference,
            %manifest_digest,
            "published index carries this content but no signature tag; signing in place"
        );
        sign::sign_artifact(&reference, &manifest_digest, credentials).await?;
        return Ok(IndexPublishOutcome::Resigned { manifest_digest });
    }

    let layer = ImageLayer::new(index_bytes.to_vec(), STOW_INDEX_MEDIA_TYPE.to_owned(), None);
    let config = Config::new(
        b"{}".to_vec(),
        STOW_INDEX_CONFIG_MEDIA_TYPE.to_owned(),
        None,
    );
    let manifest = OciImageManifest::build(
        std::slice::from_ref(&layer),
        &config,
        Some(BTreeMap::from([(
            INDEX_CONTENT_SHA256_ANNOTATION.to_owned(),
            content_sha256.to_owned(),
        )])),
    );
    crate::backpressure::retrying_rate_limits("push index", || {
        client.push(
            &parsed_reference,
            std::slice::from_ref(&layer),
            config.clone(),
            &auth,
            Some(manifest.clone()),
        )
    })
    .await
    .map_err(|error| stow_types::stow_error!("push index artifact {reference}: {error}"))?;
    let manifest_digest =
        crate::backpressure::retrying_rate_limits("fetch index manifest digest", || {
            client.fetch_manifest_digest(&parsed_reference, &auth)
        })
        .await
        .map_err(|error| {
            stow_types::stow_error!("fetch index manifest digest for {reference}: {error}")
        })?;
    tracing::info!(
        %reference,
        digest = %manifest_digest,
        "pushed artifact index to GHCR"
    );

    sign::sign_artifact(&reference, &manifest_digest, credentials).await?;

    Ok(IndexPublishOutcome::Published { manifest_digest })
}

/// Whether an `oci-client` error is the registry reporting the tag absent —
/// a `MANIFEST_UNKNOWN`/`NOT_FOUND` envelope, or a bare 404 from a registry
/// that does not emit the OCI error envelope.
fn manifest_not_found(error: &OciDistributionError) -> bool {
    match error {
        OciDistributionError::RegistryError { envelope, .. } => {
            envelope.errors.iter().any(|entry| {
                matches!(
                    entry.code,
                    OciErrorCode::ManifestUnknown | OciErrorCode::NotFound
                )
            })
        }
        OciDistributionError::ServerError { code, .. } => *code == 404,
        OciDistributionError::ImageManifestNotFoundError(_) => true,
        _ => false,
    }
}
