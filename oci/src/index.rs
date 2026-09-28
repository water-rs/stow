use std::collections::BTreeMap;

use oci_client::Reference;
use oci_client::client::{Config, ImageLayer};
use oci_client::manifest::{OciImageManifest, OciManifest};
use stow_types::bundle::sigstore_signature_tag;
use stow_types::index::{
    STOW_FOLDED_CONFIG_MEDIA_TYPE, STOW_FOLDED_MEDIA_TYPE, STOW_INDEX_CONFIG_MEDIA_TYPE,
    STOW_INDEX_MEDIA_TYPE, folded_tag, index_tag,
};
use stow_types::registry::{GHCR_BASE, sha256_digest};

use crate::client::{RegistrySession, canonical_manifest_bytes};
use crate::registry::{RegistryBase, RegistryCredentials, pull_blob_verified};
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

/// Whether the digest's `.sig` manifest already carries a signature
/// whose payload binds `identity_reference` — the `repo:tag` the
/// signature claims. Tag existence is not enough: several tags may share
/// one manifest digest, and the `.sig` then names whichever references
/// were actually signed — a tag absent from it is still owed its own
/// signature even though the `.sig` manifest exists.
///
/// # Errors
///
/// Returns an error when the signature manifest pull fails for any
/// reason other than absence, or a payload cannot be read.
async fn signature_present(
    session: &RegistrySession,
    reference: &Reference,
    manifest_digest: &str,
    identity_reference: &str,
) -> stow_types::error::Result<bool> {
    let signature_reference: Reference = format!(
        "{}/{}:{}",
        reference.registry(),
        reference.repository(),
        sigstore_signature_tag(manifest_digest)
    )
    .parse()
    .map_err(|error| stow_types::stow_error!("parse signature reference: {error}"))?;
    match session.fetch_manifest_digest(&signature_reference).await {
        Ok(_) => {}
        Err(error) if error.is_not_found() => return Ok(false),
        Err(error) => {
            return Err(stow_types::stow_error!(
                "fetch signature manifest {signature_reference}: {error}"
            ));
        }
    }
    let materials =
        crate::artifacts::pull_signature_materials(session, reference, manifest_digest).await?;
    Ok(materials.iter().any(|material| {
        crate::verify::verify_payload_identity(
            &material.payload_bytes,
            identity_reference,
            manifest_digest,
        )
        .is_ok()
    }))
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
    session: &RegistrySession,
    reference: &str,
) -> stow_types::error::Result<Option<(String, String)>> {
    let reference: Reference = reference
        .parse()
        .map_err(|error| stow_types::stow_error!("parse index reference {reference}: {error}"))?;
    let (bytes, digest) = match session.pull_manifest(&reference).await {
        Ok(pulled) => pulled,
        Err(error) if error.is_not_found() => return Ok(None),
        Err(error) => {
            return Err(stow_types::stow_error!(
                "pull index manifest {reference}: {error}"
            ));
        }
    };
    match serde_json::from_slice(&bytes)
        .map_err(|error| stow_types::stow_error!("parse index manifest {reference}: {error}"))?
    {
        OciManifest::Image(manifest) => {
            let content_sha256 = manifest
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(INDEX_CONTENT_SHA256_ANNOTATION).cloned());
            Ok(content_sha256.map(|sha256| (sha256, digest)))
        }
        OciManifest::ImageIndex(_) => Err(stow_types::stow_error!(
            "index reference {reference} resolves to an image index, not an image manifest"
        )),
    }
}

/// Pull the index blob the slice's tag currently resolves to.
///
/// The previous index `stow-admin index export` bases its generation
/// stamp and `index report` bases its delta on. `None` when the tag
/// does not exist yet (first publish).
///
/// # Errors
///
/// Returns an error when the reference does not parse, the pull fails,
/// the tag resolves to an image index, or the manifest has no layer.
pub async fn pull_published_index(
    session: &RegistrySession,
    target: &str,
    rustc_version: &str,
) -> stow_types::error::Result<Option<Vec<u8>>> {
    let reference = format!("{GHCR_BASE}:{}", index_tag(target, rustc_version));
    let parsed_reference: Reference = reference
        .parse()
        .map_err(|error| stow_types::stow_error!("parse index reference {reference}: {error}"))?;
    let (manifest_bytes, _) = match session.pull_manifest(&parsed_reference).await {
        Ok(pulled) => pulled,
        Err(error) if error.is_not_found() => return Ok(None),
        Err(error) => {
            return Err(stow_types::stow_error!(
                "pull index manifest {reference}: {error}"
            ));
        }
    };
    match serde_json::from_slice(&manifest_bytes)
        .map_err(|error| stow_types::stow_error!("parse index manifest {reference}: {error}"))?
    {
        OciManifest::Image(manifest) => {
            let layer = manifest.layers.first().ok_or_else(|| {
                stow_types::stow_error!("index manifest {reference} carries no layer")
            })?;
            session
                .pull_blob(&layer.digest)
                .await
                .map(Some)
                .map_err(|error| stow_types::stow_error!("pull index blob {reference}: {error}"))
        }
        OciManifest::ImageIndex(_) => Err(stow_types::stow_error!(
            "index reference {reference} resolves to an image index, not an image manifest"
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
/// Returns an error when the manifest pull/push, the blob uploads, or the
/// cosign signature fails.
pub async fn publish_index(
    credentials: &RegistryCredentials,
    index_bytes: &[u8],
    target: &str,
    rustc_version: &str,
    content_sha256: &str,
) -> stow_types::error::Result<IndexPublishOutcome> {
    let session = credentials.session()?;
    let reference = format!("{GHCR_BASE}:{}", index_tag(target, rustc_version));
    let parsed_reference: Reference = reference
        .parse()
        .map_err(|error| stow_types::stow_error!("parse index reference {reference}: {error}"))?;

    if let Some((published_sha256, manifest_digest)) =
        published_index_content_sha256(&session, &reference).await?
        && published_sha256 == content_sha256
    {
        if signature_present(&session, &parsed_reference, &manifest_digest, &reference).await? {
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
    session
        .push_blob(&layer.sha256_digest(), &layer.data)
        .await
        .map_err(|error| stow_types::stow_error!("push index artifact {reference}: {error}"))?;
    session
        .push_blob(&sha256_digest(&config.data), &config.data)
        .await
        .map_err(|error| stow_types::stow_error!("push index artifact {reference}: {error}"))?;
    let manifest_bytes = canonical_manifest_bytes(&manifest)?;
    let manifest_digest =
        sign::put_signed_manifest(&session, &parsed_reference, &manifest_bytes, |digest| {
            let reference = &reference;
            async move { sign::sign_artifact(reference, &digest, credentials).await }
        })
        .await
        .map_err(|error| stow_types::stow_error!("push index artifact {reference}: {error}"))?;
    tracing::info!(
        %reference,
        digest = %manifest_digest,
        "pushed and signed artifact index on GHCR"
    );

    Ok(IndexPublishOutcome::Published { manifest_digest })
}

/// A published index slice pulled back: the raw layer bytes plus the
/// manifest digest the puller verifies a signature for. Decode is the
/// caller's — it owns the recovery an unreadable format names.
#[derive(Debug)]
pub struct PulledIndex {
    /// The slice's encoded body.
    pub bytes: Vec<u8>,
    /// Digest of the manifest the tag resolved to — the input to
    /// `pull_signature_materials`.
    pub manifest_digest: String,
}

/// Pull the published `index.<target>.<rustc>` slice: `None` when the tag
/// does not exist, the verified manifest digest otherwise.
///
/// # Errors
///
/// Returns an error when the pull fails, the manifest is malformed for an
/// index artifact, or the layer fails its digest check.
pub async fn pull_index(
    session: &RegistrySession,
    base: &RegistryBase,
    target: &str,
    rustc_version: &str,
) -> stow_types::error::Result<Option<PulledIndex>> {
    let tag = index_tag(target, rustc_version);
    let reference = base.reference(&tag)?;
    let (bytes, manifest_digest) = match session.pull_manifest(&reference).await {
        Ok(pulled) => pulled,
        Err(error) if error.is_not_found() => return Ok(None),
        Err(error) => {
            return Err(stow_types::stow_error!(
                "pull index manifest {reference}: {error}"
            ));
        }
    };
    let manifest: OciImageManifest = serde_json::from_slice(&bytes)
        .map_err(|error| stow_types::stow_error!("parse index manifest {reference}: {error}"))?;
    let descriptor = manifest
        .layers
        .first()
        .ok_or_else(|| stow_types::stow_error!("index artifact {reference} has no layers"))?;
    if descriptor.media_type != STOW_INDEX_MEDIA_TYPE {
        return Err(stow_types::stow_error!(
            "index artifact {reference} layer is {}, not {STOW_INDEX_MEDIA_TYPE}",
            descriptor.media_type
        ));
    }
    let bytes = pull_blob_verified(session, descriptor).await?;
    Ok(Some(PulledIndex {
        bytes,
        manifest_digest,
    }))
}

/// A published folded set pulled back: the sorted records-tag list plus
/// the manifest digest the puller verifies a signature for.
#[derive(Debug)]
pub struct PulledFolded {
    /// The tags already folded into the sibling index slice, sorted.
    pub tags: Vec<String>,
    /// Digest of the manifest the tag resolved to — the input to
    /// `pull_signature_materials`.
    pub manifest_digest: String,
}

/// Pull the published `folded.<target>.<rustc>` artifact: `None` when the
/// tag does not exist.
///
/// # Errors
///
/// Returns an error when the pull fails or the artifact is malformed.
pub async fn pull_folded(
    session: &RegistrySession,
    base: &RegistryBase,
    target: &str,
    rustc_version: &str,
) -> stow_types::error::Result<Option<PulledFolded>> {
    let tag = folded_tag(target, rustc_version);
    let reference = base.reference(&tag)?;
    let (bytes, manifest_digest) = match session.pull_manifest(&reference).await {
        Ok(pulled) => pulled,
        Err(error) if error.is_not_found() => return Ok(None),
        Err(error) => {
            return Err(stow_types::stow_error!(
                "pull folded manifest {reference}: {error}"
            ));
        }
    };
    let manifest: OciImageManifest = serde_json::from_slice(&bytes)
        .map_err(|error| stow_types::stow_error!("parse folded manifest {reference}: {error}"))?;
    let descriptor = manifest
        .layers
        .first()
        .ok_or_else(|| stow_types::stow_error!("folded artifact {reference} has no layers"))?;
    if descriptor.media_type != STOW_FOLDED_MEDIA_TYPE {
        return Err(stow_types::stow_error!(
            "folded artifact {reference} layer is {}, not {STOW_FOLDED_MEDIA_TYPE}",
            descriptor.media_type
        ));
    }
    let bytes = pull_blob_verified(session, descriptor).await?;
    let tags: Vec<String> = serde_json::from_slice(&bytes)
        .map_err(|error| stow_types::stow_error!("decode folded layer of {reference}: {error}"))?;
    Ok(Some(PulledFolded {
        tags,
        manifest_digest,
    }))
}

/// Push and sign the `folded.<target>.<rustc>` companion artifact.
///
/// `index publish` performs it under the index workflow's identity. The
/// content is deterministic (the sorted tag list), so the published
/// manifest digest itself is the change check: a matching digest means
/// neither a push nor a signature is owed.
///
/// # Errors
///
/// Same as [`publish_index`].
pub async fn publish_folded(
    credentials: &RegistryCredentials,
    folded_bytes: &[u8],
    target: &str,
    rustc_version: &str,
) -> stow_types::error::Result<IndexPublishOutcome> {
    let session = credentials.session()?;
    let reference = format!("{GHCR_BASE}:{}", folded_tag(target, rustc_version));
    let parsed_reference: Reference = reference
        .parse()
        .map_err(|error| stow_types::stow_error!("parse folded reference {reference}: {error}"))?;

    let layer = ImageLayer::new(
        folded_bytes.to_vec(),
        STOW_FOLDED_MEDIA_TYPE.to_owned(),
        None,
    );
    let config = Config::new(
        b"{}".to_vec(),
        STOW_FOLDED_CONFIG_MEDIA_TYPE.to_owned(),
        None,
    );
    let manifest = OciImageManifest::build(std::slice::from_ref(&layer), &config, None);
    let manifest_bytes = canonical_manifest_bytes(&manifest)?;
    let expected_digest = sha256_digest(&manifest_bytes);

    match session.fetch_manifest_digest(&parsed_reference).await {
        Ok(published_digest) if published_digest == expected_digest => {
            if signature_present(&session, &parsed_reference, &published_digest, &reference).await?
            {
                tracing::info!(%reference, "published folded set already carries this content");
                return Ok(IndexPublishOutcome::Unchanged {
                    manifest_digest: published_digest,
                });
            }
            sign::sign_artifact(&reference, &published_digest, credentials).await?;
            return Ok(IndexPublishOutcome::Resigned {
                manifest_digest: published_digest,
            });
        }
        Ok(_) => {}
        Err(error) if error.is_not_found() => {}
        Err(error) => {
            return Err(stow_types::stow_error!(
                "fetch folded manifest {reference}: {error}"
            ));
        }
    }

    session
        .push_blob(&layer.sha256_digest(), &layer.data)
        .await
        .map_err(|error| stow_types::stow_error!("push folded artifact {reference}: {error}"))?;
    session
        .push_blob(&sha256_digest(&config.data), &config.data)
        .await
        .map_err(|error| stow_types::stow_error!("push folded artifact {reference}: {error}"))?;
    let manifest_digest =
        sign::put_signed_manifest(&session, &parsed_reference, &manifest_bytes, |digest| {
            let reference = &reference;
            async move { sign::sign_artifact(reference, &digest, credentials).await }
        })
        .await
        .map_err(|error| stow_types::stow_error!("push folded artifact {reference}: {error}"))?;
    tracing::info!(
        %reference,
        digest = %manifest_digest,
        "pushed and signed folded set on GHCR"
    );

    Ok(IndexPublishOutcome::Published { manifest_digest })
}
