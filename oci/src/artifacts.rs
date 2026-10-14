use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use async_fs::read;
use oci_client::Reference;
use oci_client::client::{Config, ImageLayer};
use oci_client::manifest::OciImageManifest;
use stow_types::bundle::{
    ArtifactBlobConfig, BundleArtifactConfig, BundleLayer, BundleParts, BundleSignatureMaterial,
    SIGSTORE_BUNDLE_ANNOTATION, SIGSTORE_CERT_ANNOTATION, SIGSTORE_OCI_MEDIA_TYPE,
    SIGSTORE_SIGNATURE_ANNOTATION, STOW_ARTIFACT_CONFIG_MEDIA_TYPE, STOW_BUNDLE_CONFIG_MEDIA_TYPE,
    STOW_BUNDLE_MEDIA_TYPE, assemble_bundle, sigstore_payload_path, sigstore_signature_tag,
};
use stow_types::bundle_schema::validate_bundle_schema;
use stow_types::registry::{bundle_oci_reference, sha256_digest};
use stow_types::upload_plan::{PlannedArtifact, PlannedArtifactOutput, PublishedArtifact};

use crate::client::{RegistryError, RegistryHttp, RegistrySession, canonical_manifest_bytes};
use crate::registry::RegistryCredentials;
use crate::retry::retry_with_backoff;
use crate::sign;

/// What [`push_artifacts`] did: the published coordinates of every plan.
#[derive(Debug, Clone)]
pub struct UploadOutcome {
    /// Registry coordinates of every plan, keyed by `oci_reference`.
    pub published_by_reference: BTreeMap<String, PublishedArtifact>,
    /// How many artifacts were pushed this run.
    pub newly_pushed: u32,
}

/// Publish every plan: push the artifact, sign it, assemble the bundle
/// tar, and push that as the `<tag>.bundle` artifact.
///
/// One session mints one bearer for the whole batch, and one plan at a time
/// keeps the layer bytes of only one artifact ever in memory.
///
/// # Errors
///
/// Returns an error when a push, the cosign signature, or a bundle pull
/// fails; the registry round-trip error names the plan's OCI reference.
pub async fn push_artifacts(
    plans: &[PlannedArtifact],
    credentials: &RegistryCredentials,
    http: &RegistryHttp,
) -> stow_types::error::Result<UploadOutcome> {
    let session = credentials.session(http)?;
    push_artifacts_with(&session, plans, |reference, digest| async move {
        sign::sign_artifact(&reference, &digest, credentials).await
    })
    .await
}

/// [`push_artifacts`] with the session and signer supplied — the mock
/// registry test pushes through this with an in-process signer so no cosign
/// binary is involved.
///
/// `sign` is invoked once per plan with `(oci_reference, manifest_digest)`.
///
/// # Errors
///
/// Same as [`push_artifacts`].
pub async fn push_artifacts_with<S, Fut>(
    session: &RegistrySession,
    plans: &[PlannedArtifact],
    sign: S,
) -> stow_types::error::Result<UploadOutcome>
where
    S: Fn(String, String) -> Fut + Send + Sync,
    Fut: Future<Output = stow_types::error::Result<()>> + Send,
{
    let mut published = BTreeMap::new();
    let mut newly_pushed = 0u32;

    for plan in plans {
        let artifact = publish_artifact(session, plan, &sign).await?;
        published.insert(plan.oci_reference.clone(), artifact);
        newly_pushed = newly_pushed.saturating_add(1);
    }

    Ok(UploadOutcome {
        published_by_reference: published,
        newly_pushed,
    })
}

async fn publish_artifact<S, Fut>(
    session: &RegistrySession,
    plan: &PlannedArtifact,
    sign: &S,
) -> stow_types::error::Result<PublishedArtifact>
where
    S: Fn(String, String) -> Fut + Send + Sync,
    Fut: Future<Output = stow_types::error::Result<()>> + Send,
{
    let reference: Reference = plan.oci_reference.parse().map_err(|error| {
        stow_types::stow_error!("parse OCI reference {}: {error}", plan.oci_reference)
    })?;
    let config = artifact_config(plan);
    let config_bytes = serde_json::to_vec(&config)?;
    let layers = build_layers(plan).await?;

    // Push order matches the manifest the bytes describe: every layer, then
    // the config blob, then the manifest. A blob already stored under its
    // digest is skipped by `push_blob`'s HEAD — content addressing means it
    // can only be the same bytes.
    for layer in &layers {
        session
            .push_blob(&layer.sha256_digest(), &layer.data)
            .await
            .map_err(|error| {
                stow_types::stow_error!("push OCI artifact {}: {error}", plan.oci_reference)
            })?;
    }
    session
        .push_blob(&sha256_digest(&config_bytes), &config_bytes)
        .await
        .map_err(|error| {
            stow_types::stow_error!("push OCI artifact {}: {error}", plan.oci_reference)
        })?;
    let manifest = OciImageManifest::build(
        &layers,
        &Config::new(
            config_bytes.clone(),
            STOW_ARTIFACT_CONFIG_MEDIA_TYPE.to_owned(),
            None,
        ),
        None,
    );
    let manifest_bytes = canonical_manifest_bytes(&manifest)?;
    let oci_digest = sign::put_signed_manifest(session, &reference, &manifest_bytes, |digest| {
        sign(plan.oci_reference.clone(), digest)
    })
    .await
    .map_err(|error| {
        stow_types::stow_error!("push OCI artifact {}: {error}", plan.oci_reference)
    })?;
    tracing::info!(
        oci_reference = %plan.oci_reference,
        digest = %oci_digest,
        "pushed and signed OCI artifact on GHCR"
    );

    let signatures = pull_pushed_signature_materials(session, &reference, &oci_digest).await?;

    let (bundle_digest, bundle_size) = push_bundle(
        session,
        &BundleParts {
            oci_reference: &plan.oci_reference,
            oci_digest: &oci_digest,
            manifest_bytes: &manifest_bytes,
            config_bytes: &config_bytes,
            config: &config,
            signatures: &signatures,
            layers: &layers
                .iter()
                .map(|layer| BundleLayer {
                    media_type: &layer.media_type,
                    bytes: &layer.data,
                })
                .collect::<Vec<_>>(),
        },
    )
    .await?;

    Ok(PublishedArtifact {
        oci_digest,
        bundle_digest,
        bundle_size,
    })
}

/// Assemble the bundle tar, validate it, and push it as the `<tag>.bundle`
/// artifact. Returns the bundle layer's digest and size — the coordinates
/// the edge streams it by.
async fn push_bundle(
    session: &RegistrySession,
    parts: &BundleParts<'_>,
) -> stow_types::error::Result<(String, u64)> {
    let oci_reference = parts.oci_reference;
    let bundle_bytes = assemble_bundle(parts)
        .map_err(|error| stow_types::stow_error!("assemble bundle for {oci_reference}: {error}"))?;
    validate_bundle_schema(&bundle_bytes).map_err(|error| {
        stow_types::stow_error!("bundle for {oci_reference} failed schema validation: {error}")
    })?;

    let bundle_reference = bundle_oci_reference(oci_reference)
        .ok_or_else(|| stow_types::stow_error!("no bundle reference fits for {oci_reference}"))?;
    let bundle_size = u64::try_from(bundle_bytes.len())
        .map_err(|_| stow_types::stow_error!("bundle for {oci_reference} exceeds u64 bytes"))?;
    let bundle_layer = ImageLayer::new(bundle_bytes, STOW_BUNDLE_MEDIA_TYPE.to_owned(), None);
    let bundle_digest = bundle_layer.sha256_digest();
    let bundle_config = serde_json::to_vec(&BundleArtifactConfig {
        oci_reference: oci_reference.to_owned(),
        oci_digest: parts.oci_digest.to_owned(),
    })?;
    let parsed_bundle_reference: Reference = bundle_reference.parse().map_err(|error| {
        stow_types::stow_error!("parse bundle reference {bundle_reference}: {error}")
    })?;
    session
        .push_blob(&bundle_digest, &bundle_layer.data)
        .await
        .map_err(|error| {
            stow_types::stow_error!("push bundle artifact {bundle_reference}: {error}")
        })?;
    session
        .push_blob(&sha256_digest(&bundle_config), &bundle_config)
        .await
        .map_err(|error| {
            stow_types::stow_error!("push bundle artifact {bundle_reference}: {error}")
        })?;
    let manifest = OciImageManifest::build(
        std::slice::from_ref(&bundle_layer),
        &Config::new(
            bundle_config,
            STOW_BUNDLE_CONFIG_MEDIA_TYPE.to_owned(),
            None,
        ),
        None,
    );
    let manifest_bytes = canonical_manifest_bytes(&manifest)?;
    session
        .put_manifest(&parsed_bundle_reference, &manifest_bytes)
        .await
        .map_err(|error| {
            stow_types::stow_error!("push bundle artifact {bundle_reference}: {error}")
        })?;
    tracing::info!(
        bundle_reference = %bundle_reference,
        bundle_digest = %bundle_digest,
        bundle_size,
        "pushed bundle artifact to GHCR"
    );
    Ok((bundle_digest, bundle_size))
}

/// Pull every `sha256-<hex>.sig` signature layer for `oci_digest`.
///
/// One material per simple-signing layer: payload path and bytes,
/// signature, certificate, and the Rekor bundle when cosign uploaded one.
/// Shared by the bundle republish path and the CLI's index verification.
///
/// This is the read for a signature published earlier or by someone else:
/// a `404` is the answer — the signature does not exist. For a signature
/// this publish just pushed, use [`pull_pushed_signature_materials`].
///
/// # Errors
///
/// Returns an error when the signature manifest or a layer cannot be pulled
/// or parsed.
pub async fn pull_signature_materials(
    session: &RegistrySession,
    reference: &Reference,
    oci_digest: &str,
) -> stow_types::error::Result<Vec<BundleSignatureMaterial>> {
    let signature_reference = signature_reference(reference, oci_digest)?;
    let (manifest_bytes, _) =
        session
            .pull_manifest(&signature_reference)
            .await
            .map_err(|error| {
                stow_types::stow_error!("pull signature manifest {signature_reference}: {error}")
            })?;
    // `Box::pin` keeps the shared tail's future out of the callers' — the
    // CLI's `run_cli` tree measures these reads inside one large future.
    Box::pin(signature_materials(
        session,
        &signature_reference,
        &manifest_bytes,
    ))
    .await
}

/// How many times the read-back of a signature this publish just pushed
/// runs before its absence is final. The registry may not show a tag the
/// instant its push returned — run 38377192790 read the `.sig` tag 70 ms
/// after cosign's push and got `MANIFEST_UNKNOWN` — and a tag this
/// process pushed cannot legitimately be absent, so the bound is what
/// separates a registry catching up from a push that never landed
/// (stow#709).
const PUSHED_READ_MAX_ATTEMPTS: u32 = 5;

/// The first retry's delay; doubling across the attempts yields 200, 400,
/// 800 and 1600 ms — three seconds in all.
const PUSHED_READ_INITIAL_DELAY: Duration = Duration::from_millis(200);

/// Pull every `sha256-<hex>.sig` signature layer for a manifest this
/// publish has just signed and pushed.
///
/// The registry may not show a tag the instant its push returned, so the
/// manifest pull retries a `404` within [`PUSHED_READ_MAX_ATTEMPTS`]
/// before its absence is final. Use this only right after pushing the
/// signature in the same publish; every other read goes through
/// [`pull_signature_materials`], where a `404` is the answer.
///
/// # Errors
///
/// Same as [`pull_signature_materials`].
pub async fn pull_pushed_signature_materials(
    session: &RegistrySession,
    reference: &Reference,
    oci_digest: &str,
) -> stow_types::error::Result<Vec<BundleSignatureMaterial>> {
    let signature_reference = signature_reference(reference, oci_digest)?;
    let (manifest_bytes, _) = retry_with_backoff(
        "read back the pushed signature",
        PUSHED_READ_MAX_ATTEMPTS,
        PUSHED_READ_INITIAL_DELAY,
        || session.pull_manifest(&signature_reference),
        RegistryError::is_not_found,
    )
    .await
    .map_err(|error| {
        stow_types::stow_error!("pull signature manifest {signature_reference}: {error}")
    })?;
    Box::pin(signature_materials(
        session,
        &signature_reference,
        &manifest_bytes,
    ))
    .await
}

/// The `sha256-<hex>.sig` reference `oci_digest`'s signature manifest
/// sits under in `reference`'s registry and repository.
fn signature_reference(
    reference: &Reference,
    oci_digest: &str,
) -> stow_types::error::Result<Reference> {
    Ok(format!(
        "{}/{}:{}",
        reference.registry(),
        reference.repository(),
        sigstore_signature_tag(oci_digest)
    )
    .parse()?)
}

/// The materials of the signature manifest `signature_reference` pulled —
/// the part of the read [`pull_signature_materials`] and
/// [`pull_pushed_signature_materials`] share once the manifest bytes are
/// in hand.
async fn signature_materials(
    session: &RegistrySession,
    signature_reference: &Reference,
    manifest_bytes: &[u8],
) -> stow_types::error::Result<Vec<BundleSignatureMaterial>> {
    let manifest: OciImageManifest = serde_json::from_slice(manifest_bytes).map_err(|error| {
        stow_types::stow_error!("parse signature manifest {signature_reference}: {error}")
    })?;
    let mut materials = Vec::new();
    for (index, descriptor) in manifest.layers.iter().enumerate() {
        if descriptor.media_type != SIGSTORE_OCI_MEDIA_TYPE {
            continue;
        }
        let annotations = descriptor.annotations.as_ref().ok_or_else(|| {
            stow_types::stow_error!(
                "signature layer {index} of {signature_reference} has no annotations"
            )
        })?;
        let annotation = |name: &str| {
            annotations.get(name).cloned().ok_or_else(|| {
                stow_types::stow_error!(
                    "signature layer {index} of {signature_reference} lacks {name}"
                )
            })
        };
        let signature = annotation(SIGSTORE_SIGNATURE_ANNOTATION)?;
        let certificate_pem = annotation(SIGSTORE_CERT_ANNOTATION)?;
        let rekor_bundle_json = annotations.get(SIGSTORE_BUNDLE_ANNOTATION).cloned();
        let payload_bytes = session
            .pull_blob(&descriptor.digest)
            .await
            .map_err(|error| {
                stow_types::stow_error!(
                    "pull signature payload {} of {signature_reference}: {error}",
                    descriptor.digest
                )
            })?;
        materials.push(BundleSignatureMaterial {
            payload_path: sigstore_payload_path(index),
            payload_bytes,
            signature,
            certificate_pem,
            rekor_bundle_json,
        });
    }
    if materials.is_empty() {
        return Err(stow_types::stow_error!(
            "signature image {signature_reference} carries no simple-signing layer"
        ));
    }
    Ok(materials)
}

fn artifact_config(plan: &PlannedArtifact) -> ArtifactBlobConfig {
    ArtifactBlobConfig {
        compile_key: plan.compile_key.clone(),
        crate_name: plan.crate_name.clone(),
        crate_version: plan.crate_version.clone(),
        c_metadata: plan.c_metadata.clone(),
        extra_filename: plan.extra_filename.clone(),
        target: plan.target.clone(),
        rustc_version: plan.rustc_version.clone(),
        features_json: plan.features_json.clone(),
        dependency_c_metadata_json: plan.dependency_c_metadata_json.clone(),
        dependency_identity: Some(plan.dependency_identity.clone()),
        dependency_compile_keys_json: plan.dependency_compile_keys_json.clone(),
        profile: plan.profile.clone(),
        emit: plan.emit.clone(),
        artifact_size: plan.artifact_size,
        compile_millis: plan.compile_millis,
        kind: plan.kind.clone(),
        crate_types: plan.crate_types.clone(),
        outputs: plan
            .outputs
            .iter()
            .map(|output| output.bundle_file.clone())
            .collect(),
        native: plan.native.clone(),
        native_archive: plan
            .native_archive
            .as_ref()
            .map(|archive| archive.bundle_file.clone()),
    }
}

async fn build_layers(plan: &PlannedArtifact) -> stow_types::error::Result<Vec<ImageLayer>> {
    let mut layers = Vec::new();

    // Layer order is part of the contract: consumers zip `config.outputs`
    // against the leading layers and take the native archive, when the config
    // declares one, as the trailing layer.
    for output in plan.outputs.iter().chain(plan.native_archive.as_ref()) {
        let media_type = output.bundle_file.storage_media_type();
        layers.push(ImageLayer::new(
            read_output(output).await?,
            media_type,
            None,
        ));
    }

    if layers.is_empty() {
        return Err(stow_types::stow_error!(
            "artifact {} has no uploadable layers",
            plan.oci_reference
        ));
    }

    Ok(layers)
}

async fn read_output(output: &PlannedArtifactOutput) -> stow_types::error::Result<Vec<u8>> {
    let bytes = read(&output.path).await?;
    compress_zstd(bytes, output.path.clone()).await
}

/// Asynchronously compress `bytes` with the workspace-wide stow zstd level
/// using smol's blocking-task pool.
async fn compress_zstd(bytes: Vec<u8>, path: PathBuf) -> stow_types::error::Result<Vec<u8>> {
    smol::unblock(move || {
        zstd::bulk::compress(&bytes, stow_shim::STOW_ZSTD_COMPRESSION_LEVEL).map_err(|error| {
            stow_types::stow_error!(
                "zstd compress {} at level {}: {error}",
                path.display(),
                stow_shim::STOW_ZSTD_COMPRESSION_LEVEL
            )
        })
    })
    .await
}
