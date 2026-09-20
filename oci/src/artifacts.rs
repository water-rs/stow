use std::collections::BTreeMap;
use std::path::PathBuf;

use async_fs::read;
use oci_client::Reference;
use oci_client::client::{Client, Config, ImageLayer};
use oci_client::manifest::OciImageManifest;
use oci_client::secrets::RegistryAuth;
use stow_types::api::ArtifactRecord;
use stow_types::bundle::{
    ArtifactBlobConfig, BundleArtifactConfig, BundleLayer, BundleParts, BundleSignatureMaterial,
    OCI_IMAGE_MANIFEST_MEDIA_TYPE, SIGSTORE_BUNDLE_ANNOTATION, SIGSTORE_CERT_ANNOTATION,
    SIGSTORE_OCI_MEDIA_TYPE, SIGSTORE_SIGNATURE_ANNOTATION, STOW_ARTIFACT_CONFIG_MEDIA_TYPE,
    STOW_BUNDLE_CONFIG_MEDIA_TYPE, STOW_BUNDLE_MEDIA_TYPE, assemble_bundle, sigstore_payload_path,
    sigstore_signature_tag,
};
use stow_types::bundle_schema::validate_bundle_schema;
use stow_types::registry::{bundle_oci_reference, sha256_digest};
use stow_types::upload_plan::{PlannedArtifact, PlannedArtifactOutput, PublishedArtifact};

use crate::registry::{RegistryCredentials, pull_blob, pull_manifest_by_digest, registry_client};
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
/// One plan at a time so the layer bytes of only one artifact are ever in
/// memory.
///
/// # Errors
///
/// Returns an error when a push, the cosign signature, or a bundle pull
/// fails; the registry round-trip error names the plan's OCI reference.
pub async fn push_artifacts(
    plans: &[PlannedArtifact],
    credentials: &RegistryCredentials,
) -> stow_types::error::Result<UploadOutcome> {
    let (client, auth) = registry_client(credentials);
    let mut published = BTreeMap::new();
    let mut newly_pushed = 0u32;

    for plan in plans {
        let artifact = publish_artifact(&client, &auth, credentials, plan).await?;
        published.insert(plan.oci_reference.clone(), artifact);
        newly_pushed = newly_pushed.saturating_add(1);
    }

    Ok(UploadOutcome {
        published_by_reference: published,
        newly_pushed,
    })
}

async fn publish_artifact(
    client: &Client,
    auth: &RegistryAuth,
    credentials: &RegistryCredentials,
    plan: &PlannedArtifact,
) -> stow_types::error::Result<PublishedArtifact> {
    let reference: Reference = plan.oci_reference.parse().map_err(|error| {
        stow_types::stow_error!("parse OCI reference {}: {error}", plan.oci_reference)
    })?;
    let config = artifact_config(plan);
    let config_bytes = serde_json::to_vec(&config)?;
    let layers = build_layers(plan).await?;

    client
        .push(
            &reference,
            &layers,
            Config::new(
                config_bytes.clone(),
                STOW_ARTIFACT_CONFIG_MEDIA_TYPE.to_owned(),
                None,
            ),
            auth,
            None,
        )
        .await
        .map_err(|error| {
            stow_types::stow_error!("push OCI artifact {}: {error}", plan.oci_reference)
        })?;
    let oci_digest = client
        .fetch_manifest_digest(&reference, auth)
        .await
        .map_err(|error| {
            stow_types::stow_error!("fetch manifest digest for {}: {error}", plan.oci_reference)
        })?;
    tracing::info!(
        oci_reference = %plan.oci_reference,
        digest = %oci_digest,
        "pushed OCI artifact to GHCR"
    );

    sign::sign_artifact(&plan.oci_reference, &oci_digest, credentials).await?;

    let manifest_bytes = pull_verified_manifest(
        client,
        auth,
        plan,
        &reference,
        &oci_digest,
        &config_bytes,
        &layers,
    )
    .await?;
    let signatures = pull_signature_materials(client, auth, &reference, &oci_digest).await?;

    let (bundle_digest, bundle_size) = push_bundle(
        client,
        auth,
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

/// Publish the `<tag>.bundle` of an artifact pushed and signed before
/// bundles existed.
///
/// Everything the bundle carries is read back from the registry by the
/// record's `oci_digest`, then assembled, validated and pushed exactly as
/// the publish stage does for a fresh artifact.
///
/// # Errors
///
/// Returns an error when the artifact's manifest, config, layers or
/// signature materials cannot be pulled or parsed, or the bundle push
/// fails.
pub async fn republish_bundle(
    client: &Client,
    auth: &RegistryAuth,
    record: &ArtifactRecord,
) -> stow_types::error::Result<PublishedArtifact> {
    let reference: Reference = record.oci_reference.parse().map_err(|error| {
        stow_types::stow_error!("parse OCI reference {}: {error}", record.oci_reference)
    })?;
    let manifest_bytes =
        pull_manifest_by_digest(client, auth, &reference, &record.oci_digest).await?;
    let manifest: OciImageManifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        stow_types::stow_error!("parse manifest of {}: {error}", record.oci_reference)
    })?;
    let config_bytes = pull_blob(client, &reference, &manifest.config).await?;
    let config: ArtifactBlobConfig = serde_json::from_slice(&config_bytes).map_err(|error| {
        stow_types::stow_error!("parse config of {}: {error}", record.oci_reference)
    })?;
    let mut layers = Vec::with_capacity(manifest.layers.len());
    for descriptor in &manifest.layers {
        layers.push(ImageLayer::new(
            pull_blob(client, &reference, descriptor).await?,
            descriptor.media_type.clone(),
            None,
        ));
    }
    let signatures = pull_signature_materials(client, auth, &reference, &record.oci_digest).await?;
    let (bundle_digest, bundle_size) = push_bundle(
        client,
        auth,
        &BundleParts {
            oci_reference: &record.oci_reference,
            oci_digest: &record.oci_digest,
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
        oci_digest: record.oci_digest.clone(),
        bundle_digest,
        bundle_size,
    })
}

/// The manifest bytes the registry stores for the artifact just pushed,
/// checked against what was pushed: the config digest and every layer's
/// digest and media type must be the local ones, or the bundle would
/// carry a manifest that does not describe its own files.
async fn pull_verified_manifest(
    client: &Client,
    auth: &RegistryAuth,
    plan: &PlannedArtifact,
    reference: &Reference,
    oci_digest: &str,
    config_bytes: &[u8],
    layers: &[ImageLayer],
) -> stow_types::error::Result<Vec<u8>> {
    let manifest_bytes = pull_manifest_by_digest(client, auth, reference, oci_digest).await?;
    let manifest: OciImageManifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        stow_types::stow_error!("parse pushed manifest of {}: {error}", plan.oci_reference)
    })?;
    let config_digest = sha256_digest(config_bytes);
    if manifest.config.digest != config_digest {
        return Err(stow_types::stow_error!(
            "registry manifest of {} names config {} but the pushed config hashes to {config_digest}",
            plan.oci_reference,
            manifest.config.digest
        ));
    }
    if manifest.layers.len() != layers.len() {
        return Err(stow_types::stow_error!(
            "registry manifest of {} has {} layers but {} were pushed",
            plan.oci_reference,
            manifest.layers.len(),
            layers.len()
        ));
    }
    for (layer, descriptor) in layers.iter().zip(&manifest.layers) {
        let digest = layer.sha256_digest();
        if descriptor.digest != digest || descriptor.media_type != layer.media_type {
            return Err(stow_types::stow_error!(
                "registry manifest of {} names layer {} ({}) but the pushed layer is {digest} ({})",
                plan.oci_reference,
                descriptor.digest,
                descriptor.media_type,
                layer.media_type
            ));
        }
    }
    Ok(manifest_bytes)
}

/// Assemble the bundle tar, validate it, and push it as the `<tag>.bundle`
/// artifact. Returns the bundle layer's digest and size — the coordinates
/// the edge streams it by.
async fn push_bundle(
    client: &Client,
    auth: &RegistryAuth,
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
    client
        .push(
            &bundle_reference.parse().map_err(|error| {
                stow_types::stow_error!("parse bundle reference {bundle_reference}: {error}")
            })?,
            std::slice::from_ref(&bundle_layer),
            Config::new(
                bundle_config,
                STOW_BUNDLE_CONFIG_MEDIA_TYPE.to_owned(),
                None,
            ),
            auth,
            None,
        )
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
/// # Errors
///
/// Returns an error when the signature manifest or a layer cannot be pulled
/// or parsed.
pub async fn pull_signature_materials(
    client: &Client,
    auth: &RegistryAuth,
    reference: &Reference,
    oci_digest: &str,
) -> stow_types::error::Result<Vec<BundleSignatureMaterial>> {
    let signature_reference: Reference = format!(
        "{}/{}:{}",
        reference.registry(),
        reference.repository(),
        sigstore_signature_tag(oci_digest)
    )
    .parse()?;
    let (manifest_bytes, _) = client
        .pull_manifest_raw(&signature_reference, auth, &[OCI_IMAGE_MANIFEST_MEDIA_TYPE])
        .await
        .map_err(|error| {
            stow_types::stow_error!("pull signature manifest {signature_reference}: {error}")
        })?;
    let manifest: OciImageManifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
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
        let mut payload_bytes = Vec::new();
        client
            .pull_blob(&signature_reference, descriptor, &mut payload_bytes)
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
