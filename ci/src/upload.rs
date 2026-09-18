use std::collections::BTreeMap;

use crate::zstd_util;
use async_fs::read;
use oci_client::Reference;
use oci_client::client::{Client, ClientConfig, Config, ImageLayer};
use oci_client::secrets::RegistryAuth;
use stow_types::bundle::ArtifactBlobConfig;
use stow_types::upload_plan::{PlannedArtifact, PlannedArtifactOutput};

const GHCR_USERNAME_ENV: &str = "GHCR_USERNAME";
const GHCR_TOKEN_ENV: &str = "GHCR_TOKEN";

const STOW_CONFIG_MEDIA_TYPE: &str = "application/vnd.stow.artifact.config.v1+json";

#[derive(Debug, Clone)]
pub struct UploadOutcome {
    pub digests_by_reference: BTreeMap<String, String>,
    pub pushed_digests_by_reference: BTreeMap<String, String>,
    pub newly_pushed: u32,
}

/// The one registry credential the trusted publish stage holds: the OCI
/// uploader and cosign push with the same pair, so a runner needs no Docker
/// CLI or Docker config file.
#[derive(Debug, Clone)]
pub struct RegistryCredentials {
    pub username: String,
    pub password: String,
}

impl RegistryCredentials {
    /// Read `GHCR_USERNAME` / `GHCR_TOKEN` from the job environment.
    pub fn from_env() -> stow_types::error::Result<Self> {
        Ok(Self {
            username: env_required(GHCR_USERNAME_ENV)?,
            password: env_required(GHCR_TOKEN_ENV)?,
        })
    }
}

pub async fn push_artifacts(
    plans: &[PlannedArtifact],
    credentials: &RegistryCredentials,
) -> stow_types::error::Result<UploadOutcome> {
    let auth = RegistryAuth::Basic(credentials.username.clone(), credentials.password.clone());
    let client = Client::new(ClientConfig::default());
    let mut digests = BTreeMap::new();
    let mut pushed_digests = BTreeMap::new();
    let mut newly_pushed = 0u32;

    for plan in plans {
        let reference: Reference = plan.oci_reference.parse().map_err(|error| {
            stow_types::stow_error!("parse OCI reference {}: {error}", plan.oci_reference)
        })?;
        let config = build_config(plan)?;
        let layers = build_layers(plan).await?;

        client
            .push(&reference, &layers, config, &auth, None)
            .await
            .map_err(|error| {
                stow_types::stow_error!("push OCI artifact {}: {error}", plan.oci_reference)
            })?;
        let digest = client
            .fetch_manifest_digest(&reference, &auth)
            .await
            .map_err(|error| {
                stow_types::stow_error!("fetch manifest digest for {}: {error}", plan.oci_reference)
            })?;

        tracing::info!(
            oci_reference = %plan.oci_reference,
            digest = %digest,
            "pushed OCI artifact to GHCR"
        );
        digests.insert(plan.oci_reference.clone(), digest.clone());
        pushed_digests.insert(plan.oci_reference.clone(), digest);
        newly_pushed = newly_pushed.saturating_add(1);
    }

    Ok(UploadOutcome {
        digests_by_reference: digests,
        pushed_digests_by_reference: pushed_digests,
        newly_pushed,
    })
}

fn build_config(plan: &PlannedArtifact) -> stow_types::error::Result<Config> {
    let metadata = serde_json::to_vec(&ArtifactBlobConfig {
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
    })?;
    Ok(Config::new(
        metadata,
        STOW_CONFIG_MEDIA_TYPE.to_owned(),
        None,
    ))
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
    zstd_util::compress(bytes, output.path.clone()).await
}

fn env_required(name: &str) -> stow_types::error::Result<String> {
    std::env::var(name)
        .map_err(|_| stow_types::stow_error!("missing required environment variable {name}"))
}
