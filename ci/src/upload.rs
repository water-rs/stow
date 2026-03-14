use std::collections::BTreeMap;

use async_fs::read;
use oci_client::client::{Client, ClientConfig, Config, ImageLayer};
use oci_client::secrets::RegistryAuth;
use oci_client::Reference;

use crate::plan::PlannedArtifact;

const GHCR_USERNAME_ENV: &str = "GHCR_USERNAME";
const GHCR_TOKEN_ENV: &str = "GHCR_TOKEN";
const STOW_PUSH_GHCR_ENV: &str = "STOW_PUSH_GHCR";

const STOW_CONFIG_MEDIA_TYPE: &str = "application/vnd.stow.artifact.config.v1+json";
const STOW_RLIB_MEDIA_TYPE: &str = "application/vnd.stow.rlib.v1";
const STOW_RMETA_MEDIA_TYPE: &str = "application/vnd.stow.rmeta.v1";
const STOW_PROC_MACRO_MEDIA_TYPE: &str = "application/vnd.stow.proc-macro.v1";

pub async fn maybe_push_artifacts(
    plans: &[PlannedArtifact],
) -> eyre::Result<Option<BTreeMap<String, String>>> {
    if std::env::var(STOW_PUSH_GHCR_ENV).ok().as_deref() != Some("1") {
        return Ok(None);
    }

    let auth = RegistryAuth::Basic(env_required(GHCR_USERNAME_ENV)?, env_required(GHCR_TOKEN_ENV)?);
    let client = Client::new(ClientConfig::default());
    let mut digests = BTreeMap::new();

    for plan in plans {
        let reference: Reference = plan
            .oci_reference
            .parse()
            .map_err(|error| eyre::eyre!("parse OCI reference {}: {error}", plan.oci_reference))?;
        let config = build_config(plan)?;
        let layers = build_layers(plan).await?;

        client
            .push(&reference, &layers, config, &auth, None)
            .await
            .map_err(|error| eyre::eyre!("push OCI artifact {}: {error}", plan.oci_reference))?;
        let digest = client
            .fetch_manifest_digest(&reference, &auth)
            .await
            .map_err(|error| eyre::eyre!("fetch manifest digest for {}: {error}", plan.oci_reference))?;

        tracing::info!(
            oci_reference = %plan.oci_reference,
            digest = %digest,
            "pushed OCI artifact to GHCR"
        );
        digests.insert(plan.oci_reference.clone(), digest);
    }

    Ok(Some(digests))
}

fn build_config(plan: &PlannedArtifact) -> eyre::Result<Config> {
    let metadata = serde_json::to_vec(&UploadConfig {
        crate_name: plan.crate_name.clone(),
        crate_version: plan.crate_version.clone(),
        c_metadata: plan.c_metadata.clone(),
        target: plan.target.clone(),
        rustc_version: plan.rustc_version.clone(),
        features_json: plan.features_json.clone(),
        artifact_size: plan.artifact_size,
        kind: plan.kind.as_str().to_owned(),
        rlib_sha256: plan.rlib_sha256.clone(),
        rmeta_sha256: plan.rmeta_sha256.clone(),
        proc_macro_sha256: plan.proc_macro_sha256.clone(),
    })?;
    Ok(Config::new(metadata, STOW_CONFIG_MEDIA_TYPE.to_owned(), None))
}

async fn build_layers(plan: &PlannedArtifact) -> eyre::Result<Vec<ImageLayer>> {
    let mut layers = Vec::new();

    if let Some(path) = &plan.rlib_path {
        layers.push(ImageLayer::new(
            read(path).await?,
            STOW_RLIB_MEDIA_TYPE.to_owned(),
            None,
        ));
    }
    if let Some(path) = &plan.rmeta_path {
        layers.push(ImageLayer::new(
            read(path).await?,
            STOW_RMETA_MEDIA_TYPE.to_owned(),
            None,
        ));
    }
    if let Some(path) = &plan.proc_macro_path {
        layers.push(ImageLayer::new(
            read(path).await?,
            STOW_PROC_MACRO_MEDIA_TYPE.to_owned(),
            None,
        ));
    }

    if layers.is_empty() {
        return Err(eyre::eyre!(
            "artifact {} has no uploadable layers",
            plan.oci_reference
        ));
    }

    Ok(layers)
}

fn env_required(name: &str) -> eyre::Result<String> {
    std::env::var(name).map_err(|_| eyre::eyre!("missing required environment variable {name}"))
}

#[derive(Debug, serde::Serialize)]
struct UploadConfig {
    crate_name: String,
    crate_version: String,
    c_metadata: String,
    target: String,
    rustc_version: String,
    features_json: String,
    artifact_size: u64,
    kind: String,
    rlib_sha256: Option<String>,
    rmeta_sha256: Option<String>,
    proc_macro_sha256: Option<String>,
}
