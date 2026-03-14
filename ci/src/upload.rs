use std::collections::BTreeMap;
use std::path::Path;

use async_fs::read;
use oci_client::client::{Client, ClientConfig, Config, ImageLayer};
use oci_client::secrets::RegistryAuth;
use oci_client::Reference;
use stow_types::bundle::{
    ArtifactBlobConfig, ArtifactBundleFile, STOW_PROC_MACRO_MEDIA_TYPE, STOW_RLIB_MEDIA_TYPE,
    STOW_RMETA_MEDIA_TYPE,
};

use crate::plan::PlannedArtifact;

const GHCR_USERNAME_ENV: &str = "GHCR_USERNAME";
const GHCR_TOKEN_ENV: &str = "GHCR_TOKEN";
const STOW_PUSH_GHCR_ENV: &str = "STOW_PUSH_GHCR";

const STOW_CONFIG_MEDIA_TYPE: &str = "application/vnd.stow.artifact.config.v1+json";
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
    let metadata = serde_json::to_vec(&ArtifactBlobConfig {
        crate_name: plan.crate_name.clone(),
        crate_version: plan.crate_version.clone(),
        c_metadata: plan.c_metadata.clone(),
        target: plan.target.clone(),
        rustc_version: plan.rustc_version.clone(),
        features_json: plan.features_json.clone(),
        artifact_size: plan.artifact_size,
        kind: plan.kind.clone(),
        rlib: optional_file(
            plan.rlib_path.as_deref(),
            plan.rlib_sha256.as_deref(),
            STOW_RLIB_MEDIA_TYPE,
        )?,
        rmeta: optional_file(
            plan.rmeta_path.as_deref(),
            plan.rmeta_sha256.as_deref(),
            STOW_RMETA_MEDIA_TYPE,
        )?,
        proc_macro: optional_file(
            plan.proc_macro_path.as_deref(),
            plan.proc_macro_sha256.as_deref(),
            STOW_PROC_MACRO_MEDIA_TYPE,
        )?,
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

fn optional_file(
    path: Option<&Path>,
    sha256: Option<&str>,
    media_type: &str,
) -> eyre::Result<Option<ArtifactBundleFile>> {
    match (path, sha256) {
        (Some(path), Some(sha256)) => Ok(Some(ArtifactBundleFile {
            file_name: file_name(path)?,
            media_type: media_type.to_owned(),
            sha256: sha256.to_owned(),
        })),
        (None, None) => Ok(None),
        (Some(path), None) => Err(eyre::eyre!(
            "missing sha256 for upload path {}",
            path.display()
        )),
        (None, Some(_)) => Err(eyre::eyre!(
            "missing upload path for media type {media_type}"
        )),
    }
}

fn file_name(path: &Path) -> eyre::Result<String> {
    path.file_name()
        .and_then(|file_name| file_name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| eyre::eyre!("upload path {} is missing a UTF-8 file name", path.display()))
}
