use std::collections::BTreeMap;

use async_fs::read;
use oci_client::client::{Client, ClientConfig, Config, ImageLayer};
use oci_client::secrets::RegistryAuth;
use oci_client::Reference;
use stow_types::bundle::ArtifactBlobConfig;

use crate::plan::{PlannedArtifact, PlannedArtifactOutput};
use crate::register;

const GHCR_USERNAME_ENV: &str = "GHCR_USERNAME";
const GHCR_TOKEN_ENV: &str = "GHCR_TOKEN";
const STOW_PUSH_GHCR_ENV: &str = "STOW_PUSH_GHCR";
const CLOUDFLARE_API_TOKEN_ENV: &str = "CLOUDFLARE_API_TOKEN";
const CLOUDFLARE_ACCOUNT_ID_ENV: &str = "CLOUDFLARE_ACCOUNT_ID";
const CLOUDFLARE_D1_DATABASE_ID_ENV: &str = "CLOUDFLARE_D1_DATABASE_ID";

const STOW_CONFIG_MEDIA_TYPE: &str = "application/vnd.stow.artifact.config.v1+json";
#[derive(Debug, Clone)]
pub struct UploadOutcome {
    pub digests_by_reference: BTreeMap<String, String>,
    pub pushed_digests_by_reference: BTreeMap<String, String>,
    pub newly_pushed: u32,
}

pub async fn maybe_push_artifacts(
    plans: &[PlannedArtifact],
) -> eyre::Result<Option<UploadOutcome>> {
    if std::env::var(STOW_PUSH_GHCR_ENV).ok().as_deref() != Some("1") {
        return Ok(None);
    }

    let auth = RegistryAuth::Basic(env_required(GHCR_USERNAME_ENV)?, env_required(GHCR_TOKEN_ENV)?);
    let client = Client::new(ClientConfig::default());
    let mut digests = existing_digests(plans).await?;
    let mut pushed_digests = BTreeMap::new();
    let mut newly_pushed = 0u32;

    for plan in plans {
        if digests.contains_key(&plan.oci_reference) {
            tracing::info!(
                oci_reference = %plan.oci_reference,
                "skipping GHCR push because artifact is already registered in D1"
            );
            continue;
        }

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
        digests.insert(plan.oci_reference.clone(), digest.clone());
        pushed_digests.insert(plan.oci_reference.clone(), digest);
        newly_pushed = newly_pushed.saturating_add(1);
    }

    Ok(Some(UploadOutcome {
        digests_by_reference: digests,
        pushed_digests_by_reference: pushed_digests,
        newly_pushed,
    }))
}

async fn existing_digests(plans: &[PlannedArtifact]) -> eyre::Result<BTreeMap<String, String>> {
    if std::env::var(CLOUDFLARE_API_TOKEN_ENV).is_err()
        || std::env::var(CLOUDFLARE_ACCOUNT_ID_ENV).is_err()
        || std::env::var(CLOUDFLARE_D1_DATABASE_ID_ENV).is_err()
    {
        return Ok(BTreeMap::new());
    }

    let keys = plans
        .iter()
        .map(|plan| {
            (
                plan.c_metadata.clone(),
                plan.target.clone(),
                plan.rustc_version.clone(),
            )
        })
        .collect::<Vec<_>>();
    register::query_registered_artifacts(&keys).await
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
        crate_types: plan.crate_types.clone(),
        outputs: plan
            .outputs
            .iter()
            .map(|output| output.bundle_file.clone())
            .collect(),
        native: plan.native.clone(),
    })?;
    Ok(Config::new(metadata, STOW_CONFIG_MEDIA_TYPE.to_owned(), None))
}

async fn build_layers(plan: &PlannedArtifact) -> eyre::Result<Vec<ImageLayer>> {
    let mut layers = Vec::new();

    for output in &plan.outputs {
        layers.push(ImageLayer::new(
            read_output(output).await?,
            output.bundle_file.media_type.clone(),
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

async fn read_output(output: &PlannedArtifactOutput) -> eyre::Result<Vec<u8>> {
    read(&output.path).await.map_err(Into::into)
}

fn env_required(name: &str) -> eyre::Result<String> {
    std::env::var(name).map_err(|_| eyre::eyre!("missing required environment variable {name}"))
}
