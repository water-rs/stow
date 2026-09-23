//! One-time migration: publish the `<tag>.bundle` of every artifact row
//! registered before the publish stage pushed bundles.
//!
//! Runs outside CI with a GHCR credential that can write the package and
//! the developer's GitHub token for the edge's trusted endpoints. Each pass
//! lists rows without a `bundle_digest`, republishes their bundles, and
//! re-registers the records with the bundle coordinates, until the listing
//! comes back empty.

use stow_types::api::ArtifactRecord;
use zenwave::{Client, ResponseExt};

use crate::{auth, register};

const STOW_EDGE_URL_ENV: &str = "STOW_EDGE_URL";

/// Backfill bundles for up to `batch` rows per pass until none remain.
/// Returns the number of rows republished.
pub async fn backfill_bundles(batch: usize) -> stow_types::error::Result<usize> {
    let edge_url = env_required(STOW_EDGE_URL_ENV)?;
    let credentials = stow_oci::RegistryCredentials::from_env()?;
    let session = credentials.session()?;
    let mut republished = 0usize;
    loop {
        let records = list_unbundled(&edge_url, batch).await?;
        if records.is_empty() {
            return Ok(republished);
        }
        let mut updated = Vec::with_capacity(records.len());
        for mut record in records {
            let published = stow_oci::republish_bundle(&session, &record).await?;
            record.bundle_digest = published.bundle_digest;
            record.bundle_size = published.bundle_size;
            updated.push(record);
        }
        // Backfill runs outside a dispatched task as a push caller — no
        // `task_id` to bind the write to.
        register::register_artifacts(None, &updated).await?;
        republished += updated.len();
        tracing::info!(republished, "backfilled bundle records");
    }
}

async fn list_unbundled(
    edge_url: &str,
    limit: usize,
) -> stow_types::error::Result<Vec<ArtifactRecord>> {
    let token = auth::edge_bearer().await?;
    let url = format!(
        "{}/api/v1/admin/artifacts/unbundled?limit={limit}",
        edge_url.trim_end_matches('/')
    );
    let mut client = zenwave::client();
    let response = client
        .get(&url)?
        .header("Authorization", format!("Bearer {token}"))?
        .await
        .map_err(|error| stow_types::stow_error!("GET {url}: {error}"))?
        .error_for_status()
        .await
        .map_err(|error| stow_types::stow_error!("GET {url}: {error}"))?;
    let body = response
        .into_bytes()
        .await
        .map_err(|error| stow_types::stow_error!("read {url} body: {error}"))?;
    serde_json::from_slice(&body)
        .map_err(|error| stow_types::stow_error!("parse {url} body: {error}"))
}

fn env_required(name: &str) -> stow_types::error::Result<String> {
    std::env::var(name).map_err(|_| stow_types::stow_error!("missing required env var {name}"))
}
