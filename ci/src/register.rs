//! Trusted-CI register path.
//!
//! CI does not own a Cloudflare D1 credential. After building and signing
//! an OCI artifact bundle, CI POSTs the corresponding `ArtifactRecord`
//! values to the edge worker's authenticated admin endpoint:
//!
//!   POST {`STOW_EDGE_URL}/api/v1/admin/artifacts/register`
//!   Header: Authorization: Bearer {`auth::edge_bearer()`}
//!
//! The bearer is the run's GitHub Actions OIDC JWT in CI (or the
//! developer's GitHub token locally) — see `auth.rs`. The edge owns the
//! `STOW_DB` D1 binding and serializes the records into `artifacts` rows.
//! The composite uniqueness key `(c_metadata, target, rustc_version)` plus
//! the edge's `ON CONFLICT` upsert keeps retries idempotent.
//!
//! Trust note: an attacker who can call register can pollute D1 with rows
//! that point at digests they do not control. The CLI verifies cosign
//! signatures on every fetch, so a polluted row causes a 404 on the
//! client and a stale-row prune on the edge — it cannot be used to inject
//! malicious code. The edge additionally binds every OIDC write to the
//! dispatched task's dependency closure, so a compromised run can only
//! register the rows its own build could produce.

use stow_types::api::{ArtifactRecord, RegisterArtifactsRequest};
use zenwave::{Client, ResponseExt};

use crate::auth;

const STOW_EDGE_URL_ENV: &str = "STOW_EDGE_URL";

// The edge inserts each record with its own D1 query, and Cloudflare Workers
// cap subrequests per invocation (50 on the free plan). Chunk conservatively
// so one register POST never exceeds that budget; retries stay idempotent via
// the (c_metadata, target, rustc_version) upsert key.
const REGISTER_CHUNK_SIZE: usize = 32;

/// Register artifact records with the edge worker, chunked so each POST
/// stays within Workers' per-invocation subrequest limits.
///
/// `task_id` is the scheduler task the calling run was dispatched for
/// (`BuildTaskPayload::task_id`); the edge binds the record set to that
/// task's dependency closure. `None` only on the operator backfill path,
/// which registers as a repo-push caller rather than a dispatched run.
pub async fn register_artifacts(
    task_id: Option<&str>,
    records: &[ArtifactRecord],
) -> stow_types::error::Result<()> {
    if records.is_empty() {
        return Ok(());
    }
    let edge_url = env_required(STOW_EDGE_URL_ENV)?;
    let token = auth::edge_bearer().await?;
    let url = format!(
        "{}/api/v1/admin/artifacts/register",
        edge_url.trim_end_matches('/')
    );

    for chunk in records.chunks(REGISTER_CHUNK_SIZE) {
        let body = RegisterArtifactsRequest {
            task_id: task_id.map(str::to_owned),
            records: chunk.to_vec(),
        };
        let mut client = zenwave::client();
        client
            .post(&url)?
            .header("Authorization", format!("Bearer {token}"))?
            .json_body(&body)?
            .await
            .map_err(|error| stow_types::stow_error!("POST {url}: {error}"))?
            .error_for_status()
            .await
            .map_err(|error| {
                stow_types::stow_error!("edge admin register rejected records: {error}")
            })?;
    }

    tracing::info!(
        registered = records.len(),
        url,
        "registered artifact records via edge admin endpoint"
    );

    Ok(())
}

fn env_required(name: &str) -> stow_types::error::Result<String> {
    std::env::var(name).map_err(|_| stow_types::stow_error!("missing required env var {name}"))
}
