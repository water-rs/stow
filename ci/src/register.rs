//! Trusted-CI register path.
//!
//! CI does not own a Cloudflare D1 credential. After building and signing
//! an OCI artifact bundle, CI POSTs the corresponding `ArtifactRecord`
//! values to the edge worker's authenticated admin endpoint:
//!
//!   POST {`STOW_EDGE_URL}/api/v1/admin/artifacts/register`
//!   Header: x-stow-register-token: {`STOW_REGISTER_AUTH_TOKEN`}
//!
//! The edge owns the `STOW_DB` D1 binding and serializes the records into
//! `artifacts` rows. The composite uniqueness key
//! `(c_metadata, target, rustc_version)` plus `INSERT OR REPLACE` keeps
//! retries idempotent.
//!
//! Trust note: an attacker who steals the register token can pollute D1
//! with rows that point at digests they do not control. The CLI verifies
//! cosign signatures on every fetch, so a polluted row causes a 404 on
//! the client and a stale-row prune on the edge — it cannot be used to
//! inject malicious code. Migrating this endpoint to cosign-verified
//! request bodies (so register itself becomes signature-rooted) is
//! tracked in `docs/ARCHITECTURE.md`.

use stow_types::api::ArtifactRecord;
use zenwave::{Client, ResponseExt};

const STOW_EDGE_URL_ENV: &str = "STOW_EDGE_URL";
const STOW_REGISTER_AUTH_TOKEN_ENV: &str = "STOW_REGISTER_AUTH_TOKEN";
const REGISTER_AUTH_HEADER: &str = "x-stow-register-token";

// The edge inserts each record with its own D1 query, and Cloudflare Workers
// cap subrequests per invocation (50 on the free plan). Chunk conservatively
// so one register POST never exceeds that budget; retries stay idempotent via
// the (c_metadata, target, rustc_version) upsert key.
const REGISTER_CHUNK_SIZE: usize = 32;

/// Register artifact records with the edge worker, chunked so each POST
/// stays within Workers' per-invocation subrequest limits.
pub async fn register_artifacts(records: &[ArtifactRecord]) -> stow_types::error::Result<()> {
    if records.is_empty() {
        return Ok(());
    }
    let edge_url = env_required(STOW_EDGE_URL_ENV)?;
    let token = env_required(STOW_REGISTER_AUTH_TOKEN_ENV)?;
    let url = format!(
        "{}/api/v1/admin/artifacts/register",
        edge_url.trim_end_matches('/')
    );

    for chunk in records.chunks(REGISTER_CHUNK_SIZE) {
        let mut client = zenwave::client();
        client
            .post(&url)?
            .header(REGISTER_AUTH_HEADER, &token)?
            .json_body(&chunk)?
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
