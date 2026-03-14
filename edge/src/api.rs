use skyzen::extract::Query;
use skyzen::routing::Params;
use skyzen::utils::State;
use skyzen::{Body, Response, StatusCode};
use skyzen_cloudflare::{CfCache, CfD1, CfDurableNamespace};
use stow_types::bundle::STOW_BUNDLE_MEDIA_TYPE;

use crate::db;
use crate::{cache, ghcr, miss_logger};

/// Query parameters for artifact requests.
#[derive(Debug, serde::Deserialize)]
pub struct ArtifactQuery {
    /// Crate name (for miss logging and validation).
    #[serde(rename = "crate")]
    pub crate_name: Option<String>,
    /// Crate version (for miss logging).
    pub v: Option<String>,
}

/// GET /api/v1/artifacts/{target}/{rustc_version}/{c_metadata}?crate=serde&v=1.0.210
///
/// Returns the complete artifact bundle for one crate compilation unit.
///
/// Flow:
/// 1. CF Cache API check (free, per-datacenter)
/// 2. Hit → return from CF cache
/// 3. Miss → lookup OCI reference in D1, fetch from GHCR, tee into CF Cache
/// 4. GHCR error → 302 redirect client to GHCR direct URL
/// 5. D1 miss → validate crate_name, log miss, return 404
pub async fn get_artifact(
    params: Params,
    query: Option<Query<ArtifactQuery>>,
    State(d1): State<CfD1>,
    State(scheduler): State<CfDurableNamespace>,
    State(cache): State<CfCache>,
    State(ghcr_token): State<GhcrToken>,
) -> Result<Response, GetArtifactError> {
    let target = params.get("target").map_err(|_| GetArtifactError::BadRequest)?;
    let rustc_version = params
        .get("rustc_version")
        .map_err(|_| GetArtifactError::BadRequest)?;
    let c_metadata = params
        .get("c_metadata")
        .map_err(|_| GetArtifactError::BadRequest)?;

    let cache_key = format!("{target}/{rustc_version}/{c_metadata}");

    // 1. Check CF Cache API first
    match cache::get(&cache, &cache_key).await {
        Ok(Some(cached)) => {
            tracing::debug!(key = %cache_key, "cf cache hit");
            let mut response = Response::new(Body::from(cached));
            response.headers_mut().insert(
                "content-type",
                STOW_BUNDLE_MEDIA_TYPE.parse().unwrap(),
            );
            response.headers_mut().insert(
                "x-stow-cache",
                "hit".parse().unwrap(),
            );
            return Ok(response);
        }
        Ok(None) => {
            tracing::debug!(key = %cache_key, "cf cache miss");
        }
        Err(e) => {
            tracing::warn!(key = %cache_key, error = %e, "cf cache error");
        }
    }

    // 2. Lookup OCI reference from D1
    let artifact_row = db::get_artifact_reference(&d1, c_metadata, target, rustc_version)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "D1 query failed");
            GetArtifactError::Internal
        })?;

    let Some(row) = artifact_row else {
        // 404 IS the miss event. Log it server-side.
        if let Some(Query(ref q)) = query {
            if let Some(ref crate_name) = q.crate_name {
                miss_logger::log_miss(&d1, c_metadata, crate_name, target, "", Some(&scheduler))
                    .await;
            }
        }
        return Err(GetArtifactError::NotFound);
    };

    // 3. Fetch from GHCR
    let name = row
        .oci_reference
        .strip_prefix("ghcr.io/stow-rs/cache/")
        .and_then(|s| s.split(':').next())
        .unwrap_or("unknown");

    match ghcr::fetch_bundle(&row.oci_reference, name, &row.oci_digest, &ghcr_token.0).await {
        Ok(body) => {
            // Tee into CF Cache (fire-and-forget)
            if let Err(e) = cache::try_put(&cache, &cache_key, &body, row.artifact_size).await {
                tracing::warn!(key = %cache_key, error = %e, "cf cache put failed");
            }

            let mut response = Response::new(Body::from(body));
            response.headers_mut().insert(
                "content-type",
                STOW_BUNDLE_MEDIA_TYPE.parse().unwrap(),
            );
            response.headers_mut().insert(
                "x-stow-cache",
                "miss".parse().unwrap(),
            );
            Ok(response)
        }
        Err(ghcr::FetchError::Unavailable) => {
            // GHCR unreachable → 302 redirect to GHCR direct URL
            tracing::warn!(key = %cache_key, "GHCR unavailable, redirecting client");
            match ghcr::resolve_blob_redirect_url(name, &row.oci_digest, &ghcr_token.0).await {
                Ok(redirect_url) => {
                    let mut response = Response::new(Body::empty());
                    *response.status_mut() = StatusCode::FOUND;
                    response.headers_mut().insert(
                        "location",
                        redirect_url.parse().unwrap(),
                    );
                    Ok(response)
                }
                Err(e) => {
                    tracing::error!(error = %e, "GHCR redirect resolution failed");
                    Err(GetArtifactError::GhcrUnavailable)
                }
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "GHCR fetch failed");
            Err(GetArtifactError::GhcrUnavailable)
        }
    }
}

/// HEAD /api/v1/artifacts/{target}/{rustc_version}/{c_metadata}
///
/// Check if an artifact exists without downloading it.
pub async fn check_artifact(
    params: Params,
    State(d1): State<CfD1>,
) -> Result<Response, GetArtifactError> {
    let target = params.get("target").map_err(|_| GetArtifactError::BadRequest)?;
    let rustc_version = params
        .get("rustc_version")
        .map_err(|_| GetArtifactError::BadRequest)?;
    let c_metadata = params
        .get("c_metadata")
        .map_err(|_| GetArtifactError::BadRequest)?;

    let artifact_row = db::get_artifact_reference(&d1, c_metadata, target, rustc_version)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "D1 query failed");
            GetArtifactError::Internal
        })?;

    match artifact_row {
        Some(row) => {
            let mut response = Response::new(Body::empty());
            if let Some(size) = row.artifact_size {
                response.headers_mut().insert(
                    "content-length",
                    size.to_string().parse().unwrap(),
                );
            }
            Ok(response)
        }
        None => Err(GetArtifactError::NotFound),
    }
}

/// GET /api/v1/status/{crate_name}
pub async fn get_status(params: Params) -> Result<&'static str, GetArtifactError> {
    let _crate_name = params
        .get("crate_name")
        .map_err(|_| GetArtifactError::BadRequest)?;
    Ok("ok")
}

/// Wrapper for the GHCR authentication token, stored via `State<GhcrToken>`.
#[derive(Debug, Clone)]
pub struct GhcrToken(pub String);

#[skyzen::error(message = "artifact error")]
pub enum GetArtifactError {
    #[error("bad request", status = BAD_REQUEST)]
    BadRequest,
    #[error("artifact not found", status = NOT_FOUND)]
    NotFound,
    #[error("GHCR unavailable", status = BAD_GATEWAY)]
    GhcrUnavailable,
    #[error("internal server error")]
    Internal,
}
