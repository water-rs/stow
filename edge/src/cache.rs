use skyzen_cloudflare::worker;
use skyzen_cloudflare::{CfCache, CfCacheError};

use crate::db::ArtifactRow;

/// Internal domain for CF Cache API keys.
const CACHE_DOMAIN: &str = "https://cache.stow.internal";

/// CF Cache 512MB limit (Free/Pro/Biz tiers).
const MAX_CACHE_SIZE: u64 = 512 * 1024 * 1024;

/// Lookup entries can go stale when a row is re-registered or pruned;
/// every mutation path deletes them explicitly, and this TTL bounds the
/// window when a delete itself fails.
const LOOKUP_TTL_SECONDS: u32 = 24 * 60 * 60;

/// Try to get a cached response from CF Cache API.
pub async fn get(cache: &CfCache, cache_key: &str) -> Result<Option<Vec<u8>>, CacheError> {
    let url = bundle_url(cache_key);
    cache
        .get_url_bytes(url, false)
        .await
        .map_err(|error| CacheError::from_cf(&error))
}

/// Try to put a response into CF Cache API.
pub async fn try_put(
    cache: &CfCache,
    cache_key: &str,
    body: &[u8],
    artifact_size: Option<u64>,
) -> Result<(), CacheError> {
    if let Some(size) = artifact_size
        && size > MAX_CACHE_SIZE
    {
        return Err(CacheError::TooLarge(size));
    }

    put_response(
        cache,
        bundle_url(cache_key),
        body,
        "application/octet-stream",
        "public, s-maxage=31536000, immutable",
    )
    .await
}

/// Fetch a cached artifact-row lookup. A hit carries everything a serve
/// needs — OCI reference, digest, size — so the caller skips D1 entirely.
/// A corrupt entry is treated as a miss: the D1 read it falls back to
/// overwrites the entry with fresh data.
pub async fn get_lookup(cache: &CfCache, key: &str) -> Result<Option<ArtifactRow>, CacheError> {
    let Some(bytes) = cache
        .get_url_bytes(lookup_url(key), false)
        .await
        .map_err(|error| CacheError::from_cf(&error))?
    else {
        return Ok(None);
    };
    match serde_json::from_slice::<ArtifactRow>(&bytes) {
        Ok(row) => Ok(Some(row)),
        Err(error) => {
            tracing::warn!(key = %key, %error, "cf cache lookup entry failed to parse; treating as miss");
            Ok(None)
        }
    }
}

/// Cache the artifact row a D1 read just resolved. Best-effort: callers
/// log and continue on failure.
pub async fn put_lookup(cache: &CfCache, key: &str, row: &ArtifactRow) -> Result<(), CacheError> {
    let body = serde_json::to_vec(row)
        .map_err(|error| CacheError::Worker(format!("serialize lookup entry: {error}")))?;
    put_response(
        cache,
        lookup_url(key),
        &body,
        "application/json",
        &format!("public, s-maxage={LOOKUP_TTL_SECONDS}"),
    )
    .await
}

/// Drop a lookup entry after the row it names was re-registered or
/// pruned. `ResponseNotFound` is success — the entry is gone either way.
pub async fn delete_lookup(cache: &CfCache, key: &str) -> Result<(), CacheError> {
    cache
        .delete_url(lookup_url(key), false)
        .await
        .map(|_| ())
        .map_err(|error| CacheError::from_cf(&error))
}

async fn put_response(
    cache: &CfCache,
    url: String,
    body: &[u8],
    content_type: &'static str,
    cache_control: &str,
) -> Result<(), CacheError> {
    let mut response = worker::Response::from_bytes(body.to_vec())
        .map_err(|error| CacheError::from_worker(&error))?;
    response
        .headers_mut()
        .set("Cache-Control", cache_control)
        .map_err(|error| CacheError::from_worker(&error))?;
    response
        .headers_mut()
        .set("Content-Type", content_type)
        .map_err(|error| CacheError::from_worker(&error))?;

    cache
        .put_url(url, response)
        .await
        .map_err(|error| CacheError::from_cf(&error))
}

fn bundle_url(cache_key: &str) -> String {
    format!("{CACHE_DOMAIN}/artifacts/{cache_key}")
}

/// Lookup entries get their own URL namespace so a metadata key can never
/// alias a bundle key.
fn lookup_url(key: &str) -> String {
    format!("{CACHE_DOMAIN}/lookups/{key}")
}

#[derive(Debug)]
pub enum CacheError {
    Cloudflare(String),
    Worker(String),
    TooLarge(u64),
}

impl CacheError {
    fn from_cf(error: &CfCacheError) -> Self {
        Self::Cloudflare(error.to_string())
    }

    fn from_worker(error: &worker::Error) -> Self {
        Self::Worker(error.to_string())
    }
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cloudflare(message) => write!(f, "CF Cache error: {message}"),
            Self::Worker(message) => write!(f, "worker cache error: {message}"),
            Self::TooLarge(size) => {
                write!(f, "artifact too large for CF Cache: {size} bytes")
            }
        }
    }
}
