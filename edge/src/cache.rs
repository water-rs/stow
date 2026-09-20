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

/// Open the cached bundle under `cache_key` as a streaming response.
pub async fn get_stream(
    cache: &CfCache,
    cache_key: &str,
) -> Result<Option<worker::Response>, CacheError> {
    cache
        .get_url(bundle_url(cache_key), false)
        .await
        .map_err(|error| CacheError::from_cf(&error))
}

/// Whether a bundle of `size` bytes fits the Cache API object limit. A
/// bundle over it streams through from the registry on every request.
#[must_use]
pub const fn fits_cache(size: u64) -> bool {
    size <= MAX_CACHE_SIZE
}

/// Store a bundle stream under `cache_key`. The response is the registry's
/// (or a tee of it); the immutable cache headers are set here so the entry
/// never revalidates. Resolves once the stream has been consumed.
pub async fn put_stream(
    cache: &CfCache,
    cache_key: &str,
    mut response: worker::Response,
) -> Result<(), CacheError> {
    response
        .headers_mut()
        .set("Cache-Control", "public, s-maxage=31536000, immutable")
        .map_err(|error| CacheError::from_worker(&error))?;
    response
        .headers_mut()
        .set("Content-Type", "application/octet-stream")
        .map_err(|error| CacheError::from_worker(&error))?;
    cache
        .put_url(bundle_url(cache_key), response)
        .await
        .map_err(|error| CacheError::from_cf(&error))
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

/// Seconds a cached panic-flag answer may be reused per colo. The flag is
/// the attack backstop, so the TTL trades propagation delay against the
/// Durable Object read every entry expiry would otherwise cost.
const PANIC_TTL_SECONDS: u32 = 60;

/// The cached panic flag, or `None` on a miss. A corrupt entry is a miss:
/// the Durable Object read it falls back to rewrites the entry.
pub async fn get_panic_flag(cache: &CfCache) -> Result<Option<bool>, CacheError> {
    let Some(bytes) = cache
        .get_url_bytes(panic_url(), false)
        .await
        .map_err(|error| CacheError::from_cf(&error))?
    else {
        return Ok(None);
    };
    if let Some(enabled) = crate::panic::parse_flag(&bytes) {
        return Ok(Some(enabled));
    }
    tracing::warn!("cf cache panic entry failed to parse; treating as miss");
    Ok(None)
}

/// Re-populate the panic-flag entry after a Durable Object read.
pub async fn put_panic_flag(cache: &CfCache, enabled: bool) -> Result<(), CacheError> {
    put_response(
        cache,
        panic_url(),
        &crate::panic::flag_body(enabled),
        "application/json",
        &format!("public, s-maxage={PANIC_TTL_SECONDS}"),
    )
    .await
}

/// Drop the panic-flag entry so the colo that flipped the switch sees the
/// new value on the next request instead of up to a TTL later.
pub async fn delete_panic_flag(cache: &CfCache) -> Result<(), CacheError> {
    cache
        .delete_url(panic_url(), false)
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

/// The fixed key the panic flag lives under — one flag, one entry.
fn panic_url() -> String {
    format!("{CACHE_DOMAIN}/settings/panic")
}

#[derive(Debug)]
pub enum CacheError {
    Cloudflare(String),
    Worker(String),
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
        }
    }
}
