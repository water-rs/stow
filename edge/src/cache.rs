use skyzen_cloudflare::worker;
use skyzen_cloudflare::{CfCache, CfCacheError};

/// Internal domain for CF Cache API keys.
const CACHE_DOMAIN: &str = "https://cache.stow.internal";

/// CF Cache 512MB limit (Free/Pro/Biz tiers).
const MAX_CACHE_SIZE: u64 = 512 * 1024 * 1024;

/// How long the public `UsageStats` body is cached — the published page
/// tolerates hourly staleness and the SQL API is billed per query.
const STATS_TTL_SECONDS: u32 = 60 * 60;

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

/// Open a cached index slice under `cache_key` as a streaming response —
/// the same shape as [`get_stream`] but under the slice namespace so a
/// slice key can never alias a bundle key.
pub async fn get_index_slice(
    cache: &CfCache,
    cache_key: &str,
) -> Result<Option<worker::Response>, CacheError> {
    cache
        .get_url(index_slice_url(cache_key), false)
        .await
        .map_err(|error| CacheError::from_cf(&error))
}

/// Store a streamed index slice under `cache_key` — the zstd
/// pass-through tees the registry response, same as [`put_stream`].
pub async fn put_index_slice_stream(
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
        .put_url(index_slice_url(cache_key), response)
        .await
        .map_err(|error| CacheError::from_cf(&error))
}

/// Store a buffered index slice under `cache_key` — the gzip transcode
/// is already materialized, so a plain put suffices.
pub async fn put_index_slice_bytes(
    cache: &CfCache,
    cache_key: &str,
    bytes: &[u8],
) -> Result<(), CacheError> {
    put_response(
        cache,
        index_slice_url(cache_key),
        bytes,
        "application/octet-stream",
        "public, s-maxage=31536000, immutable",
    )
    .await
}

/// How long the resolved stable rustc version is cached — releases ship
/// roughly every six weeks, so an hour is ample.
const STABLE_RUSTC_TTL_SECONDS: u32 = 60 * 60;

/// Fetch the cached stable rustc version string — a single fixed key;
/// one release channel, one entry.
pub async fn get_stable_rustc(cache: &CfCache) -> Result<Option<Vec<u8>>, CacheError> {
    cache
        .get_url_bytes(stable_rustc_url(), false)
        .await
        .map_err(|error| CacheError::from_cf(&error))
}

/// Cache a resolved stable rustc version for [`STABLE_RUSTC_TTL_SECONDS`].
/// The stored body is the version string alone, so a hit reparses a
/// dozen bytes rather than the ~900 KB channel manifest it came from.
pub async fn put_stable_rustc(cache: &CfCache, version: &str) -> Result<(), CacheError> {
    put_response(
        cache,
        stable_rustc_url(),
        version.as_bytes(),
        "text/plain",
        &format!("public, s-maxage={STABLE_RUSTC_TTL_SECONDS}"),
    )
    .await
}

/// Fetch the cached public-stats JSON body — a single fixed key; the
/// `UsageStats` aggregates are global, never per-request.
pub async fn get_stats(cache: &CfCache) -> Result<Option<Vec<u8>>, CacheError> {
    cache
        .get_url_bytes(stats_url(), false)
        .await
        .map_err(|error| CacheError::from_cf(&error))
}

/// Cache the serialized `UsageStats` for [`STATS_TTL_SECONDS`].
pub async fn put_stats(cache: &CfCache, body: &[u8]) -> Result<(), CacheError> {
    put_response(
        cache,
        stats_url(),
        body,
        "application/json",
        &format!("public, s-maxage={STATS_TTL_SECONDS}"),
    )
    .await
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
    format!("{CACHE_DOMAIN}/bundles/{cache_key}")
}

/// Index slices get their own URL namespace so a slice key can never
/// alias a bundle key.
fn index_slice_url(cache_key: &str) -> String {
    format!("{CACHE_DOMAIN}/index-slices/{cache_key}")
}

/// The stats body lives under its own fixed key — there is exactly one
/// public aggregate.
fn stats_url() -> String {
    format!("{CACHE_DOMAIN}/stats")
}

/// The fixed key the stable channel's resolved rustc version lives under.
fn stable_rustc_url() -> String {
    format!("{CACHE_DOMAIN}/rustc/stable")
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

impl std::error::Error for CacheError {}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cloudflare(message) => write!(f, "CF Cache error: {message}"),
            Self::Worker(message) => write!(f, "worker cache error: {message}"),
        }
    }
}
