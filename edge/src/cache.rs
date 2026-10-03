use skyzen_cloudflare::worker;
use skyzen_cloudflare::{CfCache, CfCacheError};

/// Internal domain for CF Cache API keys.
const CACHE_DOMAIN: &str = "https://cache.stow.internal";

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
