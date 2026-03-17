use skyzen_cloudflare::worker;
use skyzen_cloudflare::{CfCache, CfCacheError};

/// Internal domain for CF Cache API keys.
const CACHE_DOMAIN: &str = "https://cache.stow.internal";

/// CF Cache 512MB limit (Free/Pro/Biz tiers).
const MAX_CACHE_SIZE: u64 = 512 * 1024 * 1024;

/// Try to get a cached response from CF Cache API.
pub async fn get(cache: &CfCache, cache_key: &str) -> Result<Option<Vec<u8>>, CacheError> {
    let url = cache_url(cache_key);
    cache
        .get_url_bytes(url, false)
        .await
        .map_err(CacheError::from_cf)
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

    let url = cache_url(cache_key);
    let mut response =
        worker::Response::from_bytes(body.to_vec()).map_err(CacheError::from_worker)?;
    response
        .headers_mut()
        .set("Cache-Control", "public, s-maxage=31536000, immutable")
        .map_err(CacheError::from_worker)?;
    response
        .headers_mut()
        .set("Content-Type", "application/octet-stream")
        .map_err(CacheError::from_worker)?;

    cache
        .put_url(url, response)
        .await
        .map_err(CacheError::from_cf)
}

fn cache_url(cache_key: &str) -> String {
    format!("{CACHE_DOMAIN}/artifacts/{cache_key}")
}

#[derive(Debug)]
pub enum CacheError {
    Cloudflare(String),
    Worker(String),
    TooLarge(u64),
}

impl CacheError {
    fn from_cf(error: CfCacheError) -> Self {
        Self::Cloudflare(error.to_string())
    }

    fn from_worker(error: worker::Error) -> Self {
        Self::Worker(error.to_string())
    }
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheError::Cloudflare(message) => write!(f, "CF Cache error: {message}"),
            CacheError::Worker(message) => write!(f, "worker cache error: {message}"),
            CacheError::TooLarge(size) => {
                write!(f, "artifact too large for CF Cache: {size} bytes")
            }
        }
    }
}
