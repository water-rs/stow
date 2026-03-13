use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// Internal domain for CF Cache API keys.
/// CF Cache API uses URL-shaped keys; we construct synthetic internal URLs.
const CACHE_DOMAIN: &str = "https://cache.stow.internal";

/// CF Cache 512MB limit (Free/Pro/Biz tiers).
const MAX_CACHE_SIZE: u64 = 512 * 1024 * 1024;

/// Try to get a cached response from CF Cache API.
///
/// Returns `Ok(Some(bytes))` on hit, `Ok(None)` on miss.
pub async fn get(cache_key: &str) -> Result<Option<Vec<u8>>, CacheError> {
    let url = format!("{CACHE_DOMAIN}/artifacts/{cache_key}");

    let cache = open_default_cache().await?;
    let request = web_sys::Request::new_with_str(&url).map_err(|e| CacheError::Js(format!("{e:?}")))?;

    let promise = cache_match(&cache, &request)?;
    let result = JsFuture::from(promise)
        .await
        .map_err(|e| CacheError::Js(format!("{e:?}")))?;

    if result.is_undefined() || result.is_null() {
        return Ok(None);
    }

    let response: web_sys::Response = result.unchecked_into();
    let promise = response
        .array_buffer()
        .map_err(|e| CacheError::Js(format!("{e:?}")))?;
    let buffer = JsFuture::from(promise)
        .await
        .map_err(|e| CacheError::Js(format!("{e:?}")))?;
    let array = js_sys::Uint8Array::new(&buffer);
    Ok(Some(array.to_vec()))
}

/// Try to put a response into CF Cache API.
///
/// Returns Err if CF Cache rejects (e.g., >512MB). Caller should log
/// the error but NOT fail the client request.
pub async fn try_put(cache_key: &str, body: &[u8], artifact_size: Option<u64>) -> Result<(), CacheError> {
    // Skip cache write for known oversized artifacts
    if let Some(size) = artifact_size {
        if size > MAX_CACHE_SIZE {
            return Err(CacheError::TooLarge(size));
        }
    }

    let url = format!("{CACHE_DOMAIN}/artifacts/{cache_key}");

    let cache = open_default_cache().await?;
    let request = web_sys::Request::new_with_str(&url).map_err(|e| CacheError::Js(format!("{e:?}")))?;

    let headers = web_sys::Headers::new().map_err(|e| CacheError::Js(format!("{e:?}")))?;
    headers
        .set("Cache-Control", "public, s-maxage=31536000, immutable")
        .map_err(|e| CacheError::Js(format!("{e:?}")))?;
    headers
        .set("Content-Type", "application/octet-stream")
        .map_err(|e| CacheError::Js(format!("{e:?}")))?;

    let init = web_sys::ResponseInit::new();
    init.set_status(200);
    init.set_headers(&headers);

    let uint8 = js_sys::Uint8Array::from(body);
    let response = web_sys::Response::new_with_opt_buffer_source_and_init(Some(&uint8), &init)
        .map_err(|e| CacheError::Js(format!("{e:?}")))?;

    let promise = cache_put(&cache, &request, &response)?;
    JsFuture::from(promise)
        .await
        .map_err(|e| CacheError::Js(format!("{e:?}")))?;

    Ok(())
}

#[derive(Debug)]
pub enum CacheError {
    Js(String),
    TooLarge(u64),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheError::Js(msg) => write!(f, "CF Cache error: {msg}"),
            CacheError::TooLarge(size) => {
                write!(f, "artifact too large for CF Cache: {size} bytes")
            }
        }
    }
}

// -- CF Cache API FFI bindings --
// The Workers Cache API is accessed via `caches.default`.

#[wasm_bindgen]
extern "C" {
    type CacheStorage;

    #[wasm_bindgen(js_namespace = caches, js_name = default, getter)]
    fn default_cache() -> Cache;

    type Cache;

    #[wasm_bindgen(method, catch, js_name = match)]
    fn match_(this: &Cache, request: &web_sys::Request) -> Result<js_sys::Promise, JsValue>;

    #[wasm_bindgen(method, catch)]
    fn put(
        this: &Cache,
        request: &web_sys::Request,
        response: &web_sys::Response,
    ) -> Result<js_sys::Promise, JsValue>;
}

async fn open_default_cache() -> Result<Cache, CacheError> {
    Ok(default_cache())
}

fn cache_match(cache: &Cache, request: &web_sys::Request) -> Result<js_sys::Promise, CacheError> {
    cache
        .match_(request)
        .map_err(|e| CacheError::Js(format!("{e:?}")))
}

fn cache_put(
    cache: &Cache,
    request: &web_sys::Request,
    response: &web_sys::Response,
) -> Result<js_sys::Promise, CacheError> {
    cache
        .put(request, response)
        .map_err(|e| CacheError::Js(format!("{e:?}")))
}
