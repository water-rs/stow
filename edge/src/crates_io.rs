//! Cloudflare-fetch-backed [`CratesIo`] client reading the sparse registry index.
//!
//! crates.io's JSON API rate-limits shared Worker egress IPs aggressively:
//! a burst of two calls per cold crate collapsed into 429s and a redacted
//! 500 (issue #91). The sparse index serves every published version of a
//! crate — features, dependencies, and yanked flags — in one static file,
//! the same file cargo itself fetches, so a single request covers a whole
//! metadata lookup and the CDN absorbs the parallelism the API could not.
//! Responses are additionally cached at the Cloudflare edge, so repeated
//! lookups across invocations rarely reach the index at all.
//!
//! This is the only place edge code talks to crates.io over the network;
//! resolver logic depends on the [`CratesIo`] trait so it stays host-testable.

use std::time::Duration;

use skyzen_cloudflare::worker::send::SendWrapper;
use skyzen_cloudflare::{CfFetch, worker};

use crate::crates_io_fetch::{FetchOutcome, decide, retry_delay};
use crate::crates_io_index::{index_url, parse_index_file};
use crate::dependency_resolver::{CratesIo, CratesIoSearchHit, PublishedRelease};
use crate::errors::ResolverError;
use crate::fetch_guard::{GuardedResponse, outbound_slot};

const CRATES_IO_API_BASE: &str = "https://crates.io/api/v1/crates";
/// The user agent the data-access policy asks for: the tool's name and
/// version plus the repository that operates it.
const CRATES_IO_USER_AGENT: &str = concat!(
    "stow-edge/",
    env!("CARGO_PKG_VERSION"),
    " (https://github.com/water-rs/stow)"
);
/// Index files are static content that only changes when the crate
/// publishes; a one-hour edge TTL absorbs repeated lookups across worker
/// invocations while staying well under the six-hour TTL the D1 graph
/// cache already tolerates.
const INDEX_EDGE_CACHE_TTL_SECONDS: i32 = 3600;
/// Fetch attempts before giving up: transient statuses and network errors
/// get bounded exponential backoff; deterministic answers (2xx, 404, and
/// other 4xx) are final on the first try.
const MAX_ATTEMPTS: u32 = 4;

/// Production crates.io client running on Cloudflare Workers fetch.
#[derive(Debug, Clone, Copy, Default)]
pub struct CfCratesIo;

#[derive(Debug, serde::Deserialize)]
struct CratesIoSearchResponse {
    crates: Vec<CratesIoSearchHit>,
}

impl CratesIo for CfCratesIo {
    async fn package_metadata(
        &self,
        crate_name: &str,
    ) -> Result<Vec<PublishedRelease>, ResolverError> {
        let body = fetch_index_file(crate_name).await?;
        parse_index_file(crate_name, &body)
    }

    async fn search(
        &self,
        query: &str,
        limit: u32,
    ) -> Result<Vec<CratesIoSearchHit>, ResolverError> {
        // The query is arbitrary user input, so it is percent-encoded
        // before it becomes part of the URL.
        let encoded = String::from(js_sys::encode_uri_component(query));
        let url = format!("{CRATES_IO_API_BASE}?q={encoded}&per_page={limit}");
        // crates.io has no 404 for a search that matches nothing, so this
        // arm only fires if the endpoint itself disappears.
        let response: CratesIoSearchResponse = fetch_json(&url, false, &|| {
            ResolverError::CratesIo(format!(
                "crates.io {CRATES_IO_API_BASE} search returned 404"
            ))
        })
        .await?;
        Ok(response.crates)
    }
}

/// GET the crate's index file, retrying transient failures with bounded
/// exponential backoff (`Retry-After` honored when the index sends it).
/// Every failure still surfaces the last error — retries hide flakiness,
/// never the failure itself.
async fn fetch_index_file(crate_name: &str) -> Result<String, ResolverError> {
    fetch_text(&index_url(crate_name), true, &|| {
        ResolverError::CrateNotPublished {
            crate_name: crate_name.to_owned(),
        }
    })
    .await
}

/// GET `url` and decode the body as `T`. The HTTP status is checked
/// before parsing: a 404 body is not the requested schema, so without the
/// check a missing crate surfaced as a decode error — and a 500.
/// `missing` says what a 404 on *this* URL means, because only the caller
/// knows what it asked for. Other non-2xx statuses stay
/// [`ResolverError::CratesIo`]; the error body is never read, since
/// upstream diagnostics must not reach clients.
async fn fetch_json<T: serde::de::DeserializeOwned>(
    url: &str,
    cacheable: bool,
    missing: &(impl Fn() -> ResolverError + Sync),
) -> Result<T, ResolverError> {
    let body = fetch_text(url, cacheable, missing).await?;
    serde_json::from_str(&body)
        .map_err(|error| ResolverError::Json(format!("decode {url}: {error}")))
}

/// GET `url` as text, retrying transient failures with bounded
/// exponential backoff (`Retry-After` honored when the server sends it).
/// `cacheable` pins the response into the Cloudflare edge cache; only
/// index files qualify — API responses (search) must not be pinned.
async fn fetch_text(
    url: &str,
    cacheable: bool,
    missing: &(impl Fn() -> ResolverError + Sync),
) -> Result<String, ResolverError> {
    use skyzen_cloudflare::worker::send::IntoSendFuture as _;

    for attempt in 0..MAX_ATTEMPTS {
        match fetch_once(url, cacheable, missing, attempt).await {
            FetchOutcome::Body(body) => return Ok(body),
            FetchOutcome::Retryable { error, delay_ms } => {
                if attempt + 1 >= MAX_ATTEMPTS {
                    return Err(error);
                }
                tracing::warn!(
                    url,
                    attempt = attempt + 1,
                    delay_ms,
                    %error,
                    "retrying crates.io fetch"
                );
                worker::Delay::from(Duration::from_millis(delay_ms))
                    .into_send()
                    .await;
            }
            FetchOutcome::Fatal(error) => return Err(error),
        }
    }
    unreachable!("the loop returns on every terminal attempt")
}

async fn fetch_once(
    url: &str,
    cacheable: bool,
    missing: &(impl Fn() -> ResolverError + Sync),
    attempt: u32,
) -> FetchOutcome {
    // The slot bounds the fan-out `fetch_releases_by_name` drives
    // against the Workers connection limit; `decide` releases it once
    // the body reaches its terminal state.
    let _slot = outbound_slot().await;
    // `SendWrapper` keeps the `JsValue`-backed request handle sendable
    // across the await so the trait's `+ Send` future bound holds.
    let request = match build_get_request(url, cacheable) {
        Ok(request) => SendWrapper::new(request),
        Err(error) => return FetchOutcome::Fatal(error),
    };
    let response = match CfFetch.request(&request).await {
        Ok(response) => GuardedResponse::new(SendWrapper::new(response)),
        Err(error) => {
            return FetchOutcome::Retryable {
                error: ResolverError::CratesIo(format!("fetch {url}: {error}")),
                delay_ms: retry_delay(attempt, None),
            };
        }
    };
    decide(response, url, missing, attempt).await
}

fn build_get_request(url: &str, cacheable: bool) -> Result<worker::Request, ResolverError> {
    let headers = worker::Headers::new();
    headers
        .set("User-Agent", CRATES_IO_USER_AGENT)
        .map_err(|error| ResolverError::CratesIo(error.to_string()))?;

    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Get);
    init.with_headers(headers);
    if cacheable {
        // Cache index responses at the Cloudflare edge: identical lookups
        // from any invocation in the colo hit the cache instead of the
        // origin.
        init.with_cf_properties(worker::CfProperties {
            cache_everything: Some(true),
            cache_ttl: Some(INDEX_EDGE_CACHE_TTL_SECONDS),
            ..worker::CfProperties::default()
        });
    }

    worker::Request::new_with_init(url, &init)
        .map_err(|error| ResolverError::CratesIo(error.to_string()))
}
