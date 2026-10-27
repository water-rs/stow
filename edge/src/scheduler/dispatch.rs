//! The scheduler's [`stow_types::ci::CiTransport`] — the wasm half of
//! the one privileged CI interface (stow#877). Request construction,
//! the GitHub-shaped paths, occupancy attribution and answer decodes
//! live in `stow_types::ci` shared with `stow-admin`; what stays here
//! is the Cloudflare plumbing every outbound call rides: `CfFetch`
//! under the invocation's [`OutboundPool`] bound, with the response
//! buffered inside the fetch guard.

#[cfg(target_arch = "wasm32")]
use skyzen_cloudflare::worker::send::IntoSendFuture as _;
#[cfg(target_arch = "wasm32")]
use skyzen_cloudflare::{CfFetch, worker};

#[cfg(target_arch = "wasm32")]
use crate::cf_http;
#[cfg(target_arch = "wasm32")]
use crate::fetch_guard::OutboundPool;
#[cfg(target_arch = "wasm32")]
use crate::fetch_guard::{FetchedResponse, GuardedResponse};
#[cfg(target_arch = "wasm32")]
use stow_types::ci::{CiRequest, CiResponse, CiTransport};

#[cfg(target_arch = "wasm32")]
pub use stow_types::ci::{CiInterface, DispatchError};

/// `CfFetch` under the pool's outbound bound — the transport the
/// scheduler's [`CiInterface`] drives on wasm.
#[cfg(target_arch = "wasm32")]
pub struct CfTransport {
    pool: OutboundPool,
}

#[cfg(target_arch = "wasm32")]
impl CfTransport {
    /// A transport bound to `pool` — each call takes one slot.
    pub const fn new(pool: OutboundPool) -> Self {
        Self { pool }
    }
}

/// The per-fetch cap every outbound CI call rides (stow#940): a
/// `workflow_dispatch` POST now runs inside the `complete-run`
/// webhook, which GitHub abandons at 10 s — a fetch gets 5 s, so even
/// a bound of four sequential rounds cannot carry a request past the
/// delivery window.
#[cfg(target_arch = "wasm32")]
const DISPATCH_FETCH_TIMEOUT_MS: u64 = 5_000;

#[cfg(target_arch = "wasm32")]
impl CiTransport for CfTransport {
    async fn send(&self, request: CiRequest) -> Result<CiResponse, DispatchError> {
        let method = match request.method {
            "GET" => worker::Method::Get,
            "POST" => worker::Method::Post,
            other => {
                return Err(DispatchError::Network(format!(
                    "unsupported method {other}"
                )));
            }
        };
        let headers: Vec<(&str, &str)> = request
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let worker_request =
            cf_http::bare_request(method, &request.url, &headers, request.body.as_deref())
                .map_err(|error| DispatchError::Network(error.to_string()))?;
        let _slot = self.pool.slot().await;
        // A `workflow_dispatch` POST rides a completion webhook's
        // request under stow#940, whose 10 s GitHub delivery window
        // bounds the whole pass: one fetch must finish well inside
        // it. A timed-out fetch drops its pool slot and the claim
        // takes the dispatch-failure backoff.
        let fetch = CfFetch.request(&worker_request).into_send();
        let timeout =
            worker::Delay::from(std::time::Duration::from_millis(DISPATCH_FETCH_TIMEOUT_MS))
                .into_send();
        futures_util::pin_mut!(fetch);
        futures_util::pin_mut!(timeout);
        let response = match futures_util::future::select(fetch, timeout).await {
            futures_util::future::Either::Left((response, _)) => response
                .map(GuardedResponse::new)
                .map_err(|error| DispatchError::Network(error.to_string()))?,
            futures_util::future::Either::Right(((), _)) => {
                return Err(DispatchError::Network(format!(
                    "dispatch fetch exceeded {DISPATCH_FETCH_TIMEOUT_MS} ms"
                )));
            }
        };
        let status = response.get_ref().status_code();
        // The contract reads only these headers; a `worker::Response`
        // exposes them by name rather than as an enumerable map.
        let headers = ["link", "retry-after", "x-ratelimit-remaining"]
            .into_iter()
            .filter_map(|name| {
                response
                    .get_ref()
                    .header(name)
                    .map(|value| (name.to_owned(), value))
            })
            .collect();
        let body = response
            .into_inner()
            .text()
            .await
            .map_err(DispatchError::Response)?
            .into_bytes();
        Ok(CiResponse {
            status,
            headers,
            body,
        })
    }
}
