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
/// `workflow_dispatch` POST runs inside the `complete-run` webhook.
/// Both headers and body must finish within the fetch's five seconds;
/// expiry aborts the network request and releases its outbound slot.
#[cfg(target_arch = "wasm32")]
const DISPATCH_FETCH_TIMEOUT_MS: u32 = 5_000;

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
        // The native signal stays attached through CfFetch's Request
        // clone and response consumption. A Rust future race would only
        // bound headers and would not abort the underlying fetch.
        let worker_request = {
            let init = web_sys::RequestInit::new();
            init.set_signal(Some(&web_sys::AbortSignal::timeout_with_u32(
                DISPATCH_FETCH_TIMEOUT_MS,
            )));
            web_sys::Request::new_with_request_and_init(worker_request.inner(), &init)
                .map(worker::Request::from)
                .map_err(|error| DispatchError::Network(worker::Error::from(error).to_string()))?
        };
        let response = CfFetch
            .request(&worker_request)
            .await
            .map(GuardedResponse::new)
            .map_err(|error| DispatchError::Network(error.to_string()))?;
        let status = response.get_ref().status_code();
        // The contract reads only these headers; a `worker::Response`
        // exposes them by name rather than as an enumerable map.
        let headers = [
            "link",
            "retry-after",
            "x-ratelimit-remaining",
            "x-ratelimit-reset",
        ]
        .into_iter()
        .filter_map(|name| {
            response
                .get_ref()
                .header(name)
                .map(|value| (name.to_owned(), value))
        })
        .collect();
        // CI answers are buffered JSON. Native arrayBuffer avoids a
        // per-chunk Wasm reader and its releaseLock rejection on abort.
        let body = {
            let response: web_sys::Response = response.into_inner().into();
            response
                .array_buffer()
                .map_err(|error| DispatchError::Response(worker::Error::from(error).to_string()))?
        };
        let body = wasm_bindgen_futures::JsFuture::from(body)
            .into_send()
            .await
            .map_err(|error| DispatchError::Response(worker::Error::from(error).to_string()))?;
        Ok(CiResponse {
            status,
            headers,
            body: js_sys::Uint8Array::new(&body).to_vec(),
        })
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
mod window;
#[cfg(target_arch = "wasm32")]
pub(super) use window::{dispatch_claims, retain_ci_limit};
