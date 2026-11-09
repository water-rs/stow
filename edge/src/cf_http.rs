//! Re-exports of the `worker::Request` builder helpers that now live in
//! `skyzen-cloudflare::http_request`. Kept as a stow-local module so existing
//! call sites (`crate::cf_http::*`) continue to compile after the helper was
//! pushed upstream — see plan task P3.4.

pub use skyzen_cloudflare::bare_request;

/// CI control requests and records verification must leave room inside
/// GitHub's webhook delivery deadline for the scheduler's own work.
pub type RequestSignal = skyzen_cloudflare::worker::send::SendWrapper<web_sys::AbortSignal>;

/// The same signal can bound an authenticated request and its retry.
#[cfg(target_arch = "wasm32")]
pub fn control_deadline() -> RequestSignal {
    skyzen_cloudflare::worker::send::SendWrapper::new(web_sys::AbortSignal::timeout_with_u32(5_000))
}

/// Attach a native cancellation signal through response consumption.
pub fn with_abort_signal(
    request: &skyzen_cloudflare::worker::Request,
    signal: &web_sys::AbortSignal,
) -> Result<skyzen_cloudflare::worker::Request, skyzen_cloudflare::worker::Error> {
    let init = web_sys::RequestInit::new();
    init.set_signal(Some(signal));
    web_sys::Request::new_with_request_and_init(request.inner(), &init)
        .map(skyzen_cloudflare::worker::Request::from)
        .map_err(skyzen_cloudflare::worker::Error::from)
}
