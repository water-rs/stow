//! Re-exports of the `worker::Request` builder helpers that now live in
//! `skyzen-cloudflare::http_request`. Kept as a stow-local module so existing
//! call sites (`crate::cf_http::*`) continue to compile after the helper was
//! pushed upstream — see plan task P3.4.

pub use skyzen_cloudflare::{bare_request, json_request};
