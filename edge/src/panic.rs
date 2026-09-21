//! The anonymous-traffic circuit breaker ("panic switch").
//!
//! Cloudflare has no spend cap, so under an attack the only true backstop
//! is shedding anonymous traffic while trusted CI keeps working. The flag
//! itself lives in the scheduler Durable Object's `settings` table; this
//! module holds the pieces that decide over it on the edge — the shed
//! response every anonymous route answers, the flag's cache-entry codec,
//! and the wasm-side [`PanicGate`] middleware `entry.rs` applies to the
//! anonymous route group.

use skyzen::header::{CONTENT_TYPE, HeaderValue, RETRY_AFTER};
use skyzen::{Body, Response, StatusCode};

/// `Retry-After` seconds a shed response asks clients to wait — long
/// enough to thin a flood, short enough that a flipped switch recovers
/// within minutes.
const SHED_RETRY_AFTER: &str = "300";

/// The `503 Service Unavailable` every anonymous route answers while the
/// panic flag is on — and while the flag cannot be read, since a shed
/// request is cheaper than an unbounded one.
pub fn shed_response() -> Response {
    #[derive(serde::Serialize)]
    struct ShedBody<'a> {
        error: &'a str,
    }
    let payload = serde_json::to_vec(&ShedBody {
        error: "stow is shedding anonymous traffic; retry later",
    })
    .expect("a struct of string slices serializes to JSON");
    let mut response = Response::new(Body::from(payload));
    *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static(SHED_RETRY_AFTER));
    response
}

/// Serialize the flag the way its Cache API entry stores it.
pub fn flag_body(enabled: bool) -> Vec<u8> {
    serde_json::to_vec(&stow_types::api::PanicSwitch { enabled })
        .expect("PanicSwitch is a single bool field; serialization cannot fail")
}

/// Decode a cached flag entry. `None` on a corrupt body — callers treat
/// it as a cache miss and re-read the Durable Object.
pub fn parse_flag(bytes: &[u8]) -> Option<bool> {
    serde_json::from_slice::<stow_types::api::PanicSwitch>(bytes)
        .map(|switch| switch.enabled)
        .ok()
}

/// Skyzen middleware `entry.rs` applies to every anonymous route: while
/// the scheduler-held panic flag is on, the request never reaches its
/// handler and is answered by [`shed_response`] instead.
///
/// The flag is read through the Cache API under a fixed key — a hit is
/// effectively free, so per-request cost is one local cache probe. A miss
/// or a cache error falls through to the Durable Object and re-populates
/// the entry; an object error fails closed.
#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone)]
pub struct PanicGate {
    scheduler: skyzen_cloudflare::CfDurableNamespace,
    cache: skyzen_cloudflare::CfCache,
}

#[cfg(target_arch = "wasm32")]
impl PanicGate {
    /// Capture the scheduler namespace and Cache API handle the gate
    /// reads the flag through.
    pub const fn new(
        scheduler: skyzen_cloudflare::CfDurableNamespace,
        cache: skyzen_cloudflare::CfCache,
    ) -> Self {
        Self { scheduler, cache }
    }

    /// Cache-first flag read. A cache error is logged and treated as a
    /// miss — the object is then read — while an object error sheds the
    /// request: a shed request is cheaper than an unbounded one.
    async fn enabled(&self) -> bool {
        match crate::cache::get_panic_flag(&self.cache).await {
            Ok(Some(enabled)) => return enabled,
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, "panic flag cache read failed; consulting scheduler");
            }
        }
        match crate::scheduler_client::get_panic(&self.scheduler).await {
            Ok(switch) => {
                if let Err(error) = crate::cache::put_panic_flag(&self.cache, switch.enabled).await
                {
                    tracing::warn!(%error, "panic flag cache write failed");
                }
                switch.enabled
            }
            Err(error) => {
                tracing::error!(%error, "failed to read panic flag from scheduler; shedding request");
                true
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl skyzen::middleware::Middleware for PanicGate {
    async fn handle(
        &self,
        request: &mut skyzen::Request,
        next: skyzen::middleware::Next<'_>,
    ) -> Result<Response, skyzen::Error> {
        if self.enabled().await {
            return Ok(shed_response());
        }
        next.run(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_flag, shed_response};

    #[tokio::test]
    async fn shed_response_is_503_json_with_retry_after() {
        let mut response = shed_response();
        assert_eq!(response.status(), skyzen::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get(skyzen::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            response
                .headers()
                .get(skyzen::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("300")
        );
        assert_eq!(
            response.body_mut().as_str().await.expect("utf8 body"),
            r#"{"error":"stow is shedding anonymous traffic; retry later"}"#
        );
    }

    #[test]
    fn flag_codec_round_trips_and_rejects_garbage() {
        for enabled in [true, false] {
            let body = serde_json::to_vec(&stow_types::api::PanicSwitch { enabled })
                .expect("serialize PanicSwitch");
            assert_eq!(parse_flag(&body), Some(enabled));
        }
        assert_eq!(parse_flag(b"not json"), None);
        assert_eq!(parse_flag(br#"{"enabled":"yes"}"#), None);
        assert_eq!(parse_flag(b""), None);
    }
}
