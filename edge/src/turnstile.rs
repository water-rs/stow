//! Cloudflare Turnstile verification for the human request lane.
//!
//! `POST /api/v1/requests` is public but must stay human-only: the request
//! page embeds an invisible Turnstile widget and posts the token it mints.
//! Verification posts `secret`, `response`, and the caller's `remoteip` to
//! siteverify. The secret is a Worker secret binding probed at startup and
//! is never logged or returned in a response.
//!
//! The trait boundary keeps the handler testable: `CfTurnstileVerifier`
//! does the wasm fetch while host tests drive canned siteverify bodies
//! through [`parse_siteverify`].

use std::future::Future;

use serde::Deserialize;

use crate::errors::TurnstileError;

/// The siteverify endpoint Turnstile tokens are checked against.
#[cfg(target_arch = "wasm32")]
const SITEVERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/// Parsed body of a Turnstile siteverify response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SiteverifyOutcome {
    /// Whether the submitted token passed the challenge.
    pub success: bool,
    /// Cloudflare error codes explaining a rejection (e.g.
    /// `timeout-or-duplicate`, `invalid-input-response`).
    #[serde(default, rename = "error-codes")]
    pub error_codes: Vec<String>,
    /// Hostname of the site the challenge ran on.
    #[serde(default)]
    pub hostname: Option<String>,
    /// ISO 8601 timestamp of when the challenge was solved.
    #[serde(default)]
    pub challenge_ts: Option<String>,
}

/// Parse a siteverify JSON body — kept separate from the network call so
/// host tests can drive every documented response shape.
///
/// # Errors
/// [`TurnstileError::Decode`] when the body is not valid siteverify JSON.
pub fn parse_siteverify(body: &str) -> Result<SiteverifyOutcome, TurnstileError> {
    serde_json::from_str(body).map_err(|error| TurnstileError::Decode(error.to_string()))
}

/// Verifies Turnstile tokens — `CfTurnstileVerifier` on wasm, stubs in
/// host tests.
pub trait TurnstileVerifier: Sync {
    /// Check `token` against siteverify; `remoteip` is the caller's
    /// `CF-Connecting-IP` when present.
    fn verify(
        &self,
        token: &str,
        remoteip: Option<&str>,
    ) -> impl Future<Output = Result<SiteverifyOutcome, TurnstileError>> + Send;
}

/// Production verifier bound to `CfFetch`.
#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone)]
pub struct CfTurnstileVerifier {
    /// The `TURNSTILE_SECRET_KEY` binding — a credential; never logged or
    /// returned in a response body.
    secret: String,
}

#[cfg(target_arch = "wasm32")]
impl CfTurnstileVerifier {
    /// Construct from the probed secret binding.
    pub const fn new(secret: String) -> Self {
        Self { secret }
    }
}

#[cfg(target_arch = "wasm32")]
impl TurnstileVerifier for CfTurnstileVerifier {
    async fn verify(
        &self,
        token: &str,
        remoteip: Option<&str>,
    ) -> Result<SiteverifyOutcome, TurnstileError> {
        use skyzen_cloudflare::worker::send::{IntoSendFuture as _, SendWrapper};
        use web_sys::UrlSearchParams;

        let form = UrlSearchParams::new()
            .map_err(|error| TurnstileError::Request(format!("init form: {error:?}")))?;
        form.set("secret", &self.secret);
        form.set("response", token);
        if let Some(ip) = remoteip {
            form.set("remoteip", ip);
        }
        let body = form
            .to_string()
            .as_string()
            .ok_or_else(|| TurnstileError::Request("encode siteverify form".to_owned()))?;
        let request = SendWrapper::new(
            crate::cf_http::bare_request(
                skyzen_cloudflare::worker::Method::Post,
                SITEVERIFY_URL,
                &[("Content-Type", "application/x-www-form-urlencoded")],
                Some(body.as_bytes()),
            )
            .map_err(|error| TurnstileError::Request(format!("build request: {error}")))?,
        );
        let mut response = SendWrapper::new(
            skyzen_cloudflare::CfFetch
                .request(&request)
                .await
                .map_err(|error| TurnstileError::Request(error.to_string()))?,
        );
        let status = response.status_code();
        let text = response
            .text()
            .into_send()
            .await
            .map_err(|error| TurnstileError::Decode(error.to_string()))?;
        if !(200..300).contains(&status) {
            return Err(TurnstileError::Http { status, body: text });
        }
        parse_siteverify(&text)
    }
}

#[cfg(test)]
mod tests {
    use super::parse_siteverify;

    #[test]
    fn parses_success_body() {
        let outcome = parse_siteverify(
            r#"{"success":true,"challenge_ts":"2026-01-15T12:34:56Z","hostname":"stow.waterui.dev","error-codes":[],"action":"","cdata":""}"#,
        )
        .expect("parse success");
        assert!(outcome.success);
        assert_eq!(outcome.hostname.as_deref(), Some("stow.waterui.dev"));
        assert_eq!(
            outcome.challenge_ts.as_deref(),
            Some("2026-01-15T12:34:56Z")
        );
        assert!(outcome.error_codes.is_empty());
    }

    #[test]
    fn parses_failure_body_with_error_codes() {
        let outcome = parse_siteverify(
            r#"{"success":false,"error-codes":["timeout-or-duplicate","invalid-input-response"]}"#,
        )
        .expect("parse failure");
        assert!(!outcome.success);
        assert_eq!(
            outcome.error_codes,
            vec![
                "timeout-or-duplicate".to_owned(),
                "invalid-input-response".to_owned()
            ]
        );
        assert_eq!(outcome.hostname, None);
        assert_eq!(outcome.challenge_ts, None);
    }

    #[test]
    fn rejects_malformed_body() {
        assert!(parse_siteverify("not json").is_err());
        assert!(parse_siteverify(r#"{"success":"yes"}"#).is_err());
    }
}
