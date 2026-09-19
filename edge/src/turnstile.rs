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
use skyzen::{Body, Response, StatusCode};

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

/// The only `error-codes` value a client ever sees when siteverify itself
/// could not be reached or read — transport failures, non-2xx replies,
/// undecodable bodies all collapse here. The real [`TurnstileError`] is
/// logged server-side and never reflected to the client.
pub const SITEVERIFY_UNAVAILABLE_CODE: &str = "siteverify-unavailable";

/// The `error-codes` a request is rejected with, or `None` to admit it.
///
/// A `success: false` body reports its own `error-codes` verbatim. A
/// successful challenge must additionally name `expected_hostname` — the
/// `TURNSTILE_HOSTNAME` binding, the site the widget is registered for — as
/// the host it was solved on: a token minted for a different site proves
/// nothing about this deployment, so a missing or mismatched hostname is
/// rejected `hostname-mismatch`. The binding rather than the request's
/// `Host` header is the reference because Cloudflare's always-pass test
/// keys report `example.com` whatever host the mock stack runs on.
/// `action` is deliberately not validated: the invisible widget sets none.
pub fn rejection_error_codes(
    siteverify: &SiteverifyOutcome,
    expected_hostname: &str,
) -> Option<Vec<String>> {
    if !siteverify.success {
        return Some(siteverify.error_codes.clone());
    }
    if siteverify.hostname.as_deref() == Some(expected_hostname) {
        return None;
    }
    Some(vec!["hostname-mismatch".to_owned()])
}

/// The 403 response the request-API contract guarantees for a Turnstile
/// rejection: `{"error":"turnstile rejected","error-codes":[...]}`.
/// Skyzen's shared error renderer emits only `{"error": ...}`, so the
/// handler builds this body directly — mirroring that renderer's
/// construction exactly.
pub fn rejected_response(error_codes: &[String]) -> Response {
    #[derive(serde::Serialize)]
    struct RejectionBody<'a> {
        error: &'a str,
        #[serde(rename = "error-codes")]
        error_codes: &'a [String],
    }
    let payload = serde_json::to_vec(&RejectionBody {
        error: "turnstile rejected",
        error_codes,
    })
    .expect("a struct of string slices serializes to JSON");
    let mut response = Response::new(Body::from(payload));
    *response.status_mut() = StatusCode::FORBIDDEN;
    response.headers_mut().insert(
        skyzen::header::CONTENT_TYPE,
        skyzen::header::HeaderValue::from_static("application/json"),
    );
    response
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
///
/// No `Debug`: `secret` is a credential and must not be printable by
/// accident — same precedent as `GitHubAppTokenRow`.
#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
pub struct CfTurnstileVerifier {
    /// The `TURNSTILE_SECRET_KEY` binding — a credential; never logged or
    /// returned in a response body.
    secret: String,
    /// The `TURNSTILE_HOSTNAME` binding: the hostname siteverify must
    /// report for a token to count.
    expected_hostname: String,
}

#[cfg(target_arch = "wasm32")]
impl CfTurnstileVerifier {
    /// Construct from the probed `TURNSTILE_SECRET_KEY` and
    /// `TURNSTILE_HOSTNAME` bindings.
    pub const fn new(secret: String, expected_hostname: String) -> Self {
        Self {
            secret,
            expected_hostname,
        }
    }

    /// The hostname a token's siteverify report must carry.
    #[must_use]
    pub fn expected_hostname(&self) -> &str {
        &self.expected_hostname
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
    use super::{SiteverifyOutcome, parse_siteverify, rejected_response, rejection_error_codes};

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
        assert!(outcome.error_codes.is_empty(), "{:?}", outcome.error_codes);
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

    fn outcome(success: bool, error_codes: &[&str], hostname: Option<&str>) -> SiteverifyOutcome {
        SiteverifyOutcome {
            success,
            error_codes: error_codes.iter().map(|code| (*code).to_owned()).collect(),
            hostname: hostname.map(str::to_owned),
            challenge_ts: None,
        }
    }

    #[test]
    fn rejection_reports_siteverify_error_codes_verbatim() {
        let siteverify = outcome(
            false,
            &["timeout-or-duplicate", "invalid-input-response"],
            None,
        );
        assert_eq!(
            rejection_error_codes(&siteverify, "stow.waterui.dev"),
            Some(vec![
                "timeout-or-duplicate".to_owned(),
                "invalid-input-response".to_owned()
            ])
        );
    }

    #[test]
    fn rejection_is_none_only_when_hostname_matches_the_configured_site() {
        let siteverify = outcome(true, &[], Some("stow.waterui.dev"));
        assert_eq!(rejection_error_codes(&siteverify, "stow.waterui.dev"), None);
        assert_eq!(
            rejection_error_codes(&siteverify, "other.example"),
            Some(vec!["hostname-mismatch".to_owned()])
        );
        // A success body without a hostname cannot prove where the token
        // was minted — fail closed.
        let siteverify = outcome(true, &[], None);
        assert_eq!(
            rejection_error_codes(&siteverify, "stow.waterui.dev"),
            Some(vec!["hostname-mismatch".to_owned()])
        );
    }

    #[tokio::test]
    async fn rejection_response_is_403_with_contract_body() {
        let mut response =
            rejected_response(&["timeout-or-duplicate".to_owned(), "other".to_owned()]);
        assert_eq!(response.status(), skyzen::StatusCode::FORBIDDEN);
        assert_eq!(
            response.body_mut().as_str().await.expect("utf8 body"),
            r#"{"error":"turnstile rejected","error-codes":["timeout-or-duplicate","other"]}"#
        );
        assert_eq!(
            response
                .headers()
                .get(skyzen::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
    }
}
