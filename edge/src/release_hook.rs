//! `POST /api/v1/newreleases/release` — newreleases.io's webhook for
//! `rust-lang/rust` releases (stow#880).
//!
//! A new stable rustc invalidates the whole preheated pool, so the
//! release wakes a wave: this route verifies the delivery's signature,
//! pins it to the one project the subscription covers, and forwards
//! the claimed version to the scheduler, which dispatches
//! `preheat-admin.yml` through the same GitHub arm the build dispatch
//! uses. The workflow itself confirms the version against
//! `channel-rust-stable.toml` before resolving, so a forged delivery
//! costs one manifest check and nothing more.
//!
//! newreleases.io signs per <https://newreleases.io/webhooks>:
//! `X-Newreleases-Signature` carries the hex HMAC-SHA256 of
//! `<X-Newreleases-Timestamp>.<raw-body>` under the webhook's signing
//! secret (`STOW_NEWRELEASES_WEBHOOK_SECRET`), and the timestamp is a
//! unix-second the receiver tolerances — 300 s here. Like the GitHub
//! `workflow-run` route, the signature is the authentication: the
//! route carries no caller-credential gate.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use skyzen::Request;
use skyzen::extract::Extractor;
#[cfg(target_arch = "wasm32")]
use skyzen::utils::Json;
use skyzen::utils::State;
#[cfg(target_arch = "wasm32")]
use skyzen_cloudflare::CfDurableNamespace;
#[cfg(target_arch = "wasm32")]
use skyzen_cloudflare::worker::send::IntoSendFuture as _;

#[cfg(target_arch = "wasm32")]
use crate::api::OkResponse;
use crate::errors::GetArtifactError;
#[cfg(target_arch = "wasm32")]
use crate::scheduler_client;

type HmacSha256 = Hmac<Sha256>;

/// The `STOW_NEWRELEASES_WEBHOOK_SECRET` binding, stored via `State`.
#[derive(Debug, Clone)]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub struct NewreleasesSecret(pub String);

/// The window a delivery's `X-Newreleases-Timestamp` must fall inside —
/// the doc leaves the tolerance to the receiver
/// (<https://newreleases.io/webhooks>, step 4). Five minutes covers a
/// slow hop while staying far inside newreleases.io's backoff retry.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
const TIMESTAMP_TOLERANCE_SECS: i64 = 300;

/// The project the subscription covers — the only payload this route
/// acts on. `rust-lang/rust` tags carry the bare `1.N.0` form, which
/// `WireRustcVersion` parses.
const PROVIDER: &str = "github";
const PROJECT: &str = "rust-lang/rust";

/// A delivery after its timestamp window and HMAC verified — the raw
/// body, undecoded.
#[derive(Debug)]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub struct VerifiedRelease {
    /// The exact body bytes the signature covered.
    body: Vec<u8>,
}

impl Extractor for VerifiedRelease {
    type Error = GetArtifactError;

    async fn extract(request: &mut Request) -> Result<Self, Self::Error> {
        let header = |name: &str| -> Result<String, GetArtifactError> {
            request
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
                .ok_or_else(|| {
                    GetArtifactError::BadRequestWithMessage(format!(
                        "missing required `{name}` header"
                    ))
                })
        };
        let timestamp = header("X-Newreleases-Timestamp")?;
        let signature = header("X-Newreleases-Signature")?;
        let body = skyzen_core::take_body_bytes::<Self>(request)
            .await
            .map_err(|error| {
                GetArtifactError::BadRequestWithMessage(format!("read webhook body: {error}"))
            })?
            .to_vec();
        let State(secret) =
            State::<NewreleasesSecret>::extract(request)
                .await
                .map_err(|error| {
                    GetArtifactError::InternalWithMessage(format!(
                        "newreleases secret binding missing: {error}"
                    ))
                })?;
        verify_signature(
            &secret.0,
            &timestamp,
            &signature,
            &body,
            now_secs(),
            TIMESTAMP_TOLERANCE_SECS,
        )?;
        Ok(Self { body })
    }
}

/// Constant-time check of the delivery: `timestamp` must sit inside
/// `±tolerance_secs` of `now_secs` (a replay outside the window fails
/// before the HMAC is even compared — it signs nothing fresher), and
/// `signature` must hex-decode to the HMAC-SHA256 of
/// `{timestamp}.{body}` under `secret`.
fn verify_signature(
    secret: &str,
    timestamp: &str,
    signature: &str,
    body: &[u8],
    now_secs: i64,
    tolerance_secs: i64,
) -> Result<(), GetArtifactError> {
    let stamped: i64 = timestamp
        .parse()
        .map_err(|_| GetArtifactError::Unauthorized)?;
    if (stamped - now_secs).abs() > tolerance_secs {
        return Err(GetArtifactError::Unauthorized);
    }
    let expected = hex::decode(signature).map_err(|_| GetArtifactError::Unauthorized)?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.verify_slice(&expected)
        .map_err(|_| GetArtifactError::Unauthorized)
}

/// The unix second now — the wall clock's source on either target.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn now_secs() -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        #[allow(clippy::cast_possible_truncation)]
        {
            (js_sys::Date::now() / 1_000.0) as i64
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(i64::MAX, |elapsed| {
                i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
            })
    }
}

/// The fields this route reads — newreleases.io sends the full
/// version-release document; the rest is ignored.
#[derive(Debug, serde::Deserialize)]
struct ReleaseEvent {
    provider: String,
    project: String,
    version: String,
}

/// The verified body's forward decision: `Some` carries the rust
/// release's claimed version — stripped of a leading `v`, which rust
/// tags do not carry but the parse must not hinge on — and `None` is
/// a delivery outside the subscription, answered 200 and dropped. The
/// `WireRustcVersion` parse is the shape gate; a malformed payload is
/// a 400.
fn decode_release(
    body: &[u8],
) -> Result<Option<stow_types::api::PreheatReleaseRequest>, GetArtifactError> {
    let event: ReleaseEvent = serde_json::from_slice(body).map_err(|error| {
        GetArtifactError::BadRequestWithMessage(format!("malformed release payload: {error}"))
    })?;
    if event.provider != PROVIDER || event.project != PROJECT {
        tracing::debug!(
            provider = %event.provider,
            project = %event.project,
            "ignoring release delivery outside the subscription"
        );
        return Ok(None);
    }
    let rustc_version = event
        .version
        .strip_prefix('v')
        .unwrap_or(&event.version)
        .parse()
        .map_err(|error| {
            GetArtifactError::BadRequestWithMessage(format!(
                "release version {:?}: {error}",
                event.version
            ))
        })?;
    Ok(Some(stow_types::api::PreheatReleaseRequest {
        rustc_version,
    }))
}

/// `POST /api/v1/newreleases/release`.
///
/// Deliveries naming another provider or project answer 200 — the
/// subscription is pinned to `rust-lang/rust`, and anything else is a
/// delivery, not a failure. A rust release forwards its `version`
/// (stripped of a leading `v`, which rust tags do not carry but the
/// parse must not hinge on) to the scheduler's `POST /preheat/release`;
/// the DO's `WireRustcVersion` decode is the shape gate, so a 400 from
/// it is a malformed payload, not a forward failure. Only a stale or
/// bad signature (401), a malformed body (400), and an upstream
/// failure (500) leave the 2xx path — non-2xx makes newreleases.io
/// retry under its exponential backoff.
#[cfg(target_arch = "wasm32")]
pub async fn newreleases_release(
    delivery: VerifiedRelease,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<OkResponse>, GetArtifactError> {
    let Some(request) = decode_release(&delivery.body)? else {
        return Ok(Json(OkResponse { ok: true }));
    };
    scheduler_client::send_preheat_release(&scheduler, &request)
        .into_send()
        .await?;
    tracing::info!(version = %request.rustc_version, "release delivery forwarded to the scheduler");
    Ok(Json(OkResponse { ok: true }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-webhook-secret";
    const BODY: &[u8] = br#"{"provider":"github","project":"rust-lang/rust","version":"1.90.0"}"#;

    fn sign(secret: &str, timestamp: &str, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
        mac.update(timestamp.as_bytes());
        mac.update(b".");
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    /// A correctly signed, in-window delivery verifies.
    #[test]
    fn valid_signature_verifies() {
        let timestamp = "1700000000";
        let signature = sign(SECRET, timestamp, BODY);
        verify_signature(SECRET, timestamp, &signature, BODY, 1_700_000_000, 300)
            .expect("a correctly signed in-window delivery verifies");
    }

    /// A signature computed under another secret is refused.
    #[test]
    fn wrong_secret_is_refused() {
        let timestamp = "1700000000";
        let signature = sign("another-secret", timestamp, BODY);
        let error = verify_signature(SECRET, timestamp, &signature, BODY, 1_700_000_000, 300)
            .expect_err("a foreign signature is refused");
        assert!(matches!(error, GetArtifactError::Unauthorized));
    }

    /// A delivery stamped outside the tolerance window is refused
    /// before the HMAC is consulted — the correct signature under the
    /// stale timestamp must still fail.
    #[test]
    fn stale_timestamp_is_refused() {
        let timestamp = "1700000000";
        let signature = sign(SECRET, timestamp, BODY);
        let error = verify_signature(SECRET, timestamp, &signature, BODY, 1_700_000_301, 300)
            .expect_err("a timestamp past the tolerance is refused");
        assert!(matches!(error, GetArtifactError::Unauthorized));
        verify_signature(SECRET, timestamp, &signature, BODY, 1_700_000_300, 300)
            .expect("the window's edge still verifies");
    }

    /// A body the signature does not cover is refused — the signature
    /// signs the timestamp string verbatim, so a tampered body fails
    /// the same way a wrong key does.
    #[test]
    fn tampered_body_is_refused() {
        let timestamp = "1700000000";
        let signature = sign(SECRET, timestamp, BODY);
        let error = verify_signature(SECRET, timestamp, &signature, b"{}", 1_700_000_000, 300)
            .expect_err("a body the signature does not cover is refused");
        assert!(matches!(error, GetArtifactError::Unauthorized));
    }

    /// A non-hex or truncated signature is refused, never panics.
    #[test]
    fn malformed_signature_is_refused() {
        let timestamp = "1700000000";
        for signature in ["not-hex", "ab", &"ff".repeat(31)] {
            let error = verify_signature(SECRET, timestamp, signature, BODY, 1_700_000_000, 300)
                .expect_err("a malformed signature is refused");
            assert!(matches!(error, GetArtifactError::Unauthorized));
        }
    }

    /// The forward's pin: the rust release's version is what the
    /// scheduler dispatch is told.
    #[test]
    fn rust_release_forwards_its_version() {
        let request = decode_release(BODY)
            .expect("a rust release decodes")
            .expect("a rust release forwards");
        assert_eq!(request.rustc_version.as_str(), "1.90.0");
    }

    /// Extra payload fields are ignored and a `v` prefix is stripped —
    /// the scheduler is never told a form `WireRustcVersion` rejects.
    #[test]
    fn release_with_extra_fields_and_v_prefix_decodes() {
        let body =
            br#"{"provider":"github","project":"rust-lang/rust","version":"v1.90.1","time":"2025-01-01T00:00:00Z","is_prerelease":false}"#;
        let request = decode_release(body)
            .expect("extra fields decode")
            .expect("a rust release forwards");
        assert_eq!(request.rustc_version.as_str(), "1.90.1");
    }

    /// A delivery outside the subscription answers 200 without a
    /// forward — the handler's `None` arm.
    #[test]
    fn foreign_project_is_not_forwarded() {
        for body in [
            br#"{"provider":"github","project":"water-rs/stow","version":"1.0.0"}"#.as_slice(),
            br#"{"provider":"gitlab","project":"rust-lang/rust","version":"1.90.0"}"#.as_slice(),
        ] {
            assert!(decode_release(body).expect("decodes").is_none());
        }
    }

    /// A malformed document or a missing `version` is a 400 — the
    /// only shape gate before the dispatch. A version that is merely
    /// wrong forwards anyway: the workflow's manifest check is the
    /// authority on it, so the edge wastes at most one manifest read.
    #[test]
    fn malformed_release_is_refused() {
        for body in [
            b"not json".as_slice(),
            br#"{"provider":"github","project":"rust-lang/rust","version":""}"#.as_slice(),
            br#"{"provider":"github","project":"rust-lang/rust"}"#.as_slice(),
        ] {
            let error = decode_release(body).expect_err("a malformed delivery is refused");
            assert!(matches!(error, GetArtifactError::BadRequestWithMessage(_)));
        }
    }
}
