//! GitHub App authentication for the scheduler's `workflow_dispatch`.
//!
//! Production dispatch is authorized by a GitHub App installation token
//! minted on the edge: the App's private key PEM is converted to PKCS#8
//! DER, wrapped in an RS256 JWT signed through `WebCrypto` (`crypto.subtle`
//! — Workers has no Node `crypto`), and exchanged at the GitHub API for a
//! one-hour installation token. The minted token is cached in the Durable
//! Object's SQL storage (`github_app_token`) and reused while more than
//! five minutes of validity remain, so a Durable Object restart does not
//! mint again.
//!
//! PEM decoding and JWT header/claims encoding are pure functions
//! unit-tested on the host; `WebCrypto` signing and the token-exchange POST
//! are `wasm32`-only like the rest of the Cloudflare-bound modules. The
//! token and the JWT are credentials — they are never logged and never
//! appear in `Debug` output.

use base64::Engine as _;
use serde::Serialize;

#[cfg(target_arch = "wasm32")]
use skyzen_services::durable::DurableDb;

use crate::errors::QueueError;

/// A GitHub App installation token, either freshly minted or loaded from
/// the Durable Object cache.
pub struct InstallationToken {
    /// The bearer credential for `workflow_dispatch` requests.
    pub token: String,
    /// GitHub's `expires_at` (RFC 3339), stored verbatim in DO storage and
    /// compared there with `strftime('%s', ...)`.
    pub expires_at: String,
}

impl std::fmt::Debug for InstallationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstallationToken")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// The three GitHub App bindings the scheduler reads from Worker env:
/// `GITHUB_APP_ID` and `GITHUB_APP_INSTALLATION_ID` vars plus the
/// `GITHUB_APP_PRIVATE_KEY` secret.
#[cfg(target_arch = "wasm32")]
pub struct AppConfig {
    /// The App's numeric ID (`iss` of the JWT).
    pub app_id: String,
    /// The App's installation ID on `water-rs`, which the token exchange
    /// addresses.
    pub installation_id: String,
    /// The App's private key PEM (`RSA PRIVATE KEY` or `PRIVATE KEY`).
    pub private_key_pem: String,
}

#[cfg(target_arch = "wasm32")]
impl std::fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppConfig")
            .field("app_id", &self.app_id)
            .field("installation_id", &self.installation_id)
            .field("private_key_pem", &"<redacted>")
            .finish()
    }
}

/// Errors raised while minting or loading a GitHub App installation token.
#[derive(Debug, thiserror::Error)]
pub enum GitHubAppError {
    /// The `GITHUB_APP_PRIVATE_KEY` PEM could not be decoded or converted
    /// to PKCS#8.
    #[error("GITHUB_APP_PRIVATE_KEY: {0}")]
    PrivateKey(String),
    /// JWT header/claims serialization failed.
    #[error("encode JWT: {0}")]
    Encode(String),
    /// `WebCrypto` key import or RS256 signing failed.
    #[error("webcrypto RS256 sign: {0}")]
    Sign(String),
    /// The token-exchange request failed or its response could not be
    /// decoded.
    #[error("installation token exchange: {0}")]
    Exchange(String),
    /// The token exchange returned a non-2xx status.
    #[error("installation token exchange returned HTTP {status}: {body}")]
    ExchangeStatus {
        /// HTTP status code.
        status: u16,
        /// Response body for diagnostics.
        body: String,
    },
    /// The Durable Object token cache could not be read or written.
    #[error("token cache: {0}")]
    Storage(#[from] QueueError),
}

/// Decode a GitHub App private-key PEM into PKCS#8 DER for `WebCrypto`'s
/// `importKey("pkcs8", ...)`.
///
/// GitHub issues `RSA PRIVATE KEY` (PKCS#1) PEMs, which are re-wrapped
/// into a PKCS#8 `PrivateKeyInfo` carrying the rsaEncryption algorithm;
/// `PRIVATE KEY` (PKCS#8) PEMs pass through after a parse check. Any
/// other PEM tag is rejected.
///
/// # Errors
///
/// Returns [`GitHubAppError::PrivateKey`] when the PEM cannot be parsed,
/// carries an unsupported tag, or fails PKCS#1 decode / PKCS#8 encode.
pub fn pkcs8_der_from_pem(pem_text: &str) -> Result<Vec<u8>, GitHubAppError> {
    let pem = pem::parse(pem_text)
        .map_err(|error| GitHubAppError::PrivateKey(format!("parse PEM: {error}")))?;
    match pem.tag() {
        "RSA PRIVATE KEY" => {
            // GitHub issues PKCS#1 PEMs; `WebCrypto`'s `importKey` wants
            // PKCS#8, so the validated PKCS#1 body is re-wrapped in a
            // PrivateKeyInfo carrying the rsaEncryption algorithm — the
            // same DER `rsa::EncodePrivateKey` emits, without a bigint
            // dependency.
            pkcs1::RsaPrivateKey::try_from(pem.contents()).map_err(|error| {
                GitHubAppError::PrivateKey(format!("invalid PKCS#1 RSA key: {error}"))
            })?;
            let info = pkcs8::PrivateKeyInfo::new(pkcs1::ALGORITHM_ID, pem.contents());
            let document = pkcs8::SecretDocument::try_from(info).map_err(|error| {
                GitHubAppError::PrivateKey(format!("re-encode as PKCS#8: {error}"))
            })?;
            Ok(document.as_bytes().to_vec())
        }
        "PRIVATE KEY" => {
            pkcs8::PrivateKeyInfo::try_from(pem.contents()).map_err(|error| {
                GitHubAppError::PrivateKey(format!("invalid PKCS#8 key: {error}"))
            })?;
            Ok(pem.contents().to_vec())
        }
        tag => Err(GitHubAppError::PrivateKey(format!(
            "unsupported PEM tag '{tag}' — expected 'RSA PRIVATE KEY' or 'PRIVATE KEY'"
        ))),
    }
}

#[derive(Serialize)]
struct JwtHeader<'a> {
    alg: &'a str,
    typ: &'a str,
}

#[derive(Serialize)]
struct JwtClaims<'a> {
    iat: i64,
    exp: i64,
    iss: &'a str,
}

/// The `header.payload` signing input for the App JWT — the bytes RS256
/// signs before [`encode_jwt`] appends the signature.
///
/// GitHub requires `exp` no more than 10 minutes out; `iat` is backdated
/// 60 seconds and `exp` set to `now + 9 minutes` to absorb clock skew.
///
/// # Errors
///
/// Returns [`GitHubAppError::Encode`] when claims serialization fails.
pub fn jwt_signing_input(app_id: &str, now_unix: i64) -> Result<String, GitHubAppError> {
    let header = serde_json::to_vec(&JwtHeader {
        alg: "RS256",
        typ: "JWT",
    })
    .map_err(|error| GitHubAppError::Encode(error.to_string()))?;
    let claims = serde_json::to_vec(&JwtClaims {
        iat: now_unix - 60,
        exp: now_unix + 9 * 60,
        iss: app_id,
    })
    .map_err(|error| GitHubAppError::Encode(error.to_string()))?;
    Ok(format!(
        "{}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims)
    ))
}

/// Append the base64url RS256 signature to a signing input, producing the
/// JWT sent as `Authorization: Bearer` to the token exchange.
#[must_use]
pub fn encode_jwt(signing_input: &str, signature: &[u8]) -> String {
    format!(
        "{signing_input}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
    )
}

/// Load the cached installation token or mint and cache a fresh one.
///
/// The cache row in DO storage is reused while more than five minutes of
/// validity remain; otherwise a new token is minted from `config` and
/// stored over the singleton row.
///
/// # Errors
///
/// Returns [`GitHubAppError::Storage`] when DO storage cannot be read or
/// written, or the mint errors ([`GitHubAppError::PrivateKey`],
/// [`GitHubAppError::Sign`], [`GitHubAppError::Exchange`],
/// [`GitHubAppError::ExchangeStatus`]).
#[cfg(target_arch = "wasm32")]
pub async fn installation_token(
    db: &DurableDb,
    config: &AppConfig,
) -> Result<InstallationToken, GitHubAppError> {
    if let Some(cached) = crate::scheduler::queue::github_app_token(db).await? {
        return Ok(cached);
    }
    let minted = mint_installation_token(config).await?;
    crate::scheduler::queue::store_github_app_token(db, &minted).await?;
    tracing::info!(
        expires_at = %minted.expires_at,
        "minted GitHub App installation token"
    );
    Ok(minted)
}

/// Build the JWT from the App key and exchange it for an installation
/// token.
#[cfg(target_arch = "wasm32")]
async fn mint_installation_token(config: &AppConfig) -> Result<InstallationToken, GitHubAppError> {
    let pkcs8_der = pkcs8_der_from_pem(&config.private_key_pem)?;
    // `Date::now()` returns whole milliseconds well below 2^53, so the
    // value is exactly representable and always fits i64.
    #[expect(clippy::cast_possible_truncation, reason = "epoch ms fits i64")]
    let now_unix = (js_sys::Date::now() / 1000.0) as i64;
    let signing_input = jwt_signing_input(&config.app_id, now_unix)?;
    let signature = sign_rs256(&pkcs8_der, signing_input.as_bytes()).await?;
    let jwt = encode_jwt(&signing_input, &signature);
    exchange_installation_token(&config.installation_id, &jwt).await
}

/// `POST /app/installations/{id}/access_tokens` with the JWT; a non-2xx
/// response is an error carrying status and body.
#[cfg(target_arch = "wasm32")]
async fn exchange_installation_token(
    installation_id: &str,
    jwt: &str,
) -> Result<InstallationToken, GitHubAppError> {
    use skyzen_cloudflare::worker::send::{IntoSendFuture as _, SendWrapper};

    let url = format!("https://api.github.com/app/installations/{installation_id}/access_tokens");
    let bearer = format!("Bearer {jwt}");
    let request = SendWrapper::new(
        crate::cf_http::bare_request(
            skyzen_cloudflare::worker::Method::Post,
            &url,
            &[
                ("Authorization", &bearer),
                ("Accept", "application/vnd.github+json"),
                ("X-GitHub-Api-Version", "2022-11-28"),
                ("User-Agent", "stow-scheduler"),
            ],
            None,
        )
        .map_err(|error| GitHubAppError::Exchange(format!("build request: {error}")))?,
    );

    let mut response = SendWrapper::new(
        skyzen_cloudflare::CfFetch
            .request(&request)
            .await
            .map_err(|error| GitHubAppError::Exchange(error.to_string()))?,
    );
    let status = response.status_code();
    if !(200..300).contains(&status) {
        let body = response
            .text()
            .into_send()
            .await
            .unwrap_or_else(|_| "<unreadable body>".to_owned());
        return Err(GitHubAppError::ExchangeStatus { status, body });
    }
    let parsed: AccessTokenResponse = response
        .json()
        .into_send()
        .await
        .map_err(|error| GitHubAppError::Exchange(format!("decode response: {error}")))?;
    Ok(InstallationToken {
        token: parsed.token,
        expires_at: parsed.expires_at,
    })
}

/// Sign `data` with the App key through `crypto.subtle` — Workers has no
/// Node `crypto`, so RS256 goes through `WebCrypto`.
#[cfg(target_arch = "wasm32")]
async fn sign_rs256(pkcs8_der: &[u8], data: &[u8]) -> Result<Vec<u8>, GitHubAppError> {
    use skyzen_cloudflare::worker::send::{IntoSendFuture as _, SendWrapper};
    use wasm_bindgen::{JsCast as _, JsValue};

    fn js_error(error: &JsValue) -> GitHubAppError {
        GitHubAppError::Sign(format!("{error:?}"))
    }

    let global = js_sys::global();
    let crypto: web_sys::Crypto = js_sys::Reflect::get(&global, &JsValue::from_str("crypto"))
        .map_err(|error| js_error(&error))?
        .unchecked_into();
    // `SendWrapper` marks the JS handles that live across `.await` points
    // `Send` — sound on Workers' single-threaded wasm runtime and required
    // for the handler futures to satisfy skyzen's `Send` bound.
    let subtle = SendWrapper::new(crypto.subtle());

    let algorithm = SendWrapper::new(js_sys::Object::new());
    js_sys::Reflect::set(
        &algorithm,
        &JsValue::from_str("name"),
        &JsValue::from_str("RSASSA-PKCS1-v1_5"),
    )
    .map_err(|error| js_error(&error))?;
    js_sys::Reflect::set(
        &algorithm,
        &JsValue::from_str("hash"),
        &JsValue::from_str("SHA-256"),
    )
    .map_err(|error| js_error(&error))?;

    let key_data: js_sys::Object = js_sys::Uint8Array::from(pkcs8_der).unchecked_into();
    let usages: JsValue = js_sys::Array::of1(&JsValue::from_str("sign")).into();
    let key = SendWrapper::new(
        wasm_bindgen_futures::JsFuture::from(
            subtle
                .import_key_with_object("pkcs8", &key_data, &algorithm, false, &usages)
                .map_err(|error| js_error(&error))?,
        )
        .into_send()
        .await
        .map_err(|error| js_error(&error))?
        .unchecked_into::<web_sys::CryptoKey>(),
    );

    let signature = wasm_bindgen_futures::JsFuture::from(
        subtle
            .sign_with_object_and_u8_array(&algorithm, &key, data)
            .map_err(|error| js_error(&error))?,
    )
    .into_send()
    .await
    .map_err(|error| js_error(&error))?;
    let buffer: js_sys::ArrayBuffer = signature.unchecked_into();
    Ok(js_sys::Uint8Array::new(&buffer).to_vec())
}

/// GitHub's `access_tokens` response body.
#[cfg(target_arch = "wasm32")]
#[derive(Debug, serde::Deserialize)]
struct AccessTokenResponse {
    token: String,
    expires_at: String,
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::{encode_jwt, jwt_signing_input, pkcs8_der_from_pem};

    /// Test-only RSA-2048 keys under `edge/tests/fixtures/` — see that
    /// directory's README. `RSA PRIVATE KEY` (PKCS#1) is what GitHub
    /// issues; `PRIVATE KEY` (PKCS#8) is the openssl `genpkey` output.
    const PKCS1_PEM: &str = include_str!("../tests/fixtures/github_app_pkcs1.pem");
    const PKCS8_PEM: &str = include_str!("../tests/fixtures/github_app_pkcs8.pem");

    #[test]
    fn decodes_pkcs1_pem_into_pkcs8_der() {
        let der = pkcs8_der_from_pem(PKCS1_PEM).expect("pkcs1 pem decodes");
        let info = pkcs8::PrivateKeyInfo::try_from(der.as_slice()).expect("output is valid PKCS#8");
        assert_eq!(info.algorithm.oid.to_string(), "1.2.840.113549.1.1.1");

        // PKCS#8 wraps rather than transforms: the private_key payload
        // must be the original PKCS#1 DER verbatim.
        let pkcs1_der = pem::parse(PKCS1_PEM).expect("parse pkcs1 fixture");
        assert_eq!(info.private_key, pkcs1_der.contents());
    }

    #[test]
    fn decodes_pkcs8_pem_passthrough() {
        let der = pkcs8_der_from_pem(PKCS8_PEM).expect("pkcs8 pem decodes");
        let info = pkcs8::PrivateKeyInfo::try_from(der.as_slice()).expect("valid PKCS#8");
        assert_eq!(info.algorithm.oid.to_string(), "1.2.840.113549.1.1.1");
    }

    #[test]
    fn rejects_unsupported_pem_tag() {
        let error = pkcs8_der_from_pem(
            "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n",
        )
        .expect_err("ec pem is not an app key");
        assert!(error.to_string().contains("unsupported PEM tag"));
    }

    #[test]
    fn jwt_signing_input_matches_known_base64url() {
        // `{"alg":"RS256","typ":"JWT"}` base64url-encodes to the well-known
        // JWT header string; the claims segment is asserted against an
        // independently computed encoding of the exact claim set.
        let input = jwt_signing_input("4985635", 1_700_000_000).expect("encodes");
        let expected_claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"iat":1699999940,"exp":1700000540,"iss":"4985635"}"#);
        assert_eq!(
            input,
            format!("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.{expected_claims}")
        );
    }

    #[test]
    fn encode_jwt_appends_base64url_signature() {
        assert_eq!(encode_jwt("a.b", &[0x01, 0x02]), "a.b.AQI");
    }
}
