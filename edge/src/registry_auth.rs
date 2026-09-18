//! Anonymous OCI registry token exchange (Docker registry token spec).
//!
//! ghcr.io answers every unauthenticated `/v2/` request with `401` and a
//! `WWW-Authenticate: Bearer realm="…",service="…",scope="…"` challenge;
//! the client fetches `{realm}?service=…&scope=…` anonymously and retries
//! with the returned bearer. Public `stow-cache` packages grant
//! `repository:<name>:pull` to anonymous callers, so no credential is
//! configured anywhere — the token itself is the only secret, lives for
//! `expires_in` seconds, and is cached per scope in isolate memory.
//!
//! Everything here is pure and unit-tested on the host: the challenge
//! parser, the per-scope token cache, and the realm response body. The
//! wasm-bound request path that drives them lives in `crate::ghcr`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// TTL the spec assigns a token whose response omits `expires_in`
/// (the issue's pinned value — the spec floor is lower, but GHCR always
/// returns `expires_in` so the default only guards a terse realm).
pub const DEFAULT_TOKEN_TTL_SECS: u64 = 300;

/// OCI `pull` scope a `repository:<name>:pull` challenge carries. Derived
/// client-side so a live cached bearer can be attached without first
/// eating a `401`.
pub fn pull_scope(name: &str) -> String {
    format!("repository:{name}:pull")
}

/// A parsed `WWW-Authenticate` Bearer challenge (RFC 6750 auth-params).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerChallenge {
    /// Token endpoint the client exchanges at anonymously.
    pub realm: String,
    /// `service` auth-param, forwarded to the realm as a query parameter.
    pub service: Option<String>,
    /// `scope` auth-param — the cache key for the issued token.
    pub scope: Option<String>,
}

/// Failure to interpret a `WWW-Authenticate` header value as a Bearer
/// challenge.
#[derive(Debug, thiserror::Error)]
pub enum ChallengeError {
    /// The auth scheme was not `Bearer` (e.g. `Basic`, or a bare `Bearer`
    /// glued to a non-parameter token).
    #[error("not a Bearer challenge")]
    NotBearer,
    /// The auth-param list could not be parsed.
    #[error("malformed Bearer challenge: {0}")]
    Malformed(String),
    /// The challenge carried no `realm` parameter.
    #[error("Bearer challenge has no realm")]
    MissingRealm,
}

/// Parse a `WWW-Authenticate` Bearer challenge header value.
///
/// Parameters may appear in any order and unknown parameters are ignored
/// (registries append `error`/`error_description` on failed exchanges).
/// Values accept both RFC 7230 token and quoted-string forms; quoted
/// strings unescape `\\` / `\"` pairs and may contain `,`/`=`.
///
/// # Errors
///
/// [`ChallengeError::NotBearer`] when the scheme is not `Bearer`,
/// [`ChallengeError::Malformed`] for a broken auth-param list, and
/// [`ChallengeError::MissingRealm`] when no `realm` is present.
pub fn parse_bearer_challenge(header: &str) -> Result<BearerChallenge, ChallengeError> {
    const BEARER: &str = "bearer";
    let header = header.trim_start();
    if header.len() < BEARER.len() || !header[..BEARER.len()].eq_ignore_ascii_case(BEARER) {
        return Err(ChallengeError::NotBearer);
    }
    // `BearerX` must not match: the scheme is followed by whitespace or
    // ends the header (a bare `Bearer` then fails MissingRealm below).
    let rest = &header[BEARER.len()..];
    if !rest.is_empty() && !rest.starts_with([' ', '\t']) {
        return Err(ChallengeError::NotBearer);
    }

    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for param in split_auth_params(rest.trim_start())? {
        let param = param.trim();
        if param.is_empty() {
            continue;
        }
        let (key, value) = param
            .split_once('=')
            .ok_or_else(|| ChallengeError::Malformed(format!("auth-param '{param}' has no '='")))?;
        match key.trim().to_ascii_lowercase().as_str() {
            "realm" => realm = Some(auth_param_value(value.trim())?),
            "service" => service = Some(auth_param_value(value.trim())?),
            "scope" => scope = Some(auth_param_value(value.trim())?),
            _ => {}
        }
    }
    let realm = realm
        .filter(|realm| !realm.is_empty())
        .ok_or(ChallengeError::MissingRealm)?;
    Ok(BearerChallenge {
        realm,
        service,
        scope,
    })
}

/// Split a Bearer auth-param list on commas that sit outside quoted
/// strings (`realm="https://auth/token?a=b,c"` is one parameter).
fn split_auth_params(rest: &str) -> Result<Vec<&str>, ChallengeError> {
    let mut params = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut chars = rest.char_indices();
    while let Some((index, ch)) = chars.next() {
        match ch {
            '\\' if in_quotes => {
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                params.push(&rest[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if in_quotes {
        return Err(ChallengeError::Malformed(
            "unterminated quoted-string".to_owned(),
        ));
    }
    params.push(&rest[start..]);
    Ok(params)
}

/// Decode one auth-param value: a quoted-string with `\\`/`\"` escapes,
/// or a bare token. Anything else is malformed.
fn auth_param_value(raw: &str) -> Result<String, ChallengeError> {
    if raw.starts_with('"') {
        let inner = raw
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .ok_or_else(|| ChallengeError::Malformed("unterminated quoted-string".to_owned()))?;
        let mut unescaped = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            match ch {
                '\\' => unescaped.push(chars.next().ok_or_else(|| {
                    ChallengeError::Malformed("trailing escape in quoted-string".to_owned())
                })?),
                '"' => {
                    return Err(ChallengeError::Malformed(
                        "bare '\"' inside quoted-string".to_owned(),
                    ));
                }
                ch => unescaped.push(ch),
            }
        }
        return Ok(unescaped);
    }
    if raw.is_empty() || raw.contains('"') || raw.chars().any(char::is_whitespace) {
        return Err(ChallengeError::Malformed(format!(
            "invalid auth-param value '{raw}'"
        )));
    }
    Ok(raw.to_owned())
}

/// `GET {realm}` response body (Docker registry token spec). `token` is
/// the bearer; `access_token` is the OAuth2-compatible alias, of which at
/// least one must be present.
#[derive(Debug, serde::Deserialize)]
pub struct TokenResponse {
    /// Issued bearer token (`token` field).
    pub token: Option<String>,
    /// OAuth2-style alias for `token`.
    pub access_token: Option<String>,
    /// Seconds the token stays valid; absent means [`DEFAULT_TOKEN_TTL_SECS`].
    pub expires_in: Option<u64>,
}

impl TokenResponse {
    /// The bearer to send as `Authorization: Bearer`, preferring `token`
    /// over its `access_token` alias.
    pub fn bearer(&self) -> Option<&str> {
        self.token.as_deref().or(self.access_token.as_deref())
    }
}

/// A registry bearer held in isolate memory until `expires_at_ms`
/// (`Date::now()` epoch milliseconds).
#[derive(Clone)]
struct CachedToken {
    token: String,
    expires_at_ms: i64,
}

impl std::fmt::Debug for CachedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedToken")
            .field("token", &"<redacted>")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

/// Per-isolate cache of registry bearer tokens keyed by `scope`.
///
/// `skyzen::utils::State` requires `Send + Sync + Clone`, so the map sits
/// behind `Arc<Mutex<_>>` rather than `RefCell`. Workers run each isolate
/// single-threaded and the guard is never held across an `.await`, so the
/// lock can never contend and poisoning is unreachable.
#[derive(Debug, Default, Clone)]
pub struct RegistryTokens {
    inner: Arc<Mutex<HashMap<String, CachedToken>>>,
}

impl RegistryTokens {
    /// The cached bearer for `scope` while it is still valid at `now_ms`
    /// (epoch milliseconds, `js_sys::Date::now()` on the worker).
    pub fn bearer_for(&self, scope: &str, now_ms: i64) -> Option<String> {
        self.lock()
            .get(scope)
            .filter(|cached| cached.expires_at_ms > now_ms)
            .map(|cached| cached.token.clone())
    }

    /// Cache a freshly exchanged token for `scope`; `expires_in` is
    /// seconds from `now_ms` (already defaulted by the caller when the
    /// realm omitted it).
    pub fn insert(&self, scope: &str, token: String, expires_in: u64, now_ms: i64) {
        let ttl_ms = i64::try_from(expires_in.min(u64::MAX / 1000) * 1000).unwrap_or(i64::MAX);
        self.lock().insert(
            scope.to_owned(),
            CachedToken {
                token,
                expires_at_ms: now_ms.saturating_add(ttl_ms),
            },
        );
    }

    /// Drop the cached token for `scope`: the registry rejected it, so it
    /// must not be sent again.
    pub fn remove(&self, scope: &str) {
        self.lock().remove(scope);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, CachedToken>> {
        self.inner
            .lock()
            .expect("registry token cache mutex poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::{ChallengeError, RegistryTokens, parse_bearer_challenge, pull_scope};

    #[test]
    fn parses_ghcr_challenge() {
        let challenge = parse_bearer_challenge(
            r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:water-rs/stow-cache/serde:pull""#,
        )
        .expect("valid challenge");
        assert_eq!(challenge.realm, "https://ghcr.io/token");
        assert_eq!(challenge.service.as_deref(), Some("ghcr.io"));
        assert_eq!(
            challenge.scope.as_deref(),
            Some("repository:water-rs/stow-cache/serde:pull")
        );
    }

    #[test]
    fn accepts_any_parameter_order_and_unknown_params() {
        let challenge = parse_bearer_challenge(
            r#"Bearer scope="repository:a/b:pull",error="invalid_token",realm="https://auth/token",service="svc",error_description="expired""#,
        )
        .expect("reordered challenge");
        assert_eq!(challenge.realm, "https://auth/token");
        assert_eq!(challenge.service.as_deref(), Some("svc"));
        assert_eq!(challenge.scope.as_deref(), Some("repository:a/b:pull"));
    }

    #[test]
    fn accepts_unquoted_token_values_and_case_insensitive_scheme() {
        let challenge = parse_bearer_challenge(
            "bearer realm=https://auth/token,service=svc,scope=repository:a:pull",
        )
        .expect("token-form challenge");
        assert_eq!(challenge.realm, "https://auth/token");
        assert_eq!(challenge.scope.as_deref(), Some("repository:a:pull"));
    }

    #[test]
    fn keeps_commas_and_escapes_inside_quoted_values() {
        let challenge = parse_bearer_challenge(
            r#"Bearer realm="https://auth/token?a=b,c=\"d\"",scope="repository:a:pull""#,
        )
        .expect("quoted challenge");
        assert_eq!(challenge.realm, "https://auth/token?a=b,c=\"d\"");
    }

    #[test]
    fn rejects_non_bearer_schemes() {
        for header in [
            r#"Basic realm="https://auth/token""#,
            r#"BearerXrealm="https://auth/token""#,
            "",
        ] {
            assert_eq!(
                parse_bearer_challenge(header).unwrap_err().to_string(),
                ChallengeError::NotBearer.to_string(),
                "header: {header}"
            );
        }
    }

    #[test]
    fn rejects_missing_realm() {
        assert_eq!(
            parse_bearer_challenge("Bearer").unwrap_err().to_string(),
            ChallengeError::MissingRealm.to_string()
        );
        assert_eq!(
            parse_bearer_challenge(r#"Bearer service="svc",realm="""#)
                .unwrap_err()
                .to_string(),
            ChallengeError::MissingRealm.to_string()
        );
    }

    #[test]
    fn rejects_malformed_params() {
        for header in [
            "Bearer realm",
            r#"Bearer realm="unterminated"#,
            r#"Bearer realm="trailing\""#,
            "Bearer realm=",
            "Bearer realm=a b",
        ] {
            assert!(
                parse_bearer_challenge(header).is_err(),
                "header should fail: {header}"
            );
        }
    }

    #[test]
    fn pull_scope_matches_registry_format() {
        assert_eq!(
            pull_scope("water-rs/stow-cache/serde"),
            "repository:water-rs/stow-cache/serde:pull"
        );
    }

    #[test]
    fn serves_cached_token_until_expiry() {
        let tokens = RegistryTokens::default();
        tokens.insert("repository:a:pull", "tok".to_owned(), 300, 1_000);
        assert_eq!(
            tokens.bearer_for("repository:a:pull", 1_000 + 299_999),
            Some("tok".to_owned())
        );
        assert_eq!(
            tokens.bearer_for("repository:a:pull", 1_000 + 300_000),
            None
        );
        assert_eq!(tokens.bearer_for("repository:b:pull", 1_000), None);
    }

    #[test]
    fn remove_drops_cached_token() {
        let tokens = RegistryTokens::default();
        tokens.insert("repository:a:pull", "tok".to_owned(), 300, 0);
        tokens.remove("repository:a:pull");
        assert_eq!(tokens.bearer_for("repository:a:pull", 0), None);
    }

    #[test]
    fn cloned_caches_share_state() {
        let tokens = RegistryTokens::default();
        let clone = tokens.clone();
        tokens.insert("repository:a:pull", "tok".to_owned(), 300, 0);
        assert_eq!(
            clone.bearer_for("repository:a:pull", 1),
            Some("tok".to_owned())
        );
    }
}
