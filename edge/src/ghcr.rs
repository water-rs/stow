//! GHCR blob access through the anonymous registry token exchange.
//!
//! The edge never assembles anything: the trusted publish stage pushes the
//! finished bundle tar as the `<tag>.bundle` layer, and the only thing this
//! module opens is that blob, by digest, as a stream the handler forwards.

use skyzen_cloudflare::{CfFetch, worker};
use stow_types::registry::RepositoryPath;

use crate::cf_http;
use crate::fetch_guard::{FetchedResponse, GuardedResponse, OutboundPool};
use crate::registry_auth::{
    BearerChallenge, DEFAULT_TOKEN_TTL_SECS, RegistryTokens, RetryAuth, TokenResponse,
    parse_bearer_challenge, pull_scope,
};

pub const fn default_base_url() -> &'static str {
    stow_types::registry::GHCR_V2_BASE_URL
}

/// `GET blobs/<digest>` as a streaming response. GHCR answers a blob GET
/// with a redirect to its object store, which `fetch` follows; the body is
/// content-addressed by `digest`, and the CLI verifies the cosign material
/// inside it, so nothing here buffers or inspects the bytes.
pub async fn open_blob(
    base_url: &str,
    repo: RepositoryPath<'_>,
    digest: &str,
    tokens: &RegistryTokens,
    pool: &OutboundPool,
) -> Result<worker::Response, FetchError> {
    let url = format!("{}/blobs/{digest}", base_url.trim_end_matches('/'));
    send_request(&url, tokens, &pull_scope(repo), None, pool).await
}

/// `GET manifests/<reference>` — the image manifest JSON an admin
/// inspection reads. Unlike [`open_blob`] the response is a small
/// document the handler buffers and decodes into
/// [`stow_types::api::OciManifest`].
pub async fn open_manifest(
    base_url: &str,
    repo: RepositoryPath<'_>,
    reference: &str,
    tokens: &RegistryTokens,
    pool: &OutboundPool,
) -> Result<worker::Response, FetchError> {
    let url = format!("{}/manifests/{reference}", base_url.trim_end_matches('/'));
    send_request(
        &url,
        tokens,
        &pull_scope(repo),
        Some(OCI_MANIFEST_ACCEPT),
        pool,
    )
    .await
}

/// Accept header for the manifest GET — the OCI image manifest media type
/// every stow-cache tag resolves to.
const OCI_MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json";

/// `GET url` through the registry token exchange.
///
/// The request goes out with the cached bearer for `scope` when one is
/// live, anonymously otherwise. A `401` is answered by parsing the
/// `WWW-Authenticate` Bearer challenge, exchanging at its realm once,
/// caching the issued token under the challenge's scope, and retrying the
/// request a single time. A cached bearer that was attached and still
/// rejected is dropped and the exchange runs fresh — a second `401` (or
/// any non-2xx terminal response) is classified and returned as an error.
async fn send_request(
    url: &str,
    tokens: &RegistryTokens,
    scope: &str,
    accept: Option<&str>,
    pool: &OutboundPool,
) -> Result<worker::Response, FetchError> {
    let attached = tokens.bearer_for(scope, now_ms());
    let response = send(url, attached.as_deref(), accept, pool).await?;
    if response.get_ref().status_code() != 401 {
        return classify_status(response).await;
    }

    let challenge = parse_challenge(response).await?;
    let bearer = match tokens.resolve_retry(&challenge, attached.as_deref(), scope, now_ms()) {
        RetryAuth::Cached(token) => token,
        RetryAuth::Exchange(scope) => exchange_and_cache(&challenge, &scope, tokens, pool).await?,
    };
    let response = send(url, Some(&bearer), accept, pool).await?;
    classify_status(response).await
}

/// Parse the `WWW-Authenticate` Bearer challenge off a `401` response —
/// the arm that only ever needed headers, so the body is cancelled on
/// the guard's drop. A response without the header is a plain
/// unauthorized error carrying its body; a present-but-broken challenge
/// is [`FetchError::InvalidChallenge`].
async fn parse_challenge<B: FetchedResponse>(
    response: GuardedResponse<B>,
) -> Result<BearerChallenge, FetchError> {
    match response.get_ref().header("www-authenticate") {
        Some(header) => parse_bearer_challenge(&header)
            .map_err(|error| FetchError::InvalidChallenge(error.to_string())),
        None => Err(FetchError::Unauthorized {
            status: response.get_ref().status_code(),
            body: body_text(response).await,
        }),
    }
}

/// Exchange the challenge's realm anonymously and cache the issued token
/// under `scope`.
async fn exchange_and_cache(
    challenge: &BearerChallenge,
    scope: &str,
    tokens: &RegistryTokens,
    pool: &OutboundPool,
) -> Result<String, FetchError> {
    let (token, expires_in) = exchange_token(challenge, pool).await?;
    tokens.insert(scope, token.clone(), expires_in, now_ms());
    Ok(token)
}

/// `GET {realm}?service=…&scope=…` anonymously; returns the bearer and its
/// TTL in seconds ([`DEFAULT_TOKEN_TTL_SECS`] when the realm omits it).
/// A non-2xx realm response, or a 2xx body with no `token`/`access_token`,
/// is [`FetchError::TokenExchange`] carrying status and body.
async fn exchange_token(
    challenge: &BearerChallenge,
    pool: &OutboundPool,
) -> Result<(String, u64), FetchError> {
    let url = token_request_url(challenge)?;
    let response = send(&url, None, None, pool).await?;
    let status = response.get_ref().status_code();
    let body = body_text(response).await;
    if !(200..300).contains(&status) {
        return Err(FetchError::TokenExchange { status, body });
    }
    let parsed: TokenResponse =
        serde_json::from_str(&body).map_err(|error| FetchError::TokenExchange {
            status,
            body: format!("{body} (unparseable token response: {error})"),
        })?;
    let Some(token) = parsed.bearer() else {
        return Err(FetchError::TokenExchange { status, body });
    };
    Ok((
        token.to_owned(),
        parsed.expires_in.unwrap_or(DEFAULT_TOKEN_TTL_SECS),
    ))
}

/// Build `{realm}?service=…&scope=…` through the platform `URL` API so
/// parameter encoding stays the runtime's job.
fn token_request_url(challenge: &BearerChallenge) -> Result<String, FetchError> {
    let url = web_sys::Url::new(&challenge.realm).map_err(|error| {
        FetchError::InvalidChallenge(format!("invalid realm {:?}: {error:?}", challenge.realm))
    })?;
    let params = url.search_params();
    if let Some(service) = &challenge.service {
        params.set("service", service);
    }
    if let Some(scope) = &challenge.scope {
        params.set("scope", scope);
    }
    Ok(url.href())
}

async fn send(
    url: &str,
    token: Option<&str>,
    accept: Option<&str>,
    pool: &OutboundPool,
) -> Result<GuardedResponse<worker::Response>, FetchError> {
    // The slot covers the headers exchange the runtime meters; a 2xx
    // body the caller streams on is past this function's reach — the
    // guard still frees the connection if the body is never read.
    let _slot = pool.slot().await;
    let request = build_request(url, token, accept)?;
    CfFetch
        .request(&request)
        .await
        .map(GuardedResponse::new)
        .map_err(|error| FetchError::Network(error.to_string()))
}

fn build_request(
    url: &str,
    token: Option<&str>,
    accept: Option<&str>,
) -> Result<worker::Request, FetchError> {
    let bearer = token.map(|token| format!("Bearer {token}"));
    let mut headers: Vec<(&str, &str)> = Vec::with_capacity(2);
    if let Some(accept) = accept {
        headers.push(("Accept", accept));
    }
    if let Some(bearer) = &bearer {
        headers.push(("Authorization", bearer.as_str()));
    }
    cf_http::bare_request(worker::Method::Get, url, &headers, None)
        .map_err(|error| FetchError::InvalidRequest(error.to_string()))
}

/// Body for an error variant that must carry it; an unreadable body is
/// still reported rather than dropped silently.
async fn body_text<B: FetchedResponse>(response: GuardedResponse<B>) -> String {
    response
        .into_inner()
        .text()
        .await
        .unwrap_or_else(|_| "<unreadable body>".to_owned())
}

/// Classify a response by status: 2xx hands the response back (its body
/// streams or buffers downstream), every other arm reads the body for
/// diagnostics or lets the guard cancel it.
async fn classify_status<B: FetchedResponse>(
    response: GuardedResponse<B>,
) -> Result<B, FetchError> {
    let status = response.get_ref().status_code();
    match status {
        200..=299 => Ok(response.into_inner()),
        401 | 403 => Err(FetchError::Unauthorized {
            status,
            body: body_text(response).await,
        }),
        404 => Err(FetchError::NotFound),
        429 | 500..=599 => Err(FetchError::Unavailable),
        _ => Err(FetchError::UnexpectedStatus(status)),
    }
}

/// `Date::now()` epoch milliseconds — the only wall clock Workers' wasm
/// runtime exposes; whole ms well below 2^53, so the cast never loses
/// precision.
fn now_ms() -> i64 {
    #[expect(clippy::cast_possible_truncation, reason = "epoch ms fits i64")]
    {
        js_sys::Date::now() as i64
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("invalid GHCR request: {0}")]
    InvalidRequest(String),
    #[error("GHCR network error: {0}")]
    Network(String),
    #[error("GHCR unavailable (rate limit or 5xx)")]
    Unavailable,
    #[error("malformed registry auth challenge: {0}")]
    InvalidChallenge(String),
    #[error("registry token exchange failed (HTTP {status}): {body}")]
    TokenExchange {
        /// HTTP status of the realm response.
        status: u16,
        /// Realm response body for diagnostics.
        body: String,
    },
    #[error("GHCR authentication/authorization failed (HTTP {status}): {body}")]
    Unauthorized {
        /// HTTP status of the rejected request.
        status: u16,
        /// Response body for diagnostics.
        body: String,
    },
    #[error("artifact not found in GHCR")]
    NotFound,
    #[error("GHCR returned unexpected HTTP status {0}")]
    UnexpectedStatus(u16),
}

impl FetchError {
    /// Whether the failure means the registry no longer holds what the D1
    /// row promises, so the row is pruned rather than retried.
    pub const fn indicates_stale_artifact(&self) -> bool {
        match self {
            Self::NotFound => true,
            Self::InvalidRequest(_)
            | Self::Network(_)
            | Self::Unavailable
            | Self::InvalidChallenge(_)
            | Self::TokenExchange { .. }
            | Self::Unauthorized { .. }
            | Self::UnexpectedStatus(_) => false,
        }
    }
}
