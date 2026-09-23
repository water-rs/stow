//! The one HTTP session every stow registry round trip shares.
//!
//! GHCR caps a namespace at 2000 requests per minute and answers the excess
//! with `429 TOOMANYREQUESTS` (and `503` under load), carrying its wait in a
//! `Retry-After` header and a `retry-after:` field in the error body. The cap
//! is a property of the preheat wave — tens of build jobs publishing into the
//! same namespace — so the wait a refusal names is a floor, not the answer:
//! retrying exactly at it lands back on the cap. Every request this module
//! sends, including the bearer-token exchange, retries a `429`/`503` in this
//! one place with a bounded exponential backoff plus jitter; when the
//! attempts run out the refusal is passed through with the registry's own
//! text, never re-worded.
//!
//! One session also means one bearer token: it is minted once — a challenge
//! `GET /v2/` plus the `GET <realm>` exchange — and authenticates every
//! request until the process exits. Together with a `HEAD` per blob before
//! uploading (a content-addressed blob already present is never re-sent) and
//! a monolithic `POST …/uploads/?digest=` per missing blob, a push costs the
//! minimum the OCI distribution spec allows: `2` requests to mint the token
//! once, `1-2` per blob, `1` per manifest.

use std::time::Duration;

use oci_client::Reference;
use reqwest::header::{self, HeaderMap, HeaderValue};
use reqwest::{Method, StatusCode};
use stow_types::error::Context;
use stow_types::registry::sha256_digest;

use crate::registry::{RegistryBase, RegistryCredentials};

/// Total dispatches a single request may make before the registry's refusal
/// is returned verbatim — the first try plus `MAX_ATTEMPTS - 1` retries. With
/// [`BASE_DELAY`] doubling per attempt, the worst-case added wait is about
/// 32 seconds, bounded so a blocked publish still fails while the scheduler
/// can observe it.
const MAX_ATTEMPTS: u32 = 8;

/// First local backoff after a `429`/`503`; doubles per attempt and is
/// jittered by `±50%` so a fleet of jobs never retries in lockstep.
const BASE_DELAY: Duration = Duration::from_millis(250);

/// Ceiling on any single wait — the server hint and the local backoff are
/// both capped here, so a hostile `Retry-After` cannot stall a publish.
const MAX_DELAY: Duration = Duration::from_secs(30);

/// The OCI error codes that mean "the object is absent" inside a refusal's
/// `{"errors":[{"code":…}]}` envelope.
const NOT_FOUND_CODES: [&str; 3] = ["MANIFEST_UNKNOWN", "BLOB_UNKNOWN", "NOT_FOUND"];

/// What a registry round trip produced: every completed HTTP exchange —
/// including refused ones — comes back as this, so the caller keeps the
/// status, headers and verbatim body the registry answered.
struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Response {
    /// The refusal as an error: status plus the body's own text, so the
    /// message GHCR sent (e.g. `retry-after: 28.55879ms, allowed:
    /// 2000/minute`) reaches the caller unmodified.
    fn refusal(&self, what: &str, url: &str) -> RegistryError {
        RegistryError {
            what: format!("{what} {url}"),
            kind: RegistryErrorKind::Refused {
                status: self.status,
                body: String::from_utf8_lossy(&self.body).into_owned(),
            },
        }
    }

    /// `Ok(())` on a success status, else the refusal error.
    fn ensure_success(&self, what: &str, url: &str) -> Result<(), RegistryError> {
        if self.status.is_success() {
            Ok(())
        } else {
            Err(self.refusal(what, url))
        }
    }
}

/// Why a registry round trip failed: either the request never completed
/// (transport), or the registry answered a non-success status (refusal —
/// including a `429`/`503` that outlived every retry).
#[derive(Debug)]
pub struct RegistryError {
    what: String,
    kind: RegistryErrorKind,
}

#[derive(Debug)]
enum RegistryErrorKind {
    /// The request never got an answer — connect, TLS, or body-read failure.
    Transport(String),
    /// The registry answered a status outside the success range; `body` is
    /// the response text verbatim.
    Refused { status: StatusCode, body: String },
}

impl RegistryError {
    fn transport(what: &str, url: &str, error: impl std::fmt::Display) -> Self {
        Self {
            what: format!("{what} {url}"),
            kind: RegistryErrorKind::Transport(error.to_string()),
        }
    }

    /// Whether this refusal is the registry reporting the object absent.
    /// Only a `404` may read as absent — a refusal at any other status is an
    /// error whatever its body says — and a `404` carrying the OCI error
    /// envelope only counts when a `code` says so; a bare `404` (no
    /// envelope, e.g. a `HEAD` body) is absent outright.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        let RegistryErrorKind::Refused { status, body } = &self.kind else {
            return false;
        };
        if *status != StatusCode::NOT_FOUND {
            return false;
        }
        let Ok(envelope) = serde_json::from_slice::<serde_json::Value>(body.as_bytes()) else {
            return true;
        };
        let Some(errors) = envelope.get("errors").and_then(serde_json::Value::as_array) else {
            return true;
        };
        errors.iter().any(|entry| {
            entry
                .get("code")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|code| NOT_FOUND_CODES.contains(&code))
        })
    }
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            RegistryErrorKind::Transport(message) => {
                write!(formatter, "{}: {message}", self.what)
            }
            RegistryErrorKind::Refused { status, body } => {
                write!(
                    formatter,
                    "{}: registry answered {status}: {body}",
                    self.what
                )
            }
        }
    }
}

impl std::error::Error for RegistryError {}

/// A request `send` can replay: the verb's method, absolute URL, headers and
/// body, plus how to authenticate. `authenticated` requests carry the
/// session's bearer and may re-mint it once after a `401`.
struct SessionRequest {
    method: Method,
    url: String,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
    /// Basic-auth pair for the token exchange — the only request that
    /// authenticates with the username/password pair rather than a bearer.
    basic_auth: Option<(String, String)>,
    authenticated: bool,
}

impl SessionRequest {
    fn authenticated(method: Method, url: String) -> Self {
        Self {
            method,
            url,
            headers: HeaderMap::new(),
            body: None,
            basic_auth: None,
            authenticated: true,
        }
    }

    fn unauthenticated(method: Method, url: String) -> Self {
        Self {
            authenticated: false,
            ..Self::authenticated(method, url)
        }
    }
}

/// One HTTP session over a `RegistryBase` — owns the reqwest client, the
/// single minted bearer, and the one retry loop.
///
/// Construct through [`RegistryBase::session`] (anonymous `pull`) or
/// [`RegistryBase::push_session`] (credentialed `pull,push`); the bearer is
/// minted lazily on the first request so a session is cheap to create and a
/// registry that answers the challenge with `200` needs no token at all.
pub struct RegistrySession {
    http: reqwest::Client,
    /// `{scheme}://{host[:port]}` — challenge ping and asset URLs hang off it.
    origin: String,
    /// The repository every request addresses (`water-rs/stow-cache`).
    repository: String,
    credential: SessionCredential,
    /// OAuth scope the bearer requests: `pull` for anonymous sessions,
    /// `pull,push` for credentialed ones.
    scope: &'static str,
    /// Challenge and minted bearer, behind a lock so concurrent first
    /// requests share a single mint.
    auth: smol::lock::Mutex<AuthState>,
}

/// Credentials and tokens never render — the session's `Debug` shows only
/// where it points.
impl std::fmt::Debug for RegistrySession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistrySession")
            .field("origin", &self.origin)
            .field("repository", &self.repository)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

pub enum SessionCredential {
    Anonymous,
    Basic { username: String, password: String },
}

impl std::fmt::Debug for SessionCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Anonymous => f.write_str("Anonymous"),
            Self::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Default)]
struct AuthState {
    challenge: ChallengeState,
    bearer: Option<String>,
}

/// The parsed `WWW-Authenticate` answer to the `GET /v2/` ping: `None` when
/// the registry needs no token, `Bearer` with the token realm when it does.
#[derive(Default, Clone)]
enum ChallengeState {
    #[default]
    Unknown,
    None,
    Bearer(BearerChallenge),
}

#[derive(Clone)]
struct BearerChallenge {
    realm: String,
    service: Option<String>,
}

impl RegistrySession {
    /// A session on `base`: `origin` keeps the parsed scheme and host so
    /// `http` stays plain HTTP for the mock registry and `https` for GHCR.
    #[must_use]
    pub fn new(base: &RegistryBase, credential: SessionCredential, scope: &'static str) -> Self {
        Self {
            http: reqwest::Client::new(),
            origin: format!("{}://{}", base.scheme(), base.registry()),
            repository: base.repository().to_owned(),
            credential,
            scope,
            auth: smol::lock::Mutex::new(AuthState::default()),
        }
    }

    /// Whether `digest`'s blob is already stored — the `HEAD` that makes a
    /// present blob cost one request instead of an upload.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] on a transport failure or a refusal other
    /// than `404`.
    pub async fn blob_exists(&self, digest: &str) -> Result<bool, RegistryError> {
        let url = self.api(&format!("blobs/{digest}"));
        let response = self
            .send(
                "head blob",
                SessionRequest::authenticated(Method::HEAD, url.clone()),
            )
            .await?;
        match response.status {
            status if status.is_success() => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            _ => Err(response.refusal("head blob", &url)),
        }
    }

    /// Upload `bytes` as `digest`'s blob when absent: one `HEAD`, then the
    /// monolithic `POST /blobs/uploads/?digest=` the distribution spec
    /// defines — never a session, chunk and commit per blob. A registry
    /// that does not implement the single `POST` answers `202` plus the
    /// upload session's `Location`; the spec's own fallback commits it with
    /// one `PUT` carrying the body and `?digest=`.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] when the `HEAD`, `POST` or fallback `PUT`
    /// is refused, or the registry reports a different stored digest than
    /// `digest`.
    pub async fn push_blob(&self, digest: &str, bytes: &[u8]) -> Result<(), RegistryError> {
        if self.blob_exists(digest).await? {
            return Ok(());
        }
        let url = format!("{}/blobs/uploads/", self.api(""));
        let url = reqwest::Url::parse_with_params(&url, &[("digest", digest)])
            .map_err(|error| RegistryError {
                what: format!("build blob upload URL {url}"),
                kind: RegistryErrorKind::Transport(error.to_string()),
            })?
            .to_string();
        let mut request = SessionRequest::authenticated(Method::POST, url.clone());
        request.body = Some(bytes.to_vec());
        request.headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        let response = self.send("push blob", request).await?;
        match response.status {
            StatusCode::CREATED => {}
            StatusCode::ACCEPTED => {
                return self.commit_blob_upload(&response, digest, bytes).await;
            }
            _ => return Err(response.refusal("push blob", &url)),
        }
        verify_stored_digest(&response, digest, "push blob", &url)
    }

    /// The distribution spec's fallback after a `POST` answered `202`:
    /// `PUT` the `Location` the session opened, with the body and the
    /// `digest` query the commit requires. The location is absolute or
    /// resolves against the session origin.
    async fn commit_blob_upload(
        &self,
        response: &Response,
        digest: &str,
        bytes: &[u8],
    ) -> Result<(), RegistryError> {
        let url = upload_commit_url(&self.origin, &response.headers, digest)?;
        let mut request = SessionRequest::authenticated(Method::PUT, url.clone());
        request.body = Some(bytes.to_vec());
        request.headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        let response = self.send("commit blob upload", request).await?;
        if response.status != StatusCode::CREATED {
            return Err(response.refusal("commit blob upload", &url));
        }
        verify_stored_digest(&response, digest, "commit blob upload", &url)
    }

    /// PUT `manifest` under `reference`'s tag or digest selector. Returns the
    /// digest the registry stored: the response's `Docker-Content-Digest`,
    /// which must equal the pushed bytes' own hash — the signature and the
    /// bundle both key on it, so a registry that rewrote the bytes is an
    /// error here rather than a wrong digest downstream.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] when the `PUT` is refused or the stored
    /// digest disagrees with the pushed bytes.
    pub async fn put_manifest(
        &self,
        reference: &Reference,
        manifest: &[u8],
    ) -> Result<String, RegistryError> {
        let selector = self.selector(reference)?;
        let url = self.api(&format!("manifests/{selector}"));
        let mut request = SessionRequest::authenticated(Method::PUT, url.clone());
        request.body = Some(manifest.to_vec());
        request.headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(stow_types::bundle::OCI_IMAGE_MANIFEST_MEDIA_TYPE),
        );
        let response = self.send("push manifest", request).await?;
        response.ensure_success("push manifest", &url)?;
        let expected = sha256_digest(manifest);
        match docker_content_digest(&response.headers) {
            Some(stored) if stored != expected => Err(RegistryError {
                what: format!("push manifest {url}"),
                kind: RegistryErrorKind::Refused {
                    status: response.status,
                    body: format!(
                        "registry stored manifest as {stored}, pushed bytes hash to {expected}"
                    ),
                },
            }),
            Some(_) => Ok(expected),
            // The registry stored without saying under which digest — read
            // the manifest back under the pushed bytes' own digest and
            // demand the same bytes: the returned digest means nothing
            // otherwise.
            None => {
                let (served, _) = self.pull_manifest_selector(&expected).await?;
                if served != manifest {
                    return Err(RegistryError {
                        what: format!("push manifest {url}"),
                        kind: RegistryErrorKind::Refused {
                            status: response.status,
                            body: format!(
                                "registry serves different bytes under {expected} than pushed"
                            ),
                        },
                    });
                }
                Ok(expected)
            }
        }
    }

    /// `HEAD` the manifest `reference` names, returning its
    /// `Docker-Content-Digest`. Falls back to a `GET` when the registry
    /// answers a `HEAD` without the header — one extra request, only on a
    /// registry that does not implement the digest header.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] on a transport failure or a refusal —
    /// `404`/`MANIFEST_UNKNOWN` when the tag does not exist.
    pub async fn fetch_manifest_digest(
        &self,
        reference: &Reference,
    ) -> Result<String, RegistryError> {
        let selector = self.selector(reference)?;
        let url = self.api(&format!("manifests/{selector}"));
        let mut request = SessionRequest::authenticated(Method::HEAD, url.clone());
        request.headers.insert(
            header::ACCEPT,
            HeaderValue::from_static(stow_types::bundle::OCI_IMAGE_MANIFEST_MEDIA_TYPE),
        );
        let response = self.send("head manifest", request).await?;
        response.ensure_success("head manifest", &url)?;
        if let Some(digest) = docker_content_digest(&response.headers) {
            return Ok(digest);
        }
        let (_, digest) = self.pull_manifest(reference).await?;
        Ok(digest)
    }

    /// GET the manifest `reference` names: its bytes exactly as stored and
    /// the body's own sha256 — `Docker-Content-Digest` is only ever checked
    /// to agree with the bytes, never trusted alone: a header that names a
    /// digest the body does not hash to is a forgery (the signature binds
    /// the digest while the consumer reads the bytes). A `@digest` selector
    /// must equal the body's hash.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] on a transport failure, a refusal (the tag
    /// absent is a `404`/`MANIFEST_UNKNOWN` refusal), or a digest mismatch.
    pub async fn pull_manifest(
        &self,
        reference: &Reference,
    ) -> Result<(Vec<u8>, String), RegistryError> {
        let selector = self.selector(reference)?;
        self.pull_manifest_selector(&selector).await
    }

    /// [`pull_manifest`] on a bare `tag`/`sha256:…` selector — the path a
    /// digest already verified against its source takes.
    async fn pull_manifest_selector(
        &self,
        selector: &str,
    ) -> Result<(Vec<u8>, String), RegistryError> {
        let url = self.api(&format!("manifests/{selector}"));
        let mut request = SessionRequest::authenticated(Method::GET, url.clone());
        request.headers.insert(
            header::ACCEPT,
            HeaderValue::from_static(stow_types::bundle::OCI_IMAGE_MANIFEST_MEDIA_TYPE),
        );
        let response = self.send("pull manifest", request).await?;
        response.ensure_success("pull manifest", &url)?;
        let digest = sha256_digest(&response.body);
        if let Some(served) = docker_content_digest(&response.headers)
            && served != digest
        {
            return Err(RegistryError {
                what: format!("pull manifest {url}"),
                kind: RegistryErrorKind::Refused {
                    status: response.status,
                    body: format!("registry claims digest {served} for a body hashing to {digest}"),
                },
            });
        }
        if selector.starts_with("sha256:") && digest != selector {
            return Err(RegistryError {
                what: format!("pull manifest {url}"),
                kind: RegistryErrorKind::Refused {
                    status: response.status,
                    body: format!("manifest requested as {selector} hashes to {digest}"),
                },
            });
        }
        Ok((response.body, digest))
    }

    /// GET `digest`'s blob bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] on a transport failure or a refusal.
    pub async fn pull_blob(&self, digest: &str) -> Result<Vec<u8>, RegistryError> {
        let url = self.api(&format!("blobs/{digest}"));
        let response = self
            .send(
                "pull blob",
                SessionRequest::authenticated(Method::GET, url.clone()),
            )
            .await?;
        response.ensure_success("pull blob", &url)?;
        Ok(response.body)
    }

    /// The manifest selector `reference` addresses (`tag` or `digest`), after
    /// checking the reference names this session's repository — a reference
    /// for another repository is a bug, not a URL to build.
    fn selector(&self, reference: &Reference) -> Result<String, RegistryError> {
        if reference.repository() != self.repository {
            return Err(RegistryError {
                what: format!("select manifest {reference} in {}", self.repository),
                kind: RegistryErrorKind::Transport(format!(
                    "reference names repository {}, session serves {}",
                    reference.repository(),
                    self.repository
                )),
            });
        }
        Ok(reference
            .digest()
            .map_or_else(|| reference.tag().unwrap_or("latest"), |digest| digest)
            .to_owned())
    }

    /// `{origin}/v2/{repository}/{path}` — every asset URL in one place so no
    /// verb spells the API shape twice.
    fn api(&self, path: &str) -> String {
        format!("{}/v2/{}/{}", self.origin, self.repository, path)
    }

    /// Dispatch `request`, retrying a `429`/`503` until the registry accepts
    /// or [`MAX_ATTEMPTS`] dispatches have been refused — the only place the
    /// whole push path handles backpressure, the bearer exchange included.
    /// A request that gets a definitive answer — success or any other
    /// status — comes back as a [`Response`]; only transport failures
    /// return `Err`, so the caller always sees the refusal GHCR actually
    /// sent. An `authenticated` request carries the session bearer and may
    /// re-mint it once after a `401`; an unauthenticated one (the challenge
    /// ping, the token exchange) is retried identically but never mints.
    async fn send(&self, what: &str, request: SessionRequest) -> Result<Response, RegistryError> {
        let mut reauthed = false;
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let mut builder = self.http.request(request.method.clone(), &request.url);
            if request.authenticated
                && let Some(bearer) = self.bearer().await?
            {
                builder = builder.bearer_auth(bearer);
            }
            if let Some((username, password)) = &request.basic_auth {
                builder = builder.basic_auth(username, Some(password));
            }
            builder = builder.headers(request.headers.clone());
            if let Some(body) = &request.body {
                builder = builder.body(body.clone());
            }
            let response = builder
                .send()
                .await
                .map_err(|error| RegistryError::transport(what, &request.url, error))?;
            let status = response.status();
            let headers = response.headers().clone();
            let body = response
                .bytes()
                .await
                .map_err(|error| RegistryError::transport(what, &request.url, error))?
                .to_vec();
            if status == StatusCode::UNAUTHORIZED && request.authenticated && !reauthed {
                // The minted bearer was rejected mid-session — the mock TTL
                // is minutes, GHCR's is not much longer — mint once more and
                // replay the request rather than failing it.
                reauthed = true;
                self.refresh_bearer().await?;
                continue;
            }
            let response = Response {
                status,
                headers,
                body,
            };
            if status != StatusCode::TOO_MANY_REQUESTS && status != StatusCode::SERVICE_UNAVAILABLE
            {
                return Ok(response);
            }
            if attempt >= MAX_ATTEMPTS {
                return Ok(response);
            }
            let delay = retry_delay(attempt, retry_after_hint(&response));
            tracing::warn!(
                what,
                attempt,
                %status,
                delay_ms = delay.as_millis(),
                "registry asked to wait; retrying"
            );
            smol::Timer::after(delay).await;
        }
    }

    /// The session's bearer, minting it on first use: challenge `GET /v2/`,
    /// then `GET <realm>` under the session scope. `None` when the registry
    /// answers the challenge without asking for a token.
    async fn bearer(&self) -> Result<Option<String>, RegistryError> {
        let mut auth = self.auth.lock().await;
        if let Some(bearer) = &auth.bearer {
            return Ok(Some(bearer.clone()));
        }
        let challenge = match &auth.challenge {
            ChallengeState::Bearer(challenge) => Some(challenge.clone()),
            ChallengeState::None => None,
            ChallengeState::Unknown => {
                let url = format!("{}/v2/", self.origin);
                // `Box::pin` breaks the `send → bearer → send` cycle for
                // this in-loop call the same way the token exchange's is.
                let response = Box::pin(self.send(
                    "registry challenge",
                    SessionRequest::unauthenticated(Method::GET, url.clone()),
                ))
                .await?;
                let challenge = if response.status == StatusCode::UNAUTHORIZED {
                    match parse_challenge(&response.headers) {
                        Some(challenge) => ChallengeState::Bearer(challenge),
                        None => {
                            return Err(response.refusal(
                                "registry challenge answered 401 without a Bearer realm",
                                &url,
                            ));
                        }
                    }
                } else {
                    ChallengeState::None
                };
                auth.challenge = challenge;
                match &auth.challenge {
                    ChallengeState::Bearer(challenge) => Some(challenge.clone()),
                    _ => None,
                }
            }
        };
        let Some(challenge) = challenge else {
            return Ok(None);
        };
        let bearer = self.exchange_token(&challenge).await?;
        auth.bearer = Some(bearer.clone());
        drop(auth);
        Ok(Some(bearer))
    }

    /// Re-mint the bearer after a `401` — clears the cached token and runs
    /// the exchange again under the cached challenge.
    async fn refresh_bearer(&self) -> Result<(), RegistryError> {
        let mut auth = self.auth.lock().await;
        auth.bearer = None;
        let ChallengeState::Bearer(challenge) = &auth.challenge else {
            return Err(RegistryError {
                what: "re-authenticate".to_owned(),
                kind: RegistryErrorKind::Transport(
                    "registry answered 401 but never issued a Bearer challenge".to_owned(),
                ),
            });
        };
        auth.bearer = Some(self.exchange_token(&challenge.clone()).await?);
        drop(auth);
        Ok(())
    }

    /// `GET <realm>?service=…&scope=repository:<repo>:<scope>` — the OAuth
    /// exchange that mints the session's one bearer. Credentialed sessions
    /// send the pair as basic auth exactly like a registry login.
    async fn exchange_token(&self, challenge: &BearerChallenge) -> Result<String, RegistryError> {
        let mut query = vec![(
            "scope",
            format!("repository:{}:{}", self.repository, self.scope),
        )];
        if let Some(service) = &challenge.service {
            query.push(("service", service.clone()));
        }
        let url = reqwest::Url::parse_with_params(&challenge.realm, &query)
            .map_err(|error| RegistryError {
                what: format!("build token URL {}", challenge.realm),
                kind: RegistryErrorKind::Transport(error.to_string()),
            })?
            .to_string();
        let mut request = SessionRequest::unauthenticated(Method::GET, url.clone());
        if let SessionCredential::Basic { username, password } = &self.credential {
            request.basic_auth = Some((username.clone(), password.clone()));
        }
        // `Box::pin` breaks the `send → refresh_bearer → exchange_token →
        // send` cycle — boxing makes this future's size finite.
        let response = Box::pin(self.send("exchange bearer token", request)).await?;
        response.ensure_success("exchange bearer token", &url)?;
        let body: serde_json::Value =
            serde_json::from_slice(&response.body).map_err(|error| RegistryError {
                what: format!("parse token response {url}"),
                kind: RegistryErrorKind::Transport(error.to_string()),
            })?;
        body.get("token")
            .or_else(|| body.get("access_token"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| RegistryError {
                what: format!("parse token response {url}"),
                kind: RegistryErrorKind::Transport(
                    "token response carried neither token nor access_token".to_owned(),
                ),
            })
    }
}

/// The `Docker-Content-Digest` the registry reported on an accepted
/// `POST`/`PUT` blob — when it says anything — must equal `digest`.
fn verify_stored_digest(
    response: &Response,
    digest: &str,
    what: &str,
    url: &str,
) -> Result<(), RegistryError> {
    if let Some(stored) = docker_content_digest(&response.headers)
        && stored != digest
    {
        return Err(RegistryError {
            what: format!("{what} {url}"),
            kind: RegistryErrorKind::Refused {
                status: response.status,
                body: format!("registry stored blob as {stored}, expected {digest}"),
            },
        });
    }
    Ok(())
}

/// The URL a `202`-accepted upload session commits at: its `Location`,
/// absolute or resolved against `origin`, with `digest` appended as the
/// distribution spec's commit requires.
fn upload_commit_url(
    origin: &str,
    headers: &HeaderMap,
    digest: &str,
) -> Result<String, RegistryError> {
    let location = headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| RegistryError {
            what: format!("blob upload session on {origin}"),
            kind: RegistryErrorKind::Transport(
                "registry answered 202 without a Location to commit".to_owned(),
            ),
        })?;
    let mut url = if let Ok(url) = reqwest::Url::parse(location) {
        url
    } else {
        reqwest::Url::parse(&format!("{origin}/"))
            .and_then(|base| base.join(location))
            .map_err(|error| RegistryError {
                what: format!("resolve upload Location {location}"),
                kind: RegistryErrorKind::Transport(error.to_string()),
            })?
    };
    url.query_pairs_mut().append_pair("digest", digest);
    Ok(url.to_string())
}

/// The `Docker-Content-Digest` response header GHCR returns on manifest and
/// blob pushes and on `HEAD`/`GET` manifest — the registry's own statement of
/// what it stored.
fn docker_content_digest(headers: &HeaderMap) -> Option<String> {
    headers
        .get("docker-content-digest")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// The wait a `429`/`503` asks for: the larger of the registry's own hint
/// (`Retry-After` header or the `retry-after:` value in its error body,
/// whichever is greater) and the jittered local backoff — all bounded by
/// [`MAX_DELAY`].
fn retry_delay(attempt: u32, hint: Option<Duration>) -> Duration {
    let backoff = BASE_DELAY
        .saturating_mul(2u32.saturating_pow(attempt.saturating_sub(1)))
        .min(MAX_DELAY);
    let jittered = backoff.mul_f64(fastrand::f64().mul_add(0.5, 0.5));
    hint.unwrap_or(Duration::ZERO).min(MAX_DELAY).max(jittered)
}

/// The registry's own wait hint from a refused response: the greater of the
/// `Retry-After` header and the `retry-after:` value in the error body.
fn retry_after_hint(response: &Response) -> Option<Duration> {
    let header_hint = response
        .headers
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_retry_after_header);
    let body_hint = std::str::from_utf8(&response.body)
        .ok()
        .and_then(parse_retry_after_body);
    header_hint.max(body_hint)
}

/// The `Retry-After` header as a duration — decimal or whole seconds.
/// `None` when the value is missing, unparsesable, or an HTTP-date.
fn parse_retry_after_header(value: &str) -> Option<Duration> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.contains(',') {
        // An HTTP-date carries a comma — the integer form never does.
        return None;
    }
    let seconds: f64 = value.parse().ok()?;
    if !(seconds.is_finite() && seconds >= 0.0) {
        return None;
    }
    Duration::try_from_secs_f64(seconds).ok()
}

/// The `retry-after: <duration>` GHCR writes into the refusal body, as a
/// duration. `None` when the body carries no such value or spells it in a
/// unit we do not know.
fn parse_retry_after_body(message: &str) -> Option<Duration> {
    let rest = message.split("retry-after:").nth(1)?.trim_start();
    let digits = rest
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .map_or(rest, |end| &rest[..end]);
    let value: f64 = digits.parse().ok()?;
    let unit = rest[digits.len()..].trim_start();
    let seconds = if unit.starts_with("ns") {
        value / 1e9
    } else if unit.starts_with("us") || unit.starts_with("µs") {
        value / 1e6
    } else if unit.starts_with("ms") {
        value / 1e3
    } else if unit.starts_with('s') {
        value
    } else {
        return None;
    };
    Duration::try_from_secs_f64(seconds).ok()
}

/// The `WWW-Authenticate: Bearer realm=…,service=…,scope=…` challenge a `401`
/// carries — parsed into the realm to mint against and the optional service
/// the token endpoint wants echoed. The scheme matches case-insensitively
/// (RFC 7235).
fn parse_challenge(headers: &HeaderMap) -> Option<BearerChallenge> {
    let header = headers.get(header::WWW_AUTHENTICATE)?.to_str().ok()?;
    let (scheme, rest) = header.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let rest = rest.trim();
    let mut realm = None;
    let mut service = None;
    for pair in rest.split(',') {
        let Some((key, value)) = pair.trim().split_once('=') else {
            continue;
        };
        let value = value.trim_matches('"');
        match key.trim() {
            "realm" => realm = Some(value.to_owned()),
            "service" => service = Some(value.to_owned()),
            _ => {}
        }
    }
    realm.map(|realm| BearerChallenge { realm, service })
}

/// Serialize an OCI image manifest the way the distribution spec expects:
/// canonical JSON (sorted keys, no whitespace) so the pushed bytes — and
/// therefore the manifest digest — are reproducible.
///
/// # Errors
///
/// Returns an error when the manifest cannot be serialized — a bug, not a
/// runtime condition.
pub fn canonical_manifest_bytes(
    manifest: &oci_client::manifest::OciImageManifest,
) -> stow_types::error::Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut serializer =
        serde_json::Serializer::with_formatter(&mut body, olpc_cjson::CanonicalFormatter::new());
    serde::Serialize::serialize(
        &oci_client::manifest::OciManifest::Image(manifest.clone()),
        &mut serializer,
    )
    .wrap_err("serialize OCI manifest canonically")?;
    Ok(body)
}

/// The session variants `RegistryBase` hands out.
impl RegistryBase {
    /// The anonymous pull session every stow read path uses — the cache
    /// package is public, so the bearer mints with a `pull` scope and no
    /// credential.
    #[must_use]
    pub fn session(&self) -> RegistrySession {
        RegistrySession::new(self, SessionCredential::Anonymous, "pull")
    }

    /// The credentialed publish session — `pull,push` scope over
    /// `GHCR_USERNAME`/`GHCR_TOKEN`.
    #[must_use]
    pub fn push_session(&self, credentials: &RegistryCredentials) -> RegistrySession {
        RegistrySession::new(
            self,
            SessionCredential::Basic {
                username: credentials.username.clone(),
                password: credentials.password.clone(),
            },
            "pull,push",
        )
    }
}
