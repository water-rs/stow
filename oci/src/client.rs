//! The one HTTP session every stow registry round trip shares.
//!
//! GHCR caps a namespace at 2000 requests per minute and answers the excess
//! with `429 TOOMANYREQUESTS` (and `503` under load), carrying its wait in a
//! `Retry-After` header and a `retry-after:` field in the error body. The cap
//! is a property of the preheat wave — tens of build jobs publishing into the
//! same namespace — so the wait a refusal names is a floor, not the answer:
//! retrying exactly at it lands back on the cap. Every request this module
//! sends, including the bearer-token exchange, retries a transient answer —
//! a `429`, any `5xx`, a `408`, or a request that never completed — in this
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
//!
//! A credentialed session also holds the process's [`WriteBudget`]: every
//! write it dispatches — retries included — first takes a token, so the
//! process stays under the operator's write rate instead of finding the
//! cap through refusals.
//!
//! The Sigstore exchanges the keyless signer makes (OIDC token, Fulcio,
//! Rekor) ride the same client and the same retry loop, without a
//! session: they carry their own authorization and spend no registry
//! write budget.

use std::sync::Arc;
use std::time::Duration;

use oci_client::Reference;
use reqwest::header::{self, HeaderMap, HeaderValue};
use reqwest::{Method, StatusCode};
use stow_types::error::Context;
use stow_types::registry::sha256_digest;

use crate::registry::{RegistryBase, RegistryCredentials};
use crate::throttle::WriteBudget;

/// Total dispatches a single request may make before the registry's refusal
/// is returned verbatim — the first try plus `MAX_ATTEMPTS - 1` retries. With
/// [`BASE_DELAY`] doubling per attempt, the worst-case added wait is about
/// 32 seconds, bounded so a blocked publish still fails while the scheduler
/// can observe it.
const MAX_ATTEMPTS: u32 = 8;

/// First local backoff after a transient answer; doubles per attempt and is
/// jittered by `±50%` so a fleet of jobs never retries in lockstep.
const BASE_DELAY: Duration = Duration::from_millis(250);

/// Ceiling on any single wait — the server hint and the local backoff are
/// both capped here, so a hostile `Retry-After` cannot stall a publish.
const MAX_DELAY: Duration = Duration::from_secs(30);

/// The default log filter of the operator tools (`stow-admin`, `stow-build`).
///
/// `info`, plus this module's per-attempt retry lines: they sit at `debug`
/// because a user's build must not print one per attempt, while an operator
/// reads them as the sign of an unhealthy registry.
pub const OPERATOR_LOG_FILTER: &str = concat!("info,", module_path!(), "=debug");

/// The OCI error codes that mean "the object is absent" inside a refusal's
/// `{"errors":[{"code":…}]}` envelope.
const NOT_FOUND_CODES: [&str; 3] = ["MANIFEST_UNKNOWN", "BLOB_UNKNOWN", "NOT_FOUND"];

/// What a registry round trip produced: every completed HTTP exchange —
/// including refused ones — comes back as this, so the caller keeps the
/// status, headers and verbatim body the registry answered.
pub struct Response {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Vec<u8>,
}

impl Response {
    /// The refusal as an error: status plus the body's own text, so the
    /// message GHCR sent (e.g. `retry-after: 28.55879ms, allowed:
    /// 2000/minute`) reaches the caller unmodified.
    pub(crate) fn refusal(&self, what: &str, url: &str) -> RegistryError {
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
/// including a transient status that outlived every retry).
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
    /// Whether the request never got an answer — connect, TLS or
    /// body-read failure, as opposed to a refusal the registry sent.
    /// The class a consumer's circuit trips on: reachability was the
    /// question and this is its answer (stow#977).
    #[must_use]
    pub const fn is_transport(&self) -> bool {
        matches!(self.kind, RegistryErrorKind::Transport(_))
    }

    pub(crate) fn transport(what: &str, url: &str, error: impl std::fmt::Display) -> Self {
        Self {
            what: format!("{what} {url}"),
            kind: RegistryErrorKind::Transport(error.to_string()),
        }
    }

    /// Whether this refusal is the registry reporting the object absent.
    /// A `404` carrying the OCI error envelope only counts when a `code`
    /// says so; a bare `404` (no envelope, e.g. a `HEAD` body) is absent
    /// outright. The object's whole package being absent
    /// ([`Self::is_package_missing`]) is an absence too — a `403`/`DENIED`
    /// or `404`/`NAME_UNKNOWN` is not an error for a reader that asks
    /// "does the index hold this", it is the answer "no".
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        let RegistryErrorKind::Refused { status, body } = &self.kind else {
            return false;
        };
        if self.is_package_missing() {
            return true;
        }
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

    /// Whether this refusal is the registry reporting the object's whole
    /// package absent — GHCR answers an anonymous pull of a package that
    /// does not exist (or is not public — it refuses to say which) with a
    /// `403` carrying the OCI `DENIED` code, on the token exchange or the
    /// asset request alike; a spec registry answers `404`/`NAME_UNKNOWN`
    /// for an unknown repository. A `403` with any other body stays a
    /// refusal, and so do `401` and every other status.
    #[must_use]
    pub fn is_package_missing(&self) -> bool {
        let RegistryErrorKind::Refused { status, body } = &self.kind else {
            return false;
        };
        stow_types::registry::package_missing(status.as_u16(), body)
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
/// body, plus the basic-auth pair of the token exchange. Whether it carries
/// a session bearer is the caller's choice of [`RegistryHttp::send`]'s
/// session.
pub struct SessionRequest {
    pub(crate) method: Method,
    pub(crate) url: String,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Option<Vec<u8>>,
    /// Basic-auth pair for the token exchange — the only request that
    /// authenticates with the username/password pair rather than a bearer.
    basic_auth: Option<(String, String)>,
}

impl SessionRequest {
    pub(crate) fn new(method: Method, url: String) -> Self {
        Self {
            method,
            url,
            headers: HeaderMap::new(),
            body: None,
            basic_auth: None,
        }
    }
}

/// Whether `method` writes — the verbs GHCR counts against its write cap.
const fn is_write(method: &Method) -> bool {
    matches!(*method, Method::POST | Method::PUT | Method::PATCH)
}

/// How a registry client's transport treats connection setup.
///
/// Publishing keeps the historical policy — no connect bound, connect
/// failures retried — because its waits are the fleet's `429` backoff,
/// not reachability. A consumer's build wants the opposite: an
/// unreachable registry is one diagnostic, and the build's circuit
/// carries the outage instead of eight stalled attempts (stow#977).
#[derive(Debug, Clone, Copy)]
pub struct TransportPolicy {
    /// `reqwest`'s connect timeout — it covers the DNS lookup and the
    /// connect itself; `None` leaves the OS's own bound.
    pub connect_timeout: Option<Duration>,
    /// Whether a connect/DNS failure retries like a `429` or `5xx`.
    /// Every other transport failure keeps its retry either way.
    pub retry_connect_failures: bool,
}

impl TransportPolicy {
    /// The publish/operator policy: no connect bound, and a connect or
    /// DNS failure retries like every other transient answer — the
    /// behaviour every caller had before a consumer's build asked for
    /// fast detection (stow#977).
    pub const PATIENT: Self = Self {
        connect_timeout: None,
        retry_connect_failures: true,
    };
}

/// The registry's HTTP client, built once per process and shared by every
/// session the process opens (stow#624).
///
/// Building a `reqwest::Client` loads the platform trust store
/// synchronously — on Linux the system bundle plus every entry under
/// `/etc/ssl/certs`, hundreds of certificate files parsed before the
/// constructor returns. A session that built its own paid that scan per
/// session, on whichever runtime worker polled it. [`RegistryHttp::new`]
/// is the only constructor and runs the build on a blocking thread;
/// sessions clone the handle instead.
#[derive(Debug, Clone)]
pub struct RegistryHttp {
    /// `reqwest::Client` is itself reference-counted; the outer `Arc`
    /// gives the handle an identity [`Self::same_client`] can compare.
    client: Arc<reqwest::Client>,
    /// The caller's transport policy — bounded connect and the
    /// connect/DNS retry choice every `send` this handle serves shares.
    transport: TransportPolicy,
}

impl RegistryHttp {
    /// Build the client on a blocking thread.
    ///
    /// # Errors
    ///
    /// A TLS backend that cannot initialize — `reqwest::Client::new`
    /// panics on it, the builder returns it — and a blocking task that
    /// cannot be joined.
    pub async fn new(transport: TransportPolicy) -> stow_types::error::Result<Self> {
        let client = tokio::task::spawn_blocking(move || {
            let mut builder = reqwest::Client::builder();
            if let Some(connect_timeout) = transport.connect_timeout {
                builder = builder.connect_timeout(connect_timeout);
            }
            builder.build()
        })
        .await
        .map_err(|error| stow_types::stow_error!("join registry HTTP client build: {error}"))?
        .map_err(|error| stow_types::stow_error!("build registry HTTP client: {error}"))?;
        Ok(Self {
            client: Arc::new(client),
            transport,
        })
    }

    /// Whether `other` is a clone of this handle — the same client, the
    /// same connection pool, the same single trust-store load.
    #[must_use]
    pub fn same_client(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.client, &other.client)
    }

    /// Dispatch `request`, retrying a transient answer until the server accepts
    /// or [`MAX_ATTEMPTS`] dispatches have been refused — the only place the
    /// whole push path handles backpressure, the bearer exchange and the
    /// Sigstore exchanges included. A request that gets a definitive
    /// answer — success or any other status — comes back as a
    /// [`Response`]; only a transport failure that outlived every retry
    /// returns `Err`, so the caller always sees the refusal the server
    /// actually sent.
    ///
    /// With a `session`, the request carries the session bearer and may
    /// re-mint it once after a `401`, and a write first takes a token from
    /// the session's [`WriteBudget`] on every dispatch; without one (the
    /// challenge ping, the token exchange, the Sigstore services) it is
    /// retried identically but never mints and spends no write budget.
    pub(crate) async fn send(
        &self,
        what: &str,
        request: SessionRequest,
        session: Option<&RegistrySession>,
    ) -> Result<Response, RegistryError> {
        let writes = session
            .and_then(RegistrySession::write_budget)
            .filter(|_| is_write(&request.method));
        let mut reauthed = false;
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let mut builder = self.client.request(request.method.clone(), &request.url);
            if let Some(session) = session
                && let Some(bearer) = session.bearer().await?
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
            if let Some(writes) = writes {
                writes.acquire().await;
            }
            let sent = async {
                let response = builder.send().await?;
                let status = response.status();
                let headers = response.headers().clone();
                let body = response.bytes().await?.to_vec();
                Ok::<_, reqwest::Error>((status, headers, body))
            }
            .await;
            // A request that never produced a whole answer — the connection
            // dropped, the stream reset mid-body — is transient: every
            // request here is content-addressed or idempotent, so sending
            // it again is safe.
            let (status, headers, body) = match sent {
                Ok(answer) => answer,
                Err(error) => {
                    // A connect or DNS failure answers reachability, not
                    // congestion: a policy that declines to retry it
                    // returns at once — the caller's circuit carries the
                    // outage (stow#977). Every other transport failure
                    // stays in the sweep. The timeout the policy sets is
                    // the connect bound — this client has no request
                    // timeout, so `is_timeout` can only be a connect
                    // that outlived it, and reqwest's connect timeout
                    // does not surface as `is_connect`.
                    let retriable = self.transport.retry_connect_failures
                        || !(error.is_connect() || error.is_dns() || error.is_timeout());
                    let error = RegistryError::transport(what, &request.url, error);
                    if !retriable || attempt >= MAX_ATTEMPTS {
                        return Err(error);
                    }
                    let delay = retry_delay(attempt, None);
                    tracing::debug!(
                        what,
                        attempt,
                        %error,
                        delay_ms = delay.as_millis(),
                        "registry request failed in transport; retrying"
                    );
                    smol::Timer::after(delay).await;
                    continue;
                }
            };
            if status == StatusCode::UNAUTHORIZED
                && let Some(session) = session
                && !reauthed
            {
                // The minted bearer was rejected mid-session — the mock TTL
                // is minutes, GHCR's is not much longer — mint once more and
                // replay the request rather than failing it.
                reauthed = true;
                session.refresh_bearer().await?;
                continue;
            }
            let response = Response {
                status,
                headers,
                body,
            };
            if !stow_types::transient::is_transient_status(status.as_u16()) {
                return Ok(response);
            }
            if attempt >= MAX_ATTEMPTS {
                return Ok(response);
            }
            let delay = retry_delay(attempt, retry_after_hint(&response));
            tracing::debug!(
                what,
                attempt,
                %status,
                delay_ms = delay.as_millis(),
                "registry answered a transient status; retrying"
            );
            smol::Timer::after(delay).await;
        }
    }
}

/// One HTTP session over a `RegistryBase` — holds the process's client
/// handle, and owns the single minted bearer and the one retry loop.
///
/// Construct through [`RegistryBase::session`] (anonymous `pull`) or
/// [`RegistryBase::push_session`] (credentialed `pull,push`); the bearer is
/// minted lazily on the first request so a session is cheap to create and a
/// registry that answers the challenge with `200` needs no token at all.
pub struct RegistrySession {
    http: RegistryHttp,
    /// `{scheme}://{host[:port]}` — challenge ping and asset URLs hang off it.
    origin: String,
    /// `host[:port]` — the reference-form half of `origin`.
    registry: String,
    /// The repository every request addresses
    /// (`water-rs/stow-cache-<rustc>`).
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

/// How a session authenticates. Only a credentialed session writes, so it
/// is the one that carries the process's [`WriteBudget`].
pub enum SessionCredential {
    Anonymous,
    Basic {
        username: String,
        password: String,
        writes: WriteBudget,
    },
}

impl std::fmt::Debug for SessionCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Anonymous => f.write_str("Anonymous"),
            Self::Basic {
                username, writes, ..
            } => f
                .debug_struct("Basic")
                .field("username", username)
                .field("writes_per_minute", &writes.writes_per_minute())
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
    /// A session on `base` addressing `repository` — one per cache
    /// package, so the session's bearer mints under that repository's
    /// scope. `origin` keeps the parsed scheme and host so `http` stays
    /// plain HTTP for the mock registry and `https` for GHCR. `http` is
    /// the process's [`RegistryHttp`]; a session never builds a client of
    /// its own (stow#624).
    #[must_use]
    pub fn new(
        base: &RegistryBase,
        repository: &stow_types::registry::CacheRepository,
        credential: SessionCredential,
        scope: &'static str,
        http: &RegistryHttp,
    ) -> Self {
        Self {
            http: http.clone(),
            origin: format!("{}://{}", base.scheme(), base.registry()),
            registry: base.registry().to_owned(),
            repository: repository.as_str().to_owned(),
            credential,
            scope,
            auth: smol::lock::Mutex::new(AuthState::default()),
        }
    }

    /// The repository path this session's requests address.
    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// The write budget a credentialed session spends.
    const fn write_budget(&self) -> Option<&WriteBudget> {
        match &self.credential {
            SessionCredential::Anonymous => None,
            SessionCredential::Basic { writes, .. } => Some(writes),
        }
    }

    /// `<host>/<repository>:<tag>` — the pull reference of `tag` in this
    /// session's repository.
    ///
    /// # Errors
    ///
    /// Returns an error when `tag` cannot form a valid OCI reference.
    pub fn reference(&self, tag: &str) -> stow_types::error::Result<Reference> {
        format!("{}/{}:{tag}", self.registry, self.repository)
            .parse()
            .wrap_err_with(|| format!("build OCI reference for tag {tag:?}"))
    }

    /// `<host>/<repository>@<digest>` — the digest-addressed pull
    /// reference of `digest` in this session's repository.
    ///
    /// # Errors
    ///
    /// Returns an error when `digest` cannot form a valid OCI reference.
    pub fn digest_reference(&self, digest: &str) -> stow_types::error::Result<Reference> {
        format!("{}/{}@{digest}", self.registry, self.repository)
            .parse()
            .wrap_err_with(|| format!("build OCI reference for digest {digest:?}"))
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
            .send("head blob", SessionRequest::new(Method::HEAD, url.clone()))
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
        let url = self.api("blobs/uploads/");
        let url = reqwest::Url::parse_with_params(&url, &[("digest", digest)])
            .map_err(|error| RegistryError {
                what: format!("build blob upload URL {url}"),
                kind: RegistryErrorKind::Transport(error.to_string()),
            })?
            .to_string();
        let mut request = SessionRequest::new(Method::POST, url.clone());
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
        let mut request = SessionRequest::new(Method::PUT, url.clone());
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
        let mut request = SessionRequest::new(Method::PUT, url.clone());
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
        let mut request = SessionRequest::new(Method::HEAD, url.clone());
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

    /// `GET tags/list` — every tag the session's repository carries,
    /// following the spec's `n`/`last` continuation while the registry
    /// answers a `Link: …rel="next"` header. Admin's records export lists
    /// the `records-*` tag space through this.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] on a transport failure, a refusal, or an
    /// undecodable page body.
    pub async fn list_tags(&self) -> Result<Vec<String>, RegistryError> {
        /// Tags per page — large enough that the records tag space is one
        /// request for a long time.
        const PAGE_SIZE: u32 = 1000;
        let mut tags = Vec::new();
        let mut last: Option<String> = None;
        loop {
            let Some((page, has_next)) = self.tags_page(PAGE_SIZE, last.as_deref()).await? else {
                break;
            };
            last = page.last().cloned();
            tags.extend(page);
            if !has_next || last.is_none() {
                break;
            }
        }
        Ok(tags)
    }

    /// Whether the repository holds at least one tag: one
    /// `tags/list?n=1` request, however many tags it carries. A package
    /// that does not exist (see [`RegistryError::is_not_found`]) and an
    /// empty one hold none.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] on a transport failure, a refusal that
    /// is not an absence, or an undecodable body.
    pub async fn has_tags(&self) -> Result<bool, RegistryError> {
        Ok(self
            .tags_page(1, None)
            .await?
            .is_some_and(|(page, _)| !page.is_empty()))
    }

    /// One `tags/list?n=<n>[&last=<last>]` page and whether the registry
    /// links a next one; `None` when the package does not exist yet, which
    /// every index reader treats as the empty index — an absence answered
    /// on the token exchange or on the listing itself
    /// (`404`/`NAME_UNKNOWN`). `"tags": null` is an empty page.
    async fn tags_page(
        &self,
        n: u32,
        last: Option<&str>,
    ) -> Result<Option<(Vec<String>, bool)>, RegistryError> {
        #[derive(serde::Deserialize)]
        struct TagsList {
            /// Distribution registries answer an empty repository
            /// `"tags": null`.
            #[serde(default)]
            tags: Option<Vec<String>>,
        }
        let url = self.api("tags/list");
        let url = last.map_or_else(
            || format!("{url}?n={n}"),
            |last| format!("{url}?n={n}&last={last}"),
        );
        let response = match self
            .send("list tags", SessionRequest::new(Method::GET, url.clone()))
            .await
        {
            Ok(response) => response,
            Err(error) if error.is_not_found() => return Ok(None),
            Err(error) => return Err(error),
        };
        match response.ensure_success("list tags", &url) {
            Err(error) if error.is_not_found() => return Ok(None),
            other => other?,
        }
        let page: TagsList =
            serde_json::from_slice(&response.body).map_err(|error| RegistryError {
                what: format!("list tags {url}"),
                kind: RegistryErrorKind::Transport(format!("decode tags list: {error}")),
            })?;
        let has_next = response
            .headers
            .get(header::LINK)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|link| link.contains("rel=\"next\""));
        Ok(Some((page.tags.unwrap_or_default(), has_next)))
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
        let mut request = SessionRequest::new(Method::GET, url.clone());
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
            .send("pull blob", SessionRequest::new(Method::GET, url.clone()))
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

    /// Dispatch `request` with the session's bearer — see
    /// [`RegistryHttp::send`]. The loop's future is returned as is, so a
    /// caller's future holds the request once.
    fn send<'a>(
        &'a self,
        what: &'a str,
        request: SessionRequest,
    ) -> impl Future<Output = Result<Response, RegistryError>> + 'a {
        self.http.send(what, request, Some(self))
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
                let response = Box::pin(self.http.send(
                    "registry challenge",
                    SessionRequest::new(Method::GET, url.clone()),
                    None,
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
        let mut request = SessionRequest::new(Method::GET, url.clone());
        if let SessionCredential::Basic {
            username, password, ..
        } = &self.credential
        {
            request.basic_auth = Some((username.clone(), password.clone()));
        }
        // `Box::pin` breaks the `send → refresh_bearer → exchange_token →
        // send` cycle — boxing makes this future's size finite.
        let response = Box::pin(self.http.send("exchange bearer token", request, None)).await?;
        // GHCR answers the anonymous exchange for a package that does not
        // exist or is not public with `403 DENIED` — a bare envelope that
        // reads like an auth failure. Name the real cause so a refused
        // pull against a rustc nothing has been built for is legible, and
        // keep the answer verbatim in `body` so `is_package_missing` reads
        // the same envelope a refused asset request carries.
        if !response.status.is_success() && matches!(self.credential, SessionCredential::Anonymous)
        {
            return Err(RegistryError {
                what: format!(
                    "exchange bearer token {url} — the package does not exist yet or is not public"
                ),
                kind: RegistryErrorKind::Refused {
                    status: response.status,
                    body: String::from_utf8_lossy(&response.body).into_owned(),
                },
            });
        }
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

/// The wait a transient answer asks for: the larger of the registry's own hint
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

/// The session variants `RegistryBase` hands out — one per cache
/// package, so the minted bearer's `repository:<repo>:<scope>` names the
/// rustc's own repository.
impl RegistryBase {
    /// The anonymous pull session every stow read path uses — cache
    /// packages are public, so the bearer mints with a `pull` scope and
    /// no credential.
    #[must_use]
    pub fn session(
        &self,
        repository: &stow_types::registry::CacheRepository,
        http: &RegistryHttp,
    ) -> RegistrySession {
        RegistrySession::new(self, repository, SessionCredential::Anonymous, "pull", http)
    }

    /// The credentialed publish session — `pull,push` scope over
    /// `GHCR_USERNAME`/`GHCR_TOKEN`, every write spending `writes`.
    #[must_use]
    pub fn push_session(
        &self,
        repository: &stow_types::registry::CacheRepository,
        credentials: &RegistryCredentials,
        http: &RegistryHttp,
        writes: &WriteBudget,
    ) -> RegistrySession {
        RegistrySession::new(
            self,
            repository,
            SessionCredential::Basic {
                username: credentials.username.clone(),
                password: credentials.password.clone(),
                writes: writes.clone(),
            },
            "pull,push",
            http,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RegistryBase, RegistryCredentials, RegistryHttp, RegistrySession, TransportPolicy,
    };

    /// stow#624: sessions opened from one handle ride the one client it
    /// built. The handle's own identity is the count — one constructor
    /// call, one client, however many sessions clone it — and a second
    /// constructor call is a second client.
    #[tokio::test]
    async fn sessions_from_one_handle_share_its_client() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = RegistryHttp::new(TransportPolicy::PATIENT)
            .await
            .expect("build registry http");
        let base = RegistryBase::production().expect("production registry base");
        let repository = stow_types::registry::cache_repository(
            &stow_types::identity::WireRustcVersion::parse("1.99.0").expect("rustc"),
        );
        let pull = base.session(&repository, &http);
        let push = base.push_session(
            &repository,
            &RegistryCredentials {
                username: "u".to_owned(),
                password: "p".to_owned(),
            },
            &http,
            &crate::WriteBudget::per_minute(std::num::NonZeroU32::MIN),
        );
        assert!(pull.http.same_client(&http));
        assert!(push.http.same_client(&http));
        assert!(pull.http.same_client(&push.http));

        let second = RegistryHttp::new(TransportPolicy::PATIENT)
            .await
            .expect("build a second handle");
        assert!(
            !base.session(&repository, &second).http.same_client(&http),
            "a second constructor call builds a second client"
        );
    }

    type Answer = (u16, String, &'static str);

    /// An anonymous registry on loopback answering each connection with
    /// the next scripted answer; the script is built from the server's
    /// own URL because the challenge names it. The task returns every
    /// request line.
    async fn scripted_registry(
        script: impl FnOnce(&str) -> Vec<Answer>,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let script = script(&url);
        let task = tokio::spawn(async move {
            let mut lines = Vec::new();
            for (status, headers, body) in script {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut buffer = vec![0_u8; 8192];
                let read = stream.read(&mut buffer).await.expect("read");
                let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
                lines.push(request.lines().next().unwrap_or_default().to_owned());
                let response = format!(
                    "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n{headers}\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.expect("write");
            }
            lines
        });
        (url, task)
    }

    const NAME_UNKNOWN: &str = r#"{"errors":[{"code":"NAME_UNKNOWN","message":"x"}]}"#;
    const DENIED: &str = r#"{"errors":[{"code":"DENIED","message":"x"}]}"#;

    /// The challenge, then a token (or a `403 DENIED` exchange when
    /// `denied`), then the `tags/list` answers.
    fn script(url: &str, denied: bool, tags: Vec<(u16, &'static str)>) -> Vec<Answer> {
        let mut answers = vec![(
            401,
            format!("www-authenticate: Bearer realm=\"{url}/token\",service=\"s\"\r\n"),
            "",
        )];
        if denied {
            answers.push((403, String::new(), DENIED));
        } else {
            answers.push((200, String::new(), r#"{"token":"t"}"#));
            answers.extend(
                tags.into_iter()
                    .map(|(status, body)| (status, String::new(), body)),
            );
        }
        answers
    }

    async fn session_on(url: &str) -> (RegistrySession, RegistryHttp) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = RegistryHttp::new(TransportPolicy::PATIENT)
            .await
            .expect("registry http");
        let repository = stow_types::registry::cache_repository(
            &stow_types::identity::WireRustcVersion::parse("1.99.0").expect("rustc"),
        );
        let session = RegistryBase::parse(url)
            .expect("base")
            .session(&repository, &http);
        (session, http)
    }

    /// `has_tags` asks for one tag, and answers from it.
    #[tokio::test]
    async fn has_tags_asks_for_one_tag() {
        let (url, task) =
            scripted_registry(|url| script(url, false, vec![(200, r#"{"tags":["index.x"]}"#)]))
                .await;
        let (session, _http) = session_on(&url).await;
        assert!(session.has_tags().await.expect("has tags"));
        let lines = task.await.expect("server");
        assert!(lines[2].contains("/tags/list?n=1 "), "{lines:?}");
    }

    /// An absent package, an empty repository and `"tags": null` hold no tags.
    #[tokio::test]
    async fn has_tags_is_false_for_absent_and_empty_repositories() {
        for (denied, tags) in [
            (true, vec![]),
            (false, vec![(404, NAME_UNKNOWN)]),
            (false, vec![(200, r#"{"tags":[]}"#)]),
            (false, vec![(200, r#"{"name":"n","tags":null}"#)]),
        ] {
            let (url, task) = scripted_registry(|url| script(url, denied, tags.clone())).await;
            let (session, _http) = session_on(&url).await;
            assert!(!session.has_tags().await.expect("absence is an answer"));
            task.await.expect("server");
        }
    }

    /// Any other refusal is an error.
    #[tokio::test]
    async fn has_tags_fails_on_other_refusals() {
        let (url, task) = scripted_registry(|url| {
            script(
                url,
                false,
                vec![(400, r#"{"errors":[{"code":"UNSUPPORTED"}]}"#)],
            )
        })
        .await;
        let (session, _http) = session_on(&url).await;
        assert!(session.has_tags().await.is_err());
        task.await.expect("server");
    }

    /// `list_tags` reads a `404`/`NAME_UNKNOWN` listing as no tags, and a
    /// `null` tag list as an empty page.
    #[tokio::test]
    async fn list_tags_reads_absence_on_the_listing_and_null_tags() {
        for tags in [(404, NAME_UNKNOWN), (200, r#"{"tags":null}"#)] {
            let (url, task) = scripted_registry(|url| script(url, false, vec![tags])).await;
            let (session, _http) = session_on(&url).await;
            assert_eq!(
                session.list_tags().await.expect("list"),
                Vec::<String>::new()
            );
            task.await.expect("server");
        }
        let (url, task) =
            scripted_registry(|url| script(url, false, vec![(200, r#"{"tags":["a","b"]}"#)])).await;
        let (session, _http) = session_on(&url).await;
        assert_eq!(session.list_tags().await.expect("list"), ["a", "b"]);
        task.await.expect("server");
    }
}
