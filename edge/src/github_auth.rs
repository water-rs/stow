//! GitHub-identity authentication for the trusted write surface.
//!
//! The scheduler-control and artifact-write endpoints previously sat
//! behind two long-lived shared secrets (`x-stow-scheduler-token`,
//! `x-stow-register-token`). Both are replaced by GitHub identity on a
//! single `Authorization: Bearer` header — nothing is stored anywhere:
//!
//! - **GitHub Actions OIDC JWT** — a repo workflow mints a token per run
//!   (`id-token: write`); the edge verifies the RS256 signature against
//!   GitHub's JWKS and pins `iss`, `aud`, `repository`, and the
//!   `owner/repo/.github/workflows/` prefix on the workflow ref — any
//!   workflow inside the trusted repo (`preheat-admin.yml` submits
//!   scheduler tasks this way), never a fork's, whose runs carry their
//!   own `repository` claim.
//! - **Repo-push credential** — the admin path and non-OIDC CI calls:
//!   the edge probes the credential's push capability directly via git
//!   smart-HTTP (`info/refs?service=git-receive-pack` answers 200 only
//!   when GitHub would accept a push). That shape covers user tokens
//!   (`gh auth token`), fine-grained PATs, and Actions `GITHUB_TOKEN`
//!   installation tokens alike — the last is how the mock-e2e job drives
//!   a local edge. No bespoke secret exists to leak or rotate. The
//!   probe's verdict is cached per credential in isolate memory
//!   ([`PushVerdicts`]) — the Worker egresses from shared IPs, and
//!   re-probing GitHub on every request is what got the probe
//!   rate-limited in production.
//!
//! Claims validation and the per-isolate caches (signing keys, push
//! verdicts) are pure and host-tested. Everything that needs the platform
//! goes through the injectable [`GitHubTrustApi`]: the two upstream GETs
//! (JWKS, repo permission) and the RS256 check itself, which the Worker
//! runs on `WebCrypto` (`crypto.subtle`) with the imported key cached
//! beside the JWKS entry, so a known `kid` costs no key import.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use sha2::Digest as _;

use crate::fetch_guard::{FetchedResponse, GuardedResponse};

/// The OIDC issuer every GitHub Actions token carries — also the
/// production host the JWKS document comes from.
const OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Clock-skew allowance on `exp`/`nbf` — GitHub's tokens are minted seconds
/// before use, so a minute is already generous.
const CLOCK_LEEWAY_SECS: i64 = 60;

/// How long a fetched signing key serves from isolate memory. GitHub
/// rotates its OIDC keys far slower than this and overlaps old and new
/// `kid`s in the JWKS, so an hour bounds staleness while covering a whole
/// build's worth of trusted calls.
const JWKS_CACHE_TTL_SECS: i64 = 3600;

/// How long a *proven* push verdict serves from isolate memory — the
/// revocation latency the cache adds: a token whose push access is
/// revoked on GitHub stays trusted here for at most this long after its
/// last probe. The probe it replaces is what GitHub rate-limited during
/// a write burst, so the TTL bounds upstream traffic as well.
const PUSH_VERDICT_TTL_SECS: i64 = 300;

/// How long a *denied* verdict is held — shorter than a proven one, so
/// a credential that just gained push access is never locked out for
/// the full positive TTL.
const PUSH_DENIED_TTL_SECS: i64 = 60;

/// The ref every mutating route pins (stow#955): a workflow run on any
/// other ref can read but never mutate.
pub const MAIN_REF: &str = "refs/heads/main";

/// The workflow every operator mutation runs through (stow#955).
/// `stow-admin` dispatches a fresh run per command, so the edge admits
/// only a run's first attempt: a token's `actor` names whoever started
/// the run, never whoever re-ran it, and a re-run would attribute one
/// operator's mutation to another.
pub const OPERATIONS_WORKFLOW: &str = "operations.yml";

/// Which workflows' runs may call a mutating route (stow#955). Each
/// route names its own policy type, so the set it admits is fixed where
/// the route is mounted; only a GitHub Actions OIDC identity of one of
/// these workflows, running at [`MAIN_REF`], passes [`authorize_mutation`].
pub trait MutationPolicy: Send + Sync + 'static {
    /// Workflow files under the repository's `.github/workflows/`.
    const WORKFLOWS: &'static [&'static str];
}

/// A caller that cleared the trust check. Carried into tracing so the
/// write logs name *who* wrote rather than "someone with the token".
#[derive(Debug, Clone)]
pub enum TrustedCaller {
    /// A GitHub Actions OIDC identity.
    Actions {
        /// `owner/repo/.github/workflows/<file>.yml@refs/...` of the job.
        job_workflow_ref: String,
        /// `owner/repo/.github/workflows/<file>.yml@refs/...` of the run
        /// — differs from `job_workflow_ref` only when the job runs a
        /// reusable workflow.
        workflow_ref: String,
        /// The workflow run id, for correlating a write back to its run.
        run_id: String,
        /// Which attempt of the run the job belongs to — `1` unless the
        /// run was re-run.
        run_attempt: String,
        /// The token's `ref` claim — the ref the run executes at.
        git_ref: String,
        /// The token's `actor` claim — the GitHub login that triggered
        /// the run, which a mutation's log row is attributed to.
        actor: String,
    },
    /// A GitHub credential that proved push access to the repo — a user
    /// token (label is the login) or an installation token such as the
    /// `GITHUB_TOKEN` the mock-e2e job drives the local edge with.
    Push {
        /// The token owner's GitHub login, or the credential class when
        /// the token cannot call user endpoints (app tokens 403 on
        /// `/user`).
        label: String,
    },
}

/// Gate an authenticated caller for a mutating route (stow#955). Only a
/// GitHub Actions OIDC identity passes — a user token and every other
/// push credential are read-only — and only one whose run executes at
/// [`MAIN_REF`] with both its run's and its job's workflow being one of
/// `workflows` at [`MAIN_REF`], so neither another ref's copy of an
/// allowed workflow nor an allowed workflow called from another one
/// can mutate; a run passes only on its first attempt, since a re-run
/// carries the original run's actor. Every claim compared here was read from a token whose
/// signature, issuer, audience, expiry and repository
/// [`authenticate`] already verified. Returns the actor the mutation is
/// attributed to.
///
/// # Errors
/// [`AuthError::Unauthorized`] for any caller outside the policy.
pub fn authorize_mutation<'a>(
    caller: &'a TrustedCaller,
    workflows: &[&str],
    repo: &str,
) -> Result<&'a str, AuthError> {
    let TrustedCaller::Actions {
        job_workflow_ref,
        workflow_ref,
        run_attempt,
        git_ref,
        actor,
        ..
    } = caller
    else {
        return Err(AuthError::Unauthorized);
    };
    let pinned = |file: &str| format!("{repo}/.github/workflows/{file}@{MAIN_REF}");
    let admitted = |claim: &str| workflows.iter().any(|file| claim == pinned(file));
    if git_ref != MAIN_REF || job_workflow_ref != workflow_ref || !admitted(workflow_ref) {
        return Err(AuthError::Unauthorized);
    }
    if run_attempt != "1" {
        return Err(AuthError::Unauthorized);
    }
    Ok(actor)
}

impl std::fmt::Display for TrustedCaller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Actions {
                job_workflow_ref,
                run_id,
                run_attempt,
                actor,
                ..
            } => write!(
                f,
                "actions:{job_workflow_ref} run {run_id} attempt {run_attempt} actor {actor}"
            ),
            Self::Push { label } => write!(f, "push:{label}"),
        }
    }
}

/// Non-secret trust configuration (worker vars).
#[derive(Debug, Clone)]
pub struct GitHubTrustConfig {
    /// `owner/repo` every credential must resolve inside.
    pub repo: String,
    /// The `aud` the CI side requests when it mints its OIDC token.
    pub oidc_audience: String,
    /// Origin every trust probe resolves under — `None` selects
    /// GitHub's production hosts (`api.github.com` for `/user`,
    /// `github.com` for the smart-HTTP push probe,
    /// `token.actions.githubusercontent.com` for the JWKS). The mock
    /// deploy pins one loopback origin (`STOW_GITHUB_API_URL`) whose
    /// stub answers every endpoint the check calls, so the mock stack's
    /// trusted lanes never reach the real API.
    pub probe_base_url: Option<String>,
}

/// Ways authentication can fail. `Unauthorized` means the credential itself
/// did not clear; `Upstream` means GitHub could not be consulted — kept
/// distinct so an upstream outage is not misread as a bad credential.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The credential was absent, malformed, or failed its check.
    #[error("unauthorized")]
    Unauthorized,
    /// A GitHub/JWKS fetch or response failed.
    #[error("github trust upstream: {0}")]
    Upstream(String),
    /// GitHub refused the trust check itself with a rate limit (a 429,
    /// or a 403 carrying rate-limit headers) — the credential was never
    /// evaluated. `retry_after_secs` is the delay GitHub asked for,
    /// echoed to the caller as `Retry-After` so its backoff matches the
    /// window GitHub is enforcing.
    #[error("github trust upstream rate limited")]
    RateLimited {
        /// Seconds the caller should wait before retrying.
        retry_after_secs: u64,
    },
}

/// The HTTP surface the auth layer needs. The wasm impl calls GitHub through
/// the worker fetch API; tests substitute a stub so every policy branch stays
/// host-verified. `Sync` + `Send` bounds mirror `CratesIo`: `&impl
/// GitHubTrustApi` must stay sendable across awaits inside extractors.
pub trait GitHubTrustApi: Sync {
    /// A signing key imported for verification, cached per `kid`.
    type Key: Clone + Send + Sync;
    /// Import `jwk` as a key that only verifies RS256.
    fn import_key(&self, jwk: &Jwk) -> impl Future<Output = Result<Self::Key, AuthError>> + Send;
    /// Verify the RS256 `signature` over `signing_input` with `key`;
    /// any failure is [`AuthError::Unauthorized`].
    fn verify_rs256(
        &self,
        key: &Self::Key,
        signing_input: &[u8],
        signature: &[u8],
    ) -> impl Future<Output = Result<(), AuthError>> + Send;
    /// The current GitHub Actions OIDC signing keys.
    fn jwks(&self) -> impl Future<Output = Result<JwkSet, AuthError>> + Send;
    /// A caller label for `token` when it has push access to `repo`,
    /// `None` when the token is valid but lacks push (or is invalid).
    fn repo_push_login(
        &self,
        token: &str,
        repo: &str,
    ) -> impl Future<Output = Result<Option<String>, AuthError>> + Send;
}

/// Authenticate an `Authorization: Bearer` credential.
///
/// JWT-shaped credentials (a `kid`+`alg` header) take the OIDC path; every
/// other shape is treated as a GitHub user token and checked against the
/// repo's push capability. The probe's verdict is served from
/// `push_verdicts` when fresh — a cached hit carries its caller label and
/// makes zero GitHub calls.
pub async fn authenticate<A: GitHubTrustApi>(
    config: &GitHubTrustConfig,
    api: &A,
    jwks: &Jwks<A::Key>,
    push_verdicts: &PushVerdicts,
    bearer: &str,
    now_unix: i64,
) -> Result<TrustedCaller, AuthError> {
    if looks_like_jwt(bearer) {
        return authenticate_oidc(config, api, jwks, bearer, now_unix).await;
    }
    if !looks_like_user_token(bearer) {
        return Err(AuthError::Unauthorized);
    }
    match push_verdicts.verdict_for(bearer, now_unix) {
        Some(Verdict::Push { label }) => return Ok(TrustedCaller::Push { label }),
        Some(Verdict::Denied) => return Err(AuthError::Unauthorized),
        None => {}
    }
    let verdict = api
        .repo_push_login(bearer, &config.repo)
        .await?
        .map_or(Verdict::Denied, |label| Verdict::Push { label });
    push_verdicts.record(bearer, verdict.clone(), now_unix);
    match verdict {
        Verdict::Push { label } => Ok(TrustedCaller::Push { label }),
        Verdict::Denied => Err(AuthError::Unauthorized),
    }
}

/// The OIDC path: pin the claims to this deployment, resolve the header
/// `kid` against the cached keyset (fetching the JWKS once on a miss),
/// then verify RS256.
async fn authenticate_oidc<A: GitHubTrustApi>(
    config: &GitHubTrustConfig,
    api: &A,
    jwks: &Jwks<A::Key>,
    token: &str,
    now_unix: i64,
) -> Result<TrustedCaller, AuthError> {
    let (header, signing_input, signature, claims) = decode_jwt(token)?;
    // The claims are checked before the signature: a token that does not
    // name this deployment is refused without a key lookup or any crypto.
    let caller = validate_claims(config, claims, now_unix)?;
    let key = resolve_key(api, jwks, &header.kid, now_unix).await?;
    api.verify_rs256(&key, signing_input.as_bytes(), &signature)
        .await?;
    Ok(caller)
}

/// The imported key for `kid`. An unknown or expired `kid` refreshes the
/// set exactly once; a `kid` still missing after the fresh fetch is a bad
/// credential, not a refetch loop. A listed key is imported on first use
/// and kept beside its JWKS entry.
async fn resolve_key<A: GitHubTrustApi>(
    api: &A,
    jwks: &Jwks<A::Key>,
    kid: &str,
    now_unix: i64,
) -> Result<A::Key, AuthError> {
    let lookup = if let Some(lookup) = jwks.lookup(kid, now_unix) {
        lookup
    } else {
        jwks.replace_all(api.jwks().await?, now_unix);
        jwks.lookup(kid, now_unix).ok_or(AuthError::Unauthorized)?
    };
    match lookup {
        Lookup::Imported(key) => Ok(key),
        Lookup::Listed(jwk) => {
            let key = api.import_key(&jwk).await?;
            jwks.keep_import(&jwk, &key);
            Ok(key)
        }
    }
}

/// Every claim that pins the token to this deployment — issuer, audience,
/// repo, expiry — and that the job's workflow lives in the repo. Pure:
/// the signature is a separate check.
fn validate_claims(
    config: &GitHubTrustConfig,
    claims: OidcClaims,
    now_unix: i64,
) -> Result<TrustedCaller, AuthError> {
    if claims.iss != OIDC_ISSUER
        || !claims.aud.contains(&config.oidc_audience)
        || claims.exp + CLOCK_LEEWAY_SECS <= now_unix
        || claims
            .nbf
            .is_some_and(|nbf| nbf - CLOCK_LEEWAY_SECS > now_unix)
        || claims.repository != config.repo
    {
        return Err(AuthError::Unauthorized);
    }
    let workflow_prefix = format!("{}/.github/workflows/", config.repo);
    if !claims.job_workflow_ref.starts_with(&workflow_prefix) {
        return Err(AuthError::Unauthorized);
    }
    Ok(TrustedCaller::Actions {
        job_workflow_ref: claims.job_workflow_ref,
        workflow_ref: claims.workflow_ref,
        run_id: claims.run_id,
        run_attempt: claims.run_attempt,
        git_ref: claims.git_ref,
        actor: claims.actor,
    })
}

/// GitHub's credential formats are published: `ghp_`/`github_pat_` are
/// personal tokens, `gho_` OAuth, `ghu_`/`ghs_`/`ghr_` app and refresh
/// tokens. Anything else is not a GitHub credential — rejecting it here
/// keeps a garbage bearer from fanning out to the permission API.
fn looks_like_user_token(token: &str) -> bool {
    const PREFIXES: &[&str] = &["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"];
    PREFIXES.iter().any(|prefix| token.starts_with(prefix))
}

/// Three base64url segments with a decodable JSON header carrying `kid` —
/// GitHub's OIDC tokens always set one; user tokens never parse as JWTs at
/// all, so a failed header decode routes to the token path rather than a
/// hard rejection.
fn looks_like_jwt(token: &str) -> bool {
    let mut parts = token.split('.');
    let (Some(header), Some(_), Some(_)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    b64url_decode(header)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<JwtHeader>(&bytes).ok())
        .is_some_and(|header| header.alg == "RS256")
}

/// The JWT header fields the verifier uses.
#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    kid: String,
}

/// The claims subset the policy pins.
#[derive(Debug, Deserialize)]
struct OidcClaims {
    iss: String,
    #[serde(default)]
    aud: Audience,
    exp: i64,
    #[serde(default)]
    nbf: Option<i64>,
    repository: String,
    job_workflow_ref: String,
    #[serde(default)]
    run_id: String,
    /// GitHub sets `workflow_ref`, `run_attempt`, `ref` and `actor` on
    /// every Actions token; one without them is not a token the mutation
    /// gate can judge, so they are required rather than defaulted.
    workflow_ref: String,
    run_attempt: String,
    /// The `ref` claim (a Rust keyword — renamed).
    #[serde(rename = "ref")]
    git_ref: String,
    /// The `actor` claim — the login that triggered the run.
    actor: String,
}

/// `aud` arrives as a string for a single audience and an array for many.
#[derive(Debug, Default, Deserialize)]
#[serde(untagged)]
enum Audience {
    #[default]
    None,
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, wanted: &str) -> bool {
        match self {
            Self::None => false,
            Self::One(aud) => aud == wanted,
            Self::Many(auds) => auds.iter().any(|aud| aud == wanted),
        }
    }
}

/// One RSA signing key from GitHub's JWKS.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    /// Key type — always `RSA` on GitHub's set.
    pub kty: String,
    /// Key id matching the JWT header.
    pub kid: String,
    /// Base64url-unsigned modulus.
    pub n: String,
    /// Base64url-unsigned exponent.
    pub e: String,
}

/// The JWKS document.
#[derive(Debug, Deserialize)]
pub struct JwkSet {
    /// Signing keys, newest first.
    pub keys: Vec<Jwk>,
}

/// A fetched signing key held in isolate memory until `expires_at_unix`
/// (epoch seconds), with its imported form once a request has used it.
#[derive(Debug, Clone)]
struct CachedKey<K> {
    jwk: Jwk,
    imported: Option<K>,
    expires_at_unix: i64,
}

/// What the cache holds for a `kid`.
enum Lookup<K> {
    /// Listed and already imported: verification needs no import.
    Imported(K),
    /// Listed, not yet imported.
    Listed(Jwk),
}

/// Per-isolate cache of GitHub's OIDC signing keys keyed by `kid`, each
/// with the imported key (`K`) beside it and the same lifetime: the import
/// leaves with the entry on expiry or on a refetch.
///
/// `skyzen::utils::State` requires `Send + Sync + Clone`, so the map sits
/// behind `Arc<Mutex<_>>` rather than `RefCell`. Workers run each isolate
/// single-threaded and the guard is never held across an `.await`, so the
/// lock can never contend and poisoning is unreachable.
#[derive(Debug)]
pub struct Jwks<K> {
    inner: Arc<Mutex<HashMap<String, CachedKey<K>>>>,
}

impl<K> Default for Jwks<K> {
    fn default() -> Self {
        Self {
            inner: Arc::default(),
        }
    }
}

impl<K> Clone for Jwks<K> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<K: Clone> Jwks<K> {
    /// The cached entry for `kid` while it is still valid at `now_unix`
    /// (epoch seconds).
    fn lookup(&self, kid: &str, now_unix: i64) -> Option<Lookup<K>> {
        self.lock()
            .get(kid)
            .filter(|cached| cached.expires_at_unix > now_unix)
            .map(|cached| {
                cached.imported.as_ref().map_or_else(
                    || Lookup::Listed(cached.jwk.clone()),
                    |key| Lookup::Imported(key.clone()),
                )
            })
    }

    /// Keep `key` as the import of the entry that still lists `jwk`. A set
    /// refetched while the import ran may have replaced the entry with
    /// other key material; that entry is imported afresh on its first use.
    fn keep_import(&self, jwk: &Jwk, key: &K) {
        if let Some(cached) = self.lock().get_mut(&jwk.kid)
            && cached.jwk.n == jwk.n
            && cached.jwk.e == jwk.e
        {
            cached.imported.get_or_insert_with(|| key.clone());
        }
    }

    /// Replace the whole cached set with a freshly fetched `jwks`; every
    /// RSA entry expires [`JWKS_CACHE_TTL_SECS`] after `now_unix`.
    /// Non-RSA keys are dropped — the verifier can never use them.
    fn replace_all(&self, jwks: JwkSet, now_unix: i64) {
        let expires_at_unix = now_unix.saturating_add(JWKS_CACHE_TTL_SECS);
        let mut cache = self.lock();
        cache.clear();
        cache.extend(jwks.keys.into_iter().filter_map(|key| {
            (key.kty == "RSA").then(|| {
                (
                    key.kid.clone(),
                    CachedKey {
                        jwk: key,
                        imported: None,
                        expires_at_unix,
                    },
                )
            })
        }));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, CachedKey<K>>> {
        self.inner.lock().expect("jwks cache mutex poisoned")
    }
}

/// The outcome a probe cached for one credential.
#[derive(Debug, Clone)]
enum Verdict {
    /// GitHub confirmed push capability; `label` is the `/user` login
    /// (or the credential class) the probe also fetched, so a cached hit
    /// carries its caller identity and makes zero GitHub calls.
    Push { label: String },
    /// GitHub answered the probe with a denial — a token without push
    /// access, or an invalid one.
    Denied,
}

/// A cached [`Verdict`] plus the `expires_at_unix` bounding how long it
/// serves.
#[derive(Debug, Clone)]
struct CachedVerdict {
    verdict: Verdict,
    expires_at_unix: i64,
}

/// Per-isolate cache of push-capability verdicts keyed by a SHA-256
/// digest of the bearer token — the token itself is never stored.
///
/// The probe it replaces ran on every trusted request, and the Worker's
/// shared egress IPs got it rate-limited by GitHub during a write
/// burst; caching by digest keeps the checks the burst needs at zero.
/// An isolate restart cold-starts the cache — it re-probes once per
/// credential and refills. Same mechanics as [`Jwks`]: `Arc<Mutex<_>>`
/// because `skyzen::utils::State` requires `Send + Sync + Clone`, and
/// the guard is never held across an `.await`.
#[derive(Debug, Default, Clone)]
pub struct PushVerdicts {
    inner: Arc<Mutex<HashMap<String, CachedVerdict>>>,
}

impl PushVerdicts {
    /// The cached verdict for `token` while it is still fresh at
    /// `now_unix`; `None` is a miss. A hit carries the `/user` label
    /// with the verdict, so serving one makes zero GitHub calls.
    fn verdict_for(&self, token: &str, now_unix: i64) -> Option<Verdict> {
        self.lock()
            .get(&token_digest(token))
            .filter(|cached| cached.expires_at_unix > now_unix)
            .map(|cached| cached.verdict.clone())
    }

    /// Cache `verdict` under `token`'s digest — [`Verdict::Push`] holds
    /// for [`PUSH_VERDICT_TTL_SECS`], [`Verdict::Denied`] for
    /// [`PUSH_DENIED_TTL_SECS`]. Errors are never recorded, so a
    /// rate-limited or unreachable GitHub never becomes a cached
    /// "no".
    fn record(&self, token: &str, verdict: Verdict, now_unix: i64) {
        let ttl = match verdict {
            Verdict::Push { .. } => PUSH_VERDICT_TTL_SECS,
            Verdict::Denied => PUSH_DENIED_TTL_SECS,
        };
        self.lock().insert(
            token_digest(token),
            CachedVerdict {
                verdict,
                expires_at_unix: now_unix.saturating_add(ttl),
            },
        );
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, CachedVerdict>> {
        self.inner
            .lock()
            .expect("push verdict cache mutex poisoned")
    }
}

/// The cache key for a credential: the SHA-256 hex of the token, so the
/// map never holds anything that could authenticate a request.
fn token_digest(token: &str) -> String {
    hex::encode(sha2::Sha256::digest(token.as_bytes()))
}

/// Marker the trust-check extractor stashes in the request extensions
/// when GitHub rate-limited the credential probe — the `Retry-After`
/// seconds [`TrustRateLimitGate`] puts on the wire. The shared
/// `{"error": ...}` envelope renders an error's status and message only,
/// so the hint has to ride the request, not the error.
#[derive(Debug, Clone, Copy)]
pub struct TrustRateLimited {
    /// Seconds to advertise in `Retry-After`.
    pub retry_after_secs: u64,
}

/// The `503 Service Unavailable` answering a rate-limited trust probe:
/// the same `{"error": ...}` shape the shared envelope produces, plus
/// the `Retry-After` GitHub asked for.
fn rate_limited_response(retry_after_secs: u64) -> skyzen::Response {
    #[derive(serde::Serialize)]
    struct RateLimitedBody<'a> {
        error: &'a str,
    }
    let payload = serde_json::to_vec(&RateLimitedBody {
        error: "github trust upstream rate limited; retry later",
    })
    .expect("a struct of string slices serializes to JSON");
    let mut response = skyzen::Response::new(skyzen::Body::from(payload));
    *response.status_mut() = skyzen::StatusCode::SERVICE_UNAVAILABLE;
    response.headers_mut().insert(
        skyzen::header::CONTENT_TYPE,
        skyzen::header::HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        skyzen::header::RETRY_AFTER,
        skyzen::header::HeaderValue::from(retry_after_secs),
    );
    response
}

/// Skyzen middleware `entry.rs` wraps the trusted route group in. When
/// the trust check left a [`TrustRateLimited`] marker on the request,
/// the answer is the 503 the marker describes — `Retry-After` included
/// — rather than the shared error envelope, which cannot attach
/// headers. Any other result passes through untouched.
#[derive(Debug, Clone)]
pub struct TrustRateLimitGate;

impl skyzen::middleware::Middleware for TrustRateLimitGate {
    async fn handle(
        &self,
        request: &mut skyzen::Request,
        next: skyzen::middleware::Next<'_>,
    ) -> Result<skyzen::Response, skyzen::Error> {
        let result = next.run(request).await;
        if result.is_err()
            && let Some(&TrustRateLimited { retry_after_secs }) =
                request.extensions().get::<TrustRateLimited>()
        {
            return Ok(rate_limited_response(retry_after_secs));
        }
        result
    }
}

/// Split a compact JWT into its signing input, signature, and typed
/// claims — no trust yet, just shape.
fn decode_jwt(token: &str) -> Result<(JwtHeader, String, Vec<u8>, OidcClaims), AuthError> {
    let mut parts = token.splitn(3, '.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return Err(AuthError::Unauthorized);
    };
    let header: JwtHeader =
        serde_json::from_slice(&b64url_decode(header_b64)?).map_err(|_| AuthError::Unauthorized)?;
    if header.alg != "RS256" {
        return Err(AuthError::Unauthorized);
    }
    let claims: OidcClaims = serde_json::from_slice(&b64url_decode(payload_b64)?)
        .map_err(|_| AuthError::Unauthorized)?;
    let signature = b64url_decode(signature_b64)?;
    Ok((
        header,
        format!("{header_b64}.{payload_b64}"),
        signature,
        claims,
    ))
}

/// Base64url-decode, tolerating the absent padding JWKS/JWT fields omit.
fn b64url_decode(value: &str) -> Result<Vec<u8>, AuthError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AuthError::Unauthorized)
}

/// `Retry-After` seconds to advertise when GitHub sent a rate-limited
/// reply without a usable hint of its own — its secondary-rate-limit
/// docs only say to wait, so a minute is conservative without
/// starving the caller.
const RATE_LIMIT_FALLBACK_SECS: u64 = 60;

/// Whether `status`/`header` describe a GitHub rate limit rather
/// than a plain denial: a 429 outright, or a 403 stamped with a
/// rate-limit header (403 is what GitHub's secondary limits send).
fn is_rate_limited(status: u16, header: impl Fn(&str) -> Option<String>) -> bool {
    status == 429
        || (status == 403
            && (header("retry-after").is_some()
                || header("x-ratelimit-remaining").is_some_and(|remaining| remaining == "0")))
}

/// The [`AuthError::RateLimited`] for a rate-limited reply —
/// `retry-after` verbatim when GitHub sent it, else
/// `x-ratelimit-reset` (an epoch) minus the wall clock, else the
/// fallback.
fn rate_limited(header: impl Fn(&str) -> Option<String>, now_unix: i64) -> AuthError {
    let retry_after_secs = header("retry-after")
        .and_then(|value| value.parse::<u64>().ok())
        .or_else(|| {
            header("x-ratelimit-reset")
                .and_then(|value| value.parse::<i64>().ok())
                .and_then(|reset| u64::try_from(reset.saturating_sub(now_unix)).ok())
        })
        .unwrap_or(RATE_LIMIT_FALLBACK_SECS)
        .max(1);
    AuthError::RateLimited { retry_after_secs }
}

/// Status classification for the trust probes' JSON GETs — the guard
/// cancels the body on every arm the caller does not read: rate limits,
/// 401/403/404 denials. 2xx and unclassified statuses read the body
/// (denial details and, past the check, the JSON the caller parses).
async fn read_json_response<B: FetchedResponse>(
    response: GuardedResponse<B>,
    url: &str,
    now_unix: i64,
) -> Result<Option<String>, AuthError> {
    let status = response.get_ref().status_code();
    if is_rate_limited(status, |name| response.get_ref().header(name)) {
        return Err(rate_limited(
            |name| response.get_ref().header(name),
            now_unix,
        ));
    }
    if matches!(status, 401 | 403 | 404) {
        return Ok(None);
    }
    let text = response
        .into_inner()
        .text()
        .await
        .map_err(|error| AuthError::Upstream(format!("read {url} body: {error}")))?;
    if !(200..300).contains(&status) {
        return Err(AuthError::Upstream(format!("{url} -> {status}")));
    }
    Ok(Some(text))
}

/// Status classification for the push probe — GitHub's ref
/// advertisement is a chunked stream the probe never needs, so every
/// arm lets the guard cancel the body rather than read it.
fn read_probe_response<B: FetchedResponse>(
    response: GuardedResponse<B>,
    url: &str,
    now_unix: i64,
) -> Result<bool, AuthError> {
    let status = response.get_ref().status_code();
    let verdict = match status {
        200 => true,
        _ if is_rate_limited(status, |name| response.get_ref().header(name)) => {
            return Err(rate_limited(
                |name| response.get_ref().header(name),
                now_unix,
            ));
        }
        401 | 403 | 404 => false,
        _ => return Err(AuthError::Upstream(format!("{url} -> {status}"))),
    };
    drop(response);
    Ok(verdict)
}

/// GitHub's REST API origin — the `/user` label probe's production host.
const GITHUB_API_BASE: &str = "https://api.github.com";

/// GitHub's web origin — the smart-HTTP `info/refs` push probe's
/// production host.
const GITHUB_WEB_BASE: &str = "https://github.com";

/// The `git-receive-pack` advertisement URL the push probe GETs —
/// `base`'s path when the deploy pins a mock origin, `github.com`
/// otherwise. A trailing slash on `base` is ignored.
fn push_probe_url(base: Option<&str>, repo: &str) -> String {
    format!(
        "{}/{repo}.git/info/refs?service=git-receive-pack",
        base.unwrap_or(GITHUB_WEB_BASE).trim_end_matches('/')
    )
}

/// The `/user` URL a proven credential's label comes from.
fn user_url(base: Option<&str>) -> String {
    format!(
        "{}/user",
        base.unwrap_or(GITHUB_API_BASE).trim_end_matches('/')
    )
}

/// The OIDC signing-keys document URL — the issuer's `.well-known`
/// path under whichever origin the probes resolve against.
fn jwks_url(base: Option<&str>) -> String {
    format!(
        "{}/.well-known/jwks",
        base.unwrap_or(OIDC_ISSUER).trim_end_matches('/')
    )
}

#[cfg(target_arch = "wasm32")]
pub use cf_impl::{CfGitHubTrust, CfJwks};

/// The production [`GitHubTrustApi`]: two GETs through the worker fetch
/// API. The JWKS fetch is only reached on a `Jwks` cache miss; a fetched
/// set replaces the cache wholesale so a malformed response never lingers
/// beside stale keys.
#[cfg(target_arch = "wasm32")]
mod cf_impl {
    use super::{AuthError, GitHubTrustApi, Jwk, JwkSet, Jwks};
    use crate::fetch_guard::OutboundPool;
    use skyzen_cloudflare::worker::send::{IntoSendFuture as _, SendWrapper};
    use wasm_bindgen::{JsCast as _, JsValue};

    /// A JWK imported through `WebCrypto` as a verify-only RS256 key. The
    /// handle is a JS object, `Send` here because Workers run each isolate
    /// on one thread.
    pub type VerifyKey = SendWrapper<web_sys::CryptoKey>;

    /// The per-isolate signing-key cache the Worker runs with.
    pub type CfJwks = Jwks<VerifyKey>;

    /// `{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }` — RS256.
    fn rs256_algorithm() -> Result<js_sys::Object, JsValue> {
        let algorithm = js_sys::Object::new();
        js_sys::Reflect::set(
            &algorithm,
            &JsValue::from_str("name"),
            &JsValue::from_str("RSASSA-PKCS1-v1_5"),
        )?;
        js_sys::Reflect::set(
            &algorithm,
            &JsValue::from_str("hash"),
            &JsValue::from_str("SHA-256"),
        )?;
        Ok(algorithm)
    }

    fn subtle() -> Result<web_sys::SubtleCrypto, JsValue> {
        let crypto: web_sys::Crypto =
            js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("crypto"))?.unchecked_into();
        Ok(crypto.subtle())
    }

    /// A rejected import or verify is a credential the edge cannot trust;
    /// the JS reason is logged, never returned to the caller.
    fn refused(error: &JsValue) -> AuthError {
        tracing::warn!(?error, "oidc signature check refused by webcrypto");
        AuthError::Unauthorized
    }

    async fn import_rs256(jwk: &Jwk) -> Result<VerifyKey, JsValue> {
        let subtle = SendWrapper::new(subtle()?);
        let algorithm = SendWrapper::new(rs256_algorithm()?);
        let data = SendWrapper::new(js_sys::Object::new());
        for (name, value) in [
            ("kty", "RSA"),
            ("alg", "RS256"),
            ("n", jwk.n.as_str()),
            ("e", jwk.e.as_str()),
        ] {
            js_sys::Reflect::set(&data, &JsValue::from_str(name), &JsValue::from_str(value))?;
        }
        js_sys::Reflect::set(&data, &JsValue::from_str("ext"), &JsValue::TRUE)?;
        let usages: JsValue = js_sys::Array::of1(&JsValue::from_str("verify")).into();
        let key = wasm_bindgen_futures::JsFuture::from(
            subtle.import_key_with_object("jwk", &data, &algorithm, false, &usages)?,
        )
        .into_send()
        .await?;
        Ok(SendWrapper::new(key.unchecked_into()))
    }

    async fn verify_with(
        key: &VerifyKey,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<bool, JsValue> {
        let subtle = SendWrapper::new(subtle()?);
        let algorithm = SendWrapper::new(rs256_algorithm()?);
        let verdict = wasm_bindgen_futures::JsFuture::from(
            subtle.verify_with_object_and_u8_array_and_u8_array(
                &algorithm,
                key,
                signature,
                signing_input,
            )?,
        )
        .into_send()
        .await?;
        Ok(verdict.is_truthy())
    }

    /// Fetches GitHub's OIDC JWKS and repo-permission checks through the
    /// worker's outbound fetch, bounded by the [`OutboundPool`] of the
    /// request that built it.
    pub struct CfGitHubTrust {
        pool: OutboundPool,
        /// `GitHubTrustConfig::probe_base_url` — the mock origin the
        /// probes resolve under when the deploy pins one, `None` on
        /// production.
        probe_base_url: Option<String>,
    }

    impl CfGitHubTrust {
        /// A trust client drawing its fetch slots from `pool`, probing
        /// `probe_base_url` instead of GitHub's production hosts when
        /// the deploy pins a mock origin.
        pub const fn new(pool: OutboundPool, probe_base_url: Option<String>) -> Self {
            Self {
                pool,
                probe_base_url,
            }
        }
    }

    /// Wall-clock seconds — `js_sys::Date` is the only clock in the
    /// worker; used to turn `x-ratelimit-reset` epochs into delays.
    fn now_unix_secs() -> i64 {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "js_sys::Date::now() returns positive epoch milliseconds; whole seconds are the intended unit"
        )]
        let seconds = (js_sys::Date::now() / 1_000.0) as i64;
        seconds
    }

    /// GET `url` with the given bearer (empty string sends none) and parse
    /// the JSON body. 404/401/403 return `None` — for permission checks
    /// that is "no", for JWKS the caller turns it into `Upstream`.
    async fn get_json<T: serde::de::DeserializeOwned>(
        url: &str,
        bearer: &str,
        pool: &OutboundPool,
    ) -> Result<Option<T>, AuthError> {
        let auth = format!("Bearer {bearer}");
        let headers: &[(&str, &str)] = if bearer.is_empty() {
            &[("User-Agent", "stow-edge"), ("Accept", "application/json")]
        } else {
            &[
                ("User-Agent", "stow-edge"),
                ("Accept", "application/json"),
                ("Authorization", auth.as_str()),
            ]
        };
        let request = SendWrapper::new(
            crate::cf_http::bare_request(
                skyzen_cloudflare::worker::Method::Get,
                url,
                headers,
                None,
            )
            .map_err(|error| AuthError::Upstream(format!("build request: {error}")))?,
        );
        // A slot bounds the probes inside the request's connection
        // budget; held until the body is read or cancelled below.
        let _slot = pool.slot().await;
        let response = crate::fetch_guard::GuardedResponse::new(SendWrapper::new(
            skyzen_cloudflare::CfFetch
                .request(&request)
                .await
                .map_err(|error| AuthError::Upstream(format!("fetch {url}: {error}")))?,
        ));
        super::read_json_response(response, url, now_unix_secs())
            .await?
            .map_or_else(
                || Ok(None),
                |text| {
                    serde_json::from_str(&text)
                        .map(Some)
                        .map_err(|error| AuthError::Upstream(format!("decode {url}: {error}")))
                },
            )
    }

    #[derive(serde::Deserialize)]
    struct GitHubUser {
        login: String,
    }

    /// `git-receive-pack` is the push half of smart-HTTP — GitHub answers
    /// the ref advertisement only when the credential may write. That
    /// probes the exact capability trusted callers need, for every
    /// credential type GitHub's git endpoint accepts (PATs, fine-grained
    /// PATs, OAuth tokens, `GITHUB_TOKEN` installation tokens); the REST
    /// permissions field does not reflect job-scoped installation tokens.
    /// 200 -> push; 401/403/404 -> no push; anything else -> upstream.
    async fn push_capable(
        token: &str,
        repo: &str,
        base: Option<&str>,
        pool: &OutboundPool,
    ) -> Result<bool, AuthError> {
        use base64::Engine;
        let basic =
            base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"));
        let url = super::push_probe_url(base, repo);
        let auth = format!("Basic {basic}");
        let request = SendWrapper::new(
            crate::cf_http::bare_request(
                skyzen_cloudflare::worker::Method::Get,
                &url,
                &[
                    ("User-Agent", "stow-edge"),
                    ("Authorization", auth.as_str()),
                ],
                None,
            )
            .map_err(|error| AuthError::Upstream(format!("build request: {error}")))?,
        );
        let _slot = pool.slot().await;
        let response = crate::fetch_guard::GuardedResponse::new(SendWrapper::new(
            skyzen_cloudflare::CfFetch
                .request(&request)
                .await
                .map_err(|error| AuthError::Upstream(format!("fetch {url}: {error}")))?,
        ));
        super::read_probe_response(response, &url, now_unix_secs())
    }

    /// Label for the log when `/user` is unreachable — app and
    /// installation tokens (`ghs_`, `GITHUB_TOKEN`) 403 on user endpoints.
    fn credential_class(token: &str) -> &'static str {
        if token.starts_with("ghs_") {
            "github-app-installation"
        } else if token.starts_with("github_pat_") {
            "fine-grained-pat"
        } else {
            "unknown-credential"
        }
    }

    impl GitHubTrustApi for CfGitHubTrust {
        type Key = VerifyKey;

        async fn import_key(&self, jwk: &Jwk) -> Result<VerifyKey, AuthError> {
            import_rs256(jwk).await.map_err(|error| refused(&error))
        }

        async fn verify_rs256(
            &self,
            key: &VerifyKey,
            signing_input: &[u8],
            signature: &[u8],
        ) -> Result<(), AuthError> {
            match verify_with(key, signing_input, signature).await {
                Ok(true) => Ok(()),
                Ok(false) => Err(AuthError::Unauthorized),
                Err(error) => Err(refused(&error)),
            }
        }

        async fn jwks(&self) -> Result<JwkSet, AuthError> {
            let url = super::jwks_url(self.probe_base_url.as_deref());
            get_json::<JwkSet>(&url, "", &self.pool)
                .await?
                .ok_or_else(|| AuthError::Upstream(format!("{url} not found")))
        }

        async fn repo_push_login(
            &self,
            token: &str,
            repo: &str,
        ) -> Result<Option<String>, AuthError> {
            if !push_capable(token, repo, self.probe_base_url.as_deref(), &self.pool).await? {
                return Ok(None);
            }
            let label = get_json::<GitHubUser>(
                &super::user_url(self.probe_base_url.as_deref()),
                token,
                &self.pool,
            )
            .await?
            .map_or_else(|| credential_class(token).to_owned(), |user| user.login);
            Ok(Some(label))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const NOW: i64 = 1_800_000_000;

    /// A stand-in signing identity. The host build carries no RS256
    /// verifier (production verifies on `WebCrypto`, covered by the workerd
    /// suite in `edge/tests/idle`), so these tests exercise the policy
    /// around the signature with a double whose "signature" binds the key
    /// and the exact signing input: a different key or a changed payload
    /// fails the stub's check the way it fails the real one.
    #[derive(Clone, Copy)]
    struct TestKey(&'static str);

    fn test_key() -> TestKey {
        TestKey("test-key")
    }

    fn forger_key() -> TestKey {
        TestKey("forger-key")
    }

    /// The stub "signature" of `signing_input` under the key whose JWK
    /// modulus is `n`.
    fn stub_signature(n: &str, signing_input: &str) -> Vec<u8> {
        format!("{n}|{signing_input}").into_bytes()
    }

    fn test_config() -> GitHubTrustConfig {
        GitHubTrustConfig {
            repo: "water-rs/stow".to_owned(),
            oidc_audience: "https://stow.waterui.dev".to_owned(),
            probe_base_url: None,
        }
    }

    /// Programmable trust surface: a fixed keyset plus whichever login the
    /// repo-permission check should report. `jwks_fetches` counts the
    /// signing-key GETs so tests can pin the cache's fetch-once behavior;
    /// `push_calls` does the same for the push probe.
    struct StubTrust {
        jwk: Jwk,
        push_login: Mutex<Option<String>>,
        push_failure: Mutex<Option<StubPushFailure>>,
        jwks_fetches: Mutex<u32>,
        imports: Mutex<u32>,
        push_calls: Mutex<u32>,
    }

    /// The upstream failure a `repo_push_login` stub call reports.
    enum StubPushFailure {
        /// A GitHub rate limit carrying this many `Retry-After` seconds.
        RateLimited { retry_after_secs: u64 },
    }

    impl StubTrust {
        fn for_key(key: &TestKey) -> Self {
            Self {
                jwk: jwk_for(key, "test-kid"),
                push_login: Mutex::new(None),
                push_failure: Mutex::new(None),
                jwks_fetches: Mutex::new(0),
                imports: Mutex::new(0),
                push_calls: Mutex::new(0),
            }
        }

        fn fetch_count(&self) -> u32 {
            *self.jwks_fetches.lock().expect("lock")
        }

        fn import_count(&self) -> u32 {
            *self.imports.lock().expect("lock")
        }

        fn push_call_count(&self) -> u32 {
            *self.push_calls.lock().expect("lock")
        }
    }

    /// The JWK advertising `key` under `kid`.
    fn jwk_for(key: &TestKey, kid: &str) -> Jwk {
        Jwk {
            kty: "RSA".to_owned(),
            kid: kid.to_owned(),
            n: b64url_encode(key.0.as_bytes()),
            e: "AQAB".to_owned(),
        }
    }

    impl GitHubTrustApi for StubTrust {
        type Key = String;

        fn import_key(&self, jwk: &Jwk) -> impl Future<Output = Result<String, AuthError>> + Send {
            *self.imports.lock().expect("lock") += 1;
            std::future::ready(Ok(jwk.n.clone()))
        }

        fn verify_rs256(
            &self,
            key: &String,
            signing_input: &[u8],
            signature: &[u8],
        ) -> impl Future<Output = Result<(), AuthError>> + Send {
            let signing_input = std::str::from_utf8(signing_input).expect("utf8 signing input");
            std::future::ready(if signature == stub_signature(key, signing_input) {
                Ok(())
            } else {
                Err(AuthError::Unauthorized)
            })
        }

        fn jwks(&self) -> impl Future<Output = Result<JwkSet, AuthError>> + Send {
            *self.jwks_fetches.lock().expect("lock") += 1;
            std::future::ready(Ok(JwkSet {
                keys: vec![self.jwk.clone()],
            }))
        }

        fn repo_push_login(
            &self,
            _token: &str,
            _repo: &str,
        ) -> impl Future<Output = Result<Option<String>, AuthError>> + Send {
            *self.push_calls.lock().expect("lock") += 1;
            if let Some(StubPushFailure::RateLimited { retry_after_secs }) =
                *self.push_failure.lock().expect("lock")
            {
                return std::future::ready(Err(AuthError::RateLimited { retry_after_secs }));
            }
            std::future::ready(Ok(self.push_login.lock().expect("lock").clone()))
        }
    }

    fn b64url_encode(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Mint a compact JWT under `test-kid`: JSON header + JSON claims,
    /// stub-signed.
    fn mint_jwt(key: &TestKey, claims: &serde_json::Value) -> String {
        mint_jwt_with_kid(key, claims, "test-kid")
    }

    /// Mint a compact JWT whose header names `kid` — for tokens signed by a
    /// key the JWKS does not advertise.
    fn mint_jwt_with_kid(key: &TestKey, claims: &serde_json::Value, kid: &str) -> String {
        let header = b64url_encode(
            serde_json::to_string(&serde_json::json!({
                "alg": "RS256",
                "typ": "JWT",
                "kid": kid,
            }))
            .expect("header")
            .as_bytes(),
        );
        let payload = b64url_encode(serde_json::to_string(&claims).expect("claims").as_bytes());
        let signing_input = format!("{header}.{payload}");
        let signature = stub_signature(&b64url_encode(key.0.as_bytes()), &signing_input);
        format!("{signing_input}.{}", b64url_encode(&signature))
    }

    fn actions_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": OIDC_ISSUER,
            "aud": "https://stow.waterui.dev",
            "exp": NOW + 600,
            "nbf": NOW - 60,
            "repository": "water-rs/stow",
            "job_workflow_ref":
                "water-rs/stow/.github/workflows/preheat-admin.yml@refs/heads/main",
            "workflow_ref":
                "water-rs/stow/.github/workflows/preheat-admin.yml@refs/heads/main",
            "run_id": "12345",
            "run_attempt": "1",
            "ref": "refs/heads/main",
            "actor": "octo-dispatcher",
        })
    }

    /// The claims a run of `file` at `git_ref` carries — a direct run,
    /// so its run and job workflow refs agree.
    fn workflow_claims(file: &str, git_ref: &str) -> serde_json::Value {
        let mut claims = actions_claims();
        let workflow = format!("water-rs/stow/.github/workflows/{file}@{git_ref}");
        claims["job_workflow_ref"] = serde_json::json!(workflow);
        claims["workflow_ref"] = serde_json::json!(workflow);
        claims["ref"] = serde_json::json!(git_ref);
        claims
    }

    /// Authenticate `claims` as a minted OIDC token.
    async fn oidc_caller(claims: &serde_json::Value) -> TrustedCaller {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        authenticate(
            &test_config(),
            &api,
            &Jwks::default(),
            &PushVerdicts::default(),
            &mint_jwt(&key, claims),
            NOW,
        )
        .await
        .expect("actions caller")
    }

    const OPERATIONS: &[&str] = &[OPERATIONS_WORKFLOW];

    /// stow#955: a push credential — the `stow-admin login` user token
    /// included — authenticates for reads but never mutates.
    #[tokio::test]
    async fn mutation_refuses_a_user_token() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        *api.push_login.lock().expect("lock") = Some("octo-dispatcher".to_owned());
        let caller = authenticate(
            &test_config(),
            &api,
            &Jwks::default(),
            &PushVerdicts::default(),
            "ghu_user_token",
            NOW,
        )
        .await
        .expect("a user token with push access still authenticates for reads");
        assert!(matches!(
            authorize_mutation(&caller, OPERATIONS, "water-rs/stow"),
            Err(AuthError::Unauthorized)
        ));
    }

    /// The operations workflow on `main` passes, attributed to the
    /// login that dispatched it.
    #[tokio::test]
    async fn mutation_admits_operations_on_main_with_its_actor() {
        let caller = oidc_caller(&workflow_claims("operations.yml", MAIN_REF)).await;
        assert_eq!(
            authorize_mutation(&caller, OPERATIONS, "water-rs/stow").expect("admitted"),
            "octo-dispatcher"
        );
    }

    /// Another workflow of the same repository on `main` is refused by a
    /// route that does not name it, and admitted by one that does.
    #[tokio::test]
    async fn mutation_refuses_a_workflow_the_route_does_not_name() {
        let caller = oidc_caller(&workflow_claims("preheat-admin.yml", MAIN_REF)).await;
        assert!(matches!(
            authorize_mutation(&caller, OPERATIONS, "water-rs/stow"),
            Err(AuthError::Unauthorized)
        ));
        assert!(
            authorize_mutation(
                &caller,
                &["operations.yml", "preheat-admin.yml"],
                "water-rs/stow"
            )
            .is_ok()
        );
    }

    /// The operations workflow run from any ref but `main` — a branch
    /// carrying its own copy of the file, a tag, a pull request merge
    /// ref — is refused.
    #[tokio::test]
    async fn mutation_refuses_operations_from_another_ref() {
        for git_ref in [
            "refs/heads/feature",
            "refs/tags/v1.0.0",
            "refs/pull/1/merge",
        ] {
            let caller = oidc_caller(&workflow_claims("operations.yml", git_ref)).await;
            assert!(
                matches!(
                    authorize_mutation(&caller, OPERATIONS, "water-rs/stow"),
                    Err(AuthError::Unauthorized)
                ),
                "{git_ref} must not mutate"
            );
        }
    }

    /// Each pinned claim is checked: a `main` run whose job workflow is
    /// another ref's copy, an allowed file reached as a reusable workflow
    /// from another one (allowed or not), and a file whose name only
    /// starts with an allowed one are all refused.
    #[tokio::test]
    async fn mutation_pins_every_workflow_claim() {
        let mut job_elsewhere = workflow_claims("operations.yml", MAIN_REF);
        job_elsewhere["job_workflow_ref"] =
            serde_json::json!("water-rs/stow/.github/workflows/operations.yml@refs/heads/feature");
        let mut reused = workflow_claims("operations.yml", MAIN_REF);
        reused["workflow_ref"] =
            serde_json::json!("water-rs/stow/.github/workflows/test.yml@refs/heads/main");
        let lookalike = workflow_claims("operations.yml.bak", MAIN_REF);
        for claims in [job_elsewhere, reused, lookalike] {
            let caller = oidc_caller(&claims).await;
            assert!(
                matches!(
                    authorize_mutation(&caller, OPERATIONS, "water-rs/stow"),
                    Err(AuthError::Unauthorized)
                ),
                "{claims}"
            );
        }
        // Both files on the route's list, one reached as a reusable
        // workflow from the other: the two claims must name one file.
        let mut crossed = workflow_claims("preheat-admin.yml", MAIN_REF);
        crossed["workflow_ref"] =
            serde_json::json!("water-rs/stow/.github/workflows/operations.yml@refs/heads/main");
        let caller = oidc_caller(&crossed).await;
        assert!(matches!(
            authorize_mutation(
                &caller,
                &["operations.yml", "preheat-admin.yml"],
                "water-rs/stow"
            ),
            Err(AuthError::Unauthorized)
        ));
    }

    /// A re-run carries the original run's `actor`, not whoever started
    /// the re-run, so no re-run may mutate; recovery dispatches a fresh
    /// run.
    #[tokio::test]
    async fn mutation_refuses_a_rerun() {
        for workflow in ["operations.yml", "preheat-admin.yml"] {
            let mut rerun = workflow_claims(workflow, MAIN_REF);
            rerun["run_attempt"] = serde_json::json!("2");
            let caller = oidc_caller(&rerun).await;
            assert!(matches!(
                authorize_mutation(&caller, &[workflow], "water-rs/stow"),
                Err(AuthError::Unauthorized)
            ));
        }
    }

    /// An Actions token missing a claim the gate judges is refused at
    /// authentication — never defaulted to an empty actor or ref.
    #[tokio::test]
    async fn oidc_without_actor_or_ref_is_refused() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        for claim in ["actor", "ref", "workflow_ref", "run_attempt"] {
            let mut claims = workflow_claims("operations.yml", MAIN_REF);
            claims.as_object_mut().expect("claims object").remove(claim);
            assert_unauthorized(
                &authenticate(
                    &test_config(),
                    &api,
                    &Jwks::default(),
                    &PushVerdicts::default(),
                    &mint_jwt(&key, &claims),
                    NOW,
                )
                .await,
            );
        }
    }

    fn assert_unauthorized(result: &Result<TrustedCaller, AuthError>) {
        assert!(
            matches!(result, Err(AuthError::Unauthorized)),
            "expected Unauthorized, got {result:?}"
        );
    }

    #[tokio::test]
    async fn valid_actions_oidc_token_is_trusted() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        let token = mint_jwt(&key, &actions_claims());
        let caller = authenticate(
            &test_config(),
            &api,
            &Jwks::default(),
            &PushVerdicts::default(),
            &token,
            NOW,
        )
        .await
        .expect("actions token");
        let TrustedCaller::Actions {
            job_workflow_ref,
            run_id,
            ..
        } = caller
        else {
            panic!("expected Actions caller");
        };
        assert!(job_workflow_ref.contains("preheat-admin.yml"));
        assert_eq!(run_id, "12345");
    }

    #[tokio::test]
    async fn wrong_audience_is_rejected() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        let mut claims = actions_claims();
        claims["aud"] = serde_json::json!("https://elsewhere.example");
        assert_unauthorized(
            &authenticate(
                &test_config(),
                &api,
                &Jwks::default(),
                &PushVerdicts::default(),
                &mint_jwt(&key, &claims),
                NOW,
            )
            .await,
        );
    }

    #[tokio::test]
    async fn wrong_repo_is_rejected() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        let mut claims = actions_claims();
        claims["repository"] = serde_json::json!("someone/fork");
        claims["job_workflow_ref"] =
            serde_json::json!("someone/fork/.github/workflows/build-crate.yml@refs/heads/main");
        assert_unauthorized(
            &authenticate(
                &test_config(),
                &api,
                &Jwks::default(),
                &PushVerdicts::default(),
                &mint_jwt(&key, &claims),
                NOW,
            )
            .await,
        );
    }

    /// The same repo's other workflows submit tasks too — the trust pin
    /// is `owner/repo/.github/workflows/`, never a particular file.
    #[tokio::test]
    async fn other_repo_workflow_is_trusted() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        let mut claims = actions_claims();
        claims["job_workflow_ref"] =
            serde_json::json!("water-rs/stow/.github/workflows/ci.yml@refs/heads/main");
        let caller = authenticate(
            &test_config(),
            &api,
            &Jwks::default(),
            &PushVerdicts::default(),
            &mint_jwt(&key, &claims),
            NOW,
        )
        .await;
        assert!(matches!(caller, Ok(TrustedCaller::Actions { .. })));
    }

    /// A workflow on a branch other than `main` is still a repo workflow —
    /// the pin names the repository, not the ref.
    #[tokio::test]
    async fn repo_workflow_on_other_ref_is_trusted() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        let mut claims = actions_claims();
        claims["job_workflow_ref"] =
            serde_json::json!("water-rs/stow/.github/workflows/build-crate.yml@refs/heads/topic");
        assert!(
            authenticate(
                &test_config(),
                &api,
                &Jwks::default(),
                &PushVerdicts::default(),
                &mint_jwt(&key, &claims),
                NOW,
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn garbage_bearer_is_rejected_without_upstream_call() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        // Not a JWT and not a GitHub token shape — fails before the
        // permission check would fire (the stub has no login programmed).
        assert_unauthorized(
            &authenticate(
                &test_config(),
                &api,
                &Jwks::default(),
                &PushVerdicts::default(),
                "not-a-credential",
                NOW,
            )
            .await,
        );
        assert_eq!(api.fetch_count(), 0, "rejected before any JWKS fetch");
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        let mut claims = actions_claims();
        claims["exp"] = serde_json::json!(NOW - 3600);
        assert_unauthorized(
            &authenticate(
                &test_config(),
                &api,
                &Jwks::default(),
                &PushVerdicts::default(),
                &mint_jwt(&key, &claims),
                NOW,
            )
            .await,
        );
    }

    #[tokio::test]
    async fn forged_signature_is_rejected() {
        let key = test_key();
        let other = forger_key();
        let api = StubTrust::for_key(&key);
        // Signed by a different key than the JWKS advertises.
        let token = mint_jwt(&other, &actions_claims());
        assert_unauthorized(
            &authenticate(
                &test_config(),
                &api,
                &Jwks::default(),
                &PushVerdicts::default(),
                &token,
                NOW,
            )
            .await,
        );
    }

    #[tokio::test]
    async fn repo_push_user_submits_tasks() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        *api.push_login.lock().expect("lock") = Some("lexoliu".to_owned());
        let caller = authenticate(
            &test_config(),
            &api,
            &Jwks::default(),
            &PushVerdicts::default(),
            "ghp_example-token",
            NOW,
        )
        .await
        .expect("user token");
        assert!(matches!(caller, TrustedCaller::Push { ref label } if label == "lexoliu"));
    }

    #[tokio::test]
    async fn user_without_push_is_rejected() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        *api.push_login.lock().expect("lock") = None;
        assert_unauthorized(
            &authenticate(
                &test_config(),
                &api,
                &Jwks::default(),
                &PushVerdicts::default(),
                "ghp_example-token",
                NOW,
            )
            .await,
        );
    }

    #[test]
    fn cached_key_serves_until_expiry() {
        let jwks = Jwks::<String>::default();
        jwks.replace_all(
            JwkSet {
                keys: vec![jwk_for(&test_key(), "test-kid")],
            },
            1_000,
        );
        assert!(
            jwks.lookup("test-kid", 1_000 + JWKS_CACHE_TTL_SECS - 1)
                .is_some()
        );
        assert!(
            jwks.lookup("test-kid", 1_000 + JWKS_CACHE_TTL_SECS)
                .is_none()
        );
        assert!(jwks.lookup("unknown-kid", 1_000).is_none());
    }

    #[test]
    fn replace_all_drops_the_previous_set() {
        let jwks = Jwks::<String>::default();
        jwks.replace_all(
            JwkSet {
                keys: vec![jwk_for(&test_key(), "kid-a")],
            },
            0,
        );
        jwks.replace_all(
            JwkSet {
                keys: vec![jwk_for(&forger_key(), "kid-b")],
            },
            1,
        );
        assert!(jwks.lookup("kid-a", 2).is_none());
        assert!(jwks.lookup("kid-b", 2).is_some());
    }

    #[test]
    fn non_rsa_keys_are_not_cached() {
        let jwks = Jwks::<String>::default();
        let mut key = jwk_for(&test_key(), "okp-kid");
        key.kty = "OKP".to_owned();
        jwks.replace_all(JwkSet { keys: vec![key] }, 0);
        assert!(jwks.lookup("okp-kid", 1).is_none());
    }

    #[test]
    fn cloned_caches_share_state() {
        let jwks = Jwks::<String>::default();
        let clone = jwks.clone();
        jwks.replace_all(
            JwkSet {
                keys: vec![jwk_for(&test_key(), "test-kid")],
            },
            0,
        );
        assert!(clone.lookup("test-kid", 1).is_some());
    }

    #[tokio::test]
    async fn cached_keyset_serves_repeat_verifications() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        let jwks = Jwks::<String>::default();
        let token = mint_jwt(&key, &actions_claims());
        for _ in 0..3 {
            authenticate(
                &test_config(),
                &api,
                &jwks,
                &PushVerdicts::default(),
                &token,
                NOW,
            )
            .await
            .expect("actions token");
        }
        assert_eq!(api.fetch_count(), 1, "one fetch fills the cache");
    }

    /// The imported key is kept beside the JWKS entry: a known `kid`
    /// imports once, however many requests use it.
    #[tokio::test]
    async fn known_kid_imports_once() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        let jwks = Jwks::default();
        let token = mint_jwt(&key, &actions_claims());
        for _ in 0..3 {
            authenticate(
                &test_config(),
                &api,
                &jwks,
                &PushVerdicts::default(),
                &token,
                NOW,
            )
            .await
            .expect("actions token");
        }
        assert_eq!(api.import_count(), 1);
    }

    /// The import leaves with the entry: past the TTL the refetched set
    /// is imported again.
    #[tokio::test]
    async fn expired_entry_imports_again() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        let jwks = Jwks::default();
        let mut claims = actions_claims();
        claims["exp"] = serde_json::json!(NOW + JWKS_CACHE_TTL_SECS + 600);
        let token = mint_jwt(&key, &claims);
        for now in [NOW, NOW + JWKS_CACHE_TTL_SECS + 1] {
            authenticate(
                &test_config(),
                &api,
                &jwks,
                &PushVerdicts::default(),
                &token,
                now,
            )
            .await
            .expect("actions token");
        }
        assert_eq!(api.import_count(), 2);
    }

    /// A claim failure is refused before any key lookup, fetch or import.
    #[tokio::test]
    async fn bad_claims_cost_no_key_work() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        let mut claims = actions_claims();
        claims["repository"] = serde_json::json!("someone/else");
        assert_unauthorized(
            &authenticate(
                &test_config(),
                &api,
                &Jwks::default(),
                &PushVerdicts::default(),
                &mint_jwt(&key, &claims),
                NOW,
            )
            .await,
        );
        assert_eq!((api.fetch_count(), api.import_count()), (0, 0));
    }

    #[tokio::test]
    async fn unknown_kid_fetches_once_and_rejects() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        let jwks = Jwks::default();
        // Signed by the real key but naming a `kid` the JWKS does not
        // advertise — the fresh fetch already happened, so this is a bad
        // credential rather than another fetch.
        let token = mint_jwt_with_kid(&key, &actions_claims(), "unlisted-kid");
        assert_unauthorized(
            &authenticate(
                &test_config(),
                &api,
                &jwks,
                &PushVerdicts::default(),
                &token,
                NOW,
            )
            .await,
        );
        assert_eq!(api.fetch_count(), 1);
    }

    #[tokio::test]
    async fn expired_cache_entry_refetches() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        let jwks = Jwks::default();
        let mut claims = actions_claims();
        claims["exp"] = serde_json::json!(NOW + JWKS_CACHE_TTL_SECS + 600);
        let token = mint_jwt(&key, &claims);
        authenticate(
            &test_config(),
            &api,
            &jwks,
            &PushVerdicts::default(),
            &token,
            NOW,
        )
        .await
        .expect("actions token");
        // Past the TTL the cached key no longer serves — the next call
        // fetches the set again before verifying.
        authenticate(
            &test_config(),
            &api,
            &jwks,
            &PushVerdicts::default(),
            &token,
            NOW + JWKS_CACHE_TTL_SECS + 1,
        )
        .await
        .expect("actions token");
        assert_eq!(api.fetch_count(), 2);
    }

    #[tokio::test]
    async fn cached_push_verdict_serves_the_next_request() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        *api.push_login.lock().expect("lock") = Some("lexoliu".to_owned());
        let verdicts = PushVerdicts::default();
        for _ in 0..3 {
            let caller = authenticate(
                &test_config(),
                &api,
                &Jwks::default(),
                &verdicts,
                "ghp_example-token",
                NOW,
            )
            .await
            .expect("user token");
            assert!(matches!(caller, TrustedCaller::Push { ref label } if label == "lexoliu"));
        }
        // One probe filled the cache; the hits carried the `/user` label
        // with the verdict, so GitHub saw zero further calls.
        assert_eq!(api.push_call_count(), 1);
    }

    #[tokio::test]
    async fn different_tokens_do_not_share_a_verdict() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        *api.push_login.lock().expect("lock") = Some("lexoliu".to_owned());
        let verdicts = PushVerdicts::default();
        for token in ["ghp_first-token", "gho_second-token", "ghs_third-token"] {
            authenticate(
                &test_config(),
                &api,
                &Jwks::default(),
                &verdicts,
                token,
                NOW,
            )
            .await
            .expect("user token");
        }
        assert_eq!(api.push_call_count(), 3, "verdicts key on the token digest");
    }

    #[tokio::test]
    async fn denied_verdict_expires_before_a_proven_one() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        let verdicts = PushVerdicts::default();
        assert_unauthorized(
            &authenticate(
                &test_config(),
                &api,
                &Jwks::default(),
                &verdicts,
                "ghp_example-token",
                NOW,
            )
            .await,
        );
        // The denial is cached — a repeat inside its TTL re-probes
        // nothing — but only for PUSH_DENIED_TTL_SECS: a credential that
        // just gained push is not locked out for the full positive TTL.
        assert_unauthorized(
            &authenticate(
                &test_config(),
                &api,
                &Jwks::default(),
                &verdicts,
                "ghp_example-token",
                NOW + PUSH_DENIED_TTL_SECS - 1,
            )
            .await,
        );
        assert_eq!(api.push_call_count(), 1);
        assert_unauthorized(
            &authenticate(
                &test_config(),
                &api,
                &Jwks::default(),
                &verdicts,
                "ghp_example-token",
                NOW + PUSH_DENIED_TTL_SECS,
            )
            .await,
        );
        assert_eq!(api.push_call_count(), 2);
        // A proven verdict, by contrast, still serves well past it.
        *api.push_login.lock().expect("lock") = Some("lexoliu".to_owned());
        authenticate(
            &test_config(),
            &api,
            &Jwks::default(),
            &verdicts,
            "ghp_other-token",
            NOW,
        )
        .await
        .expect("user token");
        authenticate(
            &test_config(),
            &api,
            &Jwks::default(),
            &verdicts,
            "ghp_other-token",
            NOW + PUSH_VERDICT_TTL_SECS - 1,
        )
        .await
        .expect("user token");
        assert_eq!(api.push_call_count(), 3);
    }

    #[tokio::test]
    async fn rate_limited_probe_surfaces_retry_after_and_is_not_cached() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        *api.push_failure.lock().expect("lock") = Some(StubPushFailure::RateLimited {
            retry_after_secs: 120,
        });
        let verdicts = PushVerdicts::default();
        let Err(AuthError::RateLimited { retry_after_secs }) = authenticate(
            &test_config(),
            &api,
            &Jwks::default(),
            &verdicts,
            "ghp_example-token",
            NOW,
        )
        .await
        else {
            panic!("expected RateLimited, got a verdict");
        };
        assert_eq!(retry_after_secs, 120);
        // An upstream failure is never recorded as a verdict — the next
        // request probes GitHub again rather than inheriting the outage.
        *api.push_failure.lock().expect("lock") = None;
        *api.push_login.lock().expect("lock") = Some("lexoliu".to_owned());
        let caller = authenticate(
            &test_config(),
            &api,
            &Jwks::default(),
            &verdicts,
            "ghp_example-token",
            NOW,
        )
        .await
        .expect("user token");
        assert!(matches!(caller, TrustedCaller::Push { ref label } if label == "lexoliu"));
        assert_eq!(api.push_call_count(), 2);
    }

    #[tokio::test]
    async fn rate_limit_gate_answers_503_with_retry_after() {
        #[derive(Debug, thiserror::Error)]
        #[error("github trust upstream rate limited")]
        struct StubRateLimited;
        impl skyzen::HttpError for StubRateLimited {
            fn status(&self) -> skyzen::StatusCode {
                skyzen::StatusCode::SERVICE_UNAVAILABLE
            }
        }
        let endpoint = skyzen::handler::into_endpoint(|| async {
            Err::<skyzen::Response, _>(StubRateLimited)
        });
        // The marker the trust-check extractor stashes: the gate turns
        // the endpoint's failure into a 503 carrying GitHub's
        // `Retry-After`, which the shared error envelope cannot attach.
        let mut request = skyzen::Request::new(skyzen::Body::from(Vec::<u8>::new()));
        request.extensions_mut().insert(TrustRateLimited {
            retry_after_secs: 42,
        });
        let mut response = skyzen::middleware::apply(&TrustRateLimitGate, &mut request, endpoint)
            .await
            .expect("the gate renders a response");
        assert_eq!(response.status(), skyzen::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get(skyzen::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("42")
        );
        assert_eq!(
            response.body_mut().as_str().await.expect("utf8 body"),
            r#"{"error":"github trust upstream rate limited; retry later"}"#
        );
    }

    #[tokio::test]
    async fn rate_limit_gate_passes_everything_else_through() {
        let endpoint = skyzen::handler::into_endpoint(|| async {
            Ok::<_, skyzen::Error>(skyzen::Response::new(skyzen::Body::from(Vec::<u8>::new())))
        });
        // No marker, no failure: the request reaches the endpoint.
        let mut request = skyzen::Request::new(skyzen::Body::from(Vec::<u8>::new()));
        let response = skyzen::middleware::apply(&TrustRateLimitGate, &mut request, endpoint)
            .await
            .expect("endpoint response");
        assert_eq!(response.status(), skyzen::StatusCode::OK);
    }

    #[test]
    fn token_digest_is_not_the_token() {
        // The cache key proves the credential cannot be lifted out of
        // isolate memory — a digest authenticates nothing.
        let digest = token_digest("ghp_secret-token");
        assert_ne!(digest, "ghp_secret-token");
        assert_eq!(digest.len(), 64);
    }

    /// The push probe needs only the status — its ref-advertisement body
    /// must be cancelled on every branch, never left open in a slot.
    #[tokio::test]
    async fn probe_cancel_branch_cancels_the_body() {
        use crate::fetch_guard::GuardedResponse;
        use crate::fetch_guard::stub::StubResponse;

        for status in [401, 403, 404] {
            let (response, cancelled, consumed) = StubResponse::new(status);
            let verdict = read_probe_response(GuardedResponse::new(response), "https://x", 0);
            assert!(!verdict.expect("denial is an answer"));
            assert!(
                cancelled.load(std::sync::atomic::Ordering::SeqCst),
                "{status} must cancel the unread body"
            );
            assert!(!consumed.load(std::sync::atomic::Ordering::SeqCst));
        }
    }

    /// A rate-limited probe surfaces the delay and still frees the slot.
    #[tokio::test]
    async fn probe_rate_limited_cancels_the_body() {
        use crate::fetch_guard::GuardedResponse;
        use crate::fetch_guard::stub::StubResponse;

        let (response, cancelled, _) = StubResponse::new(429);
        let response = response.with_header("retry-after", "7");
        let error = read_probe_response(GuardedResponse::new(response), "https://x", 0)
            .expect_err("rate limit is an error");
        assert!(matches!(
            error,
            AuthError::RateLimited {
                retry_after_secs: 7
            }
        ));
        assert!(
            cancelled.load(std::sync::atomic::Ordering::SeqCst),
            "rate-limited replies must cancel the body"
        );
    }

    /// The JSON probe's denial arm never reads the body — the guard
    /// cancels it — while a 2xx body reaches the caller consumed.
    #[tokio::test]
    async fn json_probe_cancels_denials_and_reads_2xx() {
        use crate::fetch_guard::GuardedResponse;
        use crate::fetch_guard::stub::StubResponse;

        let (response, cancelled, consumed) = StubResponse::new(403);
        let verdict = read_json_response(GuardedResponse::new(response), "https://x", 0).await;
        assert!(verdict.expect("403 is a denial").is_none());
        assert!(
            cancelled.load(std::sync::atomic::Ordering::SeqCst),
            "denial must cancel the unread body"
        );
        assert!(!consumed.load(std::sync::atomic::Ordering::SeqCst));

        let (mut response, cancelled, consumed) = StubResponse::new(200);
        response.body = "{\"login\":\"octo\"}".to_owned();
        let verdict = read_json_response(GuardedResponse::new(response), "https://x", 0).await;
        assert_eq!(
            verdict.expect("2xx reads"),
            Some("{\"login\":\"octo\"}".to_owned())
        );
        assert!(
            consumed.load(std::sync::atomic::Ordering::SeqCst),
            "2xx must read the body"
        );
        assert!(!cancelled.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// With no mock origin pinned, every probe addresses GitHub's
    /// production hosts — the bearer check's real surface.
    #[test]
    fn probe_urls_default_to_github_hosts() {
        assert_eq!(user_url(None), "https://api.github.com/user");
        assert_eq!(
            push_probe_url(None, "water-rs/stow"),
            "https://github.com/water-rs/stow.git/info/refs?service=git-receive-pack"
        );
        assert_eq!(
            jwks_url(None),
            "https://token.actions.githubusercontent.com/.well-known/jwks"
        );
    }

    /// A pinned mock origin replaces all three hosts — the mock stack's
    /// trusted lanes never address a real GitHub endpoint (stow#793),
    /// and a trailing slash on the binding cannot split the path.
    #[test]
    fn probe_urls_follow_the_mock_base() {
        let base = Some("http://127.0.0.1:28123/");
        assert_eq!(user_url(base), "http://127.0.0.1:28123/user");
        assert_eq!(
            push_probe_url(base, "water-rs/stow"),
            "http://127.0.0.1:28123/water-rs/stow.git/info/refs?service=git-receive-pack"
        );
        assert_eq!(jwks_url(base), "http://127.0.0.1:28123/.well-known/jwks");
    }
}
