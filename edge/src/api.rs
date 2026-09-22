use std::collections::{BTreeMap, BTreeSet};

use skyzen::extract::{Extractor, Query};
use skyzen::header::HeaderValue;
use skyzen::routing::Params;
use skyzen::runtime::WorkerContext;
use skyzen::runtime::wasm::from_js_response;
use skyzen::utils::{Json, State};
use skyzen::{Body, Request, Response, StatusCode};
use skyzen_cloudflare::worker::send::IntoSendFuture as _;
use skyzen_cloudflare::worker::{self, AnalyticsEngineDataset};
use skyzen_cloudflare::{CfCache, CfDurableNamespace};
use skyzen_services::Db;
use stow_types::api::{
    AdmissionRequest, ArtifactIndexPage, ArtifactRecord, BuildCompleteReport, CI_TARGET_TRIPLES,
    CrateRequest, CrateRequestOutcome, EnqueueAdmission, EnqueueTicket, QueueTaskStatus,
    RegisterArtifactsRequest,
};
use stow_types::bundle::STOW_BUNDLE_MEDIA_TYPE;
use stow_types::identity::{CMetadata, CrateName, CrateVersion, TargetTriple, WireRustcVersion};

use crate::db;
use crate::github_auth;
use crate::lookup_key::{bundle_cache_key, exact_lookup_key, row_matches_digest};
use crate::miss_logger::{Miss, MissLog};
use crate::registry_auth::RegistryTokens;
use crate::turnstile::{CfTurnstileVerifier, TurnstileVerifier};
use crate::{
    admission, cache, catalog, crates_io, dependency_resolver, ghcr, miss_logger, register,
    scheduler, scheduler_client, stats,
};

/// Header value for `x-stow-cache: hit|miss`.
const fn cache_status_header(cache_hit: bool) -> HeaderValue {
    if cache_hit {
        HeaderValue::from_static("hit")
    } else {
        HeaderValue::from_static("miss")
    }
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct OkResponse {
    ok: bool,
}

/// Marker that the request's `Authorization: Bearer` credential cleared the
/// GitHub trust check under [`github_auth::Policy::RepoWriter`]: a GitHub
/// Actions OIDC token minted inside the trusted repo, or any credential
/// with push access to it (`stow-admin`, local dev, CI `GITHUB_TOKEN`).
///
/// Verifying inside the extractor — rather than in the handler body —
/// rejects unauthorized requests *before* `Json` deserializes a
/// potentially large body.
#[derive(Debug, Clone)]
pub struct SchedulerCaller(pub github_auth::TrustedCaller);

impl Extractor for SchedulerCaller {
    type Error = GetArtifactError;

    async fn extract(request: &mut Request) -> Result<Self, Self::Error> {
        extract_trusted_caller(request, github_auth::Policy::RepoWriter)
            .await
            .map(Self)
    }
}

/// Everything a bundle-serving handler needs to stream bytes: the Cache
/// API, the registry coordinates, and the worker context that keeps the
/// cache tee alive after the response is returned.
#[derive(Debug, Clone)]
pub struct BundleStreams {
    pub context: WorkerContext,
    pub cache: CfCache,
    pub ghcr: GhcrConfig,
}

impl Extractor for BundleStreams {
    type Error = GetArtifactError;

    async fn extract(request: &mut Request) -> Result<Self, Self::Error> {
        let context = WorkerContext::extract(request)
            .await
            .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
        let State(cache) = State::<CfCache>::extract(request)
            .await
            .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
        let State(ghcr) = State::<GhcrConfig>::extract(request)
            .await
            .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
        Ok(Self {
            context,
            cache,
            ghcr,
        })
    }
}

/// Marker that the caller cleared [`github_auth::Policy::BuildWorkflow`] —
/// the OIDC pin that lets only `build-crate.yml` runs (or a repo-push user
/// driving the same endpoint in local dev) write `artifacts` rows.
#[derive(Debug, Clone)]
pub struct ArtifactWriteCaller(pub github_auth::TrustedCaller);

impl Extractor for ArtifactWriteCaller {
    type Error = GetArtifactError;

    async fn extract(request: &mut Request) -> Result<Self, Self::Error> {
        extract_trusted_caller(request, github_auth::Policy::BuildWorkflow)
            .await
            .map(Self)
    }
}

/// Pull the bearer credential off `Authorization` and authenticate it
/// against GitHub under `policy`. Upstream failures (JWKS, repo-permission
/// API) surface as `TrustUpstreamUnavailable` — a 502 the CI retries —
/// rather than a 401 that would look like a credential problem.
async fn extract_trusted_caller(
    request: &mut Request,
    policy: github_auth::Policy,
) -> Result<github_auth::TrustedCaller, GetArtifactError> {
    let bearer = request
        .headers()
        .get(skyzen::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(GetArtifactError::Unauthorized)?
        .to_owned();
    let config = State::<github_auth::GitHubTrustConfig>::extract(request)
        .await
        .map_err(|_| {
            GetArtifactError::InternalWithMessage("github trust config binding missing".to_owned())
        })?;
    let jwks = State::<github_auth::Jwks>::extract(request)
        .await
        .map_err(|_| {
            GetArtifactError::InternalWithMessage("jwks cache state missing".to_owned())
        })?;
    github_auth::authenticate(
        &config,
        &github_auth::CfGitHubTrust,
        &jwks,
        &bearer,
        policy,
        now_unix(),
    )
    .await
    .map_err(|error| match error {
        github_auth::AuthError::Unauthorized => GetArtifactError::Unauthorized,
        github_auth::AuthError::Upstream(reason) => {
            tracing::warn!(%reason, "github trust upstream check failed");
            GetArtifactError::TrustUpstreamUnavailable
        }
    })
}

/// Wall-clock seconds for OIDC `exp`/`nbf` checks — `js_sys::Date` is the
/// only clock available in the wasm worker.
fn now_unix() -> i64 {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "js_sys::Date::now() returns positive epoch milliseconds; whole seconds are the intended unit"
    )]
    let seconds = (js_sys::Date::now() / 1_000.0) as i64;
    seconds
}

/// The caller's `CF-Connecting-IP`, forwarded to Turnstile siteverify as
/// `remoteip`. `None` when the request did not come in through Cloudflare's
/// edge (local dev), which siteverify accepts.
#[derive(Debug, Clone)]
pub struct CfConnectingIp(pub Option<String>);

impl Extractor for CfConnectingIp {
    type Error = GetArtifactError;

    fn extract(
        request: &mut Request,
    ) -> impl std::future::Future<Output = Result<Self, Self::Error>> + Send {
        let remoteip = request
            .headers()
            .get("cf-connecting-ip")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        std::future::ready(Ok(Self(remoteip)))
    }
}

/// Enqueue-admission parameters carried via `State<PowAdmission>`: the HMAC
/// secret minting miss challenges (`STOW_POW_CHALLENGE_SECRET`), the
/// proof-of-work bits every admission carries (`STOW_POW_MIN_BITS`), and
/// the pending-queue depth at which `/api/v1/enqueue` stops accepting
/// tickets (`STOW_MAX_QUEUE_PENDING`).
#[derive(Debug, Clone)]
pub struct PowAdmission {
    pub challenge_secret: String,
    /// Leading-zero bits minted into every admission and required of
    /// every ticket — an enqueue is never free.
    pub min_bits: u32,
    /// Pending-queue depth that refuses miss-lane tickets with 429. This,
    /// not the proof-of-work, is what says "the queue is under pressure".
    pub max_queue_pending: u32,
}

/// `Retry-After` for a queue-depth refusal: ten minutes of drain time.
/// The scheduler dispatches at CI speed, so a short fixed hold-off is
/// more honest than a computed estimate of queue-clearing time.
const QUEUE_FULL_RETRY_AFTER_SECS: u64 = 600;

/// Unwrap the scheduler's `{"error": "..."}` JSON envelope so a refusal's
/// message reaches the client once, not nested inside a second object;
/// an unexpected body passes through verbatim.
fn scheduler_error_message(body: &str) -> &str {
    #[derive(serde::Deserialize)]
    struct ErrorBody<'a> {
        error: &'a str,
    }
    serde_json::from_str::<ErrorBody<'_>>(body).map_or(body, |parsed| parsed.error)
}

/// `429 Too Many Requests` with a `Retry-After` header — the shared
/// `{"error": ...}` renderer cannot attach headers, so the rate-limited
/// handlers build the response directly, mirroring
/// [`crate::turnstile::rejected_response`].
fn rate_limited_response(
    message: &str,
    retry_after_secs: u64,
) -> Result<Response, GetArtifactError> {
    #[derive(serde::Serialize)]
    struct RateLimitedBody<'a> {
        error: &'a str,
    }
    let mut response = Response::new(
        Body::from_json(&RateLimitedBody { error: message })
            .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?,
    );
    *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    response.headers_mut().insert(
        skyzen::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        skyzen::header::RETRY_AFTER,
        HeaderValue::from(retry_after_secs),
    );
    Ok(response)
}

/// Wall-clock minute the admission protocol stamps challenges with —
/// `js_sys::Date` is the only clock available in the wasm worker.
fn now_minute() -> u64 {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "js_sys::Date::now() returns positive epoch milliseconds; truncating to whole minutes is the intended bucket"
    )]
    let minute = (js_sys::Date::now() / 60_000.0) as u64;
    minute
}

/// Mint stateless admissions for `requests`: each carries its canonical
/// request plus a challenge HMAC-binding `(task_id, request)` to this
/// minute, and the queue-depth-derived `difficulty`. Nothing is persisted —
/// `/api/v1/enqueue` recomputes the challenge over the request the client
/// echoes back.
fn mint_admissions(
    admission: &PowAdmission,
    requests: Vec<stow_types::api::EnqueueRequest>,
    difficulty: u32,
) -> Result<Vec<EnqueueAdmission>, GetArtifactError> {
    let minute = now_minute();
    let mut admissions = Vec::with_capacity(requests.len());
    for request in requests {
        let task_id = scheduler::queue::task_id(
            request.crate_name.as_str(),
            &request.version.to_string(),
            request.features_json.raw().as_str(),
            request.target.as_str(),
            request.rustc_version.as_str(),
        );
        let request_json = serde_json::to_vec(&request)
            .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
        let challenge = admission::issue_challenge(
            &admission.challenge_secret,
            &task_id,
            &request_json,
            minute,
        );
        admissions.push(EnqueueAdmission {
            task_id,
            challenge,
            difficulty,
            request,
        });
    }
    Ok(admissions)
}

/// POST /api/v1/admin/artifacts/register
///
/// Trusted CI registers freshly-built artifacts here. CI does NOT write to
/// D1 directly; `ArtifactWriteCaller` pins the OIDC path to
/// `build-crate.yml` runs (a push-user GitHub token also passes, which is
/// what the local dev loop and `backfill-bundles` use) and the edge owns
/// the D1 binding.
///
/// The request's `task_id` binds the write to one dispatched scheduler
/// task: the Actions identity must name it, every record must carry the
/// task's target and rustc version, and each `(crate, version)` must be
/// the task crate or inside its crates.io dependency closure — checked in
/// full before the first row is written, so a rejected request leaves no
/// rows behind. A push caller may omit `task_id` (backfill/operator
/// writes run outside a dispatched task); when present the same binding
/// applies. Upsert semantics keep registration idempotent across CI
/// retries while preserving each row's original `created_at`.
pub async fn register_artifacts(
    ArtifactWriteCaller(caller): ArtifactWriteCaller,
    Json(request): Json<RegisterArtifactsRequest>,
    db: Db,
    State(cache): State<CfCache>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<OkResponse>, GetArtifactError> {
    let binding = resolve_register_binding(&scheduler, &db, request.task_id.as_deref()).await?;
    if let Some(violation) = register::first_violation(&caller, &binding, &request.records) {
        let message = violation.to_string();
        tracing::warn!(
            %caller,
            task_id = ?request.task_id,
            %violation,
            "artifact registration rejected by task binding"
        );
        return Err(match violation.kind() {
            register::ViolationKind::BadRequest => GetArtifactError::BadRequestWithMessage(message),
            register::ViolationKind::Conflict => GetArtifactError::RegisterConflict(message),
            register::ViolationKind::Forbidden => GetArtifactError::RegisterForbidden(message),
        });
    }
    // An OIDC caller's run id is the build run acting on this task — stamp
    // it so `stow-admin status` can surface the run URL. A failed stamp is
    // logged, not fatal: it is observability metadata, and a scheduler
    // hiccup must not lose the registration itself.
    if let (github_auth::TrustedCaller::Actions { run_id, .. }, Some(task_id)) =
        (&caller, request.task_id.as_deref())
        && let Err(error) = scheduler_client::observe_run(&scheduler, task_id, run_id).await
    {
        tracing::warn!(%error, %task_id, %run_id, "failed to stamp run id on queue row");
    }
    let count = request.records.len();
    for record in &request.records {
        db::insert_artifact_record(&db, record).await?;
        invalidate_lookup_entries(&cache, record).await;
    }
    tracing::info!(
        registered = count,
        %caller,
        task_id = ?request.task_id,
        "registered artifact records via admin endpoint"
    );
    Ok(Json(OkResponse { ok: true }))
}

/// Resolve a register request's `task_id` against the scheduler queue and,
/// for tasks whose closure is reproducible from crates.io, expand the
/// task's dependency closure — the record set the dispatched run is
/// allowed to write.
///
/// A task that resolves a lockfile the edge cannot see (a
/// `preserve_lockfile` overlay) gets
/// `closure: None`: a fresh crates.io expansion would resolve different
/// versions than the pinned lockfile and reject legitimate records, so
/// the binding narrows to the task's target/rustc identity.
async fn resolve_register_binding(
    scheduler: &CfDurableNamespace,
    db: &Db,
    task_id: Option<&str>,
) -> Result<register::TaskBinding, GetArtifactError> {
    let Some(task_id) = task_id else {
        return Ok(register::TaskBinding::Unbound);
    };
    let statuses = scheduler_client::get_tasks_status(scheduler, &[task_id.to_owned()]).await?;
    let Some(task) = statuses
        .into_iter()
        .find(|status| status.task_id == task_id)
    else {
        return Ok(register::TaskBinding::Unknown(task_id.to_owned()));
    };
    let closure = if !matches!(
        task.status,
        QueueTaskStatus::Dispatched | QueueTaskStatus::Running
    ) {
        // `first_violation` rejects the request before consulting the
        // closure — skip the crates.io expansion a refused request would
        // never use.
        None
    } else if task.preserve_lockfile {
        tracing::info!(
            task_id = %task.task_id,
            "register bound to a lockfile-pinned task; crates.io closure check skipped"
        );
        None
    } else {
        Some(
            dependency_resolver::expand_task_closure(
                db,
                &crates_io::CfCratesIo,
                &task.crate_name,
                task.version.as_semver(),
                &task.features_json.features().iter().cloned().collect(),
                &task.target,
            )
            .await?,
        )
    };
    Ok(register::TaskBinding::Bound(register::TaskScope {
        task_id: task.task_id,
        status: task.status,
        crate_name: task.crate_name,
        version: task.version,
        target: task.target,
        rustc_version: task.rustc_version,
        closure,
    }))
}

/// Query for `GET /api/v1/admin/artifacts/unbundled`.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct UnbundledQuery {
    /// Most rows to return; defaults to [`DEFAULT_UNBUNDLED_LIMIT`].
    pub limit: Option<usize>,
}

/// Rows one backfill pass takes: each costs the caller a manifest, a config,
/// the layers and the signature image from GHCR plus one bundle push.
const DEFAULT_UNBUNDLED_LIMIT: usize = 200;
const MAX_UNBUNDLED_LIMIT: usize = 1000;

/// GET /api/v1/admin/artifacts/unbundled?limit=N
///
/// The records of rows registered before bundle publishing, for
/// `stow-build backfill-bundles`: it pushes each row's `<tag>.bundle` and
/// re-registers the record with the bundle coordinates, which takes the
/// row out of this listing.
pub async fn list_unbundled_artifacts(
    ArtifactWriteCaller(caller): ArtifactWriteCaller,
    Query(query): Query<UnbundledQuery>,
    db: Db,
) -> Result<Json<Vec<ArtifactRecord>>, GetArtifactError> {
    let limit = query.limit.unwrap_or(DEFAULT_UNBUNDLED_LIMIT);
    if limit == 0 || limit > MAX_UNBUNDLED_LIMIT {
        return Err(GetArtifactError::BadRequestWithMessage(format!(
            "limit must be 1..={MAX_UNBUNDLED_LIMIT}"
        )));
    }
    let records = db::unbundled_artifact_records(&db, limit).await?;
    tracing::info!(rows = records.len(), %caller, "listed unbundled artifact rows");
    Ok(Json(records))
}

/// GET /api/v1/admin/panic
///
/// The anonymous-traffic circuit breaker's current state, read straight
/// from the scheduler Durable Object — an operator asking for the flag
/// wants the truth, not the edge's cached copy.
pub async fn get_panic_switch(
    SchedulerCaller(_caller): SchedulerCaller,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::PanicSwitch>, GetArtifactError> {
    Ok(Json(scheduler_client::get_panic(&scheduler).await?))
}

/// POST /api/v1/admin/panic
///
/// Flip the circuit breaker: while `enabled` holds, every anonymous route
/// sheds requests with `503` + `Retry-After`. After the write this colo's
/// cached flag entry is deleted so the change takes effect here on the
/// next request; every other colo follows within the entry's TTL.
pub async fn set_panic_switch(
    SchedulerCaller(caller): SchedulerCaller,
    Json(switch): Json<stow_types::api::PanicSwitch>,
    State(scheduler): State<CfDurableNamespace>,
    State(cache): State<CfCache>,
) -> Result<Json<stow_types::api::PanicSwitch>, GetArtifactError> {
    let stored = scheduler_client::set_panic(&scheduler, switch.enabled).await?;
    if let Err(error) = cache::delete_panic_flag(&cache).await {
        tracing::warn!(%error, "failed to delete panic flag cache entry");
    }
    tracing::warn!(enabled = stored.enabled, %caller, "panic switch flipped via admin endpoint");
    Ok(Json(stored))
}

/// Query for `GET /api/v1/admin/index/{target}/{rustc_version}`.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct IndexQuery {
    /// Keyset cursor — the page starts at the first row whose
    /// `c_metadata` is greater than this value.
    pub after: Option<String>,
    /// Most rows to return; defaults to [`DEFAULT_INDEX_LIMIT`].
    pub limit: Option<usize>,
}

/// Rows one index page serves. The page walks a whole slice ordered by
/// `c_metadata`; `limit` is the keyset window, not an arbitrary cap —
/// [`MAX_INDEX_LIMIT`] keeps a response small enough for one worker
/// invocation.
const DEFAULT_INDEX_LIMIT: usize = 500;
const MAX_INDEX_LIMIT: usize = 1000;

/// GET /`api/v1/admin/index/{target}/{rustc_version}?after=c_metadata&limit=N`
///
/// One keyset page of the slice's servable artifact rows — what
/// `stow-admin index export` pages through to assemble the published
/// [`stow_types::index::ArtifactIndex`]. `SchedulerCaller` (RepoWriter):
/// the index-publish workflow mints its token inside the trusted repo.
pub async fn list_artifact_index(
    SchedulerCaller(caller): SchedulerCaller,
    params: Params,
    Query(query): Query<IndexQuery>,
    db: Db,
) -> Result<Json<ArtifactIndexPage>, GetArtifactError> {
    let target = params
        .get("target")
        .map_err(|_| GetArtifactError::BadRequest)?
        .parse::<TargetTriple>()
        .map_err(|error| GetArtifactError::BadRequestWithMessage(error.to_string()))?;
    let rustc_version = params
        .get("rustc_version")
        .map_err(|_| GetArtifactError::BadRequest)?
        .parse::<WireRustcVersion>()
        .map_err(|error| GetArtifactError::BadRequestWithMessage(error.to_string()))?;
    let (after, limit) = (query.after, query.limit.unwrap_or(DEFAULT_INDEX_LIMIT));
    if limit == 0 || limit > MAX_INDEX_LIMIT {
        return Err(GetArtifactError::BadRequestWithMessage(format!(
            "limit must be 1..={MAX_INDEX_LIMIT}"
        )));
    }
    let after = after
        .map(|cursor| {
            CMetadata::parse(cursor)
                .map_err(|error| GetArtifactError::BadRequestWithMessage(error.to_string()))
        })
        .transpose()?;
    let rows = db::artifact_index_page(
        &db,
        target.as_str(),
        rustc_version.as_str(),
        after.as_ref().map(CMetadata::as_str),
        limit,
    )
    .await?;
    // A full page may continue; anything shorter means the slice is
    // exhausted. `next_after` is the last row's key — the next page
    // resumes strictly after it.
    let next_after = if rows.len() == limit {
        rows.last().map(|row| row.c_metadata.as_str().to_owned())
    } else {
        None
    };
    tracing::info!(
        rows = rows.len(),
        %caller,
        %target,
        %rustc_version,
        "served an artifact index page"
    );
    Ok(Json(ArtifactIndexPage { rows, next_after }))
}

// ===== Operations API (`stow-admin`, `/api/v1/admin/*`) =====

/// GET /api/v1/admin/status
///
/// The scheduler's operator view: lane depths, the oldest pending row's
/// age, in-flight builds with their GitHub run ids, per-target outcomes
/// over the trailing 24 hours, and the panic flag.
pub async fn admin_status(
    SchedulerCaller(_caller): SchedulerCaller,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::AdminStatus>, GetArtifactError> {
    Ok(Json(scheduler_client::admin_status(&scheduler).await?))
}

/// `GET /api/v1/admin/queue?task_ids=…&status=&target=&crate=&older_than=&limit=`
///
/// Queue rows matching the selector, newest transition first — the
/// `stow-admin queue list` read and the mutation preview the CLI renders
/// before `--yes`.
pub async fn admin_queue_list(
    SchedulerCaller(_caller): SchedulerCaller,
    State(scheduler): State<CfDurableNamespace>,
    Query(selector): Query<stow_types::api::QueueSelector>,
) -> Result<Json<Vec<stow_types::api::QueueTask>>, GetArtifactError> {
    Ok(Json(
        scheduler_client::list_tasks(&scheduler, &selector).await?,
    ))
}

/// Shared forwarder for the four queue mutations: `verb` is a fixed
/// literal per call site, so no caller-controlled text reaches the
/// scheduler URL.
async fn queue_mutation(
    scheduler: &CfDurableNamespace,
    verb: &'static str,
    selector: &stow_types::api::QueueSelector,
) -> Result<stow_types::api::QueueMutationResult, GetArtifactError> {
    scheduler_client::queue_mutation(scheduler, verb, selector)
        .await
        .map_err(|error| match error {
            // The scheduler's 400 (empty selector, age-less purge) names
            // the refusal — forward its message rather than wrapping it
            // in the generic report wording.
            crate::errors::SchedulerClientError::Http {
                status: 400, body, ..
            } => GetArtifactError::BadRequestWithMessage(scheduler_error_message(&body).to_owned()),
            other => other.into(),
        })
}

/// POST /api/v1/admin/queue/retry — failed → pending, backoff cleared.
pub async fn admin_queue_retry(
    SchedulerCaller(_caller): SchedulerCaller,
    Json(selector): Json<stow_types::api::QueueSelector>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::QueueMutationResult>, GetArtifactError> {
    Ok(Json(queue_mutation(&scheduler, "retry", &selector).await?))
}

/// POST /api/v1/admin/queue/cancel — pending/dispatched → failed as
/// `cancelled by operator`.
pub async fn admin_queue_cancel(
    SchedulerCaller(_caller): SchedulerCaller,
    Json(selector): Json<stow_types::api::QueueSelector>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::QueueMutationResult>, GetArtifactError> {
    Ok(Json(queue_mutation(&scheduler, "cancel", &selector).await?))
}

/// POST /api/v1/admin/queue/promote — pending miss-lane rows → human lane.
pub async fn admin_queue_promote(
    SchedulerCaller(_caller): SchedulerCaller,
    Json(selector): Json<stow_types::api::QueueSelector>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::QueueMutationResult>, GetArtifactError> {
    Ok(Json(
        queue_mutation(&scheduler, "promote", &selector).await?,
    ))
}

/// POST /api/v1/admin/queue/purge — delete completed/failed rows older
/// than the selector's age.
pub async fn admin_queue_purge(
    SchedulerCaller(_caller): SchedulerCaller,
    Json(selector): Json<stow_types::api::QueueSelector>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::QueueMutationResult>, GetArtifactError> {
    Ok(Json(queue_mutation(&scheduler, "purge", &selector).await?))
}

/// Query for `GET /api/v1/admin/coverage/{crate_name}`.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct CoverageQuery {
    /// Scope to one published version.
    pub version: Option<CrateVersion>,
    /// Scope to one CI target; absent means every `CI_TARGET_TRIPLES`
    /// entry.
    pub target: Option<TargetTriple>,
}

/// `GET /api/v1/admin/coverage/{crate_name}?version=&target=`
///
/// Per-CI-target servable identities for one crate — which artifact
/// identities exist and which targets have none. Only rows with a
/// published bundle count as servable.
pub async fn artifact_coverage(
    SchedulerCaller(_caller): SchedulerCaller,
    params: Params,
    Query(query): Query<CoverageQuery>,
    db: Db,
) -> Result<Json<stow_types::api::CrateCoverage>, GetArtifactError> {
    let crate_name = path_crate_name(&params)?;
    let (version, target) = (query.version, query.target);
    if let Some(target) = &target
        && !stow_types::api::is_ci_target(target.as_str())
    {
        return Err(GetArtifactError::UnsupportedTarget {
            target: target.as_str().to_owned(),
            supported: CI_TARGET_TRIPLES.join(", "),
        });
    }
    let pairs = db::artifact_coverage(
        &db,
        crate_name.as_str(),
        version.as_ref().map(ToString::to_string).as_deref(),
    )
    .await?;
    let mut by_target: BTreeMap<String, Vec<stow_types::api::CoverageArtifact>> = BTreeMap::new();
    for (target, artifact) in pairs {
        by_target
            .entry(target.as_str().to_owned())
            .or_default()
            .push(artifact);
    }
    let targets = match &target {
        Some(target) => vec![target.clone()],
        None => CI_TARGET_TRIPLES
            .iter()
            .map(|triple| {
                TargetTriple::parse(*triple).map_err(|error| {
                    GetArtifactError::InternalWithMessage(format!("CI target `{triple}`: {error}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    Ok(Json(stow_types::api::CrateCoverage {
        crate_name,
        version,
        targets: targets
            .into_iter()
            .map(|target| stow_types::api::CoverageTarget {
                artifacts: by_target.remove(target.as_str()).unwrap_or_default(),
                target,
            })
            .collect(),
    }))
}

/// POST /api/v1/admin/preheat/plan
///
/// Dry run of the request API's closure expansion and dominance pruning
/// for one crate request: the tasks a dispatch wave would enqueue per
/// target. Nothing is enqueued.
pub async fn preheat_plan(
    SchedulerCaller(_caller): SchedulerCaller,
    Json(request): Json<stow_types::api::PreheatPlanRequest>,
    db: Db,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::PreheatPlanResponse>, GetArtifactError> {
    if let Some(target) = &request.target
        && !stow_types::api::is_ci_target(target.as_str())
    {
        return Err(GetArtifactError::UnsupportedTarget {
            target: target.as_str().to_owned(),
            supported: CI_TARGET_TRIPLES.join(", "),
        });
    }
    let crates_io = crates_io::CfCratesIo;
    let (version, rustc_version) = futures_util::try_join!(
        async {
            match &request.version {
                Some(version) => dependency_resolver::published_version(
                    &db,
                    &crates_io,
                    request.crate_name.as_str(),
                    version.as_semver(),
                )
                .await
                .map_err(GetArtifactError::from),
                None => dependency_resolver::latest_published_version(
                    &db,
                    &crates_io,
                    request.crate_name.as_str(),
                )
                .await
                .map_err(GetArtifactError::from),
            }
        },
        async {
            match &request.rustc_version {
                Some(rustc_version) => Ok(rustc_version.clone()),
                None => scheduler_client::get_stable_rustc(&scheduler)
                    .await
                    .map_err(GetArtifactError::from),
            }
        },
    )?;
    let version = version.ok_or_else(|| GetArtifactError::VersionNotPublished {
        crate_name: request.crate_name.as_str().to_owned(),
        requested: request
            .version
            .as_ref()
            .map_or_else(|| "stable release".to_owned(), |v| format!("version {v}")),
    })?;
    let seed_features =
        dependency_resolver::normalize_feature_set(request.features_json.features().to_vec())
            .map_err(|error| GetArtifactError::BadRequestWithMessage(error.to_string()))?;
    let target_list = match &request.target {
        Some(target) => vec![target.clone()],
        None => CI_TARGET_TRIPLES
            .iter()
            .map(|triple| {
                TargetTriple::parse(*triple).map_err(|error| {
                    GetArtifactError::InternalWithMessage(format!("CI target `{triple}`: {error}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    let expansions = target_list.iter().map(|target| {
        let db = &db;
        let crates_io = &crates_io;
        let crate_name = &request.crate_name;
        let seed_features = &seed_features;
        let version = &version;
        let rustc_version = &rustc_version;
        async move {
            let plan = dependency_resolver::expand_crate_request(
                db,
                crates_io,
                crate_name,
                version,
                seed_features,
                target,
                rustc_version,
            )
            .await?;
            Ok::<_, GetArtifactError>(stow_types::api::PreheatPlanTarget {
                target: target.clone(),
                root_cached: plan.root_cached,
                tasks: plan.enqueue_requests,
            })
        }
    });
    let targets = futures_util::future::try_join_all(expansions).await?;
    Ok(Json(stow_types::api::PreheatPlanResponse {
        crate_name: request.crate_name,
        version: CrateVersion::new(version),
        rustc_version,
        targets,
    }))
}

/// Row bound for the admin artifacts listing.
const MAX_ADMIN_ARTIFACTS_LIST: u32 = 1000;

/// `GET /api/v1/admin/artifacts?rustc_version=&target=&crate=&limit=`
///
/// Bounded catalog listing — the prune preview's data source and an
/// ad-hoc record listing.
pub async fn list_artifact_records(
    SchedulerCaller(_caller): SchedulerCaller,
    Query(query): Query<stow_types::api::ArtifactListQuery>,
    db: Db,
) -> Result<Json<Vec<ArtifactRecord>>, GetArtifactError> {
    let limit = query.limit.unwrap_or(200);
    if limit == 0 || limit > MAX_ADMIN_ARTIFACTS_LIST {
        return Err(GetArtifactError::BadRequestWithMessage(format!(
            "limit must be 1..={MAX_ADMIN_ARTIFACTS_LIST}"
        )));
    }
    let records = db::list_artifact_records(
        &db,
        &query,
        usize::try_from(limit).map_err(|_| {
            GetArtifactError::InternalWithMessage("limit overflows usize".to_owned())
        })?,
    )
    .await?;
    Ok(Json(records))
}

/// `GET /api/v1/admin/artifacts/{target}/{rustc_version}/{c_metadata}`
///
/// The catalog row plus the bundle image's OCI manifest read from GHCR.
pub async fn inspect_artifact(
    SchedulerCaller(_caller): SchedulerCaller,
    params: Params,
    db: Db,
    State(ghcr): State<GhcrConfig>,
) -> Result<Json<stow_types::api::ArtifactInspection>, GetArtifactError> {
    let target = params
        .get("target")
        .map_err(|_| GetArtifactError::BadRequest)?
        .parse::<TargetTriple>()
        .map_err(|error| GetArtifactError::BadRequestWithMessage(error.to_string()))?;
    let rustc_version = params
        .get("rustc_version")
        .map_err(|_| GetArtifactError::BadRequest)?
        .parse::<WireRustcVersion>()
        .map_err(|error| GetArtifactError::BadRequestWithMessage(error.to_string()))?;
    let c_metadata = params
        .get("c_metadata")
        .map_err(|_| GetArtifactError::BadRequest)?
        .parse::<CMetadata>()
        .map_err(|error| GetArtifactError::BadRequestWithMessage(error.to_string()))?;
    let record = db::artifact_record(
        &db,
        target.as_str(),
        rustc_version.as_str(),
        c_metadata.as_str(),
    )
    .await?
    .ok_or(GetArtifactError::NotFound)?;
    let bundle_reference = stow_types::registry::bundle_oci_reference(&record.oci_reference)
        .ok_or_else(|| {
            GetArtifactError::InternalWithMessage(format!(
                "oci_reference `{}` cannot derive a bundle tag",
                record.oci_reference
            ))
        })?;
    let repo = stow_types::registry::repository_path(&bundle_reference).ok_or_else(|| {
        GetArtifactError::InternalWithMessage(format!(
            "oci_reference `{bundle_reference}` has no repository path"
        ))
    })?;
    let tag = stow_types::registry::oci_reference_tag(&bundle_reference).ok_or_else(|| {
        GetArtifactError::InternalWithMessage(format!(
            "oci_reference `{bundle_reference}` has no tag"
        ))
    })?;
    let mut response = ghcr::open_manifest(&ghcr.base_url, repo, tag, &ghcr.tokens)
        .await
        .map_err(|error| match error {
            ghcr::FetchError::NotFound => GetArtifactError::NotFound,
            ghcr::FetchError::Unavailable => GetArtifactError::GhcrUnavailable,
            other => GetArtifactError::InternalWithMessage(other.to_string()),
        })?;
    let body = response
        .text()
        .into_send()
        .await
        .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
    let manifest: stow_types::api::OciManifest = serde_json::from_str(&body).map_err(|error| {
        GetArtifactError::InternalWithMessage(format!("decode bundle manifest: {error}"))
    })?;
    Ok(Json(stow_types::api::ArtifactInspection {
        record,
        manifest,
    }))
}

/// POST /api/v1/admin/artifacts/prune
///
/// Delete every catalog row built by the retired toolchain and invalidate
/// each row's lookup-cache entries. GHCR image tags are not deleted —
/// they age out under the package's own retention.
pub async fn prune_artifacts(
    SchedulerCaller(caller): SchedulerCaller,
    Json(request): Json<stow_types::api::ArtifactPruneRequest>,
    db: Db,
    State(cache): State<CfCache>,
) -> Result<Json<stow_types::api::ArtifactPruneResponse>, GetArtifactError> {
    let records = db::artifact_records_for_rustc(&db, request.rustc_version.as_str()).await?;
    for record in &records {
        invalidate_lookup_entries(&cache, record).await;
    }
    let deleted = db::delete_artifacts_for_rustc(&db, request.rustc_version.as_str()).await?;
    tracing::warn!(
        %caller,
        rustc_version = %request.rustc_version,
        deleted,
        "pruned artifact rows for a retired toolchain"
    );
    Ok(Json(stow_types::api::ArtifactPruneResponse { deleted }))
}

/// Registration is an upsert — a rebuilt artifact overwrites the row for
/// its identity, so the cached exact lookup that could still resolve to
/// the old row is deleted with it.
async fn invalidate_lookup_entries(cache: &CfCache, record: &ArtifactRecord) {
    let key = exact_lookup_key(
        record.target.as_str(),
        record.rustc_version.as_str(),
        record.c_metadata.as_str(),
    );
    if let Err(error) = cache::delete_lookup(cache, &key).await {
        tracing::warn!(%error, key = %key, "failed to invalidate artifact lookup cache entry");
    }
}

/// POST /api/v1/scheduler/tasks/submit
///
/// Control endpoint that submits arbitrary tasks into the scheduler.
///
/// `SchedulerCaller` extracts first and rejects unauthorized requests
/// before `Json` runs, so an attacker cannot make us deserialize an
/// arbitrary body without a trusted GitHub credential.
pub async fn submit_scheduler_tasks(
    SchedulerCaller(caller): SchedulerCaller,
    Json(requests): Json<Vec<stow_types::api::EnqueueRequest>>,
    db: Db,
    State(scheduler): State<CfDurableNamespace>,
    State(settings): State<crate::runtime_settings::ResolverSettings>,
) -> Result<Json<stow_types::api::SchedulerSubmitResponse>, GetArtifactError> {
    let requested = requests.len();
    let requests = dependency_resolver::canonicalize_enqueue_requests(
        &db,
        &crates_io::CfCratesIo,
        requests,
        settings.batch_fetch_concurrency,
    )
    .await?;
    // RepoWriter submissions are exempt from the pending-depth cap — the
    // credential check is the bound on this path.
    let inserted = scheduler_client::send_enqueue_trusted(&scheduler, &requests).await?;
    tracing::info!(tasks = requests.len(), %caller, "submitted scheduler tasks");
    Ok(Json(stow_types::api::SchedulerSubmitResponse {
        submitted: u32::try_from(requests.len()).map_err(|_| {
            GetArtifactError::TooLarge("submitted task count exceeds u32".to_owned())
        })?,
        inserted,
        dropped: u32::try_from(requested - requests.len()).map_err(|_| {
            GetArtifactError::TooLarge("dropped request count exceeds u32".to_owned())
        })?,
    }))
}

/// POST /api/v1/scheduler/complete
///
/// CI (or local simulated CI) reports build completion to the scheduler
/// Durable Object. `ArtifactWriteCaller` — the same `build-crate.yml` OIDC
/// pin as register — because a completion report is the other half of the
/// pipeline write: it tells the scheduler the artifacts exist.
pub async fn complete_build(
    ArtifactWriteCaller(caller): ArtifactWriteCaller,
    Json(report): Json<BuildCompleteReport>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<OkResponse>, GetArtifactError> {
    let mut report = report;
    // The OIDC token's `run_id` claim is the run id's authoritative source —
    // never a field the request body could write.
    if let github_auth::TrustedCaller::Actions { run_id, .. } = &caller {
        report.github_run_id = Some(run_id.clone());
    }
    scheduler_client::send_complete(&scheduler, &report)
        .await
        .map_err(|error| match error {
            // The scheduler's 409 says the report's attempt no longer
            // matches the row's live state — stale or duplicate. It must
            // reach the reporter as a conflict, not the generic 400 the
            // shared scheduler-error conversion gives every 4xx.
            crate::errors::SchedulerClientError::Http {
                status: 409, body, ..
            } => GetArtifactError::CompletionConflict(body),
            other => GetArtifactError::from(other),
        })
        .inspect_err(|error| {
            tracing::error!(%error, %caller, "failed to forward build completion to scheduler");
        })?;
    Ok(Json(OkResponse { ok: true }))
}

/// GET /api/v1/scheduler/status
pub async fn scheduler_status(
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::SchedulerStatus>, GetArtifactError> {
    let status = scheduler_client::get_status(&scheduler).await?;
    Ok(Json(status))
}

/// POST /api/v1/requests
///
/// Public human lane: a Turnstile-verified request to build one crate (and
/// its dependency closure) into the public cache for every supported CI
/// target. Turnstile replaces the miss path's proof-of-work as the
/// admission check, and accepted tasks enter the scheduler's human lane —
/// dispatched ahead of queued misses and exempt from the dispatch minimum
/// age. Re-requesting a queued crate promotes its task into the human
/// lane; nothing in this path demotes one back.
pub async fn submit_crate_request(
    CfConnectingIp(remoteip): CfConnectingIp,
    Json(request): Json<CrateRequest>,
    db: Db,
    State(scheduler): State<CfDurableNamespace>,
    State(turnstile): State<CfTurnstileVerifier>,
    State(settings): State<crate::runtime_settings::ResolverSettings>,
) -> Result<Response, GetArtifactError> {
    let siteverify = match turnstile
        .verify(&request.turnstile_token, remoteip.as_deref())
        .await
    {
        Ok(siteverify) => siteverify,
        Err(error) => {
            // siteverify operational details stay in the log; the client
            // sees only `siteverify-unavailable`.
            tracing::error!(%error, "turnstile siteverify request failed");
            return GetArtifactError::TurnstileRejected {
                error_codes: vec![crate::turnstile::SITEVERIFY_UNAVAILABLE_CODE.to_owned()],
            }
            .rejection_response();
        }
    };
    if let Some(error_codes) =
        crate::turnstile::rejection_error_codes(&siteverify, turnstile.expected_hostname())
    {
        tracing::warn!(
            error_codes = ?error_codes,
            crate_name = %request.crate_name,
            "turnstile rejected request token"
        );
        return GetArtifactError::TurnstileRejected { error_codes }.rejection_response();
    }

    let crates_io = crates_io::CfCratesIo;
    // Schema-then-version stays ordered (version resolution reads the db);
    // the scheduler's rustc lookup is independent and overlaps them.
    let (version, rustc_version) = futures_util::try_join!(
        async { resolve_request_version(&db, &crates_io, &request).await },
        async {
            scheduler_client::get_stable_rustc(&scheduler)
                .await
                .map_err(Into::into)
        },
    )?;
    let seed_features = request_seed_features(&request)?;
    let (plans, enqueue) = expand_request_targets(
        &db,
        &crates_io,
        &request,
        &version,
        &seed_features,
        &rustc_version,
    )
    .await?;
    // A request enqueues its uncovered closure once per CI target, so the
    // per-request cap applies to the closure itself — the largest plan —
    // not the summed task count.
    let closure_size = plans
        .iter()
        .map(|(_, plan, _)| plan.enqueue_requests.len())
        .max()
        .unwrap_or(0);
    if closure_size > settings.human_max_closure {
        return Err(GetArtifactError::UnprocessableEntity(format!(
            "dependency closure of {closure_size} crates exceeds the per-request limit of {}",
            settings.human_max_closure
        )));
    }
    let enqueued = enqueue.len();
    let targets = match submit_and_assemble(&scheduler, enqueue, &plans).await {
        Ok(targets) => targets,
        // A 429 from the scheduler on this lane is the daily task budget;
        // its counter resets at 00:00 UTC.
        Err(GetArtifactError::SchedulerBusy(message)) => {
            return rate_limited_response(
                &message,
                scheduler::queue::seconds_until_utc_midnight(now_unix()),
            );
        }
        Err(error) => return Err(error),
    };
    tracing::info!(
        crate_name = %request.crate_name,
        %version,
        rustc_version = %rustc_version,
        enqueued,
        "human request accepted"
    );
    let mut response = Response::new(
        Body::from_json(&CrateRequestOutcome {
            crate_name: request.crate_name,
            version: CrateVersion::new(version),
            rustc_version,
            targets,
        })
        .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?,
    );
    response.headers_mut().insert(
        skyzen::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(response)
}

/// Resolve the requested version — exact-published check when given, else
/// the newest non-prerelease, non-yanked release.
async fn resolve_request_version(
    db: &Db,
    crates_io: &crates_io::CfCratesIo,
    request: &CrateRequest,
) -> Result<semver::Version, GetArtifactError> {
    let resolved = match request.version.as_ref() {
        Some(version) => {
            dependency_resolver::published_version(
                db,
                crates_io,
                request.crate_name.as_str(),
                version.as_semver(),
            )
            .await?
        }
        None => {
            dependency_resolver::latest_published_version(
                db,
                crates_io,
                request.crate_name.as_str(),
            )
            .await?
        }
    };
    resolved.ok_or_else(|| GetArtifactError::VersionNotPublished {
        crate_name: request.crate_name.as_str().to_owned(),
        requested: request.version.as_ref().map_or_else(
            || "stable release".to_owned(),
            |version| format!("version {version}"),
        ),
    })
}

/// The feature seeds for the closure walk, taken verbatim from the
/// request.
///
/// An empty list means exactly that: build with no features at all, which
/// is `--no-default-features`. It must not be re-seeded with `default` —
/// the form's only way to ask for a bare build is to untick every box, and
/// silently turning that into the full default closure builds the thing the
/// user just declined, under a task identity they did not ask for.
fn request_seed_features(request: &CrateRequest) -> Result<BTreeSet<String>, GetArtifactError> {
    dependency_resolver::normalize_feature_set(request.features_json.features().to_vec())
        .map_err(|_| GetArtifactError::BadRequest)
}

/// Expand the request's dependency closure once per CI target. Returns the
/// per-target `(target, plan, root_task_id)` triples and the flat list of
/// human-lane tasks to submit; a target whose root is already cached
/// contributes no tasks.
async fn expand_request_targets(
    db: &Db,
    crates_io: &crates_io::CfCratesIo,
    request: &CrateRequest,
    version: &semver::Version,
    seed_features: &BTreeSet<String>,
    rustc_version: &stow_types::identity::WireRustcVersion,
) -> Result<
    (
        Vec<(TargetTriple, dependency_resolver::CrateRequestPlan, String)>,
        Vec<stow_types::api::EnqueueRequest>,
    ),
    GetArtifactError,
> {
    // The per-target expansions are independent closure resolutions plus
    // cache lookups — run them concurrently. try_join_all preserves input
    // order, so the result rows still follow CI_TARGET_TRIPLES.
    let expansions = CI_TARGET_TRIPLES.iter().map(|triple| async move {
        let target = TargetTriple::parse(*triple).map_err(|error| {
            GetArtifactError::InternalWithMessage(format!("CI target `{triple}`: {error}"))
        })?;
        let plan = dependency_resolver::expand_crate_request(
            db,
            crates_io,
            &request.crate_name,
            version,
            seed_features,
            &target,
            rustc_version,
        )
        .await?;
        Ok::<_, GetArtifactError>((target, plan))
    });
    let mut plans = Vec::with_capacity(CI_TARGET_TRIPLES.len());
    let mut enqueue = Vec::new();
    for (target, plan) in futures_util::future::try_join_all(expansions).await? {
        let root_task_id = scheduler::queue::task_id(
            request.crate_name.as_str(),
            &version.to_string(),
            &plan.root_features_json,
            target.as_str(),
            rustc_version.as_str(),
        );
        // A cached root means the artifact already exists for this target:
        // report `Cached` and do not enqueue its closure.
        if !plan.root_cached {
            enqueue.extend(plan.enqueue_requests.iter().cloned());
        }
        plans.push((target, plan, root_task_id));
    }
    Ok((plans, enqueue))
}

/// Submit the human-lane tasks and assemble the per-target outcomes. The
/// pre-submit status read distinguishes `AlreadyQueued`/`Building` roots
/// from the ones this request just queued.
async fn submit_and_assemble(
    scheduler: &CfDurableNamespace,
    enqueue: Vec<stow_types::api::EnqueueRequest>,
    plans: &[(TargetTriple, dependency_resolver::CrateRequestPlan, String)],
) -> Result<Vec<stow_types::api::CrateRequestTarget>, GetArtifactError> {
    let root_task_ids = plans
        .iter()
        .filter(|(_, plan, _)| !plan.root_cached)
        .map(|(_, _, task_id)| task_id.clone())
        .collect::<Vec<_>>();
    let was_queued: BTreeSet<String> =
        scheduler_client::get_tasks_status(scheduler, &root_task_ids)
            .await?
            .into_iter()
            .map(|status| status.task_id)
            .collect();
    scheduler_client::send_enqueue(scheduler, &enqueue).await?;
    let statuses: BTreeMap<String, stow_types::api::RequestStatus> =
        scheduler_client::get_tasks_status(scheduler, &root_task_ids)
            .await?
            .into_iter()
            .map(|status| (status.task_id.clone(), status))
            .collect();
    plans
        .iter()
        .map(|(target, plan, task_id)| {
            dependency_resolver::crate_request_target(
                target,
                task_id,
                plan.root_cached,
                was_queued.contains(task_id),
                statuses.get(task_id),
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(GetArtifactError::from)
}

/// GET /`api/v1/requests/{task_id}`
///
/// Point-in-time view of one scheduler task: lane, queue status, and the
/// 1-based human-lane position while the task is still pending there.
pub async fn crate_request_status(
    params: Params,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::RequestStatus>, GetArtifactError> {
    let task_id = params
        .get("task_id")
        .map_err(|_| GetArtifactError::BadRequest)?;
    let statuses = scheduler_client::get_tasks_status(&scheduler, &[task_id.to_owned()]).await?;
    let status = statuses
        .into_iter()
        .find(|status| status.task_id == task_id)
        .ok_or_else(|| GetArtifactError::UnknownTask {
            task_id: task_id.to_owned(),
        })?;
    Ok(Json(status))
}

/// Query parameters for `GET /api/v1/crates/search`.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct CrateSearchQuery {
    /// Search text, at least [`catalog::MIN_SEARCH_QUERY_LEN`] characters.
    pub q: String,
    /// Result cap, clamped into <code>1..=[catalog::MAX_SEARCH_LIMIT]</code>.
    pub limit: Option<u32>,
}

/// How long a catalog answer may be reused. crates.io publishes
/// continuously, so a stale list costs a user one page reload, while the
/// form issues one lookup per keystroke burst and per version pick.
const CATALOG_SEARCH_MAX_AGE: &str = "public, max-age=300";
const CATALOG_VERSIONS_MAX_AGE: &str = "public, max-age=600";

/// Serialize `body` as a cacheable JSON response.
fn cacheable_json<T: serde::Serialize>(
    body: &T,
    cache_control: &'static str,
) -> Result<Response, GetArtifactError> {
    let payload = serde_json::to_vec(body)
        .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
    let mut response = Response::new(Body::from(payload));
    response.headers_mut().insert(
        skyzen::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        skyzen::header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
    Ok(response)
}

/// Read a path parameter as a validated crate name. The value reaches a
/// crates.io URL, so it is parsed into [`CrateName`] — which admits only
/// crates.io's own character set — before it is interpolated anywhere.
fn path_crate_name(params: &Params) -> Result<CrateName, GetArtifactError> {
    params
        .get("crate_name")
        .map_err(|_| GetArtifactError::BadRequest)?
        .parse::<CrateName>()
        .map_err(|error| GetArtifactError::BadRequestWithMessage(error.to_string()))
}

/// `GET /api/v1/crates/search?q=ser&limit=10`
///
/// crates.io search, proxied so the request form can offer completions
/// without the browser talking to crates.io directly (and without its CORS
/// and user-agent rules applying to every visitor).
pub async fn search_crates(
    Query(query): Query<CrateSearchQuery>,
) -> Result<Response, GetArtifactError> {
    let response = catalog::search_crates(
        &crates_io::CfCratesIo,
        &query.q,
        query.limit.unwrap_or(catalog::DEFAULT_SEARCH_LIMIT),
    )
    .await?;
    cacheable_json(&response, CATALOG_SEARCH_MAX_AGE)
}

/// `GET /api/v1/crates/{crate_name}/versions`
///
/// Every published, non-yanked version, newest first — the version picker's
/// option list.
pub async fn crate_versions(params: Params, db: Db) -> Result<Response, GetArtifactError> {
    let crate_name = path_crate_name(&params)?;
    let response =
        catalog::crate_versions(&db, &crates_io::CfCratesIo, crate_name.as_str()).await?;
    cacheable_json(&response, CATALOG_VERSIONS_MAX_AGE)
}

/// `GET /api/v1/crates/{crate_name}/versions/{version}/features`
///
/// Every feature the version lets a caller select, `default` first — the
/// feature checkboxes. Selecting `default` is what keeps cargo's default
/// feature set on; leaving it out builds `--no-default-features`.
pub async fn crate_features(params: Params, db: Db) -> Result<Response, GetArtifactError> {
    let crate_name = path_crate_name(&params)?;
    let version = params
        .get("version")
        .map_err(|_| GetArtifactError::BadRequest)?
        .parse::<CrateVersion>()
        .map_err(|error| GetArtifactError::BadRequestWithMessage(error.to_string()))?;
    let response = catalog::crate_features(
        &db,
        &crates_io::CfCratesIo,
        crate_name.as_str(),
        version.as_semver(),
    )
    .await?;
    cacheable_json(&response, CATALOG_VERSIONS_MAX_AGE)
}

/// Query parameters for artifact requests.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct ArtifactQuery {
    /// Crate name (for miss logging and validation).
    #[serde(rename = "crate")]
    pub crate_name: Option<String>,
    /// The `sha256:…` bundle digest the caller's signed index pins for
    /// this key, when the caller sends one.
    pub digest: Option<String>,
}

/// GET /`api/v1/artifacts/{target}/{rustc_version}/{c_metadata}?crate=serde&digest=sha256:…`
///
/// Returns the complete artifact bundle for one crate compilation unit.
///
/// Flow:
/// 1. Lookup-cache check for the artifact row (free, per-datacenter) — a
///    hit skips D1 entirely, unless `digest` says the cached row names a
///    bundle the caller was not promised
/// 2. Lookup miss → schema-ensured D1 read, row written back to the
///    lookup cache; a real miss is never cached
/// 3. Catalog row disagreeing with `digest` → treated as a miss, since
///    the caller verifies the bytes against its signed index
/// 4. Bundle bytes: CF Cache hit → return; miss → fetch from GHCR, tee
///    into CF Cache
/// 5. Stale GHCR fetch → prune the D1 row and the lookup entry, then 404
/// 6. D1 miss → validate `crate_name`, log miss, return 404
pub async fn get_artifact(
    params: Params,
    Query(query): Query<ArtifactQuery>,
    db: Db,
    streams: BundleStreams,
    State(analytics): State<AnalyticsEngineDataset>,
    sink: stats::StatsSink,
) -> Result<Response, GetArtifactError> {
    let BundleStreams {
        context,
        cache,
        ghcr,
    } = streams;
    let target = params
        .get("target")
        .map_err(|_| GetArtifactError::BadRequest)?;
    let rustc_version = params
        .get("rustc_version")
        .map_err(|_| GetArtifactError::BadRequest)?;
    let c_metadata = params
        .get("c_metadata")
        .map_err(|_| GetArtifactError::BadRequest)?;

    let expected_digest = query.digest.as_deref().filter(|digest| !digest.is_empty());
    let artifact_row = resolve_exact_row(
        &db,
        &cache,
        c_metadata,
        target,
        rustc_version,
        expected_digest,
    )
    .await?;

    let artifact_row = artifact_row.filter(|row| {
        catalog_row_is_the_one_requested(row, expected_digest, c_metadata, target, rustc_version)
    });

    let Some(row) = artifact_row else {
        // 404 IS the miss event. Log it server-side.
        log_exact_miss(
            &analytics,
            sink.telemetry.consent,
            &query,
            target,
            rustc_version,
        );
        return Err(GetArtifactError::NotFound);
    };
    let cache_key = bundle_cache_key(target, rustc_version, &row.bundle_digest);

    match open_bundle_stream(&context, &cache, &ghcr, &cache_key, &row).await {
        Ok((body, cache_hit)) => {
            stats::record_hit(
                &sink,
                &stats::Hit {
                    target,
                    rustc_version,
                    crate_name: &row.crate_name,
                    version: &row.version,
                    bundle_size: row.bundle_size,
                    compile_millis: row.compile_millis,
                },
            );
            Ok(bundle_response(body, row.bundle_size, cache_hit))
        }
        Err(error) if error.indicates_stale_artifact() => {
            tracing::warn!(
                %error,
                oci_reference = %row.oci_reference,
                oci_digest = %row.oci_digest,
                c_metadata,
                target,
                rustc_version,
                "pruning stale artifact row from D1 due to GHCR fetch error"
            );
            prune_stale_artifact_row(&db, &cache, c_metadata, target, rustc_version).await?;
            log_exact_miss(
                &analytics,
                sink.telemetry.consent,
                &query,
                target,
                rustc_version,
            );
            Err(GetArtifactError::NotFound)
        }
        Err(ghcr::FetchError::Unauthorized { status, .. }) => {
            tracing::error!(
                status,
                oci_reference = %row.oci_reference,
                "GHCR authentication failed — NOT pruning D1 row"
            );
            Err(GetArtifactError::InternalWithMessage(format!(
                "GHCR authentication failed (HTTP {status})"
            )))
        }
        // A retryable upstream outage surfaces as 502 and the CLI compiles
        // locally rather than waiting on the registry.
        Err(ghcr::FetchError::Unavailable) => {
            tracing::warn!(key = %cache_key, "GHCR unavailable (rate limit or 5xx)");
            Err(GetArtifactError::GhcrUnavailable)
        }
        Err(error) => {
            tracing::error!(error = %error, "GHCR fetch failed");
            Err(GetArtifactError::InternalWithMessage(error.to_string()))
        }
    }
}

/// HEAD /`api/v1/artifacts/{target}/{rustc_version}/{c_metadata}`
///
/// Check if an artifact exists without downloading it.
pub async fn check_artifact(
    params: Params,
    db: Db,
    State(cache): State<CfCache>,
) -> Result<Response, GetArtifactError> {
    let target = params
        .get("target")
        .map_err(|_| GetArtifactError::BadRequest)?;
    let rustc_version = params
        .get("rustc_version")
        .map_err(|_| GetArtifactError::BadRequest)?;
    let c_metadata = params
        .get("c_metadata")
        .map_err(|_| GetArtifactError::BadRequest)?;

    let artifact_row =
        resolve_exact_row(&db, &cache, c_metadata, target, rustc_version, None).await?;

    match artifact_row {
        Some(row) => {
            let mut response = Response::new(Body::empty());
            // GET on this URL streams the published bundle blob, so its
            // length is the response length; the raw artifact bytes (the
            // uncompressed outputs) stay under a stow header.
            response.headers_mut().insert(
                skyzen::header::CONTENT_LENGTH,
                HeaderValue::from(row.bundle_size),
            );
            if let Some(size) = row.artifact_size {
                response
                    .headers_mut()
                    .insert("x-stow-artifact-size", HeaderValue::from(size));
            }
            Ok(response)
        }
        None => Err(GetArtifactError::NotFound),
    }
}

/// POST /api/v1/admissions
///
/// The client resolved its dependency graph against the signed artifact
/// index locally and posts the same graph here — every direct entry plus
/// the cargo-expanded `c_metadata` edges. The edge re-derives which nodes
/// the catalog does not cover (crates.io feature expansion plus
/// artifact-catalog reachability), mints a stateless admission per
/// uncovered node, and returns them for the client to redeem through the
/// proof-of-work gated `/api/v1/enqueue`. The graph itself is never
/// needed to *find* artifacts — the index already did that — so nothing
/// here feeds a lookup.
pub async fn mint_miss_admissions(
    Json(request): Json<AdmissionRequest>,
    db: Db,
    State(scheduler): State<CfDurableNamespace>,
    State(admission): State<PowAdmission>,
    State(settings): State<crate::runtime_settings::ResolverSettings>,
    State(analytics): State<AnalyticsEngineDataset>,
    consent: stats::AnalyticsConsent,
) -> Result<Json<Vec<EnqueueAdmission>>, GetArtifactError> {
    if request.entries.len() > settings.max_expanded_tasks {
        tracing::warn!(
            entries = request.entries.len(),
            max_entries = settings.max_expanded_tasks,
            "dependency list exceeds edge limit"
        );
        return Err(GetArtifactError::from(
            crate::errors::ResolverError::LimitExceeded {
                what: "dependency graph direct entries",
                got: request.entries.len(),
                limit: settings.max_expanded_tasks,
            },
        ));
    }
    let plan = dependency_resolver::expand_scheduler_requests(
        &db,
        request.target.as_str(),
        request.rustc_version.as_str(),
        &request.entries,
        &request.expanded_entries,
    )
    .await
    .map_err(|error| {
        tracing::error!(%error, "admission miss derivation failed");
        GetArtifactError::InternalWithMessage(error.to_string())
    })?;
    let enqueue_requests = plan.enqueue_requests;

    // One Analytics Engine point per uncovered node — demand analytics
    // stay off the D1 row-write meter.
    miss_logger::log_graph_misses(&analytics, consent, &enqueue_requests);

    // A fully-covered graph has no misses to mint and admits nothing new
    // to drain, so it skips the scheduler round-trip entirely — the status
    // fetch and misses-table scan are pure overhead on a cache hit.
    if enqueue_requests.is_empty() {
        return Ok(Json(Vec::new()));
    }
    let difficulty = admission::difficulty(admission.min_bits);
    let admissions =
        mint_admissions(&admission, enqueue_requests, difficulty).map_err(|error| {
            tracing::error!(%error, "failed to mint dependency-graph miss admissions");
            GetArtifactError::InternalWithMessage(error.to_string())
        })?;
    drain_admitted_misses(&db, &scheduler).await;
    Ok(Json(admissions))
}

/// Internal retry channel for verified admissions: hand misses that already
/// passed the `/api/v1/enqueue` challenge + `PoW` gate back to the scheduler
/// when their direct send failed. Unadmitted misses are never drainable —
/// this is not a second minting channel, so it needs no proof-of-work of
/// its own. Best-effort like every scheduler side-channel: a drain hiccup
/// must not fail the analysis response.
async fn drain_admitted_misses(db: &Db, scheduler: &CfDurableNamespace) {
    const DRAIN_MISS_BATCH: usize = 64;

    let drained = match db::take_dependency_graph_misses(db, DRAIN_MISS_BATCH).await {
        Ok(drained) => drained,
        Err(error) => {
            tracing::error!(%error, "failed to drain admitted dependency-graph misses");
            return;
        }
    };
    if drained.is_empty() {
        return;
    }

    if let Err(error) = scheduler_client::send_enqueue(scheduler, &drained).await {
        tracing::error!(%error, "failed to enqueue admitted dependency-graph misses to scheduler");
        if let Err(restore_error) =
            db::set_dependency_graph_misses_queued(db, &drained, false).await
        {
            tracing::error!(
                %restore_error,
                "failed to restore drained dependency-graph misses after enqueue failure"
            );
        }
    }
}

/// POST /api/v1/enqueue
///
/// Redeem a miss admission statelessly: recompute the HMAC challenge over
/// the request the ticket carries, check the client's proof-of-work against
/// the queue depth current at redemption time (one bit lenient — the queue
/// may have grown since the miss response), then forward that request to
/// the scheduler. Replay is safe — the scheduler deduplicates on task id.
pub async fn enqueue_admitted_task(
    Json(ticket): Json<EnqueueTicket>,
    db: Db,
    State(scheduler): State<CfDurableNamespace>,
    State(admission): State<PowAdmission>,
) -> Result<Response, GetArtifactError> {
    let request_json = serde_json::to_vec(&ticket.request)
        .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
    if !admission::verify_challenge(
        &admission.challenge_secret,
        &ticket.task_id,
        &request_json,
        &ticket.challenge,
        now_minute(),
    ) {
        tracing::warn!(task_id = %ticket.task_id, "rejected enqueue ticket: invalid challenge");
        return Err(GetArtifactError::Unauthorized);
    }
    // The challenge binds task_id to the request's canonical identity;
    // recompute it so a verified ticket always forwards what it minted.
    let derived_task_id = scheduler::queue::task_id(
        ticket.request.crate_name.as_str(),
        &ticket.request.version.to_string(),
        ticket.request.features_json.raw().as_str(),
        ticket.request.target.as_str(),
        ticket.request.rustc_version.as_str(),
    );
    if derived_task_id != ticket.task_id {
        tracing::warn!(task_id = %ticket.task_id, "rejected enqueue ticket: task id mismatch");
        return Err(GetArtifactError::Unauthorized);
    }
    // A client builds for whatever host it runs on, and plenty of those are
    // machines this cache has no runner for. Refuse before the ticket can
    // become a dispatch that cannot run.
    if !stow_types::api::is_ci_target(ticket.request.target.as_str()) {
        tracing::info!(
            task_id = %ticket.task_id,
            target = %ticket.request.target,
            "rejected enqueue ticket: no CI runner builds this target"
        );
        return Err(GetArtifactError::UnsupportedTarget {
            target: ticket.request.target.to_string(),
            supported: CI_TARGET_TRIPLES.join(", "),
        });
    }
    let status = scheduler_client::get_status(&scheduler).await?;
    // The depth cap refuses miss-lane tickets once the queue is full; the
    // Durable Object repeats the check at submit time so a wave of
    // concurrent redemptions cannot overshoot by more than one batch.
    if status.pending >= admission.max_queue_pending {
        tracing::warn!(
            task_id = %ticket.task_id,
            pending = status.pending,
            cap = admission.max_queue_pending,
            "refusing enqueue ticket: scheduler queue is full"
        );
        return rate_limited_response(
            "scheduler queue is full; retry after it drains",
            QUEUE_FULL_RETRY_AFTER_SECS,
        );
    }
    let required = admission::difficulty(admission.min_bits);
    let solved =
        stow_types::pow::enqueue_pow_zero_bits(&ticket.task_id, &ticket.challenge, ticket.nonce);
    if solved < required {
        tracing::warn!(
            task_id = %ticket.task_id,
            solved,
            required,
            "enqueue ticket proof-of-work below required difficulty"
        );
        return Err(GetArtifactError::BadRequest);
    }

    // The ticket is verified: upsert the miss row (born `admitted_at`) so
    // the internal drain may retry the scheduler send, then deliver the
    // canonical request.
    if let Err(error) = db::record_admitted_miss(&db, &ticket.request).await {
        tracing::error!(%error, "failed to record admitted miss");
    }
    match scheduler_client::send_enqueue(&scheduler, std::slice::from_ref(&ticket.request)).await {
        Ok(()) => {}
        // The edge check raced another submit wave: the Durable Object's
        // own pending-depth cap refused this one.
        Err(crate::errors::SchedulerClientError::Http { status: 429, .. }) => {
            return rate_limited_response(
                "scheduler queue is full; retry after it drains",
                QUEUE_FULL_RETRY_AFTER_SECS,
            );
        }
        Err(error) => return Err(error.into()),
    }
    if let Err(error) =
        db::set_dependency_graph_misses_queued(&db, std::slice::from_ref(&ticket.request), true)
            .await
    {
        tracing::error!(%error, "failed to mark dependency-graph miss queued");
    }
    let mut response = Response::new(
        Body::from_json(&OkResponse { ok: true })
            .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?,
    );
    response.headers_mut().insert(
        skyzen::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(response)
}

/// Resolve the artifact row for an exact `(c_metadata, target,
/// rustc_version)` identity, CF-cache-first so warm hits never touch D1.
/// A lookup miss falls through to a schema-ensured D1 read whose result
/// is written back to the lookup cache; a real `None` (404) is never
/// cached — misses drive admission and must stay fresh.
/// Whether the catalog's own row names the bundle the caller pinned.
///
/// A row that does not is a real miss rather than a body worth sending:
/// the caller checks the bytes against its signed index and would reject
/// them, and a miss makes it fall back to rustc and enqueue the rebuild.
fn catalog_row_is_the_one_requested(
    row: &db::ArtifactRow,
    expected_digest: Option<&str>,
    c_metadata: &str,
    target: &str,
    rustc_version: &str,
) -> bool {
    if row_matches_digest(&row.bundle_digest, expected_digest) {
        return true;
    }
    tracing::info!(
        c_metadata,
        target,
        rustc_version,
        catalog_digest = %row.bundle_digest,
        expected_digest = expected_digest.unwrap_or_default(),
        "catalog bundle differs from the digest the caller's index pins"
    );
    false
}

async fn resolve_exact_row(
    db: &Db,
    cache: &CfCache,
    c_metadata: &str,
    target: &str,
    rustc_version: &str,
    expected_digest: Option<&str>,
) -> Result<Option<db::ArtifactRow>, GetArtifactError> {
    let lookup_key = exact_lookup_key(target, rustc_version, c_metadata);
    match cache::get_lookup(cache, &lookup_key).await {
        // A cached row that names the bundle the caller was promised is
        // the row the catalog holds. One that names a different bundle is
        // a leftover of a re-registration: `invalidate_lookup_entries`
        // only reaches the datacenter that served the register call, so
        // every other colo keeps the previous row until its TTL expires,
        // and serving from it hands the caller bytes its signed index
        // will reject. Drop it and read the catalog.
        Ok(Some(row)) if row_matches_digest(&row.bundle_digest, expected_digest) => {
            return Ok(Some(row));
        }
        Ok(Some(row)) => {
            tracing::info!(
                key = %lookup_key,
                cached_digest = %row.bundle_digest,
                expected_digest = expected_digest.unwrap_or_default(),
                "cached artifact row names a different bundle than the caller expects; \
                 re-reading the catalog"
            );
            if let Err(error) = cache::delete_lookup(cache, &lookup_key).await {
                tracing::warn!(%error, key = %lookup_key, "failed to drop stale lookup entry");
            }
        }
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(%error, key = %lookup_key, "cf lookup cache read failed; falling back to D1");
        }
    }
    let row = db::get_artifact_reference(db, c_metadata, target, rustc_version)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "D1 query failed");
            GetArtifactError::Internal
        })?;
    if let Some(row) = &row
        && let Err(error) = cache::put_lookup(cache, &lookup_key, row).await
    {
        tracing::warn!(%error, key = %lookup_key, "cf lookup cache write failed");
    }
    Ok(row)
}

/// The streamed bundle response: the body is the published bundle blob
/// byte-for-byte, so its length is the row's `bundle_size`.
fn bundle_response(body: Body, bundle_size: u64, cache_hit: bool) -> Response {
    let mut response = Response::new(body);
    response.headers_mut().insert(
        skyzen::header::CONTENT_TYPE,
        HeaderValue::from_static(STOW_BUNDLE_MEDIA_TYPE),
    );
    response.headers_mut().insert(
        skyzen::header::CONTENT_LENGTH,
        HeaderValue::from(bundle_size),
    );
    response
        .headers_mut()
        .insert("x-stow-cache", cache_status_header(cache_hit));
    response
}

/// Open the bundle for `row` as a stream: the Cache API copy when there is
/// one, otherwise the registry blob by digest, teed into the Cache API
/// while the client reads it. Nothing on this path buffers the bundle or
/// inspects it — the publish stage validated the tar before pushing it,
/// GHCR addresses it by content, and the CLI verifies the cosign material
/// inside it.
async fn open_bundle_stream(
    context: &WorkerContext,
    cache: &CfCache,
    ghcr: &GhcrConfig,
    cache_key: &str,
    row: &db::ArtifactRow,
) -> Result<(Body, bool), ghcr::FetchError> {
    match cache::get_stream(cache, cache_key).await {
        Ok(Some(cached)) => {
            tracing::debug!(key = %cache_key, "cf cache hit");
            return Ok((body_from_worker_response(cached)?, true));
        }
        Ok(None) => {
            tracing::debug!(key = %cache_key, "cf cache miss");
        }
        Err(error) => {
            tracing::warn!(key = %cache_key, error = %error, "cf cache error");
        }
    }

    let repository = oci_repository(&row.oci_reference).map_err(|error| {
        tracing::error!(%error, "refusing GHCR fetch for malformed OCI reference");
        ghcr::FetchError::InvalidRequest(error.to_string())
    })?;
    let mut upstream =
        ghcr::open_blob(&ghcr.base_url, repository, &row.bundle_digest, &ghcr.tokens)
            .await
            .map_err(|error| {
                tracing::error!(
                    cache_key = %cache_key,
                    oci_reference = %row.oci_reference,
                    bundle_digest = %row.bundle_digest,
                    error = %error,
                    "edge failed to open bundle blob from registry"
                );
                error
            })?;

    if cache::fits_cache(row.bundle_size) {
        // `cloned` tees the JS stream: one branch feeds the Cache API
        // under `waitUntil`, the other is the response body. The put
        // consumes its branch at the client's pace, so no branch buffers
        // beyond the tee's own backlog.
        match upstream.cloned() {
            Ok(for_cache) => {
                let cache = cache.clone();
                let key = cache_key.to_owned();
                let put = async move {
                    if let Err(error) = cache::put_stream(&cache, &key, for_cache).await {
                        tracing::warn!(key = %key, error = %error, "cf cache put failed");
                    }
                };
                if let Err(error) = context.wait_until(put) {
                    tracing::warn!(key = %cache_key, error = %error, "cf cache put not scheduled");
                }
            }
            Err(error) => {
                tracing::warn!(key = %cache_key, error = %error, "bundle stream tee failed; serving uncached");
            }
        }
    }

    Ok((body_from_worker_response(upstream)?, false))
}

/// Hand a `worker::Response` body to Skyzen without reading it.
fn body_from_worker_response(response: worker::Response) -> Result<Body, ghcr::FetchError> {
    let js: worker::web_sys::Response = response.into();
    from_js_response(&js)
        .map(skyzen::Response::into_body)
        .map_err(|error| ghcr::FetchError::Network(format!("wrap registry response: {error:?}")))
}

fn oci_repository(
    reference: &str,
) -> Result<stow_types::registry::RepositoryPath<'_>, GetArtifactError> {
    // `oci_reference_name` enforces the canonical single-package shape;
    // `repository_path` then yields `water-rs/stow-cache`, the repository
    // the pull scope names.
    stow_types::registry::oci_reference_name(reference)
        .and_then(|_| stow_types::registry::repository_path(reference))
        .ok_or_else(|| {
            GetArtifactError::InternalWithMessage(format!(
                "malformed OCI reference `{reference}` — expected ghcr.io/water-rs/stow-cache:{{crate}}.{{rest}}"
            ))
        })
}

/// OCI registry configuration for artifact fetching, stored via `State<GhcrConfig>`.
#[derive(Debug, Clone)]
pub struct GhcrConfig {
    pub base_url: String,
    /// Per-isolate bearer cache for the anonymous registry token exchange.
    pub tokens: RegistryTokens,
}

async fn prune_stale_artifact_row(
    db: &Db,
    cache: &CfCache,
    c_metadata: &str,
    target: &str,
    rustc_version: &str,
) -> Result<(), GetArtifactError> {
    tracing::warn!(
        c_metadata = %c_metadata,
        target = %target,
        rustc_version = %rustc_version,
        "pruning stale artifact row after registry miss"
    );
    db::delete_artifact_reference(db, c_metadata, target, rustc_version)
        .await
        .map_err(GetArtifactError::from)?;
    // The row is gone — any cached lookup pointing at it must die with
    // it, or the pruned artifact would keep resolving.
    if let Err(error) =
        cache::delete_lookup(cache, &exact_lookup_key(target, rustc_version, c_metadata)).await
    {
        tracing::warn!(%error, "failed to delete lookup entry for pruned artifact row");
    }
    Ok(())
}

/// Write the exact-path miss point when the client named the crate via
/// `?crate=` — a value that cannot parse as a crates.io name is not
/// demand data, so it is skipped.
fn log_exact_miss(
    analytics: &AnalyticsEngineDataset,
    consent: stats::AnalyticsConsent,
    query: &ArtifactQuery,
    target: &str,
    rustc_version: &str,
) {
    if let Some(ref crate_name) = query.crate_name
        && let Ok(crate_name) = crate_name.parse::<CrateName>()
    {
        analytics.write_miss(consent, &Miss::exact(&crate_name, target, rustc_version));
    }
}

/// GET /api/v1/stats — the public aggregate usage statistics. Anonymous:
/// the handler reads no request data at all, and the `UsageStats` it
/// returns is computed from the Analytics Engine SQL API at most once an
/// hour per colo — the serialized body rides the Cache API between runs.
pub async fn usage_stats(
    State(stats_ctx): State<stats::StatsContext>,
    State(cache): State<CfCache>,
) -> Result<Json<stow_types::api::UsageStats>, GetArtifactError> {
    stats::cached_usage_stats(&stats_ctx, &cache)
        .await
        .map(Json)
}

#[skyzen::error]
pub enum GetArtifactError {
    #[error("bad request", status = BAD_REQUEST)]
    BadRequest,
    /// A rejected request whose reason is safe to show the caller — the
    /// request page renders the body's `error` verbatim.
    #[error("{0}", status = BAD_REQUEST)]
    BadRequestWithMessage(String),
    #[error("unauthorized", status = UNAUTHORIZED)]
    Unauthorized,
    /// Turnstile rejected the request. The request-API contract renders
    /// this as `{"error":"turnstile rejected","error-codes":[...]}` — a
    /// shape the shared `{"error": ...}` renderer cannot express — so
    /// handlers return [`Self::rejection_response`] instead of `Err`.
    /// `status = FORBIDDEN` keeps even that fallback path correct.
    #[error("turnstile rejected", status = FORBIDDEN)]
    TurnstileRejected {
        /// Codes surfaced to the client verbatim (`siteverify-unavailable`,
        /// `hostname-mismatch`, or siteverify's own `error-codes`).
        error_codes: Vec<String>,
    },
    #[error("artifact not found", status = NOT_FOUND)]
    NotFound,
    /// The caller asked to build a target trusted CI has no runner for.
    /// Refused here so it can never become a dispatch: `build-crate.yml`
    /// resolves an unknown target to an empty `runs-on`, and the run then
    /// dies before any job starts, spending a queue slot and reporting
    /// nothing.
    #[error(
        "`{target}` is not a target this cache builds; supported: {supported}",
        status = BAD_REQUEST
    )]
    UnsupportedTarget {
        /// The target the caller asked for.
        target: String,
        /// The targets trusted CI can build, comma-separated.
        supported: String,
    },
    /// A request named a crate (or an exact version) crates.io does not
    /// publish; the message names it because the request page shows the
    /// body's `error` verbatim.
    #[error("crate `{crate_name}` is not published on crates.io", status = NOT_FOUND)]
    CrateNotPublished {
        /// The crate the caller asked for.
        crate_name: String,
    },
    /// The crate exists but the requested version does not (or every
    /// candidate is yanked or a prerelease).
    #[error("`{crate_name}` has no published {requested}", status = NOT_FOUND)]
    VersionNotPublished {
        /// The crate the caller asked for.
        crate_name: String,
        /// `version X.Y.Z` when one was asked for, else `stable release`.
        requested: String,
    },
    /// `GET /api/v1/requests/{task_id}` for a task the scheduler does not
    /// know: never enqueued, or already reaped.
    #[error("unknown request task id `{task_id}`", status = NOT_FOUND)]
    UnknownTask {
        /// The id from the request path.
        task_id: String,
    },
    /// The scheduler refused a completion report because its attempt no
    /// longer matches the queue row's live state — a stale report for a
    /// superseded attempt or a duplicate. The body is the scheduler's own
    /// message, which already names the task and both attempts.
    #[error("{0}", status = CONFLICT)]
    CompletionConflict(String),
    /// A register request's record set escapes the authority of the task
    /// the caller named — a record whose target or rustc version differs
    /// from the task's, or a `(crate, version)` outside the task's
    /// dependency closure. The message names the offending record.
    #[error("{0}", status = FORBIDDEN)]
    RegisterForbidden(String),
    /// A register request named a task that cannot accept records —
    /// unknown to the scheduler queue, or not in an in-flight
    /// (`dispatched`/`running`) state. A conflict, not a credential
    /// failure: the caller authenticated, the named work is just not the
    /// live row it claims.
    #[error("{0}", status = CONFLICT)]
    RegisterConflict(String),
    #[error("GHCR unavailable", status = BAD_GATEWAY)]
    GhcrUnavailable,
    /// GitHub (OIDC JWKS or the repo-permission API) could not be consulted
    /// — a 502 so CI retries instead of recording a permanent auth failure.
    /// The upstream reason stays in the worker log.
    #[error("github trust upstream unavailable", status = BAD_GATEWAY)]
    TrustUpstreamUnavailable,
    /// A request exceeded a documented edge limit. The message names the
    /// observed count and the limit — a client error (413 renders its
    /// message, 5xx does not), because retrying the same request can
    /// never help.
    #[error("{0}", status = PAYLOAD_TOO_LARGE)]
    TooLarge(String),
    /// The request is well-formed but the edge declines to process it —
    /// e.g. a `POST /api/v1/requests` dependency closure over
    /// `STOW_HUMAN_MAX_CLOSURE`. Retrying unchanged can never help.
    #[error("{0}", status = UNPROCESSABLE_ENTITY)]
    UnprocessableEntity(String),
    /// The scheduler refused a submit with 429 — on the human lane the
    /// daily task budget, on the miss lane the pending-depth cap.
    /// Handlers that know the retry semantics answer a `Retry-After`
    /// response instead; this status is the fallback for paths that
    /// surface the error as-is.
    #[error("{0}", status = TOO_MANY_REQUESTS)]
    SchedulerBusy(String),
    #[error("internal server error")]
    Internal,
    #[error("internal server error: {0}")]
    InternalWithMessage(String),
}

impl GetArtifactError {
    /// Render a [`Self::TurnstileRejected`] with the contract's
    /// `error-codes` body; every other variant passes through as `Err`
    /// for the shared `{"error": ...}` renderer.
    fn rejection_response(self) -> Result<Response, Self> {
        match self {
            Self::TurnstileRejected { error_codes } => {
                Ok(crate::turnstile::rejected_response(&error_codes))
            }
            other => Err(other),
        }
    }
}

impl From<crate::errors::SchedulerClientError> for GetArtifactError {
    fn from(error: crate::errors::SchedulerClientError) -> Self {
        match error {
            // A 429 is a capacity refusal — the queue-depth cap or the
            // human-lane daily budget — not a malformed request. The body
            // is the scheduler's own `{"error": ...}` JSON; unwrap it so
            // the message is not nested inside a second envelope.
            crate::errors::SchedulerClientError::Http {
                status: 429, body, ..
            } => Self::SchedulerBusy(scheduler_error_message(&body).to_owned()),
            // A 4xx from the scheduler is a client problem — e.g. a
            // completion report naming a task the queue never held — and
            // the body is the scheduler's own client-safe message, so it
            // reaches the reporter verbatim instead of as a bare 500.
            crate::errors::SchedulerClientError::Http { status, body, .. }
                if (400..500).contains(&status) =>
            {
                Self::BadRequestWithMessage(format!("scheduler rejected the report: {body}"))
            }
            other => Self::InternalWithMessage(other.to_string()),
        }
    }
}

impl From<crate::errors::DbError> for GetArtifactError {
    fn from(error: crate::errors::DbError) -> Self {
        Self::InternalWithMessage(error.to_string())
    }
}

impl From<crate::errors::ResolverError> for GetArtifactError {
    fn from(error: crate::errors::ResolverError) -> Self {
        match error {
            crate::errors::ResolverError::CrateNotPublished { crate_name } => {
                Self::CrateNotPublished { crate_name }
            }
            crate::errors::ResolverError::LimitExceeded { .. } => Self::TooLarge(error.to_string()),
            crate::errors::ResolverError::VersionNotPublished {
                crate_name,
                version,
            } => Self::VersionNotPublished {
                crate_name,
                requested: format!("version {version}"),
            },
            crate::errors::ResolverError::BadRequest(message) => {
                Self::BadRequestWithMessage(message)
            }
            other => Self::InternalWithMessage(other.to_string()),
        }
    }
}
