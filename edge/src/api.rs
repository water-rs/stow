use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use futures_util::stream::{self, StreamExt};
use skyzen::extract::{Extractor, Query};
use skyzen::header::HeaderValue;
use skyzen::routing::Params;
use skyzen::runtime::WorkerContext;
use skyzen::runtime::wasm::from_js_response;
use skyzen::utils::{Json, State};
use skyzen::{Body, Request, Response, StatusCode};
use skyzen_cloudflare::worker::{self, AnalyticsEngineDataset};
use skyzen_cloudflare::{CfCache, CfDurableNamespace};
use skyzen_services::Db;
use stow_types::api::{
    ArtifactIndexPage, ArtifactRecord, BatchArtifactRequest, BuildCompleteReport,
    CI_TARGET_TRIPLES, CrateRequest, CrateRequestOutcome, DependencyGraphRequest,
    DependencyGraphResponse, EnqueueAdmission, EnqueueTicket, QueueTaskStatus,
    RegisterArtifactsRequest, ResolveLockfileRequest, ResolveLockfileResponse,
    SemanticArtifactRequest,
};
use stow_types::bundle::{
    ArtifactBatchManifest, ArtifactBatchManifestEntry, STOW_BATCH_BUNDLE_MEDIA_TYPE,
    STOW_BATCH_BUNDLES_DIR, STOW_BATCH_MANIFEST_PATH, STOW_BUNDLE_MEDIA_TYPE,
};
use stow_types::identity::{CMetadata, CrateName, CrateVersion, TargetTriple, WireRustcVersion};
use tar::{Builder, Header};

use crate::db;
use crate::github_auth;
use crate::lookup_key::{SemanticLookupSurface, bundle_cache_key, exact_lookup_key};
use crate::miss_logger::{Miss, MissLog};
use crate::registry_auth::RegistryTokens;
use crate::turnstile::{CfTurnstileVerifier, TurnstileVerifier};
use crate::{
    admission, cache, catalog, crates_io, dependency_resolver, ghcr, miss_logger, register,
    scheduler, scheduler_client,
};

/// `POST /api/v1/artifacts/batch` hard caps: the response tar buffers
/// every fetched bundle in worker memory, so one request may name at
/// most this many entries and this many summed artifact bytes.
const MAX_BATCH_ENTRIES: usize = 64;
const MAX_BATCH_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

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
/// queue-depth scaling factor for proof-of-work difficulty
/// (`STOW_POW_DEPTH_PER_BIT`; 0 disables the depth scaling), the
/// difficulty floor (`STOW_POW_MIN_BITS`), and the pending-queue depth at
/// which `/api/v1/enqueue` stops accepting tickets
/// (`STOW_MAX_QUEUE_PENDING`).
#[derive(Debug, Clone)]
pub struct PowAdmission {
    pub challenge_secret: String,
    pub depth_per_bit: u32,
    /// Floor on minted and required proof-of-work difficulty — an enqueue
    /// is never free even on an empty queue.
    pub min_bits: u32,
    /// Pending-queue depth that refuses miss-lane tickets with 429.
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

/// Required `PoW` bits for freshly-minted admissions, derived from the
/// scheduler's current pending depth. A status hiccup degrades to the
/// `min_bits` floor rather than failing the miss response — a dead
/// scheduler cannot accept enqueues anyway, and the floor keeps the
/// ticket redeemable if the hiccup was transient.
async fn admission_difficulty(
    scheduler: &CfDurableNamespace,
    admission: &PowAdmission,
) -> Result<u32, GetArtifactError> {
    match scheduler_client::get_status(scheduler).await {
        Ok(status) => Ok(admission::difficulty_for_depth(
            status.pending,
            admission.depth_per_bit,
            admission.min_bits,
        )),
        Err(error) => {
            tracing::error!(%error, "failed to read scheduler queue depth for miss admissions");
            Ok(admission::difficulty_for_depth(
                0,
                admission.depth_per_bit,
                admission.min_bits,
            ))
        }
    }
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
        let source_json = scheduler::queue::source_json(request.project_source.as_ref())
            .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
        let task_id = scheduler::queue::task_id(
            request.crate_name.as_str(),
            &request.version.to_string(),
            request.features_json.raw().as_str(),
            request.target.as_str(),
            request.rustc_version.as_str(),
            &source_json,
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

/// 404 response whose body carries the admission the client redeems via
/// `/api/v1/enqueue` — a miss still reports "not found" to clients that
/// ignore the body.
fn admission_miss_response(admission: &EnqueueAdmission) -> Result<Response, GetArtifactError> {
    let mut response = Response::new(
        Body::from_json(admission)
            .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?,
    );
    *response.status_mut() = StatusCode::NOT_FOUND;
    response.headers_mut().insert(
        skyzen::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(response)
}

/// The bindings a semantic miss needs to mint its enqueue admission and
/// record the miss: the scheduler namespace, the proof-of-work admission
/// settings, resolver tuning, and the Analytics Engine dataset.
#[derive(Debug, Clone)]
pub struct MissAdmissionServices {
    pub scheduler: CfDurableNamespace,
    pub admission: PowAdmission,
    pub settings: crate::runtime_settings::ResolverSettings,
    pub analytics: AnalyticsEngineDataset,
}

impl Extractor for MissAdmissionServices {
    type Error = GetArtifactError;

    async fn extract(request: &mut Request) -> Result<Self, Self::Error> {
        let internal = |error: skyzen::utils::state::StateNotExist| {
            GetArtifactError::InternalWithMessage(error.to_string())
        };
        let State(scheduler) = State::<CfDurableNamespace>::extract(request)
            .await
            .map_err(internal)?;
        let State(admission) = State::<PowAdmission>::extract(request)
            .await
            .map_err(internal)?;
        let State(settings) = State::<crate::runtime_settings::ResolverSettings>::extract(request)
            .await
            .map_err(internal)?;
        let State(analytics) = State::<AnalyticsEngineDataset>::extract(request)
            .await
            .map_err(internal)?;
        Ok(Self {
            scheduler,
            admission,
            settings,
            analytics,
        })
    }
}

/// Mint the enqueue admission for one semantic miss: canonicalize the
/// request (dropping bogus feature seeds and versions crates.io does not
/// publish), then stamp it with a challenge binding it to this minute.
/// `None` means no canonical task exists — the caller reports a plain 404.
/// Every semantic miss funnels through here, so this is also where the
/// Analytics Engine point is written.
async fn semantic_miss_admission(
    db: &Db,
    services: &MissAdmissionServices,
    request: &SemanticArtifactRequest,
) -> Result<Option<EnqueueAdmission>, GetArtifactError> {
    let MissAdmissionServices {
        scheduler,
        admission,
        settings,
        analytics,
    } = services;
    let fetch_concurrency = settings.batch_fetch_concurrency;
    analytics.write_miss(&Miss::semantic(request));
    tracing::warn!(
        crate_name = %request.crate_name,
        version = %request.version,
        features_json = %request.features_json,
        target = %request.target,
        rustc_version = %request.rustc_version,
        profile = ?request.profile,
        emit = ?request.emit,
        kind = %request.kind.as_str(),
        crate_types = ?request.crate_types,
        "semantic artifact lookup miss"
    );
    let canonical = dependency_resolver::canonicalize_enqueue_requests(
        db,
        &crates_io::CfCratesIo,
        vec![stow_types::api::EnqueueRequest {
            crate_name: request.crate_name.clone(),
            version: request.version.clone(),
            features_json: request.features_json.clone(),
            target: request.target.clone(),
            rustc_version: request.rustc_version.clone(),
            downloads: 0,
            source: stow_types::api::EnqueueSource::CacheMiss,
            depends_on: Vec::new(),
            preserve_lockfile: false,
            project_source: None,
        }],
        fetch_concurrency,
    )
    .await?;
    let Some(request) = canonical.into_iter().next() else {
        return Ok(None);
    };
    let difficulty = admission_difficulty(scheduler, admission).await?;
    let mut admissions = mint_admissions(admission, vec![request], difficulty)?;
    Ok(admissions.pop())
}

/// POST /api/v1/catalog/resolve-lockfile
///
/// Active stow resolver: synthesize a complete `Cargo.lock` whose every
/// `[[package]]` entry corresponds to a cached artifact. The user submits
/// only their direct deps (with semver requirements + features); we walk
/// the artifacts table greedily, pinning each direct dep to a cached
/// (version, features, `c_metadata`) that satisfies the user's req, then
/// extending the closure by walking each pinned artifact's
/// `dependency_c_metadata_json` to fix the (name, `c_metadata`) of every
/// transitive. On conflict (two paths require different `c_metadata` for
/// the same crate name) we backtrack to a different candidate. When no
/// consistent assignment exists we return `lockfile_toml: None` and the
/// CLI falls back to cargo's own resolver.
///
/// Public endpoint — read-only over cache contents.
pub async fn resolve_lockfile(
    Json(request): Json<ResolveLockfileRequest>,
    db: Db,
) -> Result<Json<ResolveLockfileResponse>, GetArtifactError> {
    let outcome = crate::resolver::run_stow_resolver(&db, &request)
        .await
        .map_err(GetArtifactError::from)?;
    Ok(Json(outcome))
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
/// `project_source` checkout or a `preserve_lockfile` overlay) gets
/// `closure: None`: a fresh crates.io expansion would resolve different
/// versions than the pinned lockfile and reject legitimate records, so
/// the binding narrows to the task's target/rustc identity and the source
/// is logged.
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
    } else if task.uses_source_lockfile() {
        if let Some(source) = &task.project_source {
            tracing::info!(
                task_id = %task.task_id,
                project_url = %source.url,
                commit = %source.commit,
                "register bound to a project-source task; crates.io closure check skipped"
            );
        } else {
            tracing::info!(
                task_id = %task.task_id,
                "register bound to a lockfile-pinned task; crates.io closure check skipped"
            );
        }
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
    query: Option<Query<UnbundledQuery>>,
    db: Db,
) -> Result<Json<Vec<ArtifactRecord>>, GetArtifactError> {
    let limit = query
        .and_then(|Query(query)| query.limit)
        .unwrap_or(DEFAULT_UNBUNDLED_LIMIT);
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
    query: Option<Query<IndexQuery>>,
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
    let (after, limit) = match query {
        Some(Query(query)) => (query.after, query.limit.unwrap_or(DEFAULT_INDEX_LIMIT)),
        None => (None, DEFAULT_INDEX_LIMIT),
    };
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

/// Registration is an upsert — a rebuilt artifact overwrites the row for
/// its identity, so every cached lookup that could still resolve
/// to the old row is deleted: the exact key directly, plus the semantic
/// key rebuilt from the record's own request surface.
async fn invalidate_lookup_entries(cache: &CfCache, record: &ArtifactRecord) {
    for key in [
        exact_lookup_key(
            record.target.as_str(),
            record.rustc_version.as_str(),
            record.c_metadata.as_str(),
        ),
        SemanticLookupSurface::from(record).key(),
    ] {
        if let Err(error) = cache::delete_lookup(cache, &key).await {
            tracing::warn!(%error, key = %key, "failed to invalidate artifact lookup cache entry");
        }
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
) -> Result<Json<OkResponse>, GetArtifactError> {
    let requests = dependency_resolver::canonicalize_enqueue_requests(
        &db,
        &crates_io::CfCratesIo,
        requests,
        settings.batch_fetch_concurrency,
    )
    .await?;
    // RepoWriter submissions are exempt from the pending-depth cap — the
    // credential check is the bound on this path.
    scheduler_client::send_enqueue_trusted(&scheduler, &requests).await?;
    tracing::info!(tasks = requests.len(), %caller, "submitted scheduler tasks");
    Ok(Json(OkResponse { ok: true }))
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
            // Resolved-lockfile plans always enqueue crates.io tarball tasks.
            "",
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
}

/// GET /`api/v1/artifacts/{target}/{rustc_version}/{c_metadata}?crate=serde`
///
/// Returns the complete artifact bundle for one crate compilation unit.
///
/// Flow:
/// 1. Lookup-cache check for the artifact row (free, per-datacenter) — a
///    hit skips D1 entirely
/// 2. Lookup miss → schema-ensured D1 read, row written back to the
///    lookup cache; a real miss is never cached
/// 3. Bundle bytes: CF Cache hit → return; miss → fetch from GHCR, tee
///    into CF Cache
/// 4. Stale GHCR fetch → prune the D1 row and the lookup entry, then 404
/// 5. D1 miss → validate `crate_name`, log miss, return 404
pub async fn get_artifact(
    params: Params,
    query: Option<Query<ArtifactQuery>>,
    db: Db,
    streams: BundleStreams,
    State(analytics): State<AnalyticsEngineDataset>,
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

    let artifact_row = resolve_exact_row(&db, &cache, c_metadata, target, rustc_version).await?;

    let Some(row) = artifact_row else {
        // 404 IS the miss event. Log it server-side.
        log_exact_miss(&analytics, query.as_ref(), target, rustc_version);
        return Err(GetArtifactError::NotFound);
    };
    let cache_key = bundle_cache_key(target, rustc_version, &row.bundle_digest);

    match open_bundle_stream(&context, &cache, &ghcr, &cache_key, &row).await {
        Ok((body, cache_hit)) => Ok(bundle_response(body, row.bundle_size, cache_hit)),
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
            log_exact_miss(&analytics, query.as_ref(), target, rustc_version);
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

    let artifact_row = resolve_exact_row(&db, &cache, c_metadata, target, rustc_version).await?;

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

/// POST /api/v1/artifacts/semantic
pub async fn get_semantic_artifact(
    Json(request): Json<SemanticArtifactRequest>,
    db: Db,
    streams: BundleStreams,
    services: MissAdmissionServices,
) -> Result<Response, GetArtifactError> {
    let BundleStreams {
        context,
        cache,
        ghcr,
    } = streams;
    let row = resolve_semantic_row(&db, &cache, &request).await?;
    let Some(row) = row else {
        // The miss response carries the enqueue admission — a crates.io or
        // scheduler hiccup during minting must not turn a plain cache miss
        // into a 500, so failures degrade to a bare 404.
        return match semantic_miss_admission(&db, &services, &request).await {
            Ok(Some(ticket)) => admission_miss_response(&ticket),
            Ok(None) => Err(GetArtifactError::NotFound),
            Err(error) => {
                tracing::error!(%error, "failed to mint enqueue admission for semantic miss");
                Err(GetArtifactError::NotFound)
            }
        };
    };
    let cache_key = bundle_cache_key(
        request.target.as_str(),
        request.rustc_version.as_str(),
        &row.bundle_digest,
    );

    let (body, cache_hit) = match open_bundle_stream(&context, &cache, &ghcr, &cache_key, &row)
        .await
    {
        Ok(result) => result,
        Err(error) if error.indicates_stale_artifact() => {
            // The row may have come from the lookup cache, skipping the
            // Drop this request's own lookup entry so it cannot keep
            // resolving to the dead row.
            if let Err(delete_error) =
                cache::delete_lookup(&cache, &SemanticLookupSurface::from(&request).key()).await
            {
                tracing::warn!(%delete_error, "failed to delete semantic lookup entry for stale row");
            }
            prune_stale_artifact_row(
                &db,
                &cache,
                &row.c_metadata,
                request.target.as_str(),
                request.rustc_version.as_str(),
            )
            .await?;
            return match semantic_miss_admission(&db, &services, &request).await {
                Ok(Some(ticket)) => admission_miss_response(&ticket),
                Ok(None) => Err(GetArtifactError::NotFound),
                Err(error) => {
                    tracing::error!(%error, "failed to mint enqueue admission for semantic miss");
                    Err(GetArtifactError::NotFound)
                }
            };
        }
        Err(error) => {
            tracing::error!(%error, "semantic GHCR fetch failed");
            return Err(GetArtifactError::InternalWithMessage(error.to_string()));
        }
    };

    Ok(bundle_response(body, row.bundle_size, cache_hit))
}

/// POST /api/v1/artifacts/batch
///
/// Hard caps keep one request from pinning the worker: at most
/// [`MAX_BATCH_ENTRIES`] entries and [`MAX_BATCH_ARTIFACT_BYTES`] of
/// summed bundle size (the rows' `bundle_size`, checked before any GHCR
/// fetch — every served bundle is buffered for the response tar).
pub async fn get_artifact_batch(
    Json(request): Json<BatchArtifactRequest>,
    db: Db,
    streams: BundleStreams,
    State(settings): State<crate::runtime_settings::ResolverSettings>,
) -> Result<Response, GetArtifactError> {
    let BundleStreams {
        context,
        cache,
        ghcr,
    } = streams;
    if request.entries.len() > MAX_BATCH_ENTRIES {
        return Err(GetArtifactError::TooLarge(format!(
            "batch artifact request has {} entries; the limit is {MAX_BATCH_ENTRIES}",
            request.entries.len()
        )));
    }
    validate_batch_request(&request).map_err(|error| {
        tracing::warn!(%error, "invalid batch artifact request");
        GetArtifactError::BadRequest
    })?;

    let rows_by_metadata = batch_artifact_rows(&db, &request).await?;
    let total_bytes = rows_by_metadata
        .values()
        .fold(0_u64, |sum, row| sum.saturating_add(row.bundle_size));
    if total_bytes > MAX_BATCH_ARTIFACT_BYTES {
        return Err(GetArtifactError::TooLarge(format!(
            "batch artifacts total {total_bytes} bytes; the limit is {MAX_BATCH_ARTIFACT_BYTES}"
        )));
    }
    let fetch_results = stream::iter(request.entries.iter().cloned().enumerate())
        .map(|(index, entry)| {
            let row = rows_by_metadata.get(entry.c_metadata.as_str()).cloned();
            fetch_batch_entry(index, entry, row, &request, &context, &cache, &ghcr)
        })
        .buffer_unordered(settings.batch_fetch_concurrency)
        .collect::<Vec<_>>()
        .await;
    let (manifest_entries, fetched_bundles) =
        collect_batch_results(&db, &cache, &request, fetch_results).await?;
    assemble_batch_response(&request, manifest_entries, fetched_bundles)
}

/// Load every requested artifact row in one IN-clause query, keyed by
/// `c_metadata` for the per-entry lookup during the parallel fetch.
async fn batch_artifact_rows(
    db: &Db,
    request: &BatchArtifactRequest,
) -> Result<BTreeMap<String, db::ExactArtifactRow>, GetArtifactError> {
    let c_metadatas = request
        .entries
        .iter()
        .map(|entry| entry.c_metadata.as_str().to_owned())
        .collect::<Vec<_>>();
    let rows = db::get_artifact_references(
        db,
        &c_metadatas,
        request.target.as_str(),
        request.rustc_version.as_str(),
    )
    .await
    .map_err(|error| {
        tracing::error!(%error, "batch artifact D1 query failed");
        GetArtifactError::Internal
    })?;
    Ok(rows
        .into_iter()
        .map(|row| (row.c_metadata.clone(), row))
        .collect())
}

/// Manifest slot for a batch entry whose bundle could not be served.
fn absent_manifest_entry(
    entry: stow_types::api::BatchArtifactRequestEntry,
) -> ArtifactBatchManifestEntry {
    ArtifactBatchManifestEntry {
        crate_name: entry.crate_name,
        c_metadata: entry.c_metadata,
        bundle_path: None,
    }
}

/// Fetch one batch entry through the CF-cache → GHCR path. Every upstream
/// failure degrades to a manifest entry rather than failing the batch:
/// `Stale` additionally reports the row's `c_metadata` so the caller can
/// prune it from D1.
async fn fetch_batch_entry(
    index: usize,
    entry: stow_types::api::BatchArtifactRequestEntry,
    row: Option<db::ExactArtifactRow>,
    request: &BatchArtifactRequest,
    context: &WorkerContext,
    cache: &CfCache,
    ghcr: &GhcrConfig,
) -> BatchFetchResult {
    let Some(row) = row else {
        return BatchFetchResult::Missing {
            index,
            manifest_entry: absent_manifest_entry(entry),
        };
    };

    let cache_key = bundle_cache_key(
        request.target.as_str(),
        request.rustc_version.as_str(),
        &row.bundle_digest,
    );
    let bundle_path = batch_bundle_path(entry.c_metadata.as_str());
    // The batch tar is assembled in memory, so this path buffers the
    // streamed bundle; the per-artifact GET never does.
    let bundle_bytes = match open_bundle_stream(context, cache, ghcr, &cache_key, &row).await {
        Ok((body, _)) => match body.into_bytes().await {
            Ok(bytes) => bytes.to_vec(),
            Err(error) => {
                tracing::warn!(
                    %error,
                    crate_name = %entry.crate_name,
                    c_metadata = %entry.c_metadata,
                    "batch bundle stream ended early; treating as miss"
                );
                return BatchFetchResult::Missing {
                    index,
                    manifest_entry: absent_manifest_entry(entry),
                };
            }
        },
        Err(error) if error.indicates_stale_artifact() => {
            tracing::warn!(
                error = %error,
                crate_name = %entry.crate_name,
                c_metadata = %entry.c_metadata,
                "batch artifact was registered in D1 but stale in GHCR; pruning stale row"
            );
            return BatchFetchResult::Stale {
                index,
                c_metadata: entry.c_metadata.as_str().to_owned(),
                manifest_entry: absent_manifest_entry(entry),
            };
        }
        Err(ghcr::FetchError::Unavailable) => {
            tracing::warn!(
                crate_name = %entry.crate_name,
                c_metadata = %entry.c_metadata,
                "batch artifact fetch was temporarily unavailable; treating as miss"
            );
            return BatchFetchResult::Missing {
                index,
                manifest_entry: absent_manifest_entry(entry),
            };
        }
        Err(error) => {
            tracing::warn!(
                %error,
                crate_name = %entry.crate_name,
                c_metadata = %entry.c_metadata,
                "batch artifact fetch failed; treating as miss"
            );
            return BatchFetchResult::Missing {
                index,
                manifest_entry: absent_manifest_entry(entry),
            };
        }
    };

    BatchFetchResult::Present {
        index,
        manifest_entry: ArtifactBatchManifestEntry {
            crate_name: entry.crate_name,
            c_metadata: entry.c_metadata,
            bundle_path: Some(bundle_path.clone()),
        },
        bundle_path,
        bundle_bytes,
    }
}

/// Fold per-entry fetch outcomes into manifest slots and bundle payloads,
/// pruning the D1 rows the registry proved stale.
async fn collect_batch_results(
    db: &Db,
    cache: &CfCache,
    request: &BatchArtifactRequest,
    fetch_results: Vec<BatchFetchResult>,
) -> Result<
    (
        Vec<Option<ArtifactBatchManifestEntry>>,
        Vec<(usize, String, Vec<u8>)>,
    ),
    GetArtifactError,
> {
    let mut manifest_entries = vec![None::<ArtifactBatchManifestEntry>; request.entries.len()];
    let mut fetched_bundles = Vec::<(usize, String, Vec<u8>)>::new();
    for fetch_result in fetch_results {
        match fetch_result {
            BatchFetchResult::Missing {
                index,
                manifest_entry,
            } => {
                manifest_entries[index] = Some(manifest_entry);
            }
            BatchFetchResult::Present {
                index,
                manifest_entry,
                bundle_path,
                bundle_bytes,
            } => {
                manifest_entries[index] = Some(manifest_entry);
                fetched_bundles.push((index, bundle_path, bundle_bytes));
            }
            BatchFetchResult::Stale {
                index,
                c_metadata,
                manifest_entry,
            } => {
                prune_stale_artifact_row(
                    db,
                    cache,
                    &c_metadata,
                    request.target.as_str(),
                    request.rustc_version.as_str(),
                )
                .await?;
                manifest_entries[index] = Some(manifest_entry);
            }
        }
    }
    Ok((manifest_entries, fetched_bundles))
}

/// Assemble the response tar: bundle payloads in request order followed
/// by the JSON manifest the CLI reads to map each entry.
fn assemble_batch_response(
    request: &BatchArtifactRequest,
    manifest_entries: Vec<Option<ArtifactBatchManifestEntry>>,
    mut fetched_bundles: Vec<(usize, String, Vec<u8>)>,
) -> Result<Response, GetArtifactError> {
    fetched_bundles.sort_by_key(|(index, _, _)| *index);
    let mut tar = Builder::new(Vec::new());
    for (_index, bundle_path, bundle_bytes) in fetched_bundles {
        append_bytes(&mut tar, &bundle_path, &bundle_bytes).map_err(|error| {
            tracing::error!(%error, bundle_path = %bundle_path, "batch tar assembly failed");
            GetArtifactError::Internal
        })?;
    }

    let manifest = ArtifactBatchManifest {
        target: request.target.clone(),
        rustc_version: request.rustc_version.clone(),
        entries: manifest_entries
            .into_iter()
            .map(|entry| {
                entry.ok_or_else(|| {
                    tracing::error!("batch artifact manifest entry was not populated");
                    GetArtifactError::Internal
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|error| {
        tracing::error!(%error, "serialize batch artifact manifest failed");
        GetArtifactError::Internal
    })?;
    append_bytes(&mut tar, STOW_BATCH_MANIFEST_PATH, &manifest_bytes).map_err(|error| {
        tracing::error!(%error, "append batch artifact manifest failed");
        GetArtifactError::Internal
    })?;
    let body = tar.into_inner().map_err(|error| {
        tracing::error!(%error, "finalize batch artifact archive failed");
        GetArtifactError::Internal
    })?;

    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        "content-type",
        HeaderValue::from_static(STOW_BATCH_BUNDLE_MEDIA_TYPE),
    );
    Ok(response)
}

enum BatchFetchResult {
    Missing {
        index: usize,
        manifest_entry: ArtifactBatchManifestEntry,
    },
    Stale {
        index: usize,
        c_metadata: String,
        manifest_entry: ArtifactBatchManifestEntry,
    },
    Present {
        index: usize,
        manifest_entry: ArtifactBatchManifestEntry,
        bundle_path: String,
        bundle_bytes: Vec<u8>,
    },
}

/// POST /api/v1/catalog/graph
pub async fn analyze_dependency_graph(
    Json(request): Json<DependencyGraphRequest>,
    db: Db,
    State(scheduler): State<CfDurableNamespace>,
    State(admission): State<PowAdmission>,
    State(settings): State<crate::runtime_settings::ResolverSettings>,
    State(analytics): State<AnalyticsEngineDataset>,
) -> Result<Json<DependencyGraphResponse>, GetArtifactError> {
    // Worst-case subrequests for `max_expanded_tasks` (4096) direct
    // entries, every one cache-cold, and 4096 expanded misses:
    //   ceil(4096/49) =   84  crate_version_graph_cache read batches
    //   ≤ 4096        = 4096  sparse-index fetches (one per cold crate)
    //   ceil(4096/33) =  125  crate_version_graph_cache upsert batches
    //   ceil(4096/64) =   64  artifact-catalog reads for direct entries
    //   ceil(4096/64) =   64  expanded-graph artifact reads (chain
    //                          completion adds its referenced rows)
    //                      ~70  admitted-miss drain statements
    //   ≈ 4.5k total — inside the paid Worker's 10,000-subrequest budget
    //   (Cloudflare raised the old 1,000 cap in Feb 2026), and the ~400
    //   D1 statements among them stay under D1's own 1,000-queries-per-
    //   invocation limit. Misses themselves cost Analytics Engine data
    //   points, not D1 writes.
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
    let outcome = db::analyze_dependency_graph(
        &db,
        &crates_io::CfCratesIo,
        request.target.as_str(),
        request.rustc_version.as_str(),
        &request.entries,
        &request.expanded_entries,
        settings.batch_fetch_concurrency,
    )
    .await
    .map_err(|error| {
        tracing::error!(%error, "dependency graph analysis failed");
        GetArtifactError::InternalWithMessage(error.to_string())
    })?;
    let db::DependencyGraphAnalysisOutcome {
        mut response,
        enqueue_requests,
    } = outcome;

    // One Analytics Engine point per uncovered node — demand analytics
    // stay off the D1 row-write meter.
    miss_logger::log_graph_misses(&analytics, &enqueue_requests);

    // The fetch path never enqueues directly: each miss gets an admission
    // the client redeems through the PoW gate, and minting hiccups degrade
    // to "no admissions" rather than failing the analysis response. A
    // fully-cached analysis has no misses to mint and admits nothing new to
    // drain, so it skips the scheduler round-trip entirely — the status
    // fetch and misses-table scan are pure overhead on a cache hit.
    if !enqueue_requests.is_empty() {
        let difficulty = admission_difficulty(&scheduler, &admission).await?;
        response.miss_admissions = match mint_admissions(&admission, enqueue_requests, difficulty) {
            Ok(admissions) => admissions,
            Err(error) => {
                tracing::error!(%error, "failed to mint dependency-graph miss admissions");
                Vec::new()
            }
        };
        drain_admitted_misses(&db, &scheduler).await;
    }

    Ok(Json(response))
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
    let ticket_source_json = scheduler::queue::source_json(ticket.request.project_source.as_ref())
        .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
    let derived_task_id = scheduler::queue::task_id(
        ticket.request.crate_name.as_str(),
        &ticket.request.version.to_string(),
        ticket.request.features_json.raw().as_str(),
        ticket.request.target.as_str(),
        ticket.request.rustc_version.as_str(),
        &ticket_source_json,
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
    let required =
        admission::required_difficulty(status.pending, admission.depth_per_bit, admission.min_bits);
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

fn validate_batch_request(request: &BatchArtifactRequest) -> Result<(), String> {
    if request.entries.is_empty() {
        return Err("batch artifact request entries cannot be empty".to_owned());
    }
    let mut seen = BTreeSet::<&str>::new();
    for entry in &request.entries {
        // CrateName is non-empty by construction (parsed at deserialize time).
        if !seen.insert(entry.c_metadata.as_str()) {
            return Err(format!(
                "batch artifact request contains duplicate c_metadata {}",
                entry.c_metadata
            ));
        }
    }
    Ok(())
}

/// Resolve the artifact row for an exact `(c_metadata, target,
/// rustc_version)` identity, CF-cache-first so warm hits never touch D1.
/// A lookup miss falls through to a schema-ensured D1 read whose result
/// is written back to the lookup cache; a real `None` (404) is never
/// cached — misses drive admission and must stay fresh.
async fn resolve_exact_row(
    db: &Db,
    cache: &CfCache,
    c_metadata: &str,
    target: &str,
    rustc_version: &str,
) -> Result<Option<db::ArtifactRow>, GetArtifactError> {
    let lookup_key = exact_lookup_key(target, rustc_version, c_metadata);
    match cache::get_lookup(cache, &lookup_key).await {
        Ok(Some(row)) => return Ok(Some(row)),
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

/// Same CF-cache-first resolution for the semantic path: the lookup key
/// covers the full request surface, and the D1 fallback logs with the
/// same detail the handler used to carry.
async fn resolve_semantic_row(
    db: &Db,
    cache: &CfCache,
    request: &SemanticArtifactRequest,
) -> Result<Option<db::ArtifactRow>, GetArtifactError> {
    let lookup_key = SemanticLookupSurface::from(request).key();
    match cache::get_lookup(cache, &lookup_key).await {
        Ok(Some(row)) => return Ok(Some(row)),
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(%error, key = %lookup_key, "cf lookup cache read failed; falling back to D1");
        }
    }
    let row = db::get_semantic_artifact_reference(db, request)
        .await
        .map_err(|error| {
            tracing::error!(
                %error,
                crate_name = %request.crate_name,
                version = %request.version,
                features_json = %request.features_json,
                target = %request.target,
                rustc_version = %request.rustc_version,
                profile = ?request.profile,
                emit = ?request.emit,
                kind = %request.kind.as_str(),
                crate_types = ?request.crate_types,
                "semantic D1 query failed"
            );
            GetArtifactError::InternalWithMessage(error.to_string())
        })?;
    if let Some(row) = &row
        && let Err(error) = cache::put_lookup(cache, &lookup_key, row).await
    {
        tracing::warn!(%error, key = %lookup_key, "cf lookup cache write failed");
    }
    Ok(row)
}

/// A row the byte path can stream from: any of the artifact row shapes,
/// reduced to the registry coordinates of its published bundle.
pub trait BundleSource {
    fn oci_reference(&self) -> &str;
    fn bundle_digest(&self) -> &str;
    fn bundle_size(&self) -> u64;
}

impl BundleSource for db::ArtifactRow {
    fn oci_reference(&self) -> &str {
        &self.oci_reference
    }
    fn bundle_digest(&self) -> &str {
        &self.bundle_digest
    }
    fn bundle_size(&self) -> u64 {
        self.bundle_size
    }
}

impl BundleSource for db::ExactArtifactRow {
    fn oci_reference(&self) -> &str {
        &self.oci_reference
    }
    fn bundle_digest(&self) -> &str {
        &self.bundle_digest
    }
    fn bundle_size(&self) -> u64 {
        self.bundle_size
    }
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
    row: &(impl BundleSource + Sync),
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

    let repository = oci_repository(row.oci_reference()).map_err(|error| {
        tracing::error!(%error, "refusing GHCR fetch for malformed OCI reference");
        ghcr::FetchError::InvalidRequest(error.to_string())
    })?;
    let mut upstream = ghcr::open_blob(
        &ghcr.base_url,
        repository,
        row.bundle_digest(),
        &ghcr.tokens,
    )
    .await
    .map_err(|error| {
        tracing::error!(
            cache_key = %cache_key,
            oci_reference = %row.oci_reference(),
            bundle_digest = %row.bundle_digest(),
            error = %error,
            "edge failed to open bundle blob from registry"
        );
        error
    })?;

    if cache::fits_cache(row.bundle_size()) {
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

fn batch_bundle_path(c_metadata: &str) -> String {
    format!("{STOW_BATCH_BUNDLES_DIR}/{c_metadata}.tar")
}

fn append_bytes(tar: &mut Builder<Vec<u8>>, path: &str, bytes: &[u8]) -> Result<(), String> {
    let mut header = Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, path, Cursor::new(bytes))
        .map_err(|error| format!("append batch tar entry {path}: {error}"))
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
    query: Option<&Query<ArtifactQuery>>,
    target: &str,
    rustc_version: &str,
) {
    if let Some(Query(q)) = query
        && let Some(ref crate_name) = q.crate_name
        && let Ok(crate_name) = crate_name.parse::<CrateName>()
    {
        analytics.write_miss(&Miss::exact(&crate_name, target, rustc_version));
    }
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
