use std::collections::BTreeMap;

use skyzen::extract::{Extractor, Query};
use skyzen::header::HeaderValue;
use skyzen::routing::Params;
use skyzen::runtime::wasm::from_js_response;
use skyzen::utils::{Json, State};
use skyzen::{Body, Request, Response, StatusCode};
use skyzen_cloudflare::worker::send::IntoSendFuture as _;
use skyzen_cloudflare::worker::{self, AnalyticsEngineDataset};
use skyzen_cloudflare::{CfCache, CfDurableNamespace};
use skyzen_services::Db;
use stow_types::admission;
use stow_types::api::{
    AdmissionRequest, ArtifactIndexPage, ArtifactRecord, CI_TARGET_TRIPLES, CrateRequest,
    EnqueueAdmission, EnqueueTicket,
};
use stow_types::bundle::STOW_BUNDLE_MEDIA_TYPE;
use stow_types::identity::{CMetadata, CrateName, CrateVersion, TargetTriple, WireRustcVersion};

use crate::db;
use crate::errors::GetArtifactError;
use crate::fetch_guard::OutboundPool;
use crate::github_auth;
use crate::registry_auth::RegistryTokens;
use crate::turnstile::{CfTurnstileVerifier, TurnstileVerifier};
use crate::{
    catalog, crates_io, dependency_resolver, ghcr, index_slice, miss_logger, rust_channel,
    scheduler, scheduler_client, stats,
};

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct OkResponse {
    pub ok: bool,
}

/// Marker that the request's `Authorization: Bearer` credential cleared the
/// GitHub trust check: a GitHub Actions OIDC token minted inside the
/// trusted repo, or any credential with push access to it (`stow-admin`,
/// local dev, CI `GITHUB_TOKEN`).
///
/// Verifying inside the extractor — rather than in the handler body —
/// rejects unauthorized requests *before* `Json` deserializes a
/// potentially large body.
#[derive(Debug, Clone)]
pub struct SchedulerCaller(pub github_auth::TrustedCaller);

impl Extractor for SchedulerCaller {
    type Error = GetArtifactError;

    async fn extract(request: &mut Request) -> Result<Self, Self::Error> {
        extract_trusted_caller(request).await.map(Self)
    }
}

/// Pull the bearer credential off `Authorization` and authenticate it
/// against GitHub. Upstream failures (JWKS, repo-permission
/// API) surface as `TrustUpstreamUnavailable` — a 502 the CI retries —
/// rather than a 401 that would look like a credential problem.
async fn extract_trusted_caller(
    request: &mut Request,
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
    let push_verdicts = State::<github_auth::PushVerdicts>::extract(request)
        .await
        .map_err(|_| {
            GetArtifactError::InternalWithMessage("push verdict cache state missing".to_owned())
        })?;
    github_auth::authenticate(
        &config,
        &github_auth::CfGitHubTrust::new(OutboundPool::new()),
        &jwks,
        &push_verdicts,
        &bearer,
        now_unix(),
    )
    .await
    .map_err(|error| match error {
        github_auth::AuthError::Unauthorized => GetArtifactError::Unauthorized,
        github_auth::AuthError::RateLimited { retry_after_secs } => {
            request
                .extensions_mut()
                .insert(github_auth::TrustRateLimited { retry_after_secs });
            GetArtifactError::TrustUpstreamRateLimited
        }
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
        let task_id = request.task_id().map_err(|error| {
            GetArtifactError::BadRequestWithMessage(format!("enqueue task id: {error}"))
        })?;
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

/// POST /api/v1/admin/artifacts/sync — the D1 sync step of
/// `index-publish.yml` (stow#455).
///
/// GHCR's records artifacts are the only record store; `artifacts` rows
/// exist only to serve lookups, and they are written here by the sync
/// step replaying the verified records it pulled — never by the build
/// itself. The caller is a repo-writer credential (the workflow's
/// `GITHUB_TOKEN` or an operator's token), so no task binding applies:
/// the records' provenance was already proven by cosign verification
/// before they were ever sent here.
pub async fn sync_artifacts(
    _caller: SchedulerCaller,
    Json(records): Json<Vec<ArtifactRecord>>,
    db: Db,
) -> Result<Json<OkResponse>, GetArtifactError> {
    let count = records.len();
    db::insert_artifact_records(&db, &records).await?;
    tracing::info!(synced = count, "synced GHCR artifact records into D1");
    Ok(Json(OkResponse { ok: true }))
}

/// GET /api/v1/admin/dispatch-freeze
///
/// The dispatch freeze's current state — flag plus the stored record
/// (trigger, notify outcome) — read straight from the scheduler Durable
/// Object. No cache entry rides this flag: unlike the WAF maintenance
/// rules it only gates dispatch inside the object and the trusted lanes
/// that talk to it.
pub async fn get_dispatch_freeze(
    SchedulerCaller(_caller): SchedulerCaller,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::DispatchFreeze>, GetArtifactError> {
    Ok(Json(
        scheduler_client::get_dispatch_freeze(&scheduler).await?,
    ))
}

/// POST /api/v1/admin/dispatch-freeze
///
/// The manual transition that is also the freeze's only recovery path —
/// clearing it resumes dispatch of everything that queued meanwhile.
pub async fn set_dispatch_freeze(
    SchedulerCaller(caller): SchedulerCaller,
    Json(switch): Json<stow_types::api::DispatchFreeze>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::DispatchFreeze>, GetArtifactError> {
    let stored = scheduler_client::set_dispatch_freeze(&scheduler, switch.enabled).await?;
    tracing::warn!(enabled = stored.enabled, %caller, "dispatch freeze flipped via admin endpoint");
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
/// [`stow_types::index::ArtifactIndex`]. `SchedulerCaller` (repo-writer):
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

/// POST /`api/v1/admin/index/{target}/{rustc_version}`
///
/// The index-publish path's report that this slice went live, carrying
/// the semantic identities the signed index serves — recorded inside the
/// scheduler as the membership the dependency gate checks a dependent's
/// edges against. Same `SchedulerCaller` (repo-writer) trust as the page
/// reads: the index-publish workflow mints its token inside the trusted
/// repo.
pub async fn record_published_index(
    SchedulerCaller(caller): SchedulerCaller,
    params: Params,
    State(scheduler): State<CfDurableNamespace>,
    Json(report): Json<stow_types::api::PublishedSliceReport>,
) -> Result<Json<OkResponse>, GetArtifactError> {
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
    let rows = report.added.len() + report.retired.len();
    scheduler_client::record_published_index(
        &scheduler,
        &stow_types::api::PublishedSlice {
            target: target.clone(),
            rustc_version: rustc_version.clone(),
            base_generation: report.base_generation,
            generation: report.generation,
            added: report.added,
            retired: report.retired,
        },
    )
    .await?;
    tracing::info!(
        rows,
        %caller,
        %target,
        %rustc_version,
        "recorded a published index slice"
    );
    Ok(Json(OkResponse { ok: true }))
}

// ===== Operations API (`stow-admin`, `/api/v1/admin/*`) =====

/// GET /api/v1/admin/status
///
/// The scheduler's operator view: lane depths, the oldest pending row's
/// age, in-flight builds with their GitHub run ids, per-target outcomes
/// over the trailing 24 hours.
pub async fn admin_status(
    SchedulerCaller(_caller): SchedulerCaller,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::AdminStatus>, GetArtifactError> {
    Ok(Json(scheduler_client::admin_status(&scheduler).await?))
}

/// `POST /api/v1/admin/scheduler/migrate`
///
/// Run the scheduler Durable Object's schema migration — the only code
/// path that may issue DDL on its database. `deploy-edge.yml` calls it
/// right after `skyzen deploy` (migrations are additive, so the previous
/// build keeps serving while they apply); `stow-admin scheduler
/// migrate` is the manual path. Reports the schema version before and
/// after.
pub async fn admin_scheduler_migrate(
    SchedulerCaller(caller): SchedulerCaller,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::SchemaMigrationReport>, GetArtifactError> {
    let report = scheduler_client::migrate_scheduler(&scheduler).await?;
    tracing::warn!(
        before = report.before,
        after = report.after,
        %caller,
        "scheduler schema migrated via admin endpoint"
    );
    Ok(Json(report))
}

/// `POST /api/v1/admin/scheduler/budget/seed`
///
/// Seed the production-shaped fixture into the scheduler Durable Object —
/// the workerd cost harness's load step (stow#433). The object 404s
/// unless the deploy carries `STOW_SCHEDULER_BUDGET=1`, which only the
/// mock stack does.
pub async fn admin_scheduler_budget_seed(
    SchedulerCaller(_caller): SchedulerCaller,
    State(scheduler): State<CfDurableNamespace>,
    Json(request): Json<stow_types::api::SchedulerSeedRequest>,
) -> Result<Json<stow_types::api::SchedulerSeedReport>, GetArtifactError> {
    Ok(Json(
        scheduler_client::seed_budget_fixture(&scheduler, &request).await?,
    ))
}

/// `POST /api/v1/admin/scheduler/budget`
///
/// Measure every scheduler route and the alarm pass with the Durable
/// Object's real `rowsRead`/`rowsWritten` cursor counters — the numbers
/// Cloudflare bills on, and the budget the merge gate enforces
/// (stow#433). Same deploy-var guard as the seed route.
pub async fn admin_scheduler_budget(
    SchedulerCaller(_caller): SchedulerCaller,
    State(scheduler): State<CfDurableNamespace>,
    Json(request): Json<stow_types::api::SchedulerBudgetRequest>,
) -> Result<Json<stow_types::api::SchedulerBudgetReport>, GetArtifactError> {
    Ok(Json(
        scheduler_client::scheduler_budget(&scheduler, &request).await?,
    ))
}

/// `POST /api/v1/admin/scheduler/demand`
///
/// Apply one demand batch to the scheduler's unbuilt closure
/// (stow#522): the trusted input the hourly demand feed (#523)
/// delivers. Operator-only — `SchedulerCaller`, like every route here.
pub async fn admin_scheduler_demand(
    SchedulerCaller(_caller): SchedulerCaller,
    State(scheduler): State<CfDurableNamespace>,
    Json(request): Json<stow_types::api::SchedulerDemandRequest>,
) -> Result<Json<stow_types::api::SchedulerDemandReport>, GetArtifactError> {
    Ok(Json(
        scheduler_client::scheduler_demand(&scheduler, &request).await?,
    ))
}

/// `POST /api/v1/admin/scheduler/demand-feed/query`
///
/// Stream one closed hour's Analytics Engine `FORMAT JSON` document to
/// the feed's materializer (stow#523): the edge authenticates, runs the
/// checked-in query and hands the body through unbuffered — the hour
/// can exceed anything the worker could hold.
pub async fn admin_scheduler_demand_feed_query(
    SchedulerCaller(_caller): SchedulerCaller,
    State(stats_ctx): State<stats::StatsContext>,
    Json(request): Json<stow_types::api::DemandFeedQueryRequest>,
) -> Result<Response, GetArtifactError> {
    #[allow(clippy::cast_possible_truncation)]
    let now_secs = (js_sys::Date::now() / 1_000.0) as i64;
    request
        .hour
        .ensure_closed(now_secs)
        .map_err(GetArtifactError::BadRequestWithMessage)?;
    stats::demand_feed_query(&stats_ctx, &request.hour).await
}

/// `POST /api/v1/admin/scheduler/demand-feed/begin`
///
/// Open or resume the hour's staging attempt (stow#523). Operator-only.
pub async fn admin_scheduler_demand_feed_begin(
    SchedulerCaller(_caller): SchedulerCaller,
    State(scheduler): State<CfDurableNamespace>,
    Json(request): Json<stow_types::api::DemandFeedBeginRequest>,
) -> Result<Json<stow_types::api::DemandFeedBeginReport>, GetArtifactError> {
    Ok(Json(
        scheduler_client::demand_feed_begin(&scheduler, &request).await?,
    ))
}

/// `POST /api/v1/admin/scheduler/demand-feed/page`
///
/// Stage one bounded immutable page under the attempt generation.
pub async fn admin_scheduler_demand_feed_page(
    SchedulerCaller(_caller): SchedulerCaller,
    State(scheduler): State<CfDurableNamespace>,
    Json(request): Json<stow_types::api::DemandFeedPageRequest>,
) -> Result<StatusCode, GetArtifactError> {
    scheduler_client::demand_feed_page(&scheduler, &request).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/admin/scheduler/demand-feed/complete`
///
/// The completion barrier — freeze the hour when its generation's
/// manifest is fully staged.
pub async fn admin_scheduler_demand_feed_complete(
    SchedulerCaller(_caller): SchedulerCaller,
    State(scheduler): State<CfDurableNamespace>,
    Json(request): Json<stow_types::api::DemandFeedCompleteRequest>,
) -> Result<StatusCode, GetArtifactError> {
    scheduler_client::demand_feed_complete(&scheduler, &request).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/admin/scheduler/demand-feed/cleanup`
///
/// Retire one bounded chunk of the hour's dead page rows — explicit
/// event work the feed's caller drains to completion (stow#523).
pub async fn admin_scheduler_demand_feed_cleanup(
    SchedulerCaller(_caller): SchedulerCaller,
    State(scheduler): State<CfDurableNamespace>,
    Json(request): Json<stow_types::api::DemandFeedCleanupRequest>,
) -> Result<Json<stow_types::api::DemandFeedCleanupReport>, GetArtifactError> {
    Ok(Json(
        scheduler_client::demand_feed_cleanup(&scheduler, &request).await?,
    ))
}

/// `POST /api/v1/admin/scheduler/demand-feed/deliver`
///
/// Deliver the next undelivered original page of a complete hour into
/// the demand ledger, or retire a fully-acked hour (stow#523).
pub async fn admin_scheduler_demand_feed_deliver(
    SchedulerCaller(_caller): SchedulerCaller,
    State(scheduler): State<CfDurableNamespace>,
    Json(request): Json<stow_types::api::DemandFeedDeliverRequest>,
) -> Result<Json<stow_types::api::DemandFeedDeliverReport>, GetArtifactError> {
    Ok(Json(
        scheduler_client::demand_feed_deliver(&scheduler, &request).await?,
    ))
}

/// `GET /api/v1/admin/scheduler/demand-feed/status`
///
/// The durable resume cursor: oldest unfinished hour plus the
/// delivered watermark (stow#523).
pub async fn admin_scheduler_demand_feed_status(
    SchedulerCaller(_caller): SchedulerCaller,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::DemandFeedStatus>, GetArtifactError> {
    Ok(Json(
        scheduler_client::demand_feed_status(&scheduler).await?,
    ))
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
            } => GetArtifactError::BadRequestWithMessage(
                crate::errors::scheduler_error_message(&body).to_owned(),
            ),
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
    let mut response = ghcr::open_manifest(
        &ghcr.base_url,
        repo,
        tag,
        &ghcr.tokens,
        &OutboundPool::new(),
    )
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
/// Delete every catalog row built by the retired toolchain. GHCR image
/// tags are not deleted — they age out under the package's own retention.
pub async fn prune_artifacts(
    SchedulerCaller(caller): SchedulerCaller,
    Json(request): Json<stow_types::api::ArtifactPruneRequest>,
    db: Db,
) -> Result<Json<stow_types::api::ArtifactPruneResponse>, GetArtifactError> {
    let deleted = db::delete_artifacts_for_rustc(&db, request.rustc_version.as_str()).await?;
    tracing::warn!(
        %caller,
        rustc_version = %request.rustc_version,
        deleted,
        "pruned artifact rows for a retired toolchain"
    );
    Ok(Json(stow_types::api::ArtifactPruneResponse { deleted }))
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
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::SchedulerSubmitResponse>, GetArtifactError> {
    // The edge resolves nothing (stow#429): every lane that posts here
    // already submits resolver-canonical requests, so they land verbatim —
    // `Json` deserialization itself is the only check (`FeaturesJson`
    // rejects a non-canonical feature list there).
    // Repo-writer submissions are exempt from the pending-depth cap — the
    // credential check is the bound on this path.
    let inserted = scheduler_client::send_enqueue_trusted(&scheduler, &requests).await?;
    tracing::info!(tasks = requests.len(), %caller, "submitted scheduler tasks");
    Ok(Json(stow_types::api::SchedulerSubmitResponse {
        submitted: u32::try_from(requests.len()).map_err(|_| {
            GetArtifactError::TooLarge("submitted task count exceeds u32".to_owned())
        })?,
        inserted,
        // Verbatim submission drops nothing; the field stays on the wire
        // shape the submitters already parse.
        dropped: 0,
    }))
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
/// admission check. The edge itself resolves nothing (stow#428): the
/// request's record lives in the scheduler, which dispatches a
/// `resolve-request.yml` run through the GitHub App; the job resolves
/// with `stow-resolver`, reports the outcome back, and the scheduler
/// enqueues the covered tasks into the human lane — dispatched ahead of
/// queued misses and exempt from the dispatch minimum age. Re-requesting
/// a live request answers its record; a failed one re-attempts.
pub async fn submit_crate_request(
    CfConnectingIp(remoteip): CfConnectingIp,
    Json(request): Json<CrateRequest>,
    db: Db,
    State(scheduler): State<CfDurableNamespace>,
    State(cache): State<CfCache>,
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

    let crates_io = crates_io::CfCratesIo::new(OutboundPool::new());
    // The request's version resolve (db reads) and the stable rustc
    // resolve (a Cache API read) are independent, so they overlap.
    let (version, rustc_version) = futures_util::try_join!(
        async { resolve_request_version(&db, &crates_io, &request).await },
        async {
            rust_channel::stable_rustc_version(&cache, &rust_channel::CfRustChannel)
                .await
                .map_err(Into::into)
        },
    )?;
    // `features_json` is already canonical — `FeaturesJson` rejects an
    // unsorted list at deserialize — so the id hashes the exact string
    // every other lane recomputes.
    let admission = stow_types::api::RequestAdmission {
        request_id: stow_types::api::request_id(
            request.crate_name.as_str(),
            &version.to_string(),
            &request.features_json.raw(),
            rustc_version.as_str(),
        ),
        crate_name: request.crate_name.clone(),
        version: CrateVersion::new(version),
        features_json: request.features_json.clone(),
        rustc_version,
        // `Settings` carries the cap as usize; the wire type is u32 —
        // a value past u32::MAX clamps there, still refusing nothing a
        // site would legitimately request.
        max_closure: u32::try_from(settings.human_max_closure).unwrap_or(u32::MAX),
    };
    let status = match scheduler_client::submit_request(&scheduler, &admission).await {
        Ok(status) => status,
        // A 429 from the scheduler on this lane is the daily task budget;
        // its counter resets at 00:00 UTC.
        Err(error) => match GetArtifactError::from(error) {
            GetArtifactError::SchedulerBusy(message) => {
                return rate_limited_response(
                    &message,
                    scheduler::queue::seconds_until_utc_midnight(now_unix()),
                );
            }
            other => return Err(other),
        },
    };
    tracing::info!(
        request_id = %status.request_id,
        crate_name = %request.crate_name,
        version = %status.version,
        rustc_version = %status.rustc_version,
        phase = ?status.status,
        "human request admitted"
    );
    let mut response = Response::new(
        Body::from_json(&status)
            .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?,
    );
    response.headers_mut().insert(
        skyzen::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(response)
}

/// `POST /api/v1/scheduler/requests/{request_id}/outcome`
///
/// The resolve job's outcome report: `stow-admin request resolve` posts
/// the tasks it resolved across `CI_TARGET_TRIPLES` (or the failure the
/// run ended in) and the record settles `enqueued`/`failed`. The tasks
/// ride the trusted submit path verbatim — the resolver already pinned
/// each identity, so no canonicalization runs here.
///
/// `SchedulerCaller` extracts first and rejects unauthorized requests
/// before `Json` runs.
pub async fn scheduler_request_outcome(
    SchedulerCaller(_caller): SchedulerCaller,
    params: Params,
    Json(report): Json<stow_types::api::RequestOutcomeReport>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::CrateRequestStatus>, GetArtifactError> {
    let request_id = params
        .get("request_id")
        .map_err(|_| GetArtifactError::BadRequest)?;
    let status = scheduler_client::send_request_outcome(&scheduler, request_id, &report).await?;
    Ok(Json(status))
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

/// GET /`api/v1/requests/{request_id}`
///
/// The request record's live view — `accepted` while the resolve run is
/// queued or mid-dispatch, `resolving` once GitHub reports the run
/// `in_progress`, then `enqueued` (per-target states re-probed against
/// the queue on each read) or `failed`.
pub async fn crate_request_status(
    params: Params,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Response, GetArtifactError> {
    let request_id = params
        .get("request_id")
        .map_err(|_| GetArtifactError::BadRequest)?;
    let status = scheduler_client::get_request(&scheduler, request_id)
        .await?
        .ok_or_else(|| GetArtifactError::UnknownRequest {
            request_id: request_id.to_owned(),
        })?;
    cacheable_json(&status, POINT_IN_TIME_NO_STORE)
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

/// `Cache-Control` on every point-in-time answer — the task status lanes
/// change underneath the caller, so Workers Cache must never store one.
const POINT_IN_TIME_NO_STORE: &str = "no-store";

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
        &crates_io::CfCratesIo::new(OutboundPool::new()),
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
    let response = catalog::crate_versions(
        &db,
        &crates_io::CfCratesIo::new(OutboundPool::new()),
        crate_name.as_str(),
    )
    .await?;
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
        &crates_io::CfCratesIo::new(OutboundPool::new()),
        crate_name.as_str(),
        version.as_semver(),
    )
    .await?;
    cacheable_json(&response, CATALOG_VERSIONS_MAX_AGE)
}

/// GET /`api/v1/bundles/{digest}`
///
/// The byte path: streams the `<tag>.bundle` blobs under
/// `ghcr.io/water-rs/stow-cache`. The `sha256:<64 lowercase hex>` path
/// segment is the whole address — it is validated before any fetch; the
/// answer's immutable `Cache-Control` is what Workers Cache stores and
/// replays without this worker running; a GHCR 404 is a 404. No catalog
/// row is consulted: the CLI's signed index named these bytes, and the
/// CLI verifies them against the index before they are used.
pub async fn get_bundle(
    params: Params,
    State(ghcr): State<GhcrConfig>,
) -> Result<Response, GetArtifactError> {
    let digest = params
        .get("digest")
        .map_err(|_| GetArtifactError::BadRequest)?;
    if !stow_types::registry::is_sha256_digest(digest) {
        return Err(GetArtifactError::BadRequestWithMessage(format!(
            "malformed bundle digest `{digest}` — expected sha256:<64 lowercase hex>"
        )));
    }

    let (body, content_length) = open_bundle_stream(&ghcr, digest)
        .await
        .map_err(registry_fetch_error)?;
    Ok(bundle_response(body, content_length))
}

/* ---- index slices ---- */

/// `Cache-Control` on the digest-resolution answer: the
/// `index.<target>.<rustc>` tag moves at every index publish, so the
/// pointer stays short-lived while the blob it names is immutable.
const INDEX_DIGEST_MAX_AGE: &str = "public, max-age=60";

/// `Cache-Control` on every digest-addressed answer — index slice bytes
/// and bundles: the digest pins the content, so the answer is immutable
/// and no cache in front of it ever revalidates.
const DIGEST_ADDRESSED_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

/// The request's `Accept-Encoding` header value (empty when absent) —
/// the slice route negotiates its `Content-Encoding` on it.
#[derive(Debug)]
pub struct AcceptEncoding(pub String);

impl Extractor for AcceptEncoding {
    type Error = std::convert::Infallible;

    fn extract(
        request: &mut Request,
    ) -> impl std::future::Future<Output = Result<Self, Self::Error>> + Send {
        let value = request
            .headers()
            .get(skyzen::header::ACCEPT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        std::future::ready(Ok(Self(value)))
    }
}

/// Response of `GET /api/v1/index/{target}/{rustc_version}` — the layer
/// digest the slice's OCI tag currently points at, so a client can then
/// fetch the bytes from the immutable digest-addressed route.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct IndexSlicePointer {
    /// The requested compilation target triple.
    pub target: String,
    /// The rustc version the slice is built for — the resolved version
    /// when the path named `stable`.
    pub rustc_version: String,
    /// `sha256:…` digest of the index layer blob.
    pub digest: String,
    /// Compressed layer size in bytes.
    pub size: u64,
}

/// The validated `{target}` path segment — parsed into a
/// [`TargetTriple`] so only the triple alphabet can reach a registry URL.
fn path_target(params: &Params) -> Result<TargetTriple, GetArtifactError> {
    params
        .get("target")
        .map_err(|_| GetArtifactError::BadRequest)?
        .parse::<TargetTriple>()
        .map_err(|error| GetArtifactError::BadRequestWithMessage(error.to_string()))
}

/// Resolve the `{rustc_version}` path segment for the index routes:
/// `stable` resolves in the Worker from the Cache-API-cached channel
/// answer (`rust_channel`), so an index view never wakes the scheduler
/// Durable Object; any other value must already be a wire rustc
/// version.
async fn index_rustc_version(
    cache: &CfCache,
    raw: &str,
) -> Result<WireRustcVersion, GetArtifactError> {
    if raw == "stable" {
        return rust_channel::stable_rustc_version(cache, &rust_channel::CfRustChannel)
            .await
            .map_err(GetArtifactError::from);
    }
    raw.parse::<WireRustcVersion>()
        .map_err(|error| GetArtifactError::BadRequestWithMessage(error.to_string()))
}

/// The fixed repository every cached blob lives in —
/// `water-rs/stow-cache`, the repository the pull scope names. Slice tags
/// are built by `index_tag` under `GHCR_BASE` and bundle digests are
/// caller-supplied but validated to `sha256:<64 hex>` — neither ever names
/// another repository.
fn cache_repository() -> stow_types::registry::RepositoryPath<'static> {
    stow_types::registry::repository_path(stow_types::registry::GHCR_BASE)
        .expect("GHCR_BASE is a fixed canonical reference with a repository path")
}

/// Map a registry failure on the byte paths onto the public error
/// surface: a missing blob is a 404, a rate-limited or 5xx registry is
/// a 502, and anything else is an internal error — never a silent empty
/// answer.
fn registry_fetch_error(error: ghcr::FetchError) -> GetArtifactError {
    match error {
        ghcr::FetchError::NotFound => GetArtifactError::NotFound,
        ghcr::FetchError::Unavailable => GetArtifactError::GhcrUnavailable,
        other => {
            tracing::error!(error = %other, "index fetch from registry failed");
            GetArtifactError::InternalWithMessage(other.to_string())
        }
    }
}

/// Fetch the `index.<target>.<rustc>` manifest and return its single
/// index layer — the digest the published slice currently points at,
/// and the size that bounds the buffered read.
async fn index_slice_layer(
    ghcr: &GhcrConfig,
    target: &TargetTriple,
    rustc_version: &WireRustcVersion,
    pool: &OutboundPool,
) -> Result<stow_types::api::OciDescriptor, GetArtifactError> {
    let tag = stow_types::index::index_tag(target.as_str(), rustc_version.as_str());
    let mut response =
        ghcr::open_manifest(&ghcr.base_url, cache_repository(), &tag, &ghcr.tokens, pool)
            .await
            .map_err(registry_fetch_error)?;
    let body = response
        .text()
        .into_send()
        .await
        .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
    let manifest: stow_types::api::OciManifest = serde_json::from_str(&body).map_err(|error| {
        GetArtifactError::InternalWithMessage(format!("decode index manifest: {error}"))
    })?;
    index_slice::index_layer(&manifest)
        .cloned()
        .map_err(|error| GetArtifactError::InternalWithMessage(format!("{tag}: {error}")))
}

/// `GET /api/v1/index/{target}/{rustc_version}` — which blob digest the
/// `index.<target>.<rustc>` OCI tag currently names. The page asks this
/// first, then fetches the digest-addressed route for the bytes.
pub async fn get_index_slice_digest(
    params: Params,
    State(ghcr): State<GhcrConfig>,
    State(cache): State<CfCache>,
) -> Result<Response, GetArtifactError> {
    let target = path_target(&params)?;
    let rustc_version = index_rustc_version(
        &cache,
        params
            .get("rustc_version")
            .map_err(|_| GetArtifactError::BadRequest)?,
    )
    .await?;
    let layer = index_slice_layer(&ghcr, &target, &rustc_version, &OutboundPool::new()).await?;
    cacheable_json(
        &IndexSlicePointer {
            target: target.into_inner(),
            rustc_version: rustc_version.into_inner(),
            digest: layer.digest.clone(),
            size: layer.size,
        },
        INDEX_DIGEST_MAX_AGE,
    )
}

/// Fetch a digest-addressed index slice after proving the digest is
/// still this pair's index layer — returns the layer the manifest
/// declared and the streaming blob response.
async fn fetch_index_slice_upstream(
    ghcr: &GhcrConfig,
    target: &TargetTriple,
    rustc_version: &WireRustcVersion,
    digest: &str,
    pool: &OutboundPool,
) -> Result<(stow_types::api::OciDescriptor, worker::Response), GetArtifactError> {
    // A miss must still be this pair's index layer — without the check,
    // any `sha256:` digest the repository holds (a several-hundred-MB
    // bundle included) would make the worker fetch it, and the gzip
    // transcode would buffer the whole blob inside one isolate.
    let layer = index_slice_layer(ghcr, target, rustc_version, pool).await?;
    if layer.digest != digest {
        return Err(GetArtifactError::NotFound);
    }
    let upstream = ghcr::open_blob(
        &ghcr.base_url,
        cache_repository(),
        digest,
        &ghcr.tokens,
        pool,
    )
    .await
    .map_err(registry_fetch_error)?;
    if let Some(length) = worker_content_length(&upstream).filter(|length| *length > layer.size) {
        return Err(GetArtifactError::InternalWithMessage(format!(
            "slice blob reports {length} bytes, over the {} its manifest declares",
            layer.size
        )));
    }
    Ok((layer, upstream))
}

/// Read a registry blob response into memory, stopping the moment it
/// outgrows the size its manifest declared — the gzip transcode's
/// buffered path, bounded so a wrong blob cannot eat one isolate's heap.
async fn bounded_blob_bytes(
    response: &mut worker::Response,
    size: u64,
) -> Result<Vec<u8>, GetArtifactError> {
    // `ByteStream` is a !Send JsValue stream — the whole read is wrapped
    // in `into_send` rather than each `next`, so the stream state may
    // cross the loop's awaits inside one isolate-local future.
    let read = async {
        use futures_util::StreamExt as _;

        let too_big = |bytes: &[u8]| {
            (bytes.len() as u64 > size).then(|| {
                GetArtifactError::InternalWithMessage(format!(
                    "slice blob exceeds the {size} bytes its manifest declares"
                ))
            })
        };
        if let Ok(stream) = response.stream() {
            futures_util::pin_mut!(stream);
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk
                    .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
                bytes.extend_from_slice(&chunk);
                if let Some(error) = too_big(&bytes) {
                    return Err(error);
                }
            }
            Ok(bytes)
        } else {
            let bytes = response
                .bytes()
                .await
                .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
            too_big(&bytes).map_or(Ok(bytes), Err)
        }
    };
    read.into_send().await
}

/// The registry/cache response's `Content-Length`, when it carries one —
/// forwarded onto the slice answer so the client can size the download.
fn worker_content_length(response: &worker::Response) -> Option<u64> {
    response
        .headers()
        .get("content-length")
        .ok()
        .flatten()
        .and_then(|value| value.parse().ok())
}

/// The streamed slice response. `Content-Type` is `application/json`
/// because `Content-Encoding` describes the transfer encoding: the bytes
/// the client ends up reading are always the index JSON document.
fn slice_response(
    body: Body,
    encoding: index_slice::SliceEncoding,
    content_length: Option<u64>,
) -> Response {
    let mut response = Response::new(body);
    let headers = response.headers_mut();
    headers.insert(
        skyzen::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(
        skyzen::header::CONTENT_ENCODING,
        HeaderValue::from_static(encoding.content_encoding()),
    );
    headers.insert(
        skyzen::header::CACHE_CONTROL,
        HeaderValue::from_static(DIGEST_ADDRESSED_CACHE_CONTROL),
    );
    // One URL serves both encodings — every cache between the worker and
    // the client must key on the request's Accept-Encoding.
    headers.insert(
        skyzen::header::VARY,
        HeaderValue::from_static("accept-encoding"),
    );
    if let Some(length) = content_length {
        headers.insert(skyzen::header::CONTENT_LENGTH, HeaderValue::from(length));
    }
    response
}

/// `GET /api/v1/index/{target}/{rustc_version}/{digest}` — the index
/// slice itself: the same blob the CLI's index refresh pulls, served
/// from this origin so a browser never has to run GHCR's anonymous
/// bearer exchange, and cached by Workers Cache on the response's own
/// immutable `Cache-Control`. `Accept-Encoding` picks the
/// `Content-Encoding`: `zstd` passes the published blob through
/// byte-for-byte; anything else gets a gzip transcode, cached per
/// encoding by the `Vary` the answer carries.
pub async fn get_index_slice(
    params: Params,
    accept: AcceptEncoding,
    State(ghcr): State<GhcrConfig>,
    State(cache): State<CfCache>,
) -> Result<Response, GetArtifactError> {
    let target = path_target(&params)?;
    let rustc_version = index_rustc_version(
        &cache,
        params
            .get("rustc_version")
            .map_err(|_| GetArtifactError::BadRequest)?,
    )
    .await?;
    let digest = index_slice::parse_layer_digest(
        params
            .get("digest")
            .map_err(|_| GetArtifactError::BadRequest)?,
    )
    .map_err(|error| GetArtifactError::BadRequestWithMessage(error.to_string()))?
    .to_owned();

    let encoding = index_slice::negotiate_encoding(&accept.0);

    // One bound for the whole request: the manifest read and the blob
    // stream draw from the same invocation's budget.
    let pool = OutboundPool::new();
    let (layer, mut upstream) =
        fetch_index_slice_upstream(&ghcr, &target, &rustc_version, &digest, &pool).await?;

    match encoding {
        index_slice::SliceEncoding::Zstd => {
            let content_length = worker_content_length(&upstream);
            Ok(slice_response(
                body_from_worker_response(upstream).map_err(registry_fetch_error)?,
                encoding,
                content_length,
            ))
        }
        index_slice::SliceEncoding::Gzip => {
            // Buffer and transcode on a Workers Cache miss; the response's
            // `Vary: accept-encoding` caches the gzip copy under its own
            // variant. The manifest's declared size bounds the read — a
            // blob that grows past it is an error, not a bigger buffer.
            let zstd = bounded_blob_bytes(&mut upstream, layer.size).await?;
            let gzip = index_slice::zstd_to_gzip(&zstd)
                .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
            let content_length = gzip.len() as u64;
            Ok(slice_response(
                Body::from(gzip),
                encoding,
                Some(content_length),
            ))
        }
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
    let derived_task_id = ticket.request.task_id().map_err(|error| {
        GetArtifactError::BadRequestWithMessage(format!("enqueue task id: {error}"))
    })?;
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

/// The streamed bundle response: the body is the published bundle blob
/// byte-for-byte, so its length is the upstream `content-length` when the
/// registry reported one. The immutable `Cache-Control` is the whole
/// caching contract Workers Cache needs to answer later reads without
/// this worker running.
fn bundle_response(body: Body, content_length: Option<u64>) -> Response {
    let mut response = Response::new(body);
    let headers = response.headers_mut();
    headers.insert(
        skyzen::header::CONTENT_TYPE,
        HeaderValue::from_static(STOW_BUNDLE_MEDIA_TYPE),
    );
    headers.insert(
        skyzen::header::CACHE_CONTROL,
        HeaderValue::from_static(DIGEST_ADDRESSED_CACHE_CONTROL),
    );
    if let Some(length) = content_length {
        headers.insert(skyzen::header::CONTENT_LENGTH, HeaderValue::from(length));
    }
    response
}

/// Open the bundle for `digest` as a stream straight from the registry.
/// Nothing on this path buffers the bundle or inspects it — the publish
/// stage validated the tar before pushing it, GHCR addresses it by
/// content, and the CLI verifies the digest and the cosign material
/// inside it.
async fn open_bundle_stream(
    ghcr: &GhcrConfig,
    digest: &str,
) -> Result<(Body, Option<u64>), ghcr::FetchError> {
    let upstream = ghcr::open_blob(
        &ghcr.base_url,
        cache_repository(),
        digest,
        &ghcr.tokens,
        &OutboundPool::new(),
    )
    .await
    .map_err(|error| {
        tracing::error!(
            bundle_digest = %digest,
            error = %error,
            "edge failed to open bundle blob from registry"
        );
        error
    })?;

    let content_length = worker_content_length(&upstream);
    Ok((body_from_worker_response(upstream)?, content_length))
}

/// Hand a `worker::Response` body to Skyzen without reading it.
fn body_from_worker_response(response: worker::Response) -> Result<Body, ghcr::FetchError> {
    let js: worker::web_sys::Response = response.into();
    from_js_response(&js)
        .map(skyzen::Response::into_body)
        .map_err(|error| ghcr::FetchError::Network(format!("wrap registry response: {error:?}")))
}

/// OCI registry configuration for artifact fetching, stored via `State<GhcrConfig>`.
#[derive(Debug, Clone)]
pub struct GhcrConfig {
    pub base_url: String,
    /// Per-isolate bearer cache for the anonymous registry token exchange.
    pub tokens: RegistryTokens,
}

/// `Cache-Control` on the public stats answer — the SQL API is billed
/// per query, so Workers Cache holds the body for the hour the figure
/// tolerates being stale.
const USAGE_STATS_MAX_AGE: &str = "public, max-age=3600";

/// GET /api/v1/stats — the public aggregate usage statistics. Anonymous:
/// the handler reads no request data at all, and the `UsageStats` it
/// returns is computed from the Analytics Engine SQL API at most once an
/// hour — Workers Cache replays the answer for the rest of the hour.
pub async fn usage_stats(
    State(stats_ctx): State<stats::StatsContext>,
) -> Result<Response, GetArtifactError> {
    let stats = stats::compute_usage_stats(&stats_ctx).await?;
    cacheable_json(&stats, USAGE_STATS_MAX_AGE)
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
