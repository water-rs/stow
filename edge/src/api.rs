use skyzen::extract::{Extractor, Query};
use skyzen::header::HeaderValue;
use skyzen::routing::Params;
use skyzen::runtime::wasm::passthrough_js_response;
use skyzen::utils::{Json, State};
use skyzen::{Body, Request, Response, StatusCode};
use skyzen_cloudflare::worker::send::IntoSendFuture as _;
use skyzen_cloudflare::worker::{self, AnalyticsEngineDataset};
use skyzen_cloudflare::{CfCache, CfDurableNamespace};
use stow_types::admission;
use stow_types::api::{
    AdmissionRequest, CI_TARGET_TRIPLES, CrateRequest, EnqueueAdmission, EnqueueTicket,
};
use stow_types::bundle::STOW_BUNDLE_MEDIA_TYPE;
use stow_types::identity::{CrateName, CrateVersion, TargetTriple, WireRustcVersion};

use crate::errors::GetArtifactError;
use crate::fetch_guard::OutboundPool;
use crate::github_auth::{self, OPERATIONS_WORKFLOW};
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
/// local dev, CI `GITHUB_TOKEN`). It gates the read routes only; every
/// mutating route takes a [`Mutator`] (stow#955).
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

/// A mutating route's caller (stow#955): only a GitHub Actions OIDC
/// identity of one of `P`'s workflows, running at `refs/heads/main` — a
/// user token and every other push credential stay read-only. Carries
/// the verified `actor` the scheduler log attributes the mutation to.
#[derive(Debug)]
pub struct Mutator<P> {
    /// The authenticated identity (always `TrustedCaller::Actions`).
    pub caller: github_auth::TrustedCaller,
    /// The token's verified `actor` claim.
    pub actor: String,
    policy: std::marker::PhantomData<fn() -> P>,
}

impl<P: github_auth::MutationPolicy> Extractor for Mutator<P> {
    type Error = GetArtifactError;

    async fn extract(request: &mut Request) -> Result<Self, Self::Error> {
        let caller = extract_trusted_caller(request).await?;
        let config = State::<github_auth::GitHubTrustConfig>::extract(request)
            .await
            .map_err(|_| {
                GetArtifactError::InternalWithMessage(
                    "github trust config binding missing".to_owned(),
                )
            })?;
        let actor = github_auth::authorize_mutation(&caller, P::WORKFLOWS, &config.repo)
            .map_err(|_| {
                tracing::warn!(%caller, "mutation refused: caller outside the route's workflows");
                GetArtifactError::Unauthorized
            })?
            .to_owned();
        Ok(Self {
            caller,
            actor,
            policy: std::marker::PhantomData,
        })
    }
}

/// Operator-only routes: the freeze switch, queue mutations, the store
/// reset and the mock-only budget probe.
pub struct OperatorRoute;
impl github_auth::MutationPolicy for OperatorRoute {
    const WORKFLOWS: &'static [&'static str] = &[OPERATIONS_WORKFLOW];
}

/// `tasks/submit`: operator submits plus the scheduled and dispatched
/// preheat lanes.
pub struct SubmitRoute;
impl github_auth::MutationPolicy for SubmitRoute {
    const WORKFLOWS: &'static [&'static str] = &[
        OPERATIONS_WORKFLOW,
        "preheat-admin.yml",
        "preheat-missed.yml",
    ];
}

/// `tasks/submit-ids`: `preheat projects submit`, by an operator or the
/// preheat-admin lane.
pub struct SubmitIdsRoute;
impl github_auth::MutationPolicy for SubmitIdsRoute {
    const WORKFLOWS: &'static [&'static str] = &[OPERATIONS_WORKFLOW, "preheat-admin.yml"];
}

/// `scheduler/demand` and the demand feed: the hourly feed plus an
/// operator's `scheduler demand-feed --hour` recovery.
pub struct DemandRoute;
impl github_auth::MutationPolicy for DemandRoute {
    const WORKFLOWS: &'static [&'static str] = &[OPERATIONS_WORKFLOW, "demand-feed.yml"];
}

/// `index/published`: the index publish run's slice report.
pub struct IndexPublishRoute;
impl github_auth::MutationPolicy for IndexPublishRoute {
    const WORKFLOWS: &'static [&'static str] = &["index-publish.yml"];
}

/// `requests/{id}/outcome`: the resolve job's verdict.
pub struct RequestOutcomeRoute;
impl github_auth::MutationPolicy for RequestOutcomeRoute {
    const WORKFLOWS: &'static [&'static str] = &["resolve-request.yml"];
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
        &github_auth::CfGitHubTrust::new(OutboundPool::new(), config.probe_base_url.clone()),
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
/// secret minting miss challenges (`STOW_POW_CHALLENGE_SECRET`) and the
/// proof-of-work bits every admission carries (`STOW_POW_MIN_BITS`). The
/// pending-depth refusal lives in the scheduler's own cap
/// (`STOW_MAX_QUEUE_PENDING`), whose 429 this handler maps — the edge
/// reads no depth of its own (stow#940).
#[derive(Debug, Clone)]
pub struct PowAdmission {
    pub challenge_secret: String,
    /// Leading-zero bits minted into every admission and required of
    /// every ticket — an enqueue is never free.
    pub min_bits: u32,
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
    trees: Vec<stow_types::api::SubmissionTree>,
    difficulty: u32,
) -> Result<Vec<EnqueueAdmission>, GetArtifactError> {
    let minute = now_minute();
    let mut admissions = Vec::with_capacity(trees.len());
    for tree in trees {
        // The challenge binds the tree's first root — the miss the
        // admission minted — to the whole tree's canonical JSON.
        let task_id = tree
            .roots
            .first()
            .and_then(|&root| tree.nodes.get(root as usize))
            .map(|node| node.task_id.clone())
            .ok_or_else(|| {
                GetArtifactError::BadRequestWithMessage("submission tree names no roots".to_owned())
            })?;
        let request_json = serde_json::to_vec(&tree)
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
            tree,
        });
    }
    Ok(admissions)
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
    Mutator { caller, actor, .. }: Mutator<OperatorRoute>,
    Json(switch): Json<stow_types::api::DispatchFreeze>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::DispatchFreeze>, GetArtifactError> {
    let stored = scheduler_client::set_dispatch_freeze(&scheduler, switch.enabled, &actor).await?;
    tracing::warn!(enabled = stored.enabled, %caller, "dispatch freeze flipped via admin endpoint");
    Ok(Json(stored))
}

/// POST /`api/v1/admin/index/published`
///
/// The index-publish path's report that this run's slices went live,
/// carrying the semantic identities the signed index serves — recorded
/// inside the scheduler as the membership the dependency gate checks a
/// dependent's edges against. One report per publish run: the object
/// applies the slices in one append and one dispatch pass (stow#940).
/// Only the index-publish workflow's own run on `main` may report.
pub async fn record_published_index(
    Mutator { caller, actor, .. }: Mutator<IndexPublishRoute>,
    State(scheduler): State<CfDurableNamespace>,
    Json(report): Json<stow_types::api::PublishedRunReport>,
) -> Result<Json<OkResponse>, GetArtifactError> {
    let slices = report.slices.len();
    let rows: usize = report
        .slices
        .iter()
        .map(|slice| slice.added.len() + slice.retired.len())
        .sum();
    scheduler_client::record_published_index(&scheduler, &report, &actor).await?;
    tracing::info!(
        slices,
        rows,
        %caller,
        "recorded a publish run's slices"
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

/// `POST /api/v1/admin/scheduler/reset`
///
/// Reset the scheduler Durable Object's store — the only code path that
/// may issue DDL on its database, and the only way the schema lands:
/// every table, index and trigger is dropped and `schema.sql`
/// re-executed, destroying the queue and the recorded slices; the
/// queues refill from the lanes that feed them. `stow-admin scheduler
/// reset --yes` is the manual path, which a fresh deployment's
/// operator runs once to create the schema.
pub async fn admin_scheduler_reset(
    Mutator { caller, actor, .. }: Mutator<OperatorRoute>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::SchedulerResetReport>, GetArtifactError> {
    let report = scheduler_client::reset_scheduler(&scheduler, &actor).await?;
    tracing::warn!(
        dropped = report.dropped,
        %caller,
        "scheduler store reset via admin endpoint"
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
    Mutator { .. }: Mutator<OperatorRoute>,
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
    Mutator { .. }: Mutator<OperatorRoute>,
    State(scheduler): State<CfDurableNamespace>,
    Json(request): Json<stow_types::api::SchedulerBudgetRequest>,
) -> Result<Json<stow_types::api::SchedulerBudgetReport>, GetArtifactError> {
    Ok(Json(
        scheduler_client::scheduler_budget(&scheduler, &request).await?,
    ))
}

/// `POST /api/v1/admin/scheduler/budget/rearm`
///
/// Re-arm the seeded fixture's in-flight batches the traffic-cost
/// callback lane's deliveries resolved and answer every armed one, so
/// each delivery it fires is a first delivery (stow#833). Same deploy-var
/// guard as the seed route.
pub async fn admin_scheduler_budget_rearm(
    Mutator { .. }: Mutator<OperatorRoute>,
    State(scheduler): State<CfDurableNamespace>,
    Json(request): Json<stow_types::api::SchedulerRearmRequest>,
) -> Result<Json<stow_types::api::SchedulerRearmReport>, GetArtifactError> {
    Ok(Json(
        scheduler_client::rearm_budget_fixture(&scheduler, &request).await?,
    ))
}

/// `GET /api/v1/admin/scheduler/budget/ledger`
///
/// The scheduler Durable Object's billed `rowsRead`/`rowsWritten` per
/// operation since the store's last reset — what the `Preheat cost`
/// lane (stow#773) diffs between a wave's layers. Same deploy-var guard
/// as the seed route.
pub async fn admin_scheduler_budget_ledger(
    SchedulerCaller(_caller): SchedulerCaller,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::SchedulerLedger>, GetArtifactError> {
    Ok(Json(scheduler_client::scheduler_ledger(&scheduler).await?))
}

/// `POST /api/v1/admin/scheduler/demand`
///
/// Apply one demand batch to the scheduler's unbuilt closure
/// (stow#522): the trusted input the hourly demand feed (#523)
/// delivers, or an operator's recovery run.
pub async fn admin_scheduler_demand(
    Mutator { actor, .. }: Mutator<DemandRoute>,
    State(scheduler): State<CfDurableNamespace>,
    Json(request): Json<stow_types::api::SchedulerDemandRequest>,
) -> Result<Json<stow_types::api::SchedulerDemandReport>, GetArtifactError> {
    Ok(Json(
        scheduler_client::scheduler_demand(&scheduler, &request, &actor).await?,
    ))
}

/// `POST /api/v1/admin/scheduler/demand-feed/query`
///
/// Stream one closed hour's Analytics Engine `FORMAT JSON` document to
/// the feed's materializer (stow#523): the edge authenticates, runs the
/// checked-in query and hands the body through unbuffered — the hour
/// can exceed anything the worker could hold.
pub async fn admin_scheduler_demand_feed_query(
    Mutator { .. }: Mutator<DemandRoute>,
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
    Mutator { actor, .. }: Mutator<DemandRoute>,
    State(scheduler): State<CfDurableNamespace>,
    Json(request): Json<stow_types::api::DemandFeedBeginRequest>,
) -> Result<Json<stow_types::api::DemandFeedBeginReport>, GetArtifactError> {
    Ok(Json(
        scheduler_client::demand_feed_begin(&scheduler, &request, &actor).await?,
    ))
}

/// `POST /api/v1/admin/scheduler/demand-feed/page`
///
/// Stage one bounded immutable page under the attempt generation.
pub async fn admin_scheduler_demand_feed_page(
    Mutator { actor, .. }: Mutator<DemandRoute>,
    State(scheduler): State<CfDurableNamespace>,
    Json(request): Json<stow_types::api::DemandFeedPageRequest>,
) -> Result<StatusCode, GetArtifactError> {
    scheduler_client::demand_feed_page(&scheduler, &request, &actor).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/admin/scheduler/demand-feed/complete`
///
/// The completion barrier — freeze the hour when its generation's
/// manifest is fully staged.
pub async fn admin_scheduler_demand_feed_complete(
    Mutator { actor, .. }: Mutator<DemandRoute>,
    State(scheduler): State<CfDurableNamespace>,
    Json(request): Json<stow_types::api::DemandFeedCompleteRequest>,
) -> Result<StatusCode, GetArtifactError> {
    scheduler_client::demand_feed_complete(&scheduler, &request, &actor).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/admin/scheduler/demand-feed/cleanup`
///
/// Retire one bounded chunk of the hour's dead page rows — explicit
/// event work the feed's caller drains to completion (stow#523).
pub async fn admin_scheduler_demand_feed_cleanup(
    Mutator { actor, .. }: Mutator<DemandRoute>,
    State(scheduler): State<CfDurableNamespace>,
    Json(request): Json<stow_types::api::DemandFeedCleanupRequest>,
) -> Result<Json<stow_types::api::DemandFeedCleanupReport>, GetArtifactError> {
    Ok(Json(
        scheduler_client::demand_feed_cleanup(&scheduler, &request, &actor).await?,
    ))
}

/// `POST /api/v1/admin/scheduler/demand-feed/deliver`
///
/// Deliver the next undelivered original page of a complete hour into
/// the demand ledger, or retire a fully-acked hour (stow#523).
pub async fn admin_scheduler_demand_feed_deliver(
    Mutator { actor, .. }: Mutator<DemandRoute>,
    State(scheduler): State<CfDurableNamespace>,
    Json(request): Json<stow_types::api::DemandFeedDeliverRequest>,
) -> Result<Json<stow_types::api::DemandFeedDeliverReport>, GetArtifactError> {
    Ok(Json(
        scheduler_client::demand_feed_deliver(&scheduler, &request, &actor).await?,
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
    actor: &str,
) -> Result<stow_types::api::QueueMutationResult, GetArtifactError> {
    scheduler_client::queue_mutation(scheduler, verb, selector, actor)
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
    Mutator { actor, .. }: Mutator<OperatorRoute>,
    Json(selector): Json<stow_types::api::QueueSelector>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::QueueMutationResult>, GetArtifactError> {
    Ok(Json(
        queue_mutation(&scheduler, "retry", &selector, &actor).await?,
    ))
}

/// POST /api/v1/admin/queue/cancel — pending/dispatched → failed as
/// `cancelled by operator`.
pub async fn admin_queue_cancel(
    Mutator { actor, .. }: Mutator<OperatorRoute>,
    Json(selector): Json<stow_types::api::QueueSelector>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::QueueMutationResult>, GetArtifactError> {
    Ok(Json(
        queue_mutation(&scheduler, "cancel", &selector, &actor).await?,
    ))
}

/// POST /api/v1/admin/queue/promote — pending miss-lane rows → human lane.
pub async fn admin_queue_promote(
    Mutator { actor, .. }: Mutator<OperatorRoute>,
    Json(selector): Json<stow_types::api::QueueSelector>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::QueueMutationResult>, GetArtifactError> {
    Ok(Json(
        queue_mutation(&scheduler, "promote", &selector, &actor).await?,
    ))
}

/// POST /api/v1/admin/queue/purge — delete completed/failed rows older
/// than the selector's age.
pub async fn admin_queue_purge(
    Mutator { actor, .. }: Mutator<OperatorRoute>,
    Json(selector): Json<stow_types::api::QueueSelector>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::QueueMutationResult>, GetArtifactError> {
    Ok(Json(
        queue_mutation(&scheduler, "purge", &selector, &actor).await?,
    ))
}

/// POST /api/v1/scheduler/tasks/submit
///
/// Control endpoint that submits arbitrary tasks into the scheduler.
///
/// `Mutator` extracts first and rejects unauthorized requests before
/// `Json` runs, so an attacker cannot make us deserialize an arbitrary
/// body without an admitted workflow's OIDC token.
pub async fn submit_scheduler_tasks(
    Mutator { caller, actor, .. }: Mutator<SubmitRoute>,
    Json(trees): Json<Vec<stow_types::api::SubmissionTree>>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::SchedulerSubmitResponse>, GetArtifactError> {
    // The edge resolves nothing (stow#429): every lane that posts here
    // already submits resolver-canonical trees, so they land verbatim —
    // `Json` deserialization itself is the only check (`FeaturesJson`
    // rejects a non-canonical feature list there).
    // Admitted workflows' submissions are exempt from the pending-depth
    // cap — the workflow pin is the bound on this path.
    let nodes: usize = trees.iter().map(|tree| tree.nodes.len()).sum();
    let inserted = scheduler_client::send_enqueue_trusted(&scheduler, &trees, &actor).await?;
    tracing::info!(tasks = nodes, %caller, "submitted scheduler tasks");
    Ok(Json(stow_types::api::SchedulerSubmitResponse {
        submitted: u32::try_from(nodes).map_err(|_| {
            GetArtifactError::TooLarge("submitted task count exceeds u32".to_owned())
        })?,
        inserted,
        // Verbatim submission drops nothing; the field stays on the wire
        // shape the submitters already parse.
        dropped: 0,
    }))
}

/// POST /api/v1/scheduler/tasks/submit-ids — the missed lane's trusted
/// promote path (stow#588): forwards the task ids to the DO's
/// submit-by-id route; the scheduler resolves each subgraph from its
/// node store and reports ids it does not hold as `unknown`.
pub async fn submit_task_ids(
    Mutator { caller, actor, .. }: Mutator<SubmitIdsRoute>,
    Json(request): Json<stow_types::api::SubmitTaskIdsRequest>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::SubmitTaskIdsResponse>, GetArtifactError> {
    let response = scheduler_client::send_task_ids(&scheduler, &request, &actor).await?;
    tracing::info!(
        tasks = request.tasks.len(),
        unknown = response.unknown.len(),
        %caller,
        "submitted scheduler task ids"
    );
    Ok(Json(response))
}

/// GET /api/v1/scheduler/status
pub async fn scheduler_status(
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Response, GetArtifactError> {
    let status = scheduler_client::get_status(&scheduler).await?;
    cacheable_json(&status, POINT_IN_TIME_NO_STORE)
}

/// GET /api/v1/scheduler/health
///
/// The unauthenticated liveness probe (stow#860): one scheduler request
/// reading state the object already holds — no D1, no GHCR, no GitHub
/// call. `no-store` so Workers Cache never replays a stale answer.
/// An `unhealthy` scheduler component answers 503 — the status the
/// edge already gives an unavailable dependency — so a plain HTTP
/// uptime check needs no JSON parsing.
pub async fn scheduler_health(
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Response, GetArtifactError> {
    let health = scheduler_client::get_health(&scheduler).await?;
    let mut response = cacheable_json(&health, POINT_IN_TIME_NO_STORE)?;
    if health.scheduler != stow_types::api::HealthState::Ok {
        *response.status_mut() = skyzen::StatusCode::SERVICE_UNAVAILABLE;
    }
    Ok(response)
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
    // The request's version resolve (cached crates.io reads) and the stable rustc
    // resolve (a Cache API read) are independent, so they overlap.
    let (version, rustc_version) = futures_util::try_join!(
        async { resolve_request_version(&cache, &crates_io, &request).await },
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
/// `Mutator` extracts first and rejects unauthorized requests before
/// `Json` runs.
pub async fn scheduler_request_outcome(
    Mutator { actor, .. }: Mutator<RequestOutcomeRoute>,
    params: Params,
    Json(report): Json<stow_types::api::RequestOutcomeReport>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::CrateRequestStatus>, GetArtifactError> {
    let request_id = params
        .get("request_id")
        .map_err(|_| GetArtifactError::BadRequest)?;
    let status =
        scheduler_client::send_request_outcome(&scheduler, request_id, &report, &actor).await?;
    Ok(Json(status))
}

/// Resolve the requested version — exact-published check when given, else
/// the newest non-prerelease, non-yanked release.
async fn resolve_request_version(
    cache: &impl dependency_resolver::CratesIoCache,
    crates_io: &crates_io::CfCratesIo,
    request: &CrateRequest,
) -> Result<semver::Version, GetArtifactError> {
    let resolved = match request.version.as_ref() {
        Some(version) => {
            dependency_resolver::published_version(
                cache,
                crates_io,
                request.crate_name.as_str(),
                version.as_semver(),
            )
            .await?
        }
        None => {
            dependency_resolver::latest_published_version(
                cache,
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
pub async fn crate_versions(
    params: Params,
    State(cache): State<CfCache>,
) -> Result<Response, GetArtifactError> {
    let crate_name = path_crate_name(&params)?;
    let response = catalog::crate_versions(
        &cache,
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
pub async fn crate_features(
    params: Params,
    State(cache): State<CfCache>,
) -> Result<Response, GetArtifactError> {
    let crate_name = path_crate_name(&params)?;
    let version = params
        .get("version")
        .map_err(|_| GetArtifactError::BadRequest)?
        .parse::<CrateVersion>()
        .map_err(|error| GetArtifactError::BadRequestWithMessage(error.to_string()))?;
    let response = catalog::crate_features(
        &cache,
        &crates_io::CfCratesIo::new(OutboundPool::new()),
        crate_name.as_str(),
        version.as_semver(),
    )
    .await?;
    cacheable_json(&response, CATALOG_VERSIONS_MAX_AGE)
}

/// GET /`api/v1/bundles/{rustc_version}/{digest}`
///
/// The byte path: streams the `<tag>.bundle` blobs under the rustc's
/// `ghcr.io/water-rs/stow-cache-<rustc>` package, handing workerd the
/// upstream body as the registry's own stream so the bytes never enter
/// wasm. The `sha256:<64 lowercase hex>` path segment is validated before
/// any fetch; the answer's immutable `Cache-Control` is what Workers Cache
/// stores and replays without this worker running; a GHCR 404 is a 404.
/// No catalog row is consulted: the CLI's signed index named these bytes,
/// and the CLI verifies them against the index before they are used.
pub async fn get_bundle(
    params: Params,
    State(ghcr): State<GhcrConfig>,
    State(stats_ctx): State<stats::StatsContext>,
    telemetry: stats::HitTelemetry,
) -> Result<Response, GetArtifactError> {
    let rustc_version = params
        .get("rustc_version")
        .map_err(|_| GetArtifactError::BadRequest)?
        .parse::<WireRustcVersion>()
        .map_err(|error| GetArtifactError::BadRequestWithMessage(error.to_string()))?;
    let digest = params
        .get("digest")
        .map_err(|_| GetArtifactError::BadRequest)?;
    if !stow_types::registry::is_sha256_digest(digest) {
        return Err(GetArtifactError::BadRequestWithMessage(format!(
            "malformed bundle digest `{digest}` — expected sha256:<64 lowercase hex>"
        )));
    }

    let response = open_bundle_stream(&ghcr, &rustc_version, digest)
        .await
        .map_err(registry_fetch_error)?;
    // The platform cache replays most fetches before this worker runs,
    // so a hit point is recorded only for serves it observed — an
    // undercount by design (stow#889): the digest is what the request
    // already named, identity is recovered offline.
    stats_ctx.record_hit(
        &telemetry,
        &stats::Hit {
            rustc_version: rustc_version.as_str(),
            digest,
            bundle_size: response
                .headers()
                .get(skyzen::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok()),
        },
    );
    Ok(response)
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
    let repository = stow_types::registry::cache_repository(rustc_version);
    let mut response =
        ghcr::open_manifest(&ghcr.base_url, repository.path(), &tag, &ghcr.tokens, pool)
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
    let repository = stow_types::registry::cache_repository(rustc_version);
    let upstream = ghcr::open_blob(
        &ghcr.base_url,
        repository.path(),
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

/// Decorate the slice answer with its headers. `Content-Type` is
/// `application/json` because `Content-Encoding` describes the transfer
/// encoding: the bytes the client ends up reading are always the index
/// JSON document.
fn slice_response(
    mut response: Response,
    encoding: index_slice::SliceEncoding,
    content_length: Option<u64>,
) -> Response {
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
/// `Content-Encoding`: `zstd` hands workerd the upstream stream itself,
/// so the published blob passes through byte-for-byte without entering
/// wasm; anything else gets a gzip transcode, cached per encoding by the
/// `Vary` the answer carries.
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
                passthrough_upstream(upstream).map_err(registry_fetch_error)?,
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
                Response::new(Body::from(gzip)),
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
/// the cargo-expanded `c_metadata` edges. The edge re-derives the
/// posted graph's candidate nodes (crates.io feature expansion plus
/// reachability), mints one stateless admission per miss tree, and
/// returns them for the client to redeem through the proof-of-work
/// gated `/api/v1/enqueue`. The graph itself is never
/// needed to *find* artifacts — the index already did that — so nothing
/// here feeds a lookup.
pub async fn mint_miss_admissions(
    Json(request): Json<AdmissionRequest>,
    State(admission): State<PowAdmission>,
    State(settings): State<crate::runtime_settings::ResolverSettings>,
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
        request.target.as_str(),
        request.rustc_version.as_str(),
        &request.entries,
        &request.expanded_entries,
    )
    .map_err(|error| {
        tracing::error!(%error, "admission miss derivation failed");
        GetArtifactError::InternalWithMessage(error.to_string())
    })?;
    let enqueue_requests = plan.enqueue_requests;
    if enqueue_requests.is_empty() {
        return Ok(Json(Vec::new()));
    }
    // One admission and one redemption per report tree (stow#878): the
    // resolved graph folds into a single submission tree the ticket's
    // PoW binds, carrying the CLI kind the request claimed (stow#882) —
    // `CliAdmissionSource` admits only miss and inexact-hit sources.
    let tree = stow_types::api::SubmissionTree::from_enqueue_requests(
        request.source.submission_source(),
        &enqueue_requests,
    )
    .map_err(|error| GetArtifactError::InternalWithMessage(format!("miss tree: {error}")))?;
    let difficulty = admission::difficulty(admission.min_bits);
    let admissions = mint_admissions(&admission, vec![tree], difficulty).map_err(|error| {
        tracing::error!(%error, "failed to mint dependency-graph miss admissions");
        GetArtifactError::InternalWithMessage(error.to_string())
    })?;
    Ok(Json(admissions))
}

/// POST /api/v1/enqueue
///
/// Redeem a miss admission statelessly: recompute the HMAC challenge over
/// the request the ticket carries, check the client's proof-of-work against
/// the queue depth current at redemption time (one bit lenient — the queue
/// may have grown since the miss response), then forward that request to
/// The admission gate of `POST /api/v1/enqueue`: challenge + tree-id
/// binding, extracted so the handler stays under the size lint
/// (stow#878's tree ticket reuses the same gate).
fn verify_enqueue_ticket(
    ticket: &EnqueueTicket,
    admission: &PowAdmission,
) -> Result<(), GetArtifactError> {
    let request_json = serde_json::to_vec(&ticket.tree)
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
    // The challenge binds the ticket's task id to the tree's first
    // root; recompute it so a verified ticket always forwards what it
    // minted.
    let derived_task_id = ticket
        .tree
        .roots
        .first()
        .and_then(|&root| ticket.tree.nodes.get(root as usize))
        .map(|node| node.task_id.clone())
        .ok_or_else(|| {
            GetArtifactError::BadRequestWithMessage("submission tree names no roots".to_owned())
        })?;
    if derived_task_id != ticket.task_id {
        tracing::warn!(task_id = %ticket.task_id, "rejected enqueue ticket: task id mismatch");
        return Err(GetArtifactError::Unauthorized);
    }
    Ok(())
}

/// `POST /api/v1/enqueue` — verify the ticket, record the miss and
/// forward the tree to the scheduler. Replay is safe — the scheduler
/// deduplicates on task id.
pub async fn enqueue_admitted_task(
    Json(ticket): Json<EnqueueTicket>,
    State(scheduler): State<CfDurableNamespace>,
    State(admission): State<PowAdmission>,
    State(analytics): State<AnalyticsEngineDataset>,
    consent: stats::AnalyticsConsent,
) -> Result<Response, GetArtifactError> {
    verify_enqueue_ticket(&ticket, &admission)?;
    // A client builds for whatever host it runs on, and plenty of those are
    // machines this cache has no runner for. Refuse before the ticket can
    // become a dispatch that cannot run.
    if let Some(node) = ticket
        .tree
        .nodes
        .iter()
        .find(|node| !stow_types::api::is_ci_target(node.target.as_str()))
    {
        tracing::info!(
            task_id = %ticket.task_id,
            target = %node.target,
            "rejected enqueue ticket: no CI runner builds this target"
        );
        return Err(GetArtifactError::UnsupportedTarget {
            target: node.target.to_string(),
            supported: CI_TARGET_TRIPLES.join(", "),
        });
    }
    // The proof of work is pure CPU, so it verifies before the one
    // forward — the Durable Object's own pending-depth cap refuses a
    // full queue at submit and the handler maps that 429 below
    // (stow#940: the `GET /status` pre-check cost a scheduler request
    // to save none).
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

    // The ticket is verified: the miss enters the scheduler's CLI
    // entry point directly (stow#886) — a failed send is the request's
    // own error, not a row a drain would retry.
    match scheduler_client::send_enqueue(&scheduler, std::slice::from_ref(&ticket.tree)).await {
        Ok(unpublished_ids) => {
            // The merge's born-published check is the coverage verdict:
            // one Analytics Engine point per node it found unpublished.
            let unpublished: std::collections::BTreeSet<String> =
                unpublished_ids.into_iter().collect();
            miss_logger::log_misses(&analytics, consent, &ticket.tree, &unpublished);
        }
        // The Durable Object's own pending-depth cap refused this
        // redemption — the queue filled between ticket and submit.
        Err(crate::errors::SchedulerClientError::Http { status: 429, .. }) => {
            let mut response = rate_limited_response(
                "scheduler queue is full; retry after it drains",
                QUEUE_FULL_RETRY_AFTER_SECS,
            )?;
            response
                .extensions_mut()
                .insert(crate::faults::OverloadFault);
            return Ok(response);
        }
        Err(error) => return Err(error.into()),
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

/// Decorate the bundle answer with its headers: the body is the
/// published bundle blob byte-for-byte, so its length is the upstream
/// `content-length` when the registry reported one. The immutable
/// `Cache-Control` is the whole caching contract Workers Cache needs to
/// answer later reads without this worker running.
fn bundle_response(mut response: Response, content_length: Option<u64>) -> Response {
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

/// Answer with the bundle for `digest` as the registry's stream itself.
/// Nothing on this path buffers the bundle, inspects it or copies it
/// through wasm — the publish stage validated the tar before pushing it,
/// GHCR addresses it by content, and the CLI verifies the digest and the
/// cosign material inside it.
async fn open_bundle_stream(
    ghcr: &GhcrConfig,
    rustc_version: &WireRustcVersion,
    digest: &str,
) -> Result<Response, ghcr::FetchError> {
    let repository = stow_types::registry::cache_repository(rustc_version);
    let upstream = ghcr::open_blob(
        &ghcr.base_url,
        repository.path(),
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
    Ok(bundle_response(
        passthrough_upstream(upstream)?,
        content_length,
    ))
}

/// Hand the registry's body to workerd as the very stream it arrived as.
/// It never enters wasm: copying it chunk by chunk into wasm memory and
/// back out cost 63 ms of Worker CPU per bundle on average. The answer
/// starts from an empty header set — GHCR's `cache-control`, `etag`,
/// `docker-*` and cookie headers are the registry's, not this origin's —
/// and the caller sets exactly the headers it serves.
fn passthrough_upstream(upstream: worker::Response) -> Result<Response, ghcr::FetchError> {
    let js: worker::web_sys::Response = upstream.into();
    let mut response = passthrough_js_response(&js)
        .map_err(|error| ghcr::FetchError::Network(format!("wrap registry response: {error:?}")))?;
    response.headers_mut().clear();
    Ok(response)
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

/// POST /api/v1/build-report — the CLI's at-most-daily usage rollup
/// (stow#889): one `build` point in `stow_events` carrying the deltas
/// the body reports — hits, misses, builds and CPU milliseconds saved
/// that the platform cache hides from the byte path. Anonymous and
/// write-only: no scheduler, the consent extractor decides
/// whether the point lands at all.
pub async fn build_report(
    Json(report): Json<stow_types::api::BuildReport>,
    State(stats_ctx): State<stats::StatsContext>,
    telemetry: stats::HitTelemetry,
) -> Result<StatusCode, GetArtifactError> {
    stats_ctx.record_build_report(&telemetry, &report);
    Ok(StatusCode::NO_CONTENT)
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
