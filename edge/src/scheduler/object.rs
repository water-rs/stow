//! Durable Object glue: routes scheduler HTTP/alarm events into the queue
//! state machine and GitHub dispatch.

use futures_util::stream::{self, StreamExt as _};
use js_sys::Reflect;
use serde::{Deserialize, Serialize};
use skyzen::durable::DurableObject;
use skyzen::routing::{CreateRouteNode, Params, Route, Router};
use skyzen::runtime::wasm::WasmEnv;
use skyzen::utils::Json;
use skyzen::{Error, Result, StatusCode};
use skyzen_services::durable::{Alarm, DurableDb};
use wasm_bindgen::JsValue;

use std::collections::BTreeSet;

use skyzen_cloudflare::CfD1;
use skyzen_services::Db;
use stow_types::api::SchedulerResetReport;

use crate::db;
use crate::errors::QueueError;
use crate::freeze::{self, FreezeSettings};
use crate::github_app;
use crate::scheduler::batching::FormedBatch;
use crate::scheduler::dispatch::BuildRuns as _;
use crate::scheduler::meter::{self, Meter, MeterGuard};
use crate::scheduler::queue::SchedulerSettings;
use crate::scheduler::{budget, fixture};
use crate::scheduler::{dispatch, feed, queue};

const STOW_LOCAL_CI_URL_BINDING: &str = "STOW_LOCAL_CI_URL";
/// The catalog D1 binding — `pub(super)` so the budget probe's counted
/// backend wraps the same binding the dispatch path reads.
pub(super) const STOW_DB_BINDING: &str = "STOW_DB";
const STOW_DISPATCH_MIN_AGE_MINUTES_BINDING: &str = "STOW_DISPATCH_MIN_AGE_MINUTES";
const STOW_MAX_CONCURRENT_JOBS_BINDING: &str = "STOW_MAX_CONCURRENT_JOBS";
const STOW_MAX_CONCURRENT_MACOS_JOBS_BINDING: &str = "STOW_MAX_CONCURRENT_MACOS_JOBS";
const STOW_STALE_DISPATCH_MINUTES_BINDING: &str = "STOW_STALE_DISPATCH_MINUTES";
const STOW_MAX_QUEUE_PENDING_BINDING: &str = "STOW_MAX_QUEUE_PENDING";
const STOW_HUMAN_DAILY_TASK_BUDGET_BINDING: &str = "STOW_HUMAN_DAILY_TASK_BUDGET";
const STOW_MIN_DISPATCH_VALUE_BINDING: &str = "STOW_MIN_DISPATCH_VALUE";
const STOW_BATCH_PARALLELISM_BINDING: &str = "STOW_BATCH_PARALLELISM";
const STOW_BATCH_MAX_TASKS_BINDING: &str = "STOW_BATCH_MAX_TASKS";
const GITHUB_APP_ID_BINDING: &str = "GITHUB_APP_ID";
const GITHUB_APP_INSTALLATION_ID_BINDING: &str = "GITHUB_APP_INSTALLATION_ID";
const GITHUB_APP_PRIVATE_KEY_BINDING: &str = "GITHUB_APP_PRIVATE_KEY";
const GITHUB_REPO_BINDING: &str = "GITHUB_REPO";
const STOW_FREEZE_WINDOW_MINUTES_BINDING: &str = "STOW_FREEZE_WINDOW_MINUTES";
const STOW_FREEZE_MIN_OUTCOMES_BINDING: &str = "STOW_FREEZE_MIN_OUTCOMES";
const STOW_FREEZE_FAIL_PERCENT_BINDING: &str = "STOW_FREEZE_FAIL_PERCENT";
const STOW_COST_BUDGET_MULTIPLIER_BINDING: &str = "STOW_COST_BUDGET_MULTIPLIER";

fn scheduler_settings(env: &WasmEnv) -> Result<SchedulerSettings> {
    // The local-CI dispatcher only exists beside the budget probe: a
    // deploy carrying `STOW_LOCAL_CI_URL` without the probe marker is
    // misconfigured — every scheduler route fails on it here rather
    // than let one pass reach the unauthenticated credential arm.
    if read_optional_string_binding(env, STOW_LOCAL_CI_URL_BINDING).is_some()
        && !budget_probe_enabled(env)
    {
        return Err(Error::msg(
            "STOW_LOCAL_CI_URL is set without STOW_SCHEDULER_BUDGET — \
             local-CI dispatch exists only on the mock budget-probe deploy",
        ));
    }
    let defaults = SchedulerSettings::default();
    Ok(SchedulerSettings {
        dispatch: read_optional_u32_binding(env, STOW_MAX_CONCURRENT_JOBS_BINDING)?
            .map_or(defaults.dispatch, queue::Dispatch::from_max_concurrent_jobs),
        max_concurrent_macos_jobs: read_optional_u32_binding(
            env,
            STOW_MAX_CONCURRENT_MACOS_JOBS_BINDING,
        )?
        .unwrap_or(defaults.max_concurrent_macos_jobs),
        dispatch_min_age_minutes: read_optional_u32_binding(
            env,
            STOW_DISPATCH_MIN_AGE_MINUTES_BINDING,
        )?
        .unwrap_or(defaults.dispatch_min_age_minutes),
        stale_dispatch_minutes: read_optional_u32_binding(
            env,
            STOW_STALE_DISPATCH_MINUTES_BINDING,
        )?
        .unwrap_or(defaults.stale_dispatch_minutes),
        max_queue_pending: read_optional_u32_binding(env, STOW_MAX_QUEUE_PENDING_BINDING)?
            .unwrap_or(defaults.max_queue_pending),
        human_daily_task_budget: read_optional_u32_binding(
            env,
            STOW_HUMAN_DAILY_TASK_BUDGET_BINDING,
        )?
        .unwrap_or(defaults.human_daily_task_budget),
        min_dispatch_value: read_optional_i64_binding(env, STOW_MIN_DISPATCH_VALUE_BINDING)?
            .unwrap_or(defaults.min_dispatch_value),
        batch_parallelism: read_optional_u32_binding(env, STOW_BATCH_PARALLELISM_BINDING)?
            .unwrap_or(defaults.batch_parallelism),
        batch_max_tasks: read_optional_u32_binding(env, STOW_BATCH_MAX_TASKS_BINDING)?
            .unwrap_or(defaults.batch_max_tasks),
    })
}

/// The trip thresholds the failure-rate window and the cost budgets are
/// evaluated with — same binding-with-default shape as the scheduler
/// tunables.
fn freeze_settings(env: &WasmEnv) -> Result<FreezeSettings> {
    let defaults = FreezeSettings::default();
    Ok(FreezeSettings {
        window_minutes: read_optional_u32_binding(env, STOW_FREEZE_WINDOW_MINUTES_BINDING)?
            .unwrap_or(defaults.window_minutes),
        min_outcomes: read_optional_u32_binding(env, STOW_FREEZE_MIN_OUTCOMES_BINDING)?
            .unwrap_or(defaults.min_outcomes),
        fail_percent: read_optional_u32_binding(env, STOW_FREEZE_FAIL_PERCENT_BINDING)?
            .unwrap_or(defaults.fail_percent),
    })
}

/// `freeze::FreezeStore` over the object's own `settings` row — the
/// storage seam the transition coordinator runs on.
struct DbStore<'a>(&'a DurableDb);

impl freeze::FreezeStore for DbStore<'_> {
    fn record(
        &self,
    ) -> impl std::future::Future<
        Output = std::result::Result<Option<stow_types::api::DispatchFreezeRecord>, QueueError>,
    > + Send {
        queue::freeze_record(self.0)
    }
    fn set(
        &self,
        record: &stow_types::api::DispatchFreezeRecord,
    ) -> impl std::future::Future<Output = std::result::Result<(), QueueError>> + Send {
        queue::set_freeze(self.0, record)
    }
    fn delete(
        &self,
    ) -> impl std::future::Future<Output = std::result::Result<(), QueueError>> + Send {
        queue::delete_freeze(self.0)
    }
}

/// `freeze::AlertSink` over the edge's one alert channel — the
/// `send_email` notify (`crate::email::EdgeAlerter`). A missing
/// binding degrades to a `Disabled` outcome instead of erroring, so a
/// transition always lands its record. The `incident` issue record is
/// the #450 watchdog's: it reads this object's freeze state and its
/// transition log over the admin route, because the edge's App token
/// has no `issues` grant and will not get one.
type EdgeAlerter = crate::email::EdgeAlerter;

#[derive(Debug, Default, Serialize, Deserialize)]
#[skyzen::durable_object]
pub struct Scheduler;

impl DurableObject for Scheduler {
    fn fetch(&self) -> Router {
        // The Durable Object runs in its own isolate; the exported fetch
        // goes through this method before the router responds, so this is
        // where its logging gets installed.
        #[cfg(target_arch = "wasm32")]
        crate::console_log::init();
        Route::new((
            // Grouped to stay under the router's route-tuple arity —
            // the URLs are unchanged.
            "/tasks".route((
                "".at(list_tasks),
                "/submit".post(submit_tasks),
                "/submit/trusted".post(submit_tasks_trusted),
                "/submit/ids".post(submit_tasks_by_id),
                "/retry".post(queue_retry),
                "/cancel".post(queue_cancel),
                "/promote".post(queue_promote),
                "/purge".post(queue_purge),
            )),
            // The batched run's completion channel (stow#833 §3.2):
            // the report lands on the `build_batches` row verbatim and
            // the alarm pass resolves each leg from it.
            "/batches/{batch_id}/complete".post(complete_batch),
            // The human request lane (stow#428): admit deduplicates on
            // the request id and dispatches `resolve-request.yml`;
            // `outcome` is the resolve job's report channel and
            // `run-update` the webhook's `workflow_run` lifecycle events
            // for that run — the record's status is what
            // `GET /api/v1/requests/{id}` serves.
            "/requests".route((
                "".post(admit_request),
                "/{request_id}".at(read_request),
                "/{request_id}/outcome".post(apply_request_outcome),
                "/{request_id}/run-update".post(apply_request_run_update),
            )),
            "/status".at(status),
            "/admin/status".at(admin_status),
            "/index/published".post(record_published_index),
            "/reset".post(reset_scheduler),
            // The workerd budget probe — gated on the
            // `STOW_SCHEDULER_BUDGET` deploy var, which only mock stacks
            // carry; production requests hit the guard and 404.
            "/budget".post(scheduler_budget),
            "/budget/seed".post(scheduler_budget_seed),
            "/budget/ledger".at(scheduler_budget_ledger),
            // Trusted demand batches — #522's demand input; reached
            // from `POST /api/v1/admin/scheduler/demand`.
            "/demand".post(scheduler_demand),
            // The hourly demand feed's durable staging/delivery
            // surface (stow#523): `begin`/`page`/`complete` freeze one
            // closed-hour Analytics Engine response into bounded
            // immutable pages; `deliver` replays the next original
            // page into the demand ledger and `status` is the resume
            // cursor. All reached from
            // `POST /api/v1/admin/scheduler/demand-feed/*`.
            "/demand-feed".route((
                "/begin".post(demand_feed_begin),
                "/page".post(demand_feed_page),
                "/complete".post(demand_feed_complete),
                "/cleanup".post(demand_feed_cleanup),
                "/deliver".post(demand_feed_deliver),
                "/status".at(demand_feed_status),
            )),
            // A nested Route under the root — the outer tuple caps at
            // 15 nodes.
            Route::new(("/dispatch-freeze"
                .at(read_dispatch_freeze)
                .post(write_dispatch_freeze),)),
        ))
        .on_alarm(run_alarm)
        .build()
        .layer(MeterGuard)
    }
}

/// `POST /reset` — the only endpoint that may issue DDL on the queue
/// database. Reached from `POST /api/v1/admin/scheduler/reset`, which
/// `stow-admin scheduler reset --yes` invokes. Drops every store object
/// and re-executes `schema.sql`, then stamps the configured dispatch
/// floor — on the empty queue its conditional backfill is a zero-row
/// pass.
async fn reset_scheduler(env: WasmEnv, db: DurableDb) -> Result<Json<SchedulerResetReport>> {
    let settings = scheduler_settings(&env)?;
    let report = queue::reset(&db).await.map_err(to_error)?;
    queue::apply_dispatch_floor(&db, &settings)
        .await
        .map_err(to_error)?;
    tracing::warn!(dropped = report.dropped, "scheduler store reset");
    Ok(Json(report))
}

/// `POST /budget/seed` — load the production-shaped fixture through the
/// operator path. Reached from `POST /api/v1/admin/scheduler/budget/seed`.
/// Answers only on deploys carrying `STOW_SCHEDULER_BUDGET=1` — the mock
/// stack's `Skyzen.mock.toml` sets it; production never does.
async fn scheduler_budget_seed(
    env: WasmEnv,
    db: DurableDb,
    Json(request): Json<stow_types::api::SchedulerSeedRequest>,
) -> Result<Json<stow_types::api::SchedulerSeedReport>> {
    if !budget_probe_enabled(&env) {
        return Err(
            Error::msg("scheduler budget probe is not enabled on this deploy")
                .set_status(StatusCode::NOT_FOUND),
        );
    }
    Ok(Json(
        fixture::seed(&db, &request, &scheduler_settings(&env)?)
            .await
            .map_err(to_error)?,
    ))
}

/// `POST /budget` — replay every drive under the metering backend and
/// return the real `rowsRead`/`rowsWritten` per route. Same guard as the
/// seed endpoint. Reached from `POST /api/v1/admin/scheduler/budget`.
async fn scheduler_budget(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(request): Json<stow_types::api::SchedulerBudgetRequest>,
) -> Result<Json<stow_types::api::SchedulerBudgetReport>> {
    if !budget_probe_enabled(&env) {
        return Err(
            Error::msg("scheduler budget probe is not enabled on this deploy")
                .set_status(StatusCode::NOT_FOUND),
        );
    }
    let settings = scheduler_settings(&env)?;
    Ok(Json(
        budget::run(&db, &settings, &env, &alarm, &request)
            .await
            .map_err(to_error)?,
    ))
}

/// `GET /budget/ledger` — the per-operation billed rows the meter booked
/// since the last reset (stow#773). Same guard as the seed endpoint.
/// Reached from `GET /api/v1/admin/scheduler/budget/ledger`.
async fn scheduler_budget_ledger(
    env: WasmEnv,
    db: DurableDb,
) -> Result<Json<stow_types::api::SchedulerLedger>> {
    if !budget_probe_enabled(&env) {
        return Err(
            Error::msg("scheduler budget probe is not enabled on this deploy")
                .set_status(StatusCode::NOT_FOUND),
        );
    }
    Ok(Json(meter::ledger(&db).await.map_err(to_error)?))
}

/// Whether this deploy carries the budget probe — `STOW_SCHEDULER_BUDGET=1`,
/// the mock stack only. The probe routes answer and the meter books its
/// per-operation ledger only then.
pub(super) fn budget_probe_enabled(env: &WasmEnv) -> bool {
    read_optional_string_binding(env, budget::BUDGET_PROBE_BINDING)
        .is_some_and(|value| value == "1")
}

/// `POST /demand` — trusted demand batches (stow#522 I7). Reached only
/// through `POST /api/v1/admin/scheduler/demand`; never a request path.
async fn scheduler_demand(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(request): Json<stow_types::api::SchedulerDemandRequest>,
) -> Result<Json<stow_types::api::SchedulerDemandReport>> {
    let (now_ms, settings) = alarm_inputs(&env)?;
    let (report, plan) = queue::demand_pass(&db, &request, now_ms, &settings)
        .await
        .map_err(|error| {
            let status = match &error {
                crate::errors::QueueError::Invariant(_)
                | crate::errors::QueueError::Overflow { .. } => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            to_error(error).set_status(status)
        })?;
    // A folded batch can raise a queue row over the admission floor
    // (or clear its age gate) — arm the plan the shared pass decided,
    // an exact replay included: a replay repairs a schedule a
    // previously lost response never armed, and an under-floor queue
    // arms nothing (stow#525).
    queue::arm_alarm(&alarm, plan).await.map_err(|error| {
        let error = to_error(error);
        tracing::error!(%error, "scheduler demand schedule_alarm failed");
        error
    })?;
    Ok(Json(report))
}

/// The feed's clock — `js_sys::Date::now()` seconds, same source as
/// `alarm_inputs`.
fn feed_now_secs() -> i64 {
    #[allow(clippy::cast_possible_truncation)]
    let now_ms = js_sys::Date::now() as i64;
    now_ms / 1_000
}

/// `POST /demand-feed/begin` — open or rotate the hour's staging
/// attempt (stow#523).
async fn demand_feed_begin(
    db: DurableDb,
    Json(request): Json<stow_types::api::DemandFeedBeginRequest>,
) -> Result<Json<stow_types::api::DemandFeedBeginReport>> {
    feed::feed_begin(&db, &request.hour, feed_now_secs())
        .await
        .map(Json)
        .map_err(demand_feed_error)
}

/// `POST /demand-feed/page` — stage one bounded immutable page.
async fn demand_feed_page(
    db: DurableDb,
    Json(request): Json<stow_types::api::DemandFeedPageRequest>,
) -> Result<Json<serde_json::Value>> {
    feed::feed_page(&db, &request, feed_now_secs())
        .await
        .map(|()| Json(serde_json::json!({"staged": true})))
        .map_err(demand_feed_error)
}

/// `POST /demand-feed/complete` — the completion barrier: freeze the
/// hour once every page of its generation is staged and the manifest
/// matches.
async fn demand_feed_complete(
    db: DurableDb,
    Json(request): Json<stow_types::api::DemandFeedCompleteRequest>,
) -> Result<Json<serde_json::Value>> {
    feed::feed_complete(&db, &request, feed_now_secs())
        .await
        .map(|()| Json(serde_json::json!({"complete": true})))
        .map_err(demand_feed_error)
}

/// `POST /demand-feed/cleanup` — retire one bounded chunk of the
/// hour's dead page rows (obsolete generations or a delivered hour's
/// acknowledged payloads). Explicit event work, never a timer.
async fn demand_feed_cleanup(
    db: DurableDb,
    Json(request): Json<stow_types::api::DemandFeedCleanupRequest>,
) -> Result<Json<stow_types::api::DemandFeedCleanupReport>> {
    feed::feed_cleanup(&db, &request.hour, feed_now_secs())
        .await
        .map(Json)
        .map_err(demand_feed_error)
}

/// `POST /demand-feed/deliver` — replay the next undelivered original
/// page into the demand ledger, then arm the plan the shared pass
/// decided — the same probe/rearm `/demand` performs.
async fn demand_feed_deliver(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(request): Json<stow_types::api::DemandFeedDeliverRequest>,
) -> Result<Json<stow_types::api::DemandFeedDeliverReport>> {
    let (now_ms, settings) = alarm_inputs(&env)?;
    let (report, plan) = feed::feed_deliver(&db, &request.hour, now_ms, &settings)
        .await
        .map_err(demand_feed_error)?;
    queue::arm_alarm(&alarm, plan).await.map_err(|error| {
        let error = to_error(error);
        tracing::error!(%error, "demand feed deliver schedule_alarm failed");
        error
    })?;
    Ok(Json(report))
}

/// `GET /demand-feed/status` — the durable resume cursor.
async fn demand_feed_status(db: DurableDb) -> Result<Json<stow_types::api::DemandFeedStatus>> {
    feed::feed_status(&db)
        .await
        .map(Json)
        .map_err(demand_feed_error)
}

/// Map a feed [`QueueError`] — contract violations are 400s like
/// `/demand`'s, storage failures 500s.
fn demand_feed_error(error: QueueError) -> Error {
    let status = match &error {
        QueueError::Invariant(_) | QueueError::Overflow { .. } => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    to_error(error).set_status(status)
}

/// `POST /tasks/submit` — the anonymous-lane submit. The pending-depth
/// cap refuses miss-lane batches once the queue is full, and human-lane
/// tasks spend against the daily budget; either refusal answers 429.
async fn submit_tasks(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(requests): Json<Vec<stow_types::api::EnqueueRequest>>,
) -> Result<Json<InsertedResponse>> {
    submit(&env, &db, &alarm, &requests, true).await
}

/// `POST /tasks/submit/trusted` — the same submit minus the
/// pending-depth cap: callers reached it through the edge's repo-writer
/// trust check, so a full queue must not turn their work away.
async fn submit_tasks_trusted(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(requests): Json<Vec<stow_types::api::EnqueueRequest>>,
) -> Result<Json<InsertedResponse>> {
    submit(&env, &db, &alarm, &requests, false).await
}

/// `POST /tasks/submit/ids` — the trusted submit-by-id lane (stow#588):
/// the missed lane promotes an admitted miss by its exact task id; the
/// scheduler rebuilds each subgraph from its node store (never a
/// re-mint) and reports the ids it does not hold as `unknown`. The
/// pending-depth cap does not apply — the edge's repo-writer trust
/// check is the bound — but a frozen queue still refuses.
async fn submit_tasks_by_id(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(body): Json<stow_types::api::SubmitTaskIdsRequest>,
) -> Result<Json<stow_types::api::SubmitTaskIdsResponse>> {
    let settings = scheduler_settings(&env)?;
    refuse_if_frozen(&db).await?;
    let outcome = queue::submit_task_ids(&db, &body.tasks, &settings)
        .await
        .map_err(|error| {
            let status = match &error {
                crate::errors::QueueError::QueueFull { .. }
                | crate::errors::QueueError::HumanDailyBudgetExhausted { .. } => {
                    StatusCode::TOO_MANY_REQUESTS
                }
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            to_error(error).set_status(status)
        })?;
    if !outcome.unknown.is_empty() {
        tracing::info!(
            unknown = outcome.unknown.len(),
            "submit-by-id: node store misses"
        );
    }
    // Same hand-off as submit: the alarm pass owns dispatch.
    schedule_alarm(&env, &db, &alarm).await?;
    Ok(Json(stow_types::api::SubmitTaskIdsResponse {
        submitted: u32::try_from(body.tasks.len()).map_err(|_| {
            to_error("submit-ids task count exceeds u32").set_status(StatusCode::PAYLOAD_TOO_LARGE)
        })?,
        inserted: outcome.inserted,
        unknown: outcome.unknown,
    }))
}

async fn submit(
    env: &WasmEnv,
    db: &DurableDb,
    alarm: &Alarm,
    requests: &[stow_types::api::EnqueueRequest],
    enforce_pending_cap: bool,
) -> Result<Json<InsertedResponse>> {
    let settings = scheduler_settings(env)?;
    if !enforce_pending_cap {
        refuse_if_frozen(db).await?;
    }
    let result = if enforce_pending_cap {
        queue::enqueue(db, requests, &settings).await
    } else {
        queue::enqueue_trusted(db, requests, &settings).await
    };
    let inserted = result.map_err(|error| {
        let status = match &error {
            crate::errors::QueueError::QueueFull { .. }
            | crate::errors::QueueError::HumanDailyBudgetExhausted { .. } => {
                StatusCode::TOO_MANY_REQUESTS
            }
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        to_error(error).set_status(status)
    })?;
    // Dispatch is not this request's work: the alarm's dispatch pass
    // runs it, so the submit answers once the queue write lands instead
    // of holding the client — and burning the DO's per-request CPU
    // budget — through claim plus a fan-out of GitHub calls. `next_alarm`
    // decides whether a wake can make progress at all: a submit whose
    // rows all sit behind unmet gates arms nothing, while a stale
    // in-flight lease still arms at its expiry (stow#444).
    schedule_alarm(env, db, alarm).await?;
    Ok(Json(InsertedResponse { inserted }))
}

/// The trusted submit lane refuses while the freeze is engaged — a
/// cost trip means the account is over budget, so even enqueues that
/// would merely wait are declined with the freeze reason. Anonymous
/// submits stay open: a miss costs nothing until it dispatches, and
/// dropping it would just blind the queue.
async fn refuse_if_frozen(db: &DurableDb) -> Result<()> {
    if let Some(record) = queue::freeze_record(db).await.map_err(to_error)? {
        let reason = format!(
            "dispatch is frozen ({})",
            freeze::summarize_trigger(&record.trigger)
        );
        return Err(Error::msg(reason).set_status(StatusCode::SERVICE_UNAVAILABLE));
    }
    Ok(())
}

/// `POST /batches/{batch_id}/complete` — the edge's webhook forwards a
/// `build-batch.yml` run's `completed` delivery here (stow#833 §3.2).
/// The write lands even while `github_run_id` is still NULL — an early
/// webhook that beat the dispatch response — and a duplicate delivery
/// is a no-op 2xx. A batch the store does not hold answers 404: the
/// run named nothing real, so the webhook logs the orphan rather than
/// retrying it.
async fn complete_batch(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    params: Params,
    Json(report): Json<stow_types::api::BatchRunComplete>,
) -> Result<Json<OkResponse>> {
    queue::record_batch_completion(&db, batch_id_param(&params)?, &report)
        .await
        .map_err(|error| {
            let status = match &error {
                QueueError::UnknownBatch(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            to_error(error).set_status(status)
        })?;
    // A recorded completion is resolution work for the alarm — arm the
    // pass the row's `resolve_after` points at.
    schedule_alarm(&env, &db, &alarm).await?;
    Ok(Json(OkResponse { ok: true }))
}

/// The `{batch_id}` path parameter — verbatim; a completion naming an
/// id the store does not hold is the route's 404.
fn batch_id_param(params: &Params) -> Result<&str> {
    params
        .get("batch_id")
        .map_err(|_| Error::msg("batch id is required").set_status(StatusCode::BAD_REQUEST))
}

async fn status(db: DurableDb) -> Result<Json<stow_types::api::SchedulerStatus>> {
    let status = queue::status(&db).await.map_err(to_error)?;
    Ok(Json(status))
}

/// `GET /admin/status` — the operator view behind `stow-admin status`.
async fn admin_status(db: DurableDb) -> Result<Json<stow_types::api::AdminStatus>> {
    let status = queue::admin_status(&db).await.map_err(to_error)?;
    Ok(Json(status))
}

/// `GET /tasks` — admin queue listing; the selector arrives as the
/// request's flattened query string
/// (`?task_ids=…&status=&target=&crate=&older_than=&limit=`).
async fn list_tasks(
    db: DurableDb,
    skyzen::extract::Query(selector): skyzen::extract::Query<stow_types::api::QueueSelector>,
) -> Result<Json<Vec<stow_types::api::QueueTask>>> {
    let tasks = queue::list_tasks(&db, &selector).await.map_err(to_error)?;
    Ok(Json(tasks))
}

/// `POST /tasks/{verb}` — one admin mutation over a [`QueueSelector`].
/// Retried and promoted rows can dispatch immediately, and a cancellation
/// frees a slot, so every non-purge verb runs a dispatch pass.
async fn apply_queue_mutation(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    mutation: queue::QueueMutation,
    selector: stow_types::api::QueueSelector,
) -> Result<Json<stow_types::api::QueueMutationResult>> {
    let affected = queue::apply_mutation(&db, &scheduler_settings(&env)?, mutation, &selector)
        .await
        .map_err(|error| {
            let status = match &error {
                QueueError::EmptySelector | QueueError::PurgeRequiresAge => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            to_error(error).set_status(status)
        })?;
    if affected > 0 && mutation != queue::QueueMutation::Purge {
        dispatch_pending(&env, &db).await.map_err(|error| {
            tracing::error!(%error, "scheduler mutation dispatch_pending failed");
            error
        })?;
        schedule_alarm(&env, &db, &alarm).await.map_err(|error| {
            tracing::error!(%error, "scheduler mutation schedule_alarm failed");
            error
        })?;
    }
    Ok(Json(stow_types::api::QueueMutationResult { affected }))
}

async fn queue_retry(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(selector): Json<stow_types::api::QueueSelector>,
) -> Result<Json<stow_types::api::QueueMutationResult>> {
    apply_queue_mutation(env, db, alarm, queue::QueueMutation::Retry, selector).await
}

async fn queue_cancel(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(selector): Json<stow_types::api::QueueSelector>,
) -> Result<Json<stow_types::api::QueueMutationResult>> {
    apply_queue_mutation(env, db, alarm, queue::QueueMutation::Cancel, selector).await
}

async fn queue_promote(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(selector): Json<stow_types::api::QueueSelector>,
) -> Result<Json<stow_types::api::QueueMutationResult>> {
    apply_queue_mutation(env, db, alarm, queue::QueueMutation::Promote, selector).await
}

async fn queue_purge(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(selector): Json<stow_types::api::QueueSelector>,
) -> Result<Json<stow_types::api::QueueMutationResult>> {
    apply_queue_mutation(env, db, alarm, queue::QueueMutation::Purge, selector).await
}

/// `POST /requests` — the human request lane's admission, reached from
/// the edge's `POST /api/v1/requests` after Turnstile. The work itself
/// is [`admit_request_pass`], shared with the budget probe's drive.
async fn admit_request(
    env: WasmEnv,
    db: DurableDb,
    Json(admission): Json<stow_types::api::RequestAdmission>,
) -> Result<Json<stow_types::api::CrateRequestStatus>> {
    let settings = scheduler_settings(&env)?;
    // `Date::now()` returns whole milliseconds well below 2^53; the
    // payload's `dispatched_at` wants unix seconds.
    #[allow(clippy::cast_possible_truncation)]
    let dispatched_at = (js_sys::Date::now() / 1_000.0) as i64;
    admit_request_pass(&env, &db, &settings, &admission, dispatched_at)
        .await
        .map(Json)
}

/// The admission's work: insert the record (or answer the live one for
/// a dedup hit), probe the human-lane daily budget, and dispatch
/// `resolve-request.yml` through the same credential arm the alarm's
/// dispatch pass uses.
///
/// The dispatch runs inline — unlike a queued task it is not a row the
/// alarm can pick up later; the request id only exists in `requests`,
/// so nothing else would ever trigger the run. A dispatch failure marks
/// the record `failed` naming the error, so the caller's 5xx and a
/// later re-request's re-attempt stay consistent. The dispatch freeze
/// refuses admission outright: a cost trip means no new dispatches, and
/// a resolve run is one.
pub(super) async fn admit_request_pass(
    env: &WasmEnv,
    db: &DurableDb,
    settings: &SchedulerSettings,
    admission: &stow_types::api::RequestAdmission,
    dispatched_at: i64,
) -> Result<stow_types::api::CrateRequestStatus> {
    refuse_if_frozen(db).await?;
    let step = queue::admit_request(db, admission, dispatched_at, settings)
        .await
        .map_err(|error| {
            let status = match &error {
                QueueError::HumanDailyBudgetExhausted { .. } => StatusCode::TOO_MANY_REQUESTS,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            to_error(error).set_status(status)
        })?;
    let queue::RequestAdmissionStep::Dispatch { attempt } = step else {
        // A live record already serves this request — answer it.
        return queue::crate_request_status(db, &admission.request_id)
            .await
            .map_err(to_error)?
            .ok_or_else(|| {
                Error::msg(format!(
                    "request {} admitted no record",
                    admission.request_id
                ))
            });
    };
    let credential_source = credential_source(env)?;
    let github_repo = read_string_binding(env, GITHUB_REPO_BINDING)?;
    let dispatch_payload = stow_types::api::RequestDispatch {
        request_id: admission.request_id.clone(),
        attempt,
        run_title: stow_types::records::resolve_run_title(attempt, &admission.request_id),
        crate_name: admission.crate_name.clone(),
        version: admission.version.clone(),
        features_json: admission.features_json.clone(),
        rustc_version: admission.rustc_version.clone(),
        max_closure: admission.max_closure,
        dispatched_at,
    };
    // The same backend arm as `dispatch_pass`: the cached installation
    // token — minted inline on expiry — or the mock stack's local-CI URL.
    let pool = crate::fetch_guard::OutboundPool::new();
    let outcome = match credential_source {
        CredentialSource::LocalCi(url) => {
            dispatch::LocalCiBuildRuns::new(&url)
                .trigger_resolve(&dispatch_payload, &github_repo, &pool)
                .await
        }
        CredentialSource::GitHub(config) => {
            match github_app::installation_token(db, &config).await {
                Ok(token) => {
                    dispatch::GitHubBuildRuns::new(token)
                        .trigger_resolve(&dispatch_payload, &github_repo, &pool)
                        .await
                }
                Err(error) => {
                    let error = dispatch::DispatchError::TokenMint(error.to_string());
                    queue::fail_request_dispatch(
                        db,
                        &admission.request_id,
                        attempt,
                        &error.to_string(),
                    )
                    .await
                    .map_err(to_error)?;
                    return Err(Error::msg(error.to_string()).set_status(StatusCode::BAD_GATEWAY));
                }
            }
        }
    };
    if let Err(error) = outcome {
        queue::fail_request_dispatch(db, &admission.request_id, attempt, &error.to_string())
            .await
            .map_err(to_error)?;
        return Err(Error::msg(error.to_string()).set_status(StatusCode::BAD_GATEWAY));
    }
    queue::crate_request_status(db, &admission.request_id)
        .await
        .map_err(to_error)?
        .ok_or_else(|| {
            Error::msg(format!(
                "request {} admitted no record",
                admission.request_id
            ))
        })
}

/// `GET /requests/{request_id}` — the request record's live status.
async fn read_request(
    db: DurableDb,
    params: Params,
) -> Result<Json<stow_types::api::CrateRequestStatus>> {
    let request_id = request_id_param(&params)?;
    queue::crate_request_status(&db, request_id)
        .await
        .map_err(to_error)?
        .map(Json)
        .ok_or_else(|| {
            Error::msg(format!("unknown request `{request_id}`")).set_status(StatusCode::NOT_FOUND)
        })
}

/// `POST /requests/{request_id}/outcome` — the resolve job's report
/// channel (stow#428): the trusted enqueue, the per-target roots and
/// the `enqueued`/`failed` transition apply in one call, then the
/// alarm handoff runs the dispatch pass the new tasks wait on. A report
/// for an unknown record answers 404; one naming a superseded attempt,
/// 409 — the webhook logs both rather than propagating them.
async fn apply_request_outcome(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    params: Params,
    Json(report): Json<stow_types::api::RequestOutcomeReport>,
) -> Result<Json<stow_types::api::CrateRequestStatus>> {
    let request_id = request_id_param(&params)?;
    let status = queue::apply_request_outcome(&db, &scheduler_settings(&env)?, request_id, &report)
        .await
        .map_err(|error| {
            let status = match &error {
                QueueError::UnknownRequest(_) => StatusCode::NOT_FOUND,
                QueueError::RequestAttemptSuperseded { .. } => StatusCode::CONFLICT,
                QueueError::HumanDailyBudgetExhausted { .. } => StatusCode::TOO_MANY_REQUESTS,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            to_error(error).set_status(status)
        })?;
    // Same handoff as submit: the report answers once the rows land, and
    // the alarm's dispatch pass — not this request — fans them out. An
    // outcome whose batch is fully gated arms nothing (stow#444).
    schedule_alarm(&env, &db, &alarm).await?;
    Ok(Json(status))
}

/// `POST /requests/{request_id}/run-update` — the `workflow_run`
/// webhook's lifecycle events for a `resolve-request.yml` run.
/// `in_progress` flips `accepted` → `resolving`; `completed` is the
/// backstop that fails a still-live attempt without overwriting a
/// record its outcome route already settled. Unknown record → 404,
/// superseded attempt → 409, and an event on an already-settled record
/// is an applied no-op.
async fn apply_request_run_update(
    db: DurableDb,
    params: Params,
    Json(update): Json<stow_types::api::RequestRunUpdate>,
) -> Result<Json<OkResponse>> {
    let request_id = request_id_param(&params)?;
    queue::record_request_run_update(&db, request_id, &update)
        .await
        .map_err(|error| {
            let status = match &error {
                QueueError::UnknownRequest(_) => StatusCode::NOT_FOUND,
                QueueError::RequestAttemptSuperseded { .. } => StatusCode::CONFLICT,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            to_error(error).set_status(status)
        })?;
    Ok(Json(OkResponse { ok: true }))
}

/// The `{request_id}` path parameter — verbatim, the id is opaque to the
/// DO (`req-` prefix and hash legs are the edge's concern).
fn request_id_param(params: &Params) -> Result<&str> {
    params
        .get("request_id")
        .map_err(|_| Error::msg("request id is required").set_status(StatusCode::BAD_REQUEST))
}

/// `GET /dispatch-freeze` — the dispatch freeze's current state: the
/// flag plus the stored record (trigger and notify outcome) when
/// engaged.
async fn read_dispatch_freeze(db: DurableDb) -> Result<Json<stow_types::api::DispatchFreeze>> {
    let record = queue::freeze_record(&db).await.map_err(to_error)?;
    let transitions = queue::freeze_transitions(&db, 25).await.map_err(to_error)?;
    Ok(Json(stow_types::api::DispatchFreeze {
        enabled: record.is_some(),
        record,
        transitions,
    }))
}

/// `POST /dispatch-freeze` — the manual transition that is also the
/// only recovery path. Each direction sends exactly one alert, and
/// writing the state already held is a no-op so alerts never repeat.
async fn write_dispatch_freeze(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(switch): Json<stow_types::api::DispatchFreeze>,
) -> Result<Json<stow_types::api::DispatchFreeze>> {
    let sink = EdgeAlerter::new(env.as_js());
    let action = if switch.enabled {
        freeze::FreezeAction::Freeze
    } else {
        freeze::FreezeAction::Clear
    };
    let transition = freeze::apply_transition(
        &DbStore(&db),
        &sink,
        action,
        stow_types::api::DispatchFreezeTrigger::Manual,
        &iso_now(),
    )
    .await
    .map_err(to_error)?;
    match transition {
        freeze::FreezeTransition::Engaged(record) => {
            // While frozen `next_alarm` plans a delete — a live alarm
            // would only spin dispatch passes the gate would eat.
            schedule_alarm(&env, &db, &alarm).await.map_err(|error| {
                tracing::error!(%error, "scheduler freeze schedule_alarm failed");
                error
            })?;
            tracing::warn!(?record.notify, "dispatch freeze engaged manually");
            let transitions = queue::freeze_transitions(&db, 25).await.map_err(to_error)?;
            Ok(Json(stow_types::api::DispatchFreeze {
                enabled: true,
                record: Some(record),
                transitions,
            }))
        }
        freeze::FreezeTransition::Cleared(_) => {
            // Misses that queued during the freeze dispatch first now.
            dispatch_pending(&env, &db).await.map_err(|error| {
                tracing::error!(%error, "scheduler unfreeze dispatch_pending failed");
                error
            })?;
            schedule_alarm(&env, &db, &alarm).await.map_err(|error| {
                tracing::error!(%error, "scheduler unfreeze schedule_alarm failed");
                error
            })?;
            tracing::warn!("dispatch freeze cleared manually");
            let transitions = queue::freeze_transitions(&db, 25).await.map_err(to_error)?;
            Ok(Json(stow_types::api::DispatchFreeze {
                enabled: false,
                record: None,
                transitions,
            }))
        }
        freeze::FreezeTransition::Unchanged => {
            let record = queue::freeze_record(&db).await.map_err(to_error)?;
            let transitions = queue::freeze_transitions(&db, 25).await.map_err(to_error)?;
            Ok(Json(stow_types::api::DispatchFreeze {
                enabled: record.is_some(),
                record,
                transitions,
            }))
        }
    }
}

/// `Date#toISOString` — the timestamp format the record and alert
/// bodies carry.
fn iso_now() -> String {
    js_sys::Date::new_0()
        .to_iso_string()
        .as_string()
        .expect("Date#toISOString returns a string")
}

/// After a failed completion, decide whether the trailing window trips
/// the freeze. `apply_transition` owns the one-alert-per-transition
/// rule: a live freeze answers `Unchanged` without rewriting the
/// record or resending the alert. Storage and query errors propagate
/// (loud); the alert's outcome only ever lands on the record.
async fn evaluate_dispatch_freeze(
    env: &WasmEnv,
    db: &DurableDb,
    settings: &FreezeSettings,
) -> Result<()> {
    // Cheap gate first — skip the window query entirely when frozen.
    if queue::freeze_enabled(db).await.map_err(to_error)? {
        return Ok(());
    }
    let Some(draft) = queue::evaluate_freeze_trip(db, settings)
        .await
        .map_err(to_error)?
    else {
        return Ok(());
    };
    let trigger = trip_trigger(env, draft, settings)?;
    let sink = EdgeAlerter::new(env.as_js());
    if let freeze::FreezeTransition::Engaged(record) = freeze::apply_transition(
        &DbStore(db),
        &sink,
        freeze::FreezeAction::Freeze,
        trigger,
        &iso_now(),
    )
    .await
    .map_err(to_error)?
    {
        if freeze::notify_reached(&record.notify) {
            tracing::warn!(trigger = ?record.trigger, notify = %freeze::summarize_notify(&record.notify), "dispatch freeze tripped");
        } else {
            tracing::error!(
                trigger = ?record.trigger,
                notify = %freeze::summarize_notify(&record.notify),
                "dispatch freeze tripped — alert reached nobody"
            );
        }
    }
    Ok(())
}

/// `MeterGuard`'s and `run_alarm`'s shared tail: settle the
/// operation's statement counts into the day meter and — when it just
/// crossed the budget — engage the freeze on this operation, not a
/// later poll (`settle_and_trip` owns the verdict→freeze→email
/// sequence). The freeze's own bookkeeping goes through the unmetered
/// inner handle. A settle failure is logged, never raised: a metering
/// bug must not take dispatch down with it.
pub(super) async fn settle_meter(meter: &Meter, env: &WasmEnv, multiplier: f64) {
    let sink = EdgeAlerter::new(env.as_js());
    match meter
        .settle_and_trip(&DbStore(meter.unmetered()), &sink, multiplier, &iso_now())
        .await
    {
        Ok(Some(freeze::FreezeTransition::Engaged(record))) => {
            if freeze::notify_reached(&record.notify) {
                tracing::warn!(trigger = ?record.trigger, notify = %freeze::summarize_notify(&record.notify), "dispatch freeze tripped on cost");
            } else {
                tracing::error!(
                    trigger = ?record.trigger,
                    notify = %freeze::summarize_notify(&record.notify),
                    "dispatch freeze tripped on cost — alert reached nobody"
                );
            }
        }
        Ok(_) => {}
        Err(error) => tracing::error!(%error, "do meter settle failed"),
    }
}

/// Turn a trip verdict into the wire `Tripped` trigger — the example
/// run URLs only materialize for failing run ids plus the repo binding.
fn trip_trigger(
    env: &WasmEnv,
    draft: queue::FreezeTripDraft,
    settings: &FreezeSettings,
) -> Result<stow_types::api::DispatchFreezeTrigger> {
    let github_repo = read_string_binding(env, GITHUB_REPO_BINDING)?;
    let example_run_urls = draft
        .example_run_ids
        .iter()
        .map(|run_id| format!("https://github.com/{github_repo}/actions/runs/{run_id}"))
        .collect();
    draft
        .eval
        .into_wire(settings, draft.classes, example_run_urls)
        .map(stow_types::api::DispatchFreezeTrigger::Tripped)
        .map_err(|invariant| Error::msg(format!("freeze trip evidence invariant: {invariant}")))
}

/// `POST /index/published` — the index-publish path's report that a slice
/// went live, carrying the semantic identities it serves. Recording it
/// before the dispatch pass lets a dependent the report just released
/// claim in the same turn.
async fn record_published_index(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(slice): Json<stow_types::api::PublishedSlice>,
) -> Result<Json<OkResponse>> {
    let settings = scheduler_settings(&env)?;
    match queue::record_published_slice(
        &db,
        &settings,
        slice.target.as_str(),
        slice.rustc_version.as_str(),
        &stow_types::api::PublishedSliceReport {
            base_generation: slice.base_generation,
            generation: slice.generation,
            added: slice.added,
            retired: slice.retired,
        },
    )
    .await
    {
        Ok(()) => {}
        Err(error @ QueueError::SliceGenerationConflict { .. }) => {
            // A delta report on a stale base can never apply — the live
            // generation moved since the reporter read it — so the error
            // names both generations and the reporter resyncs with a
            // full report rather than retrying.
            return Err(to_error(error).set_status(StatusCode::CONFLICT));
        }
        Err(error) => return Err(to_error(error)),
    }
    dispatch_pending(&env, &db).await.map_err(|error| {
        tracing::error!(%error, "scheduler published-index dispatch_pending failed");
        error
    })?;
    schedule_alarm(&env, &db, &alarm).await.map_err(|error| {
        tracing::error!(%error, "scheduler published-index schedule_alarm failed");
        error
    })?;
    Ok(Json(OkResponse { ok: true }))
}

/// The dispatch freeze stops the scheduler as well as the work-submitting
/// routes: `plan_alarm` answers `AlarmPlan::Delete` while frozen, so a
/// dispatch pass reads no pending queue and the alarm does not re-arm —
/// nothing runs until `dispatch-freeze clear` lifts it.
///
/// The alarm handler's `DurableDb` is extracted fresh (alarms bypass
/// the router middleware), so it wraps the handle in the metering
/// backend itself and settles regardless of outcome.
async fn run_alarm(env: WasmEnv, db: DurableDb, alarm: Alarm) -> Result<&'static str> {
    let multiplier = cost_budget_multiplier(&env)?;
    let (db, meter) = Meter::wrap(db);
    let meter = if budget_probe_enabled(&env) {
        meter.with_ledger_op(stow_types::do_budgets::LEDGER_OP_ALARM.to_owned())
    } else {
        meter
    };
    let result = async {
        dispatch_pending(&env, &db).await.map_err(|error| {
            tracing::error!(%error, "scheduler alarm dispatch_pending failed");
            error
        })?;
        schedule_alarm(&env, &db, &alarm).await.map_err(|error| {
            tracing::error!(%error, "scheduler alarm schedule_alarm failed");
            error
        })?;
        Ok("ok")
    }
    .await;
    settle_meter(&meter, &env, multiplier).await;
    result
}

/// Where a dispatch pass sends claimed tasks, resolved from the Worker's
/// bindings before anything is claimed.
enum CredentialSource {
    /// `STOW_LOCAL_CI_URL` — posts to the local dispatcher, which needs
    /// none of the GitHub App bindings.
    LocalCi(String),
    /// The GitHub App bindings that mint the installation token.
    GitHub(github_app::AppConfig),
}

/// Validate an endpoint override the mock harness sets: `STOW_LOCAL_CI_URL`
/// (the dispatcher the credential arm posts builds to) and
/// `STOW_STATS_SQL_URL` (the Analytics Engine stub the stats route posts
/// its API token to) only ever live on the same host, so both are pinned
/// to loopback and can never redirect traffic — or the token — to a
/// remote endpoint. Rejected URLs fail before any request uses them.
pub fn loopback_url(binding: &str, url: &str) -> Result<String> {
    let authority = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .and_then(|rest| rest.split('/').next())
        .and_then(|authority| authority.rsplit('@').next())
        .unwrap_or_default();
    let host = authority.strip_prefix('[').map_or_else(
        || authority.split(':').next().unwrap_or_default(),
        |v6| v6.split(']').next().unwrap_or_default(),
    );
    match host {
        "127.0.0.1" | "localhost" | "0.0.0.0" | "::1" => Ok(url.to_owned()),
        _ => Err(Error::msg(format!(
            "{binding} must name a loopback host, got {url:?}"
        ))),
    }
}

/// The artifact catalog in D1, asked at claim time which pending tasks an
/// already-landed publish covered.
pub(super) struct CatalogCoverage {
    /// The catalog handle — plain `CfD1` on a real pass, the counted
    /// backend under the budget probe so the lookup's rows are priced.
    pub(super) db: Db,
}

impl queue::CoverageOracle for CatalogCoverage {
    async fn covered(
        &self,
        identities: &[queue::SemanticTaskIdentity],
    ) -> std::result::Result<BTreeSet<queue::SemanticTaskIdentity>, QueueError> {
        db::covered_semantic_identities(&self.db, identities)
            .await
            .map_err(|error| QueueError::Sql(format!("artifact coverage lookup: {error}")))
    }
}

async fn dispatch_pending(env: &WasmEnv, db: &DurableDb) -> Result<()> {
    // The dispatch freeze gates here and inside `claim_dispatchable_tasks`
    // — the enqueue side never consults it, so misses keep arriving and
    // stay pending for the first pass after a human lifts the freeze. It
    // precedes binding resolution on purpose: while frozen there is no
    // dispatch pass at all, not even its failures.
    if queue::freeze_enabled(db).await.map_err(to_error)? {
        tracing::info!("dispatch frozen — skipping dispatch pass");
        return Ok(());
    }
    let settings = scheduler_settings(env)?;
    let coverage = CatalogCoverage {
        db: Db::new(
            CfD1::from_env(env.as_js(), STOW_DB_BINDING)
                .map_err(|error| Error::msg(format!("load D1 binding: {error}")))?,
        ),
    };
    dispatch_pass(env, db, &settings, &coverage)
        .await
        .map(|_| ())
}

/// The credential arm a dispatch resolves — `STOW_LOCAL_CI_URL` for the
/// mock stack, the GitHub App bindings otherwise. Shared by the alarm's
/// dispatch pass and the request lane's inline admit dispatch.
fn credential_source(env: &WasmEnv) -> Result<CredentialSource> {
    Ok(
        match read_optional_string_binding(env, STOW_LOCAL_CI_URL_BINDING) {
            Some(url) => CredentialSource::LocalCi(loopback_url("STOW_LOCAL_CI_URL", &url)?),
            None => CredentialSource::GitHub(github_app::AppConfig {
                app_id: read_string_binding(env, GITHUB_APP_ID_BINDING)?,
                installation_id: read_string_binding(env, GITHUB_APP_INSTALLATION_ID_BINDING)?,
                private_key_pem: read_string_binding(env, GITHUB_APP_PRIVATE_KEY_BINDING)?,
            }),
        },
    )
}

/// The claim-plus-fan-out half of a dispatch pass, shared with the
/// budget probe's `"alarm pass"` drive (`drives.rs`) so the probe's
/// `wall_ms` covers the concurrent `dispatch_batch` fan-out and the
/// counted-D1 coverage lookups a real wake pays. Returns the claimed
/// task ids — the probe's claim record and the launch gate's claim
/// count both derive from the pass's own set.
pub(super) async fn dispatch_pass(
    env: &WasmEnv,
    db: &DurableDb,
    settings: &SchedulerSettings,
    coverage: &impl queue::CoverageOracle,
) -> Result<Vec<String>> {
    // Binding resolution precedes claiming: a misconfigured binding fails
    // the pass with every row still `pending` instead of burned as a
    // dispatch attempt.
    let bindings = PassBindings::read(env)?;
    let scope = bindings.scope(env, db, settings);
    // §4.3: expired leases settle first, so a completion the lease check
    // recovers resolves in this same pass.
    check_batch_leases(&scope, &bindings.credential_source).await?;
    // §3.2: completed batches resolve before claiming — a resolved
    // batch's freed slots fill this same pass.
    resolve_ready_batches(&scope, &bindings.credential_source).await?;
    let batches = queue::claim_dispatchable_tasks(db, settings, coverage)
        .await
        .map_err(to_error)?;
    let task_ids: Vec<String> = batches
        .iter()
        .flat_map(|batch| batch.tasks.iter().map(|task| task.task_id.clone()))
        .collect();
    tracing::info!(
        batches = batches.len(),
        claimed = task_ids.len(),
        "scheduler dispatch_pending selected batches"
    );
    if batches.is_empty() {
        return Ok(Vec::new());
    }

    // The backend resolves once per pass, only when batches exist: the
    // local-CI branch carries no Authorization; the GitHub branch reuses
    // the installation token cached in DO storage while more than five
    // minutes of validity remain and otherwise mints a fresh one. A
    // failed mint is a dispatch failure for every claimed batch — the
    // same backoff a failed POST would get.
    match &bindings.credential_source {
        CredentialSource::LocalCi(url) => {
            tracing::info!(url = %url, "dispatching via local-CI endpoint");
            dispatch_batches(
                db,
                settings,
                &dispatch::LocalCiBuildRuns::new(url),
                batches,
                &bindings.github_repo,
            )
            .await?;
        }
        CredentialSource::GitHub(config) => {
            match github_app::installation_token(db, config).await {
                Ok(token) => {
                    dispatch_batches(
                        db,
                        settings,
                        &dispatch::GitHubBuildRuns::new(token),
                        batches,
                        &bindings.github_repo,
                    )
                    .await?;
                }
                Err(error) => {
                    let error = dispatch::DispatchError::TokenMint(error.to_string());
                    for batch in &batches {
                        queue::persist_batch_dispatch(db, settings, batch, Err(error.to_string()))
                            .await
                            .map_err(to_error)?;
                    }
                }
            }
        }
    }
    Ok(task_ids)
}

/// How long a batch whose jobs page cannot have settled yet — or one
/// whose GitHub/GHCR read failed transiently — defers its resolution:
/// the 30 s §3.2 grants the page to finish writing.
const BATCH_RESOLVE_DEFER_MS: i64 = 30_000;

/// How long the lease check leaves a batch whose run lookup, cancel or
/// token mint failed before the next pass asks again — without it the
/// alarm would re-arm at `now` for as long as GitHub is failing.
const LEASE_RETRY_MS: i64 = BATCH_RESOLVE_DEFER_MS;

/// The GHCR config the batch resolution's records check reads — the
/// same binding the Worker's webhook builds for the per-task path
/// (entry.rs).
fn ghcr_config(env: &WasmEnv) -> crate::api::GhcrConfig {
    crate::api::GhcrConfig {
        base_url: read_optional_string_binding(env, crate::entry::GHCR_BASE_URL_BINDING)
            .unwrap_or_else(|| crate::ghcr::default_base_url().to_owned()),
        tokens: crate::registry_auth::RegistryTokens::default(),
    }
}

/// The bindings an alarm pass's batch steps read, resolved once per
/// pass.
struct PassBindings {
    github_repo: String,
    freeze: FreezeSettings,
    credential_source: CredentialSource,
}

impl PassBindings {
    fn read(env: &WasmEnv) -> Result<Self> {
        Ok(Self {
            github_repo: read_string_binding(env, GITHUB_REPO_BINDING)?,
            freeze: freeze_settings(env)?,
            credential_source: credential_source(env)?,
        })
    }

    fn scope<'a>(
        &'a self,
        env: &'a WasmEnv,
        db: &'a DurableDb,
        settings: &'a SchedulerSettings,
    ) -> PassScope<'a> {
        PassScope {
            env,
            db,
            settings,
            github_repo: &self.github_repo,
            freeze: &self.freeze,
        }
    }
}

/// Which batch step of an alarm pass the budget probe runs on its own.
#[derive(Clone, Copy, Debug)]
pub(super) enum BatchStep {
    /// §4.3's lease check over the expired batches.
    Leases,
    /// §3.2's resolution of the completed batches.
    Resolution,
}

/// One batch step of the dispatch pass, exactly as [`dispatch_pass`]
/// runs it — the budget probe's `alarm pass (batch resolution)` and
/// `alarm pass (lease check)` drives price the step alone.
pub(super) async fn run_batch_step(
    env: &WasmEnv,
    db: &DurableDb,
    settings: &SchedulerSettings,
    step: BatchStep,
) -> Result<()> {
    let bindings = PassBindings::read(env)?;
    let scope = bindings.scope(env, db, settings);
    match step {
        BatchStep::Leases => check_batch_leases(&scope, &bindings.credential_source).await,
        BatchStep::Resolution => resolve_ready_batches(&scope, &bindings.credential_source).await,
    }
}

/// What one alarm pass's batch resolution reads from its caller —
/// the bindings and handles every step of the pass shares.
struct PassScope<'a> {
    env: &'a WasmEnv,
    db: &'a DurableDb,
    settings: &'a SchedulerSettings,
    github_repo: &'a str,
    freeze: &'a FreezeSettings,
}

/// §4.3: settle every batch whose lease expired — before resolving
/// and claiming, so a recorded completion resolves and a requeued leg
/// is claimable in this same pass. It runs whether or not dispatch is
/// paused: a paused scheduler still owes its in-flight builds the
/// lease check.
///
/// An unbound batch (the dispatch response was lost) has no run to ask
/// about and requeues its legs without any HTTP. The bound ones are
/// looked up concurrently ([`check_bound_leases`]); the credential
/// resolves only when one expired, like the other arms'.
async fn check_batch_leases(
    scope: &PassScope<'_>,
    credential_source: &CredentialSource,
) -> Result<()> {
    let PassScope { db, settings, .. } = *scope;
    let now_ms = now_ms();
    let mut bound = Vec::new();
    for batch in queue::expired_batches(db, now_ms).await.map_err(to_error)? {
        match batch.run_id {
            None => {
                tracing::warn!(
                    batch_id = %batch.batch_id,
                    "batch lease expired unbound — requeueing its legs"
                );
                queue::requeue_unbound_batch(db, settings, &batch.batch_id)
                    .await
                    .map_err(to_error)?;
            }
            Some(run_id) => bound.push((batch, run_id)),
        }
    }
    if bound.is_empty() {
        return Ok(());
    }
    match credential_source {
        CredentialSource::LocalCi(url) => {
            check_bound_leases(scope, &dispatch::LocalCiBuildRuns::new(url), bound, now_ms).await
        }
        CredentialSource::GitHub(config) => {
            match github_app::installation_token(db, config).await {
                Ok(token) => {
                    check_bound_leases(scope, &dispatch::GitHubBuildRuns::new(token), bound, now_ms)
                        .await
                }
                Err(error) => {
                    tracing::error!(
                        %error,
                        batches = bound.len(),
                        "installation token mint failed — leaving expired batches for the next pass"
                    );
                    for (batch, _) in &bound {
                        queue::set_batch_lease(db, &batch.batch_id, now_ms + LEASE_RETRY_MS)
                            .await
                            .map_err(to_error)?;
                    }
                    Ok(())
                }
            }
        }
    }
}

/// What the lease check decided for one bound, expired batch.
enum LeaseVerdict {
    /// The run completed — record it as the webhook would have.
    Completed(stow_types::api::BatchRunComplete),
    /// The run is still going inside its ceiling.
    Extend,
    /// The run outlived its ceiling — cancel it, then fail the batch.
    Cancel,
    /// The lookup failed — the next pass asks again.
    Retry,
}

/// One bound expired set's lease check. The run lookups, then the
/// cancels of the runs past their ceiling, each run concurrently under
/// the invocation's outbound bound; the queue writes apply
/// sequentially afterward (`&DurableDb` is not `Send`, so it never
/// enters a concurrent future).
async fn check_bound_leases(
    scope: &PassScope<'_>,
    backend: &impl dispatch::BuildRuns,
    bound: Vec<(queue::ExpiredBatch, u64)>,
    now_ms: i64,
) -> Result<()> {
    let github_repo = scope.github_repo;
    let pool = crate::fetch_guard::OutboundPool::new();
    // Collected before streaming, like the dispatch fan-out's.
    let lookups: Vec<_> = bound
        .iter()
        .map(|&(_, run_id)| backend.run_status(github_repo, run_id, &pool))
        .collect();
    let statuses = stream::iter(lookups)
        .buffered(crate::fetch_guard::MAX_OUTBOUND_INFLIGHT)
        .collect::<Vec<_>>()
        .await;
    let mut verdicts = Vec::with_capacity(bound.len());
    for ((batch, run_id), status) in bound.iter().zip(statuses) {
        verdicts.push(lease_verdict(batch, *run_id, status)?);
    }
    let cancels: Vec<_> = bound
        .iter()
        .zip(&verdicts)
        .filter(|(_, verdict)| matches!(verdict, LeaseVerdict::Cancel))
        .map(|(&(_, run_id), _)| backend.cancel_run(github_repo, run_id, &pool))
        .collect();
    let mut cancels = stream::iter(cancels)
        .buffered(crate::fetch_guard::MAX_OUTBOUND_INFLIGHT)
        .collect::<Vec<_>>()
        .await
        .into_iter();
    for ((batch, run_id), verdict) in bound.iter().zip(verdicts) {
        let cancelled = matches!(verdict, LeaseVerdict::Cancel).then(|| {
            cancels
                .next()
                .expect("one cancel was issued per past-ceiling verdict")
        });
        apply_lease_verdict(scope, batch, *run_id, verdict, cancelled, now_ms).await?;
    }
    Ok(())
}

/// What the lease check decides for one bound, expired batch from its
/// run's state.
///
/// # Errors
/// A `completed` run with no conclusion is corrupt GitHub state.
fn lease_verdict(
    batch: &queue::ExpiredBatch,
    run_id: u64,
    status: std::result::Result<stow_types::runs::RunStatus, dispatch::DispatchError>,
) -> Result<LeaseVerdict> {
    Ok(match status {
        Err(error) => {
            tracing::error!(
                batch_id = %batch.batch_id,
                run_id,
                %error,
                "run status lookup failed — leaving the batch for the next pass"
            );
            LeaseVerdict::Retry
        }
        Ok(status) if status.status == "completed" => {
            let conclusion = status.conclusion.ok_or_else(|| {
                Error::msg(format!(
                    "run {run_id} of batch {} is completed with no conclusion",
                    batch.batch_id
                ))
            })?;
            LeaseVerdict::Completed(stow_types::api::BatchRunComplete {
                run_id,
                run_attempt: status.run_attempt,
                conclusion,
                html_url: status.html_url,
            })
        }
        Ok(_) if batch.past_ceiling => LeaseVerdict::Cancel,
        Ok(_) => LeaseVerdict::Extend,
    })
}

/// Apply one batch's verdict to the queue. `cancelled` is the cancel
/// call's outcome for a [`LeaseVerdict::Cancel`] verdict, `None` for
/// every other.
async fn apply_lease_verdict(
    scope: &PassScope<'_>,
    batch: &queue::ExpiredBatch,
    run_id: u64,
    verdict: LeaseVerdict,
    cancelled: Option<std::result::Result<(), dispatch::DispatchError>>,
    now_ms: i64,
) -> Result<()> {
    let PassScope { db, settings, .. } = *scope;
    let batch_id = batch.batch_id.as_str();
    match verdict {
        LeaseVerdict::Completed(report) => {
            tracing::info!(
                batch_id,
                run_id,
                conclusion = %report.conclusion,
                "expired lease found its run completed — recording the lost delivery"
            );
            match queue::record_batch_completion(db, batch_id, &report).await {
                Ok(()) => {}
                // The row left between the lookup and the write; the run
                // it named resolves nothing.
                Err(QueueError::UnknownBatch(_)) => {
                    tracing::warn!(batch_id, "batch gone before its completion was recorded");
                }
                Err(error) => return Err(to_error(error)),
            }
        }
        LeaseVerdict::Extend => {
            queue::extend_batch_lease(db, settings, batch_id, now_ms)
                .await
                .map_err(to_error)?;
        }
        LeaseVerdict::Cancel => match cancelled.expect("a cancel verdict carries its cancel") {
            Ok(()) => {
                tracing::error!(
                    batch_id,
                    run_id,
                    "run exceeded its ceiling — cancelled, failing its legs"
                );
                queue::fail_batch_past_ceiling(db, batch_id)
                    .await
                    .map_err(to_error)?;
            }
            Err(error) => {
                tracing::error!(
                    batch_id,
                    run_id,
                    %error,
                    "cancelling a run past its ceiling failed — leaving the batch for the next pass"
                );
                queue::set_batch_lease(db, batch_id, now_ms + LEASE_RETRY_MS)
                    .await
                    .map_err(to_error)?;
            }
        },
        LeaseVerdict::Retry => {
            queue::set_batch_lease(db, batch_id, now_ms + LEASE_RETRY_MS)
                .await
                .map_err(to_error)?;
        }
    }
    Ok(())
}

/// §3.2: resolve every batch whose `completed` delivery is bound and
/// due — before claiming, so a freed slot fills this same pass. The
/// backend resolves once, like the dispatch arm's: a token-mint
/// failure defers every ready batch rather than burning it.
async fn resolve_ready_batches(
    scope: &PassScope<'_>,
    credential_source: &CredentialSource,
) -> Result<()> {
    let PassScope { env, db, .. } = *scope;
    let now_ms = now_ms();
    let ready = queue::ready_batches(db, now_ms).await.map_err(to_error)?;
    if ready.is_empty() {
        return Ok(());
    }
    let ghcr = ghcr_config(env);
    match credential_source {
        CredentialSource::LocalCi(url) => {
            resolve_batch_set(
                scope,
                &dispatch::LocalCiBuildRuns::new(url),
                &ghcr,
                ready,
                now_ms,
            )
            .await
        }
        CredentialSource::GitHub(config) => {
            match github_app::installation_token(db, config).await {
                Ok(token) => {
                    resolve_batch_set(
                        scope,
                        &dispatch::GitHubBuildRuns::new(token),
                        &ghcr,
                        ready,
                        now_ms,
                    )
                    .await
                }
                Err(error) => {
                    tracing::error!(
                        %error,
                        batches = ready.len(),
                        "installation token mint failed — deferring batch resolution"
                    );
                    for batch in ready {
                        queue::defer_batch(db, &batch.batch_id, now_ms + BATCH_RESOLVE_DEFER_MS)
                            .await
                            .map_err(to_error)?;
                    }
                    Ok(())
                }
            }
        }
    }
}

/// One ready-batch set's resolution fan-out — the outbound reads
/// (jobs page, then a manifest read per successful leg) run
/// concurrently under the invocation's outbound bound, the same bound
/// the dispatch fan-out runs under. The queue writes apply
/// sequentially afterward: `&DurableDb` is not `Send`, so it never
/// enters a concurrent future.
async fn resolve_batch_set(
    scope: &PassScope<'_>,
    backend: &impl dispatch::BuildRuns,
    ghcr: &crate::api::GhcrConfig,
    ready: Vec<queue::ReadyBatch>,
    now_ms: i64,
) -> Result<()> {
    let PassScope {
        env,
        db,
        settings,
        github_repo,
        freeze,
    } = *scope;
    let pool = crate::fetch_guard::OutboundPool::new();
    let now = time::OffsetDateTime::from_unix_timestamp(now_ms / 1000)
        .map_err(|error| Error::msg(format!("alarm clock out of range: {error}")))?;
    // Collected before streaming: a closure inside the stream's type
    // borrows each batch under a higher-ranked lifetime, and the alarm
    // future then cannot prove itself `Send`.
    let probes: Vec<_> = ready
        .iter()
        .map(|batch| probe_batch(backend, ghcr, github_repo, batch, &pool, now))
        .collect();
    let probes = stream::iter(probes)
        .buffered(crate::fetch_guard::MAX_OUTBOUND_INFLIGHT)
        .collect::<Vec<_>>()
        .await;
    for (batch, probe) in ready.iter().zip(probes) {
        let Some(resolutions) = probe else {
            queue::defer_batch(db, &batch.batch_id, now_ms + BATCH_RESOLVE_DEFER_MS)
                .await
                .map_err(to_error)?;
            continue;
        };
        if queue::resolve_batch(db, settings, batch, &resolutions, freeze.window_minutes)
            .await
            .map_err(to_error)?
        {
            evaluate_dispatch_freeze(env, db, freeze).await?;
        }
    }
    Ok(())
}

/// One batch's outbound reads resolved into per-leg resolutions —
/// `None` while any leg is unsettled or a read failed transiently
/// (the caller defers the batch 30 s, §3.2). Concurrent-safe: it
/// touches nothing but the outbound pool.
async fn probe_batch(
    backend: &impl dispatch::BuildRuns,
    ghcr: &crate::api::GhcrConfig,
    github_repo: &str,
    batch: &queue::ReadyBatch,
    pool: &crate::fetch_guard::OutboundPool,
    now: time::OffsetDateTime,
) -> Option<Vec<queue::LegResolution>> {
    let run_id = match batch.run_id.parse::<u64>() {
        Ok(run_id) => run_id,
        Err(error) => {
            tracing::error!(batch_id = %batch.batch_id, run_id = %batch.run_id, %error, "batch run id is not numeric — deferring");
            return None;
        }
    };
    let jobs = match backend
        .attempt_jobs(github_repo, run_id, batch.done_attempt, pool)
        .await
    {
        Ok(jobs) => jobs,
        Err(error) => {
            tracing::warn!(batch_id = %batch.batch_id, run_id, %error, "batch jobs page read failed — deferring");
            return None;
        }
    };
    let outcomes = queue::leg_outcomes(batch, &jobs, now);
    // One GHCR manifest read per successful leg, concurrently under
    // the same outbound bound — the tag pins the publish job's
    // `run_attempt` (§3.1).
    let checks: Vec<_> = batch
        .legs
        .iter()
        .map(|leg| {
            let outcome = &outcomes[index_to_usize(leg.batch_leg)];
            leg_records_present(ghcr, batch, leg, outcome, run_id, pool)
        })
        .collect();
    let checks = stream::iter(checks)
        .buffer_unordered(crate::fetch_guard::MAX_OUTBOUND_INFLIGHT)
        .collect::<Vec<_>>()
        .await;
    let mut confirmed = std::collections::BTreeSet::new();
    for check in checks {
        match check {
            Ok(Some(leg_index)) => {
                confirmed.insert(leg_index);
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(batch_id = %batch.batch_id, run_id, %error, "batch records check failed — deferring");
                return None;
            }
        }
    }
    let resolutions = queue::batch_resolutions(batch, &jobs, |leg| confirmed.contains(&leg), now);
    if !batch
        .legs
        .iter()
        .all(|leg| resolutions[index_to_usize(leg.batch_leg)].is_some())
    {
        tracing::debug!(batch_id = %batch.batch_id, "batch legs still settling — deferring");
        return None;
    }
    Some(
        resolutions
            .into_iter()
            .enumerate()
            .map(|(index, resolution)| {
                resolution.unwrap_or_else(|| queue::LegResolution::Failed {
                    error: format!("invariant: leg {index} has no queue row"),
                })
            })
            .collect(),
    )
}

/// One leg's records-artifact check — a GHCR manifest read on a
/// `Succeeded` leg only, absent for every other outcome. The tag
/// pins the publish job's `run_attempt` (§3.1).
async fn leg_records_present(
    ghcr: &crate::api::GhcrConfig,
    batch: &queue::ReadyBatch,
    leg: &queue::ReadyBatchLeg,
    outcome: &stow_types::runs::LegOutcome,
    run_id: u64,
    pool: &crate::fetch_guard::OutboundPool,
) -> std::result::Result<Option<u32>, crate::ghcr::FetchError> {
    use skyzen_cloudflare::worker::send::IntoSendFuture as _;
    let present = match outcome {
        stow_types::runs::LegOutcome::Succeeded {
            publish_attempt, ..
        } => {
            crate::ghcr::records_artifact_exists(
                ghcr,
                &batch.rustc_version,
                &leg.task_id,
                stow_types::records::BuildRun {
                    run_id,
                    run_attempt: *publish_attempt,
                },
                pool,
            )
            .into_send()
            .await?
        }
        _ => false,
    };
    std::result::Result::Ok(present.then_some(leg.batch_leg))
}

/// A leg index as a slice index — `u32` fits `usize` on every stow
/// target.
fn index_to_usize(leg: u32) -> usize {
    usize::try_from(leg).expect("u32 leg index fits usize")
}

/// The wall clock a pass reads — `Date::now()` returns whole
/// milliseconds well below 2^53, so the value is exactly
/// representable and always fits i64.
fn now_ms() -> i64 {
    #[allow(clippy::cast_possible_truncation)]
    {
        js_sys::Date::now() as i64
    }
}

/// The `build-batch.yml` dispatch fan-out over one resolved backend —
/// one `workflow_dispatch` per formed batch, concurrently, then the
/// ordered outcome apply (stow#833 §4.2).
///
/// The POSTs run under the invocation's outbound bound: the stream's
/// `buffered` admits at most `MAX_OUTBOUND_INFLIGHT` (4) at once, and
/// the pool slot `dispatch_batch` waits on enforces the same bound
/// before any request posts. `buffered` — not `buffer_unordered` —
/// yields results in the batches' own order, so each outcome stays
/// matched to its batch. The queue writes then apply sequentially:
/// `&DurableDb` is not `Send`, so it never enters a concurrent future.
async fn dispatch_batches(
    db: &DurableDb,
    settings: &SchedulerSettings,
    backend: &impl dispatch::BuildRuns,
    batches: Vec<FormedBatch>,
    github_repo: &str,
) -> Result<()> {
    let pool = crate::fetch_guard::OutboundPool::new();
    // Collected before streaming: a closure inside the stream's type
    // borrows each batch under a higher-ranked lifetime, and the alarm
    // future then cannot prove itself `Send`.
    let dispatches: Vec<_> = batches
        .iter()
        .map(|batch| backend.dispatch_batch(&batch.encoded, github_repo, &pool))
        .collect();
    let outcomes = stream::iter(dispatches)
        .buffered(crate::fetch_guard::MAX_OUTBOUND_INFLIGHT)
        .collect::<Vec<_>>()
        .await;
    for (batch, outcome) in batches.iter().zip(outcomes) {
        let outcome = outcome
            .map(|run| run.workflow_run_id)
            .map_err(|error| error.to_string());
        queue::persist_batch_dispatch(db, settings, batch, outcome)
            .await
            .map_err(to_error)?;
    }
    Ok(())
}

async fn schedule_alarm(env: &WasmEnv, db: &DurableDb, alarm: &Alarm) -> Result<()> {
    let (now_ms, settings) = alarm_inputs(env)?;
    let plan = queue::next_alarm(db, now_ms, &settings)
        .await
        .map_err(to_error)?;
    queue::arm_alarm(alarm, plan).await.map_err(|error| {
        let error = to_error(error);
        tracing::error!(%error, "failed to perform scheduler alarm plan");
        error
    })
}

/// The instant and settings every alarm plan is decided under — read
/// once per pass so a route's plan and its arm see one clock.
fn alarm_inputs(env: &WasmEnv) -> Result<(i64, SchedulerSettings)> {
    Ok((now_ms(), scheduler_settings(env)?))
}

fn read_string_binding(env: &WasmEnv, binding_name: &str) -> Result<String> {
    let value = Reflect::get(env.as_js(), &JsValue::from_str(binding_name))
        .map_err(|error| Error::msg(format!("{error:?}")))?;
    value.as_string().ok_or_else(|| {
        Error::msg(format!(
            "Cloudflare Workers binding '{binding_name}' must be a string secret"
        ))
    })
}

fn read_optional_string_binding(env: &WasmEnv, binding_name: &str) -> Option<String> {
    let value = Reflect::get(env.as_js(), &JsValue::from_str(binding_name)).ok()?;
    if value.is_undefined() || value.is_null() {
        return None;
    }
    value.as_string()
}

fn read_optional_u32_binding(env: &WasmEnv, binding_name: &str) -> Result<Option<u32>> {
    let value = Reflect::get(env.as_js(), &JsValue::from_str(binding_name))
        .map_err(|error| Error::msg(format!("{error:?}")))?;
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    let raw = value.as_string().ok_or_else(|| {
        Error::msg(format!(
            "Cloudflare Workers binding '{binding_name}' must be a string when set"
        ))
    })?;
    let parsed = raw
        .parse::<u32>()
        .map_err(|error| Error::msg(format!("parse binding '{binding_name}' as u32: {error}")))?;
    Ok(Some(parsed))
}

/// An optional decimal-integer binding parsed as `i64`. The text form
/// is what crosses the env-binding boundary — a JavaScript number
/// property could not carry the wide values this is meant to hold, and
/// `i64::from_str` is what rejects overflow/rounding rather than
/// admitting a `f64`-decoded tail.
fn read_optional_i64_binding(env: &WasmEnv, binding_name: &str) -> Result<Option<i64>> {
    let value = Reflect::get(env.as_js(), &JsValue::from_str(binding_name))
        .map_err(|error| Error::msg(format!("{error:?}")))?;
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    let raw = value.as_string().ok_or_else(|| {
        Error::msg(format!(
            "Cloudflare Workers binding '{binding_name}' must be a string when set"
        ))
    })?;
    let parsed = raw
        .parse::<i64>()
        .map_err(|error| Error::msg(format!("parse binding '{binding_name}' as i64: {error}")))?;
    if parsed < 0 {
        return Err(Error::msg(format!(
            "Cloudflare Workers binding '{binding_name}' must be nonnegative"
        )));
    }
    Ok(Some(parsed))
}

fn read_optional_f64_binding(env: &WasmEnv, binding_name: &str) -> Result<Option<f64>> {
    let value = Reflect::get(env.as_js(), &JsValue::from_str(binding_name))
        .map_err(|error| Error::msg(format!("{error:?}")))?;
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    let raw = value.as_string().ok_or_else(|| {
        Error::msg(format!(
            "Cloudflare Workers binding '{binding_name}' must be a string when set"
        ))
    })?;
    Ok(Some(
        meter::parse_f64_binding(binding_name, &raw).map_err(Error::msg)?,
    ))
}

/// `STOW_COST_BUDGET_MULTIPLIER`, parsed with the same error shape as
/// every other optional binding — a value that is set but unparseable is
/// a misconfiguration, not a quiet default.
pub(super) fn cost_budget_multiplier(env: &WasmEnv) -> Result<f64> {
    Ok(
        read_optional_f64_binding(env, STOW_COST_BUDGET_MULTIPLIER_BINDING)?
            .unwrap_or(meter::DEFAULT_COST_BUDGET_MULTIPLIER),
    )
}

fn to_error(error: impl std::fmt::Display) -> Error {
    Error::msg(error.to_string())
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct InsertedResponse {
    inserted: u32,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct OkResponse {
    ok: bool,
}
