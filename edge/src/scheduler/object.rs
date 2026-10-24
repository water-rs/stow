//! Durable Object glue: routes scheduler HTTP/alarm events into the queue
//! state machine and GitHub dispatch.

use futures_util::stream::{self, StreamExt as _};
use js_sys::Reflect;
use serde::{Deserialize, Serialize};
use skyzen::durable::DurableObject;
use skyzen::routing::{CreateRouteNode, Params, Route, Router};
use skyzen::runtime::wasm::WasmEnv;
use skyzen::utils::{Json, State};
use skyzen::{Error, Result, StatusCode};
use skyzen_services::durable::{Alarm, DurableDb};
use wasm_bindgen::JsValue;

use stow_types::api::SchedulerResetReport;

use crate::errors::QueueError;
use crate::freeze::{self, FreezeSettings};
use crate::github_app;
use crate::scheduler::meter::{self, Meter, MeterGuard};
use crate::scheduler::queue::SchedulerSettings;
use crate::scheduler::{budget, fixture};
use crate::scheduler::{dispatch, feed, graph, queue, routes, store};

const STOW_LOCAL_CI_URL_BINDING: &str = "STOW_LOCAL_CI_URL";
const STOW_DISPATCH_MIN_AGE_MINUTES_BINDING: &str = "STOW_DISPATCH_MIN_AGE_MINUTES";
const STOW_MAX_CONCURRENT_JOBS_BINDING: &str = "STOW_MAX_CONCURRENT_JOBS";
const STOW_MAX_CONCURRENT_MACOS_JOBS_BINDING: &str = "STOW_MAX_CONCURRENT_MACOS_JOBS";
const STOW_STALE_DISPATCH_MINUTES_BINDING: &str = "STOW_STALE_DISPATCH_MINUTES";
const STOW_MAX_QUEUE_PENDING_BINDING: &str = "STOW_MAX_QUEUE_PENDING";
const STOW_HUMAN_DAILY_TASK_BUDGET_BINDING: &str = "STOW_HUMAN_DAILY_TASK_BUDGET";
const STOW_MIN_DISPATCH_VALUE_BINDING: &str = "STOW_MIN_DISPATCH_VALUE";
const GITHUB_APP_ID_BINDING: &str = "GITHUB_APP_ID";
const GITHUB_APP_INSTALLATION_ID_BINDING: &str = "GITHUB_APP_INSTALLATION_ID";
const GITHUB_APP_PRIVATE_KEY_BINDING: &str = "GITHUB_APP_PRIVATE_KEY";
const GITHUB_REPO_BINDING: &str = "GITHUB_REPO";
const STOW_FREEZE_WINDOW_MINUTES_BINDING: &str = "STOW_FREEZE_WINDOW_MINUTES";
const STOW_FREEZE_MIN_OUTCOMES_BINDING: &str = "STOW_FREEZE_MIN_OUTCOMES";
const STOW_FREEZE_FAIL_PERCENT_BINDING: &str = "STOW_FREEZE_FAIL_PERCENT";
const STOW_COST_BUDGET_MULTIPLIER_BINDING: &str = "STOW_COST_BUDGET_MULTIPLIER";

/// The status a core's [`QueueError`] answers with: a contract
/// violation or empty selector is the caller's 400, an unknown record
/// 404, a superseded report 409, a full queue or spent budget
/// 429, anything else the object's 500.
fn route_error(error: QueueError) -> Error {
    let status = match &error {
        QueueError::Invariant(_)
        | QueueError::Overflow { .. }
        | QueueError::EmptySelector
        | QueueError::PurgeRequiresAge => StatusCode::BAD_REQUEST,
        QueueError::UnknownRequest(_) => StatusCode::NOT_FOUND,
        QueueError::RequestAttemptSuperseded { .. } => StatusCode::CONFLICT,
        QueueError::QueueFull { .. } | QueueError::HumanDailyBudgetExhausted { .. } => {
            StatusCode::TOO_MANY_REQUESTS
        }
        QueueError::Sql(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    to_error(error).set_status(status)
}

/// Ensure the isolate's graph is loaded — the wake: snapshot + log
/// tail replay, installed before anything else awaits so a concurrent
/// request never replays a log the winner has since appended to. The
/// one request that installed it then runs the post-wake `status`
/// reconcile, which re-binds own runs by title (review Q6) and rebuilds
/// external occupancy.
async fn ensure_graph<'a>(
    env: &WasmEnv,
    db: &DurableDb,
    cell: &'a graph::GraphCell,
) -> Result<graph::LoadedGraph<'a>> {
    let loaded = if let Some(loaded) = cell.loaded() {
        loaded
    } else {
        let (mut graph, events) = store::load(db).await.map_err(to_error)?;
        store::apply_events(&mut graph, &events);
        cell.install(graph)
    };
    // The admission floor is a deploy binding, never persisted: every
    // wake plan and claim reads the one stamped here.
    let floor = scheduler_settings(env)?.min_dispatch_value;
    loaded.with(|graph| graph.set_floor(floor));
    if cell.take_reconcile() {
        // The CI `status` listing is the truth for runs a snapshot's
        // eviction could have orphaned (claims whose bindings never
        // landed). A failure leaves the replayed state: the delivery
        // stream and the stale lease repair the same drift.
        let listed = match ci_interface(env, loaded).await {
            Ok(interface) => interface.status_runs().await,
            Err(error) => Err(dispatch::DispatchError::Response(error.to_string())),
        };
        match listed {
            Ok(runs) => {
                let listed: Vec<(u64, String, stow_types::api::RunnerFamily)> = runs
                    .iter()
                    .map(|run| {
                        (
                            run.workflow_run_id,
                            run.title.clone(),
                            run.family.unwrap_or(stow_types::api::RunnerFamily::Linux),
                        )
                    })
                    .collect();
                loaded.with(|graph| graph.reconcile_runs(&listed, now_ms()));
            }
            Err(error) => {
                tracing::warn!(%error, "post-wake CI status reconcile failed — keeping replayed state");
            }
        }
    }
    Ok(loaded)
}

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
pub struct Scheduler {
    /// The in-memory graph — `None` until the first touch wakes it
    /// (stow#878). Serde never sees it: a rehydrated object replays
    /// the store like a fresh isolate.
    #[serde(skip)]
    graph: graph::GraphCell,
}

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
            // The build run's lifecycle channel (stow#876): the
            // webhook forwards a `build-crate.yml` run's verified
            // `completed` delivery to `complete-run` and its
            // `in_progress` delivery to `run-update`; both fence on
            // the queue row's bound generation.
            "/tasks/complete-run".post(complete_run),
            "/tasks/run-update".post(apply_task_run_update),
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
            "/budget/rearm".post(scheduler_budget_rearm),
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
        // The alarm endpoint runs without the router's middleware, so it
        // carries its own handle to the graph.
        .on_alarm({
            let graph = self.graph.clone();
            move |env: WasmEnv, db: DurableDb, alarm: Alarm| {
                run_alarm(graph.clone(), env, db, alarm)
            }
        })
        // Route middleware, not a router layer: skyzen checks at build
        // time that every extractor's provider sits on its route.
        .with(State(self.graph.clone()))
        .build()
        .layer(MeterGuard)
    }
}

/// `POST /reset` — the only endpoint that may issue DDL on the queue
/// database. Reached from `POST /api/v1/admin/scheduler/reset`, which
/// `stow-admin scheduler reset --yes` invokes. Drops every store object
/// and re-executes `schema.sql`; the in-memory graph is dropped with
/// the store, so the next request wakes an empty one. The alarm is
/// cleared — nothing is left to wake for.
async fn reset_scheduler(
    State(graph): State<graph::GraphCell>,
    db: DurableDb,
    alarm: Alarm,
) -> Result<Json<SchedulerResetReport>> {
    let report = store::reset(&db).await.map_err(to_error)?;
    graph.clear();
    queue::arm_alarm(&alarm, queue::AlarmPlan::Delete)
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
    State(graph): State<graph::GraphCell>,
    db: DurableDb,
    Json(request): Json<stow_types::api::SchedulerSeedRequest>,
) -> Result<Json<stow_types::api::SchedulerSeedReport>> {
    if !budget_probe_enabled(&env) {
        return Err(
            Error::msg("scheduler budget probe is not enabled on this deploy")
                .set_status(StatusCode::NOT_FOUND),
        );
    }
    let shape = fixture::FixtureShape {
        queue_rows: request
            .queue_rows
            .unwrap_or(stow_types::fixture::FixtureShape::PRODUCTION.queue_rows),
    };
    Ok(Json(
        fixture::seed(&db, &graph, shape, now_ms())
            .await
            .map_err(to_error)?,
    ))
}

/// `POST /budget/rearm` — re-arm the seeded fixture's in-flight tasks
/// the callback lane's deliveries resolved and answer every armed one
/// (stow#833). Same guard as the seed endpoint; a request naming another fixture size than the seeded
/// one is a 409, since its run ids would not be the store's.
/// Reached from `POST /api/v1/admin/scheduler/budget/rearm`.
async fn scheduler_budget_rearm(
    env: WasmEnv,
    State(graph): State<graph::GraphCell>,
    db: DurableDb,
    Json(request): Json<stow_types::api::SchedulerRearmRequest>,
) -> Result<Json<stow_types::api::SchedulerRearmReport>> {
    if !budget_probe_enabled(&env) {
        return Err(
            Error::msg("scheduler budget probe is not enabled on this deploy")
                .set_status(StatusCode::NOT_FOUND),
        );
    }
    let seeded = fixture::seeded_rows(&db)
        .await
        .map_err(to_error)?
        .ok_or_else(|| {
            Error::msg("no fixture was seeded — nothing to re-arm").set_status(StatusCode::CONFLICT)
        })?;
    if seeded != request.queue_rows {
        return Err(Error::msg(format!(
            "re-arm names a {}-row fixture, but the store was seeded at {seeded} rows",
            request.queue_rows
        ))
        .set_status(StatusCode::CONFLICT));
    }
    // Re-arming reopens the resolved runs and rebinds them: the
    // graph binds all thirty in-flight runs again with no
    // completion recorded.
    let graph = ensure_graph(&env, &db, &graph).await?;
    fixture::rearm(
        &db,
        graph,
        fixture::FixtureShape { queue_rows: seeded },
        now_ms(),
    )
    .await
    .map_err(to_error)?;
    let armed: Vec<u32> = (0..stow_types::fixture::FixtureShape::IN_FLIGHT_ROWS).collect();
    Ok(Json(stow_types::api::SchedulerRearmReport { armed }))
}

/// `POST /budget` — replay every drive under the metering backend and
/// return the real `rowsRead`/`rowsWritten` per route. Same guard as the
/// seed endpoint. Reached from `POST /api/v1/admin/scheduler/budget`.
async fn scheduler_budget(
    env: WasmEnv,
    State(graph): State<graph::GraphCell>,
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
        budget::run(&db, &graph, &settings, &env, &alarm, &request)
            .await
            .map_err(to_error)?,
    ))
}

/// `GET /budget/ledger` — the per-operation billed rows the meter booked
/// since the last reset (stow#773). Same guard as the seed endpoint.
/// Reached from `GET /api/v1/admin/scheduler/budget/ledger`.
async fn scheduler_budget_ledger(
    env: WasmEnv,
    State(graph): State<graph::GraphCell>,
    db: DurableDb,
) -> Result<Json<stow_types::api::SchedulerLedger>> {
    if !budget_probe_enabled(&env) {
        return Err(
            Error::msg("scheduler budget probe is not enabled on this deploy")
                .set_status(StatusCode::NOT_FOUND),
        );
    }
    // The ledger lives on the graph: a freshly woken isolate loads it
    // first, like every other route that reads the graph.
    let graph = ensure_graph(&env, &db, &graph).await?;
    Ok(Json(meter::ledger(graph)))
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
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(request): Json<stow_types::api::SchedulerDemandRequest>,
) -> Result<Json<stow_types::api::SchedulerDemandReport>> {
    let (now_ms, settings) = alarm_inputs(&env)?;
    let graph = ensure_graph(&env, &db, &graph).await?;
    let (report, plan) = routes::demand(graph, &db, &request, &settings, now_ms)
        .await
        .map_err(route_error)?;
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
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    Json(request): Json<stow_types::api::DemandFeedBeginRequest>,
) -> Result<Json<stow_types::api::DemandFeedBeginReport>> {
    let graph = ensure_graph(&env, &db, &graph).await?;
    routes::feed_begin(graph, &db, &request.hour, feed_now_secs())
        .await
        .map(Json)
        .map_err(demand_feed_error)
}

/// `POST /demand-feed/page` — stage one bounded immutable page.
async fn demand_feed_page(
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    Json(request): Json<stow_types::api::DemandFeedPageRequest>,
) -> Result<Json<serde_json::Value>> {
    let graph = ensure_graph(&env, &db, &graph).await?;
    routes::feed_page(graph, &db, &request, feed_now_secs())
        .await
        .map_err(demand_feed_error)?;
    Ok(Json(serde_json::json!({"staged": true})))
}

/// `POST /demand-feed/complete` — the completion barrier: freeze the
/// hour once every page of its generation is staged and the manifest
/// matches.
async fn demand_feed_complete(
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    Json(request): Json<stow_types::api::DemandFeedCompleteRequest>,
) -> Result<Json<serde_json::Value>> {
    let graph = ensure_graph(&env, &db, &graph).await?;
    routes::feed_complete(graph, &db, &request, feed_now_secs())
        .await
        .map_err(demand_feed_error)?;
    Ok(Json(serde_json::json!({"complete": true})))
}

/// `POST /demand-feed/cleanup` — retire one bounded chunk of the
/// hour's dead page rows (obsolete generations or a delivered hour's
/// acknowledged payloads). Explicit event work, never a timer.
async fn demand_feed_cleanup(
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    Json(request): Json<stow_types::api::DemandFeedCleanupRequest>,
) -> Result<Json<stow_types::api::DemandFeedCleanupReport>> {
    let graph = ensure_graph(&env, &db, &graph).await?;
    routes::feed_cleanup(graph, &db, &request.hour, feed_now_secs())
        .await
        .map(Json)
        .map_err(demand_feed_error)
}

/// `POST /demand-feed/deliver` — replay the next undelivered original
/// page into the demand ledger, then arm the plan the shared pass
/// decided — the same probe/rearm `/demand` performs.
async fn demand_feed_deliver(
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(request): Json<stow_types::api::DemandFeedDeliverRequest>,
) -> Result<Json<stow_types::api::DemandFeedDeliverReport>> {
    let (now_ms, settings) = alarm_inputs(&env)?;
    let graph = ensure_graph(&env, &db, &graph).await?;
    let (report, plan) = routes::feed_deliver(graph, &db, &request.hour, &settings, now_ms)
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
async fn demand_feed_status(
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
) -> Result<Json<stow_types::api::DemandFeedStatus>> {
    let graph = ensure_graph(&env, &db, &graph).await?;
    Ok(Json(graph.with(|graph| feed::feed_status(graph))))
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
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(trees): Json<Vec<stow_types::api::SubmissionTree>>,
) -> Result<Json<InsertedResponse>> {
    submit(&graph, &env, &db, &alarm, &trees, true).await
}

/// `POST /tasks/submit/trusted` — the same submit minus the
/// pending-depth cap: callers reached it through the edge's repo-writer
/// trust check, so a full queue must not turn their work away.
async fn submit_tasks_trusted(
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(trees): Json<Vec<stow_types::api::SubmissionTree>>,
) -> Result<Json<InsertedResponse>> {
    submit(&graph, &env, &db, &alarm, &trees, false).await
}

/// `POST /tasks/submit/ids` — the trusted submit-by-id lane (stow#588):
/// the missed lane promotes an admitted miss by its exact task id; the
/// scheduler rebuilds each subgraph from its node store (never a
/// re-mint) and reports the ids it does not hold as `unknown`. The
/// pending-depth cap does not apply — the edge's repo-writer trust
/// check is the bound — but a frozen queue still refuses.
async fn submit_tasks_by_id(
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(body): Json<stow_types::api::SubmitTaskIdsRequest>,
) -> Result<Json<stow_types::api::SubmitTaskIdsResponse>> {
    let graph = ensure_graph(&env, &db, &graph).await?;
    if graph.with(|graph| graph.freeze().is_some()) {
        return Err(Error::msg("dispatch is frozen").set_status(StatusCode::SERVICE_UNAVAILABLE));
    }
    let (inserted, unknown) = routes::submit_ids(graph, &db, &body.tasks, now_ms())
        .await
        .map_err(route_error)?;
    let outcome = queue::SubmitTaskIdsOutcome { inserted, unknown };
    if !outcome.unknown.is_empty() {
        tracing::info!(
            unknown = outcome.unknown.len(),
            "submit-by-id: node store misses"
        );
    }
    // Same hand-off as submit: the alarm pass owns dispatch.
    schedule_alarm(&env, &db, &alarm, graph.cell()).await?;
    Ok(Json(stow_types::api::SubmitTaskIdsResponse {
        submitted: u32::try_from(body.tasks.len()).map_err(|_| {
            to_error("submit-ids task count exceeds u32").set_status(StatusCode::PAYLOAD_TOO_LARGE)
        })?,
        inserted: outcome.inserted,
        unknown: outcome.unknown,
    }))
}

async fn submit(
    graph: &graph::GraphCell,
    env: &WasmEnv,
    db: &DurableDb,
    alarm: &Alarm,
    trees: &[stow_types::api::SubmissionTree],
    enforce_pending_cap: bool,
) -> Result<Json<InsertedResponse>> {
    let settings = scheduler_settings(env)?;
    let graph = ensure_graph(env, db, graph).await?;
    if !enforce_pending_cap && graph.with(|graph| graph.freeze().is_some()) {
        return Err(Error::msg("dispatch is frozen").set_status(StatusCode::SERVICE_UNAVAILABLE));
    }
    // The pending-depth cap gates miss-lane trees only — trusted and
    // human lanes arrive through their own bound — and every tree's
    // Submit parts land in one turn before the merge: the single
    // transaction the ack follows.
    let (inserted, unpublished_ids) =
        routes::submit(graph, db, &settings, trees, enforce_pending_cap, now_ms())
            .await
            .map_err(route_error)?;
    // Dispatch is not this request's work: the alarm's dispatch pass
    // runs it, so the submit answers once the queue write lands instead
    // of holding the client — and burning the DO's per-request CPU
    // budget — through claim plus a fan-out of GitHub calls. `next_alarm`
    // decides whether a wake can make progress at all: a submit whose
    // rows all sit behind unmet gates arms nothing, while a stale
    // in-flight lease still arms at its expiry (stow#444).
    schedule_alarm(env, db, alarm, graph.cell()).await?;
    Ok(Json(InsertedResponse {
        inserted,
        unpublished_ids,
    }))
}

/// The trusted submit lane refuses while the freeze is engaged — a
/// cost trip means the account is over budget, so even enqueues that
/// would merely wait are declined with the freeze reason. Anonymous
/// submits stay open: a miss costs nothing until it dispatches, and
/// dropping it would just blind the queue.
fn refuse_if_frozen(graph: graph::LoadedGraph<'_>) -> Result<()> {
    if let Some(record) = graph.with(|graph| graph.freeze().cloned()) {
        let reason = format!(
            "dispatch is frozen ({})",
            freeze::summarize_trigger(&record.trigger)
        );
        return Err(Error::msg(reason).set_status(StatusCode::SERVICE_UNAVAILABLE));
    }
    Ok(())
}

/// `POST /tasks/complete-run` — the edge's webhook route forwards a
/// `build-crate.yml` run's verified `completed` delivery here; the
/// report carries the task id and outcome but no attempt, which
/// `complete_run` resolves against the live row.
///
/// A completion for a task the queue never held answers 404, not 500 —
/// the report references nothing real. A row whose live attempt or
/// status no longer matches what the event describes answers 409 — the
/// row moved on, and the webhook logs both rather than propagating
/// them: a retried delivery changes nothing about a row that already
/// moved.
async fn complete_run(
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(report): Json<stow_types::api::WorkflowRunComplete>,
) -> Result<Json<OkResponse>> {
    complete_run_pass(&graph, &env, &db, &alarm, &report).await?;
    Ok(Json(OkResponse { ok: true }))
}

/// The completion's work, shared with the budget probe's
/// `complete-run` drives so they price the route's whole pass.
pub(super) async fn complete_run_pass(
    graph: &graph::GraphCell,
    env: &WasmEnv,
    db: &DurableDb,
    alarm: &Alarm,
    report: &stow_types::api::WorkflowRunComplete,
) -> Result<()> {
    let freeze = freeze_settings(env)?;
    let graph = ensure_graph(env, db, graph).await?;
    let now = now_ms();
    let outcome = routes::complete_run(graph, db, report, now)
        .await
        .map_err(route_error)?;
    match outcome {
        graph::FinishOutcome::Applied | graph::FinishOutcome::Parked => {}
        graph::FinishOutcome::External | graph::FinishOutcome::Stale => {
            tracing::info!(
                task_id = %report.task_id,
                run_id = ?report.github_run_id,
                "workflow_run completion resolved an external run"
            );
            return Ok(());
        }
    }
    // A failed attempt may have closed the window's trip condition —
    // evaluate while this request still holds the outcome row's write
    // context. The freeze then eats the dispatch the alarm was about
    // to run.
    if !report.success {
        evaluate_dispatch_freeze(graph, env, db, &freeze).await?;
    }
    // Same handoff as submit: the run's report is acknowledged as soon
    // as the queue row lands, and the alarm's dispatch pass — not this
    // request — runs claim plus the GitHub fan-out. The completion may
    // leave nothing dispatchable (a failure with an empty queue, a
    // finished backlog): `schedule_alarm` arms no wake then (stow#444).
    schedule_alarm(env, db, alarm, graph.cell()).await
}

/// `POST /tasks/run-update` — the webhook's `in_progress` delivery for
/// a bound `build-crate.yml` run: the row moves `dispatched` to
/// `running` under the bound generation's run id (stow#876).
///
/// A task the queue never held answers 404; a report naming a run the
/// row is not bound to — or a row that already moved past it —
/// answers 409, which the webhook logs rather than propagating.
async fn apply_task_run_update(
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    Json(update): Json<stow_types::api::TaskRunUpdate>,
) -> Result<Json<OkResponse>> {
    let graph = ensure_graph(&env, &db, &graph).await?;
    let outcome = routes::task_run_update(graph, &db, &update, now_ms())
        .await
        .map_err(route_error)?;
    match outcome {
        // Own runs change nothing persistent — the post-wake reconcile
        // restores running state (review); an external run's occupancy
        // was appended by the core.
        graph::StartOutcome::Applied
        | graph::StartOutcome::Stale
        | graph::StartOutcome::External => {}
    }
    Ok(Json(OkResponse { ok: true }))
}

async fn status(
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
) -> Result<Json<stow_types::api::SchedulerStatus>> {
    let graph = ensure_graph(&env, &db, &graph).await?;
    let counts = graph.with(|graph| graph.status_counts());
    let count =
        |label: &str| u32::try_from(counts.get(label).copied().unwrap_or(0)).unwrap_or(u32::MAX);
    Ok(Json(stow_types::api::SchedulerStatus {
        pending: count("pending").saturating_add(count("blocked")),
        human_pending: count("human_pending"),
        dispatched: count("dispatched"),
        running: count("running"),
        completed: count("completed"),
        failed: count("failed"),
        blocked: count("blocked"),
    }))
}

/// `GET /admin/status` — the operator view behind `stow-admin status`.
async fn admin_status(
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
) -> Result<Json<stow_types::api::AdminStatus>> {
    let graph = ensure_graph(&env, &db, &graph).await?;
    let status = graph
        .with(|graph| graph.admin_status(now_ms()))
        .map_err(to_error)?;
    Ok(Json(status))
}

/// `GET /tasks` — admin queue listing; the selector arrives as the
/// request's flattened query string
/// (`?task_ids=…&status=&target=&crate=&older_than=&limit=`).
async fn list_tasks(
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    skyzen::extract::Query(selector): skyzen::extract::Query<stow_types::api::QueueSelector>,
) -> Result<Json<Vec<stow_types::api::QueueTask>>> {
    let graph = ensure_graph(&env, &db, &graph).await?;
    let tasks = graph
        .with(|graph| graph.list(&selector, now_ms()))
        .map_err(to_error)?;
    Ok(Json(tasks))
}

/// `POST /tasks/{verb}` — one admin mutation over a [`QueueSelector`].
/// The selector resolves to ids against the graph, the resolved ids
/// are the logged event, and the apply is the same event replay runs.
/// Retried and promoted rows can dispatch immediately, and a
/// cancellation frees a slot, so every non-purge verb runs a dispatch
/// pass.
async fn apply_queue_mutation(
    graph: &graph::GraphCell,
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    op: stow_types::api::MutationKind,
    selector: stow_types::api::QueueSelector,
) -> Result<Json<stow_types::api::QueueMutationResult>> {
    let graph = ensure_graph(&env, &db, graph).await?;
    let affected = routes::mutate(graph, &db, op, &selector, now_ms())
        .await
        .map_err(route_error)?;
    if affected > 0 && op != stow_types::api::MutationKind::Purge {
        dispatch_pending(&env, &db, graph.cell())
            .await
            .map_err(|error| {
                tracing::error!(%error, "scheduler mutation dispatch_pending failed");
                error
            })?;
        schedule_alarm(&env, &db, &alarm, graph.cell())
            .await
            .map_err(|error| {
                tracing::error!(%error, "scheduler mutation schedule_alarm failed");
                error
            })?;
    }
    Ok(Json(stow_types::api::QueueMutationResult { affected }))
}

async fn queue_retry(
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(selector): Json<stow_types::api::QueueSelector>,
) -> Result<Json<stow_types::api::QueueMutationResult>> {
    apply_queue_mutation(
        &graph,
        env,
        db,
        alarm,
        stow_types::api::MutationKind::Retry,
        selector,
    )
    .await
}

async fn queue_cancel(
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(selector): Json<stow_types::api::QueueSelector>,
) -> Result<Json<stow_types::api::QueueMutationResult>> {
    apply_queue_mutation(
        &graph,
        env,
        db,
        alarm,
        stow_types::api::MutationKind::Cancel,
        selector,
    )
    .await
}

async fn queue_promote(
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(selector): Json<stow_types::api::QueueSelector>,
) -> Result<Json<stow_types::api::QueueMutationResult>> {
    apply_queue_mutation(
        &graph,
        env,
        db,
        alarm,
        stow_types::api::MutationKind::Promote,
        selector,
    )
    .await
}

async fn queue_purge(
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(selector): Json<stow_types::api::QueueSelector>,
) -> Result<Json<stow_types::api::QueueMutationResult>> {
    apply_queue_mutation(
        &graph,
        env,
        db,
        alarm,
        stow_types::api::MutationKind::Purge,
        selector,
    )
    .await
}

/// `POST /requests` — the human request lane's admission, reached from
/// the edge's `POST /api/v1/requests` after Turnstile. The work itself
/// is [`admit_request_pass`], shared with the budget probe's drive.
async fn admit_request(
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    Json(admission): Json<stow_types::api::RequestAdmission>,
) -> Result<Json<stow_types::api::CrateRequestStatus>> {
    let graph = ensure_graph(&env, &db, &graph).await?;
    let settings = scheduler_settings(&env)?;
    // `Date::now()` returns whole milliseconds well below 2^53; the
    // payload's `dispatched_at` wants unix seconds.
    #[allow(clippy::cast_possible_truncation)]
    let dispatched_at = (js_sys::Date::now() / 1_000.0) as i64;
    admit_request_pass(graph, &env, &db, &settings, &admission, dispatched_at)
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
    graph: graph::LoadedGraph<'_>,
    env: &WasmEnv,
    db: &DurableDb,
    settings: &SchedulerSettings,
    admission: &stow_types::api::RequestAdmission,
    dispatched_at: i64,
) -> Result<stow_types::api::CrateRequestStatus> {
    refuse_if_frozen(graph)?;
    let step = routes::admit_request(graph, db, settings, admission, dispatched_at, now_ms())
        .await
        .map_err(route_error)?;
    let queue::RequestAdmissionStep::Dispatch { attempt } = step else {
        // A live record already serves this request — answer it.
        return graph
            .with(|graph| queue::crate_request_status(graph, &admission.request_id, now_ms()))
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
            dispatch::CiInterface::local_ci(&url, dispatch::CfTransport::new(pool.clone()))
                .submit_resolve(&dispatch_payload)
                .await
        }
        CredentialSource::GitHub(config) => {
            match github_app::installation_token(graph.tokens(), &config).await {
                Ok(token) => {
                    dispatch::CiInterface::github(
                        &github_repo,
                        &token.token,
                        dispatch::CfTransport::new(pool.clone()),
                    )
                    .submit_resolve(&dispatch_payload)
                    .await
                }
                Err(error) => {
                    let error = dispatch::DispatchError::TokenMint(error.to_string());
                    routes::fail_request_dispatch(
                        graph,
                        db,
                        &admission.request_id,
                        attempt,
                        &error.to_string(),
                        now_ms(),
                    )
                    .await
                    .map_err(route_error)?;
                    return Err(Error::msg(error.to_string()).set_status(StatusCode::BAD_GATEWAY));
                }
            }
        }
    };
    if let Err(error) = outcome {
        routes::fail_request_dispatch(
            graph,
            db,
            &admission.request_id,
            attempt,
            &error.to_string(),
            now_ms(),
        )
        .await
        .map_err(route_error)?;
        return Err(Error::msg(error.to_string()).set_status(StatusCode::BAD_GATEWAY));
    }
    graph
        .with(|graph| queue::crate_request_status(graph, &admission.request_id, now_ms()))
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
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    params: Params,
) -> Result<Json<stow_types::api::CrateRequestStatus>> {
    let request_id = request_id_param(&params)?;
    let graph = ensure_graph(&env, &db, &graph).await?;
    graph
        .with(|graph| queue::crate_request_status(graph, request_id, now_ms()))
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
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    params: Params,
    Json(report): Json<stow_types::api::RequestOutcomeReport>,
) -> Result<Json<stow_types::api::CrateRequestStatus>> {
    let request_id = request_id_param(&params)?;
    let graph = ensure_graph(&env, &db, &graph).await?;
    let status = routes::request_outcome(graph, &db, request_id, &report, now_ms())
        .await
        .map_err(route_error)?;
    // Same handoff as submit: the report answers once the rows land, and
    // the alarm's dispatch pass — not this request — fans them out. An
    // outcome whose task is fully gated arms nothing (stow#444).
    schedule_alarm(&env, &db, &alarm, graph.cell()).await?;
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
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    params: Params,
    Json(update): Json<stow_types::api::RequestRunUpdate>,
) -> Result<Json<OkResponse>> {
    let request_id = request_id_param(&params)?;
    let graph = ensure_graph(&env, &db, &graph).await?;
    routes::request_run_update(graph, &db, request_id, &update, now_ms())
        .await
        .map_err(route_error)?;
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
/// engaged, and the recent transitions.
async fn read_dispatch_freeze(
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
) -> Result<Json<stow_types::api::DispatchFreeze>> {
    let graph = ensure_graph(&env, &db, &graph).await?;
    Ok(Json(freeze_view(graph)))
}

/// The freeze flag, record and transition history the graph holds.
fn freeze_view(graph: graph::LoadedGraph<'_>) -> stow_types::api::DispatchFreeze {
    graph.with(|graph| {
        let record = graph.freeze().cloned();
        stow_types::api::DispatchFreeze {
            enabled: record.is_some(),
            record,
            transitions: graph.freeze_transitions(),
        }
    })
}

/// Append the `Freeze` events a transition staged — the graph already
/// applied them, so only the log write remains.
async fn persist_freeze(
    db: &DurableDb,
    store: &graph::GraphFreezeStore<'_>,
    now: i64,
) -> Result<()> {
    let appended = store::append_events(db, &store.take_events(), now)
        .await
        .map_err(to_error)?;
    store
        .cell()
        .with(|graph| graph.log_appended(appended.bytes));
    Ok(())
}

/// `POST /dispatch-freeze` — the manual transition that is also the
/// only recovery path. Each direction sends exactly one alert, and
/// writing the state already held is a no-op so alerts never repeat.
async fn write_dispatch_freeze(
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(switch): Json<stow_types::api::DispatchFreeze>,
) -> Result<Json<stow_types::api::DispatchFreeze>> {
    let graph = ensure_graph(&env, &db, &graph).await?;
    let sink = EdgeAlerter::new(env.as_js());
    let action = if switch.enabled {
        freeze::FreezeAction::Freeze
    } else {
        freeze::FreezeAction::Clear
    };
    // The freeze gates `claim` on the graph — the transition applies
    // its `Freeze` event there and the route appends it (stow#878).
    let now = now_ms();
    let store = graph::GraphFreezeStore::new(graph, iso_now(), now);
    let transition = freeze::apply_transition(
        &store,
        &sink,
        action,
        stow_types::api::DispatchFreezeTrigger::Manual,
        &iso_now(),
    )
    .await
    .map_err(to_error)?;
    persist_freeze(&db, &store, now).await?;
    match transition {
        freeze::FreezeTransition::Engaged(record) => {
            // While frozen the wake plan is a delete — a live alarm
            // would only spin dispatch passes the gate would eat.
            schedule_alarm(&env, &db, &alarm, graph.cell())
                .await
                .map_err(|error| {
                    tracing::error!(%error, "scheduler freeze schedule_alarm failed");
                    error
                })?;
            tracing::warn!(?record.notify, "dispatch freeze engaged manually");
        }
        freeze::FreezeTransition::Cleared(_) => {
            // Misses that queued during the freeze dispatch first now.
            dispatch_pending(&env, &db, graph.cell())
                .await
                .map_err(|error| {
                    tracing::error!(%error, "scheduler unfreeze dispatch_pending failed");
                    error
                })?;
            schedule_alarm(&env, &db, &alarm, graph.cell())
                .await
                .map_err(|error| {
                    tracing::error!(%error, "scheduler unfreeze schedule_alarm failed");
                    error
                })?;
            tracing::warn!("dispatch freeze cleared manually");
        }
        freeze::FreezeTransition::Unchanged => {}
    }
    Ok(Json(freeze_view(graph)))
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
/// the freeze. `freeze_trip_draft` owns the graph half — the
/// already-frozen gate plus the window fold over the outcome ring —
/// which the host cost drive calls too. `apply_transition` owns the
/// one-alert-per-transition rule: a live freeze answers `Unchanged`
/// without rewriting the record or resending the alert. The alert's
/// outcome only ever lands on the record.
async fn evaluate_dispatch_freeze(
    graph: graph::LoadedGraph<'_>,
    env: &WasmEnv,
    db: &DurableDb,
    settings: &FreezeSettings,
) -> Result<()> {
    let now = now_ms();
    let Some(draft) = graph
        .with(|graph| queue::freeze_trip_draft(graph, settings, now))
        .map_err(to_error)?
    else {
        return Ok(());
    };
    let trigger = trip_trigger(env, draft, settings)?;
    let sink = EdgeAlerter::new(env.as_js());
    let store = graph::GraphFreezeStore::new(graph, iso_now(), now);
    let transition = freeze::apply_transition(
        &store,
        &sink,
        freeze::FreezeAction::Freeze,
        trigger,
        &iso_now(),
    )
    .await
    .map_err(to_error)?;
    persist_freeze(db, &store, now).await?;
    if let freeze::FreezeTransition::Engaged(record) = transition {
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
/// operation's row counts into the graph's day meter and — when it
/// just crossed the budget — engage the freeze on this operation, not
/// a later poll (`settle_and_trip` owns the verdict→freeze→email
/// sequence), appending the staged `Freeze` event through `db` (the
/// unmetered handle). A settle failure is logged, never raised: a
/// metering bug must not take dispatch down with it.
pub(super) async fn settle_meter(
    graph: &graph::GraphCell,
    db: &DurableDb,
    meter: &Meter,
    env: &WasmEnv,
    multiplier: f64,
) {
    // A reset leaves the graph empty; settling wakes it first.
    let graph = match ensure_graph(env, db, graph).await {
        Ok(graph) => graph,
        Err(error) => {
            tracing::error!(%error, "do meter settle: graph wake failed");
            return;
        }
    };
    let sink = EdgeAlerter::new(env.as_js());
    let now = now_ms();
    let store = graph::GraphFreezeStore::new(graph, iso_now(), now);
    let result = meter
        .settle_and_trip(graph, now, &store, &sink, multiplier, &iso_now())
        .await;
    if let Err(error) = persist_freeze(db, &store, now).await {
        tracing::error!(%error, "persist cost-trip freeze failed");
    }
    match result {
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
    State(graph): State<graph::GraphCell>,
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(slice): Json<stow_types::api::PublishedSlice>,
) -> Result<Json<OkResponse>> {
    let _settings = scheduler_settings(&env)?;
    let graph = ensure_graph(&env, &db, &graph).await?;
    // The slice report is one appended event; its flip lands on the
    // same turn (stow#878 — no generation fencing: reports apply to
    // in-memory masks, deltas stay idempotent on re-application).
    routes::slice_report(graph, &db, &slice, now_ms())
        .await
        .map_err(route_error)?;
    dispatch_pending(&env, &db, graph.cell())
        .await
        .map_err(|error| {
            tracing::error!(%error, "scheduler published-index dispatch_pending failed");
            error
        })?;
    schedule_alarm(&env, &db, &alarm, graph.cell())
        .await
        .map_err(|error| {
            tracing::error!(%error, "scheduler published-index schedule_alarm failed");
            error
        })?;
    Ok(Json(OkResponse { ok: true }))
}

/// The dispatch freeze stops the scheduler as well as the work-submitting
/// routes: a frozen graph claims nothing and plans no wake, so the
/// alarm does not re-arm — nothing runs until `dispatch-freeze clear`
/// lifts it.
///
/// The alarm handler's `DurableDb` is extracted fresh (alarms bypass
/// the router middleware), so it wraps the handle in the metering
/// backend itself and settles regardless of outcome.
async fn run_alarm(
    graph: graph::GraphCell,
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
) -> Result<&'static str> {
    let multiplier = cost_budget_multiplier(&env)?;
    let (metered, meter) = Meter::wrap(db.clone());
    let meter = if budget_probe_enabled(&env) {
        meter.with_ledger_op(stow_types::do_budgets::LEDGER_OP_ALARM.to_owned())
    } else {
        meter
    };
    let result = async {
        dispatch_pending(&env, &metered, &graph)
            .await
            .map_err(|error| {
                tracing::error!(%error, "scheduler alarm dispatch_pending failed");
                error
            })?;
        schedule_alarm(&env, &metered, &alarm, &graph)
            .await
            .map_err(|error| {
                tracing::error!(%error, "scheduler alarm schedule_alarm failed");
                error
            })?;
        Ok("ok")
    }
    .await;
    settle_meter(&graph, &db, &meter, &env, multiplier).await;
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

async fn dispatch_pending(env: &WasmEnv, db: &DurableDb, graph: &graph::GraphCell) -> Result<()> {
    let graph = ensure_graph(env, db, graph).await?;
    // The dispatch freeze gates here and inside `claim`
    // — the enqueue side never consults it, so misses keep arriving and
    // stay pending for the first pass after a human lifts the freeze. It
    // precedes binding resolution on purpose: while frozen there is no
    // dispatch pass at all, not even its failures.
    if graph.with(|graph| graph.freeze().is_some()) {
        tracing::info!("dispatch frozen — skipping dispatch pass");
        return Ok(());
    }
    let settings = scheduler_settings(env)?;
    dispatch_pass(graph.cell(), env, db, &settings)
        .await
        .map(|_| ())
}

/// The CI interface one pass resolves — same credential arm as
/// `dispatch_pass`.
async fn ci_interface(
    env: &WasmEnv,
    graph: graph::LoadedGraph<'_>,
) -> Result<dispatch::CiInterface<dispatch::CfTransport>> {
    let pool = crate::fetch_guard::OutboundPool::new();
    match credential_source(env)? {
        CredentialSource::LocalCi(url) => Ok(dispatch::CiInterface::local_ci(
            &url,
            dispatch::CfTransport::new(pool),
        )),
        CredentialSource::GitHub(config) => {
            let token = github_app::installation_token(graph.tokens(), &config)
                .await
                .map_err(to_error)?;
            let github_repo = read_string_binding(env, GITHUB_REPO_BINDING)?;
            Ok(dispatch::CiInterface::github(
                &github_repo,
                &token.token,
                dispatch::CfTransport::new(pool),
            ))
        }
    }
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

/// `status` reconciles the delivery-tracked external set at most once
/// per this many minutes — ≤2 listing calls each, ≤12 calls/hour while
/// the queue has work (stow#877).
const STATUS_RECONCILE_MS: i64 = 10 * 60 * 1000;

/// The claim-plus-fan-out half of a dispatch pass, shared with the
/// budget probe's `"alarm pass"` drive (`drives.rs`) so the probe's
/// `wall_ms` covers the concurrent `dispatch` fan-out a real wake
/// pays. Returns the claimed task ids — the probe's claim record and
/// the launch gate's claim count both derive from the pass's own set.
pub(super) async fn dispatch_pass(
    graph: &graph::GraphCell,
    env: &WasmEnv,
    db: &DurableDb,
    settings: &SchedulerSettings,
) -> Result<Vec<String>> {
    let graph = ensure_graph(env, db, graph).await?;
    // The breaker is evaluated every pass: the outcome ring it reads is
    // window-filtered in memory, so the check costs no row.
    let freeze = freeze_settings(env)?;
    evaluate_dispatch_freeze(graph, env, db, &freeze).await?;
    // Binding resolution precedes claiming: a misconfigured binding fails
    // the pass with every row still `pending` instead of burned as a
    // dispatch attempt.
    let bindings = PassBindings::read(env)?;
    // The backend resolves once per pass, before the claim: the local-CI
    // branch carries no Authorization; the GitHub branch reuses the
    // isolate's cached installation token while more than five minutes
    // of validity remain and otherwise mints a fresh one. A failed mint
    // fails the pass with every row still `pending` — a transient mint
    // outage is not worth a burned build attempt.
    let pool = crate::fetch_guard::OutboundPool::new();
    let interface = match &bindings.credential_source {
        CredentialSource::LocalCi(url) => {
            tracing::info!(url = %url, "dispatching via local-CI endpoint");
            dispatch::CiInterface::local_ci(url, dispatch::CfTransport::new(pool.clone()))
        }
        CredentialSource::GitHub(config) => {
            match github_app::installation_token(graph.tokens(), config).await {
                Ok(token) => dispatch::CiInterface::github(
                    &bindings.github_repo,
                    &token.token,
                    dispatch::CfTransport::new(pool.clone()),
                ),
                Err(error) => {
                    let error = dispatch::DispatchError::TokenMint(error.to_string());
                    return Err(to_error(error.to_string()));
                }
            }
        }
    };
    // External occupancy (stow#877): runs this scheduler did not
    // dispatch are tracked from `workflow_run` deliveries —
    // `in_progress` for an unbound run adds, `completed` removes —
    // and `status` only reconciles the set: at most once per
    // STATUS_RECONCILE minutes and only while the graph holds work,
    // so an idle scheduler costs zero calls. A reconcile failure is
    // not worth burning the pass over — the delivery-tracked set is
    // the primary source; `status` only corrects its drift.
    if graph.with(|graph| graph.reconcile_due(now_ms(), STATUS_RECONCILE_MS)) {
        match interface.status_runs().await {
            Ok(listed) => {
                let listed: Vec<(u64, String, stow_types::api::RunnerFamily)> = listed
                    .iter()
                    .map(|run| {
                        (
                            run.workflow_run_id,
                            run.title.clone(),
                            run.family.unwrap_or(stow_types::api::RunnerFamily::Linux),
                        )
                    })
                    .collect();
                graph.with(|graph| graph.reconcile_runs(&listed, now_ms()));
            }
            Err(error) => {
                tracing::warn!(%error, "CI status reconcile failed — keeping delivery-tracked external occupancy");
            }
        }
    }
    let now = now_ms();
    let claims = routes::claim_pass(graph, db, settings, now)
        .await
        .map_err(route_error)?;
    let task_ids: Vec<String> = claims.iter().map(|claim| claim.task_id.clone()).collect();
    tracing::info!(
        claimed = task_ids.len(),
        "scheduler dispatch_pending selected tasks"
    );
    if claims.is_empty() {
        return Ok(Vec::new());
    }
    dispatch_claims(graph, db, &interface, claims).await?;
    Ok(task_ids)
}

/// The bindings an alarm pass reads, resolved once per pass.
struct PassBindings {
    github_repo: String,
    credential_source: CredentialSource,
}

impl PassBindings {
    fn read(env: &WasmEnv) -> Result<Self> {
        Ok(Self {
            github_repo: read_string_binding(env, GITHUB_REPO_BINDING)?,
            credential_source: credential_source(env)?,
        })
    }
}
/// The wall clock a pass reads — `Date::now()` returns whole
/// milliseconds well below 2^53, so the value is exactly
/// representable and always fits i64.
pub(super) fn now_ms() -> i64 {
    #[allow(clippy::cast_possible_truncation)]
    {
        js_sys::Date::now() as i64
    }
}

/// The `build-crate.yml` dispatch fan-out over one resolved backend —
/// one `workflow_dispatch` per claimed task, concurrently, then the
/// ordered outcome apply (stow#876).
///
/// The POSTs run under the invocation's outbound bound: the stream's
/// `buffered` admits at most `MAX_OUTBOUND_INFLIGHT` (4) at once, and
/// the pool slot `trigger_build` waits on enforces the same bound
/// before any request posts. `buffered` — not `buffer_unordered` —
/// yields results in the tasks' own order, so each outcome stays
/// matched to its task. The queue writes then apply sequentially:
/// `&DurableDb` is not `Send`, so it never enters a concurrent future.
async fn dispatch_claims(
    graph: graph::LoadedGraph<'_>,
    db: &DurableDb,
    backend: &dispatch::CiInterface<dispatch::CfTransport>,
    claims: Vec<graph::Claimed>,
) -> Result<()> {
    // Collected before streaming: a closure inside the stream's type
    // borrows each claim under a higher-ranked lifetime, and the alarm
    // future then cannot prove itself `Send`.
    let dispatches: Vec<_> = claims
        .iter()
        .map(|claim| {
            let encoded = claim.payload.encode_dispatch_task().map_err(|error| {
                dispatch::DispatchError::Response(format!("encode task: {error}"))
            });
            async move {
                match encoded {
                    Ok(encoded) => backend.submit(&encoded).await,
                    Err(error) => Err(error),
                }
            }
        })
        .collect();
    let outcomes = stream::iter(dispatches)
        .buffered(crate::fetch_guard::MAX_OUTBOUND_INFLIGHT)
        .collect::<Vec<_>>()
        .await;
    // ONE `Bindings` row for every returned binding (review); POST
    // failures re-queue their claim under backoff in memory only —
    // the failure is not a persistent event: a wake replays the claim
    // as dispatched-unbound, which the run-listing reconcile binds or
    // the stale lease returns.
    let mut bindings = Vec::new();
    let mut fails: Vec<(String, u64, String)> = Vec::new();
    for (claim, outcome) in claims.iter().zip(outcomes) {
        match outcome {
            Ok(run) => bindings.push(stow_types::api::DispatchBinding {
                task_id: claim.task_id.clone(),
                generation: claim.generation,
                run_id: run.workflow_run_id.to_string(),
            }),
            Err(error) => {
                tracing::error!(task_id = %claim.task_id, %error, "failed to dispatch build");
                fails.push((claim.task_id.clone(), claim.generation, error.to_string()));
            }
        }
    }
    routes::settle_dispatch(graph, db, bindings, fails, now_ms())
        .await
        .map_err(route_error)
}

async fn schedule_alarm(
    env: &WasmEnv,
    db: &DurableDb,
    alarm: &Alarm,
    graph: &graph::GraphCell,
) -> Result<()> {
    let (now_ms, settings) = alarm_inputs(env)?;
    let graph = ensure_graph(env, db, graph).await?;
    let plan = routes::wake_plan(graph, &settings, now_ms);
    queue::arm_alarm(alarm, plan).await.map_err(|error| {
        let error = to_error(error);
        tracing::error!(%error, "failed to perform scheduler alarm plan");
        error
    })?;
    // The flat log is bounded by snapshots: once the appended tail
    // crosses the threshold, this turn writes the chunked snapshot —
    // covered prefix dropped — before the next wake plans against the
    // same graph.
    routes::snapshot_if_due(graph, db)
        .await
        .map_err(route_error)?;
    Ok(())
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
    /// Task ids the merge found unpublished — the redemption path's
    /// miss set (stow#886).
    unpublished_ids: Vec<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct OkResponse {
    ok: bool,
}
