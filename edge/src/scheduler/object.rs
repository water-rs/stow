//! Durable Object glue: routes scheduler HTTP/alarm events into the queue
//! state machine and GitHub dispatch.

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
use stow_types::api::SchemaMigrationReport;

use crate::db;
use crate::errors::QueueError;
use crate::freeze::{self, FreezeSettings};
use crate::github_app;
use crate::scheduler::budget;
use crate::scheduler::meter::{self, Meter, MeterGuard};
use crate::scheduler::queue::SchedulerSettings;
use crate::scheduler::{dispatch, queue};

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
                "/retry".post(queue_retry),
                "/cancel".post(queue_cancel),
                "/promote".post(queue_promote),
                "/purge".post(queue_purge),
            )),
            // The GitHub `workflow_run` webhook's completion channel —
            // carries task id + outcome and no attempt, which
            // `queue::complete_run` resolves against the live row.
            "/tasks/complete-run".post(complete_run),
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
            "/migrate".post(migrate_scheduler),
            // The workerd budget probe — gated on the
            // `STOW_SCHEDULER_BUDGET` deploy var, which only mock stacks
            // carry; production requests hit the guard and 404.
            "/budget".post(scheduler_budget),
            "/budget/seed".post(scheduler_budget_seed),
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

/// `POST /migrate` — the only endpoint that may issue DDL on the queue
/// database. Reached from `POST /api/v1/admin/scheduler/migrate`, which
/// `deploy-edge.yml` calls right after `skyzen deploy` and `stow-admin
/// scheduler migrate` calls manually. Runs the full migration pass and
/// returns the schema version before and after.
async fn migrate_scheduler(env: WasmEnv, db: DurableDb) -> Result<Json<SchemaMigrationReport>> {
    let report = queue::migrate(&db, &scheduler_settings(&env)?)
        .await
        .map_err(to_error)?;
    tracing::warn!(
        before = report.before,
        after = report.after,
        "scheduler schema migrated"
    );
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
        budget::seed(&db, &request, &scheduler_settings(&env)?)
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
        budget::run(&db, &settings, &env, &request)
            .await
            .map_err(to_error)?,
    ))
}

fn budget_probe_enabled(env: &WasmEnv) -> bool {
    read_optional_string_binding(env, budget::BUDGET_PROBE_BINDING)
        .is_some_and(|value| value == "1")
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
    // Dispatch is not this request's work: pointing the alarm at now lets
    // `run_alarm`'s dispatch pass run it, so the submit answers once the
    // queue write lands instead of holding the client — and burning the
    // DO's per-request CPU budget — through claim plus a fan-out of
    // GitHub calls.
    arm_dispatch_alarm(alarm).await?;
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

/// Point the DO alarm at now: `run_alarm` then performs the dispatch
/// pass (`dispatch_pending` plus `schedule_alarm`) that a mutating
/// handler used to run inline. `setAlarm` overrides any existing
/// scheduled alarm rather than keeping the earliest
/// (<https://developers.cloudflare.com/durable-objects/api/alarms/#setalarm>),
/// which is correct here: `run_alarm` re-arms via `schedule_alarm`, so
/// moving an earlier wake-up up to now only dispatches sooner.
async fn arm_dispatch_alarm(alarm: &Alarm) -> Result<()> {
    // `Date::now()` returns whole milliseconds well below 2^53; the value
    // is exactly representable and always fits i64.
    #[allow(clippy::cast_possible_truncation)]
    let now_ms = js_sys::Date::now() as i64;
    alarm.set_alarm(now_ms).await.map_err(|error| {
        let error = to_error(error);
        tracing::error!(%error, "failed to arm scheduler dispatch alarm");
        error
    })
}

/// `POST /tasks/complete-run` — the edge's webhook route forwards GitHub's
/// `workflow_run` event here; the report carries the task id and outcome
/// but no attempt, which `complete_run` resolves against the live row.
///
/// A completion for a task the queue never held answers 404, not 500 —
/// the report references nothing real. A row whose live attempt or
/// status no longer matches what the event describes answers 409 — the
/// row moved on, and the webhook logs both rather than propagating them:
/// a retried delivery changes nothing about a row that already moved.
async fn complete_run(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(report): Json<stow_types::api::WorkflowRunComplete>,
) -> Result<Json<OkResponse>> {
    let freeze = freeze_settings(&env)?;
    queue::complete_run(
        &db,
        &scheduler_settings(&env)?,
        &report,
        freeze.window_minutes,
    )
    .await
    .map_err(|error| {
        let status = match &error {
            crate::errors::QueueError::UnknownTask(_) => StatusCode::NOT_FOUND,
            crate::errors::QueueError::StaleCompletion { .. } => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        to_error(error).set_status(status)
    })?;
    // A failed attempt may have closed the window's trip condition —
    // evaluate while this request still holds the outcome row's write
    // context. The freeze then eats the dispatch the alarm was about
    // to run.
    if !report.success {
        evaluate_dispatch_freeze(&env, &db, &freeze).await?;
    }
    // Same handoff as submit: the run's report is acknowledged as soon
    // as the queue row lands, and the alarm's dispatch pass — not this
    // request — runs claim plus the GitHub fan-out.
    arm_dispatch_alarm(&alarm).await?;
    Ok(Json(OkResponse { ok: true }))
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
    // The same credential arm as `dispatch_pass`: the cached installation
    // token — minted inline on expiry — or the mock stack's local-CI URL.
    let credential = match credential_source {
        CredentialSource::LocalCi(url) => dispatch::DispatchCredential::LocalCi(url),
        CredentialSource::GitHub(config) => match github_app::installation_token(db, &config).await
        {
            Ok(token) => dispatch::DispatchCredential::GitHub(token),
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
        },
    };
    let pool = crate::fetch_guard::OutboundPool::new();
    if let Err(error) =
        dispatch::trigger_resolve(&dispatch_payload, &credential, &github_repo, &pool).await
    {
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
    // the alarm's dispatch pass — not this request — fans them out.
    arm_dispatch_alarm(&alarm).await?;
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
    match queue::record_published_slice(
        &db,
        slice.target.as_str(),
        slice.rustc_version.as_str(),
        slice.base_generation,
        slice.generation,
        &slice.added,
        &slice.retired,
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
/// `wall_ms` covers the serialized `trigger_build` hop and the
/// counted-D1 coverage lookups a real wake pays. Returns the claimed
/// task count.
pub(super) async fn dispatch_pass(
    env: &WasmEnv,
    db: &DurableDb,
    settings: &SchedulerSettings,
    coverage: &impl queue::CoverageOracle,
) -> Result<usize> {
    let github_repo = read_string_binding(env, GITHUB_REPO_BINDING)?;
    // Binding resolution precedes claiming: a misconfigured binding fails
    // the pass with every row still `pending` instead of burned as a
    // dispatch attempt.
    let credential_source = credential_source(env)?;
    let tasks = queue::claim_dispatchable_tasks(db, settings, coverage)
        .await
        .map_err(to_error)?;
    tracing::info!(
        claimed = tasks.len(),
        "scheduler dispatch_pending selected tasks"
    );
    if tasks.is_empty() {
        return Ok(0);
    }
    let claimed = tasks.len();

    // The credential resolves once per pass, only when tasks exist: the
    // local-CI branch carries no Authorization; the GitHub branch reuses
    // the installation token cached in DO storage while more than five
    // minutes of validity remain and otherwise mints a fresh one. A
    // failed mint is a dispatch failure for every claimed task — the same
    // backoff a failed POST would get.
    let credential = match credential_source {
        CredentialSource::LocalCi(url) => {
            tracing::info!(url = %url, "dispatching via local-CI endpoint");
            dispatch::DispatchCredential::LocalCi(url)
        }
        CredentialSource::GitHub(config) => {
            match github_app::installation_token(db, &config).await {
                Ok(token) => dispatch::DispatchCredential::GitHub(token),
                Err(error) => {
                    let error = dispatch::DispatchError::TokenMint(error.to_string());
                    for task in &tasks {
                        queue::mark_dispatch_failed(
                            db,
                            settings,
                            &task.task_id,
                            &error.to_string(),
                        )
                        .await
                        .map_err(to_error)?;
                        tracing::error!(task_id = %task.task_id, error = %error, "failed to dispatch build");
                    }
                    return Ok(claimed);
                }
            }
        }
    };

    // One bound for the whole DO fetch invocation: dispatch is a
    // sequential loop, so a slot is always free — the pool exists so a
    // future parallel fan-out cannot exceed the invocation's budget.
    let pool = crate::fetch_guard::OutboundPool::new();
    for task in tasks {
        if let Err(error) = dispatch::trigger_build(&task, &credential, &github_repo, &pool).await {
            queue::mark_dispatch_failed(db, settings, &task.task_id, &error.to_string())
                .await
                .map_err(to_error)?;
            tracing::error!(task_id = %task.task_id, error = %error, "failed to dispatch build");
        }
    }

    Ok(claimed)
}

async fn schedule_alarm(env: &WasmEnv, db: &DurableDb, alarm: &Alarm) -> Result<()> {
    // `Date::now()` returns whole milliseconds well below 2^53; the value is
    // exactly representable and always fits i64.
    #[allow(clippy::cast_possible_truncation)]
    let now_ms = js_sys::Date::now() as i64;
    let settings = scheduler_settings(env)?;
    match queue::next_alarm(db, now_ms, &settings)
        .await
        .map_err(to_error)?
    {
        queue::AlarmPlan::Delete => alarm.delete_alarm().await.map_err(|error| {
            let error = to_error(error);
            tracing::error!(%error, "failed to delete scheduler alarm");
            error
        })?,
        queue::AlarmPlan::At(next_ms) => alarm.set_alarm(next_ms).await.map_err(|error| {
            let error = to_error(error);
            tracing::error!(%error, next_ms, "failed to set scheduler alarm");
            error
        })?,
    }

    Ok(())
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
