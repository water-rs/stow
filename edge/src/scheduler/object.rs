//! Durable Object glue: routes scheduler HTTP/alarm events into the queue
//! state machine and GitHub dispatch.

use js_sys::Reflect;
use serde::{Deserialize, Serialize};
use skyzen::durable::DurableObject;
use skyzen::routing::{CreateRouteNode, Route, Router};
use skyzen::runtime::wasm::WasmEnv;
use skyzen::utils::Json;
use skyzen::{Error, Result, StatusCode};
use skyzen_services::durable::{Alarm, DurableDb};
use wasm_bindgen::JsValue;

use std::collections::BTreeSet;

use skyzen_cloudflare::CfD1;
use skyzen_services::Db;

use crate::db;
use crate::email;
use crate::errors::QueueError;
use crate::freeze::{self, FreezeSettings};
use crate::github_app;
use crate::scheduler::queue::SchedulerSettings;
use crate::scheduler::{dispatch, queue};

const STOW_LOCAL_CI_URL_BINDING: &str = "STOW_LOCAL_CI_URL";
const STOW_DB_BINDING: &str = "STOW_DB";
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

fn scheduler_settings(env: &WasmEnv) -> Result<SchedulerSettings> {
    let defaults = SchedulerSettings::default();
    Ok(SchedulerSettings {
        max_concurrent_jobs: read_optional_u32_binding(env, STOW_MAX_CONCURRENT_JOBS_BINDING)?
            .unwrap_or(defaults.max_concurrent_jobs),
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

/// The trip thresholds the systematic-failure window is evaluated with
/// — same binding-with-default shape as the scheduler tunables.
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

#[derive(Debug, Default, Serialize, Deserialize)]
#[skyzen::durable_object]
pub struct Scheduler;

impl DurableObject for Scheduler {
    fn fetch(&mut self) -> Router {
        // The Durable Object runs in its own isolate; the exported fetch
        // goes through this method before the router responds, so this is
        // where its logging gets installed.
        #[cfg(target_arch = "wasm32")]
        crate::console_log::init();
        Route::new((
            "/tasks/submit".post(submit_tasks),
            "/tasks/submit/trusted".post(submit_tasks_trusted),
            "/tasks/status".post(tasks_status),
            "/tasks".at(list_tasks),
            "/tasks/retry".post(queue_retry),
            "/tasks/cancel".post(queue_cancel),
            "/tasks/promote".post(queue_promote),
            "/tasks/purge".post(queue_purge),
            "/tasks/observe-run".post(observe_run),
            "/complete".post(complete),
            "/status".at(status),
            "/admin/status".at(admin_status),
            "/rustc/stable".at(stable_rustc),
            "/panic".at(read_panic).post(write_panic),
            "/freeze".at(read_freeze).post(write_freeze),
        ))
        .on_alarm(run_alarm)
        .build()
    }
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
/// pending-depth cap: callers reached it through the edge's `RepoWriter`
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
    dispatch_pending(env, db).await.map_err(|error| {
        tracing::error!(%error, "scheduler submit dispatch_pending failed");
        error
    })?;
    schedule_alarm(env, db, alarm).await.map_err(|error| {
        tracing::error!(%error, "scheduler submit schedule_alarm failed");
        error
    })?;
    Ok(Json(InsertedResponse { inserted }))
}

async fn complete(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(report): Json<stow_types::api::BuildCompleteReport>,
) -> Result<Json<OkResponse>> {
    // A completion for a task the queue never held is a client error —
    // the report references nothing real — so it answers 404, not 500.
    // A report whose attempt no longer matches the row's live state is a
    // conflict: the row moved on (resurrected by a re-request, or the
    // report is a duplicate), and answering 409 keeps the reporter from
    // believing it completed the current attempt. The edge forwards
    // scheduler 4xx bodies, so the reporter sees the mismatch rather than
    // a bare "internal server error".
    queue::complete(&db, &report).await.map_err(|error| {
        let status = match &error {
            crate::errors::QueueError::UnknownTask(_) => StatusCode::NOT_FOUND,
            crate::errors::QueueError::StaleCompletion { .. } => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        to_error(error).set_status(status)
    })?;
    if !report.success {
        evaluate_dispatch_freeze(&env, &db).await?;
    }
    dispatch_pending(&env, &db).await.map_err(|error| {
        tracing::error!(%error, "scheduler complete dispatch_pending failed");
        error
    })?;
    schedule_alarm(&env, &db, &alarm).await.map_err(|error| {
        tracing::error!(%error, "scheduler complete schedule_alarm failed");
        error
    })?;
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
    let affected = queue::apply_mutation(&db, mutation, &selector)
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

/// `POST /tasks/observe-run` — a trusted caller saw a GitHub Actions run
/// act on this task (artifact registration); stamp the run id so `status`
/// can surface its URL.
async fn observe_run(
    db: DurableDb,
    Json(observe): Json<stow_types::api::ObserveRun>,
) -> Result<Json<OkResponse>> {
    queue::observe_run(&db, &observe.task_id, &observe.github_run_id)
        .await
        .map_err(to_error)?;
    Ok(Json(OkResponse { ok: true }))
}

async fn tasks_status(
    db: DurableDb,
    Json(task_ids): Json<Vec<String>>,
) -> Result<Json<Vec<stow_types::api::RequestStatus>>> {
    let statuses = queue::tasks_status(&db, &task_ids)
        .await
        .map_err(to_error)?;
    Ok(Json(statuses))
}

/// `GET /panic` — the anonymous-traffic circuit breaker's current state.
async fn read_panic(db: DurableDb) -> Result<Json<stow_types::api::PanicSwitch>> {
    let enabled = queue::panic_enabled(&db).await.map_err(to_error)?;
    Ok(Json(stow_types::api::PanicSwitch { enabled }))
}

/// `POST /panic` — write the flag, then answer what was stored.
async fn write_panic(
    db: DurableDb,
    Json(switch): Json<stow_types::api::PanicSwitch>,
) -> Result<Json<stow_types::api::PanicSwitch>> {
    queue::set_panic(&db, switch.enabled)
        .await
        .map_err(to_error)?;
    tracing::warn!(enabled = switch.enabled, "panic switch flipped");
    Ok(Json(switch))
}

/// `GET /freeze` — the dispatch freeze's current state: the flag plus
/// the stored record (trigger and notify outcome) when engaged.
async fn read_freeze(db: DurableDb) -> Result<Json<stow_types::api::DispatchFreeze>> {
    let record = queue::freeze_record(&db).await.map_err(to_error)?;
    Ok(Json(stow_types::api::DispatchFreeze {
        enabled: record.is_some(),
        record,
    }))
}

/// `POST /freeze` — the manual transition that is also the only
/// recovery path. Each direction sends exactly one alert, and writing
/// the state already held is a no-op so alerts never repeat.
async fn write_freeze(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(switch): Json<stow_types::api::DispatchFreeze>,
) -> Result<Json<stow_types::api::DispatchFreeze>> {
    let prior = queue::freeze_record(&db).await.map_err(to_error)?;
    match (prior, switch.enabled) {
        (Some(record), true) => Ok(Json(stow_types::api::DispatchFreeze {
            enabled: true,
            record: Some(record),
        })),
        (None, false) => Ok(Json(stow_types::api::DispatchFreeze {
            enabled: false,
            record: None,
        })),
        (None, true) => {
            let frozen_at = iso_now();
            let trigger = stow_types::api::DispatchFreezeTrigger::Manual;
            let notify = send_freeze_alert(&env, &frozen_at, &trigger).await;
            let record = stow_types::api::DispatchFreezeRecord {
                frozen_at,
                trigger,
                notify,
            };
            queue::set_freeze(&db, &record).await.map_err(to_error)?;
            // While frozen `next_alarm` plans a delete — a live alarm
            // would only spin dispatch passes the gate would eat.
            schedule_alarm(&env, &db, &alarm).await.map_err(|error| {
                tracing::error!(%error, "scheduler freeze schedule_alarm failed");
                error
            })?;
            tracing::warn!("dispatch freeze engaged manually");
            Ok(Json(stow_types::api::DispatchFreeze {
                enabled: true,
                record: Some(record),
            }))
        }
        (Some(record), false) => {
            queue::delete_freeze(&db).await.map_err(to_error)?;
            send_cleared_alert(&env, &record).await;
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
            Ok(Json(stow_types::api::DispatchFreeze {
                enabled: false,
                record: None,
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

/// The freeze-transition alert: resolve the transport, render the body,
/// send. Never `Err` — every failure is a recorded outcome on the
/// freeze record.
async fn send_freeze_alert(
    env: &WasmEnv,
    frozen_at: &str,
    trigger: &stow_types::api::DispatchFreezeTrigger,
) -> stow_types::api::DispatchFreezeNotify {
    let config = match email::alert_config(env.as_js()) {
        Ok(config) => config,
        Err(disabled) => return disabled,
    };
    let text = freeze::render_freeze_alert(frozen_at, trigger, &config.to, &config.from)
        .expect("freeze alert template renders");
    email::send_alert(&config, freeze::freeze_subject(trigger), &text).await
}

/// The clear-transition alert — the deleted record describes the freeze
/// it lifted. The outcome is logged, not stored (there is no record
/// left to carry it).
async fn send_cleared_alert(env: &WasmEnv, record: &stow_types::api::DispatchFreezeRecord) {
    let cleared_at = iso_now();
    match email::alert_config(env.as_js()) {
        Err(disabled) => {
            tracing::warn!(?disabled, "freeze cleared — alert transport disabled");
        }
        Ok(config) => {
            let text = freeze::render_freeze_cleared(
                &record.frozen_at,
                &cleared_at,
                &record.trigger,
                &record.notify,
                &config.to,
                &config.from,
            )
            .expect("freeze cleared template renders");
            let outcome = email::send_alert(&config, freeze::FREEZE_CLEARED_SUBJECT, &text).await;
            match outcome {
                stow_types::api::DispatchFreezeNotify::Sent { .. } => {
                    tracing::info!("freeze cleared — alert sent");
                }
                other => tracing::error!(?other, "freeze cleared — alert send failed"),
            }
        }
    }
}

/// After a failed completion, decide whether the trailing window trips
/// the freeze. A live freeze answers first — a second transition must
/// not rewrite the record or resend the alert. Storage and query errors
/// propagate (loud); the alert send's outcome only ever lands on the
/// record.
async fn evaluate_dispatch_freeze(env: &WasmEnv, db: &DurableDb) -> Result<()> {
    if queue::freeze_enabled(db).await.map_err(to_error)? {
        return Ok(());
    }
    let settings = freeze_settings(env)?;
    let Some(draft) = queue::evaluate_freeze_trip(db, &settings)
        .await
        .map_err(to_error)?
    else {
        return Ok(());
    };
    let trigger = trip_trigger(env, draft, &settings)?;
    let frozen_at = iso_now();
    // Render + send resolve before the write so the record lands once,
    // carrying the real notify outcome; the send is an outcome value,
    // never an error.
    let notify = send_freeze_alert(env, &frozen_at, &trigger).await;
    let record = stow_types::api::DispatchFreezeRecord {
        frozen_at,
        trigger,
        notify,
    };
    queue::set_freeze(db, &record).await.map_err(to_error)?;
    match &record.notify {
        stow_types::api::DispatchFreezeNotify::Sent { .. } => {
            tracing::warn!(trigger = ?record.trigger, "dispatch freeze tripped — alert sent");
        }
        stow_types::api::DispatchFreezeNotify::Failed { code, message, .. } => {
            tracing::error!(
                code = ?code,
                %message,
                trigger = ?record.trigger,
                "dispatch freeze tripped — alert send failed"
            );
        }
        stow_types::api::DispatchFreezeNotify::Disabled { reason } => {
            tracing::warn!(%reason, "dispatch freeze tripped — alert transport disabled");
        }
    }
    Ok(())
}

/// Turn a trip verdict into the wire `Tripped` trigger — the example
/// run URL only materializes when a failed run id and the repo binding
/// both exist.
fn trip_trigger(
    env: &WasmEnv,
    draft: queue::FreezeTripDraft,
    settings: &FreezeSettings,
) -> Result<stow_types::api::DispatchFreezeTrigger> {
    let example_run_url = draft.example_run_id.and_then(|run_id| {
        read_optional_string_binding(env, GITHUB_REPO_BINDING)
            .map(|repo| format!("https://github.com/{repo}/actions/runs/{run_id}"))
    });
    draft
        .eval
        .into_wire(settings, example_run_url)
        .map(stow_types::api::DispatchFreezeTrigger::Tripped)
        .map_err(|invariant| Error::msg(format!("freeze trip evidence invariant: {invariant}")))
}

async fn stable_rustc(db: DurableDb) -> Result<Json<StableRustcResponse>> {
    let version =
        crate::rust_channel::stable_rustc_version(&db, &crate::rust_channel::CfRustChannel)
            .await
            .map_err(to_error)?;
    Ok(Json(StableRustcResponse {
        version: version.as_str().to_owned(),
    }))
}

async fn run_alarm(env: WasmEnv, db: DurableDb, alarm: Alarm) -> Result<&'static str> {
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

/// Where a dispatch pass sends claimed tasks, resolved from the Worker's
/// bindings before anything is claimed.
enum CredentialSource {
    /// `STOW_LOCAL_CI_URL` — posts to the local dispatcher, which needs
    /// none of the GitHub App bindings.
    LocalCi(String),
    /// The GitHub App bindings that mint the installation token.
    GitHub(github_app::AppConfig),
}

/// The artifact catalog in D1, asked at claim time which pending tasks a
/// dominator's publish already covered.
struct CatalogCoverage {
    db: Db,
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
    // The dispatch freeze is the gate, and it lives here — the enqueue
    // side of the queue never consults it, so misses keep arriving and
    // stay pending for the first pass after a human lifts the freeze.
    // It precedes binding resolution on purpose: while frozen there is
    // no dispatch pass at all, not even its failures.
    if queue::freeze_enabled(db).await.map_err(to_error)? {
        tracing::info!("dispatch frozen — skipping dispatch pass");
        return Ok(());
    }
    let github_repo = read_string_binding(env, GITHUB_REPO_BINDING)?;
    let settings = scheduler_settings(env)?;
    // Binding resolution precedes claiming: a misconfigured binding fails
    // the pass with every row still `pending` instead of burned as a
    // dispatch attempt.
    let credential_source = match read_optional_string_binding(env, STOW_LOCAL_CI_URL_BINDING) {
        Some(url) => CredentialSource::LocalCi(url),
        None => CredentialSource::GitHub(github_app::AppConfig {
            app_id: read_string_binding(env, GITHUB_APP_ID_BINDING)?,
            installation_id: read_string_binding(env, GITHUB_APP_INSTALLATION_ID_BINDING)?,
            private_key_pem: read_string_binding(env, GITHUB_APP_PRIVATE_KEY_BINDING)?,
        }),
    };
    let coverage = CatalogCoverage {
        db: Db::new(
            CfD1::from_env(env.as_js(), STOW_DB_BINDING)
                .map_err(|error| Error::msg(format!("load D1 binding: {error}")))?,
        ),
    };
    let tasks = queue::claim_dispatchable_tasks(db, &settings, &coverage)
        .await
        .map_err(to_error)?;
    tracing::info!(
        claimed = tasks.len(),
        "scheduler dispatch_pending selected tasks"
    );
    if tasks.is_empty() {
        return Ok(());
    }

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
                        queue::mark_dispatch_failed(db, &task.task_id, &error.to_string())
                            .await
                            .map_err(to_error)?;
                        tracing::error!(task_id = %task.task_id, error = %error, "failed to dispatch build");
                    }
                    return Ok(());
                }
            }
        }
    };

    for task in tasks {
        if let Err(error) = dispatch::trigger_build(&task, &credential, &github_repo).await {
            queue::mark_dispatch_failed(db, &task.task_id, &error.to_string())
                .await
                .map_err(to_error)?;
            tracing::error!(task_id = %task.task_id, error = %error, "failed to dispatch build");
        }
    }

    Ok(())
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

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct StableRustcResponse {
    version: String,
}
