//! Durable Object glue: routes scheduler HTTP/alarm events into the queue
//! state machine and GitHub dispatch.

use js_sys::Reflect;
use serde::{Deserialize, Serialize};
use skyzen::durable::DurableObject;
use skyzen::routing::{CreateRouteNode, Route, Router};
use skyzen::runtime::wasm::WasmEnv;
use skyzen::utils::Json;
use skyzen::{Error, Result};
use skyzen_services::durable::{Alarm, DurableDb};
use wasm_bindgen::JsValue;

use crate::github_app;
use crate::scheduler::queue::SchedulerSettings;
use crate::scheduler::{dispatch, queue};

const STOW_LOCAL_CI_URL_BINDING: &str = "STOW_LOCAL_CI_URL";
const STOW_DISPATCH_MIN_AGE_MINUTES_BINDING: &str = "STOW_DISPATCH_MIN_AGE_MINUTES";
const STOW_MAX_CONCURRENT_JOBS_BINDING: &str = "STOW_MAX_CONCURRENT_JOBS";
const STOW_STALE_DISPATCH_MINUTES_BINDING: &str = "STOW_STALE_DISPATCH_MINUTES";
const GITHUB_APP_ID_BINDING: &str = "GITHUB_APP_ID";
const GITHUB_APP_INSTALLATION_ID_BINDING: &str = "GITHUB_APP_INSTALLATION_ID";
const GITHUB_APP_PRIVATE_KEY_BINDING: &str = "GITHUB_APP_PRIVATE_KEY";
const GITHUB_REPO_BINDING: &str = "GITHUB_REPO";

fn scheduler_settings(env: &WasmEnv) -> Result<SchedulerSettings> {
    let defaults = SchedulerSettings::default();
    Ok(SchedulerSettings {
        max_concurrent_jobs: read_optional_u32_binding(env, STOW_MAX_CONCURRENT_JOBS_BINDING)?
            .unwrap_or(defaults.max_concurrent_jobs),
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
    })
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[skyzen::durable_object]
pub struct Scheduler;

impl DurableObject for Scheduler {
    fn fetch(&mut self) -> Router {
        Route::new((
            "/tasks/submit".post(submit_tasks),
            "/complete".post(complete),
            "/status".at(status),
        ))
        .on_alarm(run_alarm)
        .build()
    }
}

async fn submit_tasks(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(requests): Json<Vec<stow_types::api::EnqueueRequest>>,
) -> Result<Json<InsertedResponse>> {
    let inserted = queue::enqueue(&db, &requests).await.map_err(to_error)?;
    dispatch_pending(&env, &db).await.map_err(|error| {
        tracing::error!(%error, "scheduler submit dispatch_pending failed");
        error
    })?;
    schedule_alarm(&env, &db, &alarm).await.map_err(|error| {
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
    queue::complete(&db, &report).await.map_err(to_error)?;
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

async fn dispatch_pending(env: &WasmEnv, db: &DurableDb) -> Result<()> {
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
    let tasks = queue::claim_dispatchable_tasks(db, &settings)
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
