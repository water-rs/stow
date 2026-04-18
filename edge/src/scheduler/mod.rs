pub mod dispatch;
pub mod queue;

use js_sys::Reflect;
use serde::{Deserialize, Serialize};
use skyzen::durable::DurableObject;
use skyzen::routing::{CreateRouteNode, Route};
use skyzen::runtime::wasm::WasmEnv;
use skyzen::utils::Json;
use skyzen::{Endpoint, Error, Result};
use skyzen_services::durable::{Alarm, DurableDb};
use wasm_bindgen::JsValue;

const STOW_LOCAL_CI_URL_BINDING: &str = "STOW_LOCAL_CI_URL";
const STOW_DISPATCH_MIN_AGE_MINUTES_BINDING: &str = "STOW_DISPATCH_MIN_AGE_MINUTES";
const GITHUB_TOKEN_BINDING: &str = "GITHUB_TOKEN";
const GITHUB_REPO_BINDING: &str = "GITHUB_REPO";

#[derive(Debug, Default, Serialize, Deserialize)]
#[skyzen::durable_object]
pub struct Scheduler;

impl DurableObject for Scheduler {
    fn fetch(&mut self) -> impl Endpoint + 'static {
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

async fn dispatch_pending(env: &WasmEnv, db: &DurableDb) -> Result<()> {
    let github_token = read_string_binding(env, GITHUB_TOKEN_BINDING)?;
    let github_repo = read_string_binding(env, GITHUB_REPO_BINDING)?;
    let local_ci_url = read_optional_string_binding(env, STOW_LOCAL_CI_URL_BINDING);
    let dispatch_min_age_minutes =
        read_optional_u32_binding(env, STOW_DISPATCH_MIN_AGE_MINUTES_BINDING)?;
    let tasks = queue::claim_dispatchable_tasks(db, dispatch_min_age_minutes)
        .await
        .map_err(to_error)?;
    tracing::info!(
        claimed = tasks.len(),
        ?local_ci_url,
        ?dispatch_min_age_minutes,
        "scheduler dispatch_pending selected tasks"
    );

    for task in tasks {
        if let Err(error) =
            dispatch::trigger_build(&task, &github_token, &github_repo, local_ci_url.as_deref())
                .await
        {
            queue::mark_dispatch_failed(db, &task.task_id, &error.to_string())
                .await
                .map_err(to_error)?;
            tracing::error!(task_id = %task.task_id, error = %error, "failed to dispatch build");
        }
    }

    Ok(())
}

async fn schedule_alarm(env: &WasmEnv, db: &DurableDb, alarm: &Alarm) -> Result<()> {
    if !queue::has_pending_work(db).await.map_err(to_error)? {
        alarm.delete_alarm().await.map_err(|error| {
            let error = to_error(error);
            tracing::error!(%error, "failed to delete scheduler alarm");
            error
        })?;
        return Ok(());
    }

    let now_ms = js_sys::Date::now() as i64;
    let dispatch_min_age_minutes =
        read_optional_u32_binding(env, STOW_DISPATCH_MIN_AGE_MINUTES_BINDING)?;
    let Some(next_ms) =
        queue::next_dispatch_eligible_alarm_ms(db, now_ms, dispatch_min_age_minutes)
            .await
            .map_err(to_error)?
    else {
        alarm.delete_alarm().await.map_err(|error| {
            let error = to_error(error);
            tracing::error!(%error, "failed to delete scheduler alarm without eligible task");
            error
        })?;
        return Ok(());
    };
    alarm.set_alarm(next_ms).await.map_err(|error| {
        let error = to_error(error);
        tracing::error!(%error, next_ms, "failed to set scheduler alarm");
        error
    })?;

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

#[derive(Debug, Serialize)]
struct InsertedResponse {
    inserted: u32,
}

#[derive(Debug, Serialize)]
struct OkResponse {
    ok: bool,
}
