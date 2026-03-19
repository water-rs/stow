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

const GITHUB_TOKEN_BINDING: &str = "GITHUB_TOKEN";
const GITHUB_REPO_BINDING: &str = "GITHUB_REPO";

#[derive(Debug, Default, Serialize, Deserialize)]
#[skyzen::durable_object]
pub struct Scheduler;

impl DurableObject for Scheduler {
    fn fetch(&mut self) -> impl Endpoint + 'static {
        Route::new((
            "/enqueue".post(enqueue),
            "/complete".post(complete),
            "/boost".post(boost),
            "/status".at(status),
        ))
        .on_alarm(run_alarm)
        .build()
    }
}

async fn enqueue(
    env: WasmEnv,
    db: DurableDb,
    alarm: Alarm,
    Json(requests): Json<Vec<stow_types::api::EnqueueRequest>>,
) -> Result<Json<InsertedResponse>> {
    let inserted = queue::enqueue(&db, &requests).await.map_err(to_error)?;
    dispatch_pending(&env, &db).await.map_err(|error| {
        tracing::error!(%error, "scheduler enqueue dispatch_pending failed");
        error
    })?;
    schedule_alarm(&db, &alarm).await.map_err(|error| {
        tracing::error!(%error, "scheduler enqueue schedule_alarm failed");
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
    schedule_alarm(&db, &alarm).await.map_err(|error| {
        tracing::error!(%error, "scheduler complete schedule_alarm failed");
        error
    })?;
    Ok(Json(OkResponse { ok: true }))
}

async fn boost(
    db: DurableDb,
    alarm: Alarm,
    Json(boost): Json<stow_types::api::MissBoost>,
) -> Result<Json<OkResponse>> {
    queue::boost(&db, &boost).await.map_err(to_error)?;
    schedule_alarm(&db, &alarm).await.map_err(|error| {
        tracing::error!(%error, "scheduler boost schedule_alarm failed");
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
    schedule_alarm(&db, &alarm).await.map_err(|error| {
        tracing::error!(%error, "scheduler alarm schedule_alarm failed");
        error
    })?;
    Ok("ok")
}

async fn dispatch_pending(env: &WasmEnv, db: &DurableDb) -> Result<()> {
    let github_token = read_string_binding(env, GITHUB_TOKEN_BINDING)?;
    let github_repo = read_string_binding(env, GITHUB_REPO_BINDING)?;
    let tasks = queue::claim_dispatchable_tasks(db)
        .await
        .map_err(to_error)?;

    for task in tasks {
        if let Err(error) = dispatch::trigger_build(&task, &github_token, &github_repo).await {
            queue::mark_dispatch_failed(db, &task.task_id, &error.to_string())
                .await
                .map_err(to_error)?;
            tracing::error!(task_id = %task.task_id, error = %error, "failed to dispatch build");
        }
    }

    Ok(())
}

async fn schedule_alarm(db: &DurableDb, alarm: &Alarm) -> Result<()> {
    if !queue::has_pending_work(db).await.map_err(to_error)? {
        alarm.delete_alarm().await.map_err(|error| {
            let error = to_error(error);
            tracing::error!(%error, "failed to delete scheduler alarm");
            error
        })?;
        return Ok(());
    }

    let now_ms = js_sys::Date::now() as i64;
    let Some(next_ms) = queue::next_dispatch_eligible_alarm_ms(db, now_ms)
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
