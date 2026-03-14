mod crates_api;
mod enqueue;
mod rustc_releases;

use skyzen::events::ScheduledTick;
use skyzen::js_sys::Reflect;
use skyzen::routing::{CreateRouteNode, Route, Router};
use skyzen::runtime::wasm::Env;
use skyzen_cloudflare::{CfD1, CfDurableNamespace, CfEventError, CfKv, CfScheduleContext};
use skyzen_services::{Db, Kv};
use wasm_bindgen::JsValue;

const STOW_DB_BINDING: &str = "STOW_DB";
const WATCHER_STATE_BINDING: &str = "WATCHER_STATE";
const SCHEDULER_BINDING: &str = "SCHEDULER";
const SCHEDULER_OBJECT_NAME_BINDING: &str = "SCHEDULER_OBJECT_NAME";
const TARGETS_JSON_BINDING: &str = "STOW_TARGETS_JSON";

#[skyzen::main]
fn worker() -> Router {
    Route::new((
        "/health".at(health),
    ))
    .build()
}

async fn health() -> &'static str {
    "OK"
}

#[cfg(target_arch = "wasm32")]
#[skyzen::scheduled]
async fn scheduled(
    event: ScheduledTick,
    env: Env,
    _ctx: CfScheduleContext,
) -> Result<(), CfEventError> {
    tracing::info!(
        cron = %event.cron,
        scheduled_time_ms = event.scheduled_time_ms,
        "watcher scheduled run started"
    );

    let db = Db::new(
        CfD1::from_env(&env, STOW_DB_BINDING)
            .map_err(|error| CfEventError::Runtime(error.to_string()))?,
    );
    let state_kv = Kv::new(
        CfKv::from_env(&env, WATCHER_STATE_BINDING)
            .map_err(|error| CfEventError::Runtime(error.to_string()))?,
    );
    let scheduler = CfDurableNamespace::from_env(&env, SCHEDULER_BINDING)
        .map_err(|error| CfEventError::Runtime(error.to_string()))?;

    let scheduler_object_name = read_string_binding(&env, SCHEDULER_OBJECT_NAME_BINDING)
        .map_err(CfEventError::Runtime)?;
    let targets = read_targets(&env).map_err(CfEventError::Runtime)?;

    let subscribed_crates = crates_api::list_subscribed(&db)
        .await
        .map_err(CfEventError::Runtime)?;
    let current_versions = crates_api::detect_updates(&db, &state_kv)
        .await
        .map_err(CfEventError::Runtime)?;

    if let Some(rustc_version) = rustc_releases::detect_new_stable(&state_kv)
        .await
        .map_err(CfEventError::Runtime)?
    {
        let crates = hydrate_subscribed_crates(&subscribed_crates, &current_versions)
            .await
            .map_err(CfEventError::Runtime)?;
        enqueue::enqueue_rustc_refresh(
            &scheduler,
            &scheduler_object_name,
            &targets,
            &crates,
            &rustc_version,
        )
        .await
        .map_err(CfEventError::Runtime)?;
    }

    enqueue::enqueue_crate_updates(
        &scheduler,
        &scheduler_object_name,
        &targets,
        &current_versions,
    )
    .await
    .map_err(CfEventError::Runtime)?;

    tracing::info!(
        updated_crates = current_versions.len(),
        targets = targets.len(),
        "watcher scheduled run finished"
    );

    Ok(())
}

async fn hydrate_subscribed_crates(
    subscribed_names: &[String],
    updates: &[crates_api::SubscribedCrate],
) -> Result<Vec<crates_api::SubscribedCrate>, String> {
    if subscribed_names.is_empty() {
        return Ok(Vec::new());
    }

    if updates.len() == subscribed_names.len() {
        return Ok(updates.to_vec());
    }

    let update_map = updates
        .iter()
        .map(|krate| (krate.name.as_str(), krate))
        .collect::<std::collections::BTreeMap<_, _>>();

    let mut crates = Vec::with_capacity(subscribed_names.len());
    for crate_name in subscribed_names {
        if let Some(updated) = update_map.get(crate_name.as_str()) {
            crates.push((*updated).clone());
            continue;
        }

        let latest = crates_api::fetch_current(crate_name)
            .await?;
        crates.push(latest);
    }

    Ok(crates)
}

fn read_targets(env: &Env) -> Result<Vec<String>, String> {
    let raw = read_string_binding(env, TARGETS_JSON_BINDING)?;
    let targets: Vec<String> =
        serde_json::from_str(&raw).map_err(|error| format!("parse {TARGETS_JSON_BINDING}: {error}"))?;
    if targets.is_empty() {
        return Err(format!("{TARGETS_JSON_BINDING} must not be empty"));
    }
    Ok(targets)
}

fn read_string_binding(env: &Env, binding_name: &str) -> Result<String, String> {
    let value = Reflect::get(env, &JsValue::from_str(binding_name)).map_err(|error| {
        format!("read Cloudflare binding '{binding_name}': {error:?}")
    })?;
    value
        .as_string()
        .ok_or_else(|| format!("Cloudflare binding '{binding_name}' must be a string"))
}
