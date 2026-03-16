use std::convert::TryInto;

use skyzen_cloudflare::CfDurableNamespace;
use skyzen_cloudflare::worker;
use skyzen_services::Db;
use wasm_bindgen::JsValue;

use crate::db;

const SCHEDULER_SINGLETON_NAME: &str = "scheduler";
const SCHEDULER_INTERNAL_URL: &str = "https://scheduler.internal/boost";

/// Log a cache miss. Only logs if the crate name is in the subscriptions table.
///
/// Also sends a boost to the scheduler Durable Object.
pub async fn log_miss(
    db: &Db,
    c_metadata: &str,
    crate_name: &str,
    target: &str,
    city_code: &str,
    scheduler: Option<&CfDurableNamespace>,
) {
    let is_subscribed = match db::is_subscribed_crate(db, crate_name).await {
        Ok(is_subscribed) => is_subscribed,
        Err(error) => {
            tracing::warn!(crate_name, error = %error, "failed to validate subscription");
            return;
        }
    };

    if !is_subscribed {
        tracing::debug!(crate_name, "miss for unknown crate, not logging");
        return;
    }

    if let Err(error) = db::log_cache_miss(db, c_metadata, crate_name, target, city_code).await {
        tracing::warn!(error = %error, "failed to log cache miss to D1");
    }

    if let Some(namespace) = scheduler {
        let boost = stow_types::api::MissBoost {
            crate_name: crate_name.to_owned(),
            target: target.to_owned(),
        };
        if let Err(error) = send_boost(namespace, &boost).await {
            tracing::warn!(error = %error, "failed to notify scheduler DO about miss");
        }
    }
}

async fn send_boost(
    namespace: &CfDurableNamespace,
    boost: &stow_types::api::MissBoost,
) -> Result<(), String> {
    let stub = namespace
        .get_by_name(SCHEDULER_SINGLETON_NAME)
        .map_err(|error| format!("scheduler stub: {error}"))?;
    let body = serde_json::to_vec(boost).map_err(|error| format!("serialize boost: {error}"))?;
    let worker_request = json_post_request(SCHEDULER_INTERNAL_URL, &body)?;
    let request: skyzen_cloudflare::worker_sys::web_sys::Request = (&worker_request)
        .try_into()
        .map_err(|error: worker::Error| format!("convert scheduler request: {error}"))?;
    let response = stub
        .fetch(&request)
        .await
        .map_err(|error| format!("scheduler fetch: {error}"))?;

    if !response.ok() {
        return Err(format!("scheduler boost returned HTTP {}", response.status()));
    }

    Ok(())
}

fn json_post_request(url: &str, body: &[u8]) -> Result<worker::Request, String> {
    let headers = worker::Headers::new();
    headers
        .set("Content-Type", "application/json")
        .map_err(|error| error.to_string())?;

    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post);
    init.with_headers(headers);

    let bytes = js_sys::Uint8Array::from(body);
    init.with_body(Some(JsValue::from(bytes)));

    worker::Request::new_with_init(url, &init).map_err(|error| error.to_string())
}
