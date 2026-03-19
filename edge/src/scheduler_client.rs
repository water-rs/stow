use std::convert::TryInto;

use skyzen_cloudflare::CfDurableNamespace;
use skyzen_cloudflare::worker;
use wasm_bindgen::JsValue;

const SCHEDULER_SINGLETON_NAME: &str = "scheduler";
const SCHEDULER_ENQUEUE_URL: &str = "https://scheduler.internal/enqueue";
const SCHEDULER_BOOST_URL: &str = "https://scheduler.internal/boost";

pub async fn send_enqueue(
    namespace: &CfDurableNamespace,
    requests: &[stow_types::api::EnqueueRequest],
) -> Result<(), String> {
    if requests.is_empty() {
        return Ok(());
    }
    send_json(namespace, SCHEDULER_ENQUEUE_URL, requests).await
}

pub async fn send_boost(
    namespace: &CfDurableNamespace,
    boost: &stow_types::api::MissBoost,
) -> Result<(), String> {
    send_json(namespace, SCHEDULER_BOOST_URL, boost).await
}

async fn send_json(
    namespace: &CfDurableNamespace,
    url: &str,
    payload: &(impl serde::Serialize + ?Sized),
) -> Result<(), String> {
    let stub = namespace
        .get_by_name(SCHEDULER_SINGLETON_NAME)
        .map_err(|error| format!("scheduler stub: {error}"))?;
    let body =
        serde_json::to_vec(payload).map_err(|error| format!("serialize payload: {error}"))?;
    let worker_request = json_post_request(url, &body)?;
    let request: skyzen_cloudflare::worker_sys::web_sys::Request = (&worker_request)
        .try_into()
        .map_err(|error: worker::Error| format!("convert scheduler request: {error}"))?;
    let response = stub
        .fetch(&request)
        .await
        .map_err(|error| format!("scheduler fetch: {error}"))?;
    if !response.ok() {
        return Err(format!(
            "scheduler request returned HTTP {}",
            response.status()
        ));
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
