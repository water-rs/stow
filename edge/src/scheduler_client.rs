use std::convert::TryInto;

use skyzen_cloudflare::CfDurableNamespace;
use skyzen_cloudflare::worker;
use wasm_bindgen::JsValue;
use worker::send::IntoSendFuture;

const SCHEDULER_SINGLETON_NAME: &str = "scheduler";
const SCHEDULER_SUBMIT_URL: &str = "https://scheduler.internal/tasks/submit";
const SCHEDULER_COMPLETE_URL: &str = "https://scheduler.internal/complete";
const SCHEDULER_STATUS_URL: &str = "https://scheduler.internal/status";

pub async fn send_enqueue(
    namespace: &CfDurableNamespace,
    requests: &[stow_types::api::EnqueueRequest],
) -> Result<(), String> {
    if requests.is_empty() {
        return Ok(());
    }
    send_json(namespace, SCHEDULER_SUBMIT_URL, requests).await
}

pub async fn send_complete(
    namespace: &CfDurableNamespace,
    report: &stow_types::api::BuildCompleteReport,
) -> Result<(), String> {
    send_json(namespace, SCHEDULER_COMPLETE_URL, report).await
}

pub async fn get_status(
    namespace: &CfDurableNamespace,
) -> Result<stow_types::api::SchedulerStatus, String> {
    let stub = namespace
        .get_by_name(SCHEDULER_SINGLETON_NAME)
        .map_err(|error| format!("scheduler stub: {error}"))?;
    let worker_request = request(worker::Method::Get, SCHEDULER_STATUS_URL, None)?;
    let request: skyzen_cloudflare::worker_sys::web_sys::Request = (&worker_request)
        .try_into()
        .map_err(|error: worker::Error| format!("convert scheduler request: {error}"))?;
    let response = stub
        .fetch(&request)
        .await
        .map_err(|error| format!("scheduler fetch {SCHEDULER_STATUS_URL}: {error}"))?;
    if !response.ok() {
        return Err(format!(
            "scheduler request {SCHEDULER_STATUS_URL} returned HTTP {}",
            response.status()
        ));
    }
    let mut response = worker::Response::from(response);
    response
        .json::<stow_types::api::SchedulerStatus>()
        .into_send()
        .await
        .map_err(|error| format!("decode scheduler status response: {error}"))
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
    let worker_request = request(worker::Method::Post, url, Some(&body))?;
    let request: skyzen_cloudflare::worker_sys::web_sys::Request = (&worker_request)
        .try_into()
        .map_err(|error: worker::Error| format!("convert scheduler request: {error}"))?;
    let response = stub
        .fetch(&request)
        .await
        .map_err(|error| format!("scheduler fetch {url}: {error}"))?;
    if !response.ok() {
        let status = response.status();
        let mut response = worker::Response::from(response);
        let body = response
            .text()
            .into_send()
            .await
            .unwrap_or_else(|error| format!("read scheduler error body: {error}"));
        return Err(format!(
            "scheduler request {url} returned HTTP {status}: {body}",
        ));
    }
    Ok(())
}

fn request(
    method: worker::Method,
    url: &str,
    body: Option<&[u8]>,
) -> Result<worker::Request, String> {
    let headers = worker::Headers::new();
    if body.is_some() {
        headers
            .set("Content-Type", "application/json")
            .map_err(|error| error.to_string())?;
    }

    let mut init = worker::RequestInit::new();
    init.with_method(method);
    init.with_headers(headers);
    if let Some(body) = body {
        let bytes = js_sys::Uint8Array::from(body);
        init.with_body(Some(JsValue::from(bytes)));
    }

    worker::Request::new_with_init(url, &init).map_err(|error| error.to_string())
}
