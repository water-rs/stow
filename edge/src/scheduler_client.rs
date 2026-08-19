use std::convert::TryInto;

use skyzen_cloudflare::CfDurableNamespace;
use skyzen_cloudflare::worker;
use worker::send::IntoSendFuture;

use crate::cf_http;
use crate::errors::SchedulerClientError;

const SCHEDULER_SINGLETON_NAME: &str = "scheduler";
const SCHEDULER_SUBMIT_URL: &str = "https://scheduler.internal/tasks/submit";
const SCHEDULER_COMPLETE_URL: &str = "https://scheduler.internal/complete";
const SCHEDULER_STATUS_URL: &str = "https://scheduler.internal/status";

pub async fn send_enqueue(
    namespace: &CfDurableNamespace,
    requests: &[stow_types::api::EnqueueRequest],
) -> Result<(), SchedulerClientError> {
    if requests.is_empty() {
        return Ok(());
    }
    send_json(namespace, SCHEDULER_SUBMIT_URL, requests).await
}

pub async fn send_complete(
    namespace: &CfDurableNamespace,
    report: &stow_types::api::BuildCompleteReport,
) -> Result<(), SchedulerClientError> {
    send_json(namespace, SCHEDULER_COMPLETE_URL, report).await
}

pub async fn get_status(
    namespace: &CfDurableNamespace,
) -> Result<stow_types::api::SchedulerStatus, SchedulerClientError> {
    let stub = namespace
        .get_by_name(SCHEDULER_SINGLETON_NAME)
        .map_err(|error| SchedulerClientError::Stub(error.to_string()))?;
    let worker_request = cf_http::bare_request(worker::Method::Get, SCHEDULER_STATUS_URL, &[], None)
        .map_err(|error| SchedulerClientError::BuildRequest(error.to_string()))?;
    let request: skyzen_cloudflare::worker_sys::web_sys::Request = (&worker_request)
        .try_into()
        .map_err(|error: worker::Error| SchedulerClientError::BuildRequest(error.to_string()))?;
    let response = stub
        .fetch(&request)
        .await
        .map_err(|error| SchedulerClientError::Fetch {
            url: SCHEDULER_STATUS_URL.to_owned(),
            message: error.to_string(),
        })?;
    if !response.ok() {
        return Err(SchedulerClientError::Http {
            url: SCHEDULER_STATUS_URL.to_owned(),
            status: response.status(),
            body: String::new(),
        });
    }
    let mut response = worker::Response::from(response);
    response
        .json::<stow_types::api::SchedulerStatus>()
        .into_send()
        .await
        .map_err(|error| SchedulerClientError::Decode(error.to_string()))
}

async fn send_json(
    namespace: &CfDurableNamespace,
    url: &str,
    payload: &(impl serde::Serialize + ?Sized),
) -> Result<(), SchedulerClientError> {
    let stub = namespace
        .get_by_name(SCHEDULER_SINGLETON_NAME)
        .map_err(|error| SchedulerClientError::Stub(error.to_string()))?;
    let worker_request = cf_http::json_request(worker::Method::Post, url, payload, &[])
        .map_err(|error| SchedulerClientError::BuildRequest(error.to_string()))?;
    let request: skyzen_cloudflare::worker_sys::web_sys::Request = (&worker_request)
        .try_into()
        .map_err(|error: worker::Error| SchedulerClientError::BuildRequest(error.to_string()))?;
    let response = stub
        .fetch(&request)
        .await
        .map_err(|error| SchedulerClientError::Fetch {
            url: url.to_owned(),
            message: error.to_string(),
        })?;
    if !response.ok() {
        let status = response.status();
        let mut response = worker::Response::from(response);
        let body = response
            .text()
            .into_send()
            .await
            .unwrap_or_else(|error| format!("read scheduler error body: {error}"));
        return Err(SchedulerClientError::Http {
            url: url.to_owned(),
            status,
            body,
        });
    }
    Ok(())
}
