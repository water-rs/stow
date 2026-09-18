use skyzen::header::{CONTENT_TYPE, HeaderValue};
use skyzen::{Body, Method, Request, Uri};
use skyzen_cloudflare::CfDurableNamespace;

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
    let mut response = stub
        .fetch_url(SCHEDULER_STATUS_URL)
        .await
        .map_err(|error| SchedulerClientError::Fetch {
            url: SCHEDULER_STATUS_URL.to_owned(),
            message: error.to_string(),
        })?;
    if !response.status().is_success() {
        return Err(SchedulerClientError::Http {
            url: SCHEDULER_STATUS_URL.to_owned(),
            status: response.status().as_u16(),
            body: String::new(),
        });
    }
    response
        .body_mut()
        .into_json::<stow_types::api::SchedulerStatus>()
        .await
        .map_err(|error| SchedulerClientError::Decode(error.to_string()))
}

async fn send_json(
    namespace: &CfDurableNamespace,
    url: &str,
    payload: &(impl serde::Serialize + Sync + ?Sized),
) -> Result<(), SchedulerClientError> {
    let stub = namespace
        .get_by_name(SCHEDULER_SINGLETON_NAME)
        .map_err(|error| SchedulerClientError::Stub(error.to_string()))?;
    let mut request = Request::new(
        Body::from_json(payload)
            .map_err(|error| SchedulerClientError::BuildRequest(error.to_string()))?,
    );
    *request.method_mut() = Method::POST;
    *request.uri_mut() = url
        .parse::<Uri>()
        .map_err(|error| SchedulerClientError::BuildRequest(error.to_string()))?;
    request
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let response = stub
        .fetch(request)
        .await
        .map_err(|error| SchedulerClientError::Fetch {
            url: url.to_owned(),
            message: error.to_string(),
        })?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response.into_body().into_string().await.map_or_else(
            |error| format!("read scheduler error body: {error}"),
            |body| body.to_string(),
        );
        return Err(SchedulerClientError::Http {
            url: url.to_owned(),
            status,
            body,
        });
    }
    Ok(())
}
