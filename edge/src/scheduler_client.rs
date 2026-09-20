use skyzen::header::{CONTENT_TYPE, HeaderValue};
use skyzen::{Body, Method, Request, Uri};
use skyzen_cloudflare::CfDurableNamespace;

use crate::errors::SchedulerClientError;

const SCHEDULER_SINGLETON_NAME: &str = "scheduler";
const SCHEDULER_SUBMIT_URL: &str = "https://scheduler.internal/tasks/submit";
const SCHEDULER_SUBMIT_TRUSTED_URL: &str = "https://scheduler.internal/tasks/submit/trusted";
const SCHEDULER_TASKS_STATUS_URL: &str = "https://scheduler.internal/tasks/status";
const SCHEDULER_COMPLETE_URL: &str = "https://scheduler.internal/complete";
const SCHEDULER_STATUS_URL: &str = "https://scheduler.internal/status";
const SCHEDULER_STABLE_RUSTC_URL: &str = "https://scheduler.internal/rustc/stable";

pub async fn send_enqueue(
    namespace: &CfDurableNamespace,
    requests: &[stow_types::api::EnqueueRequest],
) -> Result<(), SchedulerClientError> {
    if requests.is_empty() {
        return Ok(());
    }
    send_json(namespace, SCHEDULER_SUBMIT_URL, requests).await
}

/// The trusted submit channel: `/tasks/submit/trusted` skips the
/// pending-depth cap because every caller arrives through the edge's
/// `RepoWriter` credential check. Anonymous callers keep `send_enqueue`.
pub async fn send_enqueue_trusted(
    namespace: &CfDurableNamespace,
    requests: &[stow_types::api::EnqueueRequest],
) -> Result<(), SchedulerClientError> {
    if requests.is_empty() {
        return Ok(());
    }
    send_json(namespace, SCHEDULER_SUBMIT_TRUSTED_URL, requests).await
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

/// Per-task status for a set of scheduler task ids — drives both the
/// `POST /api/v1/requests` outcome assembly and
/// `GET /api/v1/requests/{task_id}`.
pub async fn get_tasks_status(
    namespace: &CfDurableNamespace,
    task_ids: &[String],
) -> Result<Vec<stow_types::api::RequestStatus>, SchedulerClientError> {
    let stub = namespace
        .get_by_name(SCHEDULER_SINGLETON_NAME)
        .map_err(|error| SchedulerClientError::Stub(error.to_string()))?;
    let mut request = Request::new(
        Body::from_json(task_ids)
            .map_err(|error| SchedulerClientError::BuildRequest(error.to_string()))?,
    );
    *request.method_mut() = Method::POST;
    *request.uri_mut() = SCHEDULER_TASKS_STATUS_URL
        .parse::<Uri>()
        .map_err(|error| SchedulerClientError::BuildRequest(error.to_string()))?;
    request
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let mut response = stub
        .fetch(request)
        .await
        .map_err(|error| SchedulerClientError::Fetch {
            url: SCHEDULER_TASKS_STATUS_URL.to_owned(),
            message: error.to_string(),
        })?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response.into_body().into_string().await.map_or_else(
            |error| format!("read scheduler error body: {error}"),
            |body| body.to_string(),
        );
        return Err(SchedulerClientError::Http {
            url: SCHEDULER_TASKS_STATUS_URL.to_owned(),
            status,
            body,
        });
    }
    response
        .body_mut()
        .into_json::<Vec<stow_types::api::RequestStatus>>()
        .await
        .map_err(|error| SchedulerClientError::Decode(error.to_string()))
}

/// The stable rustc version the human lane builds against, resolved (and
/// cached) inside the scheduler Durable Object.
pub async fn get_stable_rustc(
    namespace: &CfDurableNamespace,
) -> Result<stow_types::identity::WireRustcVersion, SchedulerClientError> {
    #[derive(serde::Deserialize)]
    struct StableRustcResponse {
        version: String,
    }

    let stub = namespace
        .get_by_name(SCHEDULER_SINGLETON_NAME)
        .map_err(|error| SchedulerClientError::Stub(error.to_string()))?;
    let mut response = stub
        .fetch_url(SCHEDULER_STABLE_RUSTC_URL)
        .await
        .map_err(|error| SchedulerClientError::Fetch {
            url: SCHEDULER_STABLE_RUSTC_URL.to_owned(),
            message: error.to_string(),
        })?;
    if !response.status().is_success() {
        return Err(SchedulerClientError::Http {
            url: SCHEDULER_STABLE_RUSTC_URL.to_owned(),
            status: response.status().as_u16(),
            body: String::new(),
        });
    }
    let parsed = response
        .body_mut()
        .into_json::<StableRustcResponse>()
        .await
        .map_err(|error| SchedulerClientError::Decode(error.to_string()))?;
    stow_types::identity::WireRustcVersion::parse(&parsed.version).map_err(|error| {
        SchedulerClientError::Decode(format!(
            "scheduler reported invalid rustc version `{}`: {error}",
            parsed.version
        ))
    })
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
