use skyzen::header::{CONTENT_TYPE, HeaderValue};
use skyzen::{Body, Method, Request, Response, Uri};
use skyzen_cloudflare::CfDurableNamespace;

use crate::errors::SchedulerClientError;

const SCHEDULER_SINGLETON_NAME: &str = "scheduler";
const SCHEDULER_SUBMIT_URL: &str = "https://scheduler.internal/tasks/submit";
const SCHEDULER_SUBMIT_TRUSTED_URL: &str = "https://scheduler.internal/tasks/submit/trusted";
const SCHEDULER_TASKS_STATUS_URL: &str = "https://scheduler.internal/tasks/status";
const SCHEDULER_COMPLETE_URL: &str = "https://scheduler.internal/complete";
const SCHEDULER_STATUS_URL: &str = "https://scheduler.internal/status";
const SCHEDULER_STABLE_RUSTC_URL: &str = "https://scheduler.internal/rustc/stable";
const SCHEDULER_PUBLISHED_INDEX_URL: &str = "https://scheduler.internal/index/published";
const SCHEDULER_PANIC_URL: &str = "https://scheduler.internal/panic";
const SCHEDULER_ADMIN_STATUS_URL: &str = "https://scheduler.internal/admin/status";
const SCHEDULER_TASKS_URL: &str = "https://scheduler.internal/tasks";
const SCHEDULER_OBSERVE_RUN_URL: &str = "https://scheduler.internal/tasks/observe-run";

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
) -> Result<u32, SchedulerClientError> {
    #[derive(serde::Deserialize)]
    struct InsertedResponse {
        inserted: u32,
    }
    if requests.is_empty() {
        return Ok(0);
    }
    let response: InsertedResponse =
        post_json(namespace, SCHEDULER_SUBMIT_TRUSTED_URL, requests).await?;
    Ok(response.inserted)
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
    get_json(namespace, SCHEDULER_STATUS_URL).await
}

/// Per-task status for a set of scheduler task ids — drives both the
/// `POST /api/v1/requests` outcome assembly and
/// `GET /api/v1/requests/{task_id}`.
pub async fn get_tasks_status(
    namespace: &CfDurableNamespace,
    task_ids: &[String],
) -> Result<Vec<stow_types::api::RequestStatus>, SchedulerClientError> {
    post_json(namespace, SCHEDULER_TASKS_STATUS_URL, task_ids).await
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

    let parsed = get_json::<StableRustcResponse>(namespace, SCHEDULER_STABLE_RUSTC_URL).await?;
    stow_types::identity::WireRustcVersion::parse(&parsed.version).map_err(|error| {
        SchedulerClientError::Decode(format!(
            "scheduler reported invalid rustc version `{}`: {error}",
            parsed.version
        ))
    })
}

/// The index-publish path's report that a `(target, rustc_version)`
/// slice went live — the semantic identities it serves, which become the
/// membership the scheduler's dependency gate checks.
pub async fn record_published_index(
    namespace: &CfDurableNamespace,
    slice: &stow_types::api::PublishedSlice,
) -> Result<(), SchedulerClientError> {
    send_json(namespace, SCHEDULER_PUBLISHED_INDEX_URL, slice).await
}

/// The anonymous-traffic circuit breaker's current state.
pub async fn get_panic(
    namespace: &CfDurableNamespace,
) -> Result<stow_types::api::PanicSwitch, SchedulerClientError> {
    get_json(namespace, SCHEDULER_PANIC_URL).await
}

/// Flip the circuit breaker; the object answers the value it stored.
pub async fn set_panic(
    namespace: &CfDurableNamespace,
    enabled: bool,
) -> Result<stow_types::api::PanicSwitch, SchedulerClientError> {
    post_json(
        namespace,
        SCHEDULER_PANIC_URL,
        &stow_types::api::PanicSwitch { enabled },
    )
    .await
}

/// The operator view behind `stow-admin status`.
pub async fn admin_status(
    namespace: &CfDurableNamespace,
) -> Result<stow_types::api::AdminStatus, SchedulerClientError> {
    get_json(namespace, SCHEDULER_ADMIN_STATUS_URL).await
}

/// Admin queue listing behind `stow-admin queue list` and the mutation
/// previews; the selector rides the query string flattened
/// (`?task_ids=…&status=&target=&crate=&older_than=&limit=`).
pub async fn list_tasks(
    namespace: &CfDurableNamespace,
    selector: &stow_types::api::QueueSelector,
) -> Result<Vec<stow_types::api::QueueTask>, SchedulerClientError> {
    let query = serde_html_form::to_string(selector)
        .map_err(|error| SchedulerClientError::BuildRequest(error.to_string()))?;
    let url = if query.is_empty() {
        SCHEDULER_TASKS_URL.to_owned()
    } else {
        format!("{SCHEDULER_TASKS_URL}?{query}")
    };
    get_json(namespace, &url).await
}

/// One admin mutation (`retry`, `cancel`, `promote`, `purge`) over a
/// [`QueueSelector`]; returns the affected row count.
pub async fn queue_mutation(
    namespace: &CfDurableNamespace,
    verb: &str,
    selector: &stow_types::api::QueueSelector,
) -> Result<stow_types::api::QueueMutationResult, SchedulerClientError> {
    post_json(
        namespace,
        &format!("{SCHEDULER_TASKS_URL}/{verb}"),
        selector,
    )
    .await
}

/// Stamp a GitHub Actions run id onto an in-flight queue row — called by
/// the register handler when an OIDC-claimed run reports in.
pub async fn observe_run(
    namespace: &CfDurableNamespace,
    task_id: &str,
    github_run_id: &str,
) -> Result<(), SchedulerClientError> {
    send_json(
        namespace,
        SCHEDULER_OBSERVE_RUN_URL,
        &stow_types::api::ObserveRun {
            task_id: task_id.to_owned(),
            github_run_id: github_run_id.to_owned(),
        },
    )
    .await
}

/// `GET` the object and decode its JSON body.
async fn get_json<T: serde::de::DeserializeOwned>(
    namespace: &CfDurableNamespace,
    url: &str,
) -> Result<T, SchedulerClientError> {
    let mut response = fetch(namespace, Method::GET, url, None::<&String>).await?;
    response
        .body_mut()
        .into_json::<T>()
        .await
        .map_err(|error| SchedulerClientError::Decode(error.to_string()))
}

/// `POST` a JSON body to the object and decode its JSON answer.
async fn post_json<T: serde::de::DeserializeOwned>(
    namespace: &CfDurableNamespace,
    url: &str,
    payload: &(impl serde::Serialize + Sync + ?Sized),
) -> Result<T, SchedulerClientError> {
    let mut response = fetch(namespace, Method::POST, url, Some(payload)).await?;
    response
        .body_mut()
        .into_json::<T>()
        .await
        .map_err(|error| SchedulerClientError::Decode(error.to_string()))
}

/// `POST` a JSON body whose response body carries nothing the caller reads.
async fn send_json(
    namespace: &CfDurableNamespace,
    url: &str,
    payload: &(impl serde::Serialize + Sync + ?Sized),
) -> Result<(), SchedulerClientError> {
    fetch(namespace, Method::POST, url, Some(payload))
        .await
        .map(|_| ())
}

/// Resolve the stub, dispatch the request, and gate on a 2xx status — a
/// non-2xx body is read for diagnostics before the [`SchedulerClientError::Http`]
/// goes out.
async fn fetch(
    namespace: &CfDurableNamespace,
    method: Method,
    url: &str,
    payload: Option<&(impl serde::Serialize + Sync + ?Sized)>,
) -> Result<Response, SchedulerClientError> {
    let stub = namespace
        .get_by_name(SCHEDULER_SINGLETON_NAME)
        .map_err(|error| SchedulerClientError::Stub(error.to_string()))?;
    let mut request = Request::new(match payload {
        Some(payload) => Body::from_json(payload)
            .map_err(|error| SchedulerClientError::BuildRequest(error.to_string()))?,
        None => Body::empty(),
    });
    *request.method_mut() = method;
    *request.uri_mut() = url
        .parse::<Uri>()
        .map_err(|error| SchedulerClientError::BuildRequest(error.to_string()))?;
    if payload.is_some() {
        request
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
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
    Ok(response)
}
