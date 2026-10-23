use skyzen::header::{CONTENT_TYPE, HeaderValue};
use skyzen::{Body, Method, Request, Response, Uri};
use skyzen_cloudflare::CfDurableNamespace;

use crate::errors::SchedulerClientError;

const SCHEDULER_SINGLETON_NAME: &str = "scheduler";
const SCHEDULER_SUBMIT_URL: &str = "https://scheduler.internal/tasks/submit";
const SCHEDULER_SUBMIT_TRUSTED_URL: &str = "https://scheduler.internal/tasks/submit/trusted";
const SCHEDULER_SUBMIT_IDS_URL: &str = "https://scheduler.internal/tasks/submit/ids";
const SCHEDULER_COMPLETE_RUN_URL: &str = "https://scheduler.internal/tasks/complete-run";
const SCHEDULER_RUN_UPDATE_URL: &str = "https://scheduler.internal/tasks/run-update";
const SCHEDULER_REQUESTS_URL: &str = "https://scheduler.internal/requests";
const SCHEDULER_STATUS_URL: &str = "https://scheduler.internal/status";
const SCHEDULER_PUBLISHED_INDEX_URL: &str = "https://scheduler.internal/index/published";
const SCHEDULER_FREEZE_URL: &str = "https://scheduler.internal/dispatch-freeze";
const SCHEDULER_ADMIN_STATUS_URL: &str = "https://scheduler.internal/admin/status";
const SCHEDULER_TASKS_URL: &str = "https://scheduler.internal/tasks";
const SCHEDULER_RESET_URL: &str = "https://scheduler.internal/reset";
const SCHEDULER_BUDGET_SEED_URL: &str = "https://scheduler.internal/budget/seed";
const SCHEDULER_BUDGET_URL: &str = "https://scheduler.internal/budget";
const SCHEDULER_BUDGET_LEDGER_URL: &str = "https://scheduler.internal/budget/ledger";
const SCHEDULER_BUDGET_REARM_URL: &str = "https://scheduler.internal/budget/rearm";
const SCHEDULER_DEMAND_URL: &str = "https://scheduler.internal/demand";

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
/// repo-writer credential check. Anonymous callers keep `send_enqueue`.
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

/// The trusted submit-by-id channel: `/tasks/submit/ids` promotes
/// misses by exact task id — the DO rebuilds each subgraph from its
/// node store and reports the ids it does not hold (stow#588).
pub async fn send_task_ids(
    namespace: &CfDurableNamespace,
    request: &stow_types::api::SubmitTaskIdsRequest,
) -> Result<stow_types::api::SubmitTaskIdsResponse, SchedulerClientError> {
    post_json(namespace, SCHEDULER_SUBMIT_IDS_URL, request).await
}

/// The `workflow_run` webhook's completion channel for a
/// `build-crate.yml` run (stow#876): `POST /tasks/complete-run`
/// carries the verified outcome — one forward per task, one task per
/// run.
pub async fn send_run_complete(
    namespace: &CfDurableNamespace,
    report: &stow_types::api::WorkflowRunComplete,
) -> Result<(), SchedulerClientError> {
    send_json(namespace, SCHEDULER_COMPLETE_RUN_URL, report).await
}

/// The `workflow_run` webhook's `in_progress` channel for a
/// `build-crate.yml` run: `POST /tasks/run-update` moves the bound row
/// `dispatched` → `running` (stow#876).
pub async fn send_task_run_update(
    namespace: &CfDurableNamespace,
    update: &stow_types::api::TaskRunUpdate,
) -> Result<(), SchedulerClientError> {
    send_json(namespace, SCHEDULER_RUN_UPDATE_URL, update).await
}

pub async fn get_status(
    namespace: &CfDurableNamespace,
) -> Result<stow_types::api::SchedulerStatus, SchedulerClientError> {
    get_json(namespace, SCHEDULER_STATUS_URL).await
}

/// Admit a human request: the object dedupes on the deterministic
/// request id, probes the human daily budget, dispatches
/// `resolve-request.yml` through the GitHub App, and answers the
/// record's live status.
pub async fn submit_request(
    namespace: &CfDurableNamespace,
    admission: &stow_types::api::RequestAdmission,
) -> Result<stow_types::api::CrateRequestStatus, SchedulerClientError> {
    post_json(namespace, SCHEDULER_REQUESTS_URL, admission).await
}

/// One request record's live status — `None` when the id names no
/// record, so an expired link is an unknown id, not a scheduler
/// failure.
pub async fn get_request(
    namespace: &CfDurableNamespace,
    request_id: &str,
) -> Result<Option<stow_types::api::CrateRequestStatus>, SchedulerClientError> {
    match get_json::<stow_types::api::CrateRequestStatus>(
        namespace,
        &format!("{SCHEDULER_REQUESTS_URL}/{request_id}"),
    )
    .await
    {
        Ok(status) => Ok(Some(status)),
        Err(SchedulerClientError::Http { status: 404, .. }) => Ok(None),
        Err(error) => Err(error),
    }
}

/// The resolve job's outcome report — the caller is trusted (the
/// job's OIDC identity rides the `/api/v1/scheduler` gate), so the
/// report's tasks enqueue verbatim.
pub async fn send_request_outcome(
    namespace: &CfDurableNamespace,
    request_id: &str,
    report: &stow_types::api::RequestOutcomeReport,
) -> Result<stow_types::api::CrateRequestStatus, SchedulerClientError> {
    post_json(
        namespace,
        &format!("{SCHEDULER_REQUESTS_URL}/{request_id}/outcome"),
        report,
    )
    .await
}

/// The `workflow_run` webhook's lifecycle channel for a
/// `resolve-request.yml` run: `in_progress` marks the record
/// `resolving`; `completed` is the failure backstop for a run that
/// never reported an outcome.
pub async fn send_request_run_update(
    namespace: &CfDurableNamespace,
    request_id: &str,
    update: &stow_types::api::RequestRunUpdate,
) -> Result<(), SchedulerClientError> {
    send_json(
        namespace,
        &format!("{SCHEDULER_REQUESTS_URL}/{request_id}/run-update"),
        update,
    )
    .await
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

/// Reset the scheduler store — the operator endpoint behind
/// `POST /api/v1/admin/scheduler/reset`. The only code path that
/// issues DDL on the queue database: it drops every object and
/// re-executes `schema.sql`, destroying the queue.
pub async fn reset_scheduler(
    namespace: &CfDurableNamespace,
) -> Result<stow_types::api::SchedulerResetReport, SchedulerClientError> {
    post_json(namespace, SCHEDULER_RESET_URL, &serde_json::json!({})).await
}

/// The dispatch freeze's current state — flag plus the stored record
/// (trigger, notify outcome) when engaged.
pub async fn get_dispatch_freeze(
    namespace: &CfDurableNamespace,
) -> Result<stow_types::api::DispatchFreeze, SchedulerClientError> {
    get_json(namespace, SCHEDULER_FREEZE_URL).await
}

/// The manual transition that engages or lifts the dispatch freeze; the
/// object answers the state it stored.
pub async fn set_dispatch_freeze(
    namespace: &CfDurableNamespace,
    enabled: bool,
) -> Result<stow_types::api::DispatchFreeze, SchedulerClientError> {
    post_json(
        namespace,
        SCHEDULER_FREEZE_URL,
        &stow_types::api::DispatchFreeze {
            enabled,
            record: None,
            transitions: Vec::new(),
        },
    )
    .await
}

/// The operator view behind `stow-admin status`.
pub async fn admin_status(
    namespace: &CfDurableNamespace,
) -> Result<stow_types::api::AdminStatus, SchedulerClientError> {
    get_json(namespace, SCHEDULER_ADMIN_STATUS_URL).await
}

/// Seed the production-shaped fixture through the Durable Object's probe
/// route — the workerd cost harness's load step. The DO answers only on
/// deploys carrying `STOW_SCHEDULER_BUDGET=1` (the mock stack).
pub async fn seed_budget_fixture(
    namespace: &CfDurableNamespace,
    request: &stow_types::api::SchedulerSeedRequest,
) -> Result<stow_types::api::SchedulerSeedReport, SchedulerClientError> {
    post_json(namespace, SCHEDULER_BUDGET_SEED_URL, request).await
}

/// Run the workerd budget pass: every scheduler route and the alarm
/// measured with the real `rowsRead`/`rowsWritten` cursor counters —
/// the units Cloudflare bills on. `request.dispatch_limit` overrides
/// the deploy's dispatch cap for the pass — the mock's tiny cap would
/// otherwise leave the claim unmeasured.
pub async fn scheduler_budget(
    namespace: &CfDurableNamespace,
    request: &stow_types::api::SchedulerBudgetRequest,
) -> Result<stow_types::api::SchedulerBudgetReport, SchedulerClientError> {
    post_json(namespace, SCHEDULER_BUDGET_URL, request).await
}

/// `POST /budget/rearm` — re-arm the seeded fixture's resolved
/// in-flight batches for the traffic-cost callback lane and answer every
/// armed one (stow#833). The
/// DO answers only on deploys carrying `STOW_SCHEDULER_BUDGET=1`.
pub async fn rearm_budget_fixture(
    namespace: &CfDurableNamespace,
    request: &stow_types::api::SchedulerRearmRequest,
) -> Result<stow_types::api::SchedulerRearmReport, SchedulerClientError> {
    post_json(namespace, SCHEDULER_BUDGET_REARM_URL, request).await
}

/// `GET /budget/ledger` — the probe deploy's per-operation billed rows
/// (stow#773).
pub async fn scheduler_ledger(
    namespace: &CfDurableNamespace,
) -> Result<stow_types::api::SchedulerLedger, SchedulerClientError> {
    get_json(namespace, SCHEDULER_BUDGET_LEDGER_URL).await
}

/// `POST /demand` — apply one durable demand batch (stow#522 I7):
/// each entry's delta lands on every unbuilt queue row its identity
/// names — either compile side — and that row's unbuilt dependency
/// closure, deduplicated per task and keyed on `batch_id` so a replay
/// is a no-op.
pub async fn scheduler_demand(
    namespace: &CfDurableNamespace,
    request: &stow_types::api::SchedulerDemandRequest,
) -> Result<stow_types::api::SchedulerDemandReport, SchedulerClientError> {
    post_json(namespace, SCHEDULER_DEMAND_URL, request).await
}

const SCHEDULER_DEMAND_FEED_BEGIN_URL: &str = "https://scheduler.internal/demand-feed/begin";
const SCHEDULER_DEMAND_FEED_PAGE_URL: &str = "https://scheduler.internal/demand-feed/page";
const SCHEDULER_DEMAND_FEED_COMPLETE_URL: &str = "https://scheduler.internal/demand-feed/complete";
const SCHEDULER_DEMAND_FEED_CLEANUP_URL: &str = "https://scheduler.internal/demand-feed/cleanup";
const SCHEDULER_DEMAND_FEED_DELIVER_URL: &str = "https://scheduler.internal/demand-feed/deliver";
const SCHEDULER_DEMAND_FEED_STATUS_URL: &str = "https://scheduler.internal/demand-feed/status";

/// `POST /demand-feed/begin` — open or rotate the hour's staging
/// attempt (stow#523); a resume answers a fresh generation.
pub async fn demand_feed_begin(
    namespace: &CfDurableNamespace,
    request: &stow_types::api::DemandFeedBeginRequest,
) -> Result<stow_types::api::DemandFeedBeginReport, SchedulerClientError> {
    post_json(namespace, SCHEDULER_DEMAND_FEED_BEGIN_URL, request).await
}

/// `POST /demand-feed/page` — stage one bounded immutable page under
/// the attempt generation.
pub async fn demand_feed_page(
    namespace: &CfDurableNamespace,
    request: &stow_types::api::DemandFeedPageRequest,
) -> Result<(), SchedulerClientError> {
    send_json(namespace, SCHEDULER_DEMAND_FEED_PAGE_URL, request).await
}

/// `POST /demand-feed/complete` — the completion barrier freezing the
/// hour once every page of its generation is staged.
pub async fn demand_feed_complete(
    namespace: &CfDurableNamespace,
    request: &stow_types::api::DemandFeedCompleteRequest,
) -> Result<(), SchedulerClientError> {
    send_json(namespace, SCHEDULER_DEMAND_FEED_COMPLETE_URL, request).await
}

/// `POST /demand-feed/cleanup` — retire one bounded chunk of the
/// hour's dead page rows (obsolete generations, delivered payloads).
pub async fn demand_feed_cleanup(
    namespace: &CfDurableNamespace,
    request: &stow_types::api::DemandFeedCleanupRequest,
) -> Result<stow_types::api::DemandFeedCleanupReport, SchedulerClientError> {
    post_json(namespace, SCHEDULER_DEMAND_FEED_CLEANUP_URL, request).await
}

/// `POST /demand-feed/deliver` — replay the next undelivered original
/// page into the demand ledger, or mark a fully-acked hour delivered.
pub async fn demand_feed_deliver(
    namespace: &CfDurableNamespace,
    request: &stow_types::api::DemandFeedDeliverRequest,
) -> Result<stow_types::api::DemandFeedDeliverReport, SchedulerClientError> {
    post_json(namespace, SCHEDULER_DEMAND_FEED_DELIVER_URL, request).await
}

/// `GET /demand-feed/status` — the durable resume cursor.
pub async fn demand_feed_status(
    namespace: &CfDurableNamespace,
) -> Result<stow_types::api::DemandFeedStatus, SchedulerClientError> {
    get_json(namespace, SCHEDULER_DEMAND_FEED_STATUS_URL).await
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

/// `POST` a JSON body whose response body carries nothing the caller reads —
/// still drained to completion so the socket returns to the in-flight pool
/// rather than stalling in it.
async fn send_json(
    namespace: &CfDurableNamespace,
    url: &str,
    payload: &(impl serde::Serialize + Sync + ?Sized),
) -> Result<(), SchedulerClientError> {
    let response = fetch(namespace, Method::POST, url, Some(payload)).await?;
    response
        .into_body()
        .into_bytes()
        .await
        .map(|_| ())
        .map_err(|error| SchedulerClientError::Decode(error.to_string()))
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
    let response = stub.fetch(request).await.map_err(|error| {
        let message = error.to_string();
        // A "Durable Object is overloaded" rejection is the platform's
        // own shed signal — classified apart so the error response can
        // carry the fault marker the watchdog counts (stow#888).
        if message.contains("overloaded") {
            SchedulerClientError::Overloaded {
                url: url.to_owned(),
                status: None,
                message,
            }
        } else {
            SchedulerClientError::Fetch {
                url: url.to_owned(),
                message,
            }
        }
    })?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response.into_body().into_string().await.map_or_else(
            |error| format!("read scheduler error body: {error}"),
            |body| body.to_string(),
        );
        if body.contains("overloaded") {
            return Err(SchedulerClientError::Overloaded {
                url: url.to_owned(),
                status: Some(status),
                message: body,
            });
        }
        return Err(SchedulerClientError::Http {
            url: url.to_owned(),
            status,
            body,
        });
    }
    Ok(response)
}
