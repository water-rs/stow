//! `POST /api/v1/github/workflow-run` — GitHub's `workflow_run` webhook.
//!
//! Completion reaches the scheduler here instead of from CI (stow#455):
//! `build-crate.yml` sets `run-name` to `<rustc>-<task_id>`, GitHub
//! delivers the run's `completed` event signed `sha256=<HMAC-SHA256>` with
//! `X-Hub-Signature-256` over the raw body under the
//! `STOW_GITHUB_WEBHOOK_SECRET` binding, and this route parses
//! `display_title` back into its rustc and task id, verifies the run's
//! signed records artifact in GHCR, and forwards the settled outcome
//! to the scheduler — one task, one run (stow#876).
//!
//! The route carries no caller-credential gate: the HMAC signature is the
//! authentication. Shed control lives in the zone WAF maintenance rules
//! (`admin/src/maintenance.rs`): the `lanes` scope covers only the
//! scheduler-lane paths, so a partial reopen keeps draining completions,
//! and the `anonymous` scope carves `/api/v1/github` out alongside the
//! trusted prefixes for the same reason. Only `all` blocks the route —
//! the whole site is down then, and a delivery sent during the outage is
//! lost: GitHub never redelivers on its own, and stale-dispatch recovery
//! reclaims the row a lost completion left behind.

use std::future::Future;

#[cfg(target_arch = "wasm32")]
use crate::api::OkResponse;
use crate::errors::{GetArtifactError, SchedulerClientError};
#[cfg(target_arch = "wasm32")]
use crate::scheduler_client;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use skyzen::Request;
use skyzen::extract::Extractor;
#[cfg(target_arch = "wasm32")]
use skyzen::utils::Json;
use skyzen::utils::State;
#[cfg(target_arch = "wasm32")]
use skyzen_cloudflare::CfDurableNamespace;
#[cfg(target_arch = "wasm32")]
use skyzen_cloudflare::worker::send::IntoSendFuture as _;
use stow_types::api::{TaskRunUpdate, WorkflowRunComplete};
use stow_types::records::parse_run_title;

type HmacSha256 = Hmac<Sha256>;

/// The `STOW_GITHUB_WEBHOOK_SECRET` binding, stored via `State`.
#[derive(Debug, Clone)]
pub struct WebhookSecret(pub String);

/// The `GITHUB_APP_SLUG` binding rendered into the
/// `triggering_actor.login` a scheduler-dispatched run carries —
/// `<slug>[bot]`. A `build-crate.yml` `in_progress` delivery whose run
/// carries it forwards nothing: the CI listing's reconcile reports own
/// runs' running state instead (stow#940). Required at worker startup
/// in every deployment — the mock stack sets it to the slug the local
/// CI stamps.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[derive(Debug, Clone)]
pub struct AppBotLogin(pub String);

/// The webhook's signing headers and the raw body they cover, pulled off
/// the request by [`SignedDelivery`]'s extractor.
struct SignedDelivery {
    /// The `X-GitHub-Event` value — only `workflow_run` events are
    /// consumed.
    event: String,
    /// The `X-Hub-Signature-256` header (`sha256=<hex>`).
    signature: String,
    /// The exact body bytes the signature covers — never the
    /// deserialized JSON, whose re-serialization GitHub does not promise
    /// is byte-identical.
    body: Vec<u8>,
}

impl Extractor for SignedDelivery {
    type Error = GetArtifactError;

    async fn extract(request: &mut Request) -> Result<Self, Self::Error> {
        let header = |name: &str| -> Result<String, GetArtifactError> {
            request
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
                .ok_or_else(|| {
                    GetArtifactError::BadRequestWithMessage(format!(
                        "missing required `{name}` header"
                    ))
                })
        };
        let event = header("X-GitHub-Event")?;
        let signature = header("X-Hub-Signature-256")?;
        let body = skyzen_core::take_body_bytes::<Self>(request)
            .await
            .map_err(|error| {
                GetArtifactError::BadRequestWithMessage(format!("read webhook body: {error}"))
            })?
            .to_vec();
        Ok(Self {
            event,
            signature,
            body,
        })
    }
}

/// A delivery after its HMAC signature verified — the raw event name and
/// body, undecoded. Verification runs before any payload inspection:
/// GitHub's `ping` and the `workflow_run` subscription's
/// `requested`/`in_progress` deliveries all reach the handler, which
/// answers 200 to everything it does not consume.
#[derive(Debug)]
pub struct VerifiedDelivery {
    /// `X-GitHub-Event`.
    event: String,
    /// The exact body bytes the signature covered.
    body: Vec<u8>,
}

impl Extractor for VerifiedDelivery {
    type Error = GetArtifactError;

    async fn extract(request: &mut Request) -> Result<Self, Self::Error> {
        let delivery = SignedDelivery::extract(request).await?;
        let State(secret) = State::<WebhookSecret>::extract(request)
            .await
            .map_err(|error| {
                GetArtifactError::InternalWithMessage(format!(
                    "webhook secret binding missing: {error}"
                ))
            })?;
        verify_signature(&secret.0, &delivery.signature, &delivery.body)?;
        Ok(Self {
            event: delivery.event,
            body: delivery.body,
        })
    }
}

/// The `workflow_run` object fields this route reads — GitHub sends the
/// full run document; the rest is ignored.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[derive(Debug, serde::Deserialize)]
struct WorkflowRunFields {
    /// `run-name` — the title the trusted workflow stamps.
    display_title: String,
    /// What dispatched the run — must be `workflow_dispatch`.
    event: String,
    head_branch: String,
    path: String,
    /// Read by the task forward's report and the request run update.
    conclusion: Option<String>,
    id: u64,
    /// `run_attempt` — GitHub's attempt number for the run, a positive
    /// integer. Read by the task forward's report.
    run_attempt: std::num::NonZeroU32,
    /// Read by the task forward's report and the request run update.
    html_url: Option<String>,
    /// The repo the head commit lives in — a fork's run names its fork.
    head_repository: RepoRef,
    /// `triggering_actor` — whose dispatch started the run: the App's
    /// `<slug>[bot]` login on a scheduler dispatch, an operator's login
    /// on one dispatched by hand (stow#940). A delivery without it
    /// fails the parse — GitHub always sends it.
    triggering_actor: RunActor,
}

/// `triggering_actor` — only `login` is read.
#[derive(Debug, serde::Deserialize)]
struct RunActor {
    login: String,
}

/// `full_name` (`owner/name`) of a repo the payload carries.
#[derive(Debug, serde::Deserialize)]
struct RepoRef {
    full_name: String,
}

#[derive(Debug, serde::Deserialize)]
struct WorkflowRunEvent {
    /// The repo the workflow belongs to — the trusted repo.
    repository: RepoRef,
    workflow_run: WorkflowRunFields,
}

/// The delivery's `action` alone — non-`completed` deliveries are
/// ignored without requiring the completed event's shape.
#[derive(serde::Deserialize)]
struct ActionOnly {
    action: String,
}

/// Decode a signed delivery into the `workflow_run` event plus its
/// action. `None` covers everything this hook does not consume —
/// non-`workflow_run` events (`ping`) answer 200 so GitHub's delivery
/// log stays clean; the action is returned for the caller to gate per
/// workflow (a build run is consumed on `completed`, a resolve run on
/// `in_progress` and `completed`). `Err` is a 400: the signature was
/// fine but the payload is not the shape GitHub documented.
fn decode_delivery(
    delivery: &VerifiedDelivery,
) -> Result<Option<(String, WorkflowRunEvent)>, GetArtifactError> {
    if delivery.event != "workflow_run" {
        return Ok(None);
    }
    let ActionOnly { action } = serde_json::from_slice(&delivery.body).map_err(|error| {
        GetArtifactError::BadRequestWithMessage(format!("malformed workflow_run payload: {error}"))
    })?;
    // The two lifecycle actions any trusted workflow consumes: a build
    // run reports on `completed`, a resolve run on `in_progress` and
    // `completed`. `requested`/`queued`/`waiting` deliveries carry the
    // run but nothing to apply — answer 200 without parsing further.
    if action != "in_progress" && action != "completed" {
        return Ok(None);
    }
    let event: WorkflowRunEvent = serde_json::from_slice(&delivery.body).map_err(|error| {
        GetArtifactError::BadRequestWithMessage(format!("malformed workflow_run payload: {error}"))
    })?;
    Ok(Some((action, event)))
}

/// The subject a pinned run's `run-name` decodes to — each trusted
/// workflow stamps its own shape.
#[derive(Debug)]
enum RunSubject<'a> {
    /// `build-crate.yml`'s `<rustc>-<task_id>` — a build task's own
    /// run (stow#876).
    Task {
        /// The rustc the task built under.
        rustc_version: &'a str,
        /// The task the run reports on.
        task_id: &'a str,
    },
    /// `resolve-request.yml`'s `resolve-a<attempt>-<request_id>` — the
    /// human request record's lifecycle signal (stow#428).
    Request {
        /// The record's dispatch epoch the run served.
        attempt: u32,
        /// The request record the run served.
        request_id: &'a str,
    },
}

/// The authority boundary a run event must sit inside — a fork or a
/// feature-branch run's signature still verifies, so the run's own
/// fields are what make it ours: a trusted workflow's file
/// (`build-crate.yml` or `resolve-request.yml`), on `main`, dispatched
/// by `workflow_dispatch`, in the trusted repository (its head repo
/// equal to the event repo, so a fork's delivery cannot pose as
/// upstream's).
///
/// Returns the run with its title decoded into its [`RunSubject`]. A
/// pinned run whose title does not parse is a 400 — the workflow stamps
/// every run-name itself, so a shapeless title can only mean a
/// hand-edited dispatch.
fn authorized_run(
    event: &WorkflowRunEvent,
) -> Result<Option<(&WorkflowRunFields, RunSubject<'_>)>, GetArtifactError> {
    let run = &event.workflow_run;
    let pinned = run.head_branch == stow_types::trusted_builder::BRANCH
        && run.event == "workflow_dispatch"
        && run.head_repository.full_name == event.repository.full_name
        && event.repository.full_name == stow_types::trusted_builder::REPOSITORY;
    if !pinned {
        return Ok(None);
    }
    let subject = match run.path.strip_prefix(".github/workflows/") {
        Some(stow_types::trusted_builder::WORKFLOW_FILE) => {
            let Some((rustc_version, task_id)) = parse_run_title(&run.display_title) else {
                return Err(GetArtifactError::BadRequestWithMessage(format!(
                    "run {}'s display_title {:?} is not <rustc>-<task_id>",
                    run.id, run.display_title
                )));
            };
            RunSubject::Task {
                rustc_version,
                task_id,
            }
        }
        Some(stow_types::trusted_builder::RESOLVE_WORKFLOW_FILE) => {
            let Some((attempt, request_id)) =
                stow_types::records::parse_resolve_run_title(&run.display_title)
            else {
                return Err(GetArtifactError::BadRequestWithMessage(format!(
                    "run {}'s display_title {:?} is not resolve-a<attempt>-<request_id>",
                    run.id, run.display_title
                )));
            };
            RunSubject::Request {
                attempt,
                request_id,
            }
        }
        // Any other workflow in the trusted repo.
        _ => return Ok(None),
    };
    Ok(Some((run, subject)))
}

/// Constant-time check of `sha256=<hex>` against the HMAC of `body` under
/// `secret`. `Mac::verify_slice` is the constant-time compare; a
/// malformed or wrong-length signature fails the same way rather than
/// short-circuiting on shape.
fn verify_signature(secret: &str, signature: &str, body: &[u8]) -> Result<(), GetArtifactError> {
    let Some(hex_signature) = signature.strip_prefix("sha256=") else {
        return Err(GetArtifactError::Unauthorized);
    };
    let expected = hex::decode(hex_signature).map_err(|_| GetArtifactError::Unauthorized)?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
    mac.update(body);
    mac.verify_slice(&expected)
        .map_err(|_| GetArtifactError::Unauthorized)
}

/// `POST /api/v1/github/workflow-run`.
///
/// Everything this hook does not consume answers 200 — a `ping`, a
/// `requested` action, a resolve run's non-lifecycle action, and a run
/// outside the authority boundary are deliveries, not failures. Consumed
/// events always answer 200 too: the scheduler's 404/409 answers mean the
/// event names nothing live, so they are logged, not propagated. Only a
/// malformed payload (400), a bad signature (401), and an upstream failure
/// (500) leave the 2xx path. GitHub never redelivers a failed delivery on
/// its own, so a 500 loses the event; for a completion the stale
/// check repairs the loss.
#[cfg(target_arch = "wasm32")]
pub async fn github_workflow_run(
    delivery: VerifiedDelivery,
    State(ghcr): State<crate::api::GhcrConfig>,
    State(scheduler): State<CfDurableNamespace>,
    State(app_bot_login): State<AppBotLogin>,
) -> Result<Json<OkResponse>, GetArtifactError> {
    consume_delivery(&delivery, &ghcr, &scheduler, &app_bot_login.0).await?;
    Ok(Json(OkResponse { ok: true }))
}

/// The route's whole decision for one verified delivery: what it
/// checks and which scheduler requests it forwards. Host-compiled over
/// the outbound seams so the tests drive every `workflow_run` action
/// through it and count the forwards against `stow_types::forwards` —
/// the counts the traffic projection prices (stow#937).
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
async fn consume_delivery(
    delivery: &VerifiedDelivery,
    records: &impl RecordsCheck,
    forward: &(impl TaskRunForward + RequestRunForward),
    app_bot_login: &str,
) -> Result<(), GetArtifactError> {
    let Some((action, event)) = decode_delivery(delivery)? else {
        tracing::debug!(event = %delivery.event, "ignoring non-workflow_run delivery");
        return Ok(());
    };
    let Some((run, subject)) = authorized_run(&event)? else {
        tracing::debug!("ignoring workflow_run outside the authority boundary");
        return Ok(());
    };
    match subject {
        // A build run's `completed` forwards for every run — the
        // slot-freeing channel the scheduler cannot learn elsewhere;
        // its `in_progress` only for a run the scheduler did not
        // dispatch (stow#940): own runs' running state comes from the
        // CI listing's reconcile, so their deliveries would only spend
        // a DO request each.
        RunSubject::Task {
            rustc_version,
            task_id,
        } if action == "completed" => {
            complete_build_task(records, forward, run, rustc_version, task_id).await?;
        }
        RunSubject::Task { task_id, .. } if action == "in_progress" => {
            update_external_task_run(forward, app_bot_login, run, task_id).await?;
        }
        RunSubject::Request {
            attempt,
            request_id,
        } if action == "in_progress" || action == "completed" => {
            update_request_run(forward, run, &action, attempt, request_id).await?;
        }
        // A build run's `requested`/`waiting` and a resolve run's
        // `requested`/`waiting`: neither event carries anything to
        // apply — the task's lifecycle the scheduler reads starts at
        // `in_progress` (dispatched → running) and `completed`.
        _ => {}
    }
    Ok(())
}

/// The check a build run's `completed` makes before it forwards: the
/// run's signed records artifact is in GHCR. `GhcrConfig` carries it on
/// wasm; tests stub it.
trait RecordsCheck: Sync {
    /// A registry fetch that failed — transient, so the delivery
    /// answers 500 for GitHub to retry.
    type Error: std::fmt::Display;

    /// Whether GHCR holds the records artifact this `build` of the task
    /// published — the tag names the run, so the check matches the
    /// artifact this run pushed and no other build's.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    fn records_artifact_exists<'a>(
        &'a self,
        rustc_version: &'a str,
        task_id: &'a str,
        build: stow_types::records::BuildRun,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send + 'a;
}

#[cfg(target_arch = "wasm32")]
impl RecordsCheck for crate::api::GhcrConfig {
    type Error = crate::ghcr::FetchError;

    fn records_artifact_exists<'a>(
        &'a self,
        rustc_version: &'a str,
        task_id: &'a str,
        build: stow_types::records::BuildRun,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send + 'a {
        async move {
            crate::ghcr::records_artifact_exists(
                self,
                rustc_version,
                task_id,
                build,
                &crate::fetch_guard::OutboundPool::new(),
            )
            .await
        }
        .into_send()
    }
}

/// The outbound channel a `build-crate.yml` delivery uses: the
/// forwards to the object's `POST /tasks/complete-run` and
/// `/tasks/run-update`. `CfDurableNamespace` carries it on wasm; tests
/// stub it to count what the handler sends.
trait TaskRunForward: Sync {
    /// Forward `report` to `POST /tasks/complete-run`.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    fn send_run_complete<'a>(
        &'a self,
        report: &'a WorkflowRunComplete,
    ) -> impl Future<Output = Result<(), SchedulerClientError>> + Send + 'a;

    /// Forward `update` to `POST /tasks/run-update`.
    fn send_task_run_update<'a>(
        &'a self,
        update: &'a TaskRunUpdate,
    ) -> impl Future<Output = Result<(), SchedulerClientError>> + Send + 'a;
}

#[cfg(target_arch = "wasm32")]
impl TaskRunForward for CfDurableNamespace {
    fn send_run_complete<'a>(
        &'a self,
        report: &'a WorkflowRunComplete,
    ) -> impl Future<Output = Result<(), SchedulerClientError>> + Send + 'a {
        scheduler_client::send_run_complete(self, report).into_send()
    }

    fn send_task_run_update<'a>(
        &'a self,
        update: &'a TaskRunUpdate,
    ) -> impl Future<Output = Result<(), SchedulerClientError>> + Send + 'a {
        scheduler_client::send_task_run_update(self, update).into_send()
    }
}

/// The outbound channel a `resolve-request.yml` delivery uses: the
/// forward to the object's `POST /requests/{id}/run-update`.
/// `CfDurableNamespace` carries it on wasm; tests stub it to count
/// what the handler sends.
trait RequestRunForward: Sync {
    /// Forward `update` to `POST /requests/{id}/run-update`.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    fn send_request_run_update<'a>(
        &'a self,
        request_id: &'a str,
        update: &'a stow_types::api::RequestRunUpdate,
    ) -> impl Future<Output = Result<(), SchedulerClientError>> + Send + 'a;
}

#[cfg(target_arch = "wasm32")]
impl RequestRunForward for CfDurableNamespace {
    fn send_request_run_update<'a>(
        &'a self,
        request_id: &'a str,
        update: &'a stow_types::api::RequestRunUpdate,
    ) -> impl Future<Output = Result<(), SchedulerClientError>> + Send + 'a {
        scheduler_client::send_request_run_update(self, request_id, update).into_send()
    }
}

/// `build-crate.yml` `in_progress` — `POST /tasks/run-update` serves
/// external runs only (stow#940): a run the scheduler dispatched
/// carries the App's bot login and its running state arrives through
/// the CI listing's reconcile instead, so the delivery is consumed
/// without a forward.
async fn update_external_task_run(
    forward: &impl TaskRunForward,
    app_bot_login: &str,
    run: &WorkflowRunFields,
    task_id: &str,
) -> Result<(), GetArtifactError> {
    if run.triggering_actor.login == app_bot_login {
        tracing::debug!(
            task_id,
            run_id = run.id,
            "own run's in_progress — the CI listing's reconcile reports it"
        );
        return Ok(());
    }
    update_task_run(forward, run, task_id).await
}

/// `build-crate.yml` `in_progress` of a run the scheduler did not
/// dispatch — the external run's occupancy record lands through
/// `POST /tasks/run-update` (stow#940). An unknown task or a run the
/// row is not bound to is a stale generation's event — the object's
/// 404/409 is logged, never an error back to GitHub.
async fn update_task_run(
    forward: &impl TaskRunForward,
    run: &WorkflowRunFields,
    task_id: &str,
) -> Result<(), GetArtifactError> {
    let update = TaskRunUpdate {
        task_id: task_id.to_owned(),
        github_run_id: run.id.to_string(),
    };
    match forward.send_task_run_update(&update).await {
        Ok(()) => {
            tracing::info!(task_id, run_id = run.id, "task run in_progress applied");
        }
        Err(SchedulerClientError::Http {
            status: 404 | 409,
            body,
            ..
        }) => {
            tracing::warn!(task_id, %body, "task run update named no live binding");
        }
        Err(other) => {
            return Err(GetArtifactError::from(other)).inspect_err(|error| {
                tracing::error!(task_id, %error, "forward task run update");
            });
        }
    }
    Ok(())
}

/// `build-crate.yml` `completed` — verify the run's records artifact
/// in GHCR, then forward the settled outcome to
/// `POST /tasks/complete-run` (stow#876). An unknown task is an orphan
/// run from an abandoned dispatch — the object's 404 is logged, never
/// an error back to GitHub.
async fn complete_build_task(
    records: &impl RecordsCheck,
    forward: &impl TaskRunForward,
    run: &WorkflowRunFields,
    rustc_version: &str,
    task_id: &str,
) -> Result<(), GetArtifactError> {
    let mut success = run.conclusion.as_deref() == Some("success");
    let mut error = None;
    if success {
        let build = stow_types::records::BuildRun {
            run_id: run.id,
            run_attempt: run.run_attempt.get(),
        };
        match records
            .records_artifact_exists(rustc_version, task_id, build)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                success = false;
                error = Some(format!(
                    "GitHub reports success but the records artifact for task {task_id} is not in GHCR"
                ));
                tracing::error!(task_id, "successful run produced no records artifact");
            }
            Err(fetch_error) => {
                // A registry hiccup is transient: answer 500 so GitHub's
                // redelivery retries the completion instead of dropping it.
                tracing::warn!(task_id, %fetch_error, "records artifact check failed");
                return Err(GetArtifactError::InternalWithMessage(format!(
                    "verify records artifact for {task_id}: {fetch_error}"
                )));
            }
        }
    } else {
        error = Some(format!(
            "workflow run concluded `{}`{}",
            run.conclusion.as_deref().unwrap_or("<none>"),
            run.html_url
                .as_deref()
                .map(|url| format!(" ({url})"))
                .unwrap_or_default()
        ));
    }

    forward_run_complete(forward, run, task_id, success, error).await
}

/// Forward the settled outcome to `POST /tasks/complete-run` — every
/// `completed` delivery forwards, whether the run was dispatched by
/// the scheduler or not: the delivery is what frees the slot or the
/// external run's occupancy (stow#940). An unknown task is an orphan
/// run from an abandoned dispatch — the object's 404 is logged, never
/// an error back to GitHub.
async fn forward_run_complete(
    forward: &impl TaskRunForward,
    run: &WorkflowRunFields,
    task_id: &str,
    success: bool,
    error: Option<String>,
) -> Result<(), GetArtifactError> {
    let completion = WorkflowRunComplete {
        task_id: task_id.to_owned(),
        success,
        error,
        // A `cancelled` conclusion is the concurrency group's verdict on a
        // superseded duplicate — the scheduler re-queues the task instead
        // of recording a failure (stow#877).
        cancelled: run.conclusion.as_deref() == Some("cancelled"),
        github_run_id: run.id.to_string(),
    };
    match forward.send_run_complete(&completion).await {
        Ok(()) => {
            tracing::info!(task_id, success, "workflow_run completion applied");
        }
        // The queue's 404/409 mean the task is not live for this event —
        // consumed, never an error back to GitHub.
        Err(SchedulerClientError::Http {
            status: 404 | 409,
            body,
            ..
        }) => {
            tracing::warn!(task_id, %body, "workflow_run completion did not match a live task");
        }
        Err(other) => {
            return Err(GetArtifactError::from(other)).inspect_err(|error| {
                tracing::error!(task_id, %error, "forward workflow_run completion");
            });
        }
    }
    Ok(())
}

/// `resolve-request.yml` `in_progress`/`completed` — the request
/// record's lifecycle channel (`accepted` → `resolving`, and the
/// backstop that fails a run which finished without an outcome). The
/// backstop only fires when it is needed: a `success` conclusion means
/// the run's "Resolve the request and submit its outcome" step already
/// posted the outcome — the workflow fails the step, and so the run,
/// when the post does not land — so that `completed` forwards nothing
/// (stow#940).
async fn update_request_run(
    forward: &impl RequestRunForward,
    run: &WorkflowRunFields,
    action: &str,
    attempt: u32,
    request_id: &str,
) -> Result<(), GetArtifactError> {
    if action == "completed" && run.conclusion.as_deref() == Some("success") {
        tracing::debug!(
            request_id,
            attempt,
            "resolve run completed successfully — its outcome already posted"
        );
        return Ok(());
    }
    let update = stow_types::api::RequestRunUpdate {
        attempt,
        action: if action == "completed" {
            stow_types::api::RequestRunAction::Completed
        } else {
            stow_types::api::RequestRunAction::InProgress
        },
        conclusion: run.conclusion.clone(),
        run_id: Some(run.id.to_string()),
        run_url: run.html_url.clone(),
    };
    match forward.send_request_run_update(request_id, &update).await {
        Ok(()) => {
            tracing::info!(request_id, attempt, %action, "request run update applied");
        }
        // Unknown record or a superseded attempt — consumed, never an
        // error back to GitHub: a stale run's events cannot apply to
        // the record's live attempt by design.
        Err(crate::errors::SchedulerClientError::Http {
            status: 404 | 409,
            body,
            ..
        }) => {
            tracing::warn!(
                request_id,
                %body,
                "request run update did not match the live attempt"
            );
        }
        Err(other) => {
            return Err(GetArtifactError::from(other)).inspect_err(|error| {
                tracing::error!(request_id, %error, "forward request run update");
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "webhook-secret";

    fn signed_body(secret: &str, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac accepts any key");
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    /// A request the way GitHub sends it: event + signature headers over
    /// the raw body, the `STOW_GITHUB_WEBHOOK_SECRET` binding layered in
    /// as `State`.
    fn delivery_request(event: &str, body: &[u8], signature: &str) -> Request {
        let mut request = Request::new(skyzen::Body::from(body.to_vec()));
        request
            .headers_mut()
            .insert("X-GitHub-Event", event.parse().expect("header value"));
        request.headers_mut().insert(
            "X-Hub-Signature-256",
            signature.parse().expect("header value"),
        );
        request
            .extensions_mut()
            .insert(State(WebhookSecret(SECRET.to_owned())));
        request
    }

    async fn verified(event: &str, body: &[u8]) -> Result<VerifiedDelivery, GetArtifactError> {
        let signature = signed_body(SECRET, body);
        let mut request = delivery_request(event, body, &signature);
        VerifiedDelivery::extract(&mut request).await
    }

    /// The `triggering_actor.login` a run dispatched through the CI
    /// interface carries — `<slug>[bot]`, the App's bot login.
    const APP_BOT_LOGIN: &str = "stow-ci[bot]";

    /// An operator's login — what every run the scheduler did not
    /// dispatch carries.
    const OPERATOR_LOGIN: &str = "mock-operator";

    fn completed_event(over: impl Fn(&mut serde_json::Value)) -> Vec<u8> {
        let mut event = serde_json::json!({
            "action": "completed",
            "repository": {"full_name": stow_types::trusted_builder::REPOSITORY},
            "workflow_run": {
                "display_title": "1.99.0-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                "event": "workflow_dispatch",
                "head_branch": "main",
                "path": ".github/workflows/build-crate.yml",
                "conclusion": "success",
                "id": 987_654_321_u64,
                "run_attempt": 1,
                "html_url": "https://github.com/water-rs/stow/actions/runs/987654321",
                "head_repository": {"full_name": stow_types::trusted_builder::REPOSITORY},
                "triggering_actor": {"login": OPERATOR_LOGIN},
            },
        });
        over(&mut event);
        serde_json::to_vec(&event).expect("event json")
    }

    #[test]
    fn a_correct_signature_verifies() {
        let body = b"{}";
        let signature = signed_body("secret", body);
        assert!(verify_signature("secret", &signature, body).is_ok());
    }

    #[test]
    fn wrong_secret_or_tampered_body_rejects() {
        let body = b"{}";
        let signature = signed_body("secret", body);
        assert!(verify_signature("other", &signature, body).is_err());
        assert!(verify_signature("secret", &signature, b"{\"x\":1}").is_err());
    }

    #[test]
    fn malformed_signatures_reject() {
        let body = b"{}";
        for signature in ["", "sha256=", "sha1=abc", "sha256=zz", "abc"] {
            assert!(
                verify_signature("secret", signature, body).is_err(),
                "{signature:?}"
            );
        }
    }

    /// A bad signature fails before the payload is ever looked at —
    /// `ping`, `in_progress`, everything.
    #[tokio::test]
    async fn a_bad_signature_rejects_401_before_any_decode() {
        for event in ["ping", "workflow_run"] {
            let mut request = delivery_request(event, b"{}", "sha256=deadbeef");
            let error = VerifiedDelivery::extract(&mut request)
                .await
                .expect_err("bad signature rejects");
            assert!(matches!(error, GetArtifactError::Unauthorized), "{event}");
        }
    }

    /// `ping` is a delivery GitHub requires to succeed — ignored, 200.
    #[tokio::test]
    async fn a_ping_event_is_ignored() {
        let delivery = verified("ping", b"{\"zen\":\"huh\"}")
            .await
            .expect("signed ping verifies");
        assert!(decode_delivery(&delivery).expect("ping decodes").is_none());
    }

    /// `requested`/`queued`/`waiting` deliveries on the `workflow_run`
    /// subscription are lifecycle noise — ignored, 200, before the run
    /// payload is ever parsed.
    #[tokio::test]
    async fn a_non_lifecycle_action_is_ignored() {
        for action in ["requested", "queued", "waiting"] {
            let body =
                format!("{{\"action\":\"{action}\",\"repository\":{{}},\"workflow_run\":{{}}}}");
            let delivery = verified("workflow_run", body.as_bytes())
                .await
                .expect("signed delivery verifies");
            assert!(
                decode_delivery(&delivery)
                    .unwrap_or_else(|error| unreachable!("{action} decodes: {error}"))
                    .is_none(),
                "{action}"
            );
        }
    }

    /// A signed, well-formed run outside the authority boundary —
    /// forked head repo, a non-dispatch event, another repository, a
    /// different workflow file — is ignored with 200.
    #[tokio::test]
    async fn a_run_outside_the_authority_boundary_is_ignored() {
        let cases = [
            completed_event(|event| {
                event["workflow_run"]["head_repository"]["full_name"] =
                    serde_json::json!("attacker/fork");
            }),
            completed_event(|event| {
                event["workflow_run"]["event"] = serde_json::json!("pull_request");
            }),
            completed_event(|event| {
                event["repository"]["full_name"] = serde_json::json!("attacker/fork");
            }),
            completed_event(|event| {
                event["workflow_run"]["path"] =
                    serde_json::json!(".github/workflows/index-publish.yml");
            }),
            completed_event(|event| {
                event["workflow_run"]["head_branch"] = serde_json::json!("dev");
            }),
        ];
        for body in cases {
            let delivery = verified("workflow_run", &body)
                .await
                .expect("signed delivery verifies");
            let (_action, event) = decode_delivery(&delivery)
                .expect("decodes")
                .expect("completed action");
            assert!(authorized_run(&event).expect("checks").is_none());
        }
    }

    /// `run_attempt` is required and positive — a delivery that cannot
    /// name its run's attempt is malformed like any other missing field.
    #[tokio::test]
    async fn a_run_without_a_valid_attempt_is_a_400() {
        for body in [
            completed_event(|event| {
                let _ = event["workflow_run"]
                    .as_object_mut()
                    .expect("workflow_run object")
                    .remove("run_attempt");
            }),
            completed_event(|event| {
                event["workflow_run"]["run_attempt"] = serde_json::json!(0);
            }),
        ] {
            let delivery = verified("workflow_run", &body)
                .await
                .expect("signed delivery verifies");
            let error = decode_delivery(&delivery).expect_err("an unusable run_attempt rejects");
            assert!(matches!(error, GetArtifactError::BadRequestWithMessage(_)));
        }
    }

    /// A `resolve-request.yml` run on both lifecycle actions decodes
    /// `resolve-a<attempt>-<request_id>` into the request subject.
    #[tokio::test]
    async fn a_resolve_run_decodes_its_request_subject() {
        for action in ["in_progress", "completed"] {
            let body = completed_event(|event| {
                event["action"] = serde_json::json!(action);
                event["workflow_run"]["path"] = serde_json::json!(format!(
                    ".github/workflows/{}",
                    stow_types::trusted_builder::RESOLVE_WORKFLOW_FILE
                ));
                event["workflow_run"]["display_title"] = serde_json::json!(
                    stow_types::records::resolve_run_title(2, "req-serde-1.0.0-ab12")
                );
            });
            let delivery = verified("workflow_run", &body)
                .await
                .expect("signed delivery verifies");
            let (decoded, event) = decode_delivery(&delivery)
                .expect("decodes")
                .unwrap_or_else(|| unreachable!("{action} decodes"));
            assert_eq!(decoded, action);
            let (run, subject) = authorized_run(&event).expect("checks").expect("authorized");
            let RunSubject::Request {
                attempt,
                request_id,
            } = subject
            else {
                panic!("resolve-request.yml decodes a request subject");
            };
            assert_eq!((attempt, request_id), (2, "req-serde-1.0.0-ab12"));
            assert_eq!(run.id, 987_654_321_u64);
        }
    }

    /// A resolve run's `completed` forwards only as the backstop:
    /// `success` means the outcome already posted inside the run, so
    /// the delivery sends nothing; every other conclusion forwards
    /// the `RequestRunUpdate` (stow#940).
    #[tokio::test]
    async fn a_successful_resolve_completion_forwards_nothing() {
        let body = completed_event(|event| {
            event["workflow_run"]["path"] = serde_json::json!(format!(
                ".github/workflows/{}",
                stow_types::trusted_builder::RESOLVE_WORKFLOW_FILE
            ));
            event["workflow_run"]["display_title"] =
                serde_json::json!("resolve-a2-req-serde-1.0.0-ab12");
        });
        let delivery = verified("workflow_run", &body)
            .await
            .expect("signed delivery verifies");
        let (_action, event) = decode_delivery(&delivery)
            .expect("decodes")
            .expect("completed action");
        let (run, subject) = authorized_run(&event).expect("checks").expect("authorized");
        let RunSubject::Request {
            attempt,
            request_id,
        } = subject
        else {
            panic!("resolve-request.yml decodes a request subject");
        };
        let forward = CountingForward::default();
        update_request_run(&forward, run, "completed", attempt, request_id)
            .await
            .expect("consumed");
        assert!(
            forward
                .request_updates
                .lock()
                .expect("request updates")
                .is_empty(),
            "a success conclusion posts nothing — the outcome already landed"
        );
    }

    /// Any conclusion but `success` means the outcome never posted, so
    /// the `completed` backstop forwards the update as today.
    #[tokio::test]
    async fn a_failed_resolve_completion_forwards_the_update() {
        let body = completed_event(|event| {
            event["workflow_run"]["path"] = serde_json::json!(format!(
                ".github/workflows/{}",
                stow_types::trusted_builder::RESOLVE_WORKFLOW_FILE
            ));
            event["workflow_run"]["display_title"] =
                serde_json::json!("resolve-a2-req-serde-1.0.0-ab12");
            event["workflow_run"]["conclusion"] = serde_json::json!("failure");
        });
        let delivery = verified("workflow_run", &body)
            .await
            .expect("signed delivery verifies");
        let (_action, event) = decode_delivery(&delivery)
            .expect("decodes")
            .expect("completed action");
        let (run, subject) = authorized_run(&event).expect("checks").expect("authorized");
        let RunSubject::Request {
            attempt,
            request_id,
        } = subject
        else {
            panic!("resolve-request.yml decodes a request subject");
        };
        let forward = CountingForward::default();
        update_request_run(&forward, run, "completed", attempt, request_id)
            .await
            .expect("forwarded");
        let sent = forward.request_updates.lock().expect("request updates");
        assert_eq!(sent.len(), 1, "the backstop forwards once");
        assert_eq!(sent[0].action, stow_types::api::RequestRunAction::Completed);
        assert_eq!(sent[0].conclusion.as_deref(), Some("failure"));
    }

    /// The `in_progress` delivery is unaffected — `accepted` →
    /// `resolving` is the visible progress a user waits on.
    #[tokio::test]
    async fn a_resolve_run_in_progress_still_forwards() {
        let body = completed_event(|event| {
            event["action"] = serde_json::json!("in_progress");
            event["workflow_run"]["path"] = serde_json::json!(format!(
                ".github/workflows/{}",
                stow_types::trusted_builder::RESOLVE_WORKFLOW_FILE
            ));
            event["workflow_run"]["display_title"] =
                serde_json::json!("resolve-a2-req-serde-1.0.0-ab12");
        });
        let delivery = verified("workflow_run", &body)
            .await
            .expect("signed delivery verifies");
        let (_action, event) = decode_delivery(&delivery)
            .expect("decodes")
            .expect("in_progress action");
        let (run, subject) = authorized_run(&event).expect("checks").expect("authorized");
        let RunSubject::Request {
            attempt,
            request_id,
        } = subject
        else {
            panic!("resolve-request.yml decodes a request subject");
        };
        let forward = CountingForward::default();
        update_request_run(&forward, run, "in_progress", attempt, request_id)
            .await
            .expect("forwarded");
        let sent = forward.request_updates.lock().expect("request updates");
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].action,
            stow_types::api::RequestRunAction::InProgress
        );
    }

    /// A pinned resolve run whose title is not
    /// `resolve-a<attempt>-<request_id>` is a 400 — same rule as a
    /// build run's.
    #[tokio::test]
    async fn a_resolve_run_with_a_shapeless_title_is_a_400() {
        let body = completed_event(|event| {
            event["workflow_run"]["path"] = serde_json::json!(format!(
                ".github/workflows/{}",
                stow_types::trusted_builder::RESOLVE_WORKFLOW_FILE
            ));
            event["workflow_run"]["display_title"] = serde_json::json!("not-a-resolve-title");
        });
        let delivery = verified("workflow_run", &body)
            .await
            .expect("signed delivery verifies");
        let (_action, event) = decode_delivery(&delivery)
            .expect("decodes")
            .expect("completed action");
        let error = authorized_run(&event).expect_err("shapeless title rejects");
        assert!(matches!(error, GetArtifactError::BadRequestWithMessage(_)));
    }

    /// A pinned build run whose title is not `<rustc>-<task_id>` is a
    /// 400 — the workflow stamps run-name itself, so a shapeless title
    /// means the dispatch was hand-edited.
    #[tokio::test]
    async fn an_authorized_run_with_a_shapeless_title_is_a_400() {
        let body = task_completed_event(|event| {
            event["workflow_run"]["display_title"] = serde_json::json!("nodashintitle");
        });
        let delivery = verified("workflow_run", &body)
            .await
            .expect("signed delivery verifies");
        let (_action, event) = decode_delivery(&delivery)
            .expect("decodes")
            .expect("completed action");
        let error = authorized_run(&event).expect_err("shapeless title rejects");
        assert!(matches!(error, GetArtifactError::BadRequestWithMessage(_)));
    }

    /// A signed but malformed `workflow_run` payload is a 400.
    #[tokio::test]
    async fn a_malformed_completed_payload_is_a_400() {
        let delivery = verified("workflow_run", b"{\"action\":\"completed\"}")
            .await
            .expect("signed delivery verifies");
        let error = decode_delivery(&delivery).expect_err("malformed payload rejects");
        assert!(matches!(error, GetArtifactError::BadRequestWithMessage(_)));
    }

    /// The build workflow's file and title stamp, applied to a
    /// `completed` delivery.
    fn task_completed_event(over: impl Fn(&mut serde_json::Value)) -> Vec<u8> {
        completed_event(|event| {
            event["workflow_run"]["path"] = serde_json::json!(format!(
                ".github/workflows/{}",
                stow_types::trusted_builder::WORKFLOW_FILE
            ));
            event["workflow_run"]["display_title"] = serde_json::json!(
                "1.99.0-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            );
            over(event);
        })
    }

    /// A `build-crate.yml` run decodes `<rustc>-<task_id>` into the
    /// task subject — inside the same authority boundary a resolve run
    /// sits in (stow#876).
    #[tokio::test]
    async fn a_task_run_decodes_its_task_subject() {
        let body = task_completed_event(|_| {});
        let delivery = verified("workflow_run", &body)
            .await
            .expect("signed delivery verifies");
        let (_action, event) = decode_delivery(&delivery)
            .expect("decodes")
            .expect("completed action");
        let (run, subject) = authorized_run(&event).expect("checks").expect("authorized");
        let RunSubject::Task {
            rustc_version,
            task_id,
        } = subject
        else {
            panic!("build-crate.yml decodes a task subject");
        };
        assert_eq!(rustc_version, "1.99.0");
        assert_eq!(
            task_id,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(run.id, 987_654_321_u64);
    }

    /// A `build-crate.yml` run outside the authority boundary —
    /// another branch, another event, another repo — is refused like
    /// any other run's delivery.
    #[tokio::test]
    async fn a_task_run_outside_the_authority_boundary_is_ignored() {
        let cases = [
            task_completed_event(|event| {
                event["workflow_run"]["head_branch"] = serde_json::json!("dev");
            }),
            task_completed_event(|event| {
                event["workflow_run"]["event"] = serde_json::json!("pull_request");
            }),
            task_completed_event(|event| {
                event["repository"]["full_name"] = serde_json::json!("attacker/fork");
            }),
            task_completed_event(|event| {
                event["workflow_run"]["head_repository"]["full_name"] =
                    serde_json::json!("attacker/fork");
            }),
        ];
        for body in cases {
            let delivery = verified("workflow_run", &body)
                .await
                .expect("signed delivery verifies");
            let (_action, event) = decode_delivery(&delivery)
                .expect("decodes")
                .expect("completed action");
            assert!(authorized_run(&event).expect("checks").is_none());
        }
    }

    /// The task forward's test double: records both channels —
    /// `send_task_run_update` and `send_run_complete` are the task
    /// arm's only outbound calls, so these logs are the whole of what
    /// the handler can send.
    #[derive(Default)]
    struct CountingForward {
        updates: std::sync::Mutex<Vec<TaskRunUpdate>>,
        completions: std::sync::Mutex<Vec<WorkflowRunComplete>>,
        request_updates: std::sync::Mutex<Vec<stow_types::api::RequestRunUpdate>>,
        /// Scripted status — when `Some`, the stub answers
        /// `SchedulerClientError::Http` with it.
        status: Option<u16>,
    }

    impl RequestRunForward for CountingForward {
        fn send_request_run_update<'a>(
            &'a self,
            _request_id: &'a str,
            update: &'a stow_types::api::RequestRunUpdate,
        ) -> impl Future<Output = Result<(), SchedulerClientError>> + Send + 'a {
            self.request_updates
                .lock()
                .expect("request updates")
                .push(update.clone());
            std::future::ready(Ok(()))
        }
    }

    impl TaskRunForward for CountingForward {
        fn send_run_complete<'a>(
            &'a self,
            report: &'a WorkflowRunComplete,
        ) -> impl Future<Output = Result<(), SchedulerClientError>> + Send + 'a {
            self.completions
                .lock()
                .expect("completions")
                .push(report.clone());
            std::future::ready(self.status.map_or(Ok(()), |status| {
                Err(SchedulerClientError::Http {
                    url: "https://scheduler.internal/tasks/complete-run".to_owned(),
                    status,
                    body: "{\"error\":\"unknown task\"}".to_owned(),
                })
            }))
        }

        fn send_task_run_update<'a>(
            &'a self,
            update: &'a TaskRunUpdate,
        ) -> impl Future<Output = Result<(), SchedulerClientError>> + Send + 'a {
            self.updates.lock().expect("updates").push(update.clone());
            std::future::ready(self.status.map_or(Ok(()), |status| {
                Err(SchedulerClientError::Http {
                    url: "https://scheduler.internal/tasks/run-update".to_owned(),
                    status,
                    body: "{\"error\":\"unknown task\"}".to_owned(),
                })
            }))
        }
    }

    /// The `in_progress` arm's handler issues exactly one outbound
    /// call — the `POST /tasks/run-update` forward carrying the task
    /// and run ids (stow#876). A DO 404 — an orphan run from an
    /// abandoned dispatch — is consumed: logged, still 200 to GitHub.
    /// A 5xx propagates as a 500.
    #[tokio::test]
    async fn a_task_run_update_forwards_once_and_a_404_is_consumed() {
        let body = task_completed_event(|event| {
            event["action"] = serde_json::json!("in_progress");
        });
        let delivery = verified("workflow_run", &body)
            .await
            .expect("signed delivery verifies");
        let (_action, event) = decode_delivery(&delivery)
            .expect("decodes")
            .expect("in_progress action");
        let (run, subject) = authorized_run(&event).expect("checks").expect("authorized");
        let RunSubject::Task { task_id, .. } = subject else {
            panic!("build-crate.yml decodes a task subject");
        };
        let forward = CountingForward::default();
        update_task_run(&forward, run, task_id)
            .await
            .expect("forwarded");
        let updates = forward.updates.lock().expect("updates").clone();
        assert_eq!(updates.len(), 1, "the task arm issues only the DO forward");
        assert_eq!(updates[0].task_id, task_id);
        assert_eq!(updates[0].github_run_id, "987654321");

        let unknown = CountingForward {
            status: Some(404),
            ..CountingForward::default()
        };
        update_task_run(&unknown, run, task_id)
            .await
            .expect("an unknown task is consumed, not propagated");
        let failing = CountingForward {
            status: Some(500),
            ..CountingForward::default()
        };
        let error = update_task_run(&failing, run, task_id)
            .await
            .expect_err("a DO failure propagates as a 500");
        assert!(matches!(error, GetArtifactError::InternalWithMessage(_)));
    }

    /// The `in_progress` gate (stow#940): a run the scheduler
    /// dispatched — `triggering_actor.login` is the App's bot login —
    /// forwards nothing, since the CI listing's reconcile reports its
    /// running state. An operator's run still forwards to
    /// `POST /tasks/run-update`.
    #[tokio::test]
    async fn an_own_run_in_progress_forwards_nothing_an_external_ones_does() {
        for (actor, forwards) in [(APP_BOT_LOGIN, 0_usize), (OPERATOR_LOGIN, 1)] {
            let body = task_completed_event(|event| {
                event["action"] = serde_json::json!("in_progress");
                event["workflow_run"]["triggering_actor"]["login"] = serde_json::json!(actor);
            });
            let delivery = verified("workflow_run", &body)
                .await
                .expect("signed delivery verifies");
            let (_action, event) = decode_delivery(&delivery)
                .expect("decodes")
                .expect("in_progress action");
            let (run, subject) = authorized_run(&event).expect("checks").expect("authorized");
            let RunSubject::Task { task_id, .. } = subject else {
                panic!("build-crate.yml decodes a task subject");
            };
            let forward = CountingForward::default();
            update_external_task_run(&forward, APP_BOT_LOGIN, run, task_id)
                .await
                .expect("handled");
            assert_eq!(
                forward.updates.lock().expect("updates").len(),
                forwards,
                "{actor}"
            );
        }
    }

    /// `completed` forwards for every run — the actor never gates the
    /// slot-freeing channel (stow#940).
    #[tokio::test]
    async fn a_completed_run_forwards_regardless_of_actor() {
        for actor in [APP_BOT_LOGIN, OPERATOR_LOGIN] {
            let body = task_completed_event(|event| {
                event["workflow_run"]["triggering_actor"]["login"] = serde_json::json!(actor);
            });
            let delivery = verified("workflow_run", &body)
                .await
                .expect("signed delivery verifies");
            let (_action, event) = decode_delivery(&delivery)
                .expect("decodes")
                .expect("completed action");
            let (run, subject) = authorized_run(&event).expect("checks").expect("authorized");
            let RunSubject::Task { task_id, .. } = subject else {
                panic!("build-crate.yml decodes a task subject");
            };
            let forward = CountingForward::default();
            forward_run_complete(&forward, run, task_id, true, None)
                .await
                .expect("forwarded");
            let completions = forward.completions.lock().expect("completions");
            assert_eq!(completions.len(), 1, "{actor}");
            assert_eq!(completions[0].task_id, task_id);
            assert_eq!(completions[0].github_run_id, "987654321");
        }
    }

    /// A `workflow_run` delivery without `triggering_actor` is not
    /// the shape GitHub documents — rejected like any other missing
    /// field (stow#940).
    #[tokio::test]
    async fn a_delivery_without_triggering_actor_is_a_400() {
        let body = completed_event(|event| {
            let _ = event["workflow_run"]
                .as_object_mut()
                .expect("workflow_run object")
                .remove("triggering_actor");
        });
        let delivery = verified("workflow_run", &body)
            .await
            .expect("signed delivery verifies");
        let error = decode_delivery(&delivery).expect_err("missing triggering_actor rejects");
        assert!(matches!(error, GetArtifactError::BadRequestWithMessage(_)));
    }

    /// The records check's test double: every artifact is in GHCR, so
    /// a successful `completed` forwards a success.
    struct RecordsPresent;

    impl RecordsCheck for RecordsPresent {
        type Error = std::convert::Infallible;

        fn records_artifact_exists<'a>(
            &'a self,
            _rustc_version: &'a str,
            _task_id: &'a str,
            _build: stow_types::records::BuildRun,
        ) -> impl Future<Output = Result<bool, Self::Error>> + Send + 'a {
            std::future::ready(Ok(true))
        }
    }

    /// One run of `workflow` (its file under `.github/workflows/`)
    /// titled `title`, started by `actor` and concluding `conclusion`,
    /// delivered as `action`: GitHub sends no conclusion before
    /// `completed`.
    fn run_delivery(
        action: &str,
        workflow: &str,
        title: &str,
        actor: &str,
        conclusion: &str,
    ) -> Vec<u8> {
        completed_event(|event| {
            event["action"] = serde_json::json!(action);
            event["workflow_run"]["path"] =
                serde_json::json!(format!(".github/workflows/{workflow}"));
            event["workflow_run"]["display_title"] = serde_json::json!(title);
            event["workflow_run"]["triggering_actor"]["login"] = serde_json::json!(actor);
            event["workflow_run"]["conclusion"] = if action == "completed" {
                serde_json::json!(conclusion)
            } else {
                serde_json::Value::Null
            };
        })
    }

    /// Scheduler requests the handler forwarded for one delivery,
    /// across every outbound channel it has.
    async fn forwards_for(body: &[u8]) -> u32 {
        let delivery = verified("workflow_run", body)
            .await
            .expect("signed delivery verifies");
        let forward = CountingForward::default();
        consume_delivery(&delivery, &RecordsPresent, &forward, APP_BOT_LOGIN)
            .await
            .expect("consumed");
        let sent = forward.updates.lock().expect("updates").len()
            + forward.completions.lock().expect("completions").len()
            + forward
                .request_updates
                .lock()
                .expect("request updates")
                .len();
        u32::try_from(sent).expect("a delivery forwards a handful")
    }

    /// Every lifecycle the traffic projection prices, delivered action
    /// by action through the real handler: what it forwards is the
    /// `stow_types::forwards` row the projection reads (stow#937). A
    /// handler change that forwards another delivery fails here until
    /// the row — and with it the projected bill — moves too.
    #[tokio::test]
    async fn each_lifecycle_forwards_what_the_projection_prices() {
        use stow_types::forwards::{
            EXTERNAL_BUILD_RUN, FAILED_RESOLVE_RUN, INDEX_PUBLISH_RUN, OWN_BUILD_RUN,
            SUCCESSFUL_RESOLVE_RUN, WORKFLOW_RUN_ACTIONS,
        };
        let build = stow_types::trusted_builder::WORKFLOW_FILE;
        let resolve = stow_types::trusted_builder::RESOLVE_WORKFLOW_FILE;
        let build_title = "1.99.0-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let resolve_title = "resolve-a2-req-serde-1.0.0-ab12";
        for (name, forwards, workflow, title, actor, conclusion) in [
            (
                "own build run",
                OWN_BUILD_RUN,
                build,
                build_title,
                APP_BOT_LOGIN,
                "success",
            ),
            (
                "external build run",
                EXTERNAL_BUILD_RUN,
                build,
                build_title,
                OPERATOR_LOGIN,
                "success",
            ),
            (
                "successful resolve run",
                SUCCESSFUL_RESOLVE_RUN,
                resolve,
                resolve_title,
                APP_BOT_LOGIN,
                "success",
            ),
            (
                "failed resolve run",
                FAILED_RESOLVE_RUN,
                resolve,
                resolve_title,
                APP_BOT_LOGIN,
                "failure",
            ),
            (
                "index-publish run",
                INDEX_PUBLISH_RUN,
                "index-publish.yml",
                "index publish",
                APP_BOT_LOGIN,
                "success",
            ),
        ] {
            for action in WORKFLOW_RUN_ACTIONS {
                let body = run_delivery(action, workflow, title, actor, conclusion);
                assert_eq!(
                    forwards_for(&body).await,
                    forwards.on(action).expect("a delivered action"),
                    "{name} {action}"
                );
            }
        }
    }
}
