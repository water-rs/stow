//! Dev-only local CI dispatch server.
//!
//! Activated via `stow-build serve`. Implements `POST /dispatch` so a
//! locally-running edge worker can dispatch `build-crate` runs (a
//! `BuildTaskPayload`) and `resolve-request` runs (a `RequestDispatch`)
//! for end-to-end tests without touching real GitHub Actions — and
//! `GET /tasks`, the run-state list `stow-admin preheat manual` polls in
//! its `--dispatch-url` mode.
//!
//! The run mirrors the production shape exactly: build in one process,
//! then the records artifact lands in the mock registry and completion
//! reaches the edge as a `workflow_run` webhook POST — the same
//! `X-Hub-Signature-256` HMAC GitHub signs with — never a scheduler call.
//!
//! Uses skyzen + skyzen-hyper for routing so the same DSL is shared with the
//! edge worker and there is exactly one HTTP server framework in the
//! workspace. async-net provides a futures-compatible TCP listener so we
//! avoid the tokio-IO / futures-IO bridging dance.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_net::TcpListener;
use executor_core::tokio::TokioGlobal;
use futures_lite::stream;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use skyzen::Server;
use skyzen::routing::{CreateRouteNode, Route, Router};
use skyzen::utils::{Json, State};
use skyzen::{Body, Response, StatusCode};
use stow_types::api::{BuildTaskPayload, RequestDispatch};
use tokio::time::{Duration, sleep};
use zenwave::{Client, ResponseExt};

type HmacSha256 = Hmac<Sha256>;

/// One dispatched run's state, as `GET /tasks` reports it — the local
/// stand-in for a GitHub Actions workflow run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MockTaskRun {
    /// The run's name — `<rustc>-<task_id>`, the same shape
    /// `build-crate.yml`'s `run-name` stamps on the real API.
    pub display_title: String,
    /// `queued`, `in_progress`, or `completed` — the GitHub Actions
    /// `status` field's spelling.
    pub status: &'static str,
    /// `success` or `failure` once `status` is `completed`; `null`
    /// before, exactly like the API.
    pub conclusion: Option<&'static str>,
    /// Where a human would look — the failure list prints it.
    pub html_url: String,
}

/// Per-process state injected into every `/dispatch` invocation.
#[derive(Clone)]
pub struct LocalServerState {
    /// Edge URL prefix (no trailing slash) — the `workflow_run` webhook
    /// posts to `{edge_url}/api/v1/github/workflow-run`.
    pub edge_url: String,
    /// Shared secret the webhook signature is computed with — the
    /// `STOW_GITHUB_WEBHOOK_SECRET` binding's local value.
    pub webhook_secret: String,
    /// Filesystem path to the mock cosign public key.
    pub mock_public_key_path: String,
    /// Filesystem path to the mock cosign private key.
    pub mock_private_key_path: String,
    /// Root directory the mock OCI registry serves out of.
    pub mock_registry_root: String,
    /// Every dispatched task's run state, served by `GET /tasks`.
    pub runs: Arc<Mutex<BTreeMap<String, MockTaskRun>>>,
    /// The bound listen address, filled by `serve` — the `html_url` a
    /// mock run reports.
    pub listen: SocketAddr,
}

impl std::fmt::Debug for LocalServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalServerState")
            .field("edge_url", &self.edge_url)
            .field("mock_registry_root", &self.mock_registry_root)
            .field("listen", &self.listen)
            .finish_non_exhaustive()
    }
}

impl LocalServerState {
    /// Assemble the state `serve` runs with; `listen` is overwritten by
    /// the bound address once the socket opens.
    pub fn new(
        edge_url: String,
        webhook_secret: String,
        mock_public_key_path: String,
        mock_private_key_path: String,
        mock_registry_root: String,
    ) -> Self {
        Self {
            edge_url,
            webhook_secret,
            mock_public_key_path,
            mock_private_key_path,
            mock_registry_root,
            runs: Arc::new(Mutex::new(BTreeMap::new())),
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        }
    }

    /// Record a dispatched run — `run_key` is the id `GET /tasks`
    /// indexes by (the task id for builds, the request id for resolves)
    /// and `display_title` the run-name its workflow stamps.
    fn mark_run(
        &self,
        run_key: &str,
        display_title: &str,
        status: &'static str,
        conclusion: Option<&'static str>,
    ) {
        let entry = MockTaskRun {
            display_title: display_title.to_string(),
            status,
            conclusion,
            html_url: format!("http://{}/tasks/{display_title}", self.listen),
        };
        self.runs
            .lock()
            .expect("runs mutex poisoned")
            .insert(run_key.to_owned(), entry);
    }

    /// `run_title` under `build-crate.yml`'s convention for a task —
    /// the display title `mark_run` and the `workflow_run` webhook
    /// share.
    fn build_run_title(task: &BuildTaskPayload) -> String {
        stow_types::records::run_title(task.rustc_version.as_str(), &task.task_id)
    }

    /// Record a build task's run under its task id.
    fn mark_build_run(
        &self,
        task: &BuildTaskPayload,
        status: &'static str,
        conclusion: Option<&'static str>,
    ) {
        self.mark_run(
            &task.task_id,
            &Self::build_run_title(task),
            status,
            conclusion,
        );
    }
}

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
struct RepositoryDispatchEvent {
    /// The scheduler's `trigger_workflow` discriminator — `build-crate`
    /// or `resolve-request`.
    event_type: String,
    /// The event's payload: a [`BuildTaskPayload`] for `build-crate`,
    /// a `stow_types::api::RequestDispatch` for `resolve-request`.
    client_payload: serde_json::Value,
}

#[derive(Debug, serde::Serialize)]
struct DispatchResponse {
    ok: bool,
}

#[derive(Debug, serde::Serialize)]
struct TasksResponse {
    tasks: Vec<MockTaskRun>,
}

/// Bind and serve the dev dispatch endpoint.
pub async fn serve(
    listen: SocketAddr,
    mut state: LocalServerState,
) -> stow_types::error::Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|error| stow_types::stow_error!("bind local ci server {}: {error}", listen))?;
    state.listen = listener
        .local_addr()
        .map_err(|error| stow_types::stow_error!("read bound address: {error}"))?;
    let router = build_router(state);

    tracing::info!(%listen, "local CI server listening");
    let connections = Box::pin(stream::unfold(listener, |listener| async move {
        let result = listener.accept().await;
        Some((result.map(|(stream, _addr)| stream), listener))
    }));

    skyzen::hyper::Hyper
        .serve(
            TokioGlobal,
            |error| tracing::error!(%error, "local CI server connection error"),
            connections,
            router,
        )
        .await;
    Ok(())
}

fn build_router(state: LocalServerState) -> Router {
    Route::new(("/dispatch".post(dispatch), "/tasks".at(list_tasks)))
        .with(State(state))
        .build()
}

/// `GET /tasks` — the run list `stow-admin preheat manual` polls when it
/// drives the local runner, answering the same shape the GitHub runs API
/// does (`status`/`conclusion`/`display_title` semantics).
async fn list_tasks(State(state): State<LocalServerState>) -> Response {
    let tasks = state
        .runs
        .lock()
        .expect("runs mutex poisoned")
        .values()
        .cloned()
        .collect();
    json_response(&TasksResponse { tasks }, StatusCode::OK)
}

/// `POST /dispatch` — the scheduler's one local fan-out: `build-crate`
/// events run the full simulated build, `resolve-request` events are
/// the request lane's resolve-job dispatch (stow#428).
async fn dispatch(
    State(state): State<LocalServerState>,
    Json(event): Json<RepositoryDispatchEvent>,
) -> Response {
    match event.event_type.as_str() {
        "build-crate" => match serde_json::from_value::<BuildTaskPayload>(event.client_payload) {
            Ok(task) => dispatch_build(state, task),
            Err(error) => json_response(
                &bad_request(&format!("build-crate payload: {error}")),
                StatusCode::BAD_REQUEST,
            ),
        },
        "resolve-request" => {
            match serde_json::from_value::<RequestDispatch>(event.client_payload) {
                Ok(dispatch) => dispatch_resolve(state, dispatch),
                Err(error) => json_response(
                    &bad_request(&format!("resolve-request payload: {error}")),
                    StatusCode::BAD_REQUEST,
                ),
            }
        }
        other => json_response(
            &bad_request(&format!("unknown event_type `{other}`")),
            StatusCode::BAD_REQUEST,
        ),
    }
}

fn bad_request(error: &str) -> serde_json::Value {
    serde_json::json!({ "error": error })
}

fn dispatch_build(state: LocalServerState, task: BuildTaskPayload) -> Response {
    state.mark_build_run(&task, "in_progress", None);
    tokio::spawn(async move {
        let state_for_task = state.clone();
        if let Err(error) = run_dispatched_task(state_for_task.clone(), task.clone()).await {
            tracing::error!(task_id = %task.task_id, %error, "local CI dispatched task failed");
            state_for_task.mark_build_run(&task, "completed", Some("failure"));
            if let Err(report_error) = report_failed_task(
                &state_for_task,
                &task,
                format!("local CI dispatch failed: {error}"),
            )
            .await
            {
                tracing::error!(
                    task_id = %task.task_id,
                    %report_error,
                    "failed to report local CI task failure via webhook"
                );
            }
        }
    });
    json_response(&DispatchResponse { ok: true }, StatusCode::ACCEPTED)
}

/// A `resolve-request` dispatch (stow#428): the stub absorbs the hop
/// the admit pass pays, records the run and reports `in_progress`
/// through the same signed `workflow_run` webhook a real Actions job
/// emits when its job starts. The resolve itself — `stow-admin request
/// resolve`, its outcome report, run completion — is not simulated:
/// the record the admit pass wrote stays `resolving` here until the
/// operator drives the resolve for real.
fn dispatch_resolve(state: LocalServerState, dispatch: RequestDispatch) -> Response {
    let display_title =
        stow_types::records::resolve_run_title(dispatch.attempt, &dispatch.request_id);
    state.mark_run(&dispatch.request_id, &display_title, "in_progress", None);
    let report = WorkflowRunReport {
        run_key: dispatch.request_id.clone(),
        workflow_file: stow_types::trusted_builder::RESOLVE_WORKFLOW_FILE,
        display_title,
        action: "in_progress",
        conclusion: None,
        html_url: format!("http://{}/tasks/{}", state.listen, dispatch.request_id),
        error: None,
    };
    tokio::spawn(async move {
        if let Err(error) = post_workflow_run(&state, &report).await {
            tracing::error!(
                request_id = %dispatch.request_id,
                %error,
                "failed to report resolve run in_progress via webhook"
            );
        }
    });
    json_response(&DispatchResponse { ok: true }, StatusCode::ACCEPTED)
}

fn json_response(payload: &impl serde::Serialize, status: StatusCode) -> Response {
    let body = serde_json::to_vec(payload).expect("response always serializes");
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        "content-type",
        skyzen::header::HeaderValue::from_static("application/json"),
    );
    response
}

async fn report_failed_task(
    state: &LocalServerState,
    task: &BuildTaskPayload,
    error: String,
) -> stow_types::error::Result<()> {
    post_workflow_run(
        state,
        &task_workflow_run(state, task, Some("failure"), Some(error)),
    )
    .await
}

/// The task id names a directory under the dispatch root, so it must be a
/// single plain path component: the endpoint is unauthenticated and the id
/// arrives in the request body.
fn task_directory_name(task_id: &str) -> stow_types::error::Result<&str> {
    let mut components = Path::new(task_id).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(task_id),
        _ => Err(stow_types::stow_error!(
            "task id {task_id:?} is not a plain path component"
        )),
    }
}

/// Filesystem layout of one dispatched task's working directory: the
/// workspace the build stage unpacks into, the output directory it writes
/// to, and the files the two stages exchange.
struct DispatchLayout {
    /// Per-task working directory under `.tmp/local-ci-dispatch`.
    task_root: PathBuf,
    /// `stow-build build --output-dir`: plan and content-addressed blobs.
    output_dir: PathBuf,
    /// Upload plan the build stage writes and `populate` consumes.
    upload_plan_path: PathBuf,
    /// Artifact records `populate` writes for the records-artifact step.
    records_path: PathBuf,
}

impl DispatchLayout {
    /// Create a fresh task directory under `.tmp/local-ci-dispatch`,
    /// discarding any leftover from a previous run of the same task id.
    fn create(task_id: &str) -> stow_types::error::Result<Self> {
        let dispatch_root = std::env::current_dir()?
            .join(".tmp")
            .join("local-ci-dispatch");
        std::fs::create_dir_all(&dispatch_root)?;
        let task_root = dispatch_root.join(task_directory_name(task_id)?);
        if task_root.exists() {
            std::fs::remove_dir_all(&task_root)?;
        }
        std::fs::create_dir_all(&task_root)?;
        let output_dir = task_root.join("output");
        Ok(Self {
            upload_plan_path: output_dir.join("upload-plan.json"),
            records_path: task_root.join("records.json"),
            task_root,
            output_dir,
        })
    }
}

async fn run_dispatched_task(
    state: LocalServerState,
    task: BuildTaskPayload,
) -> stow_types::error::Result<()> {
    // `STOW_LOCAL_CI_STUB=1` short-circuits the build stage: the dispatch
    // POST — the hop the alarm pass pays per claimed task — is the piece
    // the budget probe and the launch load run measure, and a real cargo
    // build per dispatch is orders of magnitude heavier than either can
    // afford. The run still completes through the same signed
    // `workflow_run` webhook, so `complete_run` lands and `GET /tasks`
    // reports a finished run — the dispatch shape is unchanged, only the
    // post-dispatch build work is stubbed. The webhook verifies the
    // task's records artifact before applying a success, so the stub
    // pushes the empty set first — the same object production writes
    // for an artifact-less task — or the edge would record the run as a
    // failure it never was.
    if std::env::var_os("STOW_LOCAL_CI_STUB").is_some() {
        let layout = DispatchLayout::create(&task.task_id)?;
        push_records(
            &state,
            &task,
            &layout.records_path,
            &std::env::current_exe()?,
        )
        .await?;
        state.mark_build_run(&task, "completed", Some("success"));
        return post_workflow_run(
            &state,
            &task_workflow_run(&state, &task, Some("success"), None),
        )
        .await;
    }
    let task_json = serde_json::to_string(&task)?;
    let exe = std::env::current_exe()?;
    let layout = DispatchLayout::create(&task.task_id)?;

    // The child is the untrusted build stage: it gets the task and nothing
    // else, exactly as the production build job does.
    let status = run_build_stage(&exe, &task_json, &layout).await?;
    if !status.success() {
        let error = format!("stow-build exited with status {status}");
        state.mark_build_run(&task, "completed", Some("failure"));
        post_workflow_run(
            &state,
            &task_workflow_run(&state, &task, Some("failure"), Some(error.clone())),
        )
        .await?;
        return Err(stow_types::stow_error!("{error}"));
    }

    // `stow-build build` exits non-zero when any cargo phase failed — the
    // outcome is binary now: a live process reached this line means the
    // build ran to completion and whatever it plans is the whole closure.
    if upload_plan_len(&layout.upload_plan_path).await? == 0 {
        // Even an artifact-less task publishes its (empty) records
        // artifact — the webhook's existence check must find it.
        push_records(&state, &task, &layout.records_path, exe.as_path()).await?;
        state.mark_build_run(&task, "completed", Some("success"));
        return post_workflow_run(
            &state,
            &task_workflow_run(&state, &task, Some("success"), None),
        )
        .await;
    }

    populate_mock_registry(&exe, &state, &task, &layout).await?;
    push_records(&state, &task, &layout.records_path, exe.as_path()).await?;
    state.mark_build_run(&task, "completed", Some("success"));
    post_workflow_run(
        &state,
        &task_workflow_run(&state, &task, Some("success"), None),
    )
    .await
}

/// Spawn the untrusted `stow-build build` stage. It receives only the task
/// JSON and a workspace root — the trusted credentials are removed from its
/// environment, as they are absent from the production build job.
async fn run_build_stage(
    exe: &Path,
    task_json: &str,
    layout: &DispatchLayout,
) -> stow_types::error::Result<std::process::ExitStatus> {
    Ok(async_process::Command::new(exe)
        .arg("build")
        .arg("--output-dir")
        .arg(&layout.output_dir)
        .env_remove("SCHEDULER_URL")
        .env_remove("STOW_EDGE_URL")
        .env_remove("STOW_GITHUB_WEBHOOK_SECRET")
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_URL")
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .env_remove("STOW_OIDC_AUDIENCE")
        .env(
            "STOW_BUILD_WORKSPACE_ROOT",
            layout.task_root.join("workspace"),
        )
        .env("STOW_BUILD_TASK_JSON", task_json)
        .status()
        .await?)
}

/// Number of entries in the build stage's upload plan; a non-array or
/// empty plan means the task produced nothing to publish.
async fn upload_plan_len(upload_plan_path: &Path) -> stow_types::error::Result<usize> {
    let upload_plan_bytes = async_fs::read(upload_plan_path).await?;
    let upload_plan_json: serde_json::Value = serde_json::from_slice(&upload_plan_bytes)?;
    Ok(upload_plan_json.as_array().map_or(0usize, Vec::len))
}

/// Populate the mock OCI registry from the upload plan and sign with the
/// mock keys, writing the artifact records the records-artifact step then
/// pushes.
async fn populate_mock_registry(
    exe: &Path,
    state: &LocalServerState,
    task: &BuildTaskPayload,
    layout: &DispatchLayout,
) -> stow_types::error::Result<()> {
    let registry_sqlite = layout.task_root.join("mock-registry.sqlite");
    let mock_registry_exe = exe
        .parent()
        .ok_or_else(|| {
            stow_types::stow_error!("cannot determine parent directory of stow-build binary")
        })?
        .join(format!(
            "stow-mock-registry{}",
            std::env::consts::EXE_SUFFIX
        ));
    if !mock_registry_exe.exists() {
        return Err(stow_types::stow_error!(
            "mock registry binary not found at {}",
            mock_registry_exe.display()
        ));
    }
    let populate_status = async_process::Command::new(&mock_registry_exe)
        .arg("populate")
        .arg("--upload-plan")
        .arg(&layout.upload_plan_path)
        .arg("--registry-root")
        .arg(PathBuf::from(&state.mock_registry_root))
        .arg("--sqlite")
        .arg(&registry_sqlite)
        .arg("--private-key")
        .arg(PathBuf::from(&state.mock_private_key_path))
        .arg("--public-key")
        .arg(PathBuf::from(&state.mock_public_key_path))
        .arg("--records-out")
        .arg(&layout.records_path)
        .status()
        .await?;
    if populate_status.success() {
        return Ok(());
    }
    let error = format!("mock registry populate exited with status {populate_status}");
    state.mark_build_run(task, "completed", Some("failure"));
    post_workflow_run(
        state,
        &task_workflow_run(state, task, Some("failure"), Some(error.clone())),
    )
    .await?;
    Err(stow_types::stow_error!("{error}"))
}

/// Write the task's records artifact into the mock registry — the same
/// object the production publish stage pushes to GHCR under
/// `records-<rustc>-<task_id hash>`, signed by the mock key instead of cosign.
async fn push_records(
    state: &LocalServerState,
    task: &BuildTaskPayload,
    records_path: &Path,
    exe: &Path,
) -> stow_types::error::Result<()> {
    let mock_registry_exe = exe
        .parent()
        .ok_or_else(|| {
            stow_types::stow_error!("cannot determine parent directory of stow-build binary")
        })?
        .join(format!(
            "stow-mock-registry{}",
            std::env::consts::EXE_SUFFIX
        ));
    // An empty plan leaves no records.json — the records artifact carries
    // the empty set, exactly like production's `push_records(&[])`.
    if !records_path.exists() {
        async_fs::write(records_path, "[]").await?;
    }
    let status = async_process::Command::new(&mock_registry_exe)
        .arg("push-records")
        .arg("--records")
        .arg(records_path)
        .arg("--task-id")
        .arg(&task.task_id)
        .arg("--rustc-version")
        .arg(&task.rustc_version)
        .arg("--registry-root")
        .arg(PathBuf::from(&state.mock_registry_root))
        .arg("--private-key")
        .arg(PathBuf::from(&state.mock_private_key_path))
        .status()
        .await?;
    if status.success() {
        return Ok(());
    }
    Err(stow_types::stow_error!(
        "mock registry push-records failed with status {status}"
    ))
}

/// The `workflow_run` event a mock run reports — the fields GitHub's
/// payload carries that the edge's signature check, authority boundary
/// and title correlation consume. `run_key` (task id or request id)
/// seeds the synthetic run id; `display_title` is the run-name the
/// workflow stamps and the edge parses back.
struct WorkflowRunReport {
    run_key: String,
    /// The workflow file — `build-crate.yml` or `resolve-request.yml`.
    workflow_file: &'static str,
    display_title: String,
    /// `in_progress` or `completed` — GitHub's `action` field.
    action: &'static str,
    /// `success`/`failure` — present on `completed` deliveries only.
    conclusion: Option<&'static str>,
    /// The run's link — the mock's own `GET /tasks` page.
    html_url: String,
    /// Failure detail worth logging alongside the report.
    error: Option<String>,
}

/// A dispatched build task's `completed` report under
/// `build-crate.yml`'s run-name.
fn task_workflow_run(
    state: &LocalServerState,
    task: &BuildTaskPayload,
    conclusion: Option<&'static str>,
    error: Option<String>,
) -> WorkflowRunReport {
    WorkflowRunReport {
        run_key: task.task_id.clone(),
        workflow_file: stow_types::trusted_builder::WORKFLOW_FILE,
        display_title: LocalServerState::build_run_title(task),
        action: "completed",
        conclusion,
        html_url: format!("http://{}/tasks/{}", state.listen, task.task_id),
        error,
    }
}

/// POST a synthetic `workflow_run` webhook to the edge — the exact
/// event shape and signature header GitHub delivers, so the mock edge
/// verifies the same HMAC the production one does.
async fn post_workflow_run(
    state: &LocalServerState,
    run: &WorkflowRunReport,
) -> stow_types::error::Result<()> {
    const MAX_ATTEMPTS: u32 = 5;
    if let Some(error) = &run.error {
        tracing::warn!(run_key = %run.run_key, %error, "workflow_run reports {:?}", run.conclusion);
    }
    // The production pin: same path/branch/event/repository fields the
    // webhook requires, with the run title the workflow stamps.
    let payload = serde_json::json!({
        "action": run.action,
        "repository": {"full_name": stow_types::trusted_builder::REPOSITORY},
        "workflow_run": {
            "id": blake3::hash(run.run_key.as_bytes()).as_bytes()[..8]
                .iter()
                .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)),
            "name": run.workflow_file,
            "path": format!(".github/workflows/{}", run.workflow_file),
            "event": "workflow_dispatch",
            "display_title": run.display_title,
            "head_branch": stow_types::trusted_builder::BRANCH,
            "conclusion": run.conclusion,
            "html_url": run.html_url,
            "head_repository": {"full_name": stow_types::trusted_builder::REPOSITORY},
        },
    });
    let body = serde_json::to_vec(&payload)?;
    let signature = {
        let mut mac = HmacSha256::new_from_slice(state.webhook_secret.as_bytes())
            .map_err(|error| stow_types::stow_error!("init webhook HMAC: {error}"))?;
        mac.update(&body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    };
    let url = format!(
        "{}/api/v1/github/workflow-run",
        state.edge_url.trim_end_matches('/')
    );
    let mut last_error: Option<stow_types::error::Error> = None;
    for attempt in 0..MAX_ATTEMPTS {
        let attempt_result = async {
            let mut client = zenwave::client();
            client
                .post(&url)?
                .header("X-GitHub-Event", "workflow_run")?
                .header("X-Hub-Signature-256", &signature)?
                .header("Content-Type", "application/json")?
                .bytes_body(body.clone())
                .await?
                .error_for_status()
                .await?;
            Ok::<(), zenwave::Error>(())
        }
        .await;
        match attempt_result {
            Ok(()) => return Ok(()),
            Err(error) => {
                last_error = Some(stow_types::stow_error!("POST {url}: {error}"));
                if attempt + 1 < MAX_ATTEMPTS {
                    sleep(Duration::from_millis(250)).await;
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        stow_types::stow_error!("post_workflow_run: all {MAX_ATTEMPTS} attempts failed")
    }))
}

#[cfg(test)]
mod tests {
    use super::task_directory_name;

    #[test]
    fn plain_task_ids_name_their_directory() {
        assert_eq!(task_directory_name("task-42").unwrap(), "task-42");
    }

    #[test]
    fn traversing_task_ids_are_rejected() {
        for task_id in ["", "..", "../escape", "nested/task", "/rooted"] {
            assert!(task_directory_name(task_id).is_err(), "{task_id:?}");
        }
    }
}
