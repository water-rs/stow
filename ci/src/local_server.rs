//! Dev-only local CI dispatch server.
//!
//! Activated via `stow-build serve`. Implements `POST /dispatch` so a
//! locally-running edge worker can dispatch a `BuildTaskPayload` for an
//! end-to-end test run without touching real GitHub Actions — and
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
use stow_types::api::BuildTaskPayload;
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

    fn mark_run(
        &self,
        task: &BuildTaskPayload,
        status: &'static str,
        conclusion: Option<&'static str>,
    ) {
        let display_title =
            stow_types::records::run_title(task.rustc_version.as_str(), &task.task_id);
        let entry = MockTaskRun {
            display_title: display_title.clone(),
            status,
            conclusion,
            html_url: format!("http://{}/tasks/{display_title}", self.listen),
        };
        self.runs
            .lock()
            .expect("runs mutex poisoned")
            .insert(task.task_id.clone(), entry);
    }
}

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
struct RepositoryDispatchEvent {
    client_payload: BuildTaskPayload,
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

async fn dispatch(
    State(state): State<LocalServerState>,
    Json(event): Json<RepositoryDispatchEvent>,
) -> Response {
    let task = event.client_payload;
    state.mark_run(&task, "in_progress", None);
    tokio::spawn(async move {
        let state_for_task = state.clone();
        if let Err(error) = run_dispatched_task(state_for_task.clone(), task.clone()).await {
            tracing::error!(task_id = %task.task_id, %error, "local CI dispatched task failed");
            state_for_task.mark_run(&task, "completed", Some("failure"));
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
    post_workflow_run(state, task, "failure", Some(error)).await
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
    let task_json = serde_json::to_string(&task)?;
    let exe = std::env::current_exe()?;
    let layout = DispatchLayout::create(&task.task_id)?;

    // The child is the untrusted build stage: it gets the task and nothing
    // else, exactly as the production build job does.
    let status = run_build_stage(&exe, &task_json, &layout).await?;
    if !status.success() {
        let error = format!("stow-build exited with status {status}");
        state.mark_run(&task, "completed", Some("failure"));
        post_workflow_run(&state, &task, "failure", Some(error.clone())).await?;
        return Err(stow_types::stow_error!("{error}"));
    }

    // `stow-build build` exits non-zero when any cargo phase failed — the
    // outcome is binary now: a live process reached this line means the
    // build ran to completion and whatever it plans is the whole closure.
    if upload_plan_len(&layout.upload_plan_path).await? == 0 {
        // Even an artifact-less task publishes its (empty) records
        // artifact — the webhook's existence check must find it.
        push_records(&state, &task, &layout.records_path, exe.as_path()).await?;
        state.mark_run(&task, "completed", Some("success"));
        return post_workflow_run(&state, &task, "success", None).await;
    }

    populate_mock_registry(&exe, &state, &task, &layout).await?;
    push_records(&state, &task, &layout.records_path, exe.as_path()).await?;
    state.mark_run(&task, "completed", Some("success"));
    post_workflow_run(&state, &task, "success", None).await
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
    state.mark_run(task, "completed", Some("failure"));
    post_workflow_run(state, task, "failure", Some(error.clone())).await?;
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

/// POST a synthetic `workflow_run` `completed` webhook to the edge — the
/// exact event shape and signature header GitHub delivers, so the mock
/// edge verifies the same HMAC the production one does.
async fn post_workflow_run(
    state: &LocalServerState,
    task: &BuildTaskPayload,
    conclusion: &str,
    error: Option<String>,
) -> stow_types::error::Result<()> {
    const MAX_ATTEMPTS: u32 = 5;
    let task_id = task.task_id.as_str();
    if let Some(error) = &error {
        tracing::warn!(task_id, %error, "workflow_run reports {conclusion}");
    }
    // The production pin: same path/branch/event/repository fields the
    // webhook requires, with the run title `build-crate.yml` would stamp.
    let payload = serde_json::json!({
        "action": "completed",
        "repository": {"full_name": stow_types::trusted_builder::REPOSITORY},
        "workflow_run": {
            "id": blake3::hash(task_id.as_bytes()).as_bytes()[..8]
                .iter()
                .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)),
            "name": "build-crate.yml",
            "path": format!(".github/workflows/{}", stow_types::trusted_builder::WORKFLOW_FILE),
            "event": "workflow_dispatch",
            "display_title": stow_types::records::run_title(task.rustc_version.as_str(), task_id),
            "head_branch": stow_types::trusted_builder::BRANCH,
            "conclusion": conclusion,
            "html_url": format!("http://{}/tasks/{task_id}", state.listen),
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
