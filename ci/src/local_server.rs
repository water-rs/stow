//! Dev-only local CI dispatch server.
//!
//! Activated via `stow-build serve`. Implements `POST /dispatch` so a
//! locally-running edge worker can dispatch a `BuildTaskPayload` for an
//! end-to-end test run without touching real GitHub Actions.
//!
//! Uses skyzen + skyzen-hyper for routing so the same DSL is shared with the
//! edge worker and there is exactly one HTTP server framework in the
//! workspace. async-net provides a futures-compatible TCP listener so we
//! avoid the tokio-IO / futures-IO bridging dance.

use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};

use async_net::TcpListener;
use executor_core::tokio::TokioGlobal;
use futures_lite::stream;
use skyzen::Server;
use skyzen::routing::{CreateRouteNode, Route, Router};
use skyzen::utils::{Json, State};
use skyzen::{Body, Response, StatusCode};
use stow_types::api::{BuildCompleteReport, BuildTaskPayload};
use tokio::time::{Duration, sleep};
use zenwave::{Client, ResponseExt};

/// Per-process state injected into every `/dispatch` invocation.
#[derive(Clone, Debug)]
pub struct LocalServerState {
    /// Scheduler `/complete` URL prefix (no trailing slash).
    pub scheduler_url: String,
    /// Edge URL prefix (no trailing slash). The local CI server appends
    /// `/api/v1/admin/artifacts/register` for trusted-CI registration —
    /// the same endpoint production CI uses.
    pub edge_url: String,
    /// Filesystem path to the mock cosign public key.
    pub mock_public_key_path: String,
    /// Filesystem path to the mock cosign private key.
    pub mock_private_key_path: String,
    /// Root directory the mock OCI registry serves out of.
    pub mock_registry_root: String,
    /// Auth token used by `/api/v1/scheduler/*` endpoints.
    pub scheduler_auth_token: String,
    /// Auth token used by `/api/v1/admin/artifacts/register`.
    pub register_auth_token: String,
}

#[derive(Debug, serde::Deserialize)]
struct RepositoryDispatchEvent {
    client_payload: BuildTaskPayload,
}

#[derive(Debug, serde::Serialize)]
struct DispatchResponse {
    ok: bool,
}

/// Bind and serve the dev dispatch endpoint.
pub async fn serve(listen: SocketAddr, state: LocalServerState) -> stow_types::error::Result<()> {
    let router = build_router(state);

    let listener = TcpListener::bind(listen)
        .await
        .map_err(|error| stow_types::stow_error!("bind local ci server {}: {error}", listen))?;
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
    Route::new(("/dispatch".post(dispatch),))
        .with(State(state))
        .build()
}

async fn dispatch(
    State(state): State<LocalServerState>,
    Json(event): Json<RepositoryDispatchEvent>,
) -> Response {
    let task = event.client_payload;
    let state_for_task = state.clone();
    tokio::spawn(async move {
        if let Err(error) = run_dispatched_task(state_for_task, task.clone()).await {
            tracing::error!(task_id = %task.task_id, %error, "local CI dispatched task failed");
            if let Err(report_error) =
                report_failed_task(&state, &task, format!("local CI dispatch failed: {error}"))
                    .await
            {
                tracing::error!(
                    task_id = %task.task_id,
                    %report_error,
                    "failed to report local CI task failure to scheduler"
                );
            }
        }
    });
    let body = serde_json::to_vec(&DispatchResponse { ok: true })
        .expect("DispatchResponse always serializes");
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::ACCEPTED;
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
    let report = BuildCompleteReport {
        task_id: task.task_id.clone(),
        success: false,
        error: Some(error),
        artifacts_uploaded: 0,
    };
    post_json(
        &format!("{}/complete", state.scheduler_url.trim_end_matches('/')),
        &report,
        Some((
            "x-stow-scheduler-token",
            state.scheduler_auth_token.as_str(),
        )),
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

async fn run_dispatched_task(
    state: LocalServerState,
    task: BuildTaskPayload,
) -> stow_types::error::Result<()> {
    let task_json = serde_json::to_string(&task)?;
    let exe = std::env::current_exe()?;
    let dispatch_root = std::env::current_dir()?
        .join(".tmp")
        .join("local-ci-dispatch");
    std::fs::create_dir_all(&dispatch_root)?;
    let task_root = dispatch_root.join(task_directory_name(&task.task_id)?);
    if task_root.exists() {
        std::fs::remove_dir_all(&task_root)?;
    }
    std::fs::create_dir_all(&task_root)?;
    let output_dir = task_root.join("output");
    let upload_plan_path = output_dir.join("upload-plan.json");
    let records_path = task_root.join("records.json");

    // The child is the untrusted build stage: it gets the task and nothing
    // else, exactly as the production build job does.
    let status = async_process::Command::new(&exe)
        .arg("build")
        .arg("--output-dir")
        .arg(&output_dir)
        .env_remove("SCHEDULER_URL")
        .env_remove("SCHEDULER_AUTH_TOKEN")
        .env_remove("STOW_REGISTER_AUTH_TOKEN")
        .env("STOW_BUILD_WORKSPACE_ROOT", task_root.join("workspace"))
        .env("STOW_BUILD_TASK_JSON", &task_json)
        .status()
        .await?;
    if !status.success() {
        let report = BuildCompleteReport {
            task_id: task.task_id,
            success: false,
            error: Some(format!("stow-build exited with status {status}")),
            artifacts_uploaded: 0,
        };
        post_json(
            &format!("{}/complete", state.scheduler_url.trim_end_matches('/')),
            &report,
            Some((
                "x-stow-scheduler-token",
                state.scheduler_auth_token.as_str(),
            )),
        )
        .await?;
        return Err(stow_types::stow_error!(
            "stow-build failed with status {status}"
        ));
    }

    let upload_plan_bytes = async_fs::read(&upload_plan_path).await?;
    let upload_plan_json: serde_json::Value = serde_json::from_slice(&upload_plan_bytes)?;
    let upload_plan_len = upload_plan_json.as_array().map_or(0usize, Vec::len);
    if upload_plan_len == 0 {
        let report = BuildCompleteReport {
            task_id: task.task_id,
            success: true,
            error: None,
            artifacts_uploaded: 0,
        };
        post_json(
            &format!("{}/complete", state.scheduler_url.trim_end_matches('/')),
            &report,
            Some((
                "x-stow-scheduler-token",
                state.scheduler_auth_token.as_str(),
            )),
        )
        .await?;
        return Ok(());
    }

    let registry_sqlite = task_root.join("mock-registry.sqlite");
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
        .arg(&upload_plan_path)
        .arg("--registry-root")
        .arg(PathBuf::from(&state.mock_registry_root))
        .arg("--sqlite")
        .arg(&registry_sqlite)
        .arg("--private-key")
        .arg(PathBuf::from(&state.mock_private_key_path))
        .arg("--public-key")
        .arg(PathBuf::from(&state.mock_public_key_path))
        .arg("--records-out")
        .arg(&records_path)
        .status()
        .await?;
    if !populate_status.success() {
        let report = BuildCompleteReport {
            task_id: task.task_id,
            success: false,
            error: Some(format!(
                "mock registry populate exited with status {populate_status}"
            )),
            artifacts_uploaded: 0,
        };
        post_json(
            &format!("{}/complete", state.scheduler_url.trim_end_matches('/')),
            &report,
            Some((
                "x-stow-scheduler-token",
                state.scheduler_auth_token.as_str(),
            )),
        )
        .await?;
        return Err(stow_types::stow_error!(
            "mock registry populate failed with status {populate_status}"
        ));
    }

    let records_bytes = async_fs::read(&records_path).await?;
    let records: Vec<serde_json::Value> = serde_json::from_slice(&records_bytes)?;
    let artifact_count = records.len();
    // Match the production register path: each record costs the edge one D1
    // subrequest, so chunk within Workers' per-invocation budget.
    for chunk in records.chunks(32) {
        post_json(
            &format!(
                "{}/api/v1/admin/artifacts/register",
                state.edge_url.trim_end_matches('/')
            ),
            &chunk,
            Some(("x-stow-register-token", state.register_auth_token.as_str())),
        )
        .await?;
    }

    let report = BuildCompleteReport {
        task_id: task.task_id,
        success: true,
        error: None,
        artifacts_uploaded: u32::try_from(artifact_count)
            .map_err(|_| stow_types::stow_error!("artifact count {artifact_count} exceeds u32"))?,
    };
    post_json(
        &format!("{}/complete", state.scheduler_url.trim_end_matches('/')),
        &report,
        Some((
            "x-stow-scheduler-token",
            state.scheduler_auth_token.as_str(),
        )),
    )
    .await?;
    Ok(())
}

async fn post_json(
    url: &str,
    payload: &(impl serde::Serialize + Sync),
    auth: Option<(&str, &str)>,
) -> stow_types::error::Result<()> {
    const MAX_ATTEMPTS: u32 = 5;
    let mut last_error: Option<stow_types::error::Error> = None;

    for attempt in 0..MAX_ATTEMPTS {
        let mut client = zenwave::client();
        let builder = client.post(url)?;
        let builder = if let Some((header, token)) = auth {
            builder.header(header, token)?
        } else {
            builder
        };
        let attempt_result = match builder.json_body(payload)?.await {
            Ok(response) => response.error_for_status().await.map(|_| ()),
            Err(error) => Err(error),
        };
        match attempt_result {
            Ok(()) => return Ok(()),
            Err(error) => {
                last_error = Some(error.into());
                if attempt + 1 < MAX_ATTEMPTS {
                    sleep(Duration::from_millis(250)).await;
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        stow_types::stow_error!("post_json: all {MAX_ATTEMPTS} attempts failed")
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
