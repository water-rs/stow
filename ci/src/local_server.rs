use std::net::SocketAddr;
use std::path::PathBuf;

use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use stow_types::api::{BuildCompleteReport, BuildTaskPayload};
use tokio::net::TcpListener;
use tokio::time::{Duration, sleep};
use zenwave::Client;

#[derive(Clone)]
pub struct LocalServerState {
    pub scheduler_url: String,
    pub register_url: String,
    pub mock_public_key_path: String,
    pub mock_private_key_path: String,
    pub mock_registry_root: String,
    pub scheduler_auth_token: String,
}

#[derive(Debug, serde::Deserialize)]
struct RepositoryDispatchEvent {
    client_payload: BuildTaskPayload,
}

pub async fn serve(listen: SocketAddr, state: LocalServerState) -> stow_types::error::Result<()> {
    let app = Router::new()
        .route("/dispatch", post(dispatch))
        .with_state(state);
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|error| stow_types::stow_error!("bind local ci server {}: {error}", listen))?;
    tracing::info!(%listen, "local CI server listening");
    axum::serve(listener, app)
        .await
        .map_err(|error| stow_types::stow_error!("serve local ci server: {error}"))
}

async fn dispatch(
    State(state): State<LocalServerState>,
    Json(event): Json<RepositoryDispatchEvent>,
) -> Result<(StatusCode, Json<serde_json::Value>), StatusCode> {
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
    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({"ok": true}))))
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
        Some(state.scheduler_auth_token.as_str()),
    )
    .await
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
    let task_root = dispatch_root.join(&task.task_id);
    if task_root.exists() {
        std::fs::remove_dir_all(&task_root)?;
    }
    std::fs::create_dir_all(&task_root)?;
    let upload_plan_path = task_root.join("upload-plan.json");
    let records_path = task_root.join("records.json");

    let status = async_process::Command::new(&exe)
        .env_remove("STOW_LOCAL_CI_LISTEN")
        .env_remove("SCHEDULER_URL")
        .env_remove("SCHEDULER_AUTH_TOKEN")
        .env_remove("STOW_REGISTER_URL")
        .env("STOW_BUILD_ONLY", "1")
        .env("STOW_BUILD_WORKSPACE_ROOT", task_root.join("workspace"))
        .env("STOW_BUILD_TASK_JSON", &task_json)
        .env("STOW_UPLOAD_PLAN_PATH", &upload_plan_path)
        .env("STOW_ARTIFACT_RECORDS_PATH", &records_path)
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
            Some(state.scheduler_auth_token.as_str()),
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
            Some(state.scheduler_auth_token.as_str()),
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
        .join("stow-mock-registry");
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
            Some(state.scheduler_auth_token.as_str()),
        )
        .await?;
        return Err(stow_types::stow_error!(
            "mock registry populate failed with status {populate_status}"
        ));
    }

    let records_bytes = async_fs::read(&records_path).await?;
    let records_json: serde_json::Value = serde_json::from_slice(&records_bytes)?;
    let artifact_count = records_json.as_array().map_or(0usize, Vec::len);
    post_json(
        &format!("{}/register", state.register_url.trim_end_matches('/')),
        &records_json,
        None,
    )
    .await?;

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
        Some(state.scheduler_auth_token.as_str()),
    )
    .await?;
    Ok(())
}

async fn post_json(
    url: &str,
    payload: &impl serde::Serialize,
    scheduler_auth_token: Option<&str>,
) -> stow_types::error::Result<()> {
    const MAX_ATTEMPTS: u32 = 5;
    let mut last_error: Option<stow_types::error::Error> = None;

    for attempt in 0..MAX_ATTEMPTS {
        let mut client = zenwave::client();
        let builder = client.post(url)?;
        let builder = if let Some(token) = scheduler_auth_token {
            builder.header("x-stow-scheduler-token", token)?
        } else {
            builder
        };
        match builder.json_body(payload)?.await {
            Ok(_) => return Ok(()),
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
