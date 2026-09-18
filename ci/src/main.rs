//! `stow-build`: the trusted CI runner that consumes a `BuildTaskPayload`
//! `repository_dispatch` event, builds the requested crate, scans the build
//! output for cacheable artifacts, packages them as OCI bundles, signs them
//! via Sigstore, pushes them to GHCR, and registers the result in D1 via the
//! Cloudflare REST API.
//!
//! This is the **only** path that produces signed artifacts and writes
//! authoritative records into D1.

mod capture;
mod dep_scan;
mod local_server;
mod notify;
mod plan;
mod register;
mod sign;
mod task;
mod upload;
mod workspace_mirror;
mod zstd_util;

use async_fs::{read_to_string, write};
use stow_types::api::BuildTaskPayload;
use tracing_subscriber::EnvFilter;

const GITHUB_EVENT_PATH_ENV: &str = "GITHUB_EVENT_PATH";
const STOW_BUILD_TASK_JSON_ENV: &str = "STOW_BUILD_TASK_JSON";
const STOW_SCAN_OUTPUT_PATH_ENV: &str = "STOW_SCAN_OUTPUT_PATH";
const STOW_UPLOAD_PLAN_PATH_ENV: &str = "STOW_UPLOAD_PLAN_PATH";
const STOW_OCI_DIGESTS_JSON_ENV: &str = "STOW_OCI_DIGESTS_JSON";
const STOW_ARTIFACT_RECORDS_PATH_ENV: &str = "STOW_ARTIFACT_RECORDS_PATH";
const STOW_LOCAL_CI_LISTEN_ENV: &str = "STOW_LOCAL_CI_LISTEN";
const STOW_EDGE_URL_ENV: &str = "STOW_EDGE_URL";
const STOW_MOCK_PUBLIC_KEY_PATH_ENV: &str = "STOW_MOCK_PUBLIC_KEY_PATH";
const STOW_MOCK_PRIVATE_KEY_PATH_ENV: &str = "STOW_MOCK_PRIVATE_KEY_PATH";
const STOW_MOCK_REGISTRY_ROOT_ENV: &str = "STOW_MOCK_REGISTRY_ROOT";
const SCHEDULER_URL_ENV: &str = "SCHEDULER_URL";
const SCHEDULER_AUTH_TOKEN_ENV: &str = "SCHEDULER_AUTH_TOKEN";
const STOW_REGISTER_AUTH_TOKEN_ENV: &str = "STOW_REGISTER_AUTH_TOKEN";

/// When set to "1", CI only builds/scans/outputs files and skips push/sign/register/notify.
/// Used by the local CI server to run a subprocess that produces artifacts without
/// requiring GHCR, cosign, D1, or scheduler credentials.
const STOW_BUILD_ONLY_ENV: &str = "STOW_BUILD_ONLY";

fn main() -> stow_types::error::Result<()> {
    install_tracing();
    smol::block_on(run())
}

async fn run() -> stow_types::error::Result<()> {
    if let Ok(listen) = std::env::var(STOW_LOCAL_CI_LISTEN_ENV) {
        let listen = listen.parse().map_err(|error| {
            stow_types::stow_error!("parse {STOW_LOCAL_CI_LISTEN_ENV}: {error}")
        })?;
        let scheduler_url = std::env::var(SCHEDULER_URL_ENV).map_err(|_| {
            stow_types::stow_error!("missing {SCHEDULER_URL_ENV} for local CI server")
        })?;
        let edge_url = std::env::var(STOW_EDGE_URL_ENV).map_err(|_| {
            stow_types::stow_error!("missing {STOW_EDGE_URL_ENV} for local CI server")
        })?;
        let mock_public_key_path = std::env::var(STOW_MOCK_PUBLIC_KEY_PATH_ENV).map_err(|_| {
            stow_types::stow_error!("missing {STOW_MOCK_PUBLIC_KEY_PATH_ENV} for local CI server")
        })?;
        let mock_private_key_path =
            std::env::var(STOW_MOCK_PRIVATE_KEY_PATH_ENV).map_err(|_| {
                stow_types::stow_error!(
                    "missing {STOW_MOCK_PRIVATE_KEY_PATH_ENV} for local CI server"
                )
            })?;
        let mock_registry_root = std::env::var(STOW_MOCK_REGISTRY_ROOT_ENV).map_err(|_| {
            stow_types::stow_error!("missing {STOW_MOCK_REGISTRY_ROOT_ENV} for local CI server")
        })?;
        let scheduler_auth_token = std::env::var(SCHEDULER_AUTH_TOKEN_ENV).map_err(|_| {
            stow_types::stow_error!("missing {SCHEDULER_AUTH_TOKEN_ENV} for local CI server")
        })?;
        let register_auth_token = std::env::var(STOW_REGISTER_AUTH_TOKEN_ENV).map_err(|_| {
            stow_types::stow_error!("missing {STOW_REGISTER_AUTH_TOKEN_ENV} for local CI server")
        })?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                stow_types::stow_error!("build tokio runtime for local CI server: {error}")
            })?;
        return runtime.block_on(local_server::serve(
            listen,
            local_server::LocalServerState {
                scheduler_url,
                edge_url,
                mock_public_key_path,
                mock_private_key_path,
                mock_registry_root,
                scheduler_auth_token,
                register_auth_token,
            },
        ));
    }
    let args = std::env::args_os().collect::<Vec<_>>();
    if capture::is_rustc_wrapper_invocation(&args) {
        return capture::run_rustc_capture_wrapper(&args).await;
    }
    let build_only = std::env::var(STOW_BUILD_ONLY_ENV).ok().as_deref() == Some("1");
    let task = load_task_payload().await?;
    if build_only {
        async_main(&task).await?;
        return Ok(());
    }
    match async_main(&task).await {
        Ok(report) => {
            notify::report_completion(&report).await?;
            Ok(())
        }
        Err(error) => {
            notify::report_completion(&stow_types::api::BuildCompleteReport {
                task_id: task.task_id.clone(),
                success: false,
                error: Some(error.to_string()),
                artifacts_uploaded: 0,
            })
            .await?;
            Err(error)
        }
    }
}

async fn async_main(
    task: &BuildTaskPayload,
) -> stow_types::error::Result<stow_types::api::BuildCompleteReport> {
    let build_only = std::env::var(STOW_BUILD_ONLY_ENV).ok().as_deref() == Some("1");

    // Phase 1: Build + scan + plan (always runs)
    let workspace = task::build(task).await?;
    let manifest = task::read_built_manifest(&workspace).await?;
    let artifacts = dep_scan::scan_artifacts(&workspace, task).await?;
    let upload_plan = plan::build_upload_plan(&artifacts).await?;

    write_scan_output(&artifacts).await?;
    write_upload_plan(&upload_plan).await?;

    if build_only {
        tracing::info!(
            task_id = %task.task_id,
            artifacts = artifacts.len(),
            upload_plan_entries = upload_plan.len(),
            "build-only mode: skipping push/sign/register/notify"
        );
        // In build-only mode, write records from STOW_OCI_DIGESTS_JSON if available,
        // otherwise just write the plan and exit.
        let artifact_records = load_artifact_records(&upload_plan, None)?;
        write_artifact_records_output(artifact_records.as_deref()).await?;
        return Ok(stow_types::api::BuildCompleteReport {
            task_id: task.task_id.clone(),
            success: true,
            error: None,
            artifacts_uploaded: 0,
        });
    }

    // Phase 2: Push + sign + register (mandatory in production)
    let upload_outcome = upload::push_artifacts(&upload_plan).await?;
    sign::sign_artifacts(&upload_outcome.pushed_digests_by_reference).await?;
    let artifact_records =
        load_artifact_records(&upload_plan, Some(&upload_outcome.digests_by_reference))?
            .ok_or_else(|| {
                stow_types::stow_error!("artifact records must be available after push")
            })?;

    tracing::info!(
        task_id = %task.task_id,
        crate_name = %task.crate_name,
        version = %task.version,
        target = %task.target,
        workspace_root = %workspace.workspace_root().display(),
        manifest = %manifest.trim(),
        artifacts = artifacts.len(),
        upload_plan_entries = upload_plan.len(),
        artifact_records = artifact_records.len(),
        "trusted CI build completed"
    );

    write_artifact_records_output(Some(&artifact_records)).await?;
    register_artifacts(&artifact_records).await?;

    Ok(stow_types::api::BuildCompleteReport {
        task_id: task.task_id.clone(),
        success: true,
        error: None,
        artifacts_uploaded: upload_outcome.newly_pushed,
    })
}

fn load_artifact_records(
    upload_plan: &[stow_types::upload_plan::PlannedArtifact],
    pushed_digests: Option<&std::collections::BTreeMap<String, String>>,
) -> stow_types::error::Result<Option<Vec<stow_types::api::ArtifactRecord>>> {
    let digests_by_reference = if let Some(pushed_digests) = pushed_digests {
        pushed_digests.clone()
    } else {
        let Ok(raw_digests) = std::env::var(STOW_OCI_DIGESTS_JSON_ENV) else {
            return Ok(None);
        };
        serde_json::from_str::<std::collections::BTreeMap<String, String>>(&raw_digests).map_err(
            |error| stow_types::stow_error!("parse {STOW_OCI_DIGESTS_JSON_ENV}: {error}"),
        )?
    };

    let records =
        stow_types::upload_plan::build_artifact_records(upload_plan, &digests_by_reference)?;
    Ok(Some(records))
}

async fn load_task_payload() -> stow_types::error::Result<BuildTaskPayload> {
    if let Ok(raw_json) = std::env::var(STOW_BUILD_TASK_JSON_ENV) {
        tracing::info!("loading build task payload from STOW_BUILD_TASK_JSON");
        return serde_json::from_str(&raw_json)
            .map_err(|error| stow_types::stow_error!("parse {STOW_BUILD_TASK_JSON_ENV}: {error}"));
    }

    let event_path = std::env::var(GITHUB_EVENT_PATH_ENV).map_err(|_| {
        stow_types::stow_error!("missing {GITHUB_EVENT_PATH_ENV} and {STOW_BUILD_TASK_JSON_ENV}")
    })?;
    let event_body = read_to_string(&event_path).await?;
    let event: RepositoryDispatchEvent = serde_json::from_str(&event_body).map_err(|error| {
        stow_types::stow_error!("parse repository_dispatch event from {event_path}: {error}")
    })?;

    tracing::info!(event_path, "loading build task payload from GitHub event");
    Ok(event.client_payload)
}

async fn write_scan_output(
    artifacts: &[dep_scan::ScannedArtifact],
) -> stow_types::error::Result<()> {
    let Some(path) = std::env::var_os(STOW_SCAN_OUTPUT_PATH_ENV) else {
        return Ok(());
    };

    let encoded = serde_json::to_vec_pretty(artifacts)?;
    write(&path, encoded).await?;
    tracing::info!(
        output_path = %std::path::PathBuf::from(path).display(),
        artifacts = artifacts.len(),
        "wrote scanned artifact output"
    );
    Ok(())
}

async fn write_upload_plan(
    plan: &[stow_types::upload_plan::PlannedArtifact],
) -> stow_types::error::Result<()> {
    let Some(path) = std::env::var_os(STOW_UPLOAD_PLAN_PATH_ENV) else {
        return Ok(());
    };

    let encoded = serde_json::to_vec_pretty(plan)?;
    write(&path, encoded).await?;
    tracing::info!(
        output_path = %std::path::PathBuf::from(path).display(),
        artifacts = plan.len(),
        "wrote upload plan output"
    );
    Ok(())
}

async fn write_artifact_records_output(
    records: Option<&[stow_types::api::ArtifactRecord]>,
) -> stow_types::error::Result<()> {
    let Some(records) = records else {
        return Ok(());
    };
    let Some(path) = std::env::var_os(STOW_ARTIFACT_RECORDS_PATH_ENV) else {
        return Ok(());
    };

    let encoded = serde_json::to_vec_pretty(records)?;
    write(&path, encoded).await?;
    tracing::info!(
        output_path = %std::path::PathBuf::from(path).display(),
        artifacts = records.len(),
        "wrote artifact records output"
    );
    Ok(())
}

async fn register_artifacts(
    records: &[stow_types::api::ArtifactRecord],
) -> stow_types::error::Result<()> {
    register::register_artifacts(records).await
}

fn install_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        // stderr, never stdout: this binary also serves as the capture `rustc` wrapper.
        .with_writer(std::io::stderr)
        .try_init();
}

#[derive(Debug, serde::Deserialize)]
struct RepositoryDispatchEvent {
    client_payload: BuildTaskPayload,
}
