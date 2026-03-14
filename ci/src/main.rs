mod dep_scan;
mod notify;
mod plan;
mod register;
mod records;
mod sign;
mod task;
mod upload;

use async_fs::{read_to_string, write};
use stow_types::api::BuildTaskPayload;
use tracing_subscriber::EnvFilter;

const GITHUB_EVENT_PATH_ENV: &str = "GITHUB_EVENT_PATH";
const STOW_BUILD_TASK_JSON_ENV: &str = "STOW_BUILD_TASK_JSON";
const STOW_SCAN_OUTPUT_PATH_ENV: &str = "STOW_SCAN_OUTPUT_PATH";
const STOW_UPLOAD_PLAN_PATH_ENV: &str = "STOW_UPLOAD_PLAN_PATH";
const STOW_OCI_DIGESTS_JSON_ENV: &str = "STOW_OCI_DIGESTS_JSON";
const STOW_ARTIFACT_RECORDS_PATH_ENV: &str = "STOW_ARTIFACT_RECORDS_PATH";
const STOW_REGISTER_D1_ENV: &str = "STOW_REGISTER_D1";

fn main() -> eyre::Result<()> {
    install_tracing();
    smol::block_on(run())
}

async fn run() -> eyre::Result<()> {
    let task = load_task_payload().await?;
    match async_main(&task).await {
        Ok(report) => {
            notify::maybe_report_completion(&report).await?;
            Ok(())
        }
        Err(error) => {
            notify::maybe_report_completion(&stow_types::api::BuildCompleteReport {
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

async fn async_main(task: &BuildTaskPayload) -> eyre::Result<stow_types::api::BuildCompleteReport> {
    let workspace = task::build(&task).await?;
    let manifest = task::read_built_manifest(&workspace).await?;
    let artifacts = dep_scan::scan_artifacts(&workspace, &task).await?;
    let upload_plan = plan::build_upload_plan(&artifacts).await?;
    let upload_outcome = upload::maybe_push_artifacts(&upload_plan).await?;
    if let Some(upload_outcome) = &upload_outcome {
        sign::maybe_sign_artifacts(&upload_outcome.pushed_digests_by_reference).await?;
    }
    let artifact_records =
        load_artifact_records(&upload_plan, upload_outcome.as_ref().map(|outcome| &outcome.digests_by_reference))?;

    tracing::info!(
        task_id = %task.task_id,
        crate_name = %task.crate_name,
        version = %task.version,
        target = %task.target,
        workspace_root = %workspace.workspace_root().display(),
        manifest = %manifest.trim(),
        artifacts = artifacts.len(),
        upload_plan_entries = upload_plan.len(),
        artifact_records = artifact_records.as_ref().map_or(0, Vec::len),
        "trusted CI build skeleton completed"
    );

    write_scan_output(&artifacts).await?;
    write_upload_plan(&upload_plan).await?;
    write_artifact_records_output(artifact_records.as_deref()).await?;
    maybe_register_artifacts(artifact_records.as_deref()).await?;

    Ok(stow_types::api::BuildCompleteReport {
        task_id: task.task_id.clone(),
        success: true,
        error: None,
        artifacts_uploaded: upload_outcome
            .as_ref()
            .map(|outcome| outcome.newly_pushed)
            .unwrap_or(0),
    })
}

fn load_artifact_records(
    upload_plan: &[plan::PlannedArtifact],
    pushed_digests: Option<&std::collections::BTreeMap<String, String>>,
) -> eyre::Result<Option<Vec<stow_types::api::ArtifactRecord>>> {
    let digests_by_reference = if let Some(pushed_digests) = pushed_digests {
        pushed_digests.clone()
    } else {
        let Ok(raw_digests) = std::env::var(STOW_OCI_DIGESTS_JSON_ENV) else {
            return Ok(None);
        };
        serde_json::from_str::<std::collections::BTreeMap<String, String>>(&raw_digests)
            .map_err(|error| eyre::eyre!("parse {STOW_OCI_DIGESTS_JSON_ENV}: {error}"))?
    };

    let records = records::build_artifact_records(upload_plan, &digests_by_reference)?;
    Ok(Some(records))
}

async fn load_task_payload() -> eyre::Result<BuildTaskPayload> {
    if let Ok(raw_json) = std::env::var(STOW_BUILD_TASK_JSON_ENV) {
        tracing::info!("loading build task payload from STOW_BUILD_TASK_JSON");
        return serde_json::from_str(&raw_json)
            .map_err(|error| eyre::eyre!("parse {STOW_BUILD_TASK_JSON_ENV}: {error}"));
    }

    let event_path = std::env::var(GITHUB_EVENT_PATH_ENV)
        .map_err(|_| eyre::eyre!("missing {GITHUB_EVENT_PATH_ENV} and {STOW_BUILD_TASK_JSON_ENV}"))?;
    let event_body = read_to_string(&event_path).await?;
    let event: RepositoryDispatchEvent = serde_json::from_str(&event_body)
        .map_err(|error| eyre::eyre!("parse repository_dispatch event from {event_path}: {error}"))?;

    tracing::info!(event_path, "loading build task payload from GitHub event");
    Ok(event.client_payload)
}

async fn write_scan_output(artifacts: &[dep_scan::ScannedArtifact]) -> eyre::Result<()> {
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

async fn write_upload_plan(plan: &[plan::PlannedArtifact]) -> eyre::Result<()> {
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
) -> eyre::Result<()> {
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

async fn maybe_register_artifacts(
    records: Option<&[stow_types::api::ArtifactRecord]>,
) -> eyre::Result<()> {
    let Some(records) = records else {
        return Ok(());
    };
    if std::env::var(STOW_REGISTER_D1_ENV).ok().as_deref() != Some("1") {
        return Ok(());
    }

    for record in records {
        register::register_artifact(record).await?;
    }
    Ok(())
}

fn install_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

#[derive(Debug, serde::Deserialize)]
struct RepositoryDispatchEvent {
    client_payload: BuildTaskPayload,
}
