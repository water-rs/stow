use stow_types::api::BuildCompleteReport;
use zenwave::{Client, ResponseExt};

use crate::auth;

const SCHEDULER_URL_ENV: &str = "SCHEDULER_URL";

pub async fn report_completion(report: &BuildCompleteReport) -> stow_types::error::Result<()> {
    let base_url = std::env::var(SCHEDULER_URL_ENV)
        .map_err(|_| stow_types::stow_error!("missing required {SCHEDULER_URL_ENV}"))?;
    let token = auth::edge_bearer().await?;

    let url = format!("{}/complete", base_url.trim_end_matches('/'));
    let mut client = zenwave::client();
    let builder = client
        .post(&url)?
        .header("Authorization", format!("Bearer {token}"))?;
    builder
        .json_body(report)?
        .await?
        .error_for_status()
        .await
        .map_err(|error| {
            stow_types::stow_error!("scheduler rejected completion report at {url}: {error}")
        })?;
    tracing::info!(
        task_id = %report.task_id,
        success = report.success,
        partial = report.partial,
        artifacts_uploaded = report.artifacts_uploaded,
        "reported build completion to scheduler"
    );
    Ok(())
}
