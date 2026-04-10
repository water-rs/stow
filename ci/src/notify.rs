use stow_types::api::BuildCompleteReport;
use zenwave::Client;

const SCHEDULER_URL_ENV: &str = "SCHEDULER_URL";
const SCHEDULER_AUTH_TOKEN_ENV: &str = "SCHEDULER_AUTH_TOKEN";
const SCHEDULER_AUTH_HEADER: &str = "x-stow-scheduler-token";

pub async fn report_completion(report: &BuildCompleteReport) -> stow_types::error::Result<()> {
    let base_url = std::env::var(SCHEDULER_URL_ENV)
        .map_err(|_| stow_types::stow_error!("missing required {SCHEDULER_URL_ENV}"))?;
    let token = std::env::var(SCHEDULER_AUTH_TOKEN_ENV)
        .map_err(|_| stow_types::stow_error!("missing required {SCHEDULER_AUTH_TOKEN_ENV}"))?;

    let url = format!("{}/complete", base_url.trim_end_matches('/'));
    let mut client = zenwave::client();
    let builder = client.post(&url)?.header(SCHEDULER_AUTH_HEADER, &token)?;
    builder.json_body(report)?.await?;
    tracing::info!(
        task_id = %report.task_id,
        success = report.success,
        artifacts_uploaded = report.artifacts_uploaded,
        "reported build completion to scheduler"
    );
    Ok(())
}
