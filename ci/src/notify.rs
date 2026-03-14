use stow_types::api::BuildCompleteReport;
use zenwave::Client;

const SCHEDULER_URL_ENV: &str = "SCHEDULER_URL";

pub async fn maybe_report_completion(report: &BuildCompleteReport) -> eyre::Result<()> {
    let Ok(base_url) = std::env::var(SCHEDULER_URL_ENV) else {
        return Ok(());
    };

    let url = format!("{}/complete", base_url.trim_end_matches('/'));
    let mut client = zenwave::client();
    client.post(&url).json_body(report).await?;
    tracing::info!(
        task_id = %report.task_id,
        success = report.success,
        artifacts_uploaded = report.artifacts_uploaded,
        "reported build completion to scheduler"
    );
    Ok(())
}
