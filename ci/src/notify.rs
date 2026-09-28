use stow_types::api::BuildCompleteReport;
use zenwave::{Client, ResponseExt};

use crate::auth;

const SCHEDULER_URL_ENV: &str = "SCHEDULER_URL";

/// POST the build's completion report to the scheduler.
///
/// Returns `false` when the scheduler answered 409 — the report's attempt
/// no longer matches the task's live state, so a newer attempt owns it
/// (the stale-dispatch lease expired the original while this run was
/// still working). The conflicting report is information, not an error:
/// the queue already moved on, and the caller's job is to exit quietly
/// rather than fail the run over an outcome that cannot apply (stow#431).
pub async fn report_completion(report: &BuildCompleteReport) -> stow_types::error::Result<bool> {
    let base_url = std::env::var(SCHEDULER_URL_ENV)
        .map_err(|_| stow_types::stow_error!("missing required {SCHEDULER_URL_ENV}"))?;
    let token = auth::edge_bearer().await?;

    let url = format!("{}/complete", base_url.trim_end_matches('/'));
    let mut client = zenwave::client();
    let builder = client
        .post(&url)?
        .header("Authorization", format!("Bearer {token}"))?;
    match builder.json_body(report)?.await?.error_for_status().await {
        Ok(_) => {}
        Err(error) if is_attempt_conflict(&error) => return Ok(false),
        Err(error) => {
            return Err(stow_types::stow_error!(
                "scheduler rejected completion report at {url}: {error}"
            ));
        }
    }
    tracing::info!(
        task_id = %report.task_id,
        success = report.success,
        artifacts_uploaded = report.artifacts_uploaded,
        "reported build completion to scheduler"
    );
    Ok(true)
}

/// Whether an edge answer is the 409 a superseded or duplicate report
/// draws — never a retryable condition and never a failure of this run.
pub fn is_attempt_conflict(error: &zenwave::Error) -> bool {
    matches!(
        error,
        zenwave::Error::Http { status, .. } if *status == zenwave::StatusCode::CONFLICT
    )
}
