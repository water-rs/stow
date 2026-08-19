use skyzen_cloudflare::{CfFetch, worker};

use crate::cf_http;
use crate::scheduler::queue::QueuedTask;

/// Trigger a GitHub Actions `repository_dispatch` event to build a crate.
///
/// Uses `CfFetch` (Cloudflare Workers' native fetch binding) to POST to the
/// GitHub API directly. We do not route this through `zenwave` because the
/// edge worker only ever runs in the Cloudflare runtime and `CfFetch` is the
/// canonical primitive there.
pub async fn trigger_build(
    task: &QueuedTask,
    gh_token: &str,
    repo: &str,
    local_ci_url: Option<&str>,
) -> Result<(), DispatchError> {
    let payload = serde_json::json!({
        "event_type": "build-crate",
        "client_payload": {
            "task_id": task.task_id,
            "crate_name": task.crate_name,
            "version": task.version,
            "features_json": task.features_json,
            "target": task.target,
            "rustc_version": task.rustc_version,
            "preserve_lockfile": task.preserve_lockfile,
        }
    });

    let (url, request) = if let Some(local_ci_url) = local_ci_url {
        let url = format!("{}/dispatch", local_ci_url.trim_end_matches('/'));
        let request = build_local_dispatch_request(&url, &payload)?;
        (url, request)
    } else {
        let url = format!("https://api.github.com/repos/{repo}/dispatches");
        let request = build_dispatch_request(&url, gh_token, &payload)?;
        (url, request)
    };
    let resp = CfFetch
        .request(&request)
        .await
        .map_err(|error| DispatchError::Network(error.to_string()))?;

    let status = resp.status_code();
    if (200..300).contains(&status) {
        tracing::info!(
            task_id = %task.task_id,
            crate_name = %task.crate_name,
            target = %task.target,
            rustc_version = %task.rustc_version,
            url = %url,
            "dispatched build"
        );
        Ok(())
    } else {
        tracing::error!(task_id = %task.task_id, status, "GH Actions dispatch failed");
        Err(DispatchError::GitHubApi(status))
    }
}

fn build_dispatch_request(
    url: &str,
    gh_token: &str,
    payload: &serde_json::Value,
) -> Result<worker::Request, DispatchError> {
    let bearer = format!("Bearer {gh_token}");
    cf_http::json_request(
        worker::Method::Post,
        url,
        payload,
        &[
            ("Accept", "application/vnd.github+json"),
            ("User-Agent", "stow-scheduler"),
            ("Authorization", &bearer),
        ],
    )
    .map_err(|error| DispatchError::Network(error.to_string()))
}

fn build_local_dispatch_request(
    url: &str,
    payload: &serde_json::Value,
) -> Result<worker::Request, DispatchError> {
    cf_http::json_request(worker::Method::Post, url, payload, &[])
        .map_err(|error| DispatchError::Network(error.to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("network error: {0}")]
    Network(String),
    #[error("GitHub API error: {0}")]
    GitHubApi(u16),
}
