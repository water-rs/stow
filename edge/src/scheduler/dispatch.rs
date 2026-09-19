use skyzen_cloudflare::{CfFetch, worker};

use crate::cf_http;
use crate::github_app::InstallationToken;
use crate::scheduler::queue::QueuedTask;

/// How a dispatch pass sends claimed tasks out, resolved once per pass
/// from the Worker's bindings.
pub enum DispatchCredential {
    /// `STOW_LOCAL_CI_URL` — posts to the local dispatcher with no
    /// `Authorization` header.
    LocalCi(String),
    /// A GitHub App installation token minted by [`crate::github_app`],
    /// sent as the `workflow_dispatch` bearer.
    GitHub(InstallationToken),
}

/// Trigger a GitHub Actions run of the trusted build workflow for a crate.
///
/// Production dispatches `workflow_dispatch` on the trusted branch: a
/// `repository_dispatch` event would run the workflow from the default
/// branch, whose certificate identity no client trusts. The whole task
/// travels as one JSON input so the publish job receives it from the
/// scheduler rather than from the build job.
///
/// Uses `CfFetch` (Cloudflare Workers' native fetch binding) to POST to the
/// GitHub API directly. We do not route this through `zenwave` because the
/// edge worker only ever runs in the Cloudflare runtime and `CfFetch` is the
/// canonical primitive there.
pub async fn trigger_build(
    task: &QueuedTask,
    credential: &DispatchCredential,
    repo: &str,
) -> Result<(), DispatchError> {
    let task_payload = serde_json::json!({
        "task_id": task.task_id,
        "crate_name": task.crate_name,
        "version": task.version,
        "features_json": task.features_json,
        "target": task.target,
        "rustc_version": task.rustc_version,
        "preserve_lockfile": task.preserve_lockfile,
        "project_source": task.project_source,
    });

    let (url, request) = match credential {
        DispatchCredential::LocalCi(local_ci_url) => {
            let url = format!("{}/dispatch", local_ci_url.trim_end_matches('/'));
            let payload = serde_json::json!({
                "event_type": "build-crate",
                "client_payload": task_payload,
            });
            let request = build_local_dispatch_request(&url, &payload)?;
            (url, request)
        }
        DispatchCredential::GitHub(token) => {
            let url = format!(
                "https://api.github.com/repos/{repo}/actions/workflows/{}/dispatches",
                stow_types::trusted_builder::WORKFLOW_FILE
            );
            let task_json = serde_json::to_string(&task_payload)
                .map_err(|error| DispatchError::Network(error.to_string()))?;
            let payload = serde_json::json!({
                "ref": stow_types::trusted_builder::BRANCH,
                "inputs": { "task": task_json },
            });
            let request = build_dispatch_request(&url, &token.token, &payload)?;
            (url, request)
        }
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
    token: &str,
    payload: &serde_json::Value,
) -> Result<worker::Request, DispatchError> {
    let bearer = format!("Bearer {token}");
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
    #[error("GitHub App installation token mint failed: {0}")]
    TokenMint(String),
    #[error("GitHub API error: {0}")]
    GitHubApi(u16),
}
