use skyzen_cloudflare::{CfFetch, worker};

use crate::cf_http;
use crate::fetch_guard::{GuardedResponse, OutboundPool};
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
pub async fn trigger_build(
    task: &QueuedTask,
    credential: &DispatchCredential,
    repo: &str,
    pool: &OutboundPool,
) -> Result<(), DispatchError> {
    let payload = serde_json::json!({
        "task_id": task.task_id,
        "attempt": task.attempt,
        "crate_name": task.crate_name,
        "version": task.version,
        "features_json": task.features_json,
        "target": task.target,
        "rustc_version": task.rustc_version,
        "host_side": task.host_side,
        "preserve_lockfile": task.preserve_lockfile,
        "dep_pins": task.dep_pins,
    });
    trigger_workflow(
        stow_types::trusted_builder::WORKFLOW_FILE,
        "build-crate",
        "task",
        &payload,
        credential,
        repo,
        pool,
    )
    .await
    .inspect(|()| {
        tracing::info!(
            task_id = %task.task_id,
            crate_name = %task.crate_name,
            target = %task.target,
            rustc_version = %task.rustc_version,
            "dispatched build"
        );
    })
    .inspect_err(|error| {
        tracing::error!(task_id = %task.task_id, %error, "GH Actions dispatch failed");
    })
}

/// Trigger a `resolve-request.yml` run for an admitted human request
/// (stow#428) — the request lane's resolve step runs on Actions, not in
/// the Worker.
///
/// Same dispatch mechanics as [`trigger_build`]: the whole
/// [`stow_types::api::RequestDispatch`] travels as one JSON
/// `workflow_dispatch` input on the trusted branch, and the record's
/// run-name (`resolve-a{attempt}-{request_id}`) is what the
/// `workflow_run` webhook correlates back to the request id.
pub async fn trigger_resolve(
    dispatch: &stow_types::api::RequestDispatch,
    credential: &DispatchCredential,
    repo: &str,
    pool: &OutboundPool,
) -> Result<(), DispatchError> {
    let input = serde_json::to_value(dispatch)
        .map_err(|error| DispatchError::Network(error.to_string()))?;
    trigger_workflow(
        stow_types::trusted_builder::RESOLVE_WORKFLOW_FILE,
        "resolve-request",
        "request",
        &input,
        credential,
        repo,
        pool,
    )
    .await
    .inspect(|()| {
        tracing::info!(
            request_id = %dispatch.request_id,
            attempt = dispatch.attempt,
            crate_name = %dispatch.crate_name,
            rustc_version = %dispatch.rustc_version,
            "dispatched resolve run"
        );
    })
    .inspect_err(|error| {
        tracing::error!(
            request_id = %dispatch.request_id,
            %error,
            "GH Actions resolve dispatch failed"
        );
    })
}

/// The shared `workflow_dispatch` fan-out one dispatch hop costs.
///
/// `input_name` is the workflow's single input (`task` for
/// `build-crate.yml`, `request` for `resolve-request.yml`) and `input`
/// its JSON-encoded content — GitHub wants inputs as strings, while the
/// local-CI arm posts the payload verbatim as `client_payload`.
///
/// Uses `CfFetch` (Cloudflare Workers' native fetch binding) to POST to the
/// GitHub API directly. We do not route this through `zenwave` because the
/// edge worker only ever runs in the Cloudflare runtime and `CfFetch` is the
/// canonical primitive there.
async fn trigger_workflow(
    workflow_file: &str,
    event_type: &str,
    input_name: &str,
    input: &serde_json::Value,
    credential: &DispatchCredential,
    repo: &str,
    pool: &OutboundPool,
) -> Result<(), DispatchError> {
    let (url, request) = match credential {
        DispatchCredential::LocalCi(local_ci_url) => {
            let url = format!("{}/dispatch", local_ci_url.trim_end_matches('/'));
            let payload = serde_json::json!({
                "event_type": event_type,
                "client_payload": input,
            });
            let request = build_local_dispatch_request(&url, &payload)?;
            (url, request)
        }
        DispatchCredential::GitHub(token) => {
            let url = format!(
                "https://api.github.com/repos/{repo}/actions/workflows/{workflow_file}/dispatches"
            );
            let input_json = serde_json::to_string(input)
                .map_err(|error| DispatchError::Network(error.to_string()))?;
            let payload = serde_json::json!({
                "ref": stow_types::trusted_builder::BRANCH,
                "inputs": { input_name: input_json },
            });
            let request = build_dispatch_request(&url, &token.token, &payload)?;
            (url, request)
        }
    };
    let _slot = pool.slot().await;
    let resp = CfFetch
        .request(&request)
        .await
        .map(GuardedResponse::new)
        .map_err(|error| DispatchError::Network(error.to_string()))?;

    let status = resp.get_ref().status_code();
    if (200..300).contains(&status) {
        tracing::info!(url = %url, input = input_name, "dispatched workflow");
        Ok(())
    } else {
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
