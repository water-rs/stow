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

/// The run identity a successful `workflow_dispatch` returns — GitHub's
/// `return_run_details` response (`workflow_run_id`, `run_url`,
/// `html_url`); the local-CI mock answers the same fields. The build
/// lane binds `workflow_run_id` to the claimed row's generation so a
/// `workflow_run` completion applies only to the run that generation
/// dispatched.
pub struct DispatchedRun {
    /// The Actions run id GitHub assigned the dispatched run.
    pub workflow_run_id: u64,
    /// The run's API URL.
    pub run_url: String,
    /// The run's browser URL.
    pub html_url: String,
}

/// Trigger a GitHub Actions run of the trusted build workflow for a crate.
///
/// Production dispatches `workflow_dispatch` on the trusted branch: a
/// `repository_dispatch` event would run the workflow from the default
/// branch, whose certificate identity no client trusts. The whole task
/// travels as one JSON input so the publish job receives it from the
/// scheduler rather than from the build job. The response's run id is
/// the generation's binding — see [`crate::scheduler::queue::bind_dispatch_run`].
pub async fn trigger_build(
    task: &QueuedTask,
    credential: &DispatchCredential,
    repo: &str,
    pool: &OutboundPool,
) -> Result<DispatchedRun, DispatchError> {
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
    let response = send_workflow_dispatch(
        stow_types::trusted_builder::WORKFLOW_FILE,
        "build-crate",
        "task",
        &payload,
        true,
        credential,
        repo,
        pool,
    )
    .await?;
    let body = response
        .into_inner()
        .text()
        .await
        .map_err(DispatchError::Response)?;
    decode_build_run_details(&body)
        .inspect(|_| {
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
/// `workflow_run` webhook correlates back to the request id. The resolve
/// lane fences on the record's `attempt`, so a successful dispatch needs
/// only its HTTP status and does not decode a build run-details body.
pub async fn trigger_resolve(
    dispatch: &stow_types::api::RequestDispatch,
    credential: &DispatchCredential,
    repo: &str,
    pool: &OutboundPool,
) -> Result<(), DispatchError> {
    let input = serde_json::to_value(dispatch)
        .map_err(|error| DispatchError::Network(error.to_string()))?;
    send_workflow_dispatch(
        stow_types::trusted_builder::RESOLVE_WORKFLOW_FILE,
        "resolve-request",
        "request",
        &input,
        false,
        credential,
        repo,
        pool,
    )
    .await
    .map(|_| ())
    .inspect(|_| {
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
/// The build caller reads the returned body for the run identity. The
/// resolve caller only needs the successful status; its workflow does not
/// bind a build generation and therefore does not require a run-details
/// body.
///
/// Uses `CfFetch` (Cloudflare Workers' native fetch binding) to POST to the
/// GitHub API directly. We do not route this through `zenwave` because the
/// edge worker only ever runs in the Cloudflare runtime and `CfFetch` is the
/// canonical primitive there.
async fn send_workflow_dispatch(
    workflow_file: &str,
    event_type: &str,
    input_name: &str,
    input: &serde_json::Value,
    return_run_details: bool,
    credential: &DispatchCredential,
    repo: &str,
    pool: &OutboundPool,
) -> Result<GuardedResponse<worker::Response>, DispatchError> {
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
            let payload = github_dispatch_payload(input_name, input_json, return_run_details);
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

    ensure_success_status(resp.get_ref().status_code())?;
    Ok(resp)
}

fn github_dispatch_payload(
    input_name: &str,
    input_json: String,
    return_run_details: bool,
) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "ref": stow_types::trusted_builder::BRANCH,
        "inputs": { input_name: input_json },
    });
    if return_run_details {
        payload["return_run_details"] = serde_json::Value::Bool(true);
    }
    payload
}

fn ensure_success_status(status: u16) -> Result<(), DispatchError> {
    if !(200..300).contains(&status) {
        return Err(DispatchError::GitHubApi(status));
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct DispatchRunDetails {
    workflow_run_id: u64,
    run_url: String,
    html_url: String,
}

fn decode_build_run_details(body: &str) -> Result<DispatchedRun, DispatchError> {
    serde_json::from_str::<DispatchRunDetails>(body)
        .map(|details| DispatchedRun {
            workflow_run_id: details.workflow_run_id,
            run_url: details.run_url,
            html_url: details.html_url,
        })
        .map_err(|error| DispatchError::Response(format!("{error}: {body}")))
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
            ("X-GitHub-Api-Version", "2022-11-28"),
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
    /// The dispatch POST succeeded but its run-details body did not
    /// read or decode — the run may exist unbound, so the caller
    /// abandons the generation and lets a fresh one claim.
    #[error("dispatch response unreadable: {0}")]
    Response(String),
}

#[cfg(test)]
mod tests {
    use super::{decode_build_run_details, ensure_success_status, github_dispatch_payload};

    #[test]
    fn resolve_success_uses_status_without_run_details_body() {
        for _body in ["", "{}", "not-json"] {
            ensure_success_status(204).expect("successful resolve dispatch status");
        }
        assert!(
            github_dispatch_payload("request", "{}".to_owned(), false)
                .get("return_run_details")
                .is_none()
        );
        assert!(
            github_dispatch_payload("task", "{}".to_owned(), true)
                .get("return_run_details")
                .is_some()
        );
    }

    #[test]
    fn build_dispatch_requires_run_details_identity() {
        for body in ["", "{}", "{\"workflow_run_id\":\"not-a-number\"}"] {
            assert!(decode_build_run_details(body).is_err(), "body: {body:?}");
        }
        assert!(
            decode_build_run_details(r#"{"workflow_run_id":42,"run_url":"run","html_url":"html"}"#)
                .is_ok()
        );
    }
}
