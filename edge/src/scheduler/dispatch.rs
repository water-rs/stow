use skyzen_cloudflare::{CfFetch, worker};

#[derive(Debug, Clone)]
pub struct QueuedTask {
    pub task_id: String,
    pub crate_name: String,
    pub version: String,
    pub features_json: String,
    pub target: String,
    pub rustc_version: String,
}

/// Trigger a GitHub Actions `repository_dispatch` event to build a crate.
///
/// Uses zenwave to POST to the GitHub API.
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
    let resp = CfFetch::default()
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
    let body =
        serde_json::to_vec(payload).map_err(|error| DispatchError::Network(error.to_string()))?;
    let headers = worker::Headers::new();
    headers
        .set("Accept", "application/vnd.github+json")
        .map_err(|error| DispatchError::Network(error.to_string()))?;
    headers
        .set("User-Agent", "stow-scheduler")
        .map_err(|error| DispatchError::Network(error.to_string()))?;
    headers
        .set("Authorization", &format!("Bearer {gh_token}"))
        .map_err(|error| DispatchError::Network(error.to_string()))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|error| DispatchError::Network(error.to_string()))?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post);
    init.with_headers(headers);
    let bytes = js_sys::Uint8Array::from(body.as_slice());
    init.with_body(Some(wasm_bindgen::JsValue::from(bytes)));
    worker::Request::new_with_init(url, &init)
        .map_err(|error| DispatchError::Network(error.to_string()))
}

fn build_local_dispatch_request(
    url: &str,
    payload: &serde_json::Value,
) -> Result<worker::Request, DispatchError> {
    let body =
        serde_json::to_vec(payload).map_err(|error| DispatchError::Network(error.to_string()))?;
    let headers = worker::Headers::new();
    headers
        .set("Content-Type", "application/json")
        .map_err(|error| DispatchError::Network(error.to_string()))?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post);
    init.with_headers(headers);
    let bytes = js_sys::Uint8Array::from(body.as_slice());
    init.with_body(Some(wasm_bindgen::JsValue::from(bytes)));
    worker::Request::new_with_init(url, &init)
        .map_err(|error| DispatchError::Network(error.to_string()))
}

#[derive(Debug)]
pub enum DispatchError {
    Network(String),
    GitHubApi(u16),
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DispatchError::Network(e) => write!(f, "network error: {e}"),
            DispatchError::GitHubApi(status) => write!(f, "GitHub API error: {status}"),
        }
    }
}
