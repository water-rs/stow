/// Trigger a GitHub Actions `repository_dispatch` event to build a crate.
///
/// Uses zenwave to POST to the GitHub API.
pub async fn trigger_build(
    task_id: &str,
    crate_name: &str,
    version: &str,
    target: &str,
    gh_token: &str,
    repo: &str,
) -> Result<(), DispatchError> {
    let url = format!("https://api.github.com/repos/{repo}/dispatches");

    let payload = serde_json::json!({
        "event_type": "build-crate",
        "client_payload": {
            "task_id": task_id,
            "crate_name": crate_name,
            "version": version,
            "target": target,
        }
    });

    let body = serde_json::to_vec(&payload).map_err(|e| DispatchError::Serialize(e.to_string()))?;

    let resp = zenwave::post(&url)
        .await
        .map_err(|e| DispatchError::Network(e.to_string()))?
        .header("Accept", "application/vnd.github+json")
        .map_err(|e| DispatchError::Network(e.to_string()))?
        .header("Authorization", &format!("Bearer {gh_token}"))
        .map_err(|e| DispatchError::Network(e.to_string()))?
        .header("User-Agent", "stow-scheduler")
        .map_err(|e| DispatchError::Network(e.to_string()))?
        .bytes_body(body)
        .send()
        .await
        .map_err(|e| DispatchError::Network(e.to_string()))?;

    if resp.status().is_success() || resp.status().as_u16() == 204 {
        tracing::info!(task_id, crate_name, target, "dispatched GH Actions build");
        Ok(())
    } else {
        let status = resp.status().as_u16();
        tracing::error!(task_id, status, "GH Actions dispatch failed");
        Err(DispatchError::GitHubApi(status))
    }
}

#[derive(Debug)]
pub enum DispatchError {
    Serialize(String),
    Network(String),
    GitHubApi(u16),
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DispatchError::Serialize(e) => write!(f, "serialization error: {e}"),
            DispatchError::Network(e) => write!(f, "network error: {e}"),
            DispatchError::GitHubApi(status) => write!(f, "GitHub API error: {status}"),
        }
    }
}
