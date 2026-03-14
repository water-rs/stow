use zenwave::Client;

#[derive(Debug, Clone)]
pub struct QueuedTask {
    pub task_id: String,
    pub crate_name: String,
    pub version: String,
    pub target: String,
}

/// Trigger a GitHub Actions `repository_dispatch` event to build a crate.
///
/// Uses zenwave to POST to the GitHub API.
pub async fn trigger_build(
    task: &QueuedTask,
    gh_token: &str,
    repo: &str,
) -> Result<(), DispatchError> {
    let url = format!("https://api.github.com/repos/{repo}/dispatches");

    let payload = serde_json::json!({
        "event_type": "build-crate",
        "client_payload": {
            "task_id": task.task_id,
            "crate_name": task.crate_name,
            "version": task.version,
            "target": task.target,
        }
    });

    let mut client = zenwave::client();
    let resp = client
        .post(&url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "stow-scheduler")
        .bearer_auth(gh_token)
        .json_body(&payload)
        .await
        .map_err(|e| DispatchError::Network(e.to_string()))?;

    if resp.status().is_success() || resp.status().as_u16() == 204 {
        tracing::info!(
            task_id = %task.task_id,
            crate_name = %task.crate_name,
            target = %task.target,
            "dispatched GH Actions build"
        );
        Ok(())
    } else {
        let status = resp.status().as_u16();
        tracing::error!(task_id = %task.task_id, status, "GH Actions dispatch failed");
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
