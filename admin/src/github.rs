//! GitHub REST plumbing for `stow-admin runs` and `stow-admin cache` —
//! both commands talk to `api.github.com` directly with the operator's
//! token; the edge is not involved.

use stow_types::stow_error;
use zenwave::{Client, ResponseExt};

/// The repository every request below addresses — `build-crate.yml` runs
/// and the Actions cache live here.
pub const REPO: &str = "water-rs/stow";

const API_BASE: &str = "https://api.github.com";
const USER_AGENT: &str = "stow-admin";
/// Workflow file whose runs `runs failures` inspects.
pub const BUILD_WORKFLOW: &str = "build-crate.yml";

/// `GET` one API path under `/repos/{REPO}/` and decode the JSON body.
/// The response body rides zenwave errors, so a rejection carries
/// GitHub's own message.
pub async fn get<T: serde::de::DeserializeOwned>(
    token: &str,
    path: &str,
) -> stow_types::error::Result<T> {
    let url = format!("{API_BASE}/repos/{REPO}/{path}");
    let mut client = zenwave::client();
    let response = client
        .get(&url)
        .map_err(|error| stow_error!("build GET {url}: {error}"))?
        .header("Authorization", format!("Bearer {token}"))
        .and_then(|request| request.header("User-Agent", USER_AGENT))
        .and_then(|request| request.header("Accept", "application/vnd.github+json"))
        .map_err(|error| stow_error!("build GET {url}: {error}"))?
        .await
        .map_err(|error| stow_error!("GET {url}: {error}"))?;
    response
        .error_for_status()
        .await
        .map_err(|error| stow_error!("GET {url}: {error}"))?
        .into_json()
        .await
        .map_err(|error| stow_error!("decode {url}: {error}"))
}

/// `GET` an absolute URL as text — job-log fetches redirect to GitHub's
/// signed blob host, where the `Authorization` header must not follow
/// (zenwave strips it cross-origin).
pub async fn get_text(token: &str, url: &str) -> stow_types::error::Result<String> {
    let mut client = zenwave::client();
    let response = client
        .get(url)
        .map_err(|error| stow_error!("build GET {url}: {error}"))?
        .header("Authorization", format!("Bearer {token}"))
        .and_then(|request| request.header("User-Agent", USER_AGENT))
        .map_err(|error| stow_error!("build GET {url}: {error}"))?
        .await
        .map_err(|error| stow_error!("GET {url}: {error}"))?;
    response
        .error_for_status()
        .await
        .map_err(|error| stow_error!("GET {url}: {error}"))?
        .into_string()
        .await
        .map(|text| text.to_string())
        .map_err(|error| stow_error!("read {url}: {error}"))
}

/// `DELETE` one API path under `/repos/{REPO}/`; 2xx/404 both count —
/// deleting an entry that is already gone achieves the same end state.
pub async fn delete(token: &str, path: &str) -> stow_types::error::Result<()> {
    let url = format!("{API_BASE}/repos/{REPO}/{path}");
    let mut client = zenwave::client();
    let response = client
        .delete(&url)
        .map_err(|error| stow_error!("build DELETE {url}: {error}"))?
        .header("Authorization", format!("Bearer {token}"))
        .and_then(|request| request.header("User-Agent", USER_AGENT))
        .and_then(|request| request.header("Accept", "application/vnd.github+json"))
        .map_err(|error| stow_error!("build DELETE {url}: {error}"))?
        .await
        .map_err(|error| stow_error!("DELETE {url}: {error}"))?;
    response
        .error_for_status()
        .await
        .map_err(|error| stow_error!("DELETE {url}: {error}"))?;
    Ok(())
}
