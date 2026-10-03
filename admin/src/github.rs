//! GitHub REST plumbing for `stow-admin runs` and `stow-admin cache` —
//! both commands talk to `api.github.com` directly with the operator's
//! token; the edge is not involved.

use stow_types::stow_error;
use stow_types::transient::{Backoff, is_transient_status, retry_after_hint};
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
    get_path(token, &format!("/repos/{REPO}/{path}")).await
}

/// `GET` an absolute `api.github.com` path (leading `/`) and decode the
/// JSON body — for endpoints outside `/repos/{REPO}`: the repository
/// search and other repositories' git trees.
pub async fn get_path<T: serde::de::DeserializeOwned>(
    token: &str,
    path: &str,
) -> stow_types::error::Result<T> {
    let url = format!("{API_BASE}{path}");
    get_path_result(token, path)
        .await
        .map_err(|error| stow_error!("GET {url}: {error}"))
}

/// `GET` an absolute `api.github.com` path (leading `/`) and decode the
/// JSON body, surfacing the raw transport error so the caller can read
/// the status itself — a 404 on a named repository is the repository
/// being gone, which is a fact about the repository and not a network
/// failure.
pub async fn get_path_result<T: serde::de::DeserializeOwned>(
    token: &str,
    path: &str,
) -> std::result::Result<T, zenwave::Error> {
    let url = format!("{API_BASE}{path}");
    let response = send_get(token, &url, Some("application/vnd.github+json")).await?;
    Ok(response.error_for_status().await?.into_json().await?)
}

/// `GET` `url` under the operator token, retried on transport errors and
/// transient statuses by the shared [`Backoff`] policy. Any other answer
/// — success or a final status — returns for the caller to read; a
/// transient failure that outlives the budget returns as its error.
async fn send_get(
    token: &str,
    url: &str,
    accept: Option<&str>,
) -> std::result::Result<zenwave::Response, zenwave::Error> {
    let mut backoff = Backoff::new();
    loop {
        let mut client = zenwave::client();
        let request = client
            .get(url)?
            .header("Authorization", format!("Bearer {token}"))
            .and_then(|request| request.header("User-Agent", USER_AGENT))?;
        let request = match accept {
            Some(accept) => request.header("Accept", accept)?,
            None => request,
        };
        let (error, retry_after) = match request.await {
            Ok(response) if !is_transient_status(response.status().as_u16()) => {
                return Ok(response);
            }
            Ok(response) => {
                let retry_after = retry_after_hint(response.headers());
                match response.error_for_status().await {
                    Ok(response) => return Ok(response),
                    Err(error) => (error, retry_after),
                }
            }
            Err(error) => (error, None),
        };
        let Some(wait) = backoff.next_wait(retry_after) else {
            return Err(error);
        };
        tracing::warn!(url, %error, "GitHub request failed; retrying");
        tokio::time::sleep(wait).await;
    }
}

/// `GET` an absolute URL as text — job-log fetches redirect to GitHub's
/// signed blob host, where the `Authorization` header must not follow
/// (zenwave strips it cross-origin).
pub async fn get_text(token: &str, url: &str) -> stow_types::error::Result<String> {
    let response = send_get(token, url, None)
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

/// `POST` one API path under `/repos/{REPO}/` with a JSON body and
/// decode the JSON response.
pub async fn post<T: serde::de::DeserializeOwned>(
    token: &str,
    path: &str,
    body: &(impl serde::Serialize + Sync),
) -> stow_types::error::Result<T> {
    send_json(
        token,
        zenwave::Method::POST,
        &format!("/repos/{REPO}/{path}"),
        Some(body),
    )
    .await
}

/// `PATCH` one API path under `/repos/{REPO}/` with a JSON body and
/// decode the JSON response.
pub async fn patch<T: serde::de::DeserializeOwned>(
    token: &str,
    path: &str,
    body: &(impl serde::Serialize + Sync),
) -> stow_types::error::Result<T> {
    send_json(
        token,
        zenwave::Method::PATCH,
        &format!("/repos/{REPO}/{path}"),
        Some(body),
    )
    .await
}

/// `PUT` an empty body to one API path under `/repos/{REPO}/` —
/// `PUT`/`POST` endpoints that take no payload, like the workflow
/// enable/disable routes, which answer 204.
pub async fn put(token: &str, path: &str) -> stow_types::error::Result<()> {
    send_empty(
        token,
        zenwave::Method::PUT,
        &format!("/repos/{REPO}/{path}"),
    )
    .await
}

/// One `send_json`/`send_empty` implementation behind the verb helpers:
/// an authenticated request to `api.github.com` whose 2xx body decodes
/// as `T`.
async fn send_json<T: serde::de::DeserializeOwned>(
    token: &str,
    method: zenwave::Method,
    path: &str,
    body: Option<&(impl serde::Serialize + Sync)>,
) -> stow_types::error::Result<T> {
    let url = format!("{API_BASE}{path}");
    let mut client = zenwave::client();
    let request = client
        .method(method.clone(), &url)
        .map_err(|error| stow_error!("build {method} {url}: {error}"))?
        .header("Authorization", format!("Bearer {token}"))
        .and_then(|request| request.header("User-Agent", USER_AGENT))
        .and_then(|request| request.header("Accept", "application/vnd.github+json"))
        .and_then(|request| request.header("X-GitHub-Api-Version", "2022-11-28"))
        .map_err(|error| stow_error!("build {method} {url}: {error}"))?;
    let request = match body {
        Some(body) => request
            .json_body(body)
            .map_err(|error| stow_error!("build {method} {url} body: {error}"))?,
        None => request,
    };
    let response = request
        .await
        .map_err(|error| stow_error!("{method} {url}: {error}"))?
        .error_for_status()
        .await
        .map_err(|error| stow_error!("{method} {url}: {error}"))?;
    response
        .into_json()
        .await
        .map_err(|error| stow_error!("read {method} {url}: {error}"))
}

/// Like [`send_json`] for endpoints whose 2xx answer carries no body —
/// the response is status-checked and dropped.
async fn send_empty(
    token: &str,
    method: zenwave::Method,
    path: &str,
) -> stow_types::error::Result<()> {
    let url = format!("{API_BASE}{path}");
    let mut client = zenwave::client();
    let response = client
        .method(method.clone(), &url)
        .map_err(|error| stow_error!("build {method} {url}: {error}"))?
        .header("Authorization", format!("Bearer {token}"))
        .and_then(|request| request.header("User-Agent", USER_AGENT))
        .and_then(|request| request.header("Accept", "application/vnd.github+json"))
        .map_err(|error| stow_error!("build {method} {url}: {error}"))?
        .await
        .map_err(|error| stow_error!("{method} {url}: {error}"))?
        .error_for_status()
        .await
        .map_err(|error| stow_error!("{method} {url}: {error}"))?;
    drop(response);
    Ok(())
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

/// `POST` one API path under `/repos/{REPO}/` with a JSON body whose
/// 2xx answer carries no body of interest — the `workflow_dispatch`
/// calls `preheat manual` drives, which answer 204.
pub async fn post_empty(
    token: &str,
    path: &str,
    body: &serde_json::Value,
) -> stow_types::error::Result<()> {
    let url = format!("{API_BASE}/repos/{REPO}/{path}");
    let mut client = zenwave::client();
    client
        .post(&url)
        .map_err(|error| stow_error!("build POST {url}: {error}"))?
        .header("Authorization", format!("Bearer {token}"))
        .and_then(|request| request.header("User-Agent", USER_AGENT))
        .and_then(|request| request.header("Accept", "application/vnd.github+json"))
        .and_then(|request| request.json_body(body))
        .map_err(|error| stow_error!("build POST {url}: {error}"))?
        .await
        .map_err(|error| stow_error!("POST {url}: {error}"))?
        .error_for_status()
        .await
        .map_err(|error| stow_error!("POST {url}: {error}"))?;
    Ok(())
}
