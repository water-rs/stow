//! Dispatch of build and resolve work to the Actions control plane —
//! one [`BuildRuns`] implementation per backend (stow#833).
//!
//! The trait, the backend types and every pure helper — the dispatch
//! payload builders, the run-details/status/jobs decoders and the URL
//! paths — compile on every target so they host-test; request
//! construction and the `CfFetch` plumbing are `wasm32`-only, like
//! [`crate::github_app`]'s signing and token-exchange half.

use std::future::Future;

#[cfg(target_arch = "wasm32")]
use skyzen_cloudflare::worker::send::IntoSendFuture as _;
#[cfg(target_arch = "wasm32")]
use skyzen_cloudflare::{CfFetch, worker};

#[cfg(target_arch = "wasm32")]
use crate::cf_http;
use crate::fetch_guard::OutboundPool;
#[cfg(target_arch = "wasm32")]
use crate::fetch_guard::{FetchedResponse, GuardedResponse};
use crate::github_app::InstallationToken;

/// `per_page` for the attempt-jobs page — at the `B = 40` leg bound a
/// batch's 80 jobs fit one page; deeper batches still page by `Link`.
const JOBS_PAGE_SIZE: u32 = 100;

/// The run identity a successful `workflow_dispatch` returns — GitHub's
/// `return_run_details` response (`workflow_run_id`, `run_url`,
/// `html_url`); the local-CI mock answers the same fields. The build
/// lane binds `workflow_run_id` once to the dispatched batch's
/// `build_batches` row, so a `workflow_run` completion resolves only
/// the run that batch dispatched.
pub struct DispatchedRun {
    /// The Actions run id GitHub assigned the dispatched run.
    pub workflow_run_id: u64,
    /// The run's API URL.
    pub run_url: String,
    /// The run's browser URL.
    pub html_url: String,
}

/// The Actions control plane every build/resolve dispatch and batch
/// run lookup goes through (stow#833 §5) — a type per backend,
/// replacing the per-request `DispatchCredential` branching.
///
/// `GitHub` serves the real REST API under the App installation token
/// the Durable Object caches; `LocalCi` serves the same paths —
/// `repos/{repo}/actions/…` plus its `/dispatch` event POST — on the
/// loopback `STOW_LOCAL_CI_URL`, so the run lookups never branch on
/// which backend answered.
pub trait BuildRuns: Sync {
    /// `workflow_dispatch` of `build-batch.yml` with `encoded` — the
    /// [`stow_types::api::BatchEncoder`] output — as the `batch`
    /// input; resolves to the run identity the batch row binds.
    fn dispatch_batch<'a>(
        &'a self,
        encoded: &'a str,
        repo: &'a str,
        pool: &'a OutboundPool,
    ) -> impl Future<Output = Result<DispatchedRun, DispatchError>> + Send + 'a;

    /// `workflow_dispatch` of `resolve-request.yml` for an admitted
    /// human request (stow#428). The request lane fences on the
    /// record's `attempt`, so a successful dispatch needs only its
    /// HTTP status — no run-details body is read.
    fn trigger_resolve<'a>(
        &'a self,
        dispatch: &'a stow_types::api::RequestDispatch,
        repo: &'a str,
        pool: &'a OutboundPool,
    ) -> impl Future<Output = Result<(), DispatchError>> + Send + 'a;

    /// `GET /repos/{repo}/actions/runs/{run_id}` — the run's coarse
    /// state the batch lease check reads (§4.3).
    fn run_status<'a>(
        &'a self,
        repo: &'a str,
        run_id: u64,
        pool: &'a OutboundPool,
    ) -> impl Future<Output = Result<stow_types::runs::RunStatus, DispatchError>> + Send + 'a;

    /// `GET …/runs/{run_id}/attempts/{attempt}/jobs?per_page=100`,
    /// following `Link: rel="next"` until the pages exhaust — every
    /// job row of the pinned attempt, first page first.
    fn attempt_jobs<'a>(
        &'a self,
        repo: &'a str,
        run_id: u64,
        attempt: u32,
        pool: &'a OutboundPool,
    ) -> impl Future<Output = Result<Vec<stow_types::runs::RunJobRow>, DispatchError>> + Send + 'a;

    /// `POST /repos/{repo}/actions/runs/{run_id}/cancel` — the lease
    /// check's past-ceiling arm.
    fn cancel_run<'a>(
        &'a self,
        repo: &'a str,
        run_id: u64,
        pool: &'a OutboundPool,
    ) -> impl Future<Output = Result<(), DispatchError>> + Send + 'a;
}

/// `api.github.com` under the App installation token the Durable
/// Object caches.
pub struct GitHubBuildRuns {
    token: InstallationToken,
}

impl GitHubBuildRuns {
    /// A backend bound to `token` — the cached installation token is
    /// minted by [`crate::github_app`] when near expiry.
    pub const fn new(token: InstallationToken) -> Self {
        Self { token }
    }
}

/// The loopback mock `STOW_LOCAL_CI_URL` — the same GitHub-shaped run
/// endpoints under the local base, and the `/dispatch` event POST the
/// dispatch calls share.
pub struct LocalCiBuildRuns {
    url: String,
}

impl LocalCiBuildRuns {
    /// The loopback base, any trailing slash trimmed.
    pub fn new(url: &str) -> Self {
        Self {
            url: url.trim_end_matches('/').to_owned(),
        }
    }
}

/// The workflow and payload sent through either dispatch transport.
struct WorkflowDispatch<'a> {
    workflow_file: &'a str,
    event_type: &'a str,
    input_name: &'a str,
    input: &'a serde_json::Value,
    return_run_details: bool,
}

/// `repos/{repo}/actions/workflows/{file}/dispatches` — GitHub's
/// `workflow_dispatch` path. The local dispatcher posts to its own
/// `/dispatch` event endpoint instead.
fn workflow_dispatch_path(repo: &str, workflow_file: &str) -> String {
    format!("repos/{repo}/actions/workflows/{workflow_file}/dispatches")
}

/// `repos/{repo}/actions/runs/{id}` — both backends serve it under
/// their own base.
fn run_path(repo: &str, run_id: u64) -> String {
    format!("repos/{repo}/actions/runs/{run_id}")
}

/// `…/runs/{id}/attempts/{n}/jobs?per_page=100` — the first page the
/// pager opens; later pages ride the `Link` header's URLs verbatim.
fn attempt_jobs_path(repo: &str, run_id: u64, attempt: u32) -> String {
    format!(
        "{}/attempts/{attempt}/jobs?per_page={JOBS_PAGE_SIZE}",
        run_path(repo, run_id)
    )
}

/// `…/runs/{id}/cancel`.
fn cancel_path(repo: &str, run_id: u64) -> String {
    format!("{}/cancel", run_path(repo, run_id))
}

/// Resolve `path_or_url` under `base` — the path helpers' output
/// joins the base, and a `Link`-returned absolute URL is followed
/// only while it stays inside the base's origin (scheme, host and
/// port together; the `/` boundary refuses prefix lookalikes like
/// `api.github.com.evil`). Anything else is refused: followed
/// verbatim it would carry the request — and the GitHub installation
/// token it bears — to a host the API never named.
fn scoped_url(base: &str, path_or_url: &str) -> Result<String, DispatchError> {
    if path_or_url.starts_with("http://") || path_or_url.starts_with("https://") {
        if path_or_url == base || path_or_url.starts_with(&format!("{base}/")) {
            return Ok(path_or_url.to_owned());
        }
        return Err(DispatchError::OutOfScope(path_or_url.to_owned()));
    }
    Ok(format!("{base}/{path_or_url}"))
}

fn github_dispatch_payload(
    input_name: &str,
    input_json: &str,
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

/// `GET …/actions/runs/{id}`'s body — the lease check's
/// `status`/`conclusion`/`run_attempt` triple.
fn decode_run_status(body: &str) -> Result<stow_types::runs::RunStatus, DispatchError> {
    serde_json::from_str::<stow_types::runs::RunStatus>(body)
        .map_err(|error| DispatchError::Response(format!("{error}: {body}")))
}

/// One attempt-jobs page's body — the `jobs` array GitHub wraps the
/// rows in.
fn decode_jobs_page(body: &str) -> Result<Vec<stow_types::runs::RunJobRow>, DispatchError> {
    serde_json::from_str::<stow_types::runs::RunJobsPage>(body)
        .map(|page| page.jobs)
        .map_err(|error| DispatchError::Response(format!("{error}: {body}")))
}

// ===== Cloudflare-bound plumbing =====

/// POST/GET one prepared request through the outbound pool, enforcing
/// the success-status contract.
#[cfg(target_arch = "wasm32")]
async fn send(
    request: &worker::Request,
    pool: &OutboundPool,
) -> Result<GuardedResponse<worker::Response>, DispatchError> {
    let _slot = pool.slot().await;
    let response = CfFetch
        .request(request)
        .await
        .map(GuardedResponse::new)
        .map_err(|error| DispatchError::Network(error.to_string()))?;
    ensure_success_status(response.get_ref().status_code())?;
    Ok(response)
}

/// Read a response's body to completion as text — the body is consumed
/// into the read, so nothing the caller can drop leaves a stalled
/// connection.
#[cfg(target_arch = "wasm32")]
async fn body_text<B: FetchedResponse>(
    response: GuardedResponse<B>,
) -> Result<String, DispatchError> {
    FetchedResponse::text(response.into_inner())
        .into_send()
        .await
        .map_err(DispatchError::Response)
}

#[cfg(target_arch = "wasm32")]
impl BuildRunsBackend for GitHubBuildRuns {
    /// `https://api.github.com/{path}` under the App bearer — the
    /// headers every GitHub Actions call carries. A `Link`-returned
    /// absolute URL is fetched only inside `api.github.com`'s origin.
    fn api_request(
        &self,
        method: worker::Method,
        path_or_url: &str,
        payload: Option<&serde_json::Value>,
    ) -> Result<worker::Request, DispatchError> {
        let url = scoped_url("https://api.github.com", path_or_url)?;
        let bearer = format!("Bearer {}", self.token.token);
        let headers = [
            ("Accept", "application/vnd.github+json"),
            ("X-GitHub-Api-Version", "2022-11-28"),
            ("User-Agent", "stow-scheduler"),
            ("Authorization", bearer.as_str()),
        ];
        match payload {
            Some(payload) => cf_http::json_request(method, &url, payload, &headers),
            None => cf_http::bare_request(method, &url, &headers, None),
        }
        .map_err(|error| DispatchError::Network(error.to_string()))
    }

    /// GitHub's `workflow_dispatch` shape: `ref`, the single named
    /// input as a JSON *string*, and the run-details flag the build
    /// lanes bind from.
    fn workflow_dispatch_request(
        &self,
        dispatch: &WorkflowDispatch<'_>,
        repo: &str,
    ) -> Result<worker::Request, DispatchError> {
        let input_json = serde_json::to_string(dispatch.input)
            .map_err(|error| DispatchError::Network(error.to_string()))?;
        let payload = github_dispatch_payload(
            dispatch.input_name,
            &input_json,
            dispatch.return_run_details,
        );
        self.api_request(
            worker::Method::Post,
            &workflow_dispatch_path(repo, dispatch.workflow_file),
            Some(&payload),
        )
    }
}

#[cfg(target_arch = "wasm32")]
impl BuildRunsBackend for LocalCiBuildRuns {
    /// `{base}/{path}` — the loopback serves the same GitHub-shaped
    /// run endpoints with no `Authorization`. A `Link`-returned
    /// absolute URL is fetched only inside the local base's origin.
    fn api_request(
        &self,
        method: worker::Method,
        path_or_url: &str,
        payload: Option<&serde_json::Value>,
    ) -> Result<worker::Request, DispatchError> {
        let url = scoped_url(&self.url, path_or_url)?;
        match payload {
            Some(payload) => cf_http::json_request(method, &url, payload, &[]),
            None => cf_http::bare_request(method, &url, &[], None),
        }
        .map_err(|error| DispatchError::Network(error.to_string()))
    }

    /// The local dispatcher's `repository_dispatch` lookalike —
    /// `{base}/dispatch` with the event name and the payload verbatim.
    fn workflow_dispatch_request(
        &self,
        dispatch: &WorkflowDispatch<'_>,
        _repo: &str,
    ) -> Result<worker::Request, DispatchError> {
        let payload = serde_json::json!({
            "event_type": dispatch.event_type,
            "client_payload": dispatch.input,
        });
        self.api_request(worker::Method::Post, "dispatch", Some(&payload))
    }
}

/// The dispatch fan-out every `workflow_dispatch` call shares: POST,
/// status check, read the run-details body. `run_details` names
/// whether the caller binds a run id — the resolve lane does not.
#[cfg(target_arch = "wasm32")]
async fn post_workflow_dispatch<R: BuildRunsBackend>(
    backend: &R,
    dispatch: &WorkflowDispatch<'_>,
    repo: &str,
    pool: &OutboundPool,
) -> Result<GuardedResponse<worker::Response>, DispatchError> {
    let request = backend.workflow_dispatch_request(dispatch, repo)?;
    send(&request, pool).await
}

/// The per-backend request mechanics under [`BuildRuns`]' shared
/// logic — the `workflow_dispatch` POST's own shape and the
/// GitHub-shaped run endpoints' requests.
#[cfg(target_arch = "wasm32")]
trait BuildRunsBackend: Sync {
    /// The request for one `workflow_dispatch` POST — GitHub's
    /// `dispatches` path or the local `/dispatch` event.
    fn workflow_dispatch_request(
        &self,
        dispatch: &WorkflowDispatch<'_>,
        repo: &str,
    ) -> Result<worker::Request, DispatchError>;
    /// A request against the GitHub-shaped run endpoints —
    /// `{base}/repos/{repo}/actions/…` — or the absolute URL a `Link`
    /// header returned, followed only inside the backend's origin.
    fn api_request(
        &self,
        method: worker::Method,
        path_or_url: &str,
        payload: Option<&serde_json::Value>,
    ) -> Result<worker::Request, DispatchError>;
}

/// GET one page: status check, `Link` header captured before the body
/// is consumed, body read to text.
#[cfg(target_arch = "wasm32")]
async fn get_page(
    request: &worker::Request,
    pool: &OutboundPool,
) -> Result<(Option<String>, String), DispatchError> {
    let response = send(request, pool).await?;
    let link = response.get_ref().header("Link");
    let body = body_text(response).await?;
    Ok((link, body))
}

#[cfg(target_arch = "wasm32")]
impl<R: BuildRunsBackend> BuildRuns for R {
    async fn dispatch_batch(
        &self,
        encoded: &str,
        repo: &str,
        pool: &OutboundPool,
    ) -> Result<DispatchedRun, DispatchError> {
        let input = serde_json::from_str::<serde_json::Value>(encoded)
            .map_err(|error| DispatchError::Response(error.to_string()))?;
        let response = post_workflow_dispatch(
            self,
            &WorkflowDispatch {
                workflow_file: stow_types::trusted_builder::BATCH_WORKFLOW_FILE,
                event_type: "build-batch",
                input_name: "batch",
                input: &input,
                return_run_details: true,
            },
            repo,
            pool,
        )
        .await?;
        let body = body_text(response).await?;
        decode_build_run_details(&body).inspect(|run| {
            tracing::info!(
                run_id = run.workflow_run_id,
                run_url = %run.run_url,
                html_url = %run.html_url,
                "dispatched build batch"
            );
        })
    }

    async fn trigger_resolve(
        &self,
        dispatch: &stow_types::api::RequestDispatch,
        repo: &str,
        pool: &OutboundPool,
    ) -> Result<(), DispatchError> {
        let input = serde_json::to_value(dispatch)
            .map_err(|error| DispatchError::Network(error.to_string()))?;
        post_workflow_dispatch(
            self,
            &WorkflowDispatch {
                workflow_file: stow_types::trusted_builder::RESOLVE_WORKFLOW_FILE,
                event_type: "resolve-request",
                input_name: "request",
                input: &input,
                return_run_details: false,
            },
            repo,
            pool,
        )
        .await
        .map(|_| ())
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

    async fn run_status(
        &self,
        repo: &str,
        run_id: u64,
        pool: &OutboundPool,
    ) -> Result<stow_types::runs::RunStatus, DispatchError> {
        let request = self.api_request(worker::Method::Get, &run_path(repo, run_id), None)?;
        let (_, body) = get_page(&request, pool).await?;
        decode_run_status(&body)
    }

    async fn attempt_jobs(
        &self,
        repo: &str,
        run_id: u64,
        attempt: u32,
        pool: &OutboundPool,
    ) -> Result<Vec<stow_types::runs::RunJobRow>, DispatchError> {
        let mut jobs = Vec::new();
        let mut url = attempt_jobs_path(repo, run_id, attempt);
        loop {
            let request = self.api_request(worker::Method::Get, &url, None)?;
            let (link, body) = get_page(&request, pool).await?;
            jobs.extend(decode_jobs_page(&body)?);
            match stow_types::runs::link_next(link.as_deref()) {
                Some(next) => url = String::from(next),
                None => return Ok(jobs),
            }
        }
    }

    async fn cancel_run(
        &self,
        repo: &str,
        run_id: u64,
        pool: &OutboundPool,
    ) -> Result<(), DispatchError> {
        let request = self.api_request(worker::Method::Post, &cancel_path(repo, run_id), None)?;
        send(&request, pool).await.map(|_| ())
    }
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
    /// A `Link` header's `next` pointed outside the backend's own
    /// origin — followed verbatim it would carry the request, and
    /// GitHub's installation token with it, to a host the API never
    /// named.
    #[error("out-of-origin URL refused: {0}")]
    OutOfScope(String),
}

#[cfg(test)]
mod tests {
    use super::{
        attempt_jobs_path, cancel_path, decode_build_run_details, decode_jobs_page,
        decode_run_status, ensure_success_status, github_dispatch_payload, run_path, scoped_url,
        workflow_dispatch_path,
    };

    #[test]
    fn resolve_success_uses_status_without_run_details_body() {
        for _body in ["", "{}", "not-json"] {
            ensure_success_status(204).expect("successful resolve dispatch status");
        }
        assert!(
            github_dispatch_payload("request", "{}", false)
                .get("return_run_details")
                .is_none()
        );
        assert!(
            github_dispatch_payload("task", "{}", true)
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

    /// The GitHub-shaped paths both backends serve — the local base
    /// swaps in for `api.github.com`, the paths are shared verbatim.
    #[test]
    fn the_run_endpoint_paths_are_shared_verbatim() {
        assert_eq!(
            workflow_dispatch_path("water-rs/stow", "build-batch.yml"),
            "repos/water-rs/stow/actions/workflows/build-batch.yml/dispatches"
        );
        assert_eq!(run_path("o/r", 42), "repos/o/r/actions/runs/42");
        assert_eq!(
            attempt_jobs_path("o/r", 42, 3),
            "repos/o/r/actions/runs/42/attempts/3/jobs?per_page=100"
        );
        assert_eq!(cancel_path("o/r", 42), "repos/o/r/actions/runs/42/cancel");
    }

    /// A `Link`-returned absolute URL is followed only inside the
    /// backend's own origin — another host, a scheme mismatch or a
    /// prefix lookalike is refused before the request, and the
    /// installation token it carries, can leave.
    #[test]
    fn a_link_url_stays_inside_the_backend_origin() {
        // In scope: the request goes out verbatim.
        assert_eq!(
            scoped_url(
                "https://api.github.com",
                "https://api.github.com/repos/o/r/actions/runs/1/attempts/1/jobs?page=2",
            )
            .expect("in-scope next URL"),
            "https://api.github.com/repos/o/r/actions/runs/1/attempts/1/jobs?page=2"
        );
        // A relative path joins the base.
        assert_eq!(
            scoped_url("https://api.github.com", "repos/o/r").expect("relative path"),
            "https://api.github.com/repos/o/r"
        );
        for url in [
            "https://evil.example/repos/o/r",  // another host
            "http://api.github.com/repos/o/r", // scheme mismatch
            "https://api.github.com.evil/x",   // prefix lookalike
            "https://api.github.com2/x",
        ] {
            let error = scoped_url("https://api.github.com", url).expect_err("refused");
            assert!(error.to_string().contains(url), "{error} names {url}");
        }
        // The local base scopes to its own origin, port included.
        assert!(scoped_url("http://127.0.0.1:8787", "http://127.0.0.1:8787/repos/o/r").is_ok());
        for url in [
            "http://127.0.0.1:87870/repos", // a port that shares the prefix
            "https://127.0.0.1:8787/repos", // scheme mismatch
        ] {
            assert!(scoped_url("http://127.0.0.1:8787", url).is_err(), "{url}");
        }
    }

    /// The lease check's decode: `status`/`conclusion`/`run_attempt`
    /// out of GitHub's run object, extras ignored, absent fields an
    /// error.
    #[test]
    fn run_status_decoding_reads_the_lease_fields() {
        let status = decode_run_status(
            r#"{"status":"in_progress","conclusion":null,"run_attempt":1,
               "html_url":"https://github.com/o/r/actions/runs/1"}"#,
        )
        .expect("decodes");
        assert_eq!(status.status, "in_progress");
        assert!(decode_run_status("not-json").is_err());
        assert!(decode_run_status(r#"{"status":"completed"}"#).is_err());
    }

    /// A jobs page decodes into `RunJobRow`s — two legs' four jobs in
    /// one `jobs` array.
    #[test]
    fn jobs_page_decoding_reads_the_rows() {
        let page = decode_jobs_page(
            r#"{"total_count":2,"jobs":[
                 {"id":1,"name":"leg 0 / build #0 serde 1.0.0 (x86_64-unknown-linux-gnu) 0123456789abcdef",
                  "status":"completed","conclusion":"success",
                  "started_at":"2026-10-18T00:00:00Z","completed_at":"2026-10-18T00:02:00Z",
                  "run_attempt":1,"html_url":"u","steps":[]},
                 {"id":2,"name":"leg 0 / publish #0 0123456789abcdef",
                  "status":"in_progress","conclusion":null,
                  "started_at":"2026-10-18T00:02:10Z","completed_at":null,
                  "run_attempt":1,"html_url":"u","steps":[]}
               ]}"#,
        )
        .expect("decodes");
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].run_attempt, 1);
        assert_eq!(page[1].conclusion, None);
        assert!(decode_jobs_page("{}").is_err());
    }
}
