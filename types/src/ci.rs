//! The one privileged CI interface (stow#877).
//!
//! Every query of `build-crate.yml` occupancy and every task
//! submission goes through [`CiInterface`], the scheduler's (host and
//! wasm32) — preheat submits trees, it never dispatches (stow#880). It
//! is FIFO and never reorders: submission is one `workflow_dispatch`
//! of `build-crate.yml` per task, in the caller's own order, and
//! priority stays the scheduler's concern.
//!
//! The interface carries no state of its own: the endpoint (real
//! GitHub under an App installation token, or the local CI server the
//! mock stack runs on the same contract) and the caller's transport
//! ([`CiTransport`]) are the whole context. The edge drives it through
//! `CfFetch`; request construction, the
//! GitHub-shaped paths, run-title attribution and every answer decode
//! live here once.

use crate::api::{RunnerFamily, runner_family, task_id_segment};

/// The org's GitHub-hosted runner capacity: 60 runners, 20 macOS.
///
/// Every stow caller shares it with the rest of the organisation; stow
/// cannot count the other repositories' runs, so callers keep the
/// margins below rather than treating the full pools as theirs.
pub const GITHUB_ORG_RUNNERS: u32 = 60;
/// The macOS pool inside [`GITHUB_ORG_RUNNERS`].
pub const GITHUB_ORG_MACOS_RUNNERS: u32 = 20;
/// Runners left for the rest of the organisation — the margin every
/// caller keeps under [`GITHUB_ORG_RUNNERS`].
pub const RUNNER_MARGIN: u32 = 15;
/// macOS runners left free — the margin under
/// [`GITHUB_ORG_MACOS_RUNNERS`].
pub const MACOS_RUNNER_MARGIN: u32 = 4;
/// Runner slots stow may hold across all runner families — the default
/// `STOW_MAX_CONCURRENT_JOBS` and `preheat manual --in-flight` share.
pub const STOW_RUNNER_BUDGET: u32 = GITHUB_ORG_RUNNERS - RUNNER_MARGIN;
/// Runner slots stow may hold on the macOS family — the default
/// `STOW_MAX_CONCURRENT_MACOS_JOBS`.
pub const STOW_MACOS_RUNNER_BUDGET: u32 = GITHUB_ORG_MACOS_RUNNERS - MACOS_RUNNER_MARGIN;

/// `build-crate.yml` runs `queued` or `in_progress`, per runner family.
///
/// The interface's `status` answer. A run is one runner slot while it
/// lives; `total` counts the slots every family holds together.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Occupancy {
    linux: u32,
    macos: u32,
    windows: u32,
    unknown: u32,
}

impl Occupancy {
    /// An empty answer — no queued or in-progress run on any family.
    pub const EMPTY: Self = Self {
        linux: 0,
        macos: 0,
        windows: 0,
        unknown: 0,
    };

    /// Runs holding a slot on `family`'s runner pool.
    #[must_use]
    pub const fn of(&self, family: RunnerFamily) -> u32 {
        match family {
            RunnerFamily::Linux => self.linux,
            RunnerFamily::MacOs => self.macos,
            RunnerFamily::Windows => self.windows,
        }
    }

    /// Runs holding a slot on any family.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.linux + self.macos + self.windows + self.unknown
    }

    /// Runner slots this family may still admit under the shared
    /// budgets — `STOW_RUNNER_BUDGET` total and
    /// `STOW_MACOS_RUNNER_BUDGET` on the macOS pool.
    #[must_use]
    pub fn free_for(&self, family: RunnerFamily) -> u32 {
        let family_free = match family {
            RunnerFamily::MacOs => STOW_MACOS_RUNNER_BUDGET.saturating_sub(self.macos),
            _ => u32::MAX,
        };
        STOW_RUNNER_BUDGET
            .saturating_sub(self.total())
            .min(family_free)
    }

    /// A slot on `family`.
    pub const fn add(&mut self, family: RunnerFamily) {
        match family {
            RunnerFamily::Linux => self.linux += 1,
            RunnerFamily::MacOs => self.macos += 1,
            RunnerFamily::Windows => self.windows += 1,
        }
    }

    /// A slot whose family the run's title did not name — counted
    /// toward the total budget only.
    pub const fn add_unknown(&mut self) {
        self.unknown += 1;
    }
}

/// The runner family a `build-crate.yml` run occupies, read off its `run-name`.
///
/// The title #876 stamps is `<rustc>-<task_id>` and a task id carries
/// its target as the `-<target>-<rustc>-d<digest>` segment, so the
/// listing alone attributes every run: no per-run
/// `jobs` call is needed.
#[must_use]
pub fn family_of_run_title(title: &str) -> Option<RunnerFamily> {
    let (_, task_id) = crate::records::parse_run_title(title)?;
    family_of_task_id(task_id)
}

/// The runner family a task id's `-<target>-` leg resolves to.
///
/// The leg is [`task_id_segment`] of a [`crate::api::CI_TARGET_TRIPLES`]
/// member — underscored, so a crate leg's own dashes can never spell it.
#[must_use]
pub fn family_of_task_id(task_id: &str) -> Option<RunnerFamily> {
    crate::api::CI_TARGET_TRIPLES.iter().find_map(|target| {
        task_id
            .contains(&format!("-{}-", task_id_segment(target)))
            .then(|| runner_family(target))
            .flatten()
    })
}

/// Which side of the `?status=` split a listed run came back under.
///
/// `queued` waits on a runner, `in_progress` holds one. The scheduler
/// moves its own runs `dispatched` → `running` on this, in place of the
/// `in_progress` delivery (stow#940).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiRunStatus {
    /// `?status=queued` — accepted by GitHub, not yet holding a runner.
    Queued,
    /// `?status=in_progress` — holding a runner.
    InProgress,
}

/// One `build-crate.yml` run the `status` listing reports — its id,
/// the runner family its title attributed (`None` when the title
/// parses to no family's target), and which `?status=` query returned
/// it.
#[derive(Debug)]
pub struct CiRunListing {
    /// The Actions run id.
    pub workflow_run_id: u64,
    /// The run's `display_title` — `<rustc>-<task_id>` for stow's own
    /// dispatches; the post-wake reconcile binds unbound claims by it
    /// (stow#878, review Q6).
    pub title: String,
    /// The family its run-name attributed.
    pub family: Option<RunnerFamily>,
    /// Which `?status=` listing the run came back under.
    pub status: CiRunStatus,
}

/// The run identity a successful submission returns.
///
/// GitHub's `return_run_details` response (`workflow_run_id`,
/// `run_url`, `html_url`); the local-CI mock answers the same fields. The
/// scheduler binds `workflow_run_id` once to the submitted task's
/// queue row, so a `workflow_run` completion resolves only the run
/// that task submitted.
#[derive(Debug)]
pub struct DispatchedRun {
    /// The Actions run id the submission was assigned.
    pub workflow_run_id: u64,
    /// The run's API URL.
    pub run_url: String,
    /// The run's browser URL.
    pub html_url: String,
}

/// One prepared call against the Actions control plane.
///
/// The shared layer's whole ask of a transport. `url` is already
/// resolved inside the endpoint's origin; `headers` carry
/// Accept/Authorization as the endpoint spells them.
#[derive(Debug)]
pub struct CiRequest {
    /// `GET` or `POST`.
    pub method: &'static str,
    /// The fully resolved URL.
    pub url: String,
    /// Request headers in order.
    pub headers: Vec<(String, String)>,
    /// The JSON body, when the call carries one.
    pub body: Option<Vec<u8>>,
}

/// A completed response: status, the headers `Link`-driven pagination
/// and rate-limit classification read, and the buffered body.
#[derive(Debug)]
pub struct CiResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers (names lowercased by the transport where the
    /// platform reports them so).
    pub headers: Vec<(String, String)>,
    /// The whole body.
    pub body: Vec<u8>,
}

impl CiResponse {
    /// First value of `name`, case-insensitive on the header name.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// The per-caller transport [`CiInterface`] drives — one method, every
/// endpoint contract (paths, payloads, pagination, classification)
/// lives above it.
pub trait CiTransport: Sync {
    /// Send one prepared request and buffer its response. The
    /// transport owns connection reuse, retry policy and any outbound
    /// bound; it must not follow URLs other than the one given.
    fn send(
        &self,
        request: CiRequest,
    ) -> impl Future<Output = Result<CiResponse, DispatchError>> + Send;
}

/// Which control plane the interface speaks to — the shapes are the
/// same paths GitHub serves; only the base URL, the dispatch verb and
/// the credentials differ.
#[derive(Debug, Clone)]
pub enum CiEndpoint {
    /// `api.github.com` under a GitHub App installation token.
    GitHub {
        /// `owner/repo` the runs and dispatches address.
        repo: String,
        /// Bearer for `Authorization:`.
        token: String,
    },
    /// The mock stack's local CI server — the same GitHub-shaped run
    /// endpoints on the loopback base, with the `/dispatch` event POST
    /// standing in for `workflow_dispatch`.
    Local {
        /// Base URL, trailing slash trimmed.
        base: String,
    },
}

/// The privileged CI interface (stow#877).
///
/// One type over endpoint and transport. `status` reports
/// `build-crate.yml` occupancy per runner family; `submit` is one
/// `workflow_dispatch` of `build-crate.yml` for one task. FIFO, never
/// reorders: each call is issued in the order invoked.
#[derive(Debug)]
pub struct CiInterface<T: CiTransport> {
    endpoint: CiEndpoint,
    transport: T,
}

impl<T: CiTransport> CiInterface<T> {
    /// An interface against real GitHub under an App installation
    /// token.
    pub fn github(repo: &str, token: &str, transport: T) -> Self {
        Self {
            endpoint: CiEndpoint::GitHub {
                repo: repo.to_owned(),
                token: token.to_owned(),
            },
            transport,
        }
    }

    /// An interface against the local CI server — the mock stack's
    /// `STOW_LOCAL_CI_URL` / `preheat manual --dispatch-url` base.
    pub fn local_ci(base_url: &str, transport: T) -> Self {
        Self {
            endpoint: CiEndpoint::Local {
                base: base_url.trim_end_matches('/').to_owned(),
            },
            transport,
        }
    }

    /// `workflow_dispatch` of `build-crate.yml` with `encoded` — the
    /// [`crate::api::BuildTaskPayload::encode_dispatch_task`] output —
    /// as the `task` input; resolves to the run identity the task
    /// binds.
    ///
    /// # Errors
    ///
    /// [`DispatchError`] — a refused POST classifies as
    /// [`DispatchError::Api`] or [`DispatchError::RateLimited`]; a send
    /// or answer that settled nothing is [`DispatchError::Network`] /
    /// [`DispatchError::Response`].
    pub async fn submit(&self, encoded: &str) -> Result<DispatchedRun, DispatchError> {
        let input = serde_json::from_str::<serde_json::Value>(encoded)
            .map_err(|error| DispatchError::Response(error.to_string()))?;
        let request = self.dispatch_request(
            crate::trusted_builder::WORKFLOW_FILE,
            "build-crate",
            "task",
            &input,
            true,
        )?;
        let response = self.send_checked(request).await?;
        let body = String::from_utf8(response.body)
            .map_err(|error| DispatchError::Response(error.to_string()))?;
        decode_run_details(&body).inspect(|run| {
            tracing::info!(
                run_id = run.workflow_run_id,
                run_url = %run.run_url,
                "submitted build task"
            );
        })
    }

    /// `workflow_dispatch` of `resolve-request.yml` for an admitted
    /// human request (stow#428). The request lane fences on the
    /// record's `attempt`, so a successful dispatch needs only its
    /// HTTP status — no run-details body is read.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError`] for the call's refusal kinds —
    /// `RateLimited`/`Api` provably did not happen, `Network` may
    /// have landed.
    pub async fn submit_resolve(
        &self,
        dispatch: &crate::api::RequestDispatch,
    ) -> Result<(), DispatchError> {
        let input = serde_json::to_value(dispatch)
            .map_err(|error| DispatchError::Network(error.to_string()))?;
        let request = self.dispatch_request(
            crate::trusted_builder::RESOLVE_WORKFLOW_FILE,
            "resolve-request",
            "request",
            &input,
            false,
        )?;
        self.send_checked(request).await.map(|_| ()).inspect(|()| {
            tracing::info!(
                request_id = %dispatch.request_id,
                attempt = dispatch.attempt,
                "submitted resolve run"
            );
        })
    }

    /// `workflow_dispatch` of `preheat-admin.yml` for a new stable
    /// rustc (stow#880): the newreleases.io delivery's claimed version
    /// is the run's `rustc_version` input; the workflow confirms it
    /// against the channel manifest before resolving, so a wrong or
    /// forged version costs one manifest check. The dispatch needs
    /// only its HTTP status — no run-details body is read.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError`] for the call's refusal kinds —
    /// `RateLimited`/`Api` provably did not happen, `Network` may
    /// have landed.
    pub async fn submit_preheat(&self, rustc_version: &str) -> Result<(), DispatchError> {
        let inputs = serde_json::json!({ "rustc_version": rustc_version });
        let request = match &self.endpoint {
            CiEndpoint::GitHub { repo, .. } => {
                let payload = serde_json::json!({
                    "ref": crate::trusted_builder::BRANCH,
                    "inputs": inputs,
                });
                let url = self.resolve(&workflow_dispatch_path(
                    repo,
                    crate::trusted_builder::PREHEAT_WORKFLOW_FILE,
                ))?;
                let body = serde_json::to_vec(&payload)
                    .map_err(|error| DispatchError::Network(error.to_string()))?;
                self.api_request("POST", &url, Some(body))
            }
            CiEndpoint::Local { base } => {
                let payload = serde_json::json!({
                    "event_type": "preheat",
                    "client_payload": inputs,
                });
                let body = serde_json::to_vec(&payload)
                    .map_err(|error| DispatchError::Network(error.to_string()))?;
                self.api_request("POST", &format!("{base}/dispatch"), Some(body))
            }
        };
        self.send_checked(request).await.map(|_| ()).inspect(|()| {
            tracing::info!(rustc_version, "submitted preheat run");
        })
    }

    /// `build-crate.yml` runs queued and in progress, per runner
    /// family — two API calls per query (`?status=queued` and
    /// `?status=in_progress` on the workflow's runs listing), plus one
    /// call per `Link` page a status runs past 100 rows.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError`] on a transport failure, a refused
    /// listing, or a `Link` page pointing outside the endpoint's
    /// origin.
    /// The `queued` and `in_progress` `build-crate.yml` runs the
    /// listing reports — two API calls per query plus one per `Link`
    /// page a status runs past 100 rows.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError`] on a transport failure, a refused
    /// listing, or a `Link` page pointing outside the endpoint's
    /// origin.
    pub async fn status_runs(&self) -> Result<Vec<CiRunListing>, DispatchError> {
        let mut runs = Vec::new();
        for (status, query) in [
            (CiRunStatus::Queued, "queued"),
            (CiRunStatus::InProgress, "in_progress"),
        ] {
            let mut url = self.resolve(&format!(
                "repos/{}/actions/workflows/{}/runs?status={query}&per_page=100",
                self.repo(),
                crate::trusted_builder::WORKFLOW_FILE,
            ))?;
            loop {
                let request = self.api_request("GET", &url, None);
                let response = self.send_checked(request).await?;
                let page: RunsPage = serde_json::from_slice(&response.body)
                    .map_err(|error| DispatchError::Response(format!("{error}")))?;
                runs.extend(page.workflow_runs.iter().map(|run| {
                    let family = family_of_run_title(&run.display_title);
                    if family.is_none() {
                        tracing::warn!(
                            title = %run.display_title,
                            "build-crate run's title attributes to no runner family"
                        );
                    }
                    CiRunListing {
                        workflow_run_id: run.id,
                        title: run.display_title.clone(),
                        family,
                        status,
                    }
                }));
                let Some(next) = crate::runs::link_next(response.header("link")) else {
                    break;
                };
                url = self.resolve(next)?;
            }
        }
        Ok(runs)
    }

    /// `build-crate.yml` runs queued and in progress, per runner
    /// family — [`CiInterface::status_runs`] folded into counts.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError`] exactly as [`CiInterface::status_runs`].
    pub async fn status(&self) -> Result<Occupancy, DispatchError> {
        let mut occupancy = Occupancy::EMPTY;
        for run in self.status_runs().await? {
            match run.family {
                Some(family) => occupancy.add(family),
                None => occupancy.add_unknown(),
            }
        }
        Ok(occupancy)
    }

    /// The repository the GitHub-shaped paths address — the endpoint's
    /// own repo on GitHub, [`crate::trusted_builder::REPOSITORY`] on
    /// the local server (which ignores the value but serves the path).
    fn repo(&self) -> &str {
        match &self.endpoint {
            CiEndpoint::GitHub { repo, .. } => repo,
            CiEndpoint::Local { .. } => crate::trusted_builder::REPOSITORY,
        }
    }

    /// Resolve a relative path or a `Link`-returned absolute URL inside
    /// the endpoint's origin — anything else is refused, since a
    /// followed URL carries the endpoint's credentials to a host the
    /// API never named.
    fn resolve(&self, path_or_url: &str) -> Result<String, DispatchError> {
        let base = match &self.endpoint {
            CiEndpoint::GitHub { .. } => "https://api.github.com",
            CiEndpoint::Local { base } => base.as_str(),
        };
        scoped_url(base, path_or_url)
    }

    /// One API request against the endpoint — GitHub's bearer headers,
    /// or the local server's unauthenticated POST/GET.
    fn api_request(&self, method: &'static str, url: &str, body: Option<Vec<u8>>) -> CiRequest {
        let mut headers = Vec::new();
        if let CiEndpoint::GitHub { token, .. } = &self.endpoint {
            headers.extend([
                (
                    "Accept".to_owned(),
                    "application/vnd.github+json".to_owned(),
                ),
                ("X-GitHub-Api-Version".to_owned(), "2022-11-28".to_owned()),
                ("User-Agent".to_owned(), "stow-ci".to_owned()),
                ("Authorization".to_owned(), format!("Bearer {token}")),
            ]);
        }
        if body.is_some() {
            headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
        }
        CiRequest {
            method,
            url: url.to_owned(),
            headers,
            body,
        }
    }

    /// The `workflow_dispatch` request for `workflow_file`/`input`
    /// under this endpoint's verb: GitHub's `dispatches` POST (the
    /// named input as a JSON *string*, the run-details flag the
    /// scheduler binds from), or the local server's `/dispatch` event.
    fn dispatch_request(
        &self,
        workflow_file: &str,
        event_type: &str,
        input_name: &str,
        input: &serde_json::Value,
        return_run_details: bool,
    ) -> Result<CiRequest, DispatchError> {
        match &self.endpoint {
            CiEndpoint::GitHub { repo, .. } => {
                let input_json = serde_json::to_string(input)
                    .map_err(|error| DispatchError::Network(error.to_string()))?;
                let mut payload = serde_json::json!({
                    "ref": crate::trusted_builder::BRANCH,
                    "inputs": { input_name: input_json },
                });
                if return_run_details {
                    payload["return_run_details"] = serde_json::Value::Bool(true);
                }
                let url = self.resolve(&workflow_dispatch_path(repo, workflow_file))?;
                let body = serde_json::to_vec(&payload)
                    .map_err(|error| DispatchError::Network(error.to_string()))?;
                Ok(self.api_request("POST", &url, Some(body)))
            }
            CiEndpoint::Local { base } => {
                let payload = serde_json::json!({
                    "event_type": event_type,
                    "client_payload": input,
                });
                let body = serde_json::to_vec(&payload)
                    .map_err(|error| DispatchError::Network(error.to_string()))?;
                Ok(self.api_request("POST", &format!("{base}/dispatch"), Some(body)))
            }
        }
    }

    /// Send one request and enforce the answer's contract: a 2xx goes
    /// through, a rate limit names its wait, a 5xx or transport
    /// failure is the write/read that settled nothing, anything else
    /// is the API's refusal.
    async fn send_checked(&self, request: CiRequest) -> Result<CiResponse, DispatchError> {
        let response = self.transport.send(request).await?;
        if (200..300).contains(&response.status) {
            return Ok(response);
        }
        Err(classify_failure(&response))
    }
}

/// `repos/{repo}/actions/workflows/{file}/dispatches` — GitHub's
/// `workflow_dispatch` path shape, shared verbatim by the local
/// server's GitHub-shaped endpoints.
fn workflow_dispatch_path(repo: &str, workflow_file: &str) -> String {
    format!("repos/{repo}/actions/workflows/{workflow_file}/dispatches")
}

/// Resolve `path_or_url` under `base` — a relative path joins it, and
/// an absolute URL is followed only while it stays inside the base's
/// origin (scheme, host and port together; the `/` boundary refuses
/// prefix lookalikes like `api.github.com.evil`). Anything else is
/// refused: followed verbatim it would carry the request — and any
/// bearer it bears — to a host the API never named.
fn scoped_url(base: &str, path_or_url: &str) -> Result<String, DispatchError> {
    if path_or_url.starts_with("http://") || path_or_url.starts_with("https://") {
        if path_or_url == base || path_or_url.starts_with(&format!("{base}/")) {
            return Ok(path_or_url.to_owned());
        }
        return Err(DispatchError::OutOfScope(path_or_url.to_owned()));
    }
    Ok(format!("{base}/{path_or_url}"))
}

/// GitHub's `{"total_count", "workflow_runs"}` envelope — only the
/// title the occupancy attribution reads is decoded.
#[derive(serde::Deserialize)]
struct RunsPage {
    workflow_runs: Vec<RunRow>,
}

/// One run row — `display_title` is the `run-name`
/// `build-crate.yml` stamps.
#[derive(serde::Deserialize)]
struct RunRow {
    id: u64,
    display_title: String,
}

#[derive(serde::Deserialize)]
struct DispatchRunDetails {
    workflow_run_id: u64,
    run_url: String,
    html_url: String,
}

fn decode_run_details(body: &str) -> Result<DispatchedRun, DispatchError> {
    serde_json::from_str::<DispatchRunDetails>(body)
        .map(|details| DispatchedRun {
            workflow_run_id: details.workflow_run_id,
            run_url: details.run_url,
            html_url: details.html_url,
        })
        .map_err(|error| DispatchError::Response(format!("{error}: {body}")))
}

/// Classify a non-2xx answer for the caller's resolve-then-resend
/// decision: a rate limit is a refusal that names its wait (`429`, a
/// `Retry-After` or `Retry-After`-shaped 403, a 403/429 with
/// `x-ratelimit-remaining: 0`), a 5xx is the answer that settled
/// nothing, and every other status is the API's refusal — the write
/// provably did not happen.
fn classify_failure(response: &CiResponse) -> DispatchError {
    let status = response.status;
    let retry_after = response
        .header("retry-after")
        .and_then(|value| value.trim().parse::<u64>().ok());
    let primary_exhausted = response
        .header("x-ratelimit-remaining")
        .is_some_and(|remaining| remaining.trim() == "0");
    if status == 429 || (status == 403 && (retry_after.is_some() || primary_exhausted)) {
        return DispatchError::RateLimited {
            status,
            retry_after_secs: retry_after,
        };
    }
    let body = String::from_utf8_lossy(&response.body);
    let body = body.chars().take(512).collect::<String>();
    DispatchError::Api {
        status,
        body: body.trim().to_owned(),
    }
}

/// How an interface call failed — the caller's retry fence: a
/// `RateLimited`/`Api` refusal provably did not happen, a `Network`/
/// `Response` failure may have landed.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    /// The send or the response-body read failed — whether the write
    /// happened is unknown.
    #[error("network error: {0}")]
    Network(String),
    /// The GitHub App installation token mint failed before any call.
    #[error("GitHub App installation token mint failed: {0}")]
    TokenMint(String),
    /// The API refused with a non-rate-limit answer — the write
    /// provably did not happen (`status`, first bytes of its body).
    #[error("GitHub API error {status}: {body}")]
    Api {
        /// HTTP status the API answered.
        status: u16,
        /// The answer's leading bytes.
        body: String,
    },
    /// GitHub's rate limit answered — the write did not happen, and
    /// `retry_after_secs` is the wait it named when it named one.
    #[error("GitHub rate limit (HTTP {status})")]
    RateLimited {
        /// HTTP status — `429`, or a `403` carrying the limit's marks.
        status: u16,
        /// `Retry-After` seconds the answer named, when it named one.
        retry_after_secs: Option<u64>,
    },
    /// The dispatch POST succeeded but its run-details body did not
    /// read or decode — the run may exist unbound, so the caller
    /// abandons the generation and lets a fresh one claim.
    #[error("dispatch response unreadable: {0}")]
    Response(String),
    /// A `Link` header's `next` pointed outside the endpoint's own
    /// origin — followed verbatim it would carry the request, and any
    /// bearer it bears, to a host the API never named.
    #[error("out-of-origin URL refused: {0}")]
    OutOfScope(String),
}

#[cfg(test)]
mod tests {
    use super::{
        CiInterface, CiRequest, CiResponse, DispatchError, Occupancy, RunnerFamily,
        family_of_run_title, scoped_url, workflow_dispatch_path,
    };
    use std::future::Future;
    use std::sync::Mutex;

    /// A scripted transport: each send answers the next queued
    /// response and records the request it was called with.
    struct Stub {
        requests: Mutex<Vec<(String, String)>>,
        answers: Mutex<Vec<CiResponse>>,
    }

    impl Stub {
        fn answer(status: u16, headers: &[(&str, &str)], body: &str) -> CiResponse {
            CiResponse {
                status,
                headers: headers
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
                body: body.as_bytes().to_vec(),
            }
        }
    }

    impl super::CiTransport for Stub {
        fn send(
            &self,
            request: CiRequest,
        ) -> impl Future<Output = Result<CiResponse, DispatchError>> + Send {
            self.requests
                .lock()
                .expect("requests")
                .push((request.method.to_owned(), request.url));
            std::future::ready(Ok(self.answers.lock().expect("answers").remove(0)))
        }
    }

    fn task_id() -> String {
        "serde-1.0.219-".to_owned()
            + &"a".repeat(64)
            + "-x86_64_unknown_linux_gnu-1_99_0-d"
            + &"b".repeat(64)
    }

    #[test]
    fn the_run_endpoint_paths_are_shared_verbatim() {
        assert_eq!(
            workflow_dispatch_path("water-rs/stow", "build-crate.yml"),
            "repos/water-rs/stow/actions/workflows/build-crate.yml/dispatches"
        );
    }

    #[test]
    fn a_link_url_stays_inside_the_endpoint_origin() {
        assert_eq!(
            scoped_url(
                "https://api.github.com",
                "https://api.github.com/repos/o/r/actions/runs?page=2",
            )
            .expect("in-scope next URL"),
            "https://api.github.com/repos/o/r/actions/runs?page=2"
        );
        assert_eq!(
            scoped_url("https://api.github.com", "repos/o/r").expect("relative path"),
            "https://api.github.com/repos/o/r"
        );
        for url in [
            "https://evil.example/repos/o/r",
            "http://api.github.com/repos/o/r",
            "https://api.github.com.evil/x",
            "https://api.github.com2/x",
        ] {
            let error = scoped_url("https://api.github.com", url).expect_err("refused");
            assert!(error.to_string().contains(url), "{error} names {url}");
        }
        assert!(scoped_url("http://127.0.0.1:8787", "http://127.0.0.1:8787/repos/o/r").is_ok());
        for url in [
            "http://127.0.0.1:87870/repos",
            "https://127.0.0.1:8787/repos",
        ] {
            assert!(scoped_url("http://127.0.0.1:8787", url).is_err(), "{url}");
        }
    }

    #[test]
    fn a_run_title_attributes_to_its_runner_family() {
        let title = format!("1.99.0-{}", task_id());
        assert_eq!(family_of_run_title(&title), Some(RunnerFamily::Linux));
        let macos = title.replace("x86_64_unknown_linux_gnu", "aarch64_apple_darwin");
        assert_eq!(family_of_run_title(&macos), Some(RunnerFamily::MacOs));
        let windows = title.replace("x86_64_unknown_linux_gnu", "aarch64_pc_windows_msvc");
        assert_eq!(family_of_run_title(&windows), Some(RunnerFamily::Windows));
        for title in [
            "",
            "not-a-title",
            "1.99.0-crate-with-no-segments",
            "resolve-a1-req",
        ] {
            assert_eq!(family_of_run_title(title), None, "{title}");
        }
    }

    #[test]
    fn occupancy_budgets_share_one_margin() {
        assert_eq!(super::STOW_RUNNER_BUDGET, 45);
        assert_eq!(super::STOW_MACOS_RUNNER_BUDGET, 16);
        let mut occupancy = Occupancy::EMPTY;
        for _ in 0..44 {
            occupancy.add(RunnerFamily::Linux);
        }
        assert_eq!(occupancy.free_for(RunnerFamily::Linux), 1);
        assert_eq!(occupancy.free_for(RunnerFamily::MacOs), 1);
        occupancy.add(RunnerFamily::Linux);
        assert_eq!(occupancy.free_for(RunnerFamily::Linux), 0);
        assert_eq!(occupancy.free_for(RunnerFamily::MacOs), 0);
        let mut macos = Occupancy::EMPTY;
        for _ in 0..16 {
            macos.add(RunnerFamily::MacOs);
        }
        assert_eq!(macos.free_for(RunnerFamily::MacOs), 0);
        assert_eq!(macos.free_for(RunnerFamily::Linux), 29);
    }

    #[test]
    fn status_reads_both_statuses_and_walks_pages() {
        let runs = |titles: &[String]| {
            serde_json::json!({
                "total_count": titles.len(),
                "workflow_runs": titles
                    .iter()
                    .enumerate()
                    .map(|(i, t)| serde_json::json!({"id": i + 1, "display_title": t}))
                    .collect::<Vec<_>>(),
            })
            .to_string()
        };
        let build = format!("1.99.0-{}", task_id());
        let answers = vec![
            Stub::answer(
                200,
                &[("link", "<https://api.github.com/next-page>; rel=\"next\"")],
                &runs(std::slice::from_ref(&build)),
            ),
            Stub::answer(200, &[], &runs(&[])),
            Stub::answer(200, &[], &runs(std::slice::from_ref(&build))),
        ];
        let stub = Stub {
            requests: Mutex::new(Vec::new()),
            answers: Mutex::new(answers),
        };
        let interface = CiInterface::github("water-rs/stow", "token", stub);
        let occupancy = futures_lite::future::block_on(interface.status()).expect("status");
        assert_eq!(occupancy.of(RunnerFamily::Linux), 2);
        assert_eq!(occupancy.total(), 2);
        let requests = interface.transport.requests.lock().expect("requests");
        assert_eq!(requests.len(), 3);
        assert!(requests[0].1.contains("status=queued"));
        assert_eq!(requests[1].1, "https://api.github.com/next-page");
        assert!(requests[2].1.contains("status=in_progress"));
        drop(requests);
    }

    #[test]
    fn a_refused_submit_classifies() {
        let answers = vec![Stub::answer(429, &[("retry-after", "30")], "{}")];
        let stub = Stub {
            requests: Mutex::new(Vec::new()),
            answers: Mutex::new(answers),
        };
        let interface = CiInterface::github("water-rs/stow", "token", stub);
        let error = futures_lite::future::block_on(interface.submit("{}")).expect_err("refused");
        assert!(matches!(
            error,
            DispatchError::RateLimited {
                status: 429,
                retry_after_secs: Some(30)
            }
        ));
    }
}
