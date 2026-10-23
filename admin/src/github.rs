//! GitHub REST plumbing for `stow-admin runs` and `stow-admin cache` —
//! both commands talk to `api.github.com` directly with the operator's
//! token; the edge is not involved.

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use futures_util::StreamExt as _;
use stow_types::runs::link_next;
use stow_types::stow_error;
use stow_types::transient::{
    Backoff, RateLimit, is_transient_status, rate_limit, retry_after_hint,
};
use zenwave::{Client, ResponseExt};

/// The repository every request below addresses — the build workflows'
/// runs and the Actions cache live here.
pub const REPO: &str = "water-rs/stow";

pub const API_BASE: &str = "https://api.github.com";
pub const USER_AGENT: &str = "stow-admin";
/// Workflow file whose runs `runs failures`, `builds digest` and the
/// watchdog's pipeline signals inspect — the batch workflow, whose
/// runs carry every leg (stow#833). Spelled once in `stow_types` with
/// the identity the scheduler dispatches to and certificates assert.
pub use stow_types::trusted_builder::BATCH_WORKFLOW_FILE as BUILD_WORKFLOW;

/// `GET` one API path under `/repos/{REPO}/` and decode the JSON body.
/// The response body rides zenwave errors, so a rejection carries
/// GitHub's own message.
pub async fn get<T: serde::de::DeserializeOwned>(
    token: &str,
    path: &str,
    backoff: Backoff,
) -> stow_types::error::Result<T> {
    get_path(token, &format!("/repos/{REPO}/{path}"), backoff).await
}

/// `GET` an absolute `api.github.com` path (leading `/`) and decode the
/// JSON body — for endpoints outside `/repos/{REPO}`: the repository
/// search and other repositories' git trees.
pub async fn get_path<T: serde::de::DeserializeOwned>(
    token: &str,
    path: &str,
    backoff: Backoff,
) -> stow_types::error::Result<T> {
    let url = format!("{API_BASE}{path}");
    get_path_result(token, path, backoff)
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
    backoff: Backoff,
) -> std::result::Result<T, zenwave::Error> {
    let url = format!("{API_BASE}{path}");
    let response = send_get(
        Some(token),
        &url,
        Some("application/vnd.github+json"),
        None,
        backoff,
    )
    .await?;
    Ok(response.error_for_status().await?.into_json().await?)
}

/// What an `If-None-Match` GET answers: `Modified` carries the fresh body
/// and the validator GitHub sent (when it sends one — an endpoint that
/// omits `ETag` simply makes every read a full GET, still correct but
/// charged against the primary rate budget), and `Unmodified` means the
/// caller's cached copy still stands. An authorized 304 is free under
/// that budget, so tracked-run polling stays cheap at any wave size.
pub enum Conditional<T> {
    Modified { body: T, etag: Option<String> },
    Unmodified,
}

/// `GET` one API path under `/repos/{REPO}/` as a conditional request:
/// `etag` rides `If-None-Match`, a 304 answers [`Conditional::Unmodified`]
/// without parsing the (empty) body, and a 200 answers the decoded body
/// plus the response's `ETag` to carry forward.
pub async fn get_conditional<T: serde::de::DeserializeOwned>(
    token: &str,
    path: &str,
    etag: Option<&str>,
    backoff: Backoff,
) -> stow_types::error::Result<Conditional<T>> {
    get_conditional_result(token, path, etag, backoff)
        .await
        .map_err(|error| stow_error!("GET {API_BASE}/repos/{REPO}/{path}: {error}"))
}

/// Like [`get_conditional`], but the raw transport error escapes so the
/// caller can read the status itself — a 404 on a just-dispatched run id
/// is the run not materialized yet, a fact about timing, not a failure.
pub async fn get_conditional_result<T: serde::de::DeserializeOwned>(
    token: &str,
    path: &str,
    etag: Option<&str>,
    backoff: Backoff,
) -> std::result::Result<Conditional<T>, zenwave::Error> {
    let url = format!("{API_BASE}/repos/{REPO}/{path}");
    let response = send_get(
        Some(token),
        &url,
        Some("application/vnd.github+json"),
        etag,
        backoff,
    )
    .await?;
    if response.status().as_u16() == 304 {
        drop(response);
        return Ok(Conditional::Unmodified);
    }
    let response = response.error_for_status().await?;
    let etag = response
        .headers()
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = response.into_json().await?;
    Ok(Conditional::Modified { body, etag })
}

/// [`get_conditional_result`] on an absolute URL — the same 200/304
/// contract for callers holding a full URL rather than a repo path:
/// paginated endpoints, whose `Link` walk addresses page URLs
/// directly. The answer's own `Link: rel="next"` comes back alongside
/// — the cursor [`ConditionalPages`] caches with the page.
pub async fn get_url_conditional<T: serde::de::DeserializeOwned>(
    token: Option<&str>,
    url: &str,
    etag: Option<&str>,
    backoff: Backoff,
) -> std::result::Result<(Conditional<T>, Option<String>), zenwave::Error> {
    let response = send_get(
        token,
        url,
        Some("application/vnd.github+json"),
        etag,
        backoff,
    )
    .await?;
    if response.status().as_u16() == 304 {
        drop(response);
        return Ok((Conditional::Unmodified, None));
    }
    let response = response.error_for_status().await?;
    let etag = response
        .headers()
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let next = link_next(
        response
            .headers()
            .get("link")
            .and_then(|value| value.to_str().ok()),
    )
    .map(str::to_owned);
    let body = response.into_json().await?;
    Ok((Conditional::Modified { body, etag }, next))
}

/// A paginated endpoint's conditional cache — one entry per page URL:
/// the `ETag` its last 200 carried, the decoded page and the
/// `Link: rel="next"` the same answer served. Revalidating sends each
/// URL's own validator: a 304 serves the cached page and its cached
/// `next`, a 200 replaces all three. A repeated reader — the watch's
/// per-tick listings and jobs pages — pays a full body only for a
/// page that actually changed; an authorized 304 is free under
/// GitHub's primary rate budget.
pub struct ConditionalPages<T> {
    pages: BTreeMap<String, ConditionalPage<T>>,
}

/// One page URL's cached answer.
struct ConditionalPage<T> {
    /// The validator the page's last 200 carried — `None` for an
    /// endpoint that sends none, which then revalidates as a full
    /// GET every time.
    etag: Option<String>,
    /// The decoded page.
    page: T,
    /// The `Link: rel="next"` the same answer carried — revalidated
    /// with the page, so a walk keeps the chain it cached.
    next: Option<String>,
}

impl<T: serde::de::DeserializeOwned> ConditionalPages<T> {
    /// An empty cache — every URL's first read is an unconditional GET.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
        }
    }

    /// The page `url` serves, revalidating a cached copy on its own
    /// `ETag`: a 304 answers the cached page and its cached `next`, a
    /// 200 replaces them. Returns the page and its `next` link.
    ///
    /// # Errors
    /// The failure `send_get` ended on — a terminal status, a dead
    /// body or an exhausted retry budget — named with the URL.
    pub async fn get(
        &mut self,
        token: Option<&str>,
        url: &str,
        backoff: Backoff,
    ) -> stow_types::error::Result<(&T, Option<&str>)> {
        let etag = self.pages.get(url).and_then(|page| page.etag.as_deref());
        match get_url_conditional(token, url, etag, backoff).await {
            Ok((Conditional::Modified { body, etag }, next)) => {
                self.pages.insert(
                    url.to_owned(),
                    ConditionalPage {
                        etag,
                        page: body,
                        next,
                    },
                );
            }
            Ok((Conditional::Unmodified, _)) => {}
            Err(error) => return Err(stow_error!("GET {url}: {error}")),
        }
        // A 304 is only an answer to the validator a cached page sent;
        // one for a URL the cache never held is GitHub misbehaving.
        let cached = self
            .pages
            .get(url)
            .ok_or_else(|| stow_error!("GET {url}: 304 for a page never cached"))?;
        Ok((&cached.page, cached.next.as_deref()))
    }
}

/// `GET` an absolute URL and decode the JSON body under the same
/// bounded idempotent-read policy, attaching `Authorization` only when
/// `token` is `Some`. The local CI server's reads are unauthenticated —
/// they pass `None`, so no operator token can leave the machine.
pub async fn get_url_json<T: serde::de::DeserializeOwned>(
    url: &str,
    token: Option<&str>,
    backoff: Backoff,
) -> stow_types::error::Result<T> {
    let response = send_get(token, url, None, None, backoff)
        .await
        .map_err(|error| stow_error!("GET {url}: {error}"))?;
    response
        .error_for_status()
        .await
        .map_err(|error| stow_error!("GET {url}: {error}"))?
        .into_json()
        .await
        .map_err(|error| stow_error!("read {url}: {error}"))
}

/// The wall clock in epoch seconds — read at the call site so
/// [`rate_limit`] itself stays clock-free, and a test scripts its own
/// reset instead of the suite waiting a wall-clock hour.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// Warn once per rate-limit wait: the URL, the wait, and the
/// `x-ratelimit-reset` epoch the answer carried, when it carried one.
fn warn_rate_limit(url: &str, wait: Duration, reset: Option<i64>) {
    tracing::warn!(url, wait = ?wait, reset = ?reset, "rate-limited; waiting for the reset");
}

/// `GET` `url`, retried on transport errors and transient statuses by
/// the caller's [`Backoff`]; `Authorization` rides the request only
/// when `token` is `Some`. zenwave delivers an error status as `Err`,
/// the response inside it — a terminal status is its error without
/// another attempt, a transient one carries its `Retry-After` hint into
/// the wait, and a failure that outlives the budget returns as its
/// final error. A rate-limited answer is neither: it is GitHub naming
/// when to come back, so its wait — `Retry-After`, or until
/// `x-ratelimit-reset` — is slept in full and the attempt never spends
/// the budget. The retried unit is the whole read — request, status
/// and body: the body is read to completion inside the loop, so a
/// connection cut mid-body retries like any other transport failure,
/// and what leaves the loop is a response whose body is already in
/// memory — a complete body that does not parse is terminal, never a
/// retry.
pub async fn send_get(
    token: Option<&str>,
    url: &str,
    accept: Option<&str>,
    if_none_match: Option<&str>,
    mut backoff: Backoff,
) -> std::result::Result<zenwave::Response, zenwave::Error> {
    loop {
        let mut client = zenwave::client();
        let mut request = client.get(url)?.header("User-Agent", USER_AGENT)?;
        if let Some(token) = token {
            request = request.header("Authorization", format!("Bearer {token}"))?;
        }
        let request = match accept {
            Some(accept) => request.header("Accept", accept)?,
            None => request,
        };
        let request = match if_none_match {
            Some(etag) => request.header("If-None-Match", etag)?,
            None => request,
        };
        let (error, retry_after) = match request.await {
            Ok(response) => {
                if let Some(RateLimit::Wait { wait, reset }) =
                    rate_limit(response.status().as_u16(), response.headers(), unix_now())
                {
                    warn_rate_limit(url, wait, reset);
                    tokio::time::sleep(wait).await;
                    continue;
                }
                if is_transient_status(response.status().as_u16()) {
                    let retry_after = retry_after_hint(response.headers());
                    match response.error_for_status().await {
                        Ok(response) => return Ok(response),
                        Err(error) => (error, retry_after),
                    }
                } else {
                    // A response cut while its body streams is the same
                    // transport failure a cut request is — buffer the body
                    // inside the loop so the retry covers it, and rebuild
                    // the response over the complete bytes so nothing the
                    // caller reads can still meet the wire.
                    let (parts, body) = response.into_parts();
                    match body.into_bytes().await {
                        Ok(bytes) => {
                            return Ok(zenwave::Response::from_parts(
                                parts,
                                zenwave::Body::from(bytes),
                            ));
                        }
                        Err(error) => (zenwave::Error::BodyParse(error), None),
                    }
                }
            }
            Err(error) => {
                if let Some(RateLimit::Wait { wait, reset }) =
                    error.response().and_then(|response| {
                        rate_limit(response.status().as_u16(), response.headers(), unix_now())
                    })
                {
                    warn_rate_limit(url, wait, reset);
                    tokio::time::sleep(wait).await;
                    continue;
                }
                let http = error.response().map(|response| {
                    (
                        response.status().as_u16(),
                        retry_after_hint(response.headers()),
                    )
                });
                match http {
                    Some((status, _)) if !is_transient_status(status) => return Err(error),
                    Some((_, retry_after)) => (error, retry_after),
                    None => (error, None),
                }
            }
        };
        let Some(wait) = backoff.next_wait(retry_after) else {
            return Err(error);
        };
        tracing::warn!(url, %error, wait = ?wait, "request failed; retrying");
        tokio::time::sleep(wait).await;
    }
}

/// `GET` an absolute URL as text — job-log fetches redirect to GitHub's
/// signed blob host, where the `Authorization` header must not follow
/// (zenwave strips it cross-origin).
pub async fn get_text(
    token: &str,
    url: &str,
    backoff: Backoff,
) -> stow_types::error::Result<String> {
    let response = send_get(Some(token), url, None, None, backoff)
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

/// How a GitHub write's failure classifies: whether the write reached
/// GitHub is the only thing that decides what the caller may do next —
/// a write that provably did not happen can be sent again or failed,
/// a write that might have happened can only be resolved by reading
/// the object it would have created.
#[derive(Debug)]
pub enum WriteFailure {
    /// GitHub answered with a status that is neither a rate limit nor
    /// 5xx — the write did not happen and repeating it is pointless.
    Refused(String),
    /// A rate-limit answer per [`rate_limit`] — a 429, a 403 carrying
    /// `Retry-After`, or a 403/429 whose `x-ratelimit-remaining` is `0`:
    /// the write did not happen, and the hint is the wait the answer
    /// named, when it named one.
    RateLimited {
        /// The rendered failure, context included.
        message: String,
        /// The answer's own wait — `Retry-After`, or until
        /// `x-ratelimit-reset` — when it carried one.
        hint: Option<Duration>,
    },
    /// A 5xx, or a transport failure from the send or the response-body
    /// read: nobody knows whether the write happened.
    Ambiguous(String),
}

impl WriteFailure {
    /// The wait a rate-limited answer named — `Retry-After`, or the
    /// reset-derived wait — `None` for every other kind and for a
    /// hintless 429.
    #[must_use]
    pub const fn hint(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { hint, .. } => *hint,
            _ => None,
        }
    }
}

impl std::fmt::Display for WriteFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::Refused(message)
            | Self::Ambiguous(message)
            | Self::RateLimited { message, .. } => message,
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for WriteFailure {}

/// Classify a write's failure answer for the caller's
/// resolve-then-resend decision — `pub` for the local dispatch arm in
/// `manual`, which speaks to the mock server over the same zenwave
/// path. `context` is the `"{method} {url}"` prefix the message
/// renders with. Rate-limit answers classify through [`rate_limit`],
/// the same decision [`send_get`] waits out on reads.
pub fn classify_write(context: &str, error: &zenwave::Error) -> WriteFailure {
    let message = format!("{context}: {error}");
    let Some(response) = error.response() else {
        return WriteFailure::Ambiguous(message);
    };
    let status = response.status().as_u16();
    match rate_limit(status, response.headers(), unix_now()) {
        Some(RateLimit::Wait { wait, .. }) => WriteFailure::RateLimited {
            message,
            hint: Some(wait),
        },
        Some(RateLimit::Unstated) => WriteFailure::RateLimited {
            message,
            hint: None,
        },
        None if status >= 500 => WriteFailure::Ambiguous(message),
        None => WriteFailure::Refused(message),
    }
}

/// `POST` one API path under `/repos/{REPO}/` with a JSON body and
/// decode the JSON response.
///
/// # Errors
/// The typed [`WriteFailure`] — callers that do not branch on the kind
/// convert it with `?`; callers that do get to tell a refused write
/// from one whose answer never settled.
pub async fn post<T: serde::de::DeserializeOwned>(
    token: &str,
    path: &str,
    body: &(impl serde::Serialize + Sync),
) -> Result<T, WriteFailure> {
    send_json(
        token,
        zenwave::Method::POST,
        &format!("{API_BASE}/repos/{REPO}/{path}"),
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
    Ok(send_json(
        token,
        zenwave::Method::PATCH,
        &format!("{API_BASE}/repos/{REPO}/{path}"),
        Some(body),
    )
    .await?)
}

/// `PUT` an empty body to one API path under `/repos/{REPO}/` —
/// `PUT`/`POST` endpoints that take no payload, like the workflow
/// enable/disable routes, which answer 204.
pub async fn put(token: &str, path: &str) -> stow_types::error::Result<()> {
    send_empty(
        token,
        zenwave::Method::PUT,
        &format!("{API_BASE}/repos/{REPO}/{path}"),
    )
    .await?;
    Ok(())
}

/// One `send_json`/`send_empty` implementation behind the verb helpers:
/// an authenticated request to `url` whose 2xx body decodes as `T`.
async fn send_json<T: serde::de::DeserializeOwned>(
    token: &str,
    method: zenwave::Method,
    url: &str,
    body: Option<&(impl serde::Serialize + Sync)>,
) -> Result<T, WriteFailure> {
    let response = send_write(token, method.clone(), url, body).await?;
    response
        .into_json()
        .await
        .map_err(|error| WriteFailure::Ambiguous(format!("read {method} {url}: {error}")))
}

/// Like [`send_json`] for endpoints whose 2xx answer carries no body —
/// the response is status-checked and dropped.
async fn send_empty(token: &str, method: zenwave::Method, url: &str) -> Result<(), WriteFailure> {
    let response = send_write(token, method, url, None::<&serde_json::Value>).await?;
    drop(response);
    Ok(())
}

/// The send half every write shares: an authenticated request whose
/// answer is status-checked. A failure to build the request is a write
/// that never happened — [`WriteFailure::Refused`]; the answer's own
/// failure classifies through [`classify_write`].
async fn send_write(
    token: &str,
    method: zenwave::Method,
    url: &str,
    body: Option<&(impl serde::Serialize + Sync)>,
) -> Result<zenwave::Response, WriteFailure> {
    let refused =
        |error: zenwave::Error| WriteFailure::Refused(format!("build {method} {url}: {error}"));
    let mut client = zenwave::client();
    let request = client
        .method(method.clone(), url)
        .map_err(refused)?
        .header("Authorization", format!("Bearer {token}"))
        .and_then(|request| request.header("User-Agent", USER_AGENT))
        .and_then(|request| request.header("Accept", "application/vnd.github+json"))
        .and_then(|request| request.header("X-GitHub-Api-Version", "2022-11-28"))
        .map_err(refused)?;
    let request = match body {
        Some(body) => request.json_body(body).map_err(|error| {
            WriteFailure::Refused(format!("build {method} {url} body: {error}"))
        })?,
        None => request,
    };
    let context = format!("{method} {url}");
    let response = request
        .await
        .map_err(|error| classify_write(&context, &error))?
        .error_for_status()
        .await
        .map_err(|error| classify_write(&context, &error))?;
    Ok(response)
}

/// `DELETE` one API path under `/repos/{REPO}/`; 2xx/404 both count —
/// deleting an entry that is already gone achieves the same end state.
pub async fn delete(token: &str, path: &str) -> stow_types::error::Result<()> {
    delete_url(token, &format!("{API_BASE}/repos/{REPO}/{path}")).await
}

/// `delete` at a resolved URL — production passes an
/// [`API_BASE`]-rooted path, tests an owned loopback URL. A rate-limited
/// answer is a settled "not yet" — the delete provably did not happen,
/// so the wait the answer named is slept and the ask resent, the same
/// classification the reads wait out.
async fn delete_url(token: &str, url: &str) -> stow_types::error::Result<()> {
    loop {
        let mut client = zenwave::client();
        let result = client
            .delete(url)
            .map_err(|error| stow_error!("build DELETE {url}: {error}"))?
            .header("Authorization", format!("Bearer {token}"))
            .and_then(|request| request.header("User-Agent", USER_AGENT))
            .and_then(|request| request.header("Accept", "application/vnd.github+json"))
            .map_err(|error| stow_error!("build DELETE {url}: {error}"))?
            .await;
        // zenwave lifts 4xx/5xx into `Err(Error::Http)` at `.await` —
        // the 404 the doc promises lands there, not in a response branch.
        let error = match result {
            Ok(response) => match response.error_for_status().await {
                Ok(_) => return Ok(()),
                Err(error) => error,
            },
            Err(error) => error,
        };
        if matches!(error, zenwave::Error::Http { status, .. } if status == zenwave::StatusCode::NOT_FOUND)
        {
            return Ok(());
        }
        if let Some(RateLimit::Wait { wait, reset }) = error.response().and_then(|response| {
            rate_limit(response.status().as_u16(), response.headers(), unix_now())
        }) {
            warn_rate_limit(url, wait, reset);
            tokio::time::sleep(wait).await;
            continue;
        }
        return Err(classify_write(&format!("DELETE {url}"), &error).into());
    }
}

/// `delete` against an explicit API root — the tests' loopback server.
#[cfg(test)]
async fn delete_at(api_base: &str, token: &str, path: &str) -> stow_types::error::Result<()> {
    delete_url(token, &format!("{api_base}/repos/{REPO}/{path}")).await
}

/// `POST` one API path under `/repos/{REPO}/` with a JSON body whose
/// 2xx answer carries no body of interest — the `workflow_dispatch`
/// calls `preheat manual` drives, which answer 204.
///
/// # Errors
/// The typed [`WriteFailure`], exactly like [`post`].
pub async fn post_empty(
    token: &str,
    path: &str,
    body: &serde_json::Value,
) -> Result<(), WriteFailure> {
    let response = send_write(
        token,
        zenwave::Method::POST,
        &format!("{API_BASE}/repos/{REPO}/{path}"),
        Some(body),
    )
    .await?;
    drop(response);
    Ok(())
}

// ===== workflow-run enumeration =====

/// The Actions `runs` listing's hard cap on one filtered query: page 11
/// of a >1000-row answer comes back empty and `total_count` says 0, so a
/// window at the cap subdivides rather than pages past it (stow#555).
pub const RUNS_LISTING_CAP: usize = 1000;
/// Concurrent independent range reads while enumerating — the same
/// explicit bound every read fan-out in this crate uses (the watch's
/// per-run jobs and log reads included, stow#853).
pub const RANGE_READ_CONCURRENCY: usize = 8;

/// The `runs` listing's page shape — `total_count` is what makes the cap
/// visible before page 11 silently empties.
#[derive(Debug, serde::Deserialize)]
#[serde(bound(deserialize = "Row: serde::de::DeserializeOwned"))]
pub struct RunsPage<Row> {
    /// The listing's declared row count — required: a body without it is
    /// not a runs page and must fail deserialize, never read as empty.
    pub total_count: u64,
    pub workflow_runs: Vec<Row>,
}

/// A workflow-run row's identity — dedup across subdivision boundaries
/// and the cap decision live on it.
pub trait RunRow {
    fn run_id(&self) -> u64;
}

/// One run row as both `workflow_runs` listings and `actions/runs/{id}`
/// serve it — every field the crate's run readers share: identity and
/// `run_attempt` for the jobs reads, `display_title` for the batch
/// binding, `head_sha`/`created_at` for staleness and dispatch
/// resolution, `actor` for who dispatched.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WorkflowRunRow {
    /// The run's id.
    pub id: u64,
    /// The rendered `run-name` — `<rustc>-b<batch_id>` for a batch run.
    pub display_title: String,
    /// The commit the run builds.
    pub head_sha: String,
    /// `queued`/`in_progress`/`completed` as GitHub serves it.
    pub status: String,
    /// The run's conclusion — `None` until it completes.
    pub conclusion: Option<String>,
    /// The run's Actions URL.
    pub html_url: String,
    /// GitHub's attempt counter — `rerun-failed-jobs` bumps it, and the
    /// jobs read is pinned to it (stow#852).
    pub run_attempt: u64,
    /// GitHub's creation time for the run — the preheat driver's
    /// unresolved-dispatch resolution accepts a run only at or after
    /// its node's attempt, minus the clock allowance.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    /// Who dispatched the run — the App's `[bot]` login on
    /// scheduler-dispatched runs, the operator's on `preheat manual`.
    /// The watch renders it.
    pub actor: Actor,
}

/// The `actor` object a run row carries — only the login is read, and
/// only by the watch.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Actor {
    /// The actor's login — the watch renders it.
    pub login: String,
}

impl RunRow for WorkflowRunRow {
    fn run_id(&self) -> u64 {
        self.id
    }
}

/// One closed `created` window, `[start..end]` inclusive at the second
/// precision GitHub's `created` filter works at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreatedRange {
    start: time::OffsetDateTime,
    end: time::OffsetDateTime,
}

impl CreatedRange {
    /// A range floored to whole seconds — GitHub compares `created` at
    /// second precision, and integer seconds are what subdivide cleanly.
    pub fn new(start: time::OffsetDateTime, end: time::OffsetDateTime) -> Self {
        let second = |t: time::OffsetDateTime| {
            time::OffsetDateTime::from_unix_timestamp(t.unix_timestamp())
                .expect("whole seconds representable")
        };
        Self {
            start: second(start),
            end: second(end),
        }
    }

    /// The `created=a..b` filter text for this window.
    fn query(&self) -> String {
        let rfc3339 = |t: time::OffsetDateTime| {
            t.format(&time::format_description::well_known::Rfc3339)
                .expect("rfc3339")
        };
        format!("{}..{}", rfc3339(self.start), rfc3339(self.end))
    }

    /// Two strictly smaller windows covering this one. A single-second
    /// window cannot halve — `None` there is the overflow condition.
    fn halves(&self) -> Option<(Self, Self)> {
        let lo = self.start.unix_timestamp();
        let hi = self.end.unix_timestamp();
        if lo >= hi {
            return None;
        }
        let mid = lo + (hi - lo) / 2;
        let at = |ts| Self {
            start: time::OffsetDateTime::from_unix_timestamp(ts)
                .expect("whole seconds representable"),
            end: time::OffsetDateTime::from_unix_timestamp(ts)
                .expect("whole seconds representable"),
        };
        Some((
            Self {
                start: at(lo).start,
                end: at(mid).end,
            },
            Self {
                start: at(mid + 1).start,
                end: at(hi).end,
            },
        ))
    }
}

/// One range fetch's answer: the rows, or a pair of sub-windows when the
/// range sits over the listing cap.
enum RangeOutcome<Row> {
    Rows(Vec<Row>),
    Split(CreatedRange, CreatedRange),
}

/// Every run in `range` matching `filters` — read pages until exhausted;
/// a `total_count` over [`RUNS_LISTING_CAP`] splits instead of paging
/// into the capped tail.
async fn fetch_range<Row, F, Fut>(
    workflow: &str,
    filters: &str,
    range: CreatedRange,
    fetch: &F,
) -> stow_types::error::Result<RangeOutcome<Row>>
where
    Row: RunRow + Send,
    F: Fn(String) -> Fut + Sync,
    Fut: std::future::Future<Output = stow_types::error::Result<RunsPage<Row>>> + Send,
{
    let page_path = |page: u32| {
        format!(
            "actions/workflows/{workflow}/runs?{filters}&created={}&per_page=100&page={page}",
            range.query()
        )
    };
    let first = fetch(page_path(1)).await?;
    if first.total_count > RUNS_LISTING_CAP as u64 {
        let Some((a, b)) = range.halves() else {
            return Err(stow_error!(
                "more than {RUNS_LISTING_CAP} workflow runs share one second ({}) — the window cannot subdivide further",
                range.query()
            ));
        };
        return Ok(RangeOutcome::Split(a, b));
    }
    let limit = usize::try_from(first.total_count).expect("total_count <= 1000");
    // The declared count is proven on DISTINCT run ids — a filtered
    // listing's rows mutate between pages, so a page can repeat ids the
    // previous page already served; Vec length reaching the declared
    // count on repeats would silently drop the tail it never saw.
    let mut rows: BTreeMap<u64, Row> = first
        .workflow_runs
        .into_iter()
        .map(|row| (row.run_id(), row))
        .collect();
    let mut page = 1u32;
    while rows.len() < limit {
        page += 1;
        let next = fetch(page_path(page)).await?;
        // The listing declared `total_count` rows but the page stream
        // ended early — an inconsistent page, which must surface,
        // never complete silently.
        if next.workflow_runs.is_empty() {
            return Err(stow_error!(
                "runs listing declared {} rows but page {page} came back empty after {} — window cannot complete",
                first.total_count,
                rows.len()
            ));
        }
        let seen = rows.len();
        rows.extend(
            next.workflow_runs
                .into_iter()
                .map(|row| (row.run_id(), row)),
        );
        if rows.len() == seen {
            return Err(stow_error!(
                "runs listing declared {} rows but page {page} repeated already-seen ids at {} — window cannot complete",
                first.total_count,
                rows.len()
            ));
        }
    }
    Ok(RangeOutcome::Rows(rows.into_values().collect()))
}

/// Enumerate every workflow-run row `filters` matches across the closed
/// `created` window `[since, until]` — for example
/// `event=workflow_dispatch&branch=main` or `status=completed`. GitHub
/// caps one filtered listing at 1000 rows, so any window reporting
/// `total_count` over the cap subdivides into smaller closed ranges
/// (bounded 8 concurrent reads) until each fits; rows dedupe on
/// [`RunRow::run_id`] across the boundaries. The captured `until` keeps
/// runs created mid-read out of the answer. A window where >1000 runs
/// share a single second cannot subdivide and fails clearly rather than
/// truncating.
///
/// `fetch` is the typed page transport — production passes
/// `github::get` under the operator token; tests drive a fake API.
///
/// The captured `until` bounds the created-time horizon so runs created
/// mid-read never join the answer — it does not freeze mutable row
/// state: GitHub is not a snapshot, and rows changing status between
/// pages can make a declared page count uncompletable, which surfaces
/// as an error rather than a silently truncated listing.
pub async fn runs_in_range<Row, F, Fut>(
    workflow: &str,
    filters: &str,
    since: time::OffsetDateTime,
    until: time::OffsetDateTime,
    fetch: F,
) -> stow_types::error::Result<Vec<Row>>
where
    Row: RunRow + Send,
    F: Fn(String) -> Fut + Sync,
    Fut: std::future::Future<Output = stow_types::error::Result<RunsPage<Row>>> + Send,
{
    if since > until {
        return Err(stow_error!(
            "runs window starts after it ends: {since}..{until}"
        ));
    }
    let mut pending: VecDeque<CreatedRange> = VecDeque::from([CreatedRange::new(since, until)]);
    let mut runs: BTreeMap<u64, Row> = BTreeMap::new();
    while !pending.is_empty() {
        let outcomes = futures_util::stream::iter(
            pending
                .drain(..pending.len().min(RANGE_READ_CONCURRENCY))
                .map(|range| fetch_range(workflow, filters, range, &fetch)),
        )
        .buffered(RANGE_READ_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
        for outcome in outcomes {
            match outcome? {
                RangeOutcome::Rows(rows) => {
                    for row in rows {
                        runs.entry(row.run_id()).or_insert(row);
                    }
                }
                RangeOutcome::Split(a, b) => {
                    pending.push_back(a);
                    pending.push_back(b);
                }
            }
        }
    }
    Ok(runs.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, serde::Deserialize)]
    struct FakeRow {
        id: u64,
    }

    impl RunRow for FakeRow {
        fn run_id(&self) -> u64 {
            self.id
        }
    }

    /// A fake `actions/workflows/{w}/runs` endpoint: rows live at
    /// `(created_unix, run_id)`, and each query is parsed back out of the
    /// path so the test sees exactly the windows and filters sent.
    struct FakeRuns {
        rows: Vec<(i64, u64)>,
        /// A `total_count` the API declares regardless of what it serves —
        /// the inconsistent-page case.
        declared: Option<u64>,
        /// Explicit page contents by page number — the mutable-paging
        /// cases that repeat ids across pages of one window.
        script: Vec<Vec<u64>>,
        queries: std::sync::Mutex<Vec<String>>,
    }

    impl FakeRuns {
        fn new(rows: Vec<(i64, u64)>) -> Self {
            Self {
                rows,
                declared: None,
                script: Vec::new(),
                queries: std::sync::Mutex::new(Vec::new()),
            }
        }

        /// Declares `total` rows but serves only what `rows` holds —
        /// the listing stream ends before its declared count.
        fn declared_but_unserved(total: u64, served: usize) -> Self {
            Self {
                rows: (0..served as u64)
                    .map(|i| (1_500_000i64, 50_000 + i))
                    .collect(),
                declared: Some(total),
                script: Vec::new(),
                queries: std::sync::Mutex::new(Vec::new()),
            }
        }

        /// Declares `total` rows: page 1 serves ids `1..=first`, and
        /// page 2 repeats that page's last `repeated` ids — the mutable
        /// listing whose row count reaches the declared count on
        /// duplicates while distinct ids stay short.
        fn repeating_tail(total: u64, first: u64, repeated: u64) -> Self {
            Self {
                rows: Vec::new(),
                declared: Some(total),
                script: vec![
                    (1..=first).collect(),
                    (first + 1 - repeated..=first).collect(),
                ],
                queries: std::sync::Mutex::new(Vec::new()),
            }
        }

        /// The production fetch shape: a page of one `created=a..b`
        /// window — `total_count` first, 100 rows per page, in the same
        /// order the API serves (callers' row order is irrelevant here).
        fn page(&self, path: &str) -> RunsPage<FakeRow> {
            self.queries.lock().expect("queries").push(path.to_owned());
            let created = path
                .split("created=")
                .nth(1)
                .and_then(|tail| tail.split('&').next())
                .expect("created filter");
            let (start, end) = created.split_once("..").expect("closed range");
            let parse = |t: &str| {
                time::OffsetDateTime::parse(t, &time::format_description::well_known::Rfc3339)
                    .expect("rfc3339 bound")
                    .unix_timestamp()
            };
            let (start, end) = (parse(start), parse(end));
            let page = path
                .split("&page=")
                .nth(1)
                .and_then(|tail| tail.split('&').next())
                .and_then(|raw| raw.parse::<usize>().ok())
                .expect("page");
            let rows: Vec<FakeRow> = if self.script.is_empty() {
                self.rows
                    .iter()
                    .filter(|(created, _)| *created >= start && *created <= end)
                    .map(|(_, id)| FakeRow { id: *id })
                    .collect()
            } else {
                self.script
                    .get(page - 1)
                    .map(|ids| ids.iter().map(|id| FakeRow { id: *id }).collect())
                    .unwrap_or_default()
            };
            let total_count = self
                .declared
                .unwrap_or_else(|| u64::try_from(rows.len()).expect("count"));
            let rows = if self.script.is_empty() {
                rows.into_iter().skip((page - 1) * 100).take(100).collect()
            } else {
                rows
            };
            RunsPage {
                total_count,
                workflow_runs: rows,
            }
        }

        fn queries(&self) -> Vec<String> {
            self.queries.lock().expect("queries").clone()
        }
    }

    fn at(seconds: i64) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(seconds).expect("timestamp")
    }

    async fn enumerate(
        api: &FakeRuns,
        filters: &str,
        since: i64,
        until: i64,
    ) -> stow_types::error::Result<Vec<u64>> {
        let rows = runs_in_range(
            "build-crate.yml",
            filters,
            at(since),
            at(until),
            |path| async move { Ok(api.page(&path)) },
        )
        .await?;
        let mut ids: Vec<u64> = rows.into_iter().map(|row| row.id).collect();
        ids.sort_unstable();
        Ok(ids)
    }

    /// The shape that broke resume: 1267 runs in one window — the old
    /// page-1..N walk silently lost the tail at page 11.
    #[tokio::test]
    async fn enumeration_reads_past_the_1000_row_cap() {
        let api = FakeRuns::new(
            (0..1267i64)
                .map(|i| (1_000_000 + i, 1000 + i.cast_unsigned()))
                .collect(),
        );
        let ids = enumerate(&api, "status=completed", 999_000, 2_000_000)
            .await
            .expect("enumerated");
        assert_eq!(ids.len(), 1267);
        assert!(ids.contains(&1000) && ids.contains(&2266));
        // The window subdivided at least once, and every query carried
        // the caller's filter and a closed created range.
        let queries = api.queries();
        assert!(queries.len() > 2, "a >1000 window must subdivide");
        assert!(
            queries
                .iter()
                .all(|q| q.contains("status=completed") && q.contains("created="))
        );
    }

    /// Rows exactly on a subdivision boundary appear in both halves'
    /// listings — dedup is on run id, not position.
    #[tokio::test]
    async fn boundary_rows_dedup_on_run_id() {
        // Force a split at second 1000_500 (midpoint of 1000000..1001000):
        // 600 rows at the boundary second plus 600 more spread out.
        let mut rows: Vec<(i64, u64)> = (0..600).map(|i| (1_000_500, 10_000 + i)).collect();
        rows.extend((0..600i64).map(|i| (1_000_000 + i, 20_000 + i.cast_unsigned())));
        let api = FakeRuns::new(rows);
        let ids = enumerate(&api, "status=failure", 1_000_000, 1_001_000)
            .await
            .expect("enumerated");
        assert_eq!(ids.len(), 1200);
        assert_eq!(
            ids.iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            1200,
            "no duplicates across boundaries"
        );
    }

    /// A sparse window answers its few rows without subdivision.
    #[tokio::test]
    async fn sparse_windows_answer_directly() {
        let api = FakeRuns::new(vec![(100, 7), (200, 9), (5_000, 11)]);
        let ids = enumerate(&api, "event=workflow_dispatch&branch=main", 0, 10_000)
            .await
            .expect("enumerated");
        assert_eq!(ids, vec![7, 9, 11]);
        assert_eq!(api.queries().len(), 1);
    }

    /// The listing declares rows it never serves — a truncated stream
    /// is an inconsistent page and must error, not complete silently.
    #[tokio::test]
    async fn a_truncated_listing_fails_instead_of_truncating() {
        let api = FakeRuns::declared_but_unserved(500, 250);
        let error = enumerate(&api, "status=completed", 1_000_000, 2_000_000)
            .await
            .expect_err("truncated listing must fail");
        assert!(error.to_string().contains("declared 500"));
    }

    /// The declared count is proven on distinct ids: page 2 repeating
    /// page 1's tail cannot fill it — a mutable listing serving 100
    /// distinct ids of a declared 120 is an inconsistent-paging error,
    /// not a successful range missing its last 20 rows.
    #[tokio::test]
    async fn repeated_page_ids_cannot_fill_the_declared_count() {
        let api = FakeRuns::repeating_tail(120, 100, 20);
        let error = enumerate(&api, "status=completed", 1_000_000, 2_000_000)
            .await
            .expect_err("repeated ids must fail");
        assert!(error.to_string().contains("repeated"));
    }

    /// A body without `total_count` is not a runs page — required fields
    /// must fail deserialize instead of reading as an empty window.
    #[test]
    fn a_page_missing_total_count_fails_deserialize() {
        assert!(serde_json::from_str::<RunsPage<FakeRow>>("{\"workflow_runs\":[]}").is_err());
        assert!(serde_json::from_str::<RunsPage<FakeRow>>("{\"total_count\":0}").is_err());
    }

    /// A window with nothing in it answers empty — one page, no split.
    #[tokio::test]
    async fn empty_windows_answer_empty() {
        let api = FakeRuns::new(Vec::new());
        let ids = enumerate(&api, "status=failure", 0, 10_000)
            .await
            .expect("enumerated");
        assert_eq!(Vec::<u64>::new(), ids);
    }

    /// More than 1000 runs in one second cannot subdivide — a clear
    /// error, never a silent truncation.
    #[tokio::test]
    async fn same_second_overflow_fails_clearly() {
        let api = FakeRuns::new((0..1500u64).map(|i| (42_000, 1 + i)).collect());
        let error = enumerate(&api, "status=completed", 41_000, 43_000)
            .await
            .expect_err("must not truncate");
        assert!(error.to_string().contains("one second"));
    }

    /// Rows outside `[since, until]` never appear, and the caller's
    /// filter rides every page query — the `workflow_dispatch`+branch
    /// filter the manual lane uses is exercised verbatim.
    #[tokio::test]
    async fn rows_outside_the_window_stay_out() {
        let api = FakeRuns::new(vec![(99, 1), (100, 2), (200, 3), (300, 4)]);
        let ids = enumerate(&api, "event=workflow_dispatch&branch=main", 100, 200)
            .await
            .expect("enumerated");
        assert_eq!(ids, vec![2, 3]);
        assert!(
            api.queries()
                .iter()
                .all(|q| q.contains("event=workflow_dispatch&branch=main"))
        );
    }

    /// 204 and 404 both close the delete — the contract is the end
    /// state, one request either way.
    #[tokio::test]
    async fn delete_accepts_removed_and_already_gone() {
        for status in [204u16, 404] {
            let server =
                crate::test_server::Loopback::start(vec![crate::test_server::Step::Respond {
                    status,
                    retry_after: None,
                    body: "{}",
                }])
                .await;
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                delete_at(&server.url, "test-token", "actions/caches/42"),
            )
            .await
            .expect("delete completes within the deadline")
            .unwrap_or_else(|error| panic!("delete status {status}: {error}"));
            let heads = server.join().await;
            assert_eq!(heads.len(), 1, "delete status {status}");
        }
    }

    /// Authorization and server failures stay errors — the 204/404
    /// contract admits nothing else.
    #[tokio::test]
    async fn delete_propagates_other_failures() {
        for status in [403u16, 500] {
            let server =
                crate::test_server::Loopback::start(vec![crate::test_server::Step::Respond {
                    status,
                    retry_after: None,
                    body: "{}",
                }])
                .await;
            let outcome = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                delete_at(&server.url, "test-token", "actions/caches/42"),
            )
            .await
            .expect("delete completes within the deadline");
            assert!(outcome.is_err(), "delete status {status}");
            let heads = server.join().await;
            assert_eq!(heads.len(), 1, "delete status {status}");
        }
    }
}

#[cfg(test)]
mod url_json_tests {
    use super::{Backoff, get_url_json};
    use crate::test_server;

    /// A connection the server drops without answering is a transport
    /// failure the shared policy retries — the same read succeeds on
    /// the next connection.
    #[tokio::test]
    async fn get_url_json_recovers_a_dropped_connection() {
        let server = test_server::Loopback::start(vec![
            test_server::Step::Drop,
            test_server::Step::Respond {
                status: 200,
                retry_after: None,
                body: r#"{"ok":true}"#,
            },
        ])
        .await;
        let body: serde_json::Value = get_url_json(&server.url, None, Backoff::new())
            .await
            .expect("a dropped connection retries");
        assert_eq!(body["ok"], true);
        let heads = server.join().await;
        assert_eq!(heads.len(), 2);
    }

    /// A transient status waits out its `Retry-After` hint and retries —
    /// the bounded hint lengthens the wait, it is not ignored.
    #[tokio::test]
    async fn get_url_json_retries_a_transient_status_after_its_hint() {
        let server = test_server::Loopback::start(vec![
            test_server::Step::Respond {
                status: 503,
                retry_after: Some(1),
                body: "{}",
            },
            test_server::Step::Respond {
                status: 200,
                retry_after: None,
                body: r#"{"ok":true}"#,
            },
        ])
        .await;
        let started = std::time::Instant::now();
        let body: serde_json::Value = get_url_json(&server.url, None, Backoff::new())
            .await
            .expect("a transient status retries");
        assert_eq!(body["ok"], true);
        let elapsed = started.elapsed();
        assert!(
            elapsed >= std::time::Duration::from_secs(1),
            "the Retry-After hint must be honored, elapsed {elapsed:?}"
        );
        server.join().await;
    }

    /// A terminal status is the answer — fail fast, never retry. A
    /// retry would reach the server's success sentinel and this test
    /// would see an `Ok`, so the error and the single captured request
    /// both prove the stop.
    #[tokio::test]
    async fn get_url_json_does_not_retry_a_terminal_status() {
        let server = test_server::Loopback::start(vec![test_server::Step::Respond {
            status: 404,
            retry_after: None,
            body: r#"{"message":"gone"}"#,
        }])
        .await;
        let result: stow_types::error::Result<serde_json::Value> =
            get_url_json(&server.url, None, Backoff::new()).await;
        assert!(result.is_err());
        let heads = server.join().await;
        assert_eq!(heads.len(), 1);
    }

    /// A 403 without rate-limit markers is the answer, not the limit —
    /// terminal, never retried.
    #[tokio::test]
    async fn get_url_json_does_not_retry_a_plain_403() {
        let server = test_server::Loopback::start(vec![test_server::Step::Respond {
            status: 403,
            retry_after: None,
            body: r#"{"message":"forbidden"}"#,
        }])
        .await;
        let result: stow_types::error::Result<serde_json::Value> =
            get_url_json(&server.url, None, Backoff::new()).await;
        assert!(result.is_err());
        let heads = server.join().await;
        assert_eq!(heads.len(), 1);
    }

    /// GitHub's primary rate limit — a 403 with `x-ratelimit-remaining: 0`
    /// and a near `x-ratelimit-reset` — is the server naming when to come
    /// back, not the request's failure: the read waits out the reset and
    /// retries, and the wait never spends the attempt budget — three
    /// 503s after it still fit inside `Backoff::new`'s three retries.
    #[tokio::test]
    async fn get_url_json_waits_out_the_primary_limit_without_spending_budget() {
        let server = test_server::Loopback::start(vec![
            test_server::Step::RateLimited {
                status: 403,
                reset_in: 1,
                body: "{}",
            },
            test_server::Step::Respond {
                status: 503,
                retry_after: None,
                body: "{}",
            },
            test_server::Step::Respond {
                status: 503,
                retry_after: None,
                body: "{}",
            },
            test_server::Step::Respond {
                status: 503,
                retry_after: None,
                body: "{}",
            },
            test_server::Step::Respond {
                status: 200,
                retry_after: None,
                body: r#"{"ok":true}"#,
            },
        ])
        .await;
        let started = std::time::Instant::now();
        let body: serde_json::Value = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            get_url_json(&server.url, None, Backoff::new()),
        )
        .await
        .expect("the limited read completes inside the bound")
        .expect("the reset is waited out and the read retries");
        assert_eq!(body["ok"], true);
        assert!(
            started.elapsed() >= std::time::Duration::from_secs(1),
            "the reset wait was honored"
        );
        let heads = server.join().await;
        assert_eq!(heads.len(), 5);
    }

    /// A `200` whose body the connection cuts mid-read is the same
    /// transport failure a dropped request is — the retried unit is the
    /// whole read, so the second attempt answers the parsed value.
    #[tokio::test]
    async fn get_url_json_retries_a_body_cut_mid_read() {
        let server = test_server::Loopback::start(vec![
            test_server::Step::Stall {
                status: 200,
                body: r#"{"ok":tr"#,
                content_length: 64,
            },
            test_server::Step::Respond {
                status: 200,
                retry_after: None,
                body: r#"{"ok":true}"#,
            },
        ])
        .await;
        let body: serde_json::Value = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            get_url_json(&server.url, None, Backoff::new()),
        )
        .await
        .expect("a cut body completes inside the bound")
        .expect("a cut body retries");
        assert_eq!(body["ok"], true);
        let heads = server.join().await;
        assert_eq!(heads.len(), 2);
    }

    /// The same cut on every attempt spends the budget and returns the
    /// final error — never a hang and never a panic.
    #[tokio::test]
    async fn get_url_json_fails_a_body_cut_past_the_budget() {
        let server = test_server::Loopback::start(
            (0..4)
                .map(|_| test_server::Step::Stall {
                    status: 200,
                    body: r#"{"ok":tr"#,
                    content_length: 64,
                })
                .collect(),
        )
        .await;
        let result: stow_types::error::Result<serde_json::Value> = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            get_url_json(&server.url, None, Backoff::new()),
        )
        .await
        .expect("a cut body ends inside the bound");
        assert!(result.is_err(), "the final error returns, it does not hang");
        let heads = server.join().await;
        assert_eq!(heads.len(), 4);
    }

    /// A 2xx that does not decode is a failure, not a retry — the same
    /// sentinel liveness proves the client stopped.
    #[tokio::test]
    async fn get_url_json_fails_a_malformed_body() {
        let server = test_server::Loopback::start(vec![test_server::Step::Respond {
            status: 200,
            retry_after: None,
            body: "not json",
        }])
        .await;
        let result: stow_types::error::Result<serde_json::Value> =
            get_url_json(&server.url, None, Backoff::new()).await;
        assert!(result.is_err());
        let heads = server.join().await;
        assert_eq!(heads.len(), 1);
    }

    /// An outage budget waits an incident out: four `502`s spend the
    /// burst budget's four attempts, and the read still answers the
    /// fifth attempt's `200`. The waits are real — a paused clock would
    /// fire the loopback's own per-connection bound mid-burst — so this
    /// test costs the 7.5 s of pauses it proves.
    #[tokio::test]
    async fn get_url_json_waits_out_a_502_burst_under_the_outage_budget() {
        let steps = (0..4)
            .map(|_| test_server::Step::Respond {
                status: 502,
                retry_after: None,
                body: "{}",
            })
            .chain([test_server::Step::Respond {
                status: 200,
                retry_after: None,
                body: r#"{"ok":true}"#,
            }])
            .collect();
        let server = test_server::Loopback::start(steps).await;
        let body: serde_json::Value = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            get_url_json(&server.url, None, Backoff::outage()),
        )
        .await
        .expect("the outage read completes inside its real-time bound")
        .expect("four 502s are inside the outage budget");
        assert_eq!(body["ok"], true);
        let heads = server.join().await;
        assert_eq!(heads.len(), 5);
    }

    /// A transient failure that outlives the budget returns its final
    /// error — after exactly four tries, the shared policy's bound.
    #[tokio::test]
    async fn get_url_json_returns_the_final_error_when_the_budget_runs_out() {
        let server = test_server::Loopback::start(
            (0..4)
                .map(|_| test_server::Step::Respond {
                    status: 503,
                    retry_after: None,
                    body: "{}",
                })
                .collect(),
        )
        .await;
        let result: stow_types::error::Result<serde_json::Value> =
            get_url_json(&server.url, None, Backoff::new()).await;
        assert!(result.is_err());
        let heads = server.join().await;
        assert_eq!(heads.len(), 4);
    }
}

#[cfg(test)]
mod send_get_tests {
    use super::{Backoff, send_get};
    use crate::test_server;

    /// A conditional GET's 304 answer carries no `Location` — it is a
    /// cache verdict, not a redirect. The client must deliver it so the
    /// caller can read the status itself; treating it as a redirect
    /// failure (or retrying past it) is the bug under test.
    #[tokio::test]
    async fn send_get_delivers_a_conditional_304_without_location() {
        let server = test_server::Loopback::start(vec![test_server::Step::Respond {
            status: 304,
            retry_after: None,
            body: "",
        }])
        .await;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            send_get(None, &server.url, None, Some("\"v1\""), Backoff::new()),
        )
        .await
        .expect("the conditional read answers inside the bound");
        let heads = server.join().await;
        let response = result.expect("a 304 without Location is a response, not a redirect error");
        assert_eq!(heads.len(), 1);
        assert_eq!(heads[0].head.method, http::Method::GET);
        assert_eq!(
            heads[0]
                .head
                .headers
                .get(http::header::IF_NONE_MATCH)
                .expect("the validator rides the request"),
            "\"v1\""
        );
        assert_eq!(response.status().as_u16(), 304);
    }
}

#[cfg(test)]
mod conditional_pages_tests {
    use super::{Backoff, ConditionalPages};
    use crate::test_server;

    #[derive(Debug, serde::Deserialize)]
    struct Page {
        n: u64,
    }

    /// A URL's cached entry revalidates on the `ETag` its last 200
    /// sent: a 304 serves the cached page, a 200 replaces the entry,
    /// and the next read sends the new validator.
    #[tokio::test]
    async fn conditional_pages_revalidate_on_their_own_etags() {
        let server = test_server::Loopback::start(vec![
            test_server::Step::RespondWith {
                status: 200,
                retry_after: None,
                headers: vec![("etag".to_owned(), "\"p1\"".to_owned())],
                body: r#"{"n":1}"#,
            },
            test_server::Step::Respond {
                status: 304,
                retry_after: None,
                body: "",
            },
            test_server::Step::RespondWith {
                status: 200,
                retry_after: None,
                headers: vec![("etag".to_owned(), "\"p2\"".to_owned())],
                body: r#"{"n":2}"#,
            },
            test_server::Step::Respond {
                status: 304,
                retry_after: None,
                body: "",
            },
        ])
        .await;
        let mut pages = ConditionalPages::<Page>::new();
        for expected in [1u64, 1, 2, 2] {
            let (page, _) = pages
                .get(None, &server.url, Backoff::new())
                .await
                .expect("the read answers");
            assert_eq!(page.n, expected);
        }
        let heads = server.join().await;
        assert_eq!(heads.len(), 4);
        assert!(heads[0].head.headers.get("if-none-match").is_none());
        assert_eq!(
            heads[1].head.headers.get("if-none-match").expect("etag"),
            "\"p1\""
        );
        assert_eq!(
            heads[2].head.headers.get("if-none-match").expect("etag"),
            "\"p1\""
        );
        assert_eq!(
            heads[3].head.headers.get("if-none-match").expect("etag"),
            "\"p2\""
        );
    }

    /// The cached `next` is revalidated with its page: a 304 answers
    /// the link the page's last 200 carried, a 200 replaces it.
    #[tokio::test]
    async fn conditional_pages_revalidate_the_cached_next_link() {
        let server = test_server::Loopback::start(vec![
            test_server::Step::RespondWith {
                status: 200,
                retry_after: None,
                headers: vec![
                    ("etag".to_owned(), "\"p1\"".to_owned()),
                    (
                        "link".to_owned(),
                        "<https://api.github.com/page2>; rel=\"next\"".to_owned(),
                    ),
                ],
                body: r#"{"n":1}"#,
            },
            test_server::Step::Respond {
                status: 304,
                retry_after: None,
                body: "",
            },
        ])
        .await;
        let mut pages = ConditionalPages::<Page>::new();
        for _ in 0..2 {
            let (_, next) = pages
                .get(None, &server.url, Backoff::new())
                .await
                .expect("the read answers");
            assert_eq!(next, Some("https://api.github.com/page2"));
        }
        server.join().await;
    }
}

#[cfg(test)]
mod write_tests {
    use super::{WriteFailure, send_write};
    use crate::test_server;

    /// One scripted POST through the shared write path — the body is a
    /// dispatch-like JSON object.
    async fn write(url: &str) -> Result<(), WriteFailure> {
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            send_write(
                "test-token",
                zenwave::Method::POST,
                url,
                Some(&serde_json::json!({"a": 1})),
            ),
        )
        .await
        .expect("the write answers inside the bound")
        .map(|_| ())
    }

    /// Every 5xx is ambiguous: the write may have landed before the
    /// error answer left, so it can be neither retried blind nor
    /// treated as a failure.
    #[tokio::test]
    async fn a_5xx_answer_is_ambiguous() {
        for status in [500u16, 502] {
            let server = test_server::Loopback::start(vec![test_server::Step::Respond {
                status,
                retry_after: None,
                body: "{}",
            }])
            .await;
            let result = write(&server.url).await;
            assert!(
                matches!(result, Err(WriteFailure::Ambiguous(_))),
                "status {status} must classify ambiguous, got {result:?}"
            );
            let heads = server.join().await;
            assert_eq!(heads.len(), 1);
        }
    }

    /// A terminal non-rate-limit answer is refused: the write did not
    /// happen and repeating it is pointless.
    #[tokio::test]
    async fn a_terminal_answer_is_refused() {
        for status in [422u16, 403] {
            let server = test_server::Loopback::start(vec![test_server::Step::Respond {
                status,
                retry_after: None,
                body: "{}",
            }])
            .await;
            let result = write(&server.url).await;
            assert!(
                matches!(result, Err(WriteFailure::Refused(_))),
                "status {status} must classify refused, got {result:?}"
            );
            let heads = server.join().await;
            assert_eq!(heads.len(), 1);
        }
    }

    /// A 429 outright, and a 403 carrying `Retry-After` — GitHub's
    /// secondary-limit shape on writes — are rate-limited answers
    /// carrying the hint through to the caller's backoff.
    #[tokio::test]
    async fn rate_limits_carry_their_retry_after_hint() {
        for (status, retry_after) in [(429u16, 3), (403, 7)] {
            let server = test_server::Loopback::start(vec![test_server::Step::Respond {
                status,
                retry_after: Some(retry_after),
                body: "{}",
            }])
            .await;
            let result = write(&server.url).await;
            match result {
                Err(WriteFailure::RateLimited { hint, .. }) => {
                    assert_eq!(
                        hint,
                        Some(std::time::Duration::from_secs(retry_after)),
                        "status {status} carries the hint"
                    );
                }
                other => panic!("status {status} must classify rate-limited, got {other:?}"),
            }
            let heads = server.join().await;
            assert_eq!(heads.len(), 1);
        }
    }

    /// GitHub's primary limit on a write — a 403 with
    /// `x-ratelimit-remaining: 0` and a `x-ratelimit-reset` — is
    /// `RateLimited` whose hint is the reset-derived wait, so the
    /// wave's write gate pauses sends for the answer's own duration.
    #[tokio::test]
    async fn a_primary_limit_answer_is_rate_limited_with_the_reset_hint() {
        let server = test_server::Loopback::start(vec![test_server::Step::RateLimited {
            status: 403,
            reset_in: 30,
            body: "{}",
        }])
        .await;
        let result = write(&server.url).await;
        match result {
            Err(WriteFailure::RateLimited {
                hint: Some(hint), ..
            }) => {
                assert!(
                    (28..=33).contains(&hint.as_secs()),
                    "the hint is the reset-derived wait, got {hint:?}"
                );
            }
            other => panic!("a primary-limit 403 must classify rate-limited, got {other:?}"),
        }
        let heads = server.join().await;
        assert_eq!(heads.len(), 1);
    }

    /// A bare 429 stays rate-limited but names no wait — the hint is
    /// `None` and the caller's own budget paces the resend.
    #[tokio::test]
    async fn a_bare_429_is_rate_limited_without_a_hint() {
        let server = test_server::Loopback::start(vec![test_server::Step::Respond {
            status: 429,
            retry_after: None,
            body: "{}",
        }])
        .await;
        let result = write(&server.url).await;
        match result {
            Err(WriteFailure::RateLimited { hint: None, .. }) => {}
            other => panic!("a bare 429 must classify rate-limited hintless, got {other:?}"),
        }
        let heads = server.join().await;
        assert_eq!(heads.len(), 1);
    }

    /// A connection closed before any answer is the ambiguous case the
    /// driver exists for — the request left the machine and nobody can
    /// say whether it landed.
    #[tokio::test]
    async fn a_connection_closed_before_the_answer_is_ambiguous() {
        let server = test_server::Loopback::start(vec![test_server::Step::Drop]).await;
        let result = write(&server.url).await;
        assert!(
            matches!(result, Err(WriteFailure::Ambiguous(_))),
            "a dropped connection must classify ambiguous, got {result:?}"
        );
        let heads = server.join().await;
        assert_eq!(heads.len(), 1);
        assert_eq!(heads[0].head.method, http::Method::POST);
    }

    /// A 2xx answer is the confirmed write — no failure kind at all.
    #[tokio::test]
    async fn a_success_answer_returns_the_response() {
        let server = test_server::Loopback::start(vec![test_server::Step::Respond {
            status: 204,
            retry_after: None,
            body: "",
        }])
        .await;
        write(&server.url).await.expect("204 is a confirmed write");
        let heads = server.join().await;
        assert_eq!(heads.len(), 1);
    }
}
