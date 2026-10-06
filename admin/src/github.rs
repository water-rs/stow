//! GitHub REST plumbing for `stow-admin runs` and `stow-admin cache` —
//! both commands talk to `api.github.com` directly with the operator's
//! token; the edge is not involved.

use std::collections::{BTreeMap, VecDeque};

use futures_util::StreamExt as _;
use stow_types::stow_error;
use stow_types::transient::{Backoff, is_transient_status, retry_after_hint};
use zenwave::{Client, ResponseExt};

/// The repository every request below addresses — `build-crate.yml` runs
/// and the Actions cache live here.
pub const REPO: &str = "water-rs/stow";

pub const API_BASE: &str = "https://api.github.com";
pub const USER_AGENT: &str = "stow-admin";
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
    let response = send_get(Some(token), &url, Some("application/vnd.github+json"), None).await?;
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
) -> stow_types::error::Result<Conditional<T>> {
    get_conditional_result(token, path, etag)
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
) -> std::result::Result<Conditional<T>, zenwave::Error> {
    let url = format!("{API_BASE}/repos/{REPO}/{path}");
    let response = send_get(Some(token), &url, Some("application/vnd.github+json"), etag).await?;
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

/// `GET` an absolute URL and decode the JSON body under the same
/// bounded idempotent-read policy, attaching `Authorization` only when
/// `token` is `Some`. The local CI server's reads are unauthenticated —
/// they pass `None`, so no operator token can leave the machine.
pub async fn get_url_json<T: serde::de::DeserializeOwned>(
    url: &str,
    token: Option<&str>,
) -> stow_types::error::Result<T> {
    let response = send_get(token, url, None, None)
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

/// `GET` `url`, retried on transport errors and transient statuses by
/// the shared [`Backoff`] policy; `Authorization` rides the request only
/// when `token` is `Some`. zenwave delivers an error status as `Err`,
/// the response inside it — a terminal status is its error without
/// another attempt, a transient one carries its `Retry-After` hint into
/// the wait, and a failure that outlives the budget returns as its
/// final error.
async fn send_get(
    token: Option<&str>,
    url: &str,
    accept: Option<&str>,
    if_none_match: Option<&str>,
) -> std::result::Result<zenwave::Response, zenwave::Error> {
    let mut backoff = Backoff::new();
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
            Err(error) => {
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
        tracing::warn!(url, %error, "request failed; retrying");
        tokio::time::sleep(wait).await;
    }
}

/// `GET` an absolute URL as text — job-log fetches redirect to GitHub's
/// signed blob host, where the `Authorization` header must not follow
/// (zenwave strips it cross-origin).
pub async fn get_text(token: &str, url: &str) -> stow_types::error::Result<String> {
    let response = send_get(Some(token), url, None, None)
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
    delete_at(API_BASE, token, path).await
}

/// `delete` at an explicit API root — production passes [`API_BASE`],
/// tests an owned loopback URL.
async fn delete_at(api_base: &str, token: &str, path: &str) -> stow_types::error::Result<()> {
    let url = format!("{api_base}/repos/{REPO}/{path}");
    let mut client = zenwave::client();
    let result = client
        .delete(&url)
        .map_err(|error| stow_error!("build DELETE {url}: {error}"))?
        .header("Authorization", format!("Bearer {token}"))
        .and_then(|request| request.header("User-Agent", USER_AGENT))
        .and_then(|request| request.header("Accept", "application/vnd.github+json"))
        .map_err(|error| stow_error!("build DELETE {url}: {error}"))?
        .await;
    // zenwave lifts 4xx/5xx into `Err(Error::Http)` at `.await` — the
    // 404 the doc promises lands there, not in a response branch.
    let error = match result {
        Ok(response) => match response.error_for_status().await {
            Ok(_) => return Ok(()),
            Err(error) => error,
        },
        Err(error) => error,
    };
    if matches!(error, zenwave::Error::Http { status, .. } if status == zenwave::StatusCode::NOT_FOUND)
    {
        Ok(())
    } else {
        Err(stow_error!("DELETE {url}: {error}"))
    }
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

// ===== workflow-run enumeration =====

/// The Actions `runs` listing's hard cap on one filtered query: page 11
/// of a >1000-row answer comes back empty and `total_count` says 0, so a
/// window at the cap subdivides rather than pages past it (stow#555).
pub const RUNS_LISTING_CAP: usize = 1000;
/// Concurrent independent range reads while enumerating — the same
/// explicit bound every read fan-out in this crate uses.
const RANGE_READ_CONCURRENCY: usize = 8;

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
    use super::get_url_json;
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
        let body: serde_json::Value = get_url_json(&server.url, None)
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
        let body: serde_json::Value = get_url_json(&server.url, None)
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
            get_url_json(&server.url, None).await;
        assert!(result.is_err());
        let heads = server.join().await;
        assert_eq!(heads.len(), 1);
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
            get_url_json(&server.url, None).await;
        assert!(result.is_err());
        let heads = server.join().await;
        assert_eq!(heads.len(), 1);
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
            get_url_json(&server.url, None).await;
        assert!(result.is_err());
        let heads = server.join().await;
        assert_eq!(heads.len(), 4);
    }
}

#[cfg(test)]
mod send_get_tests {
    use super::send_get;
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
            send_get(None, &server.url, None, Some("\"v1\"")),
        )
        .await
        .expect("the conditional read answers inside the bound");
        let heads = server.join().await;
        let response = result.expect("a 304 without Location is a response, not a redirect error");
        assert_eq!(heads.len(), 1);
        assert_eq!(heads[0].method, http::Method::GET);
        assert_eq!(
            heads[0]
                .headers
                .get(http::header::IF_NONE_MATCH)
                .expect("the validator rides the request"),
            "\"v1\""
        );
        assert_eq!(response.status().as_u16(), 304);
    }
}
