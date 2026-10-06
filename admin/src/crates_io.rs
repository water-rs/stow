//! crates.io access for the preheat lanes.
//!
//! crates.io's data-access policy caps crawlers at one request per
//! second on `crates.io` itself — the JSON API and the `.crate` download
//! endpoint alike — and asks each client to name itself and where it
//! lives in `User-Agent`. `index.crates.io`, the sparse index cargo
//! reads, is CDN-served and exempt from the cap. So every `crates.io`
//! call runs through the [`CratesIo`] client's pace gate, every request
//! carries that user agent, and a `Retry-After` answer is honored as the
//! delay it asks for rather than retried under the crawler window.
//!
//! Version and dependency data come from the sparse index wherever the
//! API is not needed. The API serves only what the index cannot: the
//! `sort=downloads` rankings, the per-version download counts a version
//! line is measured by, and the `has_lib` flag that picks a ranked
//! crate's lane.

use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use stow_types::stow_error;
use zenwave::{Client, HttpError, ResponseExt};

use stow_types::transient::{Backoff, is_transient_status, retry_after_hint};

/// `GET /api/v1/crates…` — the crates.io JSON API root the lanes read.
pub const API_BASE: &str = "https://crates.io/api/v1/crates";
/// The sparse index host — static files, CDN-served, outside the crawler
/// rate limit.
const INDEX_BASE: &str = "https://index.crates.io";

/// The user agent the data-access policy asks for: the tool's name and
/// version plus its repository URL as contact.
const USER_AGENT: &str = concat!(
    "stow-admin/",
    env!("CARGO_PKG_VERSION"),
    " (https://github.com/water-rs/stow)"
);

const TIMEOUT: Duration = Duration::from_secs(15);
/// Index files are larger than the API envelopes but still metadata —
/// the metadata timeout applies.
const INDEX_TIMEOUT: Duration = Duration::from_secs(30);

/// Minimum spacing between requests to `crates.io` — the policy's one
/// request per second, enforced globally so concurrent callers cannot
/// burst past it. The index host is exempt and skips the gate.
const MIN_INTERVAL: Duration = Duration::from_secs(1);

/// The crates.io client one lane is handed: owns the pace gate's
/// last-request instant and the run's API request count, so pacing and
/// accounting are a value threaded through the call chain rather than
/// process-global state.
pub struct CratesIo {
    /// When the previous `crates.io` request left — `None` until the
    /// first one.
    last_request: Option<Instant>,
    /// `crates.io` requests issued through this client — every attempt
    /// on every endpoint counts. Index fetches do not go through it.
    api_requests: u64,
}

impl CratesIo {
    /// A fresh client — its first request waits out no interval.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last_request: None,
            api_requests: 0,
        }
    }

    /// How many crates.io requests this client has issued. Reported on
    /// the dry-run plan so a lane shows what its resolve cost the API.
    #[must_use]
    pub const fn api_requests(&self) -> u64 {
        self.api_requests
    }

    /// The pace gate: a request to `crates.io` starts at least
    /// [`MIN_INTERVAL`] after the previous one through this client.
    /// `&mut self` serializes callers — pacing to one a second means the
    /// calls could not run concurrently anyway.
    async fn pace(&mut self) {
        if let Some(previous) = self.last_request {
            let wait = MIN_INTERVAL.saturating_sub(previous.elapsed());
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
        }
        self.last_request = Some(Instant::now());
        self.api_requests += 1;
    }

    /// `GET` a `crates.io` URL: paced, counted, retried on transient
    /// statuses with `Retry-After` honored. The caller decides what the
    /// successful body decodes to.
    async fn fetch(
        &mut self,
        url: &str,
        timeout: Duration,
    ) -> stow_types::error::Result<zenwave::Response> {
        let mut backoff = Backoff::new();
        loop {
            self.pace().await;
            match fetch_once(url, timeout).await {
                FetchOutcome::Body(response) => return Ok(response),
                FetchOutcome::Retryable { error, retry_after } => {
                    let Some(wait) = backoff.next_wait(retry_after) else {
                        return Err(error);
                    };
                    tracing::warn!(url, %error, "crates.io request failed; retrying");
                    tokio::time::sleep(wait).await;
                }
                FetchOutcome::Fatal(error) => return Err(error),
            }
        }
    }

    /// `GET` a crates.io JSON endpoint and decode the body.
    pub async fn get_json<T>(&mut self, url: &str) -> stow_types::error::Result<T>
    where
        T: DeserializeOwned,
    {
        self.fetch(url, TIMEOUT)
            .await?
            .into_json()
            .await
            .map_err(|error| stow_error!("parse crates.io JSON from {url}: {error}"))
    }
}

/// What one attempt produced: a usable response, a failure worth
/// retrying (with any `Retry-After` hint the response carried), or a
/// final answer.
enum FetchOutcome {
    Body(zenwave::Response),
    Retryable {
        error: stow_types::error::Error,
        retry_after: Option<Duration>,
    },
    Fatal(stow_types::error::Error),
}

/// One paced GET of a `crates.io` URL.
async fn fetch_once(url: &str, timeout: Duration) -> FetchOutcome {
    // The default client already follows redirects; the request bound is
    // a tokio timeout so the awaited error stays `zenwave::Error` — the
    // middleware stack's error type is opaque.
    let mut client = zenwave::client();
    let request = match client
        .get(url)
        .and_then(|request| request.header("User-Agent", USER_AGENT))
    {
        Ok(request) => request,
        Err(error) => {
            return FetchOutcome::Retryable {
                error: stow_error!("build crates.io request for {url}: {error}"),
                retry_after: None,
            };
        }
    };
    // zenwave lifts 4xx/5xx into `Err` before any status branch — whichever
    // arm carries the response, one `(status, hint)` extraction feeds the
    // single classification below; transport/timeout failures retry with
    // no hint.
    let (status, retry_after, error) =
        match tokio::time::timeout(timeout, async move { request.await }).await {
            Ok(Err(error)) => {
                let Some(response) = error.response() else {
                    return FetchOutcome::Retryable {
                        error: stow_error!("fetch crates.io {url}: {error}"),
                        retry_after: None,
                    };
                };
                (
                    response.status().as_u16(),
                    retry_after_hint(response.headers()),
                    stow_error!("fetch crates.io {url}: {error}"),
                )
            }
            Ok(Ok(response)) if response.status().is_success() => {
                return FetchOutcome::Body(response);
            }
            Ok(Ok(response)) => (
                response.status().as_u16(),
                retry_after_hint(response.headers()),
                stow_error!("crates.io {url} returned HTTP {}", response.status()),
            ),
            Err(_) => {
                return FetchOutcome::Retryable {
                    error: stow_error!("fetch crates.io {url}: timed out"),
                    retry_after: None,
                };
            }
        };
    if is_transient_status(status) {
        FetchOutcome::Retryable { error, retry_after }
    } else {
        FetchOutcome::Fatal(error)
    }
}

// ===== lane-facing fetchers =====

/// The `GET /crates` list element — an id and its all-time downloads,
/// which is the only ranking signal the API serves.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CrateSummary {
    /// The crate name.
    pub id: String,
    /// All-time downloads across every release.
    pub downloads: u64,
}

#[derive(Debug, serde::Deserialize)]
struct CratesResponse {
    crates: Vec<CrateSummary>,
}

/// One published release as the crate detail endpoint reports it.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CrateVersion {
    /// The `vers` string.
    pub num: String,
    /// Whether crates.io yanked the release.
    pub yanked: bool,
    /// All-time downloads of this exact version, which is how a version
    /// line's share of the crate's use is measured.
    #[serde(default)]
    pub downloads: u64,
    /// Whether the release publishes a library target, as crates.io's
    /// version record reports it. `None` on records that predate the
    /// field — an absent field is an old record, not a bin-only crate.
    #[serde(default)]
    pub has_lib: Option<bool>,
}

/// What a crate detail call answers: the full non-yanked version list
/// plus the newest release the lane should resolve.
#[derive(Debug)]
pub struct CrateDetail {
    /// Every version record the response carried.
    pub versions: Vec<CrateVersion>,
    /// `max_stable_version` then `max_version`, else the newest
    /// non-yanked entry — the pick the lanes submit.
    pub latest_version: Option<CrateVersion>,
    /// All-time download count, which the scheduler orders its queue by.
    pub downloads: u64,
}

#[derive(Debug, serde::Deserialize)]
struct CrateDetailResponse {
    #[serde(rename = "crate")]
    krate: CrateDetailNode,
    versions: Vec<CrateVersion>,
}

#[derive(Debug, serde::Deserialize)]
struct CrateDetailNode {
    #[serde(default)]
    max_stable_version: Option<String>,
    #[serde(default)]
    max_version: Option<String>,
    #[serde(default)]
    downloads: u64,
}

impl CratesIo {
    /// The top-N crates by downloads — the one ranking only the API
    /// serves.
    pub async fn fetch_top_crates(
        &mut self,
        limit: usize,
    ) -> stow_types::error::Result<Vec<CrateSummary>> {
        let per_page = limit.min(100);
        let url = format!("{API_BASE}?page=1&per_page={per_page}&sort=downloads");
        let response = self.get_json::<CratesResponse>(&url).await?;
        Ok(response.crates.into_iter().take(limit).collect())
    }

    /// One `GET /crates/{name}` — versions, features, `has_lib`,
    /// downloads. Everything the top and named-binary lanes need is in
    /// this envelope, so a crate never costs a second API call for its
    /// version list.
    pub async fn fetch_crate_detail(
        &mut self,
        crate_name: &str,
    ) -> stow_types::error::Result<CrateDetail> {
        let url = format!("{API_BASE}/{crate_name}");
        let response = self.get_json::<CrateDetailResponse>(&url).await?;
        let preferred_num = response
            .krate
            .max_stable_version
            .clone()
            .or_else(|| response.krate.max_version.clone());
        let latest_version = match preferred_num {
            Some(num) => response
                .versions
                .iter()
                .find(|candidate| candidate.num == num && !candidate.yanked)
                .cloned()
                .or_else(|| {
                    response
                        .versions
                        .iter()
                        .find(|candidate| !candidate.yanked)
                        .cloned()
                }),
            None => response
                .versions
                .iter()
                .find(|candidate| !candidate.yanked)
                .cloned(),
        };
        Ok(CrateDetail {
            versions: response.versions,
            latest_version,
            downloads: response.krate.downloads,
        })
    }

    /// The top-N binary crates: the `command-line-utilities` category
    /// list is the ranking (API), while each candidate's newest release
    /// comes from the sparse index — version data, which is exactly what
    /// the index is for, so this lane spends one API call total plus the
    /// list.
    pub async fn fetch_top_binary_crates(
        &mut self,
        limit: usize,
    ) -> stow_types::error::Result<Vec<BinaryCandidate>> {
        let mut binaries = Vec::with_capacity(limit);
        let mut page: u32 = 1;
        let scan_per_page: usize = 100;
        let max_scan_pages: u32 = 20;
        while binaries.len() < limit && page <= max_scan_pages {
            let url = format!(
                "{API_BASE}?category=command-line-utilities&page={page}&per_page={scan_per_page}&sort=downloads"
            );
            let response: CratesResponse = self.get_json(&url).await?;
            if response.crates.is_empty() {
                break;
            }
            for summary in response.crates {
                let latest = match index_releases(&summary.id)
                    .await
                    .map(|releases| latest_version(&releases))
                {
                    Ok(Some(latest)) => latest,
                    Ok(None) => continue,
                    Err(error) => {
                        tracing::warn!(
                            crate = %summary.id,
                            %error,
                            "skipping candidate; failed to read the index"
                        );
                        continue;
                    }
                };
                binaries.push(BinaryCandidate {
                    id: summary.id.clone(),
                    latest_version: latest,
                    downloads: summary.downloads,
                });
                if binaries.len() >= limit {
                    break;
                }
            }
            page += 1;
        }
        binaries.truncate(limit);
        Ok(binaries)
    }
}

/// A `command-line-utilities` candidate: the crate name, its newest
/// non-yanked release, and the downloads the scheduler orders by.
#[derive(Debug, Clone)]
pub struct BinaryCandidate {
    /// The crate name.
    pub id: String,
    /// Newest non-yanked release.
    pub latest_version: String,
    /// All-time downloads.
    pub downloads: u64,
}

// ===== the sparse index =====

/// One line of a crate's sparse-index file — one published release.
/// `cksum`, `deps`, `features`, `rust_version` and friends carry no
/// meaning for what the lanes read (which versions exist and which are
/// yanked; features and dependencies come from the one detail call the
/// lane already makes) and are ignored.
#[derive(Debug, serde::Deserialize)]
struct IndexLine {
    vers: String,
    #[serde(default)]
    yanked: bool,
}

/// A published release the index reports.
#[derive(Debug)]
pub struct IndexRelease {
    /// `vers` parsed as semver — a malformed index line is skipped, not
    /// fatal to the listing.
    pub version: semver::Version,
    /// Whether crates.io yanked the release.
    pub yanked: bool,
}

/// The crate's index file URL — the same sharding cargo applies: `1/`
/// and `2/` for the short names, `3/<first>` for three letters,
/// `<first-two>/<chars3-4>` beyond.
fn index_url_at(index_base: &str, crate_name: &str) -> String {
    let name = crate_name.to_ascii_lowercase();
    let path = match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[0..1]),
        _ => format!("{}/{}/{name}", &name[0..2], &name[2..4]),
    };
    format!("{index_base}/{path}")
}

/// The crate's index URL at the production root — the shape tests pin
/// against cargo's sharding (`index_releases` reaches the same path
/// through [`index_url_at`]).
#[cfg(test)]
fn index_url(crate_name: &str) -> String {
    index_url_at(INDEX_BASE, crate_name)
}

/// Fetch a crate's whole version listing from the sparse index — one
/// CDN request, no API call, no pace gate.
///
/// # Errors
/// Returns an error when the fetch fails, the crate is unknown to the
/// index, or a line does not decode — a truncated file is an error, not
/// a partial answer.
pub async fn index_releases(crate_name: &str) -> stow_types::error::Result<Vec<IndexRelease>> {
    index_releases_at(INDEX_BASE, crate_name).await
}

/// `index_releases` at an explicit index root — production passes
/// [`INDEX_BASE`], tests an owned loopback URL.
async fn index_releases_at(
    index_base: &str,
    crate_name: &str,
) -> stow_types::error::Result<Vec<IndexRelease>> {
    let url = index_url_at(index_base, crate_name);
    let mut client = zenwave::client().timeout(INDEX_TIMEOUT).follow_redirect();
    let request = client
        .get(&url)
        .and_then(|request| request.header("User-Agent", USER_AGENT))
        .map_err(|error| stow_error!("fetch crates.io index {url}: {error}"))?;
    // `error_for_status` lifts an Ok-carried 4xx/5xx into the error
    // path — one status read names the unknown-crate 404 either way.
    let (status, detail) = match request.await {
        Ok(response) => match response.error_for_status().await {
            Ok(response) => {
                let body = response
                    .into_string()
                    .await
                    .map_err(|error| stow_error!("read crates.io index {url}: {error}"))?;
                return index_lines(crate_name, &body);
            }
            Err(error) => (error.status(), error.to_string()),
        },
        Err(error) => (error.status(), error.to_string()),
    };
    if status == zenwave::StatusCode::NOT_FOUND {
        return Err(stow_error!("{crate_name} is unknown to index.crates.io"));
    }
    Err(stow_error!("fetch crates.io index {url}: {detail}"))
}

/// Decode one sparse-index body into releases — each line one
/// `IndexLine`; an unparseable version is skipped while a malformed
/// line is a hard error.
fn index_lines(crate_name: &str, body: &str) -> stow_types::error::Result<Vec<IndexRelease>> {
    let mut releases = Vec::new();
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        let line: IndexLine = serde_json::from_slice(line.as_bytes()).map_err(|error| {
            stow_error!("decode crates.io index line for {crate_name}: {error}")
        })?;
        let Ok(version) = semver::Version::parse(&line.vers) else {
            tracing::warn!(krate = %crate_name, vers = %line.vers, "skipping unparseable index version");
            continue;
        };
        releases.push(IndexRelease {
            version,
            yanked: line.yanked,
        });
    }
    Ok(releases)
}

/// The newest non-yanked release, preferring stable versions over
/// prereleases — the index equivalent of the `max_stable_version` /
/// `max_version` pair the API's crate detail answers with.
#[must_use]
pub fn latest_version(releases: &[IndexRelease]) -> Option<String> {
    let mut stable: Option<&semver::Version> = None;
    let mut any: Option<&semver::Version> = None;
    for release in releases.iter().filter(|release| !release.yanked) {
        if release.version.pre.is_empty() && stable.is_none_or(|s| release.version > *s) {
            stable = Some(&release.version);
        }
        if any.is_none_or(|a| release.version > *a) {
            any = Some(&release.version);
        }
    }
    stable.or(any).map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::{
        FetchOutcome, IndexRelease, fetch_once, index_releases_at, index_url, latest_version,
    };

    /// The sharding rule is cargo's own — pin it so a regression names
    /// itself rather than surfacing as wrong releases.
    #[test]
    fn index_urls_shard_like_cargo() {
        assert_eq!(index_url("a"), "https://index.crates.io/1/a");
        assert_eq!(index_url("cc"), "https://index.crates.io/2/cc");
        assert_eq!(index_url("req"), "https://index.crates.io/3/r/req");
        assert_eq!(index_url("itoa"), "https://index.crates.io/it/oa/itoa");
        assert_eq!(
            index_url("serde_derive"),
            "https://index.crates.io/se/rd/serde_derive"
        );
        assert_eq!(index_url("RwLock"), "https://index.crates.io/rw/lo/rwlock");
    }

    /// `latest_version` prefers the newest non-yanked stable and falls
    /// back to a prerelease only when no stable survives the filter —
    /// the `max_stable_version`-then-`max_version` rule the API detail
    /// answers with.
    #[test]
    fn latest_version_prefers_stable_over_yanked_and_prerelease() {
        let releases = |pairs: &[(&str, bool)]| {
            pairs
                .iter()
                .map(|(vers, yanked)| IndexRelease {
                    version: semver::Version::parse(vers).unwrap(),
                    yanked: *yanked,
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            latest_version(&releases(&[
                ("1.0.0", false),
                ("1.2.0", true),
                ("1.1.0", false),
            ])),
            Some("1.1.0".to_owned())
        );
        assert_eq!(
            latest_version(&releases(&[("1.0.0", false), ("1.2.0-alpha", false)])),
            Some("1.0.0".to_owned())
        );
        assert_eq!(
            latest_version(&releases(&[("1.0.0", true), ("1.1.0-alpha", false)])),
            Some("1.1.0-alpha".to_owned())
        );
        assert_eq!(latest_version(&releases(&[])), None);
    }

    /// The sparse-index 404 is the unknown-crate answer — zenwave
    /// delivers it on the `Err` arm, and one status read names it.
    #[tokio::test]
    async fn absent_index_entry_is_the_unknown_answer() {
        let server = crate::test_server::Loopback::start(vec![crate::test_server::Step::Respond {
            status: 404,
            retry_after: None,
            body: "",
        }])
        .await;
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            index_releases_at(&server.url, "no_such_crate_xyz"),
        )
        .await
        .expect("index fetch completes within the deadline")
        .expect_err("404 is the unknown-crate answer")
        .to_string();
        assert!(
            error.contains("unknown to index.crates.io"),
            "unexpected error: {error}"
        );
        assert_eq!(server.join().await.len(), 1);
    }

    /// A 500 is a fetch error — the unknown-crate reading belongs to
    /// 404 alone.
    #[tokio::test]
    async fn index_server_failure_stays_a_fetch_error() {
        let server = crate::test_server::Loopback::start(vec![crate::test_server::Step::Respond {
            status: 500,
            retry_after: None,
            body: "",
        }])
        .await;
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            index_releases_at(&server.url, "serde"),
        )
        .await
        .expect("index fetch completes within the deadline")
        .expect_err("500 is a fetch failure")
        .to_string();
        assert!(
            error.contains("fetch crates.io index"),
            "unexpected error: {error}"
        );
        assert_eq!(server.join().await.len(), 1);
    }

    /// Two well-formed index lines decode to two releases — versions
    /// and yanked flags carried through.
    #[tokio::test]
    async fn index_body_decodes_releases() {
        let server = crate::test_server::Loopback::start(vec![crate::test_server::Step::Respond {
            status: 200,
            retry_after: None,
            body: "{\"vers\":\"1.0.0\",\"yanked\":false}\n{\"vers\":\"2.1.0\",\"yanked\":true}\n",
        }])
        .await;
        let releases = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            index_releases_at(&server.url, "serde"),
        )
        .await
        .expect("index fetch completes within the deadline")
        .expect("two index lines decode");
        assert_eq!(releases.len(), 2);
        assert_eq!(releases[0].version, semver::Version::new(1, 0, 0));
        assert_eq!(releases[1].version, semver::Version::new(2, 1, 0));
        assert!(!releases[0].yanked);
        assert!(releases[1].yanked);
        assert_eq!(server.join().await.len(), 1);
    }

    /// `fetch_once` classifies the status zenwave carries inside the
    /// `Err`, the same read the `Ok` arm applies: a terminal 404 is
    /// `Fatal` after exactly one request — never a budget burned.
    #[tokio::test]
    async fn fetch_once_terminal_status_is_fatal_after_one_request() {
        let server = crate::test_server::Loopback::start(vec![crate::test_server::Step::Respond {
            status: 404,
            retry_after: None,
            body: r#"{"errors":[{"detail":"Not Found"}]}"#,
        }])
        .await;
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            fetch_once(&server.url, std::time::Duration::from_secs(30)),
        )
        .await
        .expect("the fetch completes within the deadline");
        assert!(
            matches!(outcome, FetchOutcome::Fatal(_)),
            "404 must be Fatal"
        );
        assert_eq!(server.join().await.len(), 1);
    }

    /// A transient status inside the `Err` keeps its `Retry-After`
    /// hint — the carried response's headers drive the wait.
    #[tokio::test]
    async fn fetch_once_transient_status_keeps_the_retry_after_hint() {
        let server = crate::test_server::Loopback::start(vec![crate::test_server::Step::Respond {
            status: 429,
            retry_after: Some(7),
            body: r#"{"errors":[{"detail":"rate limited"}]}"#,
        }])
        .await;
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            fetch_once(&server.url, std::time::Duration::from_secs(30)),
        )
        .await
        .expect("the fetch completes within the deadline");
        let FetchOutcome::Retryable { retry_after, .. } = outcome else {
            panic!("429 must be Retryable");
        };
        assert_eq!(retry_after, Some(std::time::Duration::from_secs(7)));
        assert_eq!(server.join().await.len(), 1);
    }

    /// A server failure inside the `Err` retries — with no hint to
    /// ride when the response carries none.
    #[tokio::test]
    async fn fetch_once_server_failure_is_retryable() {
        let server = crate::test_server::Loopback::start(vec![crate::test_server::Step::Respond {
            status: 500,
            retry_after: None,
            body: "{}",
        }])
        .await;
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            fetch_once(&server.url, std::time::Duration::from_secs(30)),
        )
        .await
        .expect("the fetch completes within the deadline");
        assert!(
            matches!(outcome, FetchOutcome::Retryable { .. }),
            "500 must be Retryable"
        );
        assert_eq!(server.join().await.len(), 1);
    }
}
