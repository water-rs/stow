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
use zenwave::{Client, ResponseExt};

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

/// How many times one request is attempted before the command fails. A
/// wave walks a few hundred endpoints, so a single transient answer is
/// likely somewhere in every run — on 2026-09-21 one `Invalid redirect
/// URL` on `lock_api` ended a whole target's lane.
const ATTEMPTS: u32 = 4;
/// Delay before the second attempt; doubles for each one after it, then
/// lengthens — never shortens — to the `Retry-After` hint when a 429
/// carries one.
const RETRY_DELAY: Duration = Duration::from_millis(500);
/// Ceiling on the backoff a `Retry-After` hint can push to — a bounded
/// wait that still honors crates.io's real answers (it sends seconds).
const RETRY_AFTER_MAX: Duration = Duration::from_mins(5);

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
                smol::Timer::after(wait).await;
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
        let mut delay = RETRY_DELAY;
        let mut last_error = None;
        for attempt in 1..=ATTEMPTS {
            self.pace().await;
            match fetch_once(url, timeout).await {
                FetchOutcome::Body(response) => return Ok(response),
                FetchOutcome::Retryable { error, retry_after } => {
                    if attempt == ATTEMPTS {
                        return Err(error);
                    }
                    tracing::warn!(url, attempt, %error, "crates.io request failed; retrying");
                    let wait =
                        retry_after.map_or(delay, |hint| hint.max(delay).min(RETRY_AFTER_MAX));
                    smol::Timer::after(wait).await;
                    delay = delay.saturating_mul(2);
                    last_error = Some(error);
                }
                FetchOutcome::Fatal(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or_else(|| stow_error!("fetch crates.io {url}: attempts exhausted")))
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

/// Statuses worth a retry: rate limiting, request timeout, and every
/// server-side failure — the same retryable set the edge client uses.
fn is_retryable(status: zenwave::StatusCode) -> bool {
    status == zenwave::StatusCode::REQUEST_TIMEOUT
        || status == zenwave::StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

/// One paced GET of a `crates.io` URL.
async fn fetch_once(url: &str, timeout: Duration) -> FetchOutcome {
    let mut client = zenwave::client().timeout(timeout).follow_redirect();
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
    let response = match request.await {
        Ok(response) => response,
        Err(error) => {
            return FetchOutcome::Retryable {
                error: stow_error!("fetch crates.io {url}: {error}"),
                retry_after: None,
            };
        }
    };
    let status = response.status();
    if status.is_success() {
        return FetchOutcome::Body(response);
    }
    let retry_after = retry_after_hint(&response);
    let error = stow_error!("crates.io {url} returned HTTP {status}");
    if is_retryable(status) {
        FetchOutcome::Retryable { error, retry_after }
    } else {
        FetchOutcome::Fatal(error)
    }
}

/// `Retry-After` as a duration; only the delta-seconds form is honored.
fn retry_after_hint(response: &zenwave::Response) -> Option<Duration> {
    response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
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
    /// The feature table the release declares.
    #[serde(default)]
    pub features: std::collections::BTreeMap<String, Vec<String>>,
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
fn index_url(crate_name: &str) -> String {
    let name = crate_name.to_ascii_lowercase();
    let path = match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[0..1]),
        _ => format!("{}/{}/{name}", &name[0..2], &name[2..4]),
    };
    format!("{INDEX_BASE}/{path}")
}

/// Fetch a crate's whole version listing from the sparse index — one
/// CDN request, no API call, no pace gate.
///
/// # Errors
/// Returns an error when the fetch fails, the crate is unknown to the
/// index, or a line does not decode — a truncated file is an error, not
/// a partial answer.
pub async fn index_releases(crate_name: &str) -> stow_types::error::Result<Vec<IndexRelease>> {
    let url = index_url(crate_name);
    let mut client = zenwave::client().timeout(INDEX_TIMEOUT).follow_redirect();
    let response = client
        .get(&url)
        .and_then(|request| request.header("User-Agent", USER_AGENT))
        .map_err(|error| stow_error!("fetch crates.io index {url}: {error}"))?
        .await
        .map_err(|error| stow_error!("fetch crates.io index {url}: {error}"))?;
    if response.status() == zenwave::StatusCode::NOT_FOUND {
        return Err(stow_error!("{crate_name} is unknown to index.crates.io"));
    }
    let body = response
        .error_for_status()
        .await
        .map_err(|error| stow_error!("fetch crates.io index {url}: {error}"))?
        .into_string()
        .await
        .map_err(|error| stow_error!("read crates.io index {url}: {error}"))?;
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
    use super::{IndexRelease, index_url, latest_version};

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
}
