//! Privacy-preserving usage statistics: the public `UsageStats`
//! aggregates are computed from the Analytics Engine SQL API
//! — and cached at the edge by Workers Cache on the answer's own
//! `Cache-Control` (the SQL API is billed per query, so the figure
//! tolerates an hour of staleness).
//!
//! `stow_events` holds one point per sampled cache hit from the era when
//! the byte path resolved catalog rows and knew the artifact's identity;
//! the digest-addressed byte path sees no identity and writes nothing, so
//! the dataset drains under retention. `stow_cache_misses` keeps
//! receiving one point per uncovered node (`miss_logger.rs`).
//!
//! The pure helpers are host-compilable for unit tests; the request
//! extractors and the SQL API calls are wasm-only.

use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;
use stow_types::analytics;
use stow_types::api::{BuildReport, UsageStatEntry, UsageStats};

/// Header the CLI sets on every edge request when `STOW_NO_ANALYTICS=1`.
pub const NO_ANALYTICS_HEADER: &str = "x-stow-no-analytics";

/// Header the CLI sets when the build runs in CI (`CI` is set).
pub const CI_HEADER: &str = "x-stow-ci";

/// Whether the request consented to usage analytics — `false` when the
/// client sent `x-stow-no-analytics: 1`. Every analytics write takes the
/// consent as an argument so the opt-out is honoured by construction
/// rather than by remembering a check at each call site.
#[derive(Debug, Clone, Copy)]
pub struct AnalyticsConsent(bool);

impl AnalyticsConsent {
    /// Unconditional consent, for tests that never saw a request.
    #[cfg(test)]
    pub const ALLOWED: Self = Self(true);

    /// Refused consent, for tests exercising the opt-out.
    #[cfg(test)]
    pub const DENIED: Self = Self(false);

    /// Consent read off a request's headers — the single read the
    /// `Extractor` impl and the overload-fault recorder both honour, so
    /// `x-stow-no-analytics` means the same thing on every analytics
    /// write.
    pub(crate) fn from_request(request: &skyzen::Request) -> Self {
        Self(
            request
                .headers()
                .get(NO_ANALYTICS_HEADER)
                .and_then(|value| value.to_str().ok())
                != Some("1"),
        )
    }

    /// Whether analytics may be written for this request.
    pub const fn allowed(self) -> bool {
        self.0
    }
}

/// The `event` blob discriminators.
const HIT_EVENT: &str = "hit";
const BUILD_EVENT: &str = "build";

/// The `surface` blob of every hit point — the digest-addressed byte
/// path (`GET /api/v1/bundles/{rustc}/{digest}`).
const HIT_SURFACE: &str = "digest";

/// Truncated install-hash length in hex characters.
const INSTALL_HASH_HEX_CHARS: usize = 16;

type InstallMac = Hmac<Sha256>;

/// Coarse bundle-size bucket for the `size_bucket` blob.
pub const fn size_bucket(bytes: u64) -> &'static str {
    const MIB: u64 = 1024 * 1024;
    if bytes < MIB {
        "<1MB"
    } else if bytes < 10 * MIB {
        "1-10MB"
    } else if bytes < 100 * MIB {
        "10-100MB"
    } else {
        ">100MB"
    }
}

/// Parse the `stow-cli/<version> (<os>)` user agent the CLI sends into
/// the `(cli_version, os_family)` dimensions. Anything else — a
/// browser, a missing header — yields two empty strings so foreign
/// traffic never lands in the version leaderboard.
pub fn user_agent_dimensions(user_agent: Option<&str>) -> (&str, &str) {
    let Some(rest) = user_agent.and_then(|value| value.strip_prefix("stow-cli/")) else {
        return ("", "");
    };
    let (version, rest) = rest.split_once(' ').map_or((rest, ""), |(v, r)| (v, r));
    let os = rest
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
        .unwrap_or("");
    (version, os)
}

/// The daily-salted install hash: `hex(HMAC-SHA256(daily, ip))[..16]`
/// where `daily = HMAC-SHA256(salt_secret, day)` and `day` is the
/// current UTC date (`YYYY-MM-DD`). The salt secret never leaves the
/// worker, the derived daily key is never stored, and the IP is hashed
/// inside the worker and never written — so the index counts distinct
/// installs per day and cannot be joined across days (#220's
/// construction, restored verbatim).
#[must_use]
pub fn install_hash(salt_secret: &str, day: &str, client_ip: &str) -> String {
    let mut salt_mac = InstallMac::new_from_slice(salt_secret.as_bytes())
        .expect("HMAC accepts keys of any length");
    salt_mac.update(day.as_bytes());
    let daily_secret = salt_mac.finalize().into_bytes();
    let mut mac =
        InstallMac::new_from_slice(&daily_secret).expect("HMAC accepts keys of any length");
    mac.update(client_ip.as_bytes());
    let hash = mac.finalize().into_bytes();
    hex::encode(&hash[..INSTALL_HASH_HEX_CHARS / 2])
}

/// One bundle fetch the Worker observed — one `stow_events` data
/// point.
#[derive(Debug)]
pub struct Hit<'a> {
    /// The rustc the path named.
    pub rustc_version: &'a str,
    /// The `sha256:…` bundle digest served — identity is recovered
    /// offline from the public signed index, so the point carries the
    /// digest and nothing else the request did not already name.
    pub digest: &'a str,
    /// The blob's content length; `None` when the registry reported
    /// none — `bundle_size`/`size_bucket` stay empty then.
    pub bundle_size: Option<u64>,
}

/// The request-carried dimensions every usage point shares:
/// `(cli_version, os_family)` off the user agent, `country` off the
/// request's Cloudflare metadata, `environment` off `x-stow-ci`.
#[derive(Debug, Clone, Copy)]
pub struct RequestDims<'a> {
    /// `stow-cli` version, or `""`.
    pub cli_version: &'a str,
    /// OS family from the user agent, or `""`.
    pub os_family: &'a str,
    /// Two-letter country code, or `""` when Cloudflare sent none.
    pub country: &'a str,
    /// `"ci"` or `"local"` — the CLI's `x-stow-ci` flag.
    pub environment: &'a str,
}

/// Everything the usage writers need from one request: consent, the
/// connecting IP for the install hash, the `stow-cli` user agent, the
/// request's country, and the `x-stow-ci` flag. Extracted once per
/// request so a handler cannot forget a piece.
#[derive(Debug, Clone)]
pub struct HitTelemetry {
    /// Whether analytics may be written for this request.
    pub consent: AnalyticsConsent,
    /// `CF-Connecting-IP`; hashed into the install index and dropped.
    pub client_ip: Option<String>,
    /// The `User-Agent` header, parsed into `cli_version`/`os_family`.
    pub user_agent: Option<String>,
    /// `CF-IPCountry` — the two-letter country Cloudflare geolocates
    /// the connecting IP to; `None` when absent.
    pub country: Option<String>,
    /// `x-stow-ci: 1` — the CLI's "this build runs in CI" flag.
    pub ci: bool,
}

impl HitTelemetry {
    /// The blob dimensions this request carries.
    pub fn dims(&self) -> RequestDims<'_> {
        let (cli_version, os_family) = user_agent_dimensions(self.user_agent.as_deref());
        RequestDims {
            cli_version,
            os_family,
            country: self.country.as_deref().unwrap_or(""),
            environment: if self.ci { "ci" } else { "local" },
        }
    }
}

/// One hit point's blob tuple, in dataset column order: `(event,
/// target, rustc_version, crate_name, version, size_bucket,
/// cli_version, os_family, surface, bundle_digest, country,
/// environment)`.
///
/// The digest-addressed byte path never sees the artifact's identity —
/// `target`, `crate_name` and `version` stay empty and are recovered
/// offline from the public signed index slices. The layout keeps the
/// pre-#467 slots so draining points of the old shape still decode.
pub fn hit_blobs<'a>(hit: &'a Hit<'a>, dims: &RequestDims<'a>) -> [&'a str; 12] {
    [
        HIT_EVENT,
        "",
        hit.rustc_version,
        "",
        "",
        hit.bundle_size.map_or("", size_bucket),
        dims.cli_version,
        dims.os_family,
        HIT_SURFACE,
        hit.digest,
        dims.country,
        dims.environment,
    ]
}

/// `(weight, reserved, bundle_size)` — weight 1.0: the install-hash
/// index already gives equitable per-install sampling, so the legacy
/// 1/10 write-time sample is gone. double2 stays 0: the edge cannot
/// know a digest's recorded compile time — the `build` point carries
/// the CLI-measured figure instead.
#[expect(
    clippy::cast_precision_loss,
    reason = "Analytics Engine doubles are f64; bundle sizes are far below 2^53"
)]
pub const fn hit_doubles(hit: &Hit<'_>) -> [f64; 3] {
    let size = match hit.bundle_size {
        Some(bytes) => bytes as f64,
        None => 0.0,
    };
    [1.0, 0.0, size]
}

/// One build report's blob tuple — the same column order as a hit
/// point so the shared dimension slots line up (`cli_version` blob7,
/// `os_family` blob8, `country` blob11, `environment` blob12).
pub const fn build_blobs<'a>(dims: &RequestDims<'a>) -> [&'a str; 12] {
    [
        BUILD_EVENT,
        "",
        "",
        "",
        "",
        "",
        dims.cli_version,
        dims.os_family,
        "",
        "",
        dims.country,
        dims.environment,
    ]
}

/// `(weight, cpu_millis_saved, hits, misses, builds)` — every counter
/// is the report's delta since its last report.
#[expect(
    clippy::cast_precision_loss,
    reason = "Analytics Engine doubles are f64; the counters are far below 2^53"
)]
pub const fn build_doubles(report: &BuildReport) -> [f64; 5] {
    [
        1.0,
        report.cpu_millis_saved as f64,
        report.hits as f64,
        report.misses as f64,
        report.builds as f64,
    ]
}

/// Where `stow_events` points go. The worker writes the bound
/// Analytics Engine dataset; host tests record the points they were
/// handed — the same boundary `miss_logger::MissLog` draws for
/// `stow_cache_misses`.
pub trait EventLog: Sync {
    /// Write one point. Infallible at the call site — analytics are a
    /// side channel that must never fail the request that observed it.
    fn write_event(&self, index: Option<&str>, blobs: &[&str], doubles: &[f64]);
}

/// Write one usage point gated on the request's consent; `day` is the
/// UTC `YYYY-MM-DD` the install hash salts on.
fn write_usage_point(
    log: &impl EventLog,
    salt_secret: &str,
    day: &str,
    telemetry: &HitTelemetry,
    blobs: &[&str],
    doubles: &[f64],
) {
    if !telemetry.consent.allowed() {
        return;
    }
    let index = telemetry
        .client_ip
        .as_deref()
        .map(|ip| install_hash(salt_secret, day, ip));
    log.write_event(index.as_deref(), blobs, doubles);
}

/// Write one `hit` point for a bundle the Worker served — recorded
/// only on serves the platform cache did not answer, so it is an
/// edge-observed undercount by design (stow#889).
pub fn record_hit(
    log: &impl EventLog,
    salt_secret: &str,
    day: &str,
    telemetry: &HitTelemetry,
    hit: &Hit<'_>,
) {
    let dims = telemetry.dims();
    write_usage_point(
        log,
        salt_secret,
        day,
        telemetry,
        &hit_blobs(hit, &dims),
        &hit_doubles(hit),
    );
}

/// Write one `build` point for the CLI's at-most-daily report —
/// the hits, misses, builds and CPU time the edge cannot observe
/// behind the platform cache.
pub fn record_build_report(
    log: &impl EventLog,
    salt_secret: &str,
    day: &str,
    telemetry: &HitTelemetry,
    report: &BuildReport,
) {
    let dims = telemetry.dims();
    write_usage_point(
        log,
        salt_secret,
        day,
        telemetry,
        &build_blobs(&dims),
        &build_doubles(report),
    );
}

/// One recorded point: `(index, blobs, doubles)`.
#[cfg(test)]
pub type RecordedPoint = (Option<String>, Vec<String>, Vec<f64>);

/// Recording [`EventLog`] for host tests — stores each point so
/// assertions see exactly what the dataset would store.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct RecordingEventLog {
    /// One [`RecordedPoint`] per `write_event` call.
    pub points: std::sync::Mutex<Vec<RecordedPoint>>,
}

#[cfg(test)]
impl EventLog for RecordingEventLog {
    fn write_event(&self, index: Option<&str>, blobs: &[&str], doubles: &[f64]) {
        self.points
            .lock()
            .expect("recording event log mutex")
            .push((
                index.map(str::to_owned),
                blobs.iter().map(|blob| (*blob).to_owned()).collect(),
                doubles.to_vec(),
            ));
    }
}

/// `stats_events.sql` — builds, hits, misses and CPU milliseconds saved,
/// from the `build` points of the `stow_events` dataset.
const EVENTS_SQL: &str = include_str!("sql/stats_events.sql");

/// `stats_installs.sql` — distinct install-days over 7 days, from the
/// `stow_events` dataset.
const INSTALLS_SQL: &str = include_str!("sql/stats_installs.sql");

/// `stats_top_digests.sql` — the 10 most-served bundle digests over 30
/// days.
const TOP_DIGESTS_SQL: &str = include_str!("sql/stats_top_digests.sql");

/// `stats_rustc_versions.sql` — hits per rustc version over 30 days.
const RUSTC_VERSIONS_SQL: &str = include_str!("sql/stats_rustc_versions.sql");

/// `stats_cli_versions.sql` — reported activity per `stow-cli` version
/// over 30 days.
const CLI_VERSIONS_SQL: &str = include_str!("sql/stats_cli_versions.sql");

/// `stats_operating_systems.sql` — reported activity per operating
/// system over 30 days.
const OPERATING_SYSTEMS_SQL: &str = include_str!("sql/stats_operating_systems.sql");

/// `stats_countries.sql` — reported activity per request country over
/// 30 days.
const COUNTRIES_SQL: &str = include_str!("sql/stats_countries.sql");

/// `stats_environments.sql` — reported activity split between CI and
/// local builds over 30 days.
const ENVIRONMENTS_SQL: &str = include_str!("sql/stats_environments.sql");

/// The Analytics Engine SQL API prefix `run_sql` posts under when no
/// `STOW_STATS_SQL_URL` override points the route at a stub.
pub const SQL_API_URL: &str = "https://api.cloudflare.com/client/v4/accounts";

/// Below this many distinct installs per day — or distinct
/// install-days inside one leaderboard bucket — the figure is
/// suppressed: stow publishes no small counts that could single out a
/// user, and a bucket is only publishable when at least this many
/// installs' daily hashes landed in it.
const MIN_PUBLISHABLE_INSTALLS: u64 = 20;

/// The demand-feed query rendered from the checked-in
/// `templates/demand_feed.sql` askama template — the only
/// substitution is the validated hour's SQL literal, never a
/// marker replace or hand-built text. Present on wasm (its only
/// caller) and under test (the render regression).
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Debug, askama::Template)]
#[template(path = "demand_feed.sql", escape = "txt")]
struct DemandFeedSql {
    /// The validated closed hour; `sql_literal()` renders its
    /// `YYYY-MM-DD HH` UTC form into the query.
    hour: stow_types::api::DemandFeedHour,
}

/// Days the install-days figure spans; the daily-salted hash makes each
/// day's installs distinct, so the average is install-days over days.
const INSTALL_WINDOW_DAYS: f64 = 7.0;

/// One row of [`EVENTS_SQL`]. `sumIf` over `double*` is `Float64`.
#[derive(Debug, Deserialize)]
struct EventsRow {
    #[serde(deserialize_with = "analytics::de_f64")]
    builds_24h: f64,
    #[serde(deserialize_with = "analytics::de_f64")]
    hits_24h: f64,
    #[serde(deserialize_with = "analytics::de_f64")]
    misses_24h: f64,
    #[serde(deserialize_with = "analytics::de_f64")]
    cpu_millis_saved_30d: f64,
}

/// One row of [`INSTALLS_SQL`]. `count(DISTINCT …)` is a `UInt64`,
/// which `FORMAT JSON` quotes.
#[derive(Debug, Deserialize)]
struct InstallsRow {
    #[serde(deserialize_with = "analytics::de_u64")]
    install_days_7d: u64,
}

/// One row of a leaderboard query — `(name, scaled hits, distinct
/// install-days)`; the `sum` is `Float64` and `count(DISTINCT index1)`
/// a quoted `UInt64` on the wire.
#[derive(Debug, Deserialize)]
struct LeaderboardRow {
    name: String,
    #[serde(deserialize_with = "analytics::de_f64")]
    hits: f64,
    #[serde(deserialize_with = "analytics::de_u64")]
    install_days: u64,
}

/// The six leaderboard query results — one `Vec<LeaderboardRow>` per
/// published dimension.
#[derive(Debug)]
struct LeaderboardRows {
    /// Most-served bundle digests (`blob10` of `hit` points).
    top_digests: Vec<LeaderboardRow>,
    /// Hits per rustc (`blob3` of `hit` points).
    rustc_versions: Vec<LeaderboardRow>,
    /// Reported activity per `stow-cli` version (`blob7` of `build`).
    cli_versions: Vec<LeaderboardRow>,
    /// Reported activity per OS (`blob8` of `build` points).
    operating_systems: Vec<LeaderboardRow>,
    /// Reported activity per request country (`blob11` of `build`).
    countries: Vec<LeaderboardRow>,
    /// Reported activity per CI/local (`blob12` of `build` points).
    environments: Vec<LeaderboardRow>,
}

/// Map the six query results into the public [`UsageStats`]. The SQL
/// already multiplies by the stored sample weight (`SUM(_sample_interval *
/// double1)`), so each count is an integral estimate — a fractional,
/// negative or non-finite wire value fails here instead of being
/// silently clamped or rounded. The daily install figure stays the
/// intentional `count(DISTINCT …) / 7` average with the privacy
/// threshold; only the count conversions are exact.
#[expect(
    clippy::cast_precision_loss,
    reason = "Analytics Engine aggregates are f64; the daily install average and hit rate are real-valued"
)]
fn usage_stats_from_rows(
    events: &EventsRow,
    installs: &InstallsRow,
    leaderboards: LeaderboardRows,
) -> Result<UsageStats, String> {
    let builds_24h = analytics::f64_to_u64_exact(events.builds_24h, "builds_24h")?;
    let hits_24h = analytics::f64_to_u64_exact(events.hits_24h, "hits_24h")?;
    let misses_24h = analytics::f64_to_u64_exact(events.misses_24h, "misses_24h")?;
    let served_24h = hits_24h
        .checked_add(misses_24h)
        .ok_or_else(|| "served_24h overflows u64".to_owned())?;
    let hit_rate_24h = if served_24h == 0 {
        0.0
    } else {
        hits_24h as f64 / served_24h as f64
    };
    let cpu_hours_saved_30d = events.cpu_millis_saved_30d / 3_600_000.0;
    let daily_installs = installs.install_days_7d as f64 / INSTALL_WINDOW_DAYS;
    let daily_active_installs_7d = if daily_installs >= MIN_PUBLISHABLE_INSTALLS as f64 {
        Some(analytics::f64_to_u64_exact(
            daily_installs.round(),
            "daily installs",
        )?)
    } else {
        None
    };
    // A bucket fewer than `MIN_PUBLISHABLE_INSTALLS` distinct
    // install-days landed in stays unpublished — however many hits
    // those installs produced.
    let entries = |rows: Vec<LeaderboardRow>| {
        rows.into_iter()
            .filter(|row| row.install_days >= MIN_PUBLISHABLE_INSTALLS)
            .map(|row| {
                Ok(UsageStatEntry {
                    name: row.name,
                    hits: analytics::f64_to_u64_exact(row.hits, "leaderboard hits")?,
                })
            })
            .collect::<Result<Vec<UsageStatEntry>, String>>()
    };
    Ok(UsageStats {
        daily_active_installs_7d,
        builds_24h,
        hits_24h,
        misses_24h,
        hit_rate_24h,
        cpu_hours_saved_30d,
        top_digests_30d: entries(leaderboards.top_digests)?,
        rustc_versions_30d: entries(leaderboards.rustc_versions)?,
        cli_versions_30d: entries(leaderboards.cli_versions)?,
        operating_systems_30d: entries(leaderboards.operating_systems)?,
        countries_30d: entries(leaderboards.countries)?,
        environments_30d: entries(leaderboards.environments)?,
    })
}

#[cfg(target_arch = "wasm32")]
mod worker {
    use skyzen::Request;
    use skyzen::extract::Extractor;
    use skyzen::header;
    use skyzen_cloudflare::worker::{AnalyticsEngineDataPointBuilder, AnalyticsEngineDataset};

    use super::{AnalyticsConsent, EventLog, HitTelemetry};
    use crate::errors::GetArtifactError;

    impl Extractor for AnalyticsConsent {
        type Error = GetArtifactError;

        fn extract(
            request: &mut Request,
        ) -> impl std::future::Future<Output = Result<Self, Self::Error>> + Send {
            std::future::ready(Ok(Self::from_request(request)))
        }
    }

    impl Extractor for HitTelemetry {
        type Error = GetArtifactError;

        fn extract(
            request: &mut Request,
        ) -> impl std::future::Future<Output = Result<Self, Self::Error>> + Send {
            let consent = request
                .headers()
                .get(super::NO_ANALYTICS_HEADER)
                .and_then(|value| value.to_str().ok())
                != Some("1");
            let client_ip = request
                .headers()
                .get("cf-connecting-ip")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let user_agent = request
                .headers()
                .get(header::USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let country = request
                .headers()
                .get("cf-ipcountry")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let ci = request
                .headers()
                .get(super::CI_HEADER)
                .and_then(|value| value.to_str().ok())
                == Some("1");
            std::future::ready(Ok(Self {
                consent: AnalyticsConsent(consent),
                client_ip,
                user_agent,
                country,
                ci,
            }))
        }
    }

    /// Today's date in UTC (`YYYY-MM-DD`) from `js_sys::Date` — the
    /// only clock the worker runtime exposes.
    fn current_utc_day() -> String {
        let iso = js_sys::Date::new_0()
            .to_iso_string()
            .as_string()
            .unwrap_or_default();
        iso.get(..10).unwrap_or(&iso).to_owned()
    }

    /// The `stow_events` dataset binding, the install-hash salt, and
    /// the credentials the public stats endpoint uses to query the
    /// Analytics Engine SQL API.
    #[derive(Debug, Clone)]
    pub struct StatsContext {
        /// `STOW_STATS` Analytics Engine dataset binding.
        pub dataset: AnalyticsEngineDataset,
        /// `STOW_STATS_SALT_SECRET` Worker secret.
        pub salt_secret: String,
        /// `CF_ANALYTICS_TOKEN` — an API token with Analytics Engine read
        /// on the account. A credential: never logged, never in a response.
        pub analytics_token: String,
        /// The full SQL API URL `run_sql` posts to — the account's real
        /// endpoint under `CF_ACCOUNT_ID`, or the harness stub
        /// `STOW_STATS_SQL_URL` names.
        pub sql_url: String,
    }

    impl StatsContext {
        /// Write one `hit` point for a bundle the Worker served.
        pub fn record_hit(&self, telemetry: &HitTelemetry, hit: &super::Hit<'_>) {
            super::record_hit(
                &self.dataset,
                &self.salt_secret,
                &current_utc_day(),
                telemetry,
                hit,
            );
        }

        /// Write one `build` point for the CLI's usage report.
        pub fn record_build_report(
            &self,
            telemetry: &HitTelemetry,
            report: &stow_types::api::BuildReport,
        ) {
            super::record_build_report(
                &self.dataset,
                &self.salt_secret,
                &current_utc_day(),
                telemetry,
                report,
            );
        }
    }

    impl EventLog for AnalyticsEngineDataset {
        fn write_event(&self, index: Option<&str>, blobs: &[&str], doubles: &[f64]) {
            let result = AnalyticsEngineDataPointBuilder::new()
                .indexes(index.into_iter().collect::<Vec<_>>())
                .blobs(blobs.iter().copied())
                .doubles(doubles.iter().copied())
                .write_to(self);
            if let Err(error) = result {
                tracing::warn!(%error, "failed to write usage event to Analytics Engine");
            }
        }
    }

    /// POST `sql` to the Analytics Engine SQL API under the shared
    /// `StatsContext` credentials and return the guarded 2xx response:
    /// the bearer header, POST and status guard are written once, and
    /// [`GuardedResponse`] cancels the connection when no caller takes
    /// the body to its terminal state. `run_sql` decodes the document;
    /// `demand_feed_query` hands the live stream onward unbuffered.
    async fn analytics_post(
        context: &StatsContext,
        sql: &str,
        what: &str,
    ) -> Result<
        crate::fetch_guard::GuardedResponse<
            skyzen_cloudflare::worker::send::SendWrapper<skyzen_cloudflare::worker::Response>,
        >,
        crate::errors::GetArtifactError,
    > {
        use crate::fetch_guard::{FetchedResponse as _, GuardedResponse};
        use skyzen_cloudflare::worker::send::SendWrapper;

        let url = context.sql_url.as_str();
        let authorization = format!("Bearer {}", context.analytics_token);
        let request = SendWrapper::new(
            crate::cf_http::bare_request(
                skyzen_cloudflare::worker::Method::Post,
                url,
                &[("Authorization", authorization.as_str())],
                Some(sql.as_bytes()),
            )
            .map_err(|error| {
                crate::errors::GetArtifactError::InternalWithMessage(format!(
                    "build {what} query: {error}"
                ))
            })?,
        );
        let response =
            SendWrapper::new(skyzen_cloudflare::CfFetch.request(&request).await.map_err(
                |error| {
                    crate::errors::GetArtifactError::InternalWithMessage(format!(
                        "{what} query fetch: {error}"
                    ))
                },
            )?);
        let guarded = GuardedResponse::new(response);
        let status = guarded.get_ref().status_code();
        if !(200..300).contains(&status) {
            let body = guarded
                .into_inner()
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_owned());
            return Err(crate::errors::GetArtifactError::InternalWithMessage(
                format!("{what} query failed: {status} {body}"),
            ));
        }
        Ok(guarded)
    }

    /// Run one `stats_*.sql` query through the Analytics Engine SQL API
    /// and decode the `FORMAT JSON` `data` rows it returns.
    async fn run_sql<T>(
        context: &StatsContext,
        sql: &str,
    ) -> Result<Vec<T>, crate::errors::GetArtifactError>
    where
        T: serde::de::DeserializeOwned + Send + 'static,
    {
        use skyzen_cloudflare::worker::send::IntoSendFuture as _;

        let mut response = analytics_post(context, sql, "stats").await?.into_inner();
        let envelope: stow_types::analytics::Envelope<T> =
            response.json().into_send().await.map_err(|error| {
                crate::errors::GetArtifactError::InternalWithMessage(format!(
                    "decode stats query result: {error}"
                ))
            })?;
        Ok(envelope.data)
    }

    /// Run the closed-hour demand-feed query and stream the
    /// `FORMAT JSON` document to the caller unbuffered (stow#523):
    /// `hour` is the validated [`stow_types::api::DemandFeedHour`] —
    /// the only value the askama template renders. The materializer
    /// parses the stream itself, so the edge never holds an hour in
    /// memory; the shared [`analytics_post`] guard cancels the
    /// connection on every early-return arm and the 2xx arm hands the
    /// body to the caller.
    pub async fn demand_feed_query(
        context: &StatsContext,
        hour: &stow_types::api::DemandFeedHour,
    ) -> Result<skyzen::Response, crate::errors::GetArtifactError> {
        use askama::Template as _;
        use skyzen::runtime::wasm::from_js_response;

        let sql = super::DemandFeedSql { hour: hour.clone() }
            .render()
            .map_err(|error| {
                crate::errors::GetArtifactError::InternalWithMessage(format!(
                    "render demand feed query: {error}"
                ))
            })?;
        let worker_response = analytics_post(context, &sql, "demand feed")
            .await?
            .into_inner()
            .0;
        let js: skyzen_cloudflare::worker::web_sys::Response = worker_response.into();
        #[allow(clippy::used_underscore_items)]
        from_js_response(&js).map_err(|error| {
            crate::errors::GetArtifactError::InternalWithMessage(format!(
                "wrap demand feed response: {error:?}"
            ))
        })
    }

    /// The one row every single-value `stats_*.sql` query returns.
    fn first_row<T>(
        mut rows: Vec<T>,
        query: &'static str,
    ) -> Result<T, crate::errors::GetArtifactError> {
        if rows.len() == 1 {
            Ok(rows.remove(0))
        } else {
            Err(crate::errors::GetArtifactError::InternalWithMessage(
                format!("{query} returned {} rows", rows.len()),
            ))
        }
    }

    /// The public [`stow_types::api::UsageStats`] — computed from the
    /// `stats_*.sql` queries on a Workers Cache miss; the answer's
    /// `Cache-Control` holds the result for the staleness the figures
    /// tolerate.
    pub async fn compute_usage_stats(
        context: &StatsContext,
    ) -> Result<stow_types::api::UsageStats, crate::errors::GetArtifactError> {
        // Six independent HTTP queries against the same analytics
        // endpoint — one shared transport, a fixed `try_join` bound of
        // six, first error propagates.
        let (
            events,
            installs,
            top_digests,
            rustc_versions,
            cli_versions,
            operating_systems,
            countries,
            environments,
        ) = futures_util::try_join!(
            run_sql(context, super::EVENTS_SQL),
            run_sql(context, super::INSTALLS_SQL),
            run_sql(context, super::TOP_DIGESTS_SQL),
            run_sql(context, super::RUSTC_VERSIONS_SQL),
            run_sql(context, super::CLI_VERSIONS_SQL),
            run_sql(context, super::OPERATING_SYSTEMS_SQL),
            run_sql(context, super::COUNTRIES_SQL),
            run_sql(context, super::ENVIRONMENTS_SQL),
        )?;
        let events = first_row(events, "stats_events")?;
        let installs = first_row(installs, "stats_installs")?;
        super::usage_stats_from_rows(
            &events,
            &installs,
            super::LeaderboardRows {
                top_digests,
                rustc_versions,
                cli_versions,
                operating_systems,
                countries,
                environments,
            },
        )
        .map_err(crate::errors::GetArtifactError::InternalWithMessage)
    }
}

#[cfg(target_arch = "wasm32")]
pub use worker::{StatsContext, compute_usage_stats, demand_feed_query};

#[cfg(test)]
mod tests {
    use super::{
        AnalyticsConsent, DemandFeedSql, EventsRow, Hit, HitTelemetry, InstallsRow, LeaderboardRow,
        LeaderboardRows, RecordingEventLog, install_hash, record_build_report, record_hit,
        usage_stats_from_rows, user_agent_dimensions,
    };
    use stow_types::api::BuildReport;

    fn leaderboard(name: &str, hits: f64, install_days: u64) -> LeaderboardRow {
        LeaderboardRow {
            name: name.to_owned(),
            hits,
            install_days,
        }
    }

    /// The `FORMAT JSON` documents the checked-in `stats_*.sql` queries
    /// emit decode into the row structs and on into [`UsageStats`] — a
    /// renamed or retyped column fails here, not only at typecheck.
    /// Weighted aggregates arrive as `Float64`; `count(DISTINCT …)`
    /// arrives as a quoted `UInt64`.
    #[test]
    fn format_json_rows_decode_through_to_usage_stats() {
        type Envelope<T> = stow_types::analytics::Envelope<T>;
        let events: Envelope<EventsRow> = serde_json::from_str(
            r#"{"data":[{"builds_24h":50.0,"hits_24h":1234.0,"misses_24h":101.0,"cpu_millis_saved_30d":9000000.0}]}"#,
        )
        .expect("events");
        let installs: Envelope<InstallsRow> =
            serde_json::from_str(r#"{"data":[{"install_days_7d":"140"}]}"#).expect("installs");
        let top_digests: Envelope<LeaderboardRow> = serde_json::from_str(
            r#"{"data":[{"name":"sha256:ab","hits":99.0,"install_days":"30"}]}"#,
        )
        .expect("top digests");
        let stats = usage_stats_from_rows(
            &events.data[0],
            &installs.data[0],
            LeaderboardRows {
                top_digests: top_digests.data,
                rustc_versions: Vec::new(),
                cli_versions: Vec::new(),
                operating_systems: Vec::new(),
                countries: Vec::new(),
                environments: Vec::new(),
            },
        )
        .expect("integral wire counts map");
        assert_eq!(stats.builds_24h, 50);
        assert_eq!(stats.hits_24h, 1_234);
        assert_eq!(stats.misses_24h, 101);
        assert_eq!(stats.daily_active_installs_7d, Some(20));
        assert_eq!(stats.top_digests_30d[0].hits, 99);
        // A drifted column name (e.g. installs_24h) deserializes to an
        // error rather than a silently missing figure.
        assert!(
            serde_json::from_str::<Envelope<InstallsRow>>(r#"{"data":[{"installs_24h":"140"}]}"#)
                .is_err()
        );
        // A fractional or negative wire count is a hard decode error,
        // never a silent clamp or round.
        for bad in [serde_json::json!(1234.5), serde_json::json!(-1.0)] {
            let events: Envelope<EventsRow> = serde_json::from_value(serde_json::json!({
                "data": [{"builds_24h": 0.0, "hits_24h": bad, "misses_24h": 0.0, "cpu_millis_saved_30d": 0.0}]
            }))
            .expect("fractional events still decode as Float64");
            assert!(
                usage_stats_from_rows(
                    &events.data[0],
                    &installs.data[0],
                    LeaderboardRows {
                        top_digests: Vec::new(),
                        rustc_versions: Vec::new(),
                        cli_versions: Vec::new(),
                        operating_systems: Vec::new(),
                        countries: Vec::new(),
                        environments: Vec::new(),
                    },
                )
                .is_err()
            );
        }
    }

    /// The demand-feed template substitutes only the validated
    /// [`DemandFeedHour`]'s canonical literal — the rendered query
    /// carries no placeholder and no caller-shaped text.
    #[test]
    fn demand_feed_template_renders_only_the_validated_hour() {
        use askama::Template as _;

        let hour = stow_types::api::DemandFeedHour::parse("2026-09-27T13")
            .expect("valid closed-hour shape");
        let sql = DemandFeedSql { hour }.render().expect("template renders");
        assert!(sql.contains("toDateTime('2026-09-27 13:00:00')"), "{sql}");
        assert!(!sql.contains("{{"), "{sql}");
        assert!(!sql.contains("__HOUR__"), "{sql}");
    }

    #[test]
    fn usage_stats_mapping_scales_and_suppresses() {
        // SUM(_sample_interval * double*) in SQL already applies the
        // sample weight — each count is integral.
        let stats = usage_stats_from_rows(
            &EventsRow {
                builds_24h: 37.0,
                hits_24h: 1_234.0,
                misses_24h: 101.0,
                cpu_millis_saved_30d: 3_600_000.0 * 2.5,
            },
            &InstallsRow {
                install_days_7d: 19 * 7,
            },
            LeaderboardRows {
                top_digests: vec![
                    leaderboard("sha256:ab", 99.0, 30),
                    // 500 scaled hits from only 3 distinct installs —
                    // the bucket suppresses on install-days, not hits.
                    leaderboard("sha256:cd", 500.0, 3),
                ],
                rustc_versions: vec![leaderboard("1.99.0", 1_000.0, 30)],
                cli_versions: vec![leaderboard("0.5.0", 42.0, 25)],
                operating_systems: vec![leaderboard("linux", 200.0, 30)],
                countries: vec![leaderboard("US", 150.0, 30)],
                environments: vec![leaderboard("ci", 80.0, 22), leaderboard("local", 120.0, 30)],
            },
        )
        .expect("integral wire counts map");
        assert_eq!(stats.builds_24h, 37);
        assert_eq!(stats.hits_24h, 1_234);
        assert_eq!(stats.misses_24h, 101);
        assert_eq!(stats.daily_active_installs_7d, None);
        assert!(
            (stats.hit_rate_24h - 1_234.0 / 1_335.0).abs() < 1e-9,
            "{}",
            stats.hit_rate_24h
        );
        assert!((stats.cpu_hours_saved_30d - 2.5).abs() < 1e-9);
        // The 500-hit bucket is suppressed: only 3 distinct
        // install-days landed in it, however large the hit count.
        assert_eq!(stats.top_digests_30d.len(), 1);
        assert_eq!(stats.top_digests_30d[0].name, "sha256:ab");
        assert_eq!(stats.top_digests_30d[0].hits, 99);
        assert_eq!(stats.rustc_versions_30d[0].name, "1.99.0");
        assert_eq!(stats.cli_versions_30d[0].name, "0.5.0");
        assert_eq!(stats.operating_systems_30d[0].name, "linux");
        assert_eq!(stats.countries_30d[0].name, "US");
        assert_eq!(stats.environments_30d.len(), 2);
        assert_eq!(stats.environments_30d[0].name, "ci");
    }

    #[test]
    fn usage_stats_mapping_publishes_installs_at_threshold() {
        let stats = usage_stats_from_rows(
            &EventsRow {
                builds_24h: 0.0,
                hits_24h: 0.0,
                misses_24h: 0.0,
                cpu_millis_saved_30d: 0.0,
            },
            &InstallsRow {
                install_days_7d: 20 * 7,
            },
            LeaderboardRows {
                top_digests: Vec::new(),
                rustc_versions: Vec::new(),
                cli_versions: Vec::new(),
                operating_systems: Vec::new(),
                countries: Vec::new(),
                environments: Vec::new(),
            },
        )
        .expect("integral wire counts map");
        assert_eq!(stats.daily_active_installs_7d, Some(20));
        assert!((stats.hit_rate_24h - 0.0).abs() < f64::EPSILON);
    }

    /// A full telemetry tuple for the point-shape tests.
    fn telemetry() -> HitTelemetry {
        HitTelemetry {
            consent: AnalyticsConsent::ALLOWED,
            client_ip: Some("203.0.113.7".to_owned()),
            user_agent: Some("stow-cli/0.5.0 (macos)".to_owned()),
            country: Some("US".to_owned()),
            ci: true,
        }
    }

    /// The `hit` point's blob/double layout and the consent gate: a
    /// denied request writes nothing.
    #[test]
    fn hit_point_shape_and_consent_gate() {
        let log = RecordingEventLog::default();
        let hit = Hit {
            rustc_version: "1.91.1",
            digest: "sha256:aaaa",
            bundle_size: Some(5 * 1024 * 1024),
        };
        record_hit(&log, "salt", "2026-10-23", &telemetry(), &hit);
        record_hit(
            &log,
            "salt",
            "2026-10-23",
            &HitTelemetry {
                consent: AnalyticsConsent::DENIED,
                ..telemetry()
            },
            &hit,
        );
        let points = log.points.lock().expect("recording lock").clone();
        assert_eq!(points.len(), 1);
        let (index, blobs, doubles) = &points[0];
        assert_eq!(
            index.as_deref(),
            Some(install_hash("salt", "2026-10-23", "203.0.113.7").as_str())
        );
        assert_eq!(
            blobs.as_slice(),
            &[
                "hit",
                "",
                "1.91.1",
                "",
                "",
                "1-10MB",
                "0.5.0",
                "macos",
                "digest",
                "sha256:aaaa",
                "US",
                "ci",
            ]
        );
        assert_eq!(*doubles, vec![1.0, 0.0, 5.0 * 1024.0 * 1024.0]);
    }

    /// The `build` point carries the report's deltas in its doubles and
    /// the request dimensions in the hit-aligned blob slots.
    #[test]
    fn build_report_point_shape() {
        let log = RecordingEventLog::default();
        let report = BuildReport {
            builds: 3,
            hits: 40,
            misses: 2,
            cpu_millis_saved: 90_000,
        };
        record_build_report(&log, "salt", "2026-10-23", &telemetry(), &report);
        let points = log.points.lock().expect("recording lock").clone();
        assert_eq!(points.len(), 1);
        let (_index, blobs, doubles) = &points[0];
        assert_eq!(blobs[0], "build");
        assert_eq!(blobs[6], "0.5.0");
        assert_eq!(blobs[7], "macos");
        assert_eq!(blobs[10], "US");
        assert_eq!(blobs[11], "ci");
        assert_eq!(*doubles, vec![1.0, 90_000.0, 40.0, 2.0, 3.0]);
    }

    /// The install hash is the #220 construction: daily-salted, 16 hex
    /// chars, different every day, never the IP itself.
    #[test]
    fn install_hash_is_daily_salted() {
        let hash = install_hash("salt", "2026-10-23", "10.0.0.1");
        assert_eq!(hash.len(), 16);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hash, install_hash("salt", "2026-10-23", "10.0.0.1"));
        assert_ne!(hash, install_hash("salt", "2026-10-24", "10.0.0.1"));
        assert_ne!(hash, install_hash("salt", "2026-10-23", "10.0.0.2"));
        assert_ne!(hash, install_hash("other-salt", "2026-10-23", "10.0.0.1"));
    }

    /// `stow-cli/<v> (<os>)` parses; anything else yields two empties.
    #[test]
    fn user_agent_dimensions_parses_stow_cli() {
        assert_eq!(
            user_agent_dimensions(Some("stow-cli/0.5.0 (linux)")),
            ("0.5.0", "linux")
        );
        assert_eq!(user_agent_dimensions(Some("stow-cli/0.5.0")), ("0.5.0", ""));
        assert_eq!(user_agent_dimensions(Some("curl/8")), ("", ""));
        assert_eq!(user_agent_dimensions(None), ("", ""));
    }
}
