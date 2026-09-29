//! Privacy-preserving usage statistics: the public `UsageStats`
//! aggregates are computed from the Analytics Engine SQL API and served
//! through the Cache API — never D1.
//!
//! `stow_events` holds one point per sampled cache hit from the era when
//! the byte path resolved catalog rows and knew the artifact's identity;
//! the digest-addressed byte path sees no identity and writes nothing, so
//! the dataset drains under retention. `stow_cache_misses` keeps
//! receiving one point per uncovered node (`miss_logger.rs`).
//!
//! The pure helpers are host-compilable for unit tests; the request
//! extractors and the SQL API calls are wasm-only.

use serde::Deserialize;
use stow_types::analytics;
use stow_types::api::{UsageStatEntry, UsageStats};

/// Header the CLI sets on every edge request when `STOW_NO_ANALYTICS=1`.
pub const NO_ANALYTICS_HEADER: &str = "x-stow-no-analytics";

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

    /// Whether analytics may be written for this request.
    pub const fn allowed(self) -> bool {
        self.0
    }
}

/// `stats_events.sql` — hit totals and CPU milliseconds saved, from the
/// `stow_events` dataset.
const EVENTS_SQL: &str = include_str!("sql/stats_events.sql");

/// `stats_installs.sql` — distinct install-days over 7 days, from the
/// `stow_events` dataset.
const INSTALLS_SQL: &str = include_str!("sql/stats_installs.sql");

/// `stats_misses.sql` — unsampled miss count, from `stow_cache_misses`.
const MISSES_SQL: &str = include_str!("sql/stats_misses.sql");

/// `stats_top_crates.sql` — the 10 most-served crates over 30 days.
const TOP_CRATES_SQL: &str = include_str!("sql/stats_top_crates.sql");

/// `stats_targets.sql` — hits per compilation target over 30 days.
const TARGETS_SQL: &str = include_str!("sql/stats_targets.sql");

/// `stats_cli_versions.sql` — hits per `stow-cli` version over 30 days.
const CLI_VERSIONS_SQL: &str = include_str!("sql/stats_cli_versions.sql");

/// Below this many distinct installs per day the figure is suppressed —
/// stow publishes no small counts that could single out a user.
const MIN_PUBLISHABLE_INSTALLS: f64 = 20.0;

/// Days the install-days figure spans; the daily-salted hash makes each
/// day's installs distinct, so the average is install-days over days.
const INSTALL_WINDOW_DAYS: f64 = 7.0;

/// One row of [`EVENTS_SQL`]. `sumIf` over `double*` is `Float64`.
#[derive(Debug, Deserialize)]
struct EventsRow {
    #[serde(deserialize_with = "analytics::de_f64")]
    hits_24h: f64,
    #[serde(deserialize_with = "analytics::de_f64")]
    hit_compile_millis_30d: f64,
}

/// One row of [`INSTALLS_SQL`]. `count(DISTINCT …)` is a `UInt64`,
/// which `FORMAT JSON` quotes.
#[derive(Debug, Deserialize)]
struct InstallsRow {
    #[serde(deserialize_with = "analytics::de_u64")]
    install_days_7d: u64,
}

/// One row of [`MISSES_SQL`]. `count()` is a `UInt64`.
#[derive(Debug, Deserialize)]
struct MissesRow {
    #[serde(deserialize_with = "analytics::de_u64")]
    misses_24h: u64,
}

/// One row of a leaderboard query — `(name, scaled hits)`; `sum` over
/// `double1` is `Float64`.
#[derive(Debug, Deserialize)]
struct LeaderboardRow {
    name: String,
    #[serde(deserialize_with = "analytics::de_f64")]
    hits: f64,
}

/// Map the six query results into the public [`UsageStats`]. The SQL
/// already multiplies by the stored sample weight (`SUM(double1)`), so the
/// mapping only rounds to whole counts, suppresses the install count below
/// [`MIN_PUBLISHABLE_INSTALLS`], and derives the hit rate and CPU hours.
#[expect(
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    reason = "Analytics Engine aggregates are f64; counts are far below 2^53 and never negative"
)]
fn usage_stats_from_rows(
    events: &EventsRow,
    installs: &InstallsRow,
    misses: &MissesRow,
    top_crates: Vec<LeaderboardRow>,
    targets: Vec<LeaderboardRow>,
    cli_versions: Vec<LeaderboardRow>,
) -> UsageStats {
    let hits_24h = events.hits_24h.round() as u64;
    let misses_24h = misses.misses_24h;
    let served_24h = hits_24h + misses_24h;
    let hit_rate_24h = if served_24h == 0 {
        0.0
    } else {
        hits_24h as f64 / served_24h as f64
    };
    let cpu_hours_saved_30d = events.hit_compile_millis_30d / 3_600_000.0;
    let daily_installs = installs.install_days_7d as f64 / INSTALL_WINDOW_DAYS;
    let daily_active_installs_7d =
        (daily_installs >= MIN_PUBLISHABLE_INSTALLS).then(|| daily_installs.round() as u64);
    let entries = |rows: Vec<LeaderboardRow>| {
        rows.into_iter()
            .map(|row| UsageStatEntry {
                name: row.name,
                hits: row.hits.round() as u64,
            })
            .collect()
    };
    UsageStats {
        daily_active_installs_7d,
        hits_24h,
        misses_24h,
        hit_rate_24h,
        cpu_hours_saved_30d,
        top_crates_30d: entries(top_crates),
        targets_30d: entries(targets),
        cli_versions_30d: entries(cli_versions),
    }
}

#[cfg(target_arch = "wasm32")]
mod worker {
    use skyzen::Request;
    use skyzen::extract::Extractor;

    use super::{AnalyticsConsent, NO_ANALYTICS_HEADER};
    use crate::errors::GetArtifactError;

    impl Extractor for AnalyticsConsent {
        type Error = GetArtifactError;

        fn extract(
            request: &mut Request,
        ) -> impl std::future::Future<Output = Result<Self, Self::Error>> + Send {
            let opted_out = request
                .headers()
                .get(NO_ANALYTICS_HEADER)
                .and_then(|value| value.to_str().ok())
                == Some("1");
            std::future::ready(Ok(Self(!opted_out)))
        }
    }

    /// The credentials the public stats endpoint uses to query the
    /// Analytics Engine SQL API.
    #[derive(Debug, Clone)]
    pub struct StatsContext {
        /// `CF_ACCOUNT_ID` — the account the SQL API is queried under.
        pub account_id: String,
        /// `CF_ANALYTICS_TOKEN` — an API token with Analytics Engine read
        /// on the account. A credential: never logged, never in a response.
        pub analytics_token: String,
    }

    /// The Analytics Engine SQL API endpoint `run_sql` posts to.
    const SQL_API_URL: &str = "https://api.cloudflare.com/client/v4/accounts";

    /// Run one `stats_*.sql` query through the Analytics Engine SQL API
    /// and decode the `FORMAT JSON` `data` rows it returns.
    async fn run_sql<T>(
        context: &StatsContext,
        sql: &str,
    ) -> Result<Vec<T>, crate::errors::GetArtifactError>
    where
        T: serde::de::DeserializeOwned + Send + 'static,
    {
        use skyzen_cloudflare::worker::send::{IntoSendFuture as _, SendWrapper};

        let url = format!(
            "{}/{}/analytics_engine/sql",
            SQL_API_URL, context.account_id
        );
        let authorization = format!("Bearer {}", context.analytics_token);
        let request = SendWrapper::new(
            crate::cf_http::bare_request(
                skyzen_cloudflare::worker::Method::Post,
                &url,
                &[("Authorization", authorization.as_str())],
                Some(sql.as_bytes()),
            )
            .map_err(|error| {
                crate::errors::GetArtifactError::InternalWithMessage(format!(
                    "build stats query: {error}"
                ))
            })?,
        );
        let mut response =
            SendWrapper::new(skyzen_cloudflare::CfFetch.request(&request).await.map_err(
                |error| {
                    crate::errors::GetArtifactError::InternalWithMessage(format!(
                        "stats query fetch: {error}"
                    ))
                },
            )?);
        let status = response.status_code();
        if !(200..300).contains(&status) {
            let body = response
                .text()
                .into_send()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_owned());
            return Err(crate::errors::GetArtifactError::InternalWithMessage(
                format!("stats query failed: {status} {body}"),
            ));
        }
        let envelope: stow_types::analytics::Envelope<T> =
            response.json().into_send().await.map_err(|error| {
                crate::errors::GetArtifactError::InternalWithMessage(format!(
                    "decode stats query result: {error}"
                ))
            })?;
        Ok(envelope.data)
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

    /// The public [`stow_types::api::UsageStats`] — served from the Cache
    /// API when fresh, else computed from the `stats_*.sql` queries and
    /// cached for one hour so the SQL API is hit at most hourly per colo.
    pub async fn cached_usage_stats(
        context: &StatsContext,
        cache: &skyzen_cloudflare::CfCache,
    ) -> Result<stow_types::api::UsageStats, crate::errors::GetArtifactError> {
        if let Some(bytes) = crate::cache::get_stats(cache).await.map_err(|error| {
            crate::errors::GetArtifactError::InternalWithMessage(error.to_string())
        })? {
            match serde_json::from_slice(&bytes) {
                Ok(stats) => return Ok(stats),
                Err(error) => {
                    tracing::warn!(%error, "cached stats failed to parse; recomputing");
                }
            }
        }
        let events = first_row(run_sql(context, super::EVENTS_SQL).await?, "stats_events")?;
        let installs = first_row(
            run_sql(context, super::INSTALLS_SQL).await?,
            "stats_installs",
        )?;
        let misses = first_row(run_sql(context, super::MISSES_SQL).await?, "stats_misses")?;
        let top_crates = run_sql(context, super::TOP_CRATES_SQL).await?;
        let targets = run_sql(context, super::TARGETS_SQL).await?;
        let cli_versions = run_sql(context, super::CLI_VERSIONS_SQL).await?;
        let stats = super::usage_stats_from_rows(
            &events,
            &installs,
            &misses,
            top_crates,
            targets,
            cli_versions,
        );
        match serde_json::to_vec(&stats) {
            Ok(body) => {
                if let Err(error) = crate::cache::put_stats(cache, &body).await {
                    tracing::warn!(%error, "failed to cache usage stats");
                }
            }
            Err(error) => tracing::warn!(%error, "failed to serialize usage stats"),
        }
        Ok(stats)
    }
}

#[cfg(target_arch = "wasm32")]
pub use worker::{StatsContext, cached_usage_stats};

#[cfg(test)]
mod tests {
    use super::{EventsRow, InstallsRow, LeaderboardRow, MissesRow, usage_stats_from_rows};

    fn leaderboard(name: &str, hits: f64) -> LeaderboardRow {
        LeaderboardRow {
            name: name.to_owned(),
            hits,
        }
    }

    #[test]
    fn usage_stats_mapping_scales_and_suppresses() {
        // SUM(double1) in SQL already applies the sample weight — the
        // mapping rounds to whole counts.
        let stats = usage_stats_from_rows(
            &EventsRow {
                hits_24h: 1_234.4,
                hit_compile_millis_30d: 3_600_000.0 * 2.5,
            },
            &InstallsRow {
                install_days_7d: 19 * 7,
            },
            &MissesRow { misses_24h: 101 },
            vec![leaderboard("serde", 99.5)],
            vec![leaderboard("x86_64-unknown-linux-gnu", 1_000.0)],
            vec![leaderboard("0.5.0", 42.0)],
        );
        assert_eq!(stats.hits_24h, 1_234);
        assert_eq!(stats.misses_24h, 101);
        assert_eq!(stats.daily_active_installs_7d, None);
        assert!(
            (stats.hit_rate_24h - 1_234.0 / 1_335.0).abs() < 1e-9,
            "{}",
            stats.hit_rate_24h
        );
        assert!((stats.cpu_hours_saved_30d - 2.5).abs() < 1e-9);
        assert_eq!(stats.top_crates_30d[0].name, "serde");
        assert_eq!(stats.top_crates_30d[0].hits, 100);
    }

    #[test]
    fn usage_stats_mapping_publishes_installs_at_threshold() {
        let stats = usage_stats_from_rows(
            &EventsRow {
                hits_24h: 0.0,
                hit_compile_millis_30d: 0.0,
            },
            &InstallsRow {
                install_days_7d: 20 * 7,
            },
            &MissesRow { misses_24h: 0 },
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(stats.daily_active_installs_7d, Some(20));
        assert!((stats.hit_rate_24h - 0.0).abs() < f64::EPSILON);
    }
}
