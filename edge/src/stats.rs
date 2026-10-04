//! Privacy-preserving usage statistics: the public `UsageStats`
//! aggregates are computed from the Analytics Engine SQL API — never D1
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

/// The Analytics Engine SQL API prefix `run_sql` posts under when no
/// `STOW_STATS_SQL_URL` override points the route at a stub.
pub const SQL_API_URL: &str = "https://api.cloudflare.com/client/v4/accounts";

/// Below this many distinct installs per day the figure is suppressed —
/// stow publishes no small counts that could single out a user.
const MIN_PUBLISHABLE_INSTALLS: f64 = 20.0;

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

/// One row of [`MISSES_SQL`]. `sum(_sample_interval * double1)` is
/// a `Float64` — an estimate that is integral under today's
/// double1 = 1.0 write pattern.
#[derive(Debug, Deserialize)]
struct MissesRow {
    #[serde(deserialize_with = "analytics::de_f64")]
    misses_24h: f64,
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
    misses: &MissesRow,
    top_crates: Vec<LeaderboardRow>,
    targets: Vec<LeaderboardRow>,
    cli_versions: Vec<LeaderboardRow>,
) -> Result<UsageStats, String> {
    let hits_24h = analytics::f64_to_u64_exact(events.hits_24h, "hits_24h")?;
    let misses_24h = analytics::f64_to_u64_exact(misses.misses_24h, "misses_24h")?;
    let served_24h = hits_24h
        .checked_add(misses_24h)
        .ok_or_else(|| "served_24h overflows u64".to_owned())?;
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
        hits_24h,
        misses_24h,
        hit_rate_24h,
        cpu_hours_saved_30d,
        top_crates_30d: entries(top_crates)?,
        targets_30d: entries(targets)?,
        cli_versions_30d: entries(cli_versions)?,
    })
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
        /// `CF_ANALYTICS_TOKEN` — an API token with Analytics Engine read
        /// on the account. A credential: never logged, never in a response.
        pub analytics_token: String,
        /// The full SQL API URL `run_sql` posts to — the account's real
        /// endpoint under `CF_ACCOUNT_ID`, or the harness stub
        /// `STOW_STATS_SQL_URL` names.
        pub sql_url: String,
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
        let (events, installs, misses, top_crates, targets, cli_versions) = futures_util::try_join!(
            run_sql(context, super::EVENTS_SQL),
            run_sql(context, super::INSTALLS_SQL),
            run_sql(context, super::MISSES_SQL),
            run_sql(context, super::TOP_CRATES_SQL),
            run_sql(context, super::TARGETS_SQL),
            run_sql(context, super::CLI_VERSIONS_SQL),
        )?;
        let events = first_row(events, "stats_events")?;
        let installs = first_row(installs, "stats_installs")?;
        let misses = first_row(misses, "stats_misses")?;
        super::usage_stats_from_rows(
            &events,
            &installs,
            &misses,
            top_crates,
            targets,
            cli_versions,
        )
        .map_err(crate::errors::GetArtifactError::InternalWithMessage)
    }
}

#[cfg(target_arch = "wasm32")]
pub use worker::{StatsContext, compute_usage_stats, demand_feed_query};

#[cfg(test)]
mod tests {
    use super::{
        DemandFeedSql, EventsRow, InstallsRow, LeaderboardRow, MissesRow, usage_stats_from_rows,
    };

    fn leaderboard(name: &str, hits: f64) -> LeaderboardRow {
        LeaderboardRow {
            name: name.to_owned(),
            hits,
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
            r#"{"data":[{"hits_24h":1234.0,"hit_compile_millis_30d":9000000.0}]}"#,
        )
        .expect("events");
        let installs: Envelope<InstallsRow> =
            serde_json::from_str(r#"{"data":[{"install_days_7d":"140"}]}"#).expect("installs");
        // `misses_24h` is a `Float64` column — the quoted form decodes
        // too, but the plain JSON number is the wire shape.
        let misses: Envelope<MissesRow> =
            serde_json::from_str(r#"{"data":[{"misses_24h":101.0}]}"#).expect("misses");
        let top_crates: Envelope<LeaderboardRow> =
            serde_json::from_str(r#"{"data":[{"name":"serde","hits":99.0}]}"#).expect("top crates");
        let stats = usage_stats_from_rows(
            &events.data[0],
            &installs.data[0],
            &misses.data[0],
            top_crates.data,
            Vec::new(),
            Vec::new(),
        )
        .expect("integral wire counts map");
        assert_eq!(stats.hits_24h, 1_234);
        assert_eq!(stats.misses_24h, 101);
        assert_eq!(stats.daily_active_installs_7d, Some(20));
        assert_eq!(stats.top_crates_30d[0].hits, 99);
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
                "data": [{"hits_24h": bad, "hit_compile_millis_30d": 0.0}]
            }))
            .expect("fractional events still decode as Float64");
            assert!(
                usage_stats_from_rows(
                    &events.data[0],
                    &installs.data[0],
                    &misses.data[0],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
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
        // SUM(_sample_interval * double1) in SQL already applies the
        // sample weight — each count is integral.
        let stats = usage_stats_from_rows(
            &EventsRow {
                hits_24h: 1_234.0,
                hit_compile_millis_30d: 3_600_000.0 * 2.5,
            },
            &InstallsRow {
                install_days_7d: 19 * 7,
            },
            &MissesRow { misses_24h: 101.0 },
            vec![leaderboard("serde", 99.0)],
            vec![leaderboard("x86_64-unknown-linux-gnu", 1_000.0)],
            vec![leaderboard("0.5.0", 42.0)],
        )
        .expect("integral wire counts map");
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
        assert_eq!(stats.top_crates_30d[0].hits, 99);
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
            &MissesRow { misses_24h: 0.0 },
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("integral wire counts map");
        assert_eq!(stats.daily_active_installs_7d, Some(20));
        assert!((stats.hit_rate_24h - 0.0).abs() < f64::EPSILON);
    }
}
