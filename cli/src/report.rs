//! The install's daily usage report (stow#889).
//!
//! The platform cache answers most bundle fetches before the edge
//! worker runs, so the edge cannot see what an install actually used —
//! the CLI reports it instead. The report holds no counters of its own:
//! `stats.json`'s cumulative `hits` and `cpu_millis_saved`,
//! `crate_stats`'s per-crate misses, and this module's atomically
//! incremented builds counter are the sources, and the stored
//! `metadata_values` row is a watermark — the sources' totals at the
//! last accepted report, its UTC day, and any `pending` report a
//! failed post left behind. A report's deltas are the live totals
//! minus the watermark.
//!
//! Concurrent `stow` processes share the state database, so claiming
//! the day is one atomic `BEGIN IMMEDIATE` transaction: read the
//! watermark, and when the day is unclaimed store the new one —
//! today's day, the live totals, and `pending` set to the carried
//! report plus this period's deltas. Every other process that day sees
//! the day claimed and posts nothing. The winner posts `pending` and,
//! on acceptance, clears it with a compare-and-swap on the JSON value
//! it wrote; a rejected or never-finished post leaves `pending` to be
//! folded into the next day's claim.
//!
//! The post rides the detached miss-drain process — the
//! `__drain-misses` lane already talks to the edge off the build's
//! wall clock — and a due report spawns that drain even when the
//! build left no miss journal. The report is a side channel: it
//! never fails a build, never runs under `STOW_NO_ANALYTICS=1` —
//! opted-out installs count nothing and post nothing — and carries
//! no crate names, digests, dependency graph or lockfile. Everything
//! about identity arrives on the request's headers; the body is four
//! counters.

use serde::{Deserialize, Serialize};
use stow_types::api::BuildReport;
use stow_types::error::Context;
use zenwave::Client as _;

use crate::config::StowConfig;
use crate::state_db::db_int;

/// The `metadata_values` key the report watermark lives under — the
/// same single-JSON-blob pattern `stats` uses for the profile
/// divergence.
const WATERMARK_KEY: &str = "build_report";

/// The `metadata_values` key the cumulative builds counter lives
/// under — its own row so the per-build increment is one atomic SQL
/// statement, never a read-modify-write racing another `stow` process.
const BUILDS_KEY: &str = "build_report_builds";

/// The cumulative totals at the last accepted report — the watermark a
/// report's deltas are measured against. The stored builds/hits/
/// misses/`cpu_millis_saved` are each source's *total* at that moment,
/// not per-period counts.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Watermark {
    /// `YYYY-MM-DD` UTC of the last claimed report — `None` until the
    /// first post.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_report_day: Option<String>,
    /// The builds counter's total at the last claim.
    builds: u64,
    /// `LocalStats.hits` at the last claim.
    hits: u64,
    /// `crate_stats` misses summed at the last claim.
    misses: u64,
    /// `LocalStats.cpu_millis_saved` at the last claim.
    cpu_millis_saved: u64,
    /// The report the last claim wrote, still unaccepted — folded into
    /// the next day's report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<BuildReport>,
}

/// The live cumulative totals the claim reads once, outside the
/// transaction — a bump that lands between the read and the commit
/// stays uncounted here and is measured by the next claim.
#[derive(Debug, Default, Clone, Copy)]
struct Totals {
    /// The builds counter.
    builds: u64,
    /// `LocalStats.hits`.
    hits: u64,
    /// `crate_stats` misses summed.
    misses: u64,
    /// `LocalStats.cpu_millis_saved`.
    cpu_millis_saved: u64,
}

impl Totals {
    /// The deltas this watermark's stored totals leave unreported.
    const fn delta_since(&self, watermark: &Watermark) -> BuildReport {
        BuildReport {
            builds: self.builds.saturating_sub(watermark.builds),
            hits: self.hits.saturating_sub(watermark.hits),
            misses: self.misses.saturating_sub(watermark.misses),
            cpu_millis_saved: self
                .cpu_millis_saved
                .saturating_sub(watermark.cpu_millis_saved),
        }
    }
}

/// What the winning claim hands to the post half: the report to send
/// and the CAS comparand that clears it on acceptance.
struct Claim {
    /// The watermark JSON this process stored — the compare-and-swap
    /// comparand for [`clear_pending`].
    stored_json: String,
    /// The claimed watermark; on acceptance the CAS writes it back
    /// with `pending` cleared.
    watermark: Watermark,
    /// The report to post — carried `pending` folded with this
    /// period's deltas.
    pending: BuildReport,
}

/// `carried` folds into `pending` — the unaccepted deltas of earlier
/// claims ride with this period's.
const fn merge_reports(pending: &mut BuildReport, carried: &BuildReport) {
    pending.builds = pending.builds.saturating_add(carried.builds);
    pending.hits = pending.hits.saturating_add(carried.hits);
    pending.misses = pending.misses.saturating_add(carried.misses);
    pending.cpu_millis_saved = pending
        .cpu_millis_saved
        .saturating_add(carried.cpu_millis_saved);
}

/// The stored watermark, or the default when the row does not exist.
async fn read_watermark(config: &StowConfig) -> stow_types::error::Result<Watermark> {
    let connection = config.state_db_pool().await?;
    let row = sqlx::query_as::<_, (String,)>("SELECT value FROM metadata_values WHERE key = ?")
        .bind(WATERMARK_KEY)
        .fetch_optional(&connection)
        .await?;
    row.map_or_else(
        || Ok(Watermark::default()),
        |(value,)| serde_json::from_str(&value).wrap_err("parse the build report watermark"),
    )
}

/// `INSERT … ON CONFLICT DO UPDATE SET value = value + 1` — SQLite
/// serializes the statement itself, so concurrent `stow` processes
/// sharing the state database both land their increment.
async fn increment_builds(config: &StowConfig) -> stow_types::error::Result<()> {
    let connection = config.state_db_pool().await?;
    sqlx::query(
        "INSERT INTO metadata_values (key, value) VALUES (?, 1) \
         ON CONFLICT(key) DO UPDATE SET value = value + 1",
    )
    .bind(BUILDS_KEY)
    .execute(&connection)
    .await?;
    Ok(())
}

/// Count one build. A failure warns quietly and drops the increment:
/// the report must never fail the operation that observed it.
pub async fn bump_build(config: &StowConfig) {
    if !reports_enabled(config) {
        return;
    }
    if let Err(error) = increment_builds(config).await {
        // `debug!`, not `warn!`: the report is a side channel that
        // never reaches a build's stderr.
        tracing::debug!(%error, "could not count the build");
    }
}

/// The cumulative builds counter — `0` until the first increment.
async fn builds_total(config: &StowConfig) -> stow_types::error::Result<u64> {
    let connection = config.state_db_pool().await?;
    let row = sqlx::query_as::<_, (i64,)>(
        "SELECT CAST(value AS INTEGER) FROM metadata_values WHERE key = ?",
    )
    .bind(BUILDS_KEY)
    .fetch_optional(&connection)
    .await?;
    row.map_or(Ok(0), |(builds,)| db_int(builds, "build report builds"))
}

/// The cumulative locally-compiled artifact count — `crate_stats`'s
/// per-crate misses summed; `cc:` keys are C-toolchain misses, not
/// artifacts.
async fn misses_total(config: &StowConfig) -> stow_types::error::Result<u64> {
    let connection = config.state_db_pool().await?;
    let (misses,): (i64,) = sqlx::query_as(
        "SELECT COALESCE(SUM(misses), 0) FROM crate_stats \
         WHERE crate_name NOT LIKE 'cc:%'",
    )
    .fetch_one(&connection)
    .await?;
    db_int(misses, "build report misses")
}

/// Today's UTC date in `YYYY-MM-DD` — the report's day key.
fn utc_today() -> String {
    time::OffsetDateTime::now_utc().date().to_string()
}

/// Whether a report is owed: the last claimed post predates today.
fn report_due(watermark: &Watermark, today: &str) -> bool {
    watermark.last_report_day.as_deref() != Some(today)
}

/// Whether today's claim is still untaken — the local read a build's
/// foreground runs before deciding to spawn the drain. The claim
/// itself is the atomic transaction inside [`maybe_report`].
pub async fn report_due_today(config: &StowConfig) -> bool {
    if !reports_enabled(config) {
        return false;
    }
    match read_watermark(config).await {
        Ok(watermark) => report_due(&watermark, &utc_today()),
        Err(error) => {
            tracing::debug!(%error, "could not read the build report watermark");
            false
        }
    }
}

/// Claim today's report inside one immediate write transaction:
/// `BEGIN IMMEDIATE` takes the write lock before the watermark read,
/// so a peer claiming the same day blocks until this commit and then
/// sees the day claimed — exactly one process walks away with a
/// report to post. `None` means today was already claimed.
async fn claim_today(
    config: &StowConfig,
    totals: &Totals,
    today: &str,
) -> stow_types::error::Result<Option<Claim>> {
    let connection = config.state_db_pool().await?;
    let mut transaction = connection.begin_with("BEGIN IMMEDIATE").await?;
    let row = sqlx::query_as::<_, (String,)>("SELECT value FROM metadata_values WHERE key = ?")
        .bind(WATERMARK_KEY)
        .fetch_optional(&mut *transaction)
        .await?;
    let watermark = row.map_or_else(
        || Ok(Watermark::default()),
        |(value,)| serde_json::from_str(&value).wrap_err("parse the build report watermark"),
    )?;
    if !report_due(&watermark, today) {
        return Ok(None);
    }
    let mut pending = totals.delta_since(&watermark);
    if let Some(carried) = watermark.pending {
        merge_reports(&mut pending, &carried);
    }
    let claimed = Watermark {
        last_report_day: Some(today.to_owned()),
        builds: totals.builds,
        hits: totals.hits,
        misses: totals.misses,
        cpu_millis_saved: totals.cpu_millis_saved,
        pending: Some(pending.clone()),
    };
    let stored_json =
        serde_json::to_string(&claimed).wrap_err("serialize the build report watermark")?;
    sqlx::query(
        "INSERT INTO metadata_values (key, value) VALUES (?, ?) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(WATERMARK_KEY)
    .bind(&stored_json)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Some(Claim {
        stored_json,
        watermark: claimed,
        pending,
    }))
}

/// Compare-and-swap the claimed row for one whose `pending` is
/// cleared — applied only when the stored JSON still equals what this
/// process wrote, so a concurrent rewrite is never clobbered. A row
/// that moved keeps its `pending` for the next day's claim.
async fn clear_pending(config: &StowConfig, claim: &Claim) -> stow_types::error::Result<()> {
    let connection = config.state_db_pool().await?;
    let cleared = serde_json::to_string(&Watermark {
        pending: None,
        ..claim.watermark.clone()
    })
    .wrap_err("serialize the build report watermark")?;
    let result = sqlx::query("UPDATE metadata_values SET value = ? WHERE key = ? AND value = ?")
        .bind(&cleared)
        .bind(WATERMARK_KEY)
        .bind(&claim.stored_json)
        .execute(&connection)
        .await?;
    if result.rows_affected() == 0 {
        tracing::debug!(
            "build report watermark moved under the post; pending stays for the next claim"
        );
    }
    Ok(())
}

/// Whether this install reports at all: not opted out, and a cache mode that
/// reaches the network (the report is the only thing it counts for).
fn reports_enabled(config: &StowConfig) -> bool {
    !crate::edge_client::analytics_opted_out() && config.cache.reaches_network()
}

/// Post the deltas since the last accepted report when a new UTC day
/// started. Best-effort end to end: any failure warns quietly and
/// leaves `pending` stored, so the next day's claim folds it into the
/// next report.
pub async fn maybe_report(config: &StowConfig) {
    if !reports_enabled(config) {
        return;
    }
    if let Err(error) = report_once(config).await {
        tracing::debug!(%error, "daily build report failed; deltas stay pending");
    }
}

async fn report_once(config: &StowConfig) -> stow_types::error::Result<()> {
    let today = utc_today();
    if !report_due(&read_watermark(config).await?, &today) {
        return Ok(());
    }
    // The sources are cumulative: the report is what grew since the
    // watermark, and the claimed watermark is the snapshot just read.
    let local = crate::stats::read_local_stats(config).await?;
    let totals = Totals {
        builds: builds_total(config).await?,
        hits: local.hits,
        misses: misses_total(config).await?,
        cpu_millis_saved: local.cpu_millis_saved,
    };
    let Some(claim) = claim_today(config, &totals, &today).await? else {
        return Ok(());
    };
    let url = format!(
        "{}/api/v1/build-report",
        config.edge_url.trim_end_matches('/')
    );
    let mut client = crate::edge_client::client(config)?;
    let response = client
        .post(&url)
        .and_then(|request| request.json_body(&claim.pending))
        .map_err(|error| stow_types::stow_error!("build {url}: {error}"))?
        .await
        .map_err(|error| stow_types::stow_error!("post {url}: {error}"))?;
    if !response.status().is_success() {
        tracing::debug!(
            status = %response.status(),
            "build report rejected; deltas stay pending"
        );
        return Ok(());
    }
    clear_pending(config, &claim).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    fn test_config(cache_dir: PathBuf) -> StowConfig {
        StowConfig {
            cache: crate::config::CacheLayers::default(),
            edge_url: "https://stow.waterui.dev".to_owned(),
            registry_base_url: stow_types::registry::GHCR_REGISTRY_URL.to_owned(),
            cache_dir,
            request_timeout: Duration::from_mins(5),
            negative_cache_ttl: Duration::from_mins(5),
            circuit_reset_after: Duration::from_mins(1),
            circuit_trip_threshold: 5,
            artifact_cache_max_bytes: 1024,
            index_refresh_interval: Duration::from_mins(5),
            verify_mode: crate::config::VerifyMode::GithubCi,
            state_db: crate::state_db::StateDb::default(),
            trust_material: std::sync::Arc::default(),
            registry_http: std::sync::Arc::default(),
            artifact_cache_staging: std::sync::Arc::default(),
        }
    }

    /// A report is owed exactly when the stored day is not today.
    #[test]
    fn report_due_once_per_utc_day() {
        let mut watermark = Watermark::default();
        assert!(report_due(&watermark, "2026-10-23"));
        watermark.last_report_day = Some("2026-10-23".to_owned());
        assert!(!report_due(&watermark, "2026-10-23"));
        assert!(report_due(&watermark, "2026-10-24"));
    }

    /// The watermark round-trips through the stored JSON, `pending`
    /// included.
    #[test]
    fn watermark_serializes() {
        let watermark = Watermark {
            last_report_day: Some("2026-10-23".to_owned()),
            builds: 2,
            hits: 40,
            misses: 3,
            cpu_millis_saved: 12_345,
            pending: Some(BuildReport {
                builds: 1,
                hits: 10,
                misses: 1,
                cpu_millis_saved: 2_000,
            }),
        };
        let json = serde_json::to_string(&watermark).expect("serialize");
        let back: Watermark = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.last_report_day.as_deref(), Some("2026-10-23"));
        assert_eq!(back.builds, 2);
        assert_eq!(back.hits, 40);
        assert_eq!(back.misses, 3);
        assert_eq!(back.cpu_millis_saved, 12_345);
        assert_eq!(back.pending.expect("pending").hits, 10);
    }

    /// Two increments in flight at once both land: the counter is a
    /// single atomic SQL statement, so concurrent `stow` processes
    /// sharing the database cannot read-modify-write over each other.
    #[tokio::test]
    async fn concurrent_build_increments_are_both_counted() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path().to_path_buf());
        let (first, second) = tokio::join!(increment_builds(&config), increment_builds(&config));
        first.expect("first increment");
        second.expect("second increment");
        assert_eq!(builds_total(&config).await.expect("builds total"), 2);
    }

    /// Two processes claiming the same day cannot both post: the
    /// `BEGIN IMMEDIATE` transaction serializes them, so one sees the
    /// day already claimed.
    #[tokio::test]
    async fn concurrent_claims_yield_one_report() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path().to_path_buf());
        let totals = Totals {
            builds: 2,
            hits: 10,
            misses: 1,
            cpu_millis_saved: 500,
        };
        let (first, second) = tokio::join!(
            claim_today(&config, &totals, "2026-10-23"),
            claim_today(&config, &totals, "2026-10-23"),
        );
        let claims = [first.expect("first claim"), second.expect("second claim")];
        let won: Vec<&Claim> = claims.iter().flatten().collect();
        assert_eq!(won.len(), 1, "exactly one claim wins the day");
        assert_eq!(won[0].pending.hits, 10);
    }

    /// A post that never cleared `pending` — the simulated failure —
    /// has its deltas folded into the next day's claim: carried plus
    /// the period's growth equals the live totals.
    #[tokio::test]
    async fn unreported_pending_folds_into_the_next_claim() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path().to_path_buf());
        let day_one = claim_today(
            &config,
            &Totals {
                builds: 1,
                hits: 10,
                misses: 2,
                cpu_millis_saved: 500,
            },
            "2026-10-23",
        )
        .await
        .expect("claim day one")
        .expect("the first claim wins");
        assert_eq!(day_one.pending.hits, 10);
        // The day's post never lands: `pending` stays stored.
        let day_two = claim_today(
            &config,
            &Totals {
                builds: 3,
                hits: 25,
                misses: 4,
                cpu_millis_saved: 900,
            },
            "2026-10-24",
        )
        .await
        .expect("claim day two")
        .expect("the next day claims");
        assert_eq!(day_two.pending.builds, 3);
        assert_eq!(day_two.pending.hits, 25);
        assert_eq!(day_two.pending.misses, 4);
        assert_eq!(day_two.pending.cpu_millis_saved, 900);
    }

    /// The CAS clear only applies when the stored row is still the one
    /// this process wrote.
    #[tokio::test]
    async fn clear_pending_swaps_only_the_written_row() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path().to_path_buf());
        let claim = claim_today(
            &config,
            &Totals {
                builds: 1,
                hits: 10,
                misses: 0,
                cpu_millis_saved: 500,
            },
            "2026-10-23",
        )
        .await
        .expect("claim")
        .expect("the claim wins");
        clear_pending(&config, &claim).await.expect("clear pending");
        let stored = read_watermark(&config).await.expect("read watermark");
        assert!(stored.pending.is_none());
        assert_eq!(stored.last_report_day.as_deref(), Some("2026-10-23"));
    }
}
