use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use stow_types::error::Context;

use crate::config::StowConfig;
use crate::state_db::db_int;

/// The user's own cumulative benefit from cache hits, kept in
/// `<cache dir>/stats.json`. Local-only by construction — nothing in it
/// ever leaves the machine.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalStats {
    /// Served cache hits.
    pub hits: u64,
    /// Sum of the served bundles' recorded compile times — the rustc CPU
    /// time this install skipped.
    pub cpu_millis_saved: u64,
    /// Sum of every served cache entry's byte size, wherever it came from.
    #[serde(default)]
    pub bytes_served: u64,
    /// The part of `bytes_served` that crossed the network. A local cache
    /// hit downloads nothing and does not count here.
    pub bytes_downloaded: u64,
}

/// Where a served bundle came from, which decides whether its bytes count
/// as downloaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitSource {
    /// Materialized from the local artifact cache; no network involved.
    Local,
    /// Fetched from the registry during this build.
    Downloaded,
}

fn stats_file_path(config: &StowConfig) -> PathBuf {
    config.cache_dir.join("stats.json")
}

/// Read `stats.json`, treating a missing file as zeroed counters. A
/// corrupt file is an error — silently resetting it would erase the
/// user's record without a trace.
pub async fn read_local_stats(config: &StowConfig) -> stow_types::error::Result<LocalStats> {
    let path = stats_file_path(config);
    match async_fs::read(&path).await {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).wrap_err_with(|| format!("parse {}", path.display()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(LocalStats::default()),
        Err(error) => Err(error).wrap_err_with(|| format!("read {}", path.display())),
    }
}

/// Add one served hit to `stats.json`: read, increment, write.
///
/// A build serves its units concurrently, so this runs concurrently with
/// itself. Read-modify-write under an advisory lock, and stage through a
/// temp file whose name carries the pid: with one shared `stats.json.tmp`
/// two updaters raced, the first rename took the file both had written and
/// the second failed with `No such file or directory` — which is what a
/// 41-unit build printed. Without the lock they also both read the same
/// counter and one hit vanished, silently understating the only number
/// that tells a user what the cache saved them.
pub async fn record_served_bundle(
    config: &StowConfig,
    compile_millis: u64,
    bytes: u64,
    source: HitSource,
) -> stow_types::error::Result<()> {
    let path = stats_file_path(config);
    if let Some(parent) = path.parent() {
        async_fs::create_dir_all(parent)
            .await
            .wrap_err_with(|| format!("create {}", parent.display()))?;
    }
    let _guard = lock_local_stats(&path).await?;
    let mut stats = read_local_stats(config).await?;
    stats.hits = stats.hits.saturating_add(1);
    stats.cpu_millis_saved = stats.cpu_millis_saved.saturating_add(compile_millis);
    stats.bytes_served = stats.bytes_served.saturating_add(bytes);
    if source == HitSource::Downloaded {
        stats.bytes_downloaded = stats.bytes_downloaded.saturating_add(bytes);
    }
    let body = serde_json::to_vec_pretty(&stats).wrap_err("serialize stats.json")?;
    let temp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    async_fs::write(&temp, body)
        .await
        .wrap_err_with(|| format!("write {}", temp.display()))?;
    async_fs::rename(&temp, &path)
        .await
        .wrap_err_with(|| format!("rename {} to {}", temp.display(), path.display()))
}

/// Hold `stats.json.lock` exclusively for one read-modify-write.
///
/// The lock is a sibling file rather than `stats.json` itself, so the
/// rename that replaces the counters never moves the object the lock is
/// held on.
async fn lock_local_stats(path: &std::path::Path) -> stow_types::error::Result<std::fs::File> {
    let lock_path = path.with_extension("json.lock");
    tokio::task::spawn_blocking(move || {
        use fs2::FileExt as _;

        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .wrap_err_with(|| format!("open {}", lock_path.display()))?;
        file.lock_exclusive()
            .wrap_err_with(|| format!("lock {}", lock_path.display()))?;
        Ok(file)
    })
    .await
    .wrap_err("join the local stats lock task")?
}

pub async fn record_hit(config: &StowConfig, crate_name: &str) -> stow_types::error::Result<()> {
    update_stats(config, crate_name, StatsField::Hits).await
}

pub async fn record_miss(config: &StowConfig, crate_name: &str) -> stow_types::error::Result<()> {
    update_stats(config, crate_name, StatsField::Misses).await
}

pub async fn record_error(config: &StowConfig, crate_name: &str) -> stow_types::error::Result<()> {
    update_stats(config, crate_name, StatsField::Errors).await
}

/// The key `metadata_values` holds the last profile divergence under.
const PROFILE_DIVERGENCE_KEY: &str = "profile_divergence";

/// A cached artifact's profile against the one a compile asked for, plus a
/// running count of how many artifacts diverged that way.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileDivergence {
    /// The cached artifacts' diverging profile fields, as `k=v`.
    pub cached: String,
    /// The same fields as the compiles requested them.
    pub wanted: String,
    /// How many artifacts have been rejected this way, ever.
    pub seen: u64,
}

/// Record one artifact rejected for its profile.
///
/// The rustc wrapper is a separate process whose diagnostics never reach the
/// parent, so a systematic divergence — one `[profile.dev]` line in the
/// user's cargo config rejecting every artifact the public cache holds —
/// showed up only as a build that downloaded bundles and served none.
pub async fn record_profile_divergence(
    config: &StowConfig,
    cached: &str,
    wanted: &str,
) -> stow_types::error::Result<()> {
    let connection = config.state_db_pool().await?;
    let previous = read_profile_divergence(config).await?;
    let divergence = ProfileDivergence {
        cached: cached.to_owned(),
        wanted: wanted.to_owned(),
        seen: previous.map_or(1, |previous| previous.seen.saturating_add(1)),
    };
    let value = serde_json::to_string(&divergence).wrap_err("serialize the profile divergence")?;
    sqlx::query(
        "INSERT INTO metadata_values (key, value) VALUES (?, ?) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(PROFILE_DIVERGENCE_KEY)
    .bind(value)
    .execute(&connection)
    .await?;
    Ok(())
}

/// Read the last recorded profile divergence, if any.
pub async fn read_profile_divergence(
    config: &StowConfig,
) -> stow_types::error::Result<Option<ProfileDivergence>> {
    let connection = config.state_db_pool().await?;
    let row = sqlx::query_as::<_, (String,)>("SELECT value FROM metadata_values WHERE key = ?")
        .bind(PROFILE_DIVERGENCE_KEY)
        .fetch_optional(&connection)
        .await?;
    let Some((value,)) = row else {
        return Ok(None);
    };
    serde_json::from_str(&value)
        .map(Some)
        .wrap_err("parse the recorded profile divergence")
}

/// The line that explains a build whose artifacts all diverged, given the
/// divergence recorded before it started. `None` when this build rejected
/// nothing for its profile.
#[must_use]
pub fn profile_divergence_line(
    before: Option<&ProfileDivergence>,
    after: Option<&ProfileDivergence>,
) -> Option<String> {
    let after = after?;
    let rejected = after
        .seen
        .saturating_sub(before.map_or(0, |before| before.seen));
    if rejected == 0 {
        return None;
    }
    let (subject, built) = if rejected == 1 {
        ("cached artifact", "it was built with")
    } else {
        ("cached artifacts", "they were built with")
    };
    Some(format!(
        "stow: {rejected} {subject} could not serve this build: {built} {}, this build asks for {}; \
         the public cache is built with cargo's default profiles\n",
        after.cached, after.wanted
    ))
}

/// How many errors each Rust crate has accumulated, for the crates that
/// have any.
///
/// The aggregate `errored` count says a cached artifact was resolved and
/// then could not be used; without the names there is nothing to act on,
/// and the wrapper's own explanation is not visible at default verbosity.
pub async fn read_error_counts(
    config: &StowConfig,
) -> stow_types::error::Result<BTreeMap<String, u64>> {
    let connection = config.state_db_pool().await?;
    let rows = sqlx::query_as::<_, (String, i64)>(
        "SELECT crate_name, errors FROM crate_stats WHERE errors > 0",
    )
    .fetch_all(&connection)
    .await?;
    let mut counts = BTreeMap::new();
    for (crate_name, errors) in rows {
        if crate_name.starts_with("cc:") {
            continue;
        }
        counts.insert(crate_name, db_int(errors, "crate stats errors")?);
    }
    Ok(counts)
}

/// The crates whose error count grew between `before` and `after`.
#[must_use]
pub fn newly_errored(before: &BTreeMap<String, u64>, after: &BTreeMap<String, u64>) -> Vec<String> {
    after
        .iter()
        .filter(|(crate_name, errors)| **errors > before.get(*crate_name).copied().unwrap_or(0))
        .map(|(crate_name, _)| crate_name.clone())
        .collect()
}

pub async fn read_summary(config: &StowConfig) -> stow_types::error::Result<StatsSummary> {
    let connection = config.state_db_pool().await?;
    let rows = sqlx::query_as::<_, (String, i64, i64, i64)>(
        "SELECT crate_name, hits, misses, errors FROM crate_stats",
    )
    .fetch_all(&connection)
    .await?;

    let mut summary = StatsSummary::default();
    for (crate_name, hits, misses, errors) in rows {
        let hits: u64 = db_int(hits, "crate stats hits")?;
        let misses: u64 = db_int(misses, "crate stats misses")?;
        let errors: u64 = db_int(errors, "crate stats errors")?;
        if crate_name.starts_with("cc:") {
            summary.cc_hits = summary.cc_hits.saturating_add(hits);
            summary.cc_misses = summary.cc_misses.saturating_add(misses);
            summary.cc_errors = summary.cc_errors.saturating_add(errors);
        } else {
            summary.rust_hits = summary.rust_hits.saturating_add(hits);
            summary.rust_misses = summary.rust_misses.saturating_add(misses);
            summary.rust_errors = summary.rust_errors.saturating_add(errors);
        }
    }
    Ok(summary)
}

async fn update_stats(
    config: &StowConfig,
    crate_name: &str,
    field: StatsField,
) -> stow_types::error::Result<()> {
    let connection = config.state_db_pool().await?;
    let query = match field {
        StatsField::Hits => {
            "INSERT INTO crate_stats (crate_name, hits, misses, errors) VALUES (?, 1, 0, 0) \
             ON CONFLICT(crate_name) DO UPDATE SET hits = crate_stats.hits + 1"
        }
        StatsField::Misses => {
            "INSERT INTO crate_stats (crate_name, hits, misses, errors) VALUES (?, 0, 1, 0) \
             ON CONFLICT(crate_name) DO UPDATE SET misses = crate_stats.misses + 1"
        }
        StatsField::Errors => {
            "INSERT INTO crate_stats (crate_name, hits, misses, errors) VALUES (?, 0, 0, 1) \
             ON CONFLICT(crate_name) DO UPDATE SET errors = crate_stats.errors + 1"
        }
    };
    sqlx::query(query)
        .bind(crate_name)
        .execute(&connection)
        .await?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum StatsField {
    Hits,
    Misses,
    Errors,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StatsSummary {
    pub rust_hits: u64,
    pub rust_misses: u64,
    pub rust_errors: u64,
    pub cc_hits: u64,
    pub cc_misses: u64,
    pub cc_errors: u64,
}

impl StatsSummary {
    /// What this build did, given the totals recorded before it started.
    ///
    /// `crate_stats` is cumulative across every stow invocation, so a single
    /// build's coverage is only visible as a delta.
    #[must_use]
    pub const fn since(self, before: Self) -> Self {
        Self {
            rust_hits: self.rust_hits.saturating_sub(before.rust_hits),
            rust_misses: self.rust_misses.saturating_sub(before.rust_misses),
            rust_errors: self.rust_errors.saturating_sub(before.rust_errors),
            cc_hits: self.cc_hits.saturating_sub(before.cc_hits),
            cc_misses: self.cc_misses.saturating_sub(before.cc_misses),
            cc_errors: self.cc_errors.saturating_sub(before.cc_errors),
        }
    }

    /// Cache lookups this build made.
    #[must_use]
    pub const fn rust_lookups(self) -> u64 {
        self.rust_hits
            .saturating_add(self.rust_misses)
            .saturating_add(self.rust_errors)
    }

    /// One line a user can read without turning on `RUST_LOG`.
    ///
    /// "Served N of M" is the number that says whether stow is working at all.
    /// Every defect the acceleration audit turned up was invisible at default
    /// verbosity, and a 1.02x median looked exactly like a working cache.
    ///
    /// The denominator is what the wrapper actually looked up — every unit it
    /// could have served — not the artifact count the edge advertised, which
    /// counts several shapes per crate. `covered_units` is used only to catch
    /// the case that motivated this line: artifacts were available and the
    /// cache was never consulted at all.
    #[must_use]
    pub fn summary_line(self, covered_units: usize, errored_crates: &[String]) -> String {
        let lookups = self.rust_lookups();
        if lookups == 0 {
            return format!(
                "stow: cache not consulted for this build ({covered_units} artifacts available)\n"
            );
        }
        let mut line = format!(
            "stow: served {} of {} cacheable dependencies",
            self.rust_hits, lookups
        );
        if self.rust_misses > 0 {
            let _ = write!(line, ", {} missed", self.rust_misses);
        }
        if self.rust_errors > 0 {
            let _ = write!(line, ", {} errored", self.rust_errors);
            if !errored_crates.is_empty() {
                let _ = write!(line, " ({})", name_list(errored_crates));
            }
        }
        if self.cc_hits > 0 || self.cc_misses > 0 {
            let _ = write!(
                line,
                " | C objects: {} of {}",
                self.cc_hits,
                self.cc_hits.saturating_add(self.cc_misses)
            );
        }
        line.push('\n');
        line
    }
}

/// The names, capped so one bad build cannot print a paragraph.
fn name_list(names: &[String]) -> String {
    const SHOWN: usize = 5;
    if names.len() <= SHOWN {
        return names.join(", ");
    }
    format!(
        "{}, +{} more",
        names[..SHOWN].join(", "),
        names.len() - SHOWN
    )
}

#[cfg(test)]
mod tests {
    use super::{
        LocalStats, ProfileDivergence, StatsSummary, read_local_stats, record_served_bundle,
    };
    use crate::config::StowConfig;
    use std::path::PathBuf;
    use std::time::Duration;

    fn test_config(cache_dir: PathBuf) -> StowConfig {
        StowConfig {
            edge_url: "https://stow.waterui.dev".to_owned(),
            registry_base_url: stow_types::registry::GHCR_V2_BASE_URL.to_owned(),
            cache_dir,
            request_timeout: Duration::from_secs(300),
            negative_cache_ttl: Duration::from_secs(300),
            circuit_reset_after: Duration::from_secs(60),
            circuit_trip_threshold: 5,
            artifact_cache_max_bytes: 1024,
            index_refresh_interval: Duration::from_secs(300),
            verify_mode: crate::config::VerifyMode::GithubCi,
            admission_drain_timeout: crate::config::DEFAULT_ADMISSION_DRAIN_TIMEOUT,
            state_db_pool: StowConfig::default_state_db_pool(),
            trust_material: std::sync::Arc::default(),
        }
    }

    #[tokio::test]
    async fn local_stats_accumulate_hits_in_a_json_file() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path().to_path_buf());

        assert_eq!(
            read_local_stats(&config).await.expect("empty stats"),
            LocalStats::default()
        );

        record_served_bundle(&config, 4_200, 2_048, super::HitSource::Downloaded)
            .await
            .expect("first hit");
        record_served_bundle(&config, 800, 512, super::HitSource::Local)
            .await
            .expect("second hit");

        let stats = read_local_stats(&config).await.expect("read stats");
        assert_eq!(
            stats,
            LocalStats {
                hits: 2,
                cpu_millis_saved: 5_000,
                bytes_served: 2_560,
                // Only the first hit crossed the network; the local one
                // materialized bytes that were already on this machine.
                bytes_downloaded: 2_048,
            }
        );
        // The temp file must not linger next to the real one.
        assert!(!tempdir.path().join("stats.json.tmp").exists());
    }

    fn summary(hits: u64, misses: u64, errors: u64) -> StatsSummary {
        StatsSummary {
            rust_hits: hits,
            rust_misses: misses,
            rust_errors: errors,
            ..StatsSummary::default()
        }
    }

    #[test]
    fn a_builds_coverage_is_the_delta_against_the_totals_before_it() {
        let before = summary(100, 5, 1);
        let after = summary(124, 7, 1);
        let delta = after.since(before);
        assert_eq!(delta.rust_hits, 24);
        assert_eq!(delta.rust_misses, 2);
        assert_eq!(delta.rust_errors, 0);
    }

    #[test]
    fn a_clean_run_reports_only_what_it_served() {
        assert_eq!(
            summary(24, 0, 0).summary_line(48, &[]),
            "stow: served 24 of 24 cacheable dependencies\n"
        );
    }

    #[test]
    fn misses_and_errors_are_named_so_a_regression_is_legible() {
        assert_eq!(
            summary(3, 20, 1).summary_line(48, &[]),
            "stow: served 3 of 24 cacheable dependencies, 20 missed, 1 errored\n"
        );
    }

    /// An errored unit is the expensive failure — the artifact was fetched
    /// and then not used — so the line names which crates it happened to.
    #[test]
    fn errored_crates_are_named() {
        assert_eq!(
            summary(3, 0, 2).summary_line(48, &["memchr".to_owned(), "libc".to_owned()]),
            "stow: served 3 of 5 cacheable dependencies, 2 errored (memchr, libc)\n"
        );
    }

    /// One bad build must not print a paragraph.
    #[test]
    fn a_long_list_of_errored_crates_is_capped() {
        let names: Vec<String> = (0..8).map(|index| format!("crate{index}")).collect();
        assert_eq!(
            summary(0, 0, 8).summary_line(48, &names),
            "stow: served 0 of 8 cacheable dependencies, 8 errored \
             (crate0, crate1, crate2, crate3, crate4, +3 more)\n"
        );
    }

    /// The names come from the crates whose error count grew during this
    /// build, not from every crate that ever errored.
    #[test]
    fn only_this_build_s_errors_are_named() {
        let before =
            std::collections::BTreeMap::from([("memchr".to_owned(), 3), ("libc".to_owned(), 1)]);
        let after = std::collections::BTreeMap::from([
            ("memchr".to_owned(), 3),
            ("libc".to_owned(), 2),
            ("serde".to_owned(), 1),
        ]);
        assert_eq!(super::newly_errored(&before, &after), vec!["libc", "serde"]);
    }

    #[test]
    fn a_cache_that_was_never_consulted_says_so() {
        // The failure mode this line exists for: artifacts were available and
        // not one lookup happened. Reporting "0 of 0" would read as success.
        assert_eq!(
            summary(0, 0, 0).summary_line(48, &[]),
            "stow: cache not consulted for this build (48 artifacts available)\n"
        );
    }

    #[test]
    fn c_objects_are_reported_only_when_some_were_compiled() {
        let with_c = StatsSummary {
            rust_hits: 2,
            cc_hits: 5,
            cc_misses: 1,
            ..StatsSummary::default()
        };
        assert!(with_c.summary_line(2, &[]).contains("C objects: 5 of 6"));
        assert!(!summary(2, 0, 0).summary_line(2, &[]).contains("C objects"));
    }

    #[test]
    fn counters_never_underflow_when_another_process_reset_the_totals() {
        assert_eq!(summary(1, 0, 0).since(summary(9, 9, 9)).rust_hits, 0);
    }

    /// Concurrent hits must all land. Before the lock two updaters read the
    /// same counter and one hit vanished; before the per-process temp name
    /// the loser's rename failed outright with `No such file or directory`,
    /// which is what a 41-unit build printed.
    #[test]
    fn concurrent_hits_all_land() {
        let cache_dir = tempfile::tempdir().expect("cache dir");
        let config = test_config(cache_dir.path().to_path_buf());
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let mut handles = Vec::new();
            for _ in 0..16 {
                let config = config.clone();
                handles.push(tokio::spawn(async move {
                    record_served_bundle(&config, 10, 100, super::HitSource::Downloaded)
                        .await
                        .expect("record hit");
                }));
            }
            for handle in handles {
                handle.await.expect("join hit task");
            }
            let stats = read_local_stats(&config).await.expect("read stats");
            assert_eq!(stats.hits, 16);
            assert_eq!(stats.cpu_millis_saved, 160);
            assert_eq!(stats.bytes_served, 1600);
            assert_eq!(stats.bytes_downloaded, 1600);
        });
    }

    #[test]
    fn a_profile_divergence_names_the_knob_and_counts_only_this_build() {
        let before = ProfileDivergence {
            cached: "debuginfo=2".to_owned(),
            wanted: "debuginfo=1".to_owned(),
            seen: 4,
        };
        let after = ProfileDivergence {
            seen: 11,
            ..before.clone()
        };
        let line = super::profile_divergence_line(Some(&before), Some(&after))
            .expect("a divergence this build saw is reported");
        assert!(
            line.starts_with("stow: 7 cached artifacts could not serve this build"),
            "{line}"
        );
        assert!(line.contains("they were built with debuginfo=2"), "{line}");
        assert!(line.contains("this build asks for debuginfo=1"), "{line}");
        // The same totals before and after mean an older build recorded it.
        assert_eq!(
            super::profile_divergence_line(Some(&after), Some(&after)),
            None
        );
        assert_eq!(super::profile_divergence_line(None, None), None);
    }
}
