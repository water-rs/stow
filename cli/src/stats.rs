use std::fmt::Write as _;

use crate::config::StowConfig;
use crate::state_db::db_int;

pub async fn record_hit(config: &StowConfig, crate_name: &str) -> stow_types::error::Result<()> {
    update_stats(config, crate_name, StatsField::Hits).await
}

pub async fn record_miss(config: &StowConfig, crate_name: &str) -> stow_types::error::Result<()> {
    update_stats(config, crate_name, StatsField::Misses).await
}

pub async fn record_error(config: &StowConfig, crate_name: &str) -> stow_types::error::Result<()> {
    update_stats(config, crate_name, StatsField::Errors).await
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
    pub fn summary_line(self, covered_units: usize) -> String {
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

#[cfg(test)]
mod tests {
    use super::StatsSummary;

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
            summary(24, 0, 0).summary_line(48),
            "stow: served 24 of 24 cacheable dependencies\n"
        );
    }

    #[test]
    fn misses_and_errors_are_named_so_a_regression_is_legible() {
        assert_eq!(
            summary(3, 20, 1).summary_line(48),
            "stow: served 3 of 24 cacheable dependencies, 20 missed, 1 errored\n"
        );
    }

    #[test]
    fn a_cache_that_was_never_consulted_says_so() {
        // The failure mode this line exists for: artifacts were available and
        // not one lookup happened. Reporting "0 of 0" would read as success.
        assert_eq!(
            summary(0, 0, 0).summary_line(48),
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
        assert!(with_c.summary_line(2).contains("C objects: 5 of 6"));
        assert!(!summary(2, 0, 0).summary_line(2).contains("C objects"));
    }

    #[test]
    fn counters_never_underflow_when_another_process_reset_the_totals() {
        assert_eq!(summary(1, 0, 0).since(summary(9, 9, 9)).rust_hits, 0);
    }
}
