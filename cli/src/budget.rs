//! Wall-clock budget for everything stow does before cargo starts.
//!
//! `stow build` must never be meaningfully slower than plain `cargo build`.
//! The resolver, graph analysis and prefetch all run *before* cargo is
//! launched, so every millisecond they spend is overhead that the cache has to
//! earn back. Left unbounded, one pathological artifact or one degraded edge
//! turns acceleration into a regression — a 1.27 GB `jemalloc-sys` bundle once
//! took `stow build` on fd from cargo's 51 s to 209 s.
//!
//! The bound is derived from what the cache can actually be worth: each unit
//! the graph analysis says is cached replaces one dependency compilation. If
//! stow spends more wall-clock warming a unit than compiling it would have
//! cost, the trade is a loss no matter how the fetch goes.

use std::ffi::OsStr;
use std::time::{Duration, Instant};

use crate::session_env::SessionEnv;

/// Wall-clock stow is willing to spend warming one cached unit.
///
/// A conservative floor for what a debug-profile dependency compilation costs;
/// prefetch runs several batches concurrently, so the realised per-unit
/// wall-clock is well under this.
const PER_UNIT_ALLOWANCE: Duration = Duration::from_millis(150);

/// Ceiling regardless of graph size, so a huge workspace cannot authorise an
/// unbounded stall. The prefetch bounds the one wait its allowance does not
/// cover, the trust root's load, by the same ceiling.
pub const MAX_BUDGET: Duration = Duration::from_secs(30);

/// Overrides the computed budget, in seconds. `0` disables the pre-build phase
/// entirely, which is the cheapest way to measure stow's overhead against a
/// plain cargo run.
const STOW_CACHE_BUDGET_SECS_ENV: &str = "STOW_CACHE_BUDGET_SECS";

/// A shrinking wall-clock allowance shared by every pre-cargo phase.
#[derive(Debug, Clone)]
pub struct CacheBudget {
    started: Instant,
    total: Duration,
}

impl CacheBudget {
    /// Budget for a graph the edge says has `covered_units` cached artifacts.
    ///
    /// Zero coverage yields a zero budget: there is nothing to warm, so any
    /// time spent is pure loss. The override is read from the build's own
    /// environment `env`.
    #[must_use]
    pub fn for_covered_units(covered_units: usize, env: &SessionEnv) -> Self {
        let total = env
            .var_os(STOW_CACHE_BUDGET_SECS_ENV)
            .and_then(OsStr::to_str)
            .and_then(|raw| raw.parse::<u64>().ok())
            .map_or_else(
                || {
                    PER_UNIT_ALLOWANCE
                        .saturating_mul(u32::try_from(covered_units).unwrap_or(u32::MAX))
                        .min(MAX_BUDGET)
                },
                Duration::from_secs,
            );
        Self {
            started: Instant::now(),
            total,
        }
    }

    /// What is left to spend.
    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.total.saturating_sub(self.started.elapsed())
    }

    /// Total allowance, for logging.
    #[must_use]
    pub const fn total(&self) -> Duration {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::time::Duration;

    use super::{CacheBudget, MAX_BUDGET, PER_UNIT_ALLOWANCE, STOW_CACHE_BUDGET_SECS_ENV};
    use crate::session_env::SessionEnv;

    #[test]
    fn nothing_cached_earns_no_budget() {
        let budget = CacheBudget::for_covered_units(0, &SessionEnv::for_tests([]));
        assert!(budget.total().is_zero());
    }

    #[test]
    fn budget_scales_with_the_units_the_cache_can_serve() {
        assert_eq!(
            CacheBudget::for_covered_units(20, &SessionEnv::for_tests([])).total(),
            PER_UNIT_ALLOWANCE * 20
        );
    }

    #[test]
    fn budget_is_capped_however_large_the_graph() {
        let env = SessionEnv::for_tests([]);
        assert_eq!(
            CacheBudget::for_covered_units(1_000_000, &env).total(),
            MAX_BUDGET
        );
        assert_eq!(
            CacheBudget::for_covered_units(usize::MAX, &env).total(),
            MAX_BUDGET
        );
    }

    /// The override is the build's own variable, not the process's.
    #[test]
    fn the_override_is_read_from_the_given_environment() {
        let env = SessionEnv::for_tests([(STOW_CACHE_BUDGET_SECS_ENV, OsStr::new("7"))]);
        assert_eq!(
            CacheBudget::for_covered_units(20, &env).total(),
            Duration::from_secs(7)
        );
    }
}
