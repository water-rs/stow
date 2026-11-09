//! Conditional activity envelope, independent of request arrival order.
//!
//! With K cold starts, hot work B and cold overhead C, active time is at
//! most B + C*K. If ordinary cold starts require H idle milliseconds,
//! all but the first and F forced cold starts also consume H of the
//! window T as idle time. The maximum of the smaller of these bounds
//! occurs at their intersection or at the finite invocation limit.
//! H is an explicit assumption: setting it to zero assumes no idle gap.
//! This calculator does not derive B or C from mock wall measurements.

use clap::Args;
use serde::Serialize;

use crate::render::{Output, Table, emit};

/// Inputs to the conditional lifecycle envelope, all times in milliseconds.
#[derive(Debug, Args, Serialize)]
pub struct DurationArgs {
    /// Calendar window whose activity is being bounded.
    #[arg(long)]
    window_ms: u64,
    /// Sum of hot processing and external waiting, excluding cold overhead.
    #[arg(long)]
    hot_ms: u64,
    /// Extra active time per cold start, including loading and external I/O.
    #[arg(long)]
    cold_ms: u64,
    /// Assumed minimum idle gap before an ordinary cold start; zero assumes none.
    #[arg(long)]
    idle_before_cold_ms: u64,
    /// Total invocations, bounding the number of cold starts.
    #[arg(long)]
    invocations: u64,
    /// Cold starts allowed without a preceding idle gap, besides the first.
    #[arg(long)]
    forced_cold_starts: u64,
}

#[derive(Debug, Serialize)]
struct Envelope<'a> {
    assumptions: &'a DurationArgs,
    /// Rounded upward to the next millisecond.
    active_ms_upper: u64,
    minimum_idle_ms: u64,
}

impl DurationArgs {
    fn envelope(&self) -> stow_types::error::Result<Envelope<'_>> {
        if self.invocations == 0 && self.hot_ms != 0 {
            return Err(stow_types::stow_error!(
                "duration envelope has hot work but no invocations"
            ));
        }
        let window = u128::from(self.window_ms);
        let hot = u128::from(self.hot_ms).min(window);
        let cold = u128::from(self.cold_ms);
        let idle = u128::from(self.idle_before_cold_ms);
        let calls = u128::from(self.invocations);
        let forced = u128::from(self.forced_cold_starts).min(calls);
        let without_idle = hot + cold * calls;
        let bound = if cold + idle == 0 {
            hot
        } else {
            let numerator = cold
                .checked_mul(window)
                .and_then(|value| value.checked_add(idle * hot))
                .and_then(|value| {
                    cold.checked_mul(idle)
                        .and_then(|cost| cost.checked_mul(forced + 1))
                        .and_then(|cost| value.checked_add(cost))
                })
                .ok_or_else(|| stow_types::stow_error!("duration envelope arithmetic overflow"))?;
            numerator.div_ceil(cold + idle)
        };
        let active = window.min(without_idle).min(bound);
        let active_ms_upper = u64::try_from(active).expect("activity is bounded by the u64 window");
        Ok(Envelope {
            assumptions: self,
            active_ms_upper,
            minimum_idle_ms: self.window_ms - active_ms_upper,
        })
    }
}

/// Print the assumptions beside their envelope; this is not a monthly gate.
pub fn run(args: &DurationArgs, output: Output) -> stow_types::error::Result<()> {
    let report = args.envelope()?;
    emit(output, &report, |report| {
        let mut table = Table::new(&["window ms", "active ms upper", "minimum idle ms"]);
        table.push([
            report.assumptions.window_ms.to_string(),
            report.active_ms_upper.to_string(),
            report.minimum_idle_ms.to_string(),
        ]);
        table.render()
    })
}

#[cfg(test)]
mod tests {
    use super::DurationArgs;

    #[test]
    fn dominates_every_discrete_cold_start_count() {
        // Exhaust the cold-start counts themselves rather than duplicating
        // the intersection calculation that supplies the closed form.
        for window in [0_u64, 1, 9, 25, 100] {
            for hot in [0, 1, 10, 120] {
                for cold in [0, 1, 8] {
                    for idle in [0, 1, 10] {
                        for invocations in [1, 2, 9] {
                            for forced in [0_u64, 1, 12] {
                                let args = DurationArgs {
                                    window_ms: window,
                                    hot_ms: hot,
                                    cold_ms: cold,
                                    idle_before_cold_ms: idle,
                                    invocations,
                                    forced_cold_starts: forced,
                                };
                                let bound = args.envelope().unwrap().active_ms_upper;
                                for starts in 1..=invocations {
                                    let required_idle =
                                        idle * starts.saturating_sub(forced.saturating_add(1));
                                    if required_idle <= window {
                                        let active =
                                            (hot + cold * starts).min(window - required_idle);
                                        assert!(bound >= active, "{args:?}, K={starts}");
                                    }
                                }
                                assert!(bound <= window);
                                assert!(bound <= hot + cold * invocations);
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn no_idle_assumption_gives_no_hibernation_discount() {
        let args = DurationArgs {
            window_ms: 100,
            hot_ms: 20,
            cold_ms: 10,
            idle_before_cold_ms: 0,
            invocations: 20,
            forced_cold_starts: 0,
        };
        assert_eq!(args.envelope().unwrap().active_ms_upper, 100);
        let with_idle = DurationArgs {
            idle_before_cold_ms: 10,
            ..args
        };
        assert_eq!(with_idle.envelope().unwrap().active_ms_upper, 65);
        let forced = DurationArgs {
            forced_cold_starts: 20,
            ..with_idle
        };
        assert_eq!(forced.envelope().unwrap().active_ms_upper, 100);
    }

    #[test]
    fn empty_window_and_finite_invocations_limit_activity() {
        let args = DurationArgs {
            window_ms: 100,
            hot_ms: 0,
            cold_ms: 10,
            idle_before_cold_ms: 10,
            invocations: 0,
            forced_cold_starts: 0,
        };
        assert_eq!(args.envelope().unwrap().active_ms_upper, 0);
        let one = DurationArgs {
            invocations: 1,
            ..args
        };
        assert_eq!(one.envelope().unwrap().active_ms_upper, 10);
        let inconsistent = DurationArgs { hot_ms: 1, ..args };
        assert!(inconsistent.envelope().is_err());
    }
}
