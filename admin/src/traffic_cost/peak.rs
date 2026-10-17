//! `stow-admin traffic-cost peak` — the Traffic cost test's
//! peak-concurrency drive (stow#452, stow#772).
//!
//! Every lane in `lanes.rs` fires at the launch model's peak-hour rate
//! for `--duration-secs` against a running mock stack. Per lane the
//! drive reports request count, the effective rate, p50/p99 latency and
//! the status mix, and exits nonzero on a breach: any `overload` signal
//! (a 429/503 or an `overload` marker in the body), any 5xx, a lane's
//! error share over 1%, a response outside the lane's expected status
//! set, or a lane p99 over its bound. The per-route row counts under
//! load come from the scheduler budget probe `scripts/traffic-cost.sh`
//! runs after the drive.

use std::collections::BTreeMap;
use std::time::Duration;

use clap::Args;
use stow_types::launch_model::LaunchModel;
use stow_types::stow_error;

use super::lanes::{self, Lane, LaneArgs, Outcome, REQUEST_TIMEOUT};
use crate::Edge;
use crate::render::{Output, Table, emit};

/// The peak drive — `stow-admin traffic-cost peak`.
#[derive(Debug, Args)]
pub struct PeakArgs {
    #[command(flatten)]
    pub lanes: LaneArgs,
    /// Seconds the drive lasts.
    #[arg(long, default_value_t = 1800)]
    pub duration_secs: u64,
    /// Multiplier over the model's peak-hour rate — `--rate-scale 0.1`
    /// for a smoke run, `1.0` for the launch rate.
    #[arg(long, default_value_t = 1.0)]
    pub rate_scale: f64,
    /// Per-lane p99 bound in milliseconds — the serialization sanity
    /// check, not a latency SLO.
    #[arg(long, default_value_t = 10_000.0)]
    pub p99_bound_ms: f64,
}

/// Lane error share the run tolerates before it fails — one percent.
const ERROR_RATE_BOUND: f64 = 0.01;

/// Per-lane measurements over the run.
#[derive(Debug, Default, serde::Serialize)]
struct LaneStats {
    /// Requests the lane fired.
    requests: u64,
    /// The rate it actually drove.
    effective_eps: f64,
    /// Median latency in milliseconds.
    p50_ms: f64,
    /// 99th-percentile latency.
    p99_ms: f64,
    /// Transport failures (connect, timeout, stream).
    transport_errors: u64,
    /// 5xx responses.
    server_errors: u64,
    /// Responses outside the lane's expected status set.
    unexpected_statuses: u64,
    /// `overload` signals — a 429/503 or the marker string in a body.
    overloaded: u64,
    /// Status histogram.
    statuses: BTreeMap<u16, u64>,
    /// Raw per-request latencies — the percentiles summarize it; kept
    /// out of the emitted JSON.
    #[serde(skip)]
    latencies_ms: Vec<f64>,
}

/// The driver's report — one entry per lane plus the verdict.
#[derive(Debug, serde::Serialize)]
struct LoadReport {
    /// Seconds the run lasted.
    duration_secs: u64,
    /// `rate_scale` the lanes ran at.
    rate_scale: f64,
    /// Per-lane stats keyed by lane name.
    lanes: BTreeMap<&'static str, LaneStats>,
    /// Every breach the verdict names; empty on a pass.
    breaches: Vec<String>,
}

/// Fire `fire` every `interval` until `duration` elapses — the pacing
/// loop every lane runs. Beats are anchored to each event's start (a
/// response slower than the interval waits nothing), but the tail
/// sleep wakes AT the deadline rather than running on to the next
/// beat: under the launch model's slowest lanes the rate floor
/// (0.005eps) makes the interval 200s, so a lane that fired at 0/200/400
/// in a 450s segment used to sleep from 400s to 600s — every segment
/// in queue run 36945779831 read 600s for that reason. An event still
/// in flight at the deadline completes on its own [`REQUEST_TIMEOUT`]:
/// it was scheduled inside the segment, so its latency counts, and
/// cancelling it would report a fake transport error into the
/// error-share gate. The clock is `tokio::time`'s so the boundary
/// cases run under a paused clock.
async fn run_paced(interval: Duration, duration: Duration, mut fire: impl AsyncFnMut(u64)) {
    let deadline = tokio::time::Instant::now() + duration;
    let mut counter = 0u64;
    loop {
        let fired = tokio::time::Instant::now();
        fire(counter).await;
        counter += 1;
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let wake = (fired + interval).min(deadline);
        if now < wake {
            tokio::time::sleep_until(wake).await;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
    }
}

/// Run one lane to the deadline, pacing at `eps`.
#[expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "request counts and percentile indices are tiny"
)]
async fn run_lane(lane: &Lane, edge: &Edge, duration: Duration) -> LaneStats {
    let mut client = zenwave::client();
    let mut stats = LaneStats::default();
    let interval = Duration::from_secs_f64(1.0 / lane.eps.max(1e-4));
    let fire = async |counter: u64| {
        let fired = tokio::time::Instant::now();
        // A response the edge never sends cannot stall the run: the
        // deadline check happens between fires, so bound each one.
        let outcome = tokio::time::timeout(
            REQUEST_TIMEOUT,
            lanes::fire_once(&lane.fire, edge, &mut client, counter),
        )
        .await
        .unwrap_or_else(|_| {
            Ok(Outcome::Transport(format!(
                "lane request exceeded {}s",
                REQUEST_TIMEOUT.as_secs()
            )))
        });
        match outcome {
            Ok(Outcome::Response { status, overloaded }) => {
                *stats.statuses.entry(status).or_default() += 1;
                if (500..600).contains(&status) {
                    stats.server_errors += 1;
                }
                if !(lane.expected)(status) {
                    stats.unexpected_statuses += 1;
                }
                if overloaded {
                    stats.overloaded += 1;
                }
            }
            Ok(Outcome::Transport(error)) => {
                stats.transport_errors += 1;
                tracing::debug!(lane = lane.name, %error, "request failed");
            }
            Err(error) => {
                stats.transport_errors += 1;
                tracing::warn!(lane = lane.name, %error, "lane request build failed");
            }
        }
        stats
            .latencies_ms
            .push(fired.elapsed().as_secs_f64() * 1000.0);
        stats.requests += 1;
    };
    run_paced(interval, duration, fire).await;
    let mut sorted = std::mem::take(&mut stats.latencies_ms);
    sorted.sort_by(f64::total_cmp);
    let percentile = |p: f64| -> f64 {
        if sorted.is_empty() {
            return 0.0;
        }
        let index = (((sorted.len() - 1) as f64) * p).round() as usize;
        sorted[index.min(sorted.len() - 1)]
    };
    stats.p50_ms = percentile(0.5);
    stats.p99_ms = percentile(0.99);
    stats.latencies_ms = sorted;
    stats.effective_eps = stats.requests as f64 / duration.as_secs_f64();
    stats
}

/// `stow-admin traffic-cost peak` — fire the lanes, then emit the
/// report and exit nonzero on a breach.
#[expect(
    clippy::cast_precision_loss,
    reason = "request counts are tiny next to f64's mantissa"
)]
pub async fn run(edge: &Edge, args: &PeakArgs, output: Output) -> stow_types::error::Result<()> {
    let model = super::read_model(&args.lanes.model).await?;
    let lanes = lanes::build_lanes(&args.lanes, &model, args.rate_scale)
        .map_err(|error| stow_error!("{error}"))?;

    let duration = Duration::from_secs(args.duration_secs);
    let results =
        futures_util::future::join_all(lanes.iter().map(|lane| run_lane(lane, edge, duration)))
            .await;

    let mut lanes_map = BTreeMap::new();
    let mut breaches = Vec::new();
    for (lane, stats) in lanes.iter().zip(results) {
        let total = stats.requests.max(1) as f64;
        let error_share = (stats.transport_errors + stats.server_errors) as f64 / total;
        if error_share > ERROR_RATE_BOUND {
            breaches.push(format!(
                "{}: error share {:.1}% over {:.0}%",
                lane.name,
                error_share * 100.0,
                ERROR_RATE_BOUND * 100.0
            ));
        }
        if stats.unexpected_statuses > 0 {
            breaches.push(format!(
                "{}: {} unexpected statuses",
                lane.name, stats.unexpected_statuses
            ));
        }
        if stats.server_errors > 0 {
            breaches.push(format!(
                "{}: {} 5xx response(s) from the stack under load",
                lane.name, stats.server_errors
            ));
        }
        if stats.overloaded > 0 {
            breaches.push(format!(
                "{}: {} overload signal(s) — the DO serialization bound",
                lane.name, stats.overloaded
            ));
        }
        if stats.p99_ms > args.p99_bound_ms {
            breaches.push(format!(
                "{}: p99 {:.0}ms over the {:.0}ms bound",
                lane.name, stats.p99_ms, args.p99_bound_ms
            ));
        }
        lanes_map.insert(lane.name, stats);
    }
    let report = LoadReport {
        duration_secs: args.duration_secs,
        rate_scale: args.rate_scale,
        lanes: lanes_map,
        breaches,
    };
    emit(output, &report, render_report)?;
    if report.breaches.is_empty() {
        Ok(())
    } else {
        Err(stow_error!(
            "traffic-cost peak: {} breach(es)",
            report.breaches.len()
        ))
    }
}

/// Human rendering — per-lane rate/latency/status table plus the
/// verdict lines.
fn render_report(report: &LoadReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let mut table = Table::new(&[
        "lane",
        "reqs",
        "eff eps",
        "p50 ms",
        "p99 ms",
        "errs",
        "unexpected",
        "overload",
        "statuses",
    ]);
    for (name, stats) in &report.lanes {
        let statuses = stats
            .statuses
            .iter()
            .map(|(status, count)| format!("{status}×{count}"))
            .collect::<Vec<_>>()
            .join(" ");
        table.push([
            (*name).to_owned(),
            stats.requests.to_string(),
            format!("{:.3}", stats.effective_eps),
            format!("{:.0}", stats.p50_ms),
            format!("{:.0}", stats.p99_ms),
            (stats.transport_errors + stats.server_errors).to_string(),
            stats.unexpected_statuses.to_string(),
            stats.overloaded.to_string(),
            statuses,
        ]);
    }
    let _ = writeln!(out, "{}", table.render());
    if report.breaches.is_empty() {
        let _ = writeln!(out, "\ntraffic-cost peak: PASS");
    } else {
        let _ = writeln!(out, "\ntraffic-cost peak: FAIL");
        for breach in &report.breaches {
            let _ = writeln!(out, "  {breach}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Duration, run_paced};
    use tokio::time::Instant;

    /// Run `run_paced` under the paused clock and return every event's
    /// virtual fire instant plus the virtual instant the run returned —
    /// each event spends `work` in flight before its call completes.
    /// `run_paced` awaits `fire` sequentially, so the closure holds the
    /// recording vec by `&mut` alone.
    async fn run_recording(
        interval: Duration,
        duration: Duration,
        work: Duration,
    ) -> (Vec<Duration>, Duration) {
        let start = Instant::now();
        let mut seen = Vec::new();
        run_paced(interval, duration, async |_counter: u64| {
            seen.push(Instant::now() - start);
            tokio::time::sleep(work).await;
        })
        .await;
        (seen, Instant::now() - start)
    }

    /// The defect this fixes: a 0.005eps lane (200s interval) in a 450s
    /// segment fires at 0/200/400 and must end AT the 450s deadline —
    /// the old pacing slept the tail to the 600s beat.
    #[tokio::test(start_paused = true)]
    async fn run_ends_at_deadline_not_next_beat() {
        let (fires, elapsed) = run_recording(
            Duration::from_secs(200),
            Duration::from_secs(450),
            Duration::ZERO,
        )
        .await;
        assert_eq!(
            fires,
            [0, 200, 400].map(Duration::from_secs),
            "fires only land inside the segment",
        );
        assert_eq!(
            elapsed,
            Duration::from_secs(450),
            "run ends at the deadline"
        );
    }

    /// A run shorter than its lane's interval still ends at its
    /// deadline, not at the first beat.
    #[tokio::test(start_paused = true)]
    async fn short_run_ends_at_deadline() {
        let (fires, elapsed) = run_recording(
            Duration::from_secs(200),
            Duration::from_secs(45),
            Duration::ZERO,
        )
        .await;
        assert_eq!(fires, [Duration::ZERO]);
        assert_eq!(elapsed, Duration::from_secs(45));
    }

    /// An event landing exactly on the deadline is not fired — the
    /// segment is `[start, deadline)`. With a 10s interval and 30s run
    /// the beats are 0/10/20 and the run still returns at 30s.
    #[tokio::test(start_paused = true)]
    async fn beat_on_deadline_is_not_fired() {
        let (fires, elapsed) = run_recording(
            Duration::from_secs(10),
            Duration::from_secs(30),
            Duration::ZERO,
        )
        .await;
        assert_eq!(fires, [0, 10, 20].map(Duration::from_secs));
        assert_eq!(elapsed, Duration::from_secs(30));
    }

    /// An event slower than the interval waits nothing before the next
    /// fire — pacing anchors to the fire's start — and an in-flight
    /// event at the deadline completes instead of being cut (cancelling
    /// would report a fake transport error).
    #[tokio::test(start_paused = true)]
    async fn slow_events_wait_nothing_and_complete() {
        let (fires, elapsed) = run_recording(
            Duration::from_secs(1),
            Duration::from_secs(4),
            Duration::from_millis(1500),
        )
        .await;
        assert_eq!(
            fires,
            [0, 1500, 3000].map(Duration::from_millis),
            "back-to-back fires when the event outlasts the interval",
        );
        assert_eq!(
            elapsed,
            Duration::from_millis(4500),
            "the in-flight event completes past the deadline",
        );
    }
}
