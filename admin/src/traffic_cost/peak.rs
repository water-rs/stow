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
use std::num::NonZeroUsize;
use std::time::Duration;

use clap::Args;
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
    /// Absolute events per second for each build workflow delivery lane.
    /// Omitted uses the launch model and global rate multiplier.
    #[arg(long)]
    pub build_callback_eps: Option<f64>,
    /// Per-lane p99 bound in milliseconds — the serialization sanity
    /// check, not a latency SLO.
    #[arg(long, default_value_t = 10_000.0)]
    pub p99_bound_ms: f64,
    /// Maximum requests in flight per lane; defaults to host available parallelism.
    #[arg(long)]
    pub max_in_flight_per_lane: Option<NonZeroUsize>,
    /// Inspector URL for CPU capture over the complete peak interval.
    #[arg(long, requires = "cpu_out")]
    pub inspector_url: Option<String>,
    /// Where to retain CPU samples, including when the peak breaches.
    #[arg(long, requires = "inspector_url")]
    pub cpu_out: Option<std::path::PathBuf>,
}

/// Lane error share the run tolerates before it fails — one percent.
const ERROR_RATE_BOUND: f64 = 0.01;

/// One timed event, retained to correlate pauses across lanes.
#[derive(Debug, serde::Serialize)]
struct Observation {
    counter: u64,
    started_ms: f64,
    preparation_ms: f64,
    elapsed_ms: f64,
    phases_ms: lanes::RequestTimingMs,
}

/// Per-lane measurements over the run.
#[derive(Debug, Default, serde::Serialize)]
struct LaneStats {
    /// Request slots used by this lane. Callback fixture rearming has one owner.
    request_slots: usize,
    /// Errors that stopped preparation of this lane.
    preparation_errors: Vec<String>,
    /// Requests the lane fired.
    requests: u64,
    /// Minimum whole requests required by the configured rate and duration.
    required_requests: u64,
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
    /// Request phases in fire order per slot; counters identify their anchored beats.
    observations: Vec<Observation>,
}

/// The driver's report — one entry per lane plus the verdict.
#[derive(Debug, serde::Serialize)]
struct LoadReport {
    /// Seconds the run lasted.
    duration_secs: u64,
    /// `rate_scale` the lanes ran at.
    rate_scale: f64,
    /// Explicit build delivery rate, independent of other traffic, when supplied.
    build_callback_eps: Option<f64>,
    /// The bounded number of independent request slots in each lane.
    max_in_flight_per_lane: usize,
    /// Per-lane stats keyed by lane name.
    lanes: BTreeMap<&'static str, LaneStats>,
    /// Every breach the verdict names; empty on a pass.
    breaches: Vec<String>,
}

/// Fire one request slot's share of the lane's anchored beats. Slot
/// `first` handles counters `first`, `first + stride`, and so on; all
/// slots share `start` and the deadline. A slow response delays only
/// its own slot. The tail
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
#[expect(clippy::cast_precision_loss, reason = "request slot counts fit f64")]
async fn run_paced(
    start: tokio::time::Instant,
    interval: Duration,
    duration: Duration,
    first: usize,
    stride: usize,
    mut fire: impl AsyncFnMut(u64),
) {
    let deadline = start + duration;
    let mut counter = first as u64;
    let mut next = start + interval.mul_f64(first as f64);
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let wake = next.min(deadline);
        if now < wake {
            tokio::time::sleep_until(wake).await;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        fire(counter).await;
        counter += stride as u64;
        next += interval.mul_f64(stride as f64);
    }
}

/// Whole requests due during the measurement window. Rounding down
/// permits only the fractional request at the boundary, not a rate deficit.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "positive finite lane rates and bounded measurement duration"
)]
fn required_requests(eps: f64, duration: Duration) -> u64 {
    (eps * duration.as_secs_f64()).floor() as u64
}

/// Run one lane to the deadline, pacing at `eps`.
async fn run_lane_worker(
    lane: &Lane,
    edge: &Edge,
    start: tokio::time::Instant,
    duration: Duration,
    first: usize,
    stride: usize,
) -> LaneStats {
    let mut client = zenwave::client();
    let mut stats = LaneStats::default();
    // A lane the harness cannot make fireable stops firing and fails the
    // pass: an event fired anyway would be a different path than the one
    // the lane prices.
    let mut unready = None;
    let interval = Duration::from_secs_f64(1.0 / lane.eps.max(1e-4));
    let fire = async |counter: u64| {
        if unready.is_some() {
            return;
        }
        // Harness work, before the event's clock starts.
        let preparation_started = tokio::time::Instant::now();
        if let Err(error) = lane.fire.ready(edge, 1).await {
            unready = Some(error);
            return;
        }
        let fired = tokio::time::Instant::now();
        let preparation_ms = preparation_started.elapsed().as_secs_f64() * 1000.0;
        let mut phases = lanes::RequestTimingMs::default();
        // A response the edge never sends cannot stall the run: the
        // deadline check happens between fires, so bound each one.
        let outcome = tokio::time::timeout(
            REQUEST_TIMEOUT,
            lanes::fire_once(&lane.fire, edge, &mut client, counter, &mut phases),
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
        let elapsed_ms = fired.elapsed().as_secs_f64() * 1000.0;
        stats.latencies_ms.push(elapsed_ms);
        stats.observations.push(Observation {
            counter,
            started_ms: fired.duration_since(start).as_secs_f64() * 1000.0,
            preparation_ms,
            elapsed_ms,
            phases_ms: phases,
        });
        stats.requests += 1;
    };
    run_paced(start, interval, duration, first, stride, fire).await;
    stats.preparation_errors.extend(unready);
    stats
}

/// Join the lane's independent request slots, then aggregate every
/// completed response before applying the unchanged rate/latency gates.
#[expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "request counts and percentile indices are tiny"
)]
async fn run_lane(
    lane: &Lane,
    edge: &Edge,
    start: tokio::time::Instant,
    duration: Duration,
    concurrency: usize,
) -> LaneStats {
    // Prepared identities and callback rearming each have one owner;
    // ready + take must stay in the same request slot. Other lanes overlap.
    let concurrency = if matches!(
        lane.fire,
        lanes::Fire::WorkflowRun(_) | lanes::Fire::HumanLifecycle(_)
    ) {
        1
    } else {
        concurrency
    };
    let results = futures_util::future::join_all(
        (0..concurrency)
            .map(|first| run_lane_worker(lane, edge, start, duration, first, concurrency)),
    )
    .await;
    let mut stats = LaneStats {
        request_slots: concurrency,
        required_requests: required_requests(lane.eps, duration),
        ..LaneStats::default()
    };
    for worker in results {
        stats.preparation_errors.extend(worker.preparation_errors);
        stats.requests += worker.requests;
        stats.transport_errors += worker.transport_errors;
        stats.server_errors += worker.server_errors;
        stats.unexpected_statuses += worker.unexpected_statuses;
        stats.overloaded += worker.overloaded;
        stats.latencies_ms.extend(worker.latencies_ms);
        stats.observations.extend(worker.observations);
        for (status, count) in worker.statuses {
            *stats.statuses.entry(status).or_default() += count;
        }
    }
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

/// Apply every lane gate even when preparation stopped before the deadline.
#[expect(clippy::cast_precision_loss, reason = "request counts fit f64")]
fn lane_breaches(lane: &Lane, stats: &LaneStats, p99_bound_ms: f64) -> Vec<String> {
    let mut breaches: Vec<_> = stats
        .preparation_errors
        .iter()
        .map(|error| format!("{}: preparation failed: {error}", lane.name))
        .collect();
    if stats.requests < stats.required_requests {
        breaches.push(format!(
            "{}: sent {} requests, below {} required at {:.6} eps",
            lane.name, stats.requests, stats.required_requests, lane.eps
        ));
    }
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
    if stats.p99_ms > p99_bound_ms {
        breaches.push(format!(
            "{}: p99 {:.0}ms over the {:.0}ms bound",
            lane.name, stats.p99_ms, p99_bound_ms
        ));
    }
    breaches
}

/// `stow-admin traffic-cost peak` — fire the lanes, then emit the
/// report and exit nonzero on a breach.
pub async fn run(edge: &Edge, args: &PeakArgs, output: Output) -> stow_types::error::Result<()> {
    let report = if let (Some(url), Some(path)) = (&args.inspector_url, &args.cpu_out) {
        let (report, cpu) = super::cpu::capture_segment(url, "peak", path, async || {
            let report = drive(edge, args).await?;
            emit(output, &report, render_report)?;
            Ok(report)
        })
        .await?;
        tokio::fs::write(path, serde_json::to_vec(&cpu)?).await?;
        report
    } else {
        let report = drive(edge, args).await?;
        emit(output, &report, render_report)?;
        report
    };
    if report.breaches.is_empty() {
        Ok(())
    } else {
        Err(stow_error!(
            "traffic-cost peak: {} breach(es)",
            report.breaches.len()
        ))
    }
}

async fn drive(edge: &Edge, args: &PeakArgs) -> stow_types::error::Result<LoadReport> {
    let model = super::read_model(&args.lanes.model).await?;
    let lanes = lanes::build_lanes(
        &args.lanes,
        &model,
        args.rate_scale,
        args.build_callback_eps,
    )
    .map_err(|error| stow_error!("{error}"))?;

    let duration = Duration::from_secs(args.duration_secs);
    let concurrency = match args.max_in_flight_per_lane {
        Some(value) => value,
        None => std::thread::available_parallelism()
            .map_err(|error| stow_error!("peak host parallelism: {error}"))?,
    };
    let start = tokio::time::Instant::now();
    let results = futures_util::future::join_all(
        lanes
            .iter()
            .map(|lane| run_lane(lane, edge, start, duration, concurrency.get())),
    )
    .await;

    let mut lanes_map = BTreeMap::new();
    let mut breaches = Vec::new();
    for (lane, stats) in lanes.iter().zip(results) {
        breaches.extend(lane_breaches(lane, &stats, args.p99_bound_ms));
        lanes_map.insert(lane.name, stats);
    }
    let report = LoadReport {
        duration_secs: args.duration_secs,
        rate_scale: args.rate_scale,
        build_callback_eps: args.build_callback_eps,
        max_in_flight_per_lane: concurrency.get(),
        lanes: lanes_map,
        breaches,
    };
    Ok(report)
}

/// Human rendering — per-lane rate/latency/status table plus the
/// verdict lines.
fn render_report(report: &LoadReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let mut table = Table::new(&[
        "lane",
        "slots",
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
            stats.request_slots.to_string(),
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
    use super::{Duration, required_requests, run_paced};
    use tokio::time::Instant;

    #[tokio::test]
    async fn http_requests_overlap_and_aggregate_completed_bodies() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock HTTP listener");
        let edge = crate::Edge::for_test(format!(
            "http://{}",
            listener.local_addr().expect("mock address")
        ));
        let pair = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let router = axum::Router::new().fallback(move || {
            let pair = pair.clone();
            async move {
                pair.wait().await;
                "complete response body"
            }
        });
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.expect("mock serves");
        });
        let lane = super::Lane {
            name: "overlap-test",
            eps: 2.0,
            fire: super::lanes::Fire::PublicGet(vec!["/body".to_owned()]),
            expected: |status| status == 200,
        };
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            super::run_lane(&lane, &edge, Instant::now(), Duration::from_secs(2), 2),
        )
        .await;
        server.abort();
        let _ = server.await;
        let stats = result.expect("overlapping clients complete");
        assert_eq!(stats.request_slots, 2);
        assert_eq!(stats.requests, 4);
        assert_eq!(stats.statuses.get(&200), Some(&4));
        assert_eq!(stats.transport_errors, 0);
        assert_eq!(stats.unexpected_statuses, 0);
        assert_eq!(stats.latencies_ms.len(), 4);
    }

    #[tokio::test]
    async fn preparation_failure_preserves_completed_requests_and_other_lanes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let edge = crate::Edge::for_test(format!(
            "http://{}",
            listener.local_addr().expect("address")
        ));
        let rearmed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let router = axum::Router::new()
            .route(
                "/api/v1/admin/scheduler/budget/rearm",
                axum::routing::post(move || {
                    let rearmed = rearmed.clone();
                    async move {
                        if rearmed.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
                            (
                                axum::http::StatusCode::OK,
                                axum::Json(serde_json::json!({"armed": [0]})),
                            )
                        } else {
                            (
                                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                                axum::Json(serde_json::json!({"error": "rearm failed"})),
                            )
                        }
                    }
                }),
            )
            .fallback(|| async { "complete body" });
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve");
        });
        let callback = super::Lane {
            name: "callback",
            eps: 10.0,
            fire: super::lanes::Fire::WorkflowRun(
                super::lanes::CallbackLane::new("secret".to_owned(), 100_000).expect("callback"),
            ),
            expected: |status| status == 200,
        };
        let healthy = super::Lane {
            name: "healthy",
            eps: 10.0,
            fire: super::lanes::Fire::PublicGet(vec!["/body".to_owned()]),
            expected: |status| status == 200,
        };
        let start = Instant::now();
        let duration = Duration::from_millis(150);
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            futures_util::join!(
                super::run_lane(&callback, &edge, start, duration, 1),
                super::run_lane(&healthy, &edge, start, duration, 1),
            )
        })
        .await;
        server.abort();
        let _ = server.await;
        let (failed, passed) = result.expect("bounded lanes");
        assert_eq!(failed.requests, 1);
        assert_eq!(failed.statuses.get(&200), Some(&1));
        assert_eq!(failed.latencies_ms.len(), 1);
        assert_eq!(failed.observations.len(), 1);
        let observations = serde_json::to_value(&failed.observations).expect("observations");
        assert!(observations[0]["phases_ms"]["body"].is_number());
        assert!(observations[0]["started_ms"].is_number());
        assert!(observations[0]["preparation_ms"].is_number());
        assert_eq!(failed.preparation_errors.len(), 1);
        assert!(failed.requests >= failed.required_requests);
        let breaches = super::lane_breaches(&callback, &failed, f64::INFINITY);
        assert_eq!(breaches.len(), 1);
        assert!(breaches[0].contains("preparation failed"));
        assert!(breaches[0].contains("503"));
        assert!(passed.requests >= passed.required_requests);
        assert_eq!(passed.statuses.get(&200), Some(&passed.requests));
        assert_eq!(
            super::lane_breaches(&healthy, &passed, f64::INFINITY),
            Vec::<String>::new()
        );
        let json = serde_json::to_value(&failed).expect("report stats");
        assert_eq!(json["requests"], 1);
        assert_eq!(
            json["preparation_errors"].as_array().expect("errors").len(),
            1
        );
    }

    /// Run `run_paced` under the paused clock and return every event's
    /// virtual fire instant plus the virtual instant the run returned —
    /// each event spends `work` in flight before its call completes.
    /// Each request slot owns its recording vector.
    async fn run_recording(
        interval: Duration,
        duration: Duration,
        work: Duration,
    ) -> (Vec<Duration>, Duration) {
        run_recording_slots(interval, duration, work, 1).await
    }

    async fn run_recording_slots(
        interval: Duration,
        duration: Duration,
        work: Duration,
        concurrency: usize,
    ) -> (Vec<Duration>, Duration) {
        let start = Instant::now();
        let slots = futures_util::future::join_all((0..concurrency).map(|first| async move {
            let mut seen = Vec::new();
            run_paced(
                start,
                interval,
                duration,
                first,
                concurrency,
                async |counter| {
                    seen.push((counter, Instant::now() - start));
                    tokio::time::sleep(work).await;
                },
            )
            .await;
            seen
        }))
        .await;
        let events: Vec<_> = slots.into_iter().flatten().collect();
        let counters: std::collections::BTreeSet<_> =
            events.iter().map(|(counter, _)| *counter).collect();
        assert_eq!(
            counters.len(),
            events.len(),
            "event identities stay distinct"
        );
        let mut seen: Vec<_> = events.into_iter().map(|(_, at)| at).collect();
        seen.sort();
        (seen, Instant::now() - start)
    }

    #[tokio::test(start_paused = true)]
    async fn overlapping_responses_preserve_the_requested_rate() {
        let (fires, elapsed) = run_recording_slots(
            Duration::from_secs(1),
            Duration::from_secs(4),
            Duration::from_millis(1500),
            2,
        )
        .await;
        assert_eq!(fires, [0, 1, 2, 3].map(Duration::from_secs));
        assert_eq!(elapsed, Duration::from_millis(4500));
    }

    #[tokio::test(start_paused = true)]
    async fn slow_responses_respect_the_in_flight_bound() {
        let (fires, elapsed) = run_recording_slots(
            Duration::from_secs(1),
            Duration::from_secs(4),
            Duration::from_secs(3),
            2,
        )
        .await;
        assert_eq!(fires, [0, 1, 3].map(Duration::from_secs));
        assert!((fires.len() as u64) < required_requests(1.0, Duration::from_secs(4)));
        assert_eq!(elapsed, Duration::from_secs(6));
    }

    #[test]
    fn rate_requirement_rounds_only_the_partial_request() {
        assert_eq!(required_requests(0.005, Duration::from_secs(450)), 2);
        assert_eq!(required_requests(9.0, Duration::from_secs(450)), 4050);
        assert_eq!(required_requests(0.005, Duration::from_secs(45)), 0);
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

    #[tokio::test(start_paused = true)]
    async fn delayed_event_does_not_shift_later_beats() {
        let start = Instant::now();
        let mut fires = Vec::new();
        run_paced(
            start,
            Duration::from_secs(1),
            Duration::from_secs(4),
            0,
            1,
            async |counter| {
                fires.push(Instant::now() - start);
                if counter == 0 {
                    tokio::time::sleep(Duration::from_millis(1200)).await;
                }
            },
        )
        .await;
        assert_eq!(fires, [0, 1200, 2000, 3000].map(Duration::from_millis));
        assert_eq!(Instant::now() - start, Duration::from_secs(4));
    }

    /// An event slower than the interval waits nothing before the next
    /// fire, and an in-flight
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
        assert!((fires.len() as u64) < required_requests(1.0, Duration::from_secs(4)));
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
