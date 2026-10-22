//! `stow-admin traffic-cost cpu` — Worker CPU per traffic lane, measured
//! on the mock stack and gated against `WORKER_CPU_BUDGETS` (stow#772).
//!
//! Local workerd reports no CPU time of its own: the tail `outcome`
//! event's `cpuTime` is hard-coded to zero in open-source workerd, and
//! `Date.now()` inside the isolate only advances on I/O. The measurement
//! Cloudflare documents for local CPU work is the V8 CPU profiler behind
//! `wrangler dev`'s `DevTools` inspector, so that is what this pass drives:
//! `Profiler.start`, one lane's events fired back to back, then
//! `Profiler.stop` and the sample count.
//!
//! workerd runs its isolates under `v8::Locker`, and V8's sampler drops
//! every tick that lands while the isolate's lock is not held
//! (`CpuSampler::SampleStack` in V8's `src/profiler/cpu-profiler.cc`
//! returns with `kIsolateNotLocked`) — so the
//! profile carries a sample only while the isolate executes, and samples
//! × the sampling interval is the isolate's CPU time. `timeDeltas` are
//! not summed: across a gap in which the isolate was not running, the
//! next delta spans the gap and would turn the number back into wall
//! time. The pass verifies that premise before it measures anything: it
//! profiles a quiet window with no traffic and fails when that window
//! collects more than [`IDLE_CPU_FRACTION`] of its length in samples —
//! a profiler that samples an idle isolate would be measuring wall time,
//! and the pass refuses to call that CPU.
//!
//! The isolate also runs the scheduler Durable Object under `wrangler
//! dev`, so a lane that calls the object carries the object's CPU too:
//! the number is at or above the Worker CPU Cloudflare bills, never
//! below it. Each lane is warmed first (JIT and caches), then measured
//! in [`ROUNDS`] separate profiles; the lane's figure is the smallest
//! round, because what else lands in the isolate during a round (an
//! alarm pass a previous lane armed, a dispatch callback) only ever adds
//! samples.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use clap::Args;
use serde::{Deserialize, Serialize};
use stow_types::do_budgets::WORKER_CPU_BUDGETS;
use stow_types::stow_error;
use zenwave::websocket::{self, WebSocket, WebSocketMessage};

use super::lanes::{self, Lane, LaneArgs, Outcome, REQUEST_TIMEOUT};
use crate::Edge;
use crate::render::{Output, Table, emit};

/// The CPU pass — `stow-admin traffic-cost cpu`.
#[derive(Debug, Args)]
pub struct CpuArgs {
    #[command(flatten)]
    pub lanes: LaneArgs,
    /// The edge's `DevTools` inspector — `wrangler dev --inspector-port`'s
    /// `ws://127.0.0.1:<port>/ws`.
    #[arg(long)]
    pub inspector_url: String,
    /// Events per profiled round.
    #[arg(long, default_value_t = 20)]
    pub events_per_round: u32,
    /// Unprofiled events fired first, so JIT tiers and caches are warm.
    #[arg(long, default_value_t = 5)]
    pub warmup_events: u32,
}

/// Profiled rounds per lane; the lane reports the smallest.
const ROUNDS: usize = 3;

/// V8 sampling interval in microseconds — the resolution of one sample.
const SAMPLING_INTERVAL_US: u64 = 100;

/// The quiet window that checks the sampler only samples a running
/// isolate.
const IDLE_WINDOW: Duration = Duration::from_secs(3);

/// The share of the quiet window the idle profile may collect. Anything
/// above it means samples arrive while the isolate is not executing.
const IDLE_CPU_FRACTION: f64 = 0.01;

/// One lane's measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerCpuRow {
    /// The lane name — `WORKER_CPU_BUDGETS`' key.
    pub lane: String,
    /// Events each profiled round fired.
    pub events_per_round: u32,
    /// CPU milliseconds per event, one entry per round.
    pub rounds_cpu_ms: Vec<f64>,
    /// The lane's figure: the smallest round.
    pub cpu_ms: f64,
    /// The budgeted CPU milliseconds per event.
    pub budget_ms: f64,
    /// `cpu_ms > budget_ms`.
    pub over_budget: bool,
}

/// What the pass writes — the per-lane rows plus the premise check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerCpuReport {
    /// The profiler's sampling interval.
    pub sampling_interval_us: u64,
    /// Length of the quiet window profiled before any lane.
    pub idle_window_ms: u64,
    /// CPU milliseconds the quiet window collected.
    pub idle_cpu_ms: f64,
    /// Per-lane measurements, in lane order.
    pub rows: Vec<WorkerCpuRow>,
}

impl WorkerCpuReport {
    /// The rows over budget.
    fn breaches(&self) -> impl Iterator<Item = &WorkerCpuRow> {
        self.rows.iter().filter(|row| row.over_budget)
    }

    /// The measured CPU of `lane`, or why the report cannot price it.
    pub fn lane_cpu_ms(&self, lane: &str) -> Result<f64, String> {
        self.rows
            .iter()
            .find(|row| row.lane == lane)
            .map(|row| row.cpu_ms)
            .ok_or_else(|| format!("Worker CPU report carries no row for lane `{lane}`"))
    }
}

/// A `DevTools` protocol session on the inspector socket.
struct Inspector {
    socket: WebSocket,
    next_id: AtomicU64,
}

impl Inspector {
    async fn connect(url: &str) -> stow_types::error::Result<Self> {
        let socket = websocket::connect(url)
            .await
            .map_err(|error| stow_error!("connect to the inspector at {url}: {error}"))?;
        Ok(Self {
            socket,
            next_id: AtomicU64::new(1),
        })
    }

    /// Send one command and return its `result`, skipping the protocol
    /// events that arrive in between.
    async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> stow_types::error::Result<serde_json::Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let message = serde_json::json!({ "id": id, "method": method, "params": params });
        self.socket
            .send_text(message.to_string())
            .await
            .map_err(|error| stow_error!("inspector {method}: send: {error}"))?;
        loop {
            let frame = tokio::time::timeout(REQUEST_TIMEOUT, self.socket.recv())
                .await
                .map_err(|_| {
                    stow_error!("inspector {method}: no answer within {REQUEST_TIMEOUT:?}")
                })?
                .map_err(|error| stow_error!("inspector {method}: receive: {error}"))?;
            let text = match frame {
                Some(WebSocketMessage::Text(text)) => text.to_string(),
                Some(WebSocketMessage::Binary(bytes)) => String::from_utf8(bytes.to_vec())
                    .map_err(|error| stow_error!("inspector {method}: non-UTF-8 frame: {error}"))?,
                Some(WebSocketMessage::Ping(_) | WebSocketMessage::Pong(_)) => continue,
                Some(WebSocketMessage::Close) | None => {
                    return Err(stow_error!("inspector {method}: the socket closed"));
                }
            };
            let reply: serde_json::Value = serde_json::from_str(&text)
                .map_err(|error| stow_error!("inspector {method}: decode: {error}"))?;
            if reply.get("id").and_then(serde_json::Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(error) = reply.get("error") {
                return Err(stow_error!("inspector {method}: {error}"));
            }
            return Ok(reply.get("result").cloned().unwrap_or_default());
        }
    }
}

/// The part of a `Profiler.stop` profile the count needs.
#[derive(Debug, Deserialize)]
struct CpuProfile {
    nodes: Vec<ProfileNode>,
    samples: Vec<u64>,
}

#[derive(Debug, Deserialize)]
struct ProfileNode {
    id: u64,
    #[serde(rename = "callFrame")]
    call_frame: CallFrame,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CallFrame {
    function_name: String,
}

/// CPU milliseconds a profile holds: its non-`(idle)` samples times the
/// sampling interval.
#[expect(
    clippy::cast_precision_loss,
    reason = "sample counts are far inside f64's mantissa"
)]
fn profile_cpu_ms(profile: &CpuProfile) -> f64 {
    let idle: std::collections::BTreeSet<u64> = profile
        .nodes
        .iter()
        .filter(|node| node.call_frame.function_name == "(idle)")
        .map(|node| node.id)
        .collect();
    let busy = profile
        .samples
        .iter()
        .filter(|sample| !idle.contains(sample))
        .count();
    busy as f64 * SAMPLING_INTERVAL_US as f64 / 1000.0
}

/// Profile whatever `work` drives and return the profile's CPU ms.
async fn profiled(
    inspector: &Inspector,
    work: impl AsyncFnOnce() -> stow_types::error::Result<()>,
) -> stow_types::error::Result<f64> {
    inspector
        .call("Profiler.start", serde_json::Value::Null)
        .await?;
    let worked = work().await;
    let stopped = inspector
        .call("Profiler.stop", serde_json::Value::Null)
        .await?;
    worked?;
    let profile: CpuProfile = serde_json::from_value(
        stopped
            .get("profile")
            .cloned()
            .ok_or_else(|| stow_error!("Profiler.stop returned no profile"))?,
    )
    .map_err(|error| stow_error!("decode the CPU profile: {error}"))?;
    Ok(profile_cpu_ms(&profile))
}

/// Fire `count` events of `lane` back to back; any response outside the
/// lane's expected set fails the pass — a CPU figure of an error path
/// prices nothing the launch fleet pays for.
async fn fire_events(
    lane: &Lane,
    edge: &Edge,
    client: &mut zenwave::DefaultClient,
    counter: &mut u64,
    count: u32,
) -> stow_types::error::Result<()> {
    for _ in 0..count {
        let outcome = tokio::time::timeout(
            REQUEST_TIMEOUT,
            lanes::fire_once(&lane.fire, edge, client, *counter),
        )
        .await
        .map_err(|_| stow_error!("{}: event exceeded {REQUEST_TIMEOUT:?}", lane.name))?
        .map_err(|error| stow_error!("{}: {error}", lane.name))?;
        *counter += 1;
        match outcome {
            Outcome::Response { status, .. } if (lane.expected)(status) => {}
            Outcome::Response { status, .. } => {
                return Err(stow_error!(
                    "{}: status {status} is not this lane's designed answer",
                    lane.name
                ));
            }
            Outcome::Transport(error) => {
                return Err(stow_error!("{}: transport error: {error}", lane.name));
            }
        }
    }
    Ok(())
}

/// Make `count` events of `lane` fireable — harness work, so it runs
/// before a round's profile starts, never inside one.
async fn ready(lane: &Lane, edge: &Edge, count: u32) -> stow_types::error::Result<()> {
    lane.fire
        .ready(
            edge,
            usize::try_from(count).map_err(|_| stow_error!("{count} events per round"))?,
        )
        .await
        .map_err(|error| stow_error!("{}: {error}", lane.name))
}

/// Measure one lane: warm it, then [`ROUNDS`] profiled rounds.
async fn measure_lane(
    lane: &Lane,
    edge: &Edge,
    inspector: &Inspector,
    args: &CpuArgs,
) -> stow_types::error::Result<WorkerCpuRow> {
    let budget = WORKER_CPU_BUDGETS
        .iter()
        .find(|budget| budget.lane == lane.name)
        .ok_or_else(|| {
            stow_error!(
                "lane `{}` has no WORKER_CPU_BUDGETS row — every measured lane is gated",
                lane.name
            )
        })?;
    let mut client = zenwave::client();
    let mut counter = 0u64;
    ready(lane, edge, args.warmup_events).await?;
    fire_events(lane, edge, &mut client, &mut counter, args.warmup_events).await?;
    let mut rounds_cpu_ms = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        ready(lane, edge, args.events_per_round).await?;
        let cpu_ms = profiled(inspector, async || {
            fire_events(lane, edge, &mut client, &mut counter, args.events_per_round).await
        })
        .await?;
        rounds_cpu_ms.push(cpu_ms / f64::from(args.events_per_round));
    }
    let cpu_ms = rounds_cpu_ms.iter().copied().fold(f64::INFINITY, f64::min);
    Ok(WorkerCpuRow {
        lane: lane.name.to_owned(),
        events_per_round: args.events_per_round,
        rounds_cpu_ms,
        cpu_ms,
        budget_ms: budget.cpu_ms,
        over_budget: budget.over_budget(cpu_ms),
    })
}

/// `stow-admin traffic-cost cpu` — check the sampler, measure every
/// lane, emit the report, and exit nonzero on a lane over budget.
#[expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    reason = "the idle window is three seconds"
)]
pub async fn run(edge: &Edge, args: &CpuArgs, output: Output) -> stow_types::error::Result<()> {
    if args.events_per_round == 0 {
        return Err(stow_error!("--events-per-round must be at least 1"));
    }
    let model = super::read_model(&args.lanes.model).await?;
    let lanes =
        lanes::build_lanes(&args.lanes, &model, 1.0).map_err(|error| stow_error!("{error}"))?;
    let inspector = Inspector::connect(&args.inspector_url).await?;
    inspector
        .call("Profiler.enable", serde_json::Value::Null)
        .await?;
    inspector
        .call(
            "Profiler.setSamplingInterval",
            serde_json::json!({ "interval": SAMPLING_INTERVAL_US }),
        )
        .await?;

    let idle_cpu_ms = profiled(&inspector, async || {
        tokio::time::sleep(IDLE_WINDOW).await;
        Ok(())
    })
    .await?;
    let idle_window_ms = IDLE_WINDOW.as_millis() as f64;
    if idle_cpu_ms > idle_window_ms * IDLE_CPU_FRACTION {
        return Err(stow_error!(
            "the profiler collected {idle_cpu_ms:.1} ms of samples over a {idle_window_ms:.0} ms \
             window with no traffic — it samples the isolate while it is not executing, so its \
             samples measure wall time, not CPU"
        ));
    }

    let mut rows = Vec::with_capacity(lanes.len());
    for lane in &lanes {
        rows.push(measure_lane(lane, edge, &inspector, args).await?);
    }
    let report = WorkerCpuReport {
        sampling_interval_us: SAMPLING_INTERVAL_US,
        idle_window_ms: IDLE_WINDOW.as_millis() as u64,
        idle_cpu_ms,
        rows,
    };
    emit(output, &report, render_report)?;
    let over = report.breaches().count();
    if over == 0 {
        Ok(())
    } else {
        Err(stow_error!(
            "traffic-cost cpu: {over} lane(s) over their Worker CPU budget"
        ))
    }
}

/// Human rendering — one row per lane against its budget.
fn render_report(report: &WorkerCpuReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let mut table = Table::new(&["lane", "cpu ms/event", "rounds", "budget ms", ""]);
    for row in &report.rows {
        table.push([
            row.lane.clone(),
            format!("{:.2}", row.cpu_ms),
            row.rounds_cpu_ms
                .iter()
                .map(|ms| format!("{ms:.2}"))
                .collect::<Vec<_>>()
                .join(" "),
            format!("{:.0}", row.budget_ms),
            if row.over_budget { "OVER" } else { "" }.to_owned(),
        ]);
    }
    let _ = writeln!(
        out,
        "Worker CPU per event (V8 profiler, {} µs sampling; idle window {} ms collected {:.2} ms):",
        report.sampling_interval_us, report.idle_window_ms, report.idle_cpu_ms
    );
    let _ = writeln!(out, "{}", table.render());
    let over: Vec<&str> = report.breaches().map(|row| row.lane.as_str()).collect();
    if over.is_empty() {
        let _ = writeln!(out, "\ntraffic-cost cpu: PASS");
    } else {
        let _ = writeln!(
            out,
            "\ntraffic-cost cpu: FAIL — over budget: {}",
            over.join(", ")
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{CpuProfile, profile_cpu_ms};

    /// Idle samples are not CPU; every other sample is one interval.
    #[test]
    fn idle_samples_do_not_count() {
        let profile: CpuProfile = serde_json::from_value(serde_json::json!({
            "nodes": [
                {"id": 1, "callFrame": {"functionName": "(root)"}},
                {"id": 2, "callFrame": {"functionName": "(idle)"}},
                {"id": 3, "callFrame": {"functionName": "fetch"}},
                {"id": 4, "callFrame": {"functionName": "(garbage collector)"}},
            ],
            "samples": [2, 3, 3, 2, 4, 3],
            "timeDeltas": [100, 100, 9000, 100, 100, 100],
        }))
        .expect("profile");
        // Four busy samples at 100 µs — the 9 ms delta is a gap, not CPU.
        assert!((profile_cpu_ms(&profile) - 0.4).abs() < 1e-9);
    }
}
