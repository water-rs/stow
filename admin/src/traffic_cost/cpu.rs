//! `stow-admin traffic-cost cpu` — Worker CPU per traffic lane, measured
//! on the mock stack and gated against `WORKER_CPU_BUDGETS` (stow#772),
//! relative to a reference workload measured in the same isolate on the
//! same runner (stow#932).
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
//!
//! Those milliseconds scale with the runner: release gate runs of the
//! same code measured the same lane up to twice apart between runs,
//! while its rounds within one run agreed to a few percent. So the gate
//! never judges a lane's milliseconds. Before the lanes and again after
//! them the pass profiles a fixed reference workload
//! (`reference_workload.js`), evaluated through the same inspector into
//! the same isolate, on the same runner and the same V8 build; a lane is
//! gated on its CPU per event over the reference's CPU. The workload
//! does the two kinds of work the lanes spend their CPU on: the
//! scheduler's scans over its in-memory graph, at the graph's layout
//! and the fixture's node count, so it meets the same cache behaviour;
//! and serializing, parsing and hashing request-sized JSON. A runner
//! that runs that work slower runs the lanes slower too, and the
//! quotient cancels it. The reference is unusable — and the pass fails
//! rather than gate on it — when it returns anything but its checksum,
//! when a round collects too few samples to resolve, or when the
//! reference before the lanes and after them disagree by more than
//! [`REFERENCE_DRIFT_LIMIT`]: the runner's speed moved during the pass,
//! so no single reference describes every lane.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use clap::Args;
use serde::{Deserialize, Serialize};
use stow_types::do_budgets::{WORKER_CPU_BUDGETS, WorkerCpuBudget};
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

/// The reference workload the lanes are gated relative to.
const REFERENCE_WORKLOAD: &str = include_str!("reference_workload.js");

/// What [`REFERENCE_WORKLOAD`] evaluates to. Any other answer means the
/// isolate ran something other than the work the budgets were derived
/// against.
const REFERENCE_CHECKSUM: u64 = 1_000_149_044;

/// The least CPU one reference round may collect: 100 samples at
/// [`SAMPLING_INTERVAL_US`], so one sample more or less moves the
/// reference by at most 1%.
const MIN_REFERENCE_CPU_MS: f64 = 10.0;

/// How far apart the reference before the lanes and the reference after
/// them may lie, as the larger over the smaller.
const REFERENCE_DRIFT_LIMIT: f64 = 1.25;

/// The reference workload's measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceCpu {
    /// Each round's CPU milliseconds, profiled before the first lane.
    pub rounds_before: Vec<f64>,
    /// Each round's CPU milliseconds, profiled after the last lane.
    pub rounds_after: Vec<f64>,
    /// The reference's CPU milliseconds: the smallest round of either
    /// set.
    pub cpu_ms: f64,
}

/// One lane's measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerCpuRow {
    /// The lane name — `WORKER_CPU_BUDGETS`' key.
    pub lane: String,
    /// Events each profiled round fired.
    pub events_per_round: u32,
    /// CPU milliseconds per event, one entry per round.
    pub rounds_cpu_ms: Vec<f64>,
    /// The lane's CPU milliseconds per event: the smallest round.
    pub cpu_ms: f64,
    /// `cpu_ms` over the reference's CPU milliseconds — the gated figure.
    pub relative_cpu: f64,
    /// The lane's budget, relative to the reference.
    pub budget_relative_cpu: f64,
    /// The budget in this run's milliseconds: `budget_relative_cpu`
    /// times the reference's CPU milliseconds.
    pub budget_ms: f64,
    /// `relative_cpu > budget_relative_cpu`.
    pub over_budget: bool,
}

/// What the pass writes — the per-lane rows plus the premise checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerCpuReport {
    /// The profiler's sampling interval.
    pub sampling_interval_us: u64,
    /// Length of the quiet window profiled before any lane.
    pub idle_window_ms: u64,
    /// CPU milliseconds the quiet window collected.
    pub idle_cpu_ms: f64,
    /// The reference workload every lane is gated relative to.
    pub reference: ReferenceCpu,
    /// Per-lane measurements, in lane order.
    pub rows: Vec<WorkerCpuRow>,
}

impl WorkerCpuReport {
    /// The rows over budget.
    fn breaches(&self) -> impl Iterator<Item = &WorkerCpuRow> {
        self.rows.iter().filter(|row| row.over_budget)
    }

    fn row(&self, lane: &str) -> Result<&WorkerCpuRow, String> {
        self.rows
            .iter()
            .find(|row| row.lane == lane)
            .ok_or_else(|| format!("Worker CPU report carries no row for lane `{lane}`"))
    }

    /// The measured CPU of `lane`, or why the report cannot price it.
    pub fn lane_cpu_ms(&self, lane: &str) -> Result<f64, String> {
        self.row(lane).map(|row| row.cpu_ms)
    }

    /// The budget of `lane` in the run's milliseconds, or why the
    /// report cannot price it.
    pub fn lane_budget_ms(&self, lane: &str) -> Result<f64, String> {
        self.row(lane).map(|row| row.budget_ms)
    }
}

/// One lane's profiled rounds, before the reference that gates them is
/// known.
struct LaneCpu {
    budget: &'static WorkerCpuBudget,
    events_per_round: u32,
    rounds_cpu_ms: Vec<f64>,
}

impl LaneCpu {
    /// Gate the lane against its budget, relative to `reference_ms`.
    fn gate(self, reference_ms: f64) -> WorkerCpuRow {
        let cpu_ms = smallest(&self.rounds_cpu_ms);
        let relative_cpu = cpu_ms / reference_ms;
        WorkerCpuRow {
            lane: self.budget.lane.to_owned(),
            events_per_round: self.events_per_round,
            rounds_cpu_ms: self.rounds_cpu_ms,
            cpu_ms,
            relative_cpu,
            budget_relative_cpu: self.budget.relative_cpu,
            budget_ms: self.budget.relative_cpu * reference_ms,
            over_budget: self.budget.over_budget(relative_cpu),
        }
    }
}

/// The smallest of `rounds` — what a measurement reports, since
/// interference only ever adds samples.
fn smallest(rounds: &[f64]) -> f64 {
    rounds.iter().copied().fold(f64::INFINITY, f64::min)
}

/// The reference from its rounds before and after the lanes, or why it
/// cannot gate them.
fn reference_cpu(
    rounds_before: Vec<f64>,
    rounds_after: Vec<f64>,
) -> stow_types::error::Result<ReferenceCpu> {
    let before = smallest(&rounds_before);
    let after = smallest(&rounds_after);
    if let Some(round) = rounds_before
        .iter()
        .chain(&rounds_after)
        .find(|&&round| round < MIN_REFERENCE_CPU_MS)
    {
        return Err(stow_error!(
            "a reference round collected {round:.1} ms of samples, under the \
             {MIN_REFERENCE_CPU_MS} ms one round needs to resolve — the profile did not cover \
             the reference workload"
        ));
    }
    let drift = before.max(after) / before.min(after);
    if drift > REFERENCE_DRIFT_LIMIT {
        return Err(stow_error!(
            "the reference measured {before:.2} ms before the lanes and {after:.2} ms after \
             them, {drift:.2}× apart (limit {REFERENCE_DRIFT_LIMIT}×) — the runner's speed \
             moved during the pass, so no one reference gates every lane"
        ));
    }
    Ok(ReferenceCpu {
        rounds_before,
        rounds_after,
        cpu_ms: before.min(after),
    })
}

/// A `DevTools` protocol session on the inspector socket.
struct Session {
    socket: WebSocket,
    next_id: AtomicU64,
}

impl Session {
    /// Send one command and return its `result`, skipping the protocol
    /// events that arrive in between.
    async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> stow_types::error::Result<serde_json::Value> {
        self.call_observing(method, params, |_| Ok(())).await
    }

    /// [`Session::call`], handing every protocol event that arrives
    /// before the answer to `observe`.
    async fn call_observing(
        &self,
        method: &str,
        params: serde_json::Value,
        mut observe: impl FnMut(&serde_json::Value) -> stow_types::error::Result<()>,
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
                if reply.get("method").is_some() {
                    observe(&reply)?;
                }
                continue;
            }
            if let Some(error) = reply.get("error") {
                return Err(stow_error!("inspector {method}: {error}"));
            }
            return Ok(reply.get("result").cloned().unwrap_or_default());
        }
    }
}

/// The inspector session, bound to the edge's execution context.
struct Inspector {
    session: Session,
    /// The execution context [`REFERENCE_WORKLOAD`] evaluates in.
    context_id: u64,
}

impl Inspector {
    /// Connect and resolve the edge's execution context.
    ///
    /// workerd's inspector client names no default context, so a
    /// `Runtime.evaluate` without a `contextId` fails with V8's "Cannot
    /// find default execution context"; the context is only known from
    /// the `Runtime.executionContextCreated` event V8 reports for it.
    /// `wrangler dev`'s inspector proxy shares one runtime session among
    /// its clients and enabled the `Runtime` domain on it when it
    /// connected — the events that reported the contexts then went to
    /// whichever client connected first — so a client's `Runtime.enable`
    /// is a no-op that reports nothing. `Runtime.disable` first makes the
    /// `Runtime.enable` that follows report every live context again,
    /// whoever connected before.
    async fn connect(url: &str) -> stow_types::error::Result<Self> {
        let socket = websocket::connect(url)
            .await
            .map_err(|error| stow_error!("connect to the inspector at {url}: {error}"))?;
        let session = Session {
            socket,
            next_id: AtomicU64::new(1),
        };
        session
            .call("Runtime.disable", serde_json::Value::Null)
            .await?;
        let mut contexts = Vec::new();
        session
            .call_observing("Runtime.enable", serde_json::Value::Null, |event| {
                track_context(&mut contexts, event)
            })
            .await?;
        Ok(Self {
            session,
            context_id: edge_context(&contexts)?,
        })
    }

    /// [`Session::call`] on this inspector's session.
    async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> stow_types::error::Result<serde_json::Value> {
        self.session.call(method, params).await
    }

    /// Evaluate [`REFERENCE_WORKLOAD`] in the isolate and check it
    /// returned [`REFERENCE_CHECKSUM`].
    async fn run_reference(&self) -> stow_types::error::Result<()> {
        let evaluated = self
            .call(
                "Runtime.evaluate",
                serde_json::json!({
                    "expression": REFERENCE_WORKLOAD,
                    "contextId": self.context_id,
                    "returnByValue": true,
                }),
            )
            .await?;
        if let Some(exception) = evaluated.get("exceptionDetails") {
            return Err(stow_error!("the reference workload threw: {exception}"));
        }
        let value = evaluated
            .get("result")
            .and_then(|result| result.get("value"))
            .and_then(serde_json::Value::as_u64);
        if value != Some(REFERENCE_CHECKSUM) {
            return Err(stow_error!(
                "the reference workload returned {evaluated}, not its checksum \
                 {REFERENCE_CHECKSUM}"
            ));
        }
        Ok(())
    }
}

/// The name workerd gives a worker's execution context when it registers
/// it with the inspector (`setupContext` in workerd's `io/worker.c++`).
const WORKER_CONTEXT_NAME: &str = "Worker";

/// An execution context the inspector reported.
#[derive(Debug, Deserialize)]
struct ExecutionContext {
    id: u64,
    name: String,
}

/// Apply one protocol event to the live execution contexts.
fn track_context(
    contexts: &mut Vec<ExecutionContext>,
    event: &serde_json::Value,
) -> stow_types::error::Result<()> {
    let params = event.get("params").unwrap_or(&serde_json::Value::Null);
    match event.get("method").and_then(serde_json::Value::as_str) {
        Some("Runtime.executionContextCreated") => {
            let context = ExecutionContext::deserialize(&params["context"])
                .map_err(|error| stow_error!("decode {event}: {error}"))?;
            contexts.retain(|live| live.id != context.id);
            contexts.push(context);
        }
        Some("Runtime.executionContextDestroyed") => {
            let id = params["executionContextId"]
                .as_u64()
                .ok_or_else(|| stow_error!("{event} names no execution context id"))?;
            contexts.retain(|live| live.id != id);
        }
        Some("Runtime.executionContextsCleared") => contexts.clear(),
        _ => {}
    }
    Ok(())
}

/// The one worker context among `contexts`, or why there is none to
/// evaluate in.
fn edge_context(contexts: &[ExecutionContext]) -> stow_types::error::Result<u64> {
    let workers: Vec<u64> = contexts
        .iter()
        .filter(|context| context.name == WORKER_CONTEXT_NAME)
        .map(|context| context.id)
        .collect();
    if let [id] = workers.as_slice() {
        return Ok(*id);
    }
    let reported: Vec<String> = contexts
        .iter()
        .map(|context| format!("{} `{}`", context.id, context.name))
        .collect();
    Err(stow_error!(
        "Runtime.enable reported {} `{WORKER_CONTEXT_NAME}` execution contexts, not one \
         (reported: [{}]) — the reference workload has no single isolate context to run in",
        workers.len(),
        reported.join(", ")
    ))
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
) -> stow_types::error::Result<LaneCpu> {
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
    Ok(LaneCpu {
        budget,
        events_per_round: args.events_per_round,
        rounds_cpu_ms,
    })
}

/// Profile the reference workload: one unprofiled run to warm the JIT,
/// then [`ROUNDS`] profiled rounds.
async fn measure_reference(inspector: &Inspector) -> stow_types::error::Result<Vec<f64>> {
    inspector.run_reference().await?;
    let mut rounds_ms = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        rounds_ms.push(profiled(inspector, async || inspector.run_reference().await).await?);
    }
    Ok(rounds_ms)
}

/// `stow-admin traffic-cost cpu` — check the sampler, measure the
/// reference and every lane, emit the report, and exit nonzero on a
/// lane over budget.
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

    let rounds_before = measure_reference(&inspector).await?;
    let mut measured = Vec::with_capacity(lanes.len());
    for lane in &lanes {
        measured.push(measure_lane(lane, edge, &inspector, args).await?);
    }
    let rounds_after = measure_reference(&inspector).await?;
    let reference = reference_cpu(rounds_before, rounds_after)?;
    let rows = measured
        .into_iter()
        .map(|lane| lane.gate(reference.cpu_ms))
        .collect();
    let report = WorkerCpuReport {
        sampling_interval_us: SAMPLING_INTERVAL_US,
        idle_window_ms: IDLE_WINDOW.as_millis() as u64,
        idle_cpu_ms,
        reference,
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
    let rounds = |rounds: &[f64]| {
        rounds
            .iter()
            .map(|ms| format!("{ms:.2}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let mut table = Table::new(&[
        "lane",
        "cpu ms/event",
        "rounds",
        "× reference",
        "budget × reference",
        "",
    ]);
    for row in &report.rows {
        table.push([
            row.lane.clone(),
            format!("{:.2}", row.cpu_ms),
            rounds(&row.rounds_cpu_ms),
            format!("{:.4}", row.relative_cpu),
            format!("{:.4}", row.budget_relative_cpu),
            if row.over_budget { "OVER" } else { "" }.to_owned(),
        ]);
    }
    let _ = writeln!(
        out,
        "Worker CPU per event (V8 profiler, {} µs sampling; idle window {} ms collected {:.2} ms):",
        report.sampling_interval_us, report.idle_window_ms, report.idle_cpu_ms
    );
    let _ = writeln!(
        out,
        "reference workload {:.2} ms (before the lanes {}; after {})",
        report.reference.cpu_ms,
        rounds(&report.reference.rounds_before),
        rounds(&report.reference.rounds_after)
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
    use stow_types::do_budgets::WORKER_CPU_BUDGETS;

    use super::{
        CpuProfile, LaneCpu, REFERENCE_DRIFT_LIMIT, edge_context, profile_cpu_ms, reference_cpu,
        track_context,
    };

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    /// The reference is the smallest round of either set, and a lane is
    /// judged on its smallest round over it: the same code on a runner
    /// twice as slow gives the same verdict.
    #[test]
    fn a_lane_is_gated_relative_to_the_reference() {
        let budget = &WORKER_CPU_BUDGETS[0];
        let verdict = |speed: f64| {
            let reference = reference_cpu(
                vec![42.0 * speed, 40.0 * speed, 41.0 * speed],
                vec![40.5 * speed, 43.0 * speed, 40.2 * speed],
            )
            .expect("reference");
            assert!(close(reference.cpu_ms, 40.0 * speed));
            let lane = LaneCpu {
                budget,
                events_per_round: 20,
                rounds_cpu_ms: vec![
                    budget.relative_cpu * 40.0 * speed * 1.1,
                    budget.relative_cpu * 40.0 * speed * 0.9,
                ],
            };
            let row = lane.gate(reference.cpu_ms);
            assert!(close(row.relative_cpu, budget.relative_cpu * 0.9));
            assert!(close(row.budget_ms, budget.relative_cpu * 40.0 * speed));
            row.over_budget
        };
        assert!(!verdict(1.0));
        assert!(!verdict(2.0));
    }

    /// A reference that moved between the two sets, or a round too
    /// small to resolve, is refused rather than used.
    #[test]
    fn an_unusable_reference_fails_the_pass() {
        let moved = 40.0 * REFERENCE_DRIFT_LIMIT * 1.01;
        assert!(reference_cpu(vec![40.0; 3], vec![moved; 3]).is_err());
        assert!(reference_cpu(vec![moved; 3], vec![40.0; 3]).is_err());
        assert!(reference_cpu(vec![40.0, 9.9, 40.0], vec![40.0; 3]).is_err());
        assert!(reference_cpu(vec![40.0; 3], vec![40.0 * REFERENCE_DRIFT_LIMIT; 3]).is_ok());
    }

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

    /// The reference evaluates in the one live worker context the
    /// inspector reported; none, or more than one, is refused.
    #[test]
    fn the_reference_runs_in_the_one_worker_context() {
        let created = |id: u64, name: &str| {
            serde_json::json!({
                "method": "Runtime.executionContextCreated",
                "params": {"context": {"id": id, "origin": "", "name": name, "uniqueId": "u"}},
            })
        };
        let mut contexts = Vec::new();
        for event in [
            created(1, "Worker"),
            serde_json::json!({"method": "Runtime.executionContextsCleared"}),
            created(2, "Compiler"),
            created(3, "Worker"),
            serde_json::json!({
                "method": "Runtime.executionContextDestroyed",
                "params": {"executionContextId": 2},
            }),
            serde_json::json!({"method": "Runtime.consoleAPICalled", "params": {}}),
        ] {
            track_context(&mut contexts, &event).expect("event");
        }
        assert_eq!(edge_context(&contexts).expect("context"), 3);

        track_context(&mut contexts, &created(4, "Worker")).expect("event");
        assert!(edge_context(&contexts).is_err());
        assert!(edge_context(&[]).is_err());
        let malformed = serde_json::json!({
            "method": "Runtime.executionContextCreated",
            "params": {"context": {"name": "Worker"}},
        });
        assert!(track_context(&mut contexts, &malformed).is_err());
    }
}
