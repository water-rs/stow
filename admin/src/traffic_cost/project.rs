//! `stow-admin traffic-cost project` — the Traffic cost test's verdict
//! over what the run measured (stow#452, stow#772).
//!
//! It reads the scheduler budget reports at both fixture sizes, the
//! report re-measured after the peak drive, and the Worker CPU report,
//! and fails on:
//!
//! - any drive over its row budget in any report (statements, rows read,
//!   rows written — `DO_BUDGETS`);
//! - a drive whose rows read or written grow with the stored bulk: the
//!   large fixture's count more than 10% plus 50 rows over the small
//!   one's;
//! - a product whose projected monthly usage exceeds half its included
//!   allowance, projected from the small report and from the post-load
//!   report;
//! - a peak second whose serialized Durable Object wall exceeds half a
//!   second.
//!
//! The projection multiplies the launch model's per-event monthly counts
//! by the per-event costs measured in the same run. Nothing it reads is a
//! checked-in constant: the reports' `*_budget` columns carry the budget
//! each row was measured against, Worker CPU per event is the profiler's
//! measurement (`cpu.rs`), and the allowances come from `watchdog`'s
//! single allowance table.
//!
//! The Durable-Object numbers decompose per event kind rather than per
//! route: the alarm lane is priced as `alarm pass (idle)` invocations
//! plus one claim's marginal cost per dispatched build — the difference
//! between the hot and idle pass rows, spread over the claims the run
//! actually made (`report.claimed_tasks`, never a checked-in slots
//! assumption). A report whose pass claimed nothing while the model
//! projects builds is refused rather than priced at zero.
//!
//! Subrequests, worker-side D1 and R2 ops carry per-event constants the
//! run does not measure; they print as diagnostics and never gate. An
//! event whose Worker CPU no lane can measure is named in the output
//! with the reason, so the gap stays visible.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use clap::Args;
use stow_types::api::SchedulerBudgetReport;
use stow_types::launch_model::{EventKind, LaunchModel};
use stow_types::stow_error;

use stow_types::do_budgets::WORKER_CPU_BUDGETS;

use super::cpu::WorkerCpuReport;
use crate::render::{Output, Table, emit};
use crate::watchdog::{
    D1_ROWS_READ_MONTHLY, D1_ROWS_WRITTEN_MONTHLY, DO_DURATION_GB_S_MONTHLY, DO_REQUESTS_MONTHLY,
    DO_ROWS_READ_MONTHLY, DO_ROWS_WRITTEN_MONTHLY, WORKER_CPU_MS_MONTHLY, WORKER_REQUESTS_MONTHLY,
};

/// The verdict — `stow-admin traffic-cost project`.
#[derive(Debug, Args)]
pub struct ProjectArgs {
    /// The scheduler budget report on the small fixture (100k rows).
    #[arg(long)]
    pub small: PathBuf,
    /// The scheduler budget report on the large fixture (1M rows), same
    /// shape — the growth check's other side.
    #[arg(long)]
    pub large: PathBuf,
    /// The scheduler budget report re-measured after the peak drive.
    #[arg(long)]
    pub after: PathBuf,
    /// The Worker CPU report `traffic-cost cpu` wrote.
    #[arg(long)]
    pub cpu: PathBuf,
    /// The checked-in launch model `launch-model.toml`.
    #[arg(long, default_value = "launch-model.toml")]
    pub model: PathBuf,
}

/// The gate fires when a product's projected monthly usage exceeds this
/// fraction of its included allowance — stow#452 fixes half.
const ALLOWANCE_FRACTION: f64 = 0.5;

/// GB-s each serialized DO wall second is priced at. Cloudflare's
/// billing rule is fixed — 128 MB of memory per Durable Object
/// instance, so 0.125 GB-s per wall second — and 0.25 deliberately
/// over-reads it by 2×, so the projection errs on the bill's side.
const DO_DURATION_GB_PER_WALL_S: f64 = 0.25;

/// The issue's peak requirement: a peak-second's serialized Durable
/// Object wall must stay under half a second.
const PEAK_SERIALIZED_S_PER_S: f64 = 0.5;

/// Tasks the enqueue drives' `submit_batch` carries — the denominator
/// a single-task insert prices against.
const SUBMIT_BATCH_TASKS: f64 = 3.0;

/// The growth rule: a drive grows with the stored bulk when its count
/// on the large fixture exceeds the small one's by more than this
/// fraction …
const GROWTH_FRACTION: f64 = 0.1;

/// … plus this many rows.
const GROWTH_SLACK_ROWS: f64 = 50.0;

/// The measured cost of one scheduler drive call, looked up in the
/// harness report by row name.
#[derive(Debug, Clone, Copy, Default)]
struct DriveCost {
    /// Σ `rowsRead`.
    rows_read: f64,
    /// Σ `rowsWritten`.
    rows_written: f64,
    /// Serialized wall milliseconds.
    wall_ms: f64,
    /// Σ D1 `meta.rowsRead` on the counted catalog backend — the
    /// per-page coverage lookups a claim pays.
    d1_rows_read: f64,
    /// Σ D1 `meta.rowsWritten` on the same backend.
    d1_rows_written: f64,
}

/// Where an event's Worker CPU comes from.
#[derive(Debug, Clone, Copy)]
enum CpuPricing {
    /// (lane, events of that lane per event) — measured by the CPU pass.
    Lanes(&'static [(&'static str, f64)]),
    /// The event is no Worker request (it runs inside the Durable
    /// Object), so the Worker bills it no CPU.
    NoWorkerRequest,
    /// A Worker request no lane can drive yet — the reason is printed.
    Unmeasured(&'static str),
}

/// One traffic kind's cost vector. `drives` names the report rows the
/// event invokes; `claims` the dispatches inside the pass lane it
/// causes (only [`EventKind::Build`] — one claim each). The gated
/// fields are structural counts (`do_requests`, `worker_requests`) or
/// measured reads (report rows, Worker CPU lanes); the `subrequests`/
/// `d1_rows_*`/`r2_ops` constants describe the handler's shape and print
/// as diagnostics only — nothing measures them, so they never gate.
#[derive(Debug, Clone, Copy)]
struct EventCost {
    /// The traffic kind this prices.
    kind: EventKind,
    /// The route label the report table prints.
    route: &'static str,
    /// (report row, calls per event).
    drives: &'static [(&'static str, f64)],
    /// Billed DO invocations per event — Cloudflare's request billing
    /// counts alarm invocations too, so the alarm lane carries 1.0.
    do_requests: f64,
    /// Dispatches the event causes inside a scheduler pass.
    claims: f64,
    /// Billed worker requests per event (index pulls are two).
    worker_requests: f64,
    /// Where the event's Worker CPU comes from.
    cpu: CpuPricing,
    /// Subrequests per event — diagnostic only.
    subrequests: f64,
    /// Worker-side D1 `rows_read` per event — diagnostic only; the
    /// measured D1 line is the claim lane's counted coverage reads.
    d1_rows_read: f64,
    /// Worker-side D1 `rows_written` per event — diagnostic only.
    d1_rows_written: f64,
    /// R2 ops per event — diagnostic only (zero today).
    r2_ops: f64,
}

/// Per-event costs, from the route handlers in `edge/src/api.rs`. The
/// DO drives are billed per call from the measured row; D1 and subrequest
/// counts are the handler's statement/lookup shapes (an admission's
/// miss drain is its 64-row batch; a callback's mirror write is the
/// ~15 artifact rows a build reports).
const EVENT_COSTS: &[EventCost] = &[
    EventCost {
        kind: EventKind::CliBytePathFetch,
        route: "GET /api/v1/bundles/{rustc_version}/{digest}",
        drives: &[],
        do_requests: 0.0,
        claims: 0.0,
        worker_requests: 1.0,
        cpu: CpuPricing::Lanes(&[("bundle-fetch", 1.0)]),
        subrequests: 1.0,
        d1_rows_read: 0.0,
        d1_rows_written: 0.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::IndexPull,
        route: "GET /api/v1/index/* (pointer + slice)",
        drives: &[],
        do_requests: 0.0,
        claims: 0.0,
        worker_requests: 2.0,
        cpu: CpuPricing::Lanes(&[("index-pull", 1.0)]),
        subrequests: 2.0,
        d1_rows_read: 0.0,
        d1_rows_written: 0.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::Admission,
        route: "POST /api/v1/admissions (+miss drain)",
        // The drain is one `send_enqueue` DO call per request; the
        // insert it carries scales with misses, so its rows are
        // priced on `EventKind::MissNode` where the model counts them.
        drives: &[],
        do_requests: 1.0,
        claims: 0.0,
        worker_requests: 1.0,
        cpu: CpuPricing::Lanes(&[("admission", 1.0)]),
        subrequests: 2.0,
        d1_rows_read: 64.0,
        d1_rows_written: 3.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::EnqueueRedemption,
        route: "POST /api/v1/enqueue",
        // A redemption forwards a single request: its insert is one
        // third of the accept drive's three-task batch, priced on the
        // accept path — an accepted redemption pays the insert.
        drives: &[
            ("GET /status", 1.0),
            ("POST /enqueue (untrusted accept)", 1.0 / SUBMIT_BATCH_TASKS),
        ],
        do_requests: 2.0,
        claims: 0.0,
        worker_requests: 1.0,
        cpu: CpuPricing::Lanes(&[("enqueue-redeem", 1.0)]),
        subrequests: 0.0,
        d1_rows_read: 1.0,
        d1_rows_written: 5.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::HumanRequest,
        route: "POST /api/v1/requests",
        // The request's whole DO lifecycle per event: the admit call
        // (dedup + budget probe + resolve dispatch), the run's two
        // webhook-driven updates, and the outcome post whose
        // `enqueue_trusted` writes the task rows.
        drives: &[
            ("POST /requests", 1.0),
            ("POST /requests/{id}/run-update (in_progress)", 1.0),
            ("POST /requests/{id}/outcome", 1.0),
            ("POST /requests/{id}/run-update (completed)", 1.0),
        ],
        do_requests: 1.0,
        claims: 0.0,
        worker_requests: 1.0,
        cpu: CpuPricing::Unmeasured(
            "POST /api/v1/requests verifies Turnstile at challenges.cloudflare.com and reads the \
             stable channel manifest from static.rust-lang.org — no lane drives it off the network",
        ),
        subrequests: 3.0,
        d1_rows_read: 0.0,
        d1_rows_written: 0.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::RequestStatusRead,
        route: "GET /api/v1/requests/{id}",
        // One `crate_request_status` read: the row plus the stored-roots
        // re-probe against the live queue.
        drives: &[("GET /requests/{id}", 1.0)],
        do_requests: 1.0,
        claims: 0.0,
        worker_requests: 1.0,
        cpu: CpuPricing::Lanes(&[("status-read", 1.0)]),
        subrequests: 0.0,
        d1_rows_read: 0.0,
        d1_rows_written: 0.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::SiteView,
        route: "GET /|install|requests/{id} (site)",
        drives: &[],
        do_requests: 0.0,
        claims: 0.0,
        worker_requests: 1.0,
        cpu: CpuPricing::Lanes(&[("site", 1.0)]),
        subrequests: 0.0,
        d1_rows_read: 0.0,
        d1_rows_written: 0.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::StatsView,
        route: "GET /stats (+/api/v1/stats)",
        drives: &[],
        do_requests: 0.0,
        claims: 0.0,
        worker_requests: 1.0,
        cpu: CpuPricing::Lanes(&[("stats", 1.0)]),
        subrequests: 0.0,
        d1_rows_read: 30.0,
        d1_rows_written: 1.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::MissNode,
        route: "miss nodes (drained insert)",
        // Every miss node is one task in an admission's drain batch —
        // one third of the accept drive's three-task enqueue, priced
        // on the accept path so a growing miss volume grows the bill.
        drives: &[("POST /enqueue (untrusted accept)", 1.0 / SUBMIT_BATCH_TASKS)],
        do_requests: 0.0,
        claims: 0.0,
        worker_requests: 0.0,
        cpu: CpuPricing::NoWorkerRequest,
        subrequests: 0.0,
        d1_rows_read: 0.0,
        d1_rows_written: 0.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::AdminOperation,
        route: "stow-admin operations",
        drives: &[("GET /admin/status", 1.0)],
        do_requests: 1.0,
        claims: 0.0,
        worker_requests: 1.0,
        cpu: CpuPricing::Lanes(&[("admin-status", 1.0)]),
        subrequests: 0.0,
        d1_rows_read: 0.0,
        d1_rows_written: 0.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::IndexPublish,
        route: "POST /api/v1/admin/index/published",
        drives: &[("POST /index/published (full)", 1.0)],
        do_requests: 1.0,
        claims: 0.0,
        worker_requests: 1.0,
        cpu: CpuPricing::Unmeasured("no lane drives POST /api/v1/admin/index/published"),
        subrequests: 2.0,
        d1_rows_read: 0.0,
        d1_rows_written: 0.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::HumanTask,
        route: "human-lane tasks (inside a claim)",
        drives: &[],
        do_requests: 0.0,
        claims: 0.0,
        worker_requests: 0.0,
        cpu: CpuPricing::NoWorkerRequest,
        subrequests: 0.0,
        d1_rows_read: 0.0,
        d1_rows_written: 0.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::Build,
        route: "dispatched builds (claim marginal)",
        drives: &[],
        do_requests: 0.0,
        claims: 1.0,
        worker_requests: 0.0,
        cpu: CpuPricing::NoWorkerRequest,
        subrequests: 0.0,
        d1_rows_read: 0.0,
        d1_rows_written: 0.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::BuildCallback,
        route: "POST /api/v1/github/workflow-run",
        drives: &[("POST /tasks/complete-run", 1.0)],
        do_requests: 1.0,
        claims: 0.0,
        worker_requests: 1.0,
        cpu: CpuPricing::Lanes(&[("workflow-callback", 1.0)]),
        subrequests: 4.0,
        d1_rows_read: 2.0,
        d1_rows_written: 15.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::AlarmPass,
        route: "scheduler alarm pass",
        drives: &[("alarm pass (idle)", 1.0)],
        // Cloudflare's DO request billing explicitly includes alarm
        // invocations (HTTP requests, RPC sessions, WebSocket messages,
        // alarm invocations) — the pass is a billed request.
        do_requests: 1.0,
        claims: 0.0,
        worker_requests: 0.0,
        cpu: CpuPricing::NoWorkerRequest,
        subrequests: 0.0,
        d1_rows_read: 0.0,
        d1_rows_written: 0.0,
        r2_ops: 0.0,
    },
];

/// One product dimension's monthly projection against its allowance.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UsageLine {
    /// The Cloudflare product: `workers`, `durable_objects`, `d1`.
    pub product: &'static str,
    /// The billed dimension (e.g. `requests`, `rows_read`,
    /// `duration_gb_s`).
    pub dimension: &'static str,
    /// Projected monthly usage at launch traffic.
    pub projected: f64,
    /// The included monthly allowance.
    pub allowance: f64,
}

/// One route's contribution for the report's top-N table.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RouteShare {
    /// The event's route label.
    pub route: &'static str,
    /// Projected monthly events.
    pub monthly_events: f64,
    /// The dimension this route is heaviest in.
    pub dimension: &'static str,
    /// Its projected share of that dimension's allowance.
    pub share: f64,
}

/// A Worker route whose CPU no lane measures, with its volume.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UnmeasuredCpu {
    /// The event's route label.
    pub route: &'static str,
    /// Projected monthly events.
    pub monthly_events: f64,
    /// Why no lane drives it.
    pub reason: &'static str,
}

/// A projected breach — the gate fails on any of these.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Breach {
    /// Product whose bound tripped.
    pub product: &'static str,
    /// The over-allowance dimension.
    pub dimension: &'static str,
    /// Projected monthly usage.
    pub projected: f64,
    /// The gate bound — `allowance × ALLOWANCE_FRACTION`.
    pub bound: f64,
    /// The route driving the projection.
    pub top_route: &'static str,
}

/// One Worker route's CPU in the monthly projection — the measured
/// figure and the budget, each against the Worker CPU allowance, so a
/// budget reads as the share of the allowance it lets the route spend.
#[derive(Debug, serde::Serialize)]
pub struct RouteCpu {
    /// The route label.
    pub route: &'static str,
    /// Projected monthly events.
    pub monthly_events: f64,
    /// Measured CPU milliseconds per event (Σ over its lanes).
    pub measured_ms_per_event: f64,
    /// Budgeted CPU milliseconds per event (Σ over its lanes'
    /// `WORKER_CPU_BUDGETS` rows).
    pub budget_ms_per_event: f64,
    /// Projected monthly CPU milliseconds at the measured figure.
    pub projected_ms: f64,
    /// `projected_ms` over the monthly Worker CPU allowance.
    pub share: f64,
    /// The same share were the route to spend its whole budget.
    pub share_at_budget: f64,
}

/// One report's projection: every usage line, the peak check, the
/// top-N routes and any breaches.
#[derive(Debug, serde::Serialize)]
pub struct GateEvaluation {
    /// Per-product projected usage lines.
    pub usage: Vec<UsageLine>,
    /// Peak-hour serialized DO wall in seconds per second.
    pub peak_serialized_s_per_s: f64,
    /// Its bound (0.5).
    pub peak_bound_s_per_s: f64,
    /// Heaviest routes by allowance share.
    pub top_routes: Vec<RouteShare>,
    /// Diagnostic-only dimensions (subrequests, worker-side D1, R2 ops).
    pub diagnostics: Vec<UsageLine>,
    /// Every measured Worker route's projected monthly CPU.
    pub cpu_routes: Vec<RouteCpu>,
    /// Projected monthly Worker CPU were every route to spend its whole
    /// budget — gated against the same bound as the measured line.
    pub worker_cpu_ms_at_budget: f64,
    /// Worker routes whose CPU the projection does not carry.
    pub unmeasured_cpu: Vec<UnmeasuredCpu>,
    /// Empty on a pass.
    pub breaches: Vec<Breach>,
}

impl GateEvaluation {
    /// Whether the projection stays inside every bound.
    const fn passes(&self) -> bool {
        self.breaches.is_empty()
    }
}

/// Σ over every event kind: projected monthly usage per product
/// dimension, the DO wall seconds that price duration, and the
/// peak-hour serialized wall — plus the per-route shares for the
/// report's top-N table and the unmeasured diagnostics.
#[derive(Debug, Default)]
struct Projection {
    /// Projected monthly worker requests.
    worker_requests: f64,
    /// Projected monthly Worker CPU milliseconds — measured per lane.
    worker_cpu_ms: f64,
    /// Projected monthly DO invocations.
    do_requests: f64,
    /// Projected monthly DO rows read.
    do_rows_read: f64,
    /// Projected monthly DO rows written.
    do_rows_written: f64,
    /// Projected monthly DO wall seconds — duration is billed on this.
    do_wall_s: f64,
    /// Projected monthly D1 rows read — the measured side only: the
    /// claim lane's counted catalog-coverage lookups.
    d1_read: f64,
    /// Projected monthly D1 rows written — measured, as above.
    d1_written: f64,
    /// Projected monthly subrequests — diagnostic, not gated.
    diag_subrequests: f64,
    /// Projected monthly worker-side D1 reads — diagnostic, not gated.
    diag_d1_read: f64,
    /// Projected monthly worker-side D1 writes — diagnostic, not gated.
    diag_d1_written: f64,
    /// Projected monthly R2 ops — diagnostic, not gated.
    diag_r2_ops: f64,
    /// Serialized scheduler wall milliseconds per second at peak —
    /// the stow#452 serialization bound's numerator.
    peak_serialized_ms: f64,
    /// One share entry per event kind, for the top-N table.
    per_route: Vec<RouteShare>,
    /// Per-route Worker CPU, measured and at budget.
    cpu_routes: Vec<RouteCpu>,
    /// Projected monthly Worker CPU milliseconds at budget.
    worker_cpu_ms_at_budget: f64,
    /// Worker routes the CPU line leaves out.
    unmeasured_cpu: Vec<UnmeasuredCpu>,
}

/// A lane's CPU budget per event, from `WORKER_CPU_BUDGETS`.
fn lane_budget_ms(lane: &str) -> Result<f64, String> {
    WORKER_CPU_BUDGETS
        .iter()
        .find(|budget| budget.lane == lane)
        .map(|budget| budget.cpu_ms)
        .ok_or_else(|| format!("lane `{lane}` has no WORKER_CPU_BUDGETS row"))
}

/// Fold one event kind's monthly and peak counts into the projection.
fn fold_kind(
    model: &LaunchModel,
    cost: &EventCost,
    drive: &dyn Fn(&'static str) -> Result<DriveCost, String>,
    claim_marginal: &DriveCost,
    cpu: &WorkerCpuReport,
    projection: &mut Projection,
) -> Result<(), String> {
    let monthly = model.monthly_events(cost.kind);
    let peak_per_s = model.peak_events_per_second(cost.kind);
    projection.worker_requests = monthly.mul_add(cost.worker_requests, projection.worker_requests);
    projection.do_requests = monthly.mul_add(cost.do_requests, projection.do_requests);
    projection.diag_subrequests = monthly.mul_add(cost.subrequests, projection.diag_subrequests);
    projection.diag_d1_read = monthly.mul_add(cost.d1_rows_read, projection.diag_d1_read);
    projection.diag_d1_written = monthly.mul_add(cost.d1_rows_written, projection.diag_d1_written);
    projection.diag_r2_ops = monthly.mul_add(cost.r2_ops, projection.diag_r2_ops);
    let mut kind_cpu_ms = 0.0;
    match cost.cpu {
        CpuPricing::Lanes(lanes) => {
            let mut budget_ms = 0.0;
            for (lane, events) in lanes {
                kind_cpu_ms = events.mul_add(cpu.lane_cpu_ms(lane)?, kind_cpu_ms);
                budget_ms = events.mul_add(lane_budget_ms(lane)?, budget_ms);
            }
            projection.worker_cpu_ms_at_budget =
                monthly.mul_add(budget_ms, projection.worker_cpu_ms_at_budget);
            projection.cpu_routes.push(RouteCpu {
                route: cost.route,
                monthly_events: monthly,
                measured_ms_per_event: kind_cpu_ms,
                budget_ms_per_event: budget_ms,
                projected_ms: monthly * kind_cpu_ms,
                share: monthly * kind_cpu_ms / WORKER_CPU_MS_MONTHLY,
                share_at_budget: monthly * budget_ms / WORKER_CPU_MS_MONTHLY,
            });
        }
        CpuPricing::NoWorkerRequest => {
            if cost.worker_requests > 0.0 {
                return Err(format!(
                    "`{}` is a Worker request priced as none — its CPU needs a lane",
                    cost.route
                ));
            }
        }
        CpuPricing::Unmeasured(reason) => projection.unmeasured_cpu.push(UnmeasuredCpu {
            route: cost.route,
            monthly_events: monthly,
            reason,
        }),
    }
    projection.worker_cpu_ms = monthly.mul_add(kind_cpu_ms, projection.worker_cpu_ms);
    let mut kind_read = 0.0;
    let mut kind_written = 0.0;
    let mut kind_wall_ms = 0.0;
    let mut kind_d1_read = 0.0;
    let mut kind_d1_written = 0.0;
    for (name, calls) in cost.drives {
        let row = drive(name)?;
        kind_read = calls.mul_add(row.rows_read, kind_read);
        kind_written = calls.mul_add(row.rows_written, kind_written);
        kind_wall_ms = calls.mul_add(row.wall_ms, kind_wall_ms);
        kind_d1_read = calls.mul_add(row.d1_rows_read, kind_d1_read);
        kind_d1_written = calls.mul_add(row.d1_rows_written, kind_d1_written);
    }
    kind_read = cost.claims.mul_add(claim_marginal.rows_read, kind_read);
    kind_written = cost
        .claims
        .mul_add(claim_marginal.rows_written, kind_written);
    kind_wall_ms = cost.claims.mul_add(claim_marginal.wall_ms, kind_wall_ms);
    kind_d1_read = cost
        .claims
        .mul_add(claim_marginal.d1_rows_read, kind_d1_read);
    kind_d1_written = cost
        .claims
        .mul_add(claim_marginal.d1_rows_written, kind_d1_written);
    projection.do_rows_read = monthly.mul_add(kind_read, projection.do_rows_read);
    projection.do_rows_written = monthly.mul_add(kind_written, projection.do_rows_written);
    projection.do_wall_s += monthly * kind_wall_ms / 1000.0;
    projection.d1_read = monthly.mul_add(kind_d1_read, projection.d1_read);
    projection.d1_written = monthly.mul_add(kind_d1_written, projection.d1_written);
    projection.peak_serialized_ms = peak_per_s.mul_add(kind_wall_ms, projection.peak_serialized_ms);
    // The route's heaviest dimension decides its allowance share — the
    // number the top-N table ranks.
    let shares = [
        (
            "do_requests",
            monthly * cost.do_requests / DO_REQUESTS_MONTHLY,
        ),
        (
            "do_duration_gb_s",
            monthly * (kind_wall_ms / 1000.0) * DO_DURATION_GB_PER_WALL_S
                / DO_DURATION_GB_S_MONTHLY,
        ),
        ("do_rows_read", monthly * kind_read / DO_ROWS_READ_MONTHLY),
        (
            "do_rows_written",
            monthly * kind_written / DO_ROWS_WRITTEN_MONTHLY,
        ),
        (
            "worker_requests",
            monthly * cost.worker_requests / WORKER_REQUESTS_MONTHLY,
        ),
        (
            "worker_cpu_ms",
            monthly * kind_cpu_ms / WORKER_CPU_MS_MONTHLY,
        ),
        (
            "d1_rows_read",
            monthly * kind_d1_read / D1_ROWS_READ_MONTHLY,
        ),
        (
            "d1_rows_written",
            monthly * kind_d1_written / D1_ROWS_WRITTEN_MONTHLY,
        ),
    ];
    let (dimension, share) = shares
        .iter()
        .copied()
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .unwrap_or(("none", 0.0));
    projection.per_route.push(RouteShare {
        route: cost.route,
        monthly_events: monthly,
        dimension,
        share,
    });
    Ok(())
}

/// The product/dimension rows the gate bounds — every line a measured
/// quantity or a structural count.
fn usage_lines(projection: &Projection) -> Vec<UsageLine> {
    vec![
        UsageLine {
            product: "workers",
            dimension: "requests",
            projected: projection.worker_requests,
            allowance: WORKER_REQUESTS_MONTHLY,
        },
        UsageLine {
            product: "workers",
            dimension: "cpu_ms",
            projected: projection.worker_cpu_ms,
            allowance: WORKER_CPU_MS_MONTHLY,
        },
        UsageLine {
            product: "durable_objects",
            dimension: "requests",
            projected: projection.do_requests,
            allowance: DO_REQUESTS_MONTHLY,
        },
        UsageLine {
            product: "durable_objects",
            dimension: "rows_read",
            projected: projection.do_rows_read,
            allowance: DO_ROWS_READ_MONTHLY,
        },
        UsageLine {
            product: "durable_objects",
            dimension: "rows_written",
            projected: projection.do_rows_written,
            allowance: DO_ROWS_WRITTEN_MONTHLY,
        },
        UsageLine {
            product: "durable_objects",
            dimension: "duration_gb_s",
            projected: projection.do_wall_s * DO_DURATION_GB_PER_WALL_S,
            allowance: DO_DURATION_GB_S_MONTHLY,
        },
        UsageLine {
            product: "d1",
            dimension: "rows_read",
            projected: projection.d1_read,
            allowance: D1_ROWS_READ_MONTHLY,
        },
        UsageLine {
            product: "d1",
            dimension: "rows_written",
            projected: projection.d1_written,
            allowance: D1_ROWS_WRITTEN_MONTHLY,
        },
    ]
}

/// Ungated dimensions printed for context only — per-event constants
/// nothing measures, kept visible so a growing one is seen.
fn diagnostic_lines(projection: &Projection) -> Vec<UsageLine> {
    vec![
        UsageLine {
            product: "workers",
            dimension: "subrequests",
            projected: projection.diag_subrequests,
            allowance: f64::INFINITY,
        },
        UsageLine {
            product: "d1 (worker-side, unmeasured)",
            dimension: "rows_read",
            projected: projection.diag_d1_read,
            allowance: f64::INFINITY,
        },
        UsageLine {
            product: "d1 (worker-side, unmeasured)",
            dimension: "rows_written",
            projected: projection.diag_d1_written,
            allowance: f64::INFINITY,
        },
        UsageLine {
            product: "r2",
            dimension: "ops",
            projected: projection.diag_r2_ops,
            allowance: f64::INFINITY,
        },
    ]
}

/// Project the launch model's monthly events against one report's
/// measured rows, the measured Worker CPU and the watchdog allowance
/// table.
#[expect(
    clippy::cast_precision_loss,
    reason = "measured counters fit f64 exactly past any launch traffic"
)]
fn evaluate(
    model: &LaunchModel,
    report: &SchedulerBudgetReport,
    cpu: &WorkerCpuReport,
) -> Result<GateEvaluation, String> {
    let measured: BTreeMap<&str, DriveCost> = report
        .rows
        .iter()
        .map(|row| {
            (
                row.name.as_str(),
                DriveCost {
                    rows_read: row.rows_read as f64,
                    rows_written: row.rows_written as f64,
                    wall_ms: row.wall_ms as f64,
                    d1_rows_read: row.d1_rows_read as f64,
                    d1_rows_written: row.d1_rows_written as f64,
                },
            )
        })
        .collect();
    let drive = |name: &'static str| -> Result<DriveCost, String> {
        measured
            .get(name)
            .copied()
            .ok_or_else(|| format!("budget report carries no row for `{name}`"))
    };
    let hot = drive("alarm pass")?;
    let idle = drive("alarm pass (idle)")?;
    // A report whose pass claimed nothing measures no claim price —
    // with nonzero build traffic the projection would silently
    // underprice the Durable Object, so the gate refuses the report
    // rather than project zero (a zero-claims pass means the probe ran
    // under a dispatch cap the fixture's in-flight rows already fill).
    let builds = model.monthly_events(EventKind::Build);
    if report.claimed_tasks == 0 && builds > 0.0 {
        return Err(format!(
            "budget report claims 0 tasks (dispatch_limit {}) while the model projects \
             {builds:.0} builds/mo — a pass that cannot claim measured no claim price",
            report.dispatch_limit
        ));
    }
    // The claims inside a hot pass are what the hot row buys over the
    // idle floor, spread over the claims the run actually made.
    let claimed = report.claimed_tasks.max(1) as f64;
    let claim_marginal = DriveCost {
        rows_read: (hot.rows_read - idle.rows_read).max(0.0) / claimed,
        rows_written: (hot.rows_written - idle.rows_written).max(0.0) / claimed,
        wall_ms: (hot.wall_ms - idle.wall_ms).max(0.0) / claimed,
        d1_rows_read: (hot.d1_rows_read - idle.d1_rows_read).max(0.0) / claimed,
        d1_rows_written: (hot.d1_rows_written - idle.d1_rows_written).max(0.0) / claimed,
    };

    let mut projection = Projection::default();
    for cost in EVENT_COSTS {
        fold_kind(model, cost, &drive, &claim_marginal, cpu, &mut projection)?;
    }

    let usage = usage_lines(&projection);
    let diagnostics = diagnostic_lines(&projection);

    let mut top_routes = projection.per_route;
    top_routes.sort_by(|a, b| b.share.total_cmp(&a.share));
    top_routes.truncate(5);

    let mut breaches = Vec::new();
    for line in &usage {
        let bound = line.allowance * ALLOWANCE_FRACTION;
        if line.projected > bound {
            // `RouteShare::dimension` keys the share dimension by
            // product prefix — `do_`, `d1_`, `worker_`.
            let prefix = match line.product {
                "workers" => "worker",
                "durable_objects" => "do",
                other => other,
            };
            let share_key = format!("{prefix}_{}", line.dimension);
            let top_route = top_routes
                .iter()
                .find(|r| r.dimension == share_key)
                .map_or("n/a", |r| r.route);
            breaches.push(Breach {
                product: line.product,
                dimension: line.dimension,
                projected: line.projected,
                bound,
                top_route,
            });
        }
    }
    // The budgets themselves must fit the allowance: a route may spend
    // its whole budget and the month must still stay inside the bound,
    // so a budget raised past what the allowance carries fails here
    // whatever the run measured.
    let cpu_bound = WORKER_CPU_MS_MONTHLY * ALLOWANCE_FRACTION;
    if projection.worker_cpu_ms_at_budget > cpu_bound {
        breaches.push(Breach {
            product: "workers",
            dimension: "cpu_ms_at_budget",
            projected: projection.worker_cpu_ms_at_budget,
            bound: cpu_bound,
            top_route: projection
                .cpu_routes
                .iter()
                .max_by(|a, b| a.share_at_budget.total_cmp(&b.share_at_budget))
                .map_or("n/a", |route| route.route),
        });
    }
    let peak_s = projection.peak_serialized_ms / 1000.0;
    if peak_s > PEAK_SERIALIZED_S_PER_S {
        breaches.push(Breach {
            product: "durable_objects",
            dimension: "peak_serialized_s_per_s",
            projected: peak_s,
            bound: PEAK_SERIALIZED_S_PER_S,
            top_route: "scheduler alarm pass",
        });
    }
    Ok(GateEvaluation {
        usage,
        peak_serialized_s_per_s: peak_s,
        peak_bound_s_per_s: PEAK_SERIALIZED_S_PER_S,
        top_routes,
        diagnostics,
        cpu_routes: projection.cpu_routes,
        worker_cpu_ms_at_budget: projection.worker_cpu_ms_at_budget,
        unmeasured_cpu: projection.unmeasured_cpu,
        breaches,
    })
}

/// One drive's counts on both fixture sizes.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GrowthRow {
    /// The drive.
    pub name: String,
    /// `rowsRead` on the small fixture.
    pub read_small: u64,
    /// `rowsRead` on the large fixture.
    pub read_large: u64,
    /// `rowsWritten` on the small fixture.
    pub written_small: u64,
    /// `rowsWritten` on the large fixture.
    pub written_large: u64,
    /// Whether either count grows with the stored bulk.
    pub grows: bool,
}

/// The growth check: every drive's counts on both fixtures. A drive
/// may legitimately be bounded by a held quantity — lane depth, the
/// 24 h outcome window, in-flight count, the report's own size — and
/// the fixture pins those across sizes, so only the stored bulk grows.
#[expect(clippy::cast_precision_loss, reason = "row counters fit f64 exactly")]
fn growth(
    small: &SchedulerBudgetReport,
    large: &SchedulerBudgetReport,
) -> Result<Vec<GrowthRow>, String> {
    if small.queue_rows >= large.queue_rows {
        return Err(format!(
            "the small report holds {} queue rows and the large one {} — the growth check \
             needs the small fixture first",
            small.queue_rows, large.queue_rows
        ));
    }
    let grows =
        |a: u64, b: u64| b as f64 > (a as f64).mul_add(1.0 + GROWTH_FRACTION, GROWTH_SLACK_ROWS);
    let rows: Vec<GrowthRow> = small
        .rows
        .iter()
        .map(|a| {
            let b = large
                .rows
                .iter()
                .find(|b| b.name == a.name)
                .ok_or_else(|| format!("the large report carries no row for `{}`", a.name))?;
            Ok(GrowthRow {
                name: a.name.clone(),
                read_small: a.rows_read,
                read_large: b.rows_read,
                written_small: a.rows_written,
                written_large: b.rows_written,
                grows: grows(a.rows_read, b.rows_read) || grows(a.rows_written, b.rows_written),
            })
        })
        .collect::<Result<_, String>>()?;
    if let Some(extra) = large
        .rows
        .iter()
        .find(|b| !small.rows.iter().any(|a| a.name == b.name))
    {
        return Err(format!(
            "the small report carries no row for `{}`",
            extra.name
        ));
    }
    Ok(rows)
}

/// A drive over its row budget in one of the reports.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OverBudget {
    /// Which report — `small`, `large` or `after`.
    pub report: &'static str,
    /// Its fixture size.
    pub queue_rows: u64,
    /// The drive.
    pub name: String,
}

/// The whole verdict.
#[derive(Debug, serde::Serialize)]
pub struct Verdict {
    /// Drives over a row budget, in any report.
    pub over_budget: Vec<OverBudget>,
    /// The growth check, row by row.
    pub growth: Vec<GrowthRow>,
    /// The projection from the small report — the clean fixture.
    pub projection: GateEvaluation,
    /// The projection from the post-load report.
    pub projection_after_load: GateEvaluation,
}

impl Verdict {
    /// Every failure, one line each.
    fn failures(&self) -> Vec<String> {
        let mut failures: Vec<String> = self
            .over_budget
            .iter()
            .map(|row| {
                format!(
                    "{} report ({} rows): `{}` over its row budget",
                    row.report, row.queue_rows, row.name
                )
            })
            .collect();
        failures.extend(
            self.growth
                .iter()
                .filter(|row| row.grows)
                .map(|row| format!("`{}` grows with the stored rows", row.name)),
        );
        for (label, evaluation) in [
            ("clean", &self.projection),
            ("post-load", &self.projection_after_load),
        ] {
            failures.extend(evaluation.breaches.iter().map(|breach| {
                format!(
                    "{label} projection: {} {} {:.3e} over bound {:.3e} — driver: {}",
                    breach.product,
                    breach.dimension,
                    breach.projected,
                    breach.bound,
                    breach.top_route
                )
            }));
        }
        failures
    }
}

/// Collect the over-budget rows of one report.
fn over_budget(label: &'static str, report: &SchedulerBudgetReport) -> Vec<OverBudget> {
    report
        .rows
        .iter()
        .filter(|row| row.over_budget)
        .map(|row| OverBudget {
            report: label,
            queue_rows: report.queue_rows,
            name: row.name.clone(),
        })
        .collect()
}

/// Judge every input.
fn judge(
    model: &LaunchModel,
    small: &SchedulerBudgetReport,
    large: &SchedulerBudgetReport,
    after: &SchedulerBudgetReport,
    cpu: &WorkerCpuReport,
) -> Result<Verdict, String> {
    let mut over = over_budget("small", small);
    over.extend(over_budget("large", large));
    over.extend(over_budget("after", after));
    Ok(Verdict {
        over_budget: over,
        growth: growth(small, large)?,
        projection: evaluate(model, small, cpu)?,
        projection_after_load: evaluate(model, after, cpu)?,
    })
}

/// Human rendering of one projection — the per-product table, the peak
/// check, the top-5 routes, the diagnostics and the unmeasured routes.
fn render_evaluation(title: &str, evaluation: &GateEvaluation) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "{title}");
    let mut table = Table::new(&[
        "product",
        "dimension",
        "projected/mo",
        "allowance/mo",
        "bound (50%)",
        "share",
    ]);
    for line in &evaluation.usage {
        table.push([
            line.product.to_owned(),
            line.dimension.to_owned(),
            format!("{:.3e}", line.projected),
            format!("{:.3e}", line.allowance),
            format!("{:.3e}", line.allowance * ALLOWANCE_FRACTION),
            format!("{:.1}%", 100.0 * line.projected / line.allowance),
        ]);
    }
    let _ = writeln!(out, "{}", table.render());
    let _ = writeln!(
        out,
        "\npeak serialized DO wall: {:.3} s/s (bound {:.2} s/s)",
        evaluation.peak_serialized_s_per_s, evaluation.peak_bound_s_per_s
    );
    let mut top = Table::new(&[
        "top routes (share of allowance)",
        "events/mo",
        "dimension",
        "share",
    ]);
    for route in &evaluation.top_routes {
        top.push([
            route.route.to_owned(),
            format!("{:.3e}", route.monthly_events),
            route.dimension.to_owned(),
            format!("{:.2}%", 100.0 * route.share),
        ]);
    }
    let _ = writeln!(out, "\n{}", top.render());
    let mut diag = Table::new(&["diagnostics (unmeasured)", "projected/mo"]);
    for line in &evaluation.diagnostics {
        diag.push([
            format!("{} {}", line.product, line.dimension),
            format!("{:.3e}", line.projected),
        ]);
    }
    let _ = writeln!(out, "\n{}", diag.render());
    let mut cpu = Table::new(&[
        "Worker CPU per route",
        "events/mo",
        "ms/event",
        "budget ms/event",
        "ms/mo",
        "share",
        "share at budget",
    ]);
    for route in &evaluation.cpu_routes {
        cpu.push([
            route.route.to_owned(),
            format!("{:.3e}", route.monthly_events),
            format!("{:.2}", route.measured_ms_per_event),
            format!("{:.2}", route.budget_ms_per_event),
            format!("{:.3e}", route.projected_ms),
            format!("{:.2}%", 100.0 * route.share),
            format!("{:.2}%", 100.0 * route.share_at_budget),
        ]);
    }
    let _ = writeln!(out, "\n{}", cpu.render());
    let _ = writeln!(
        out,
        "Worker CPU at budget: {:.3e} ms/mo, {:.1}% of the allowance (bound {:.0}%)",
        evaluation.worker_cpu_ms_at_budget,
        100.0 * evaluation.worker_cpu_ms_at_budget / WORKER_CPU_MS_MONTHLY,
        100.0 * ALLOWANCE_FRACTION
    );
    if !evaluation.unmeasured_cpu.is_empty() {
        let mut gaps = Table::new(&["Worker CPU not measured", "events/mo", "why"]);
        for gap in &evaluation.unmeasured_cpu {
            gaps.push([
                gap.route.to_owned(),
                format!("{:.3e}", gap.monthly_events),
                gap.reason.to_owned(),
            ]);
        }
        let _ = writeln!(out, "\n{}", gaps.render());
    }
    out
}

/// Human rendering of the verdict.
fn render_verdict(verdict: &Verdict) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let mut table = Table::new(&["drive", "rows_read", "rows_written", ""]);
    for row in &verdict.growth {
        table.push([
            row.name.clone(),
            format!("{}→{}", row.read_small, row.read_large),
            format!("{}→{}", row.written_small, row.written_large),
            if row.grows { "GROWS" } else { "" }.to_owned(),
        ]);
    }
    let _ = writeln!(
        out,
        "growth check (small → large fixture):\n{}",
        table.render()
    );
    let _ = writeln!(
        out,
        "\n{}",
        render_evaluation("projection — clean fixture:", &verdict.projection)
    );
    let _ = writeln!(
        out,
        "{}",
        render_evaluation(
            "projection — after the peak drive:",
            &verdict.projection_after_load
        )
    );
    let failures = verdict.failures();
    if failures.is_empty() {
        let _ = writeln!(out, "traffic cost: PASS");
    } else {
        let _ = writeln!(out, "traffic cost: FAIL");
        for failure in &failures {
            let _ = writeln!(out, "  {failure}");
        }
    }
    out
}

/// Read and decode one JSON input.
async fn read_json<T: serde::de::DeserializeOwned>(
    what: &str,
    path: &Path,
) -> stow_types::error::Result<T> {
    let text = tokio::fs::read_to_string(path)
        .await
        .map_err(|error| stow_error!("read {what} {}: {error}", path.display()))?;
    serde_json::from_str(&text)
        .map_err(|error| stow_error!("parse {what} {}: {error}", path.display()))
}

/// `stow-admin traffic-cost project` — judge and exit nonzero on any
/// failure.
pub async fn run(args: &ProjectArgs, output: Output) -> stow_types::error::Result<()> {
    let small: SchedulerBudgetReport = read_json("budget report", &args.small).await?;
    let large: SchedulerBudgetReport = read_json("budget report", &args.large).await?;
    let after: SchedulerBudgetReport = read_json("budget report", &args.after).await?;
    let cpu: WorkerCpuReport = read_json("Worker CPU report", &args.cpu).await?;
    let model = super::read_model(&args.model).await?;
    let verdict =
        judge(&model, &small, &large, &after, &cpu).map_err(|error| stow_error!("{error}"))?;
    emit(output, &verdict, render_verdict)?;
    let failures = verdict.failures();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(stow_error!("traffic cost: {} failure(s)", failures.len()))
    }
}

#[cfg(test)]
mod tests {
    use stow_types::api::{SchedulerBudgetReport, SchedulerBudgetRow};
    use stow_types::do_budgets::{DO_BUDGETS, WORKER_CPU_BUDGETS};
    use stow_types::launch_model::LaunchModel;

    use super::{evaluate, growth, judge, render_verdict};
    use crate::traffic_cost::cpu::{WorkerCpuReport, WorkerCpuRow};

    /// A fixture report built on the absolute budget bounds: every
    /// drive's measurement sits at `scale(name)` of its budget — half is
    /// the ~2× headroom the `DO_BUDGETS` table documents, so the fixture
    /// is the report a healthy run produces.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "fixture counters sit far inside both types' ranges"
    )]
    fn fixture_report(queue_rows: u64, scale: impl Fn(&str) -> f64) -> SchedulerBudgetReport {
        SchedulerBudgetReport {
            queue_rows,
            // The production dispatch cap (45) minus the fixture's 30
            // in-flight rows: the slots the hot pass claims.
            dispatch_limit: 45,
            claimed_tasks: 15,
            over_budget: false,
            rows: DO_BUDGETS
                .iter()
                .map(|budget| {
                    let factor = scale(budget.name);
                    SchedulerBudgetRow {
                        name: budget.name.to_owned(),
                        statements: (budget.statements as f64 * factor) as u64,
                        rows_read: (budget.rows_read as f64 * factor) as u64,
                        rows_written: (budget.rows_written as f64 * factor) as u64,
                        wall_ms: (budget.wall_ms as f64 * factor) as u64,
                        d1_rows_read: 0,
                        d1_rows_written: 0,
                        d1_elapsed_ms: 0,
                        statement_budget: budget.statements,
                        read_budget: budget.rows_read,
                        write_budget: budget.rows_written,
                        wall_budget: budget.wall_ms,
                        over_budget: factor > 1.0,
                        over_wall: factor > 1.0,
                        log: Vec::new(),
                    }
                })
                .collect(),
        }
    }

    /// Every lane at `scale(lane)` of its CPU budget.
    fn fixture_cpu(scale: impl Fn(&str) -> f64) -> WorkerCpuReport {
        WorkerCpuReport {
            sampling_interval_us: 100,
            idle_window_ms: 3000,
            idle_cpu_ms: 0.0,
            rows: WORKER_CPU_BUDGETS
                .iter()
                .map(|budget| {
                    let cpu_ms = budget.cpu_ms * scale(budget.lane);
                    WorkerCpuRow {
                        lane: budget.lane.to_owned(),
                        events_per_round: 20,
                        rounds_cpu_ms: vec![cpu_ms],
                        cpu_ms,
                        budget_ms: budget.cpu_ms,
                        over_budget: budget.over_budget(cpu_ms),
                    }
                })
                .collect(),
        }
    }

    /// The checked-in model — the gate test reads the real file so a
    /// regenerated model is always what the fixture is judged against.
    const MODEL_TOML: &str = include_str!("../../../launch-model.toml");

    fn model() -> LaunchModel {
        LaunchModel::from_toml(MODEL_TOML).expect("model")
    }

    #[test]
    fn a_healthy_run_passes() {
        let small = fixture_report(100_000, |_| 0.5);
        let large = fixture_report(1_000_000, |_| 0.5);
        let after = fixture_report(100_000, |_| 0.5);
        let verdict =
            judge(&model(), &small, &large, &after, &fixture_cpu(|_| 0.5)).expect("judge");
        let rendered = render_verdict(&verdict);
        assert!(verdict.failures().is_empty(), "{rendered}");
        assert!(rendered.contains("traffic cost: PASS"), "{rendered}");
        assert!(rendered.contains("workers"), "{rendered}");
        assert!(rendered.contains("cpu_ms"), "{rendered}");
        assert!(rendered.contains("Worker CPU per route"), "{rendered}");
        assert!(rendered.contains("Worker CPU at budget"), "{rendered}");
    }

    #[test]
    fn a_raised_drive_cost_fails_the_projection() {
        // 30× the hot alarm pass's written cost lifts the DO
        // rows_written projection past its bound.
        let report = fixture_report(
            100_000,
            |name| if name == "alarm pass" { 15.0 } else { 0.5 },
        );
        let evaluation = evaluate(&model(), &report, &fixture_cpu(|_| 0.5)).expect("evaluate");
        assert!(!evaluation.passes());
        assert!(
            evaluation
                .breaches
                .iter()
                .any(|breach| breach.product == "durable_objects"
                    && breach.dimension == "rows_written"),
            "{:?}",
            evaluation.breaches
        );
    }

    /// Worker CPU enters the projection: a bundle fetch costing 100×
    /// its budget pushes the month past half the CPU allowance.
    #[test]
    fn a_raised_worker_cpu_fails_the_projection() {
        let report = fixture_report(100_000, |_| 0.5);
        let cpu = fixture_cpu(|lane| if lane == "bundle-fetch" { 100.0 } else { 0.5 });
        let evaluation = evaluate(&model(), &report, &cpu).expect("evaluate");
        assert!(
            evaluation
                .breaches
                .iter()
                .any(|breach| breach.product == "workers" && breach.dimension == "cpu_ms"),
            "{:?}",
            evaluation.breaches
        );
    }

    /// A CPU report missing a lane the projection prices is refused,
    /// never priced at zero.
    #[test]
    fn a_missing_cpu_lane_is_refused() {
        let report = fixture_report(100_000, |_| 0.5);
        let mut cpu = fixture_cpu(|_| 0.5);
        cpu.rows.retain(|row| row.lane != "bundle-fetch");
        let error = evaluate(&model(), &report, &cpu).expect_err("missing lane must refuse");
        assert!(error.contains("bundle-fetch"), "{error}");
    }

    /// A pass that claimed nothing measures no claim price; with the
    /// model's nonzero build traffic the gate must refuse the report
    /// rather than project a zero claim cost (stow#452 F1).
    #[test]
    fn a_zero_claim_report_is_refused() {
        let mut report = fixture_report(100_000, |_| 0.5);
        report.claimed_tasks = 0;
        let error = evaluate(&model(), &report, &fixture_cpu(|_| 0.5))
            .expect_err("zero-claims must refuse");
        assert!(error.contains("claims 0 tasks"), "{error}");
    }

    /// A drive whose rows track the stored bulk fails the growth check;
    /// one inside 10% + 50 rows passes.
    #[test]
    fn rows_that_grow_with_the_fixture_fail() {
        let small = fixture_report(100_000, |_| 0.5);
        let flat = fixture_report(
            1_000_000,
            |name| if name == "GET /status" { 0.55 } else { 0.5 },
        );
        assert!(
            growth(&small, &flat)
                .expect("growth")
                .iter()
                .all(|row| !row.grows)
        );
        let mut grown = fixture_report(1_000_000, |_| 0.5);
        let row = grown
            .rows
            .iter_mut()
            .find(|row| row.name == "GET /tasks")
            .expect("row");
        row.rows_read *= 10;
        let rows = growth(&small, &grown).expect("growth");
        let grows: Vec<&str> = rows
            .iter()
            .filter(|row| row.grows)
            .map(|row| row.name.as_str())
            .collect();
        assert_eq!(grows, ["GET /tasks"]);
    }

    /// An over-budget row in the post-load report fails the verdict.
    #[test]
    fn an_over_budget_row_after_the_drive_fails() {
        let small = fixture_report(100_000, |_| 0.5);
        let large = fixture_report(1_000_000, |_| 0.5);
        let after = fixture_report(
            100_000,
            |name| if name == "GET /status" { 1.5 } else { 0.5 },
        );
        let verdict =
            judge(&model(), &small, &large, &after, &fixture_cpu(|_| 0.5)).expect("judge");
        let failures = verdict.failures();
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("after report") && failure.contains("GET /status")),
            "{failures:?}"
        );
    }

    #[test]
    fn every_event_cost_drive_has_a_report_row() {
        let report = fixture_report(100_000, |_| 0.5);
        let names: std::collections::BTreeSet<&str> =
            report.rows.iter().map(|row| row.name.as_str()).collect();
        for cost in super::EVENT_COSTS {
            for (name, _) in cost.drives {
                assert!(names.contains(name), "no report row for `{name}`");
            }
        }
    }

    /// Every lane the projection prices has a CPU budget row.
    #[test]
    fn every_priced_cpu_lane_has_a_budget() {
        for cost in super::EVENT_COSTS {
            if let super::CpuPricing::Lanes(lanes) = cost.cpu {
                for (lane, _) in lanes {
                    assert!(
                        WORKER_CPU_BUDGETS.iter().any(|budget| budget.lane == *lane),
                        "no Worker CPU budget for `{lane}`"
                    );
                }
            }
        }
    }

    #[test]
    fn the_cpu_budgets_fit_the_allowance() {
        let report = fixture_report(100_000, |_| 0.5);
        let evaluation = evaluate(&model(), &report, &fixture_cpu(|_| 0.5)).expect("evaluate");
        let bound = super::WORKER_CPU_MS_MONTHLY * super::ALLOWANCE_FRACTION;
        assert!(
            evaluation.worker_cpu_ms_at_budget <= bound,
            "WORKER_CPU_BUDGETS project {:.3e} ms/mo at budget, over the {bound:.3e} bound",
            evaluation.worker_cpu_ms_at_budget
        );
        let priced = super::EVENT_COSTS
            .iter()
            .filter(|cost| matches!(cost.cpu, super::CpuPricing::Lanes(_)))
            .count();
        assert_eq!(evaluation.cpu_routes.len(), priced);
        for route in &evaluation.cpu_routes {
            assert!(
                (route.measured_ms_per_event - route.budget_ms_per_event / 2.0).abs() < 1e-9,
                "{} measured at half its budget",
                route.route
            );
        }
    }
}
