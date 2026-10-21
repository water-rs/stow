//! `stow-admin traffic-cost project` — the monthly projection of each
//! Cloudflare product against half its allowance (stow#452, stow#775).
//!
//! The release gate's `Monthly projection` job runs it over what the
//! Traffic cost, Preheat cost and Production wave jobs measured: the
//! scheduler budget report on the clean fixture, the one re-measured
//! after the peak drive, the Worker CPU report,
//! `preheat-cost-report.json` and `production-wave.json`. It
//! fails when any product's projected monthly usage — user traffic plus
//! preheat — exceeds half its included allowance.
//!
//! **Traffic** multiplies the launch model's per-event monthly counts by
//! the per-event costs measured in the same run. Nothing it reads is a
//! checked-in constant: the reports' `*_budget` columns carry the budget
//! each row was measured against, Worker CPU per event is the profiler's
//! measurement (`cpu.rs`), and the allowances come from `watchdog`'s
//! single allowance table.
//!
//! **Preheat** (`preheat.rs`) adds, to each product the Preheat cost
//! report measures, one wave per stable rustc release plus one resubmit
//! per day, at the production wave's node count. A product the report
//! does not measure is printed as such and never priced at zero.
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
//!
//! The measurement checks on the same reports — row budgets, growth with
//! the stored bulk and the peak serialized wall — are `verdict.rs`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::Args;
use stow_types::api::SchedulerBudgetReport;
use stow_types::do_budgets::WORKER_CPU_BUDGETS;
use stow_types::launch_model::{EventKind, LaunchModel};
use stow_types::preheat_cost::{PreheatCostReport, ProductionWave};
use stow_types::stow_error;

use super::cpu::WorkerCpuReport;
use super::preheat::PreheatMonthly;
use crate::render::{Output, Table, emit};
use crate::watchdog::{
    D1_ROWS_READ_MONTHLY, D1_ROWS_WRITTEN_MONTHLY, DO_DURATION_GB_S_MONTHLY, DO_REQUESTS_MONTHLY,
    DO_ROWS_READ_MONTHLY, DO_ROWS_WRITTEN_MONTHLY, WORKER_CPU_MS_MONTHLY, WORKER_REQUESTS_MONTHLY,
};

/// The monthly projection — `stow-admin traffic-cost project`.
#[derive(Debug, Args)]
pub struct ProjectArgs {
    /// The scheduler budget report on the small fixture (100k rows).
    #[arg(long)]
    pub small: PathBuf,
    /// The scheduler budget report re-measured after the peak drive.
    #[arg(long)]
    pub after: PathBuf,
    /// The Worker CPU report `traffic-cost cpu` wrote.
    #[arg(long)]
    pub cpu: PathBuf,
    /// The Preheat cost job's `preheat-cost-report.json`. Required: there
    /// is no traffic-only projection, because a stable release's wave
    /// and the daily resubmit are part of every month's bill.
    #[arg(long)]
    pub preheat: PathBuf,
    /// The Production wave job's `production-wave.json`: the node count
    /// the preheat costs scale to. Required for the same reason.
    #[arg(long)]
    pub production: PathBuf,
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

/// Tasks the enqueue drives' `submit_batch` carries — the denominator
/// a single-task insert prices against.
const SUBMIT_BATCH_TASKS: f64 = 3.0;

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
/// miss drain is its 64-row batch; a callback's one subrequest is its
/// forward to the scheduler, and it touches no D1).
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
        drives: &[],
        do_requests: 1.0,
        claims: 0.0,
        worker_requests: 1.0,
        cpu: CpuPricing::Lanes(&[("workflow-callback", 1.0)]),
        subrequests: 1.0,
        d1_rows_read: 0.0,
        d1_rows_written: 0.0,
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

/// The measured drive rows of one budget report, and what one claim
/// inside an alarm pass costs on top of the idle floor.
struct Drives {
    /// Every report row by name.
    measured: BTreeMap<String, DriveCost>,
    /// The marginal cost of one claimed task.
    claim_marginal: DriveCost,
}

impl Drives {
    /// Read the report's rows and derive the claim price.
    ///
    /// # Errors
    /// The report lacks a pass row, or claimed nothing while the model
    /// projects builds.
    #[expect(
        clippy::cast_precision_loss,
        reason = "measured counters fit f64 exactly past any launch traffic"
    )]
    fn new(model: &LaunchModel, report: &SchedulerBudgetReport) -> Result<Self, String> {
        let measured: BTreeMap<String, DriveCost> = report
            .rows
            .iter()
            .map(|row| {
                (
                    row.name.clone(),
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
        let row = |name: &str| {
            measured
                .get(name)
                .copied()
                .ok_or_else(|| format!("budget report carries no row for `{name}`"))
        };
        let hot = row("alarm pass")?;
        let idle = row("alarm pass (idle)")?;
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
        Ok(Self {
            measured,
            claim_marginal,
        })
    }

    /// One drive's measured cost.
    fn drive(&self, name: &str) -> Result<DriveCost, String> {
        self.measured
            .get(name)
            .copied()
            .ok_or_else(|| format!("budget report carries no row for `{name}`"))
    }

    /// What one event of `cost`'s kind costs the scheduler: its drives'
    /// rows times their calls, plus the claim price times its claims.
    fn event(&self, cost: &EventCost) -> Result<DriveCost, String> {
        let mut total = DriveCost::default();
        for (name, calls) in cost.drives {
            total.add(*calls, &self.drive(name)?);
        }
        total.add(cost.claims, &self.claim_marginal);
        Ok(total)
    }
}

impl DriveCost {
    /// `self += calls × other`, field by field.
    const fn add(&mut self, calls: f64, other: &Self) {
        self.rows_read = calls.mul_add(other.rows_read, self.rows_read);
        self.rows_written = calls.mul_add(other.rows_written, self.rows_written);
        self.wall_ms = calls.mul_add(other.wall_ms, self.wall_ms);
        self.d1_rows_read = calls.mul_add(other.d1_rows_read, self.d1_rows_read);
        self.d1_rows_written = calls.mul_add(other.d1_rows_written, self.d1_rows_written);
    }
}

/// Serialized scheduler wall per second at the model's peak rate, in
/// seconds per second — Σ over every event kind of its peak events per
/// second times its serialized wall. The verdict bounds it.
pub(super) fn peak_serialized_s(
    model: &LaunchModel,
    report: &SchedulerBudgetReport,
) -> Result<f64, String> {
    let drives = Drives::new(model, report)?;
    let mut wall_ms = 0.0;
    for cost in EVENT_COSTS {
        wall_ms = model
            .peak_events_per_second(cost.kind)
            .mul_add(drives.event(cost)?.wall_ms, wall_ms);
    }
    Ok(wall_ms / 1000.0)
}

/// One product dimension's monthly projection against its allowance.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UsageLine {
    /// The Cloudflare product: `workers`, `durable_objects`, `d1`.
    pub product: &'static str,
    /// The billed dimension (e.g. `requests`, `rows_read`,
    /// `duration_gb_s`).
    pub dimension: &'static str,
    /// Projected monthly usage from user traffic at launch scale.
    pub traffic: f64,
    /// Projected monthly usage from preheat — one wave per stable
    /// release plus one resubmit per day. `None` when the Preheat cost
    /// report does not measure the dimension.
    pub preheat: Option<f64>,
    /// The included monthly allowance.
    pub allowance: f64,
}

impl UsageLine {
    /// Traffic plus preheat — what the bound is compared with.
    pub fn total(&self) -> f64 {
        self.traffic + self.preheat.unwrap_or(0.0)
    }
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

/// The driver a breach names when preheat, not user traffic, is the
/// larger part of the total.
const PREHEAT_ROUTE: &str = "preheat (stable-release waves + daily resubmits)";

/// A projected breach — the gate fails on any of these.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Breach {
    /// Product whose bound tripped.
    pub product: &'static str,
    /// The over-allowance dimension.
    pub dimension: &'static str,
    /// Projected monthly usage, traffic plus preheat.
    pub projected: f64,
    /// The user-traffic part of `projected`.
    pub traffic: f64,
    /// The preheat part of `projected`.
    pub preheat: f64,
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

/// One report's projection: every usage line, the top-N routes and any
/// breaches.
#[derive(Debug, serde::Serialize)]
pub struct GateEvaluation {
    /// Per-product projected usage lines.
    pub usage: Vec<UsageLine>,
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

/// Σ over every event kind: projected monthly usage per product
/// dimension and the DO wall seconds that price duration — plus the
/// per-route shares for the report's top-N table and the unmeasured
/// diagnostics.
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

/// Fold the event kind's Worker CPU price into the projection and
/// return the CPU milliseconds one event costs across its lanes.
fn fold_cpu(
    cost: &EventCost,
    cpu: &WorkerCpuReport,
    monthly: f64,
    projection: &mut Projection,
) -> Result<f64, String> {
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
    Ok(kind_cpu_ms)
}

/// Fold one event kind's monthly counts into the projection.
fn fold_kind(
    model: &LaunchModel,
    cost: &EventCost,
    drives: &Drives,
    cpu: &WorkerCpuReport,
    projection: &mut Projection,
) -> Result<(), String> {
    let monthly = model.monthly_events(cost.kind);
    projection.worker_requests = monthly.mul_add(cost.worker_requests, projection.worker_requests);
    projection.do_requests = monthly.mul_add(cost.do_requests, projection.do_requests);
    projection.diag_subrequests = monthly.mul_add(cost.subrequests, projection.diag_subrequests);
    projection.diag_d1_read = monthly.mul_add(cost.d1_rows_read, projection.diag_d1_read);
    projection.diag_d1_written = monthly.mul_add(cost.d1_rows_written, projection.diag_d1_written);
    projection.diag_r2_ops = monthly.mul_add(cost.r2_ops, projection.diag_r2_ops);
    let kind_cpu_ms = fold_cpu(cost, cpu, monthly, projection)?;
    projection.worker_cpu_ms = monthly.mul_add(kind_cpu_ms, projection.worker_cpu_ms);
    let kind = drives.event(cost)?;
    projection.do_rows_read = monthly.mul_add(kind.rows_read, projection.do_rows_read);
    projection.do_rows_written = monthly.mul_add(kind.rows_written, projection.do_rows_written);
    projection.do_wall_s += monthly * kind.wall_ms / 1000.0;
    projection.d1_read = monthly.mul_add(kind.d1_rows_read, projection.d1_read);
    projection.d1_written = monthly.mul_add(kind.d1_rows_written, projection.d1_written);
    // The route's heaviest dimension decides its allowance share — the
    // number the top-N table ranks.
    let shares = [
        (
            "do_requests",
            monthly * cost.do_requests / DO_REQUESTS_MONTHLY,
        ),
        (
            "do_duration_gb_s",
            monthly * (kind.wall_ms / 1000.0) * DO_DURATION_GB_PER_WALL_S
                / DO_DURATION_GB_S_MONTHLY,
        ),
        (
            "do_rows_read",
            monthly * kind.rows_read / DO_ROWS_READ_MONTHLY,
        ),
        (
            "do_rows_written",
            monthly * kind.rows_written / DO_ROWS_WRITTEN_MONTHLY,
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
            monthly * kind.d1_rows_read / D1_ROWS_READ_MONTHLY,
        ),
        (
            "d1_rows_written",
            monthly * kind.d1_rows_written / D1_ROWS_WRITTEN_MONTHLY,
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
/// quantity or a structural count — each with the preheat share the
/// Preheat cost report measures for it.
fn usage_lines(projection: &Projection, preheat: &PreheatMonthly) -> Vec<UsageLine> {
    let line =
        |product: &'static str, dimension: &'static str, traffic: f64, allowance: f64| UsageLine {
            product,
            dimension,
            traffic,
            preheat: preheat.monthly(product, dimension),
            allowance,
        };
    vec![
        line(
            "workers",
            "requests",
            projection.worker_requests,
            WORKER_REQUESTS_MONTHLY,
        ),
        line(
            "workers",
            "cpu_ms",
            projection.worker_cpu_ms,
            WORKER_CPU_MS_MONTHLY,
        ),
        line(
            "durable_objects",
            "requests",
            projection.do_requests,
            DO_REQUESTS_MONTHLY,
        ),
        line(
            "durable_objects",
            "rows_read",
            projection.do_rows_read,
            DO_ROWS_READ_MONTHLY,
        ),
        line(
            "durable_objects",
            "rows_written",
            projection.do_rows_written,
            DO_ROWS_WRITTEN_MONTHLY,
        ),
        line(
            "durable_objects",
            "duration_gb_s",
            projection.do_wall_s * DO_DURATION_GB_PER_WALL_S,
            DO_DURATION_GB_S_MONTHLY,
        ),
        line("d1", "rows_read", projection.d1_read, D1_ROWS_READ_MONTHLY),
        line(
            "d1",
            "rows_written",
            projection.d1_written,
            D1_ROWS_WRITTEN_MONTHLY,
        ),
    ]
}

/// Ungated dimensions printed for context only — per-event constants
/// nothing measures, kept visible so a growing one is seen.
fn diagnostic_lines(projection: &Projection) -> Vec<UsageLine> {
    let line = |product: &'static str, dimension: &'static str, traffic: f64| UsageLine {
        product,
        dimension,
        traffic,
        preheat: None,
        allowance: f64::INFINITY,
    };
    vec![
        line("workers", "subrequests", projection.diag_subrequests),
        line(
            "d1 (worker-side, unmeasured)",
            "rows_read",
            projection.diag_d1_read,
        ),
        line(
            "d1 (worker-side, unmeasured)",
            "rows_written",
            projection.diag_d1_written,
        ),
        line("r2", "ops", projection.diag_r2_ops),
    ]
}

/// Turn each usage line whose total is over `ALLOWANCE_FRACTION` of its
/// allowance into a breach, attributed to the route that dominates the
/// breached dimension — or to preheat when it is the larger part.
fn usage_breaches(usage: &[UsageLine], top_routes: &[RouteShare]) -> Vec<Breach> {
    let mut breaches = Vec::new();
    for line in usage {
        let bound = line.allowance * ALLOWANCE_FRACTION;
        if line.total() > bound {
            // `RouteShare::dimension` keys the share dimension by
            // product prefix — `do_`, `d1_`, `worker_`.
            let prefix = match line.product {
                "workers" => "worker",
                "durable_objects" => "do",
                other => other,
            };
            let share_key = format!("{prefix}_{}", line.dimension);
            let preheat = line.preheat.unwrap_or(0.0);
            let top_route = if preheat > line.traffic {
                PREHEAT_ROUTE
            } else {
                top_routes
                    .iter()
                    .find(|r| r.dimension == share_key)
                    .map_or("n/a", |r| r.route)
            };
            breaches.push(Breach {
                product: line.product,
                dimension: line.dimension,
                projected: line.total(),
                traffic: line.traffic,
                preheat,
                bound,
                top_route,
            });
        }
    }
    breaches
}

/// Project the launch model's monthly events against one report's
/// measured rows, the measured Worker CPU, the preheat share and the
/// watchdog allowance table.
fn evaluate(
    model: &LaunchModel,
    report: &SchedulerBudgetReport,
    cpu: &WorkerCpuReport,
    preheat: &PreheatMonthly,
) -> Result<GateEvaluation, String> {
    let drives = Drives::new(model, report)?;
    let mut projection = Projection::default();
    for cost in EVENT_COSTS {
        fold_kind(model, cost, &drives, cpu, &mut projection)?;
    }

    let usage = usage_lines(&projection, preheat);
    let diagnostics = diagnostic_lines(&projection);

    let mut top_routes = projection.per_route;
    top_routes.sort_by(|a, b| b.share.total_cmp(&a.share));
    top_routes.truncate(5);

    let mut breaches = usage_breaches(&usage, &top_routes);
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
            traffic: projection.worker_cpu_ms_at_budget,
            preheat: 0.0,
            bound: cpu_bound,
            top_route: projection
                .cpu_routes
                .iter()
                .max_by(|a, b| a.share_at_budget.total_cmp(&b.share_at_budget))
                .map_or("n/a", |route| route.route),
        });
    }
    Ok(GateEvaluation {
        usage,
        top_routes,
        diagnostics,
        cpu_routes: projection.cpu_routes,
        worker_cpu_ms_at_budget: projection.worker_cpu_ms_at_budget,
        unmeasured_cpu: projection.unmeasured_cpu,
        breaches,
    })
}

/// The whole projection: the preheat share and the monthly evaluation
/// of the clean and the post-load report.
#[derive(Debug, serde::Serialize)]
pub struct ProjectionReport {
    /// What preheat adds to a month, per node and in total.
    pub preheat: PreheatMonthly,
    /// The projection from the small report — the clean fixture.
    pub projection: GateEvaluation,
    /// The projection from the post-load report.
    pub projection_after_load: GateEvaluation,
}

impl ProjectionReport {
    /// Every failure, one line each.
    fn failures(&self) -> Vec<String> {
        let mut failures = Vec::new();
        for (label, evaluation) in [
            ("clean", &self.projection),
            ("post-load", &self.projection_after_load),
        ] {
            failures.extend(evaluation.breaches.iter().map(|breach| {
                format!(
                    "{label} projection: {} {} {:.3e} over bound {:.3e} \
                     (traffic {:.3e} + preheat {:.3e}) — driver: {}",
                    breach.product,
                    breach.dimension,
                    breach.projected,
                    breach.bound,
                    breach.traffic,
                    breach.preheat,
                    breach.top_route
                )
            }));
        }
        failures
    }
}

/// Project both budget reports with the preheat share.
fn project(
    model: &LaunchModel,
    small: &SchedulerBudgetReport,
    after: &SchedulerBudgetReport,
    cpu: &WorkerCpuReport,
    preheat_report: &PreheatCostReport,
    production: &ProductionWave,
) -> Result<ProjectionReport, String> {
    let preheat = PreheatMonthly::new(model, preheat_report, production)?;
    Ok(ProjectionReport {
        projection: evaluate(model, small, cpu, &preheat)?,
        projection_after_load: evaluate(model, after, cpu, &preheat)?,
        preheat,
    })
}

/// Human rendering of the preheat share: its scale, the measured
/// per-node costs it multiplies, and the legs per batch the measured
/// phases achieved — the `b̄` the per-node completion cost rides on.
fn render_preheat(preheat: &PreheatMonthly) -> String {
    use std::fmt::Write as _;
    let mut out = format!(
        "preheat: {:.2} stable releases/mo (one wave each) + {:.0} daily resubmits/mo, \
         at {} production nodes (measured on a {}-node wave)\n",
        preheat.releases_per_month,
        preheat.resubmits_per_month,
        preheat.production_nodes,
        preheat.measured_nodes,
    );
    let mut table = Table::new(&[
        "per node",
        "DO requests",
        "rows read",
        "rows written",
        "batches",
        "legs/batch",
    ]);
    for (label, cost, batching) in [
        ("wave", &preheat.wave, &preheat.wave_batching),
        ("resubmit", &preheat.resubmit, &preheat.resubmit_batching),
    ] {
        table.push([
            label.to_owned(),
            format!("{:.2}", cost.requests),
            format!("{:.2}", cost.rows_read),
            format!("{:.2}", cost.rows_written),
            batching.batches.to_string(),
            crate::preheat_cost::legs_per_batch(batching.legs_per_batch),
        ]);
    }
    let _ = write!(out, "{}", table.render());
    out
}

/// The per-product table: traffic, preheat and total beside the bound,
/// and a note on every dimension the Preheat cost report does not
/// measure.
fn render_usage(usage: &[UsageLine]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let mut table = Table::new(&[
        "product",
        "dimension",
        "traffic/mo",
        "preheat/mo",
        "total/mo",
        "allowance/mo",
        "bound (50%)",
        "share",
        "",
    ]);
    let mut unmeasured = Vec::new();
    for line in usage {
        let bound = line.allowance * ALLOWANCE_FRACTION;
        table.push([
            line.product.to_owned(),
            line.dimension.to_owned(),
            format!("{:.3e}", line.traffic),
            line.preheat
                .map_or_else(|| "n/m".to_owned(), |preheat| format!("{preheat:.3e}")),
            format!("{:.3e}", line.total()),
            format!("{:.3e}", line.allowance),
            format!("{bound:.3e}"),
            format!("{:.1}%", 100.0 * line.total() / line.allowance),
            if line.total() > bound { "OVER" } else { "" }.to_owned(),
        ]);
        if line.preheat.is_none() {
            unmeasured.push(format!(
                "  {} {}: {}",
                line.product,
                line.dimension,
                super::preheat::not_measured(line.product, line.dimension)
            ));
        }
    }
    let _ = writeln!(out, "{}", table.render());
    if !unmeasured.is_empty() {
        let _ = writeln!(
            out,
            "\nn/m — preheat not measured by the Preheat cost report (traffic only):\n{}",
            unmeasured.join("\n")
        );
    }
    out
}

/// Human rendering of one projection — the per-product table with the
/// preheat share, the top-5 routes, the diagnostics and the unmeasured
/// routes.
fn render_evaluation(title: &str, evaluation: &GateEvaluation) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "{title}");
    let _ = write!(out, "{}", render_usage(&evaluation.usage));
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
            format!("{:.3e}", line.traffic),
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

/// Human rendering of the projection.
fn render_projection(report: &ProjectionReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "{}", render_preheat(&report.preheat));
    let _ = writeln!(
        out,
        "{}",
        render_evaluation("projection — clean fixture:", &report.projection)
    );
    let _ = writeln!(
        out,
        "{}",
        render_evaluation(
            "projection — after the peak drive:",
            &report.projection_after_load
        )
    );
    let failures = report.failures();
    if failures.is_empty() {
        let _ = writeln!(out, "monthly projection: PASS");
    } else {
        let _ = writeln!(out, "monthly projection: FAIL");
        for failure in &failures {
            let _ = writeln!(out, "  {failure}");
        }
    }
    out
}

/// `stow-admin traffic-cost project` — project and exit nonzero on any
/// breach.
pub async fn run(args: &ProjectArgs, output: Output) -> stow_types::error::Result<()> {
    let small: SchedulerBudgetReport = super::read_json("budget report", &args.small).await?;
    let after: SchedulerBudgetReport = super::read_json("budget report", &args.after).await?;
    let cpu: WorkerCpuReport = super::read_json("Worker CPU report", &args.cpu).await?;
    let preheat: PreheatCostReport = super::read_json("preheat cost report", &args.preheat).await?;
    let production: ProductionWave = super::read_json("production wave", &args.production).await?;
    let model = super::read_model(&args.model).await?;
    let report = project(&model, &small, &after, &cpu, &preheat, &production)
        .map_err(|error| stow_error!("{error}"))?;
    emit(output, &report, render_projection)?;
    let failures = report.failures();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(stow_error!(
            "monthly projection: {} breach(es)",
            failures.len()
        ))
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;
    use stow_types::do_budgets::WORKER_CPU_BUDGETS;

    use super::{ProjectArgs, evaluate, project};
    use crate::traffic_cost::preheat::{Batching, PerNode, PreheatMonthly};
    use crate::traffic_cost::test_support::{fixture_cpu, fixture_report, model};

    /// A preheat share with no cost — the traffic-only baseline the
    /// tests add to.
    fn no_preheat() -> PreheatMonthly {
        preheat_of(PerNode::default(), PerNode::default())
    }

    /// 1 release a month, 1 resubmit a month, one measured node per
    /// production node: the monthly preheat is `wave + resubmit`.
    fn preheat_of(wave: PerNode, resubmit: PerNode) -> PreheatMonthly {
        PreheatMonthly {
            measured_nodes: 10,
            production_nodes: 10,
            releases_per_month: 1.0,
            resubmits_per_month: 1.0,
            wave,
            resubmit,
            wave_batching: Batching {
                batches: 0,
                legs_per_batch: None,
            },
            resubmit_batching: Batching {
                batches: 0,
                legs_per_batch: None,
            },
        }
    }

    fn rows_written_per_node(rows_written: f64) -> PerNode {
        PerNode {
            rows_written,
            ..PerNode::default()
        }
    }

    fn usage<'a>(
        evaluation: &'a super::GateEvaluation,
        product: &str,
        dimension: &str,
    ) -> &'a super::UsageLine {
        evaluation
            .usage
            .iter()
            .find(|line| line.product == product && line.dimension == dimension)
            .expect("usage line")
    }

    #[test]
    fn a_healthy_run_passes() {
        let small = fixture_report(100_000, |_| 0.5);
        let after = fixture_report(100_000, |_| 0.5);
        let report =
            project_with(&small, &after, &no_preheat(), &fixture_cpu(|_| 0.5)).expect("project");
        let rendered = super::render_projection(&report);
        assert!(report.failures().is_empty(), "{rendered}");
        assert!(rendered.contains("monthly projection: PASS"), "{rendered}");
        assert!(rendered.contains("preheat/mo"), "{rendered}");
        assert!(rendered.contains("Worker CPU per route"), "{rendered}");
        assert!(rendered.contains("Worker CPU at budget"), "{rendered}");
    }

    /// `project` over a hand-built preheat share instead of a report.
    fn project_with(
        small: &stow_types::api::SchedulerBudgetReport,
        after: &stow_types::api::SchedulerBudgetReport,
        preheat: &PreheatMonthly,
        cpu: &crate::traffic_cost::cpu::WorkerCpuReport,
    ) -> Result<super::ProjectionReport, String> {
        Ok(super::ProjectionReport {
            projection: evaluate(&model(), small, cpu, preheat)?,
            projection_after_load: evaluate(&model(), after, cpu, preheat)?,
            preheat: *preheat,
        })
    }

    /// Preheat is added to the products the Preheat cost report
    /// measures and to no other: the total is traffic plus preheat on a
    /// Durable Object line, and a Worker line carries no preheat at all.
    #[test]
    fn preheat_adds_to_the_measured_products_only() {
        let report = fixture_report(100_000, |_| 0.5);
        let cpu = fixture_cpu(|_| 0.5);
        let base = evaluate(&model(), &report, &cpu, &no_preheat()).expect("evaluate");
        let with = evaluate(
            &model(),
            &report,
            &cpu,
            &preheat_of(rows_written_per_node(1_000.0), rows_written_per_node(500.0)),
        )
        .expect("evaluate");

        let before = usage(&base, "durable_objects", "rows_written");
        let after = usage(&with, "durable_objects", "rows_written");
        assert!((before.traffic - after.traffic).abs() < 1e-6);
        // 1 wave/mo × 1000 rows/node × 10 nodes + 1 resubmit/mo ×
        // 500 rows/node × 10 nodes.
        let preheat = after.preheat.expect("measured");
        assert!((preheat - 15_000.0).abs() < 1e-6, "{preheat}");
        assert!((after.total() - (after.traffic + 15_000.0)).abs() < 1e-6);

        let workers = usage(&with, "workers", "requests");
        assert_eq!(workers.preheat, None);
        assert!((workers.total() - workers.traffic).abs() < f64::EPSILON);
    }

    /// Traffic alone is inside the bound; the same traffic plus a
    /// preheat that fills the rest of it is not — and the breach names
    /// the preheat as the driver and splits its total.
    #[test]
    fn traffic_plus_preheat_over_the_bound_fails() {
        let small = fixture_report(100_000, |_| 0.5);
        let after = fixture_report(100_000, |_| 0.5);
        let cpu = fixture_cpu(|_| 0.5);
        let base = evaluate(&model(), &small, &cpu, &no_preheat()).expect("evaluate");
        assert!(base.breaches.is_empty(), "{:?}", base.breaches);

        let line = usage(&base, "durable_objects", "rows_written");
        let headroom = line
            .allowance
            .mul_add(super::ALLOWANCE_FRACTION, -line.traffic);
        assert!(headroom > 0.0);
        // The month has one wave and one resubmit of 10 nodes each, so
        // `x` rows per node and phase is `20 x` a month.
        let fits = rows_written_per_node(headroom * 0.4 / 10.0);
        let report = project_with(&small, &after, &preheat_of(fits, fits), &cpu).expect("project");
        assert!(report.failures().is_empty(), "{:?}", report.failures());

        // A month of preheat as large as the whole allowance: over the
        // bound, and larger than the traffic it joins.
        let overflows = rows_written_per_node(line.allowance / 20.0);
        let report =
            project_with(&small, &after, &preheat_of(overflows, overflows), &cpu).expect("project");
        let failures = report.failures();
        assert_eq!(failures.len(), 2, "clean and post-load: {failures:?}");
        let breach = &report.projection.breaches[0];
        assert_eq!(breach.product, "durable_objects");
        assert_eq!(breach.dimension, "rows_written");
        assert!(breach.preheat > 0.0 && breach.traffic < breach.bound);
        assert!(breach.projected > breach.bound);
        assert_eq!(breach.top_route, super::PREHEAT_ROUTE);
    }

    /// The preheat report and the production wave are not optional: the
    /// CLI refuses a projection without either.
    #[test]
    fn the_preheat_report_and_production_wave_are_required() {
        #[derive(Debug, clap::Parser)]
        struct Cli {
            #[command(flatten)]
            args: ProjectArgs,
        }
        let base = ["project", "--small", "s", "--after", "a", "--cpu", "c"];
        for (given, missing) in [
            (["--production", "w"], "--preheat"),
            (["--preheat", "p"], "--production"),
        ] {
            let mut partial = base.to_vec();
            partial.extend(given);
            let error = Cli::try_parse_from(partial).expect_err("a required input is missing");
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::MissingRequiredArgument
            );
            assert!(error.to_string().contains(missing), "{error}");
        }
        let mut with = base.to_vec();
        with.extend(["--preheat", "p", "--production", "w"]);
        Cli::try_parse_from(with).expect("complete arguments parse");
    }

    #[test]
    fn a_report_without_nodes_cannot_be_projected() {
        let small = fixture_report(100_000, |_| 0.5);
        let after = fixture_report(100_000, |_| 0.5);
        let mut preheat = crate::traffic_cost::preheat::test_report(10);
        preheat.nodes = 0;
        let production = crate::traffic_cost::preheat::test_production(10);
        let error = project(
            &model(),
            &small,
            &after,
            &fixture_cpu(|_| 0.5),
            &preheat,
            &production,
        )
        .expect_err("a zero-node wave prices nothing");
        assert!(error.contains("0 nodes"), "{error}");
    }

    #[test]
    fn a_missing_cpu_lane_is_refused() {
        let report = fixture_report(100_000, |_| 0.5);
        let mut cpu = fixture_cpu(|_| 0.5);
        cpu.rows.retain(|row| row.lane != "bundle-fetch");
        let error =
            evaluate(&model(), &report, &cpu, &no_preheat()).expect_err("missing lane must refuse");
        assert!(error.contains("bundle-fetch"), "{error}");
    }

    #[test]
    fn a_raised_drive_cost_fails_the_projection() {
        // 30× the hot alarm pass's written cost lifts the DO
        // rows_written projection past its bound.
        let report = fixture_report(
            100_000,
            |name| if name == "alarm pass" { 15.0 } else { 0.5 },
        );
        let evaluation =
            evaluate(&model(), &report, &fixture_cpu(|_| 0.5), &no_preheat()).expect("evaluate");
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
        let evaluation = evaluate(&model(), &report, &cpu, &no_preheat()).expect("evaluate");
        assert!(
            evaluation
                .breaches
                .iter()
                .any(|breach| breach.product == "workers" && breach.dimension == "cpu_ms"),
            "{:?}",
            evaluation.breaches
        );
    }

    /// A pass that claimed nothing measures no claim price; with the
    /// model's nonzero build traffic the gate must refuse the report
    /// rather than project a zero claim cost (stow#452 F1).
    #[test]
    fn a_zero_claim_report_is_refused() {
        let mut report = fixture_report(100_000, |_| 0.5);
        report.claimed_tasks = 0;
        let error = evaluate(&model(), &report, &fixture_cpu(|_| 0.5), &no_preheat())
            .expect_err("zero-claims must refuse");
        assert!(error.contains("claims 0 tasks"), "{error}");
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
        let evaluation =
            evaluate(&model(), &report, &fixture_cpu(|_| 0.5), &no_preheat()).expect("evaluate");
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
