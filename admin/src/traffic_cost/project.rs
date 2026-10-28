//! `stow-admin traffic-cost project` — the monthly projection of each
//! Cloudflare product against the stow#883 cost line (stow#452,
//! stow#775): 80% of its monthly Workers Paid allowance.
//!
//! The release gate's `Monthly projection` job runs it over what the
//! Traffic cost, Preheat cost and Production wave jobs measured: the
//! scheduler budget report on the clean fixture, the one re-measured
//! after the peak drive, the Worker CPU report,
//! `preheat-cost-report.json` and `production-wave.json`. It
//! fails when any product's projected monthly usage — user traffic plus
//! preheat — exceeds the line, and when a preheat wave or resubmit
//! scaled to the measured production wave spends past
//! [`PREHEAT_BUDGET`].
//!
//! **Traffic** multiplies the launch model's per-event monthly counts by
//! the per-event costs measured in the same run. Nothing it reads is a
//! checked-in constant: the reports' `*_budget` columns carry the budget
//! each row was measured against, Worker CPU per event and its budget
//! are the profiler's report (`cpu.rs`) — both in that run's
//! milliseconds, the budget converted from its relative row by the run's
//! reference workload — and the allowances come from `watchdog`'s
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
//! Subrequests and R2 ops carry per-event constants the
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
use stow_types::do_budgets::{ALLOWANCE_FRACTION, PREHEAT_BUDGET};
use stow_types::forwards::{self, RunForwards};
use stow_types::launch_model::{EventKind, LaunchModel};
use stow_types::preheat_cost::{PreheatCostReport, ProductionWave};
use stow_types::stow_error;

use super::cpu::WorkerCpuReport;
use super::preheat::PreheatMonthly;
use crate::render::{Output, Table, emit};
use crate::watchdog::{
    DO_DURATION_GB_S_MONTHLY, DO_REQUESTS_MONTHLY, DO_ROWS_READ_MONTHLY, DO_ROWS_WRITTEN_MONTHLY,
    WORKER_CPU_MS_MONTHLY, WORKER_REQUESTS_MONTHLY,
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

// The gate fires when a product's projected monthly usage exceeds
// `ALLOWANCE_FRACTION` of its included allowance — the one line
// declared in `stow-types` (stow#883) that the in-edge breaker and the
// preheat budget derive from too.

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
    /// Σ `meta.rowsRead` on the counted backend.
    sql_rows_read: f64,
    /// Σ `meta.rowsWritten` on the same backend.
    sql_rows_written: f64,
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

/// One scheduler call an event pays: the Durable Object requests it is
/// billed and the share of the call's measured report row it pays.
///
/// A whole request is billed one DO request and pays its whole row
/// ([`call`]); an event whose rows ride inside another event's request
/// pays a share of that row and is billed no request of its own.
#[derive(Debug, Clone, Copy)]
struct Forward {
    /// The budget-report row that measures the call.
    row: &'static str,
    /// Billed DO invocations per event — Cloudflare's request billing
    /// counts alarm invocations too, so an alarm pass is one.
    requests: f64,
    /// The share of the row's measured rows and wall one event pays.
    share: f64,
}

/// `calls` whole requests to the route `row` measures.
const fn call(row: &'static str, calls: u32) -> Forward {
    Forward {
        row,
        requests: calls as f64,
        share: calls as f64,
    }
}

/// One traffic kind's cost vector. `forwards` names the scheduler calls
/// the event makes — its billed DO requests are their sum, never a
/// separate count — and `claims` the dispatches inside a pass it causes
/// (only [`EventKind::Build`] — one claim each). The gated fields are
/// structural counts (`forwards`, `worker_requests`) or measured reads
/// (report rows, Worker CPU lanes); the `subrequests`/`r2_ops`
/// constants describe the handler's shape and print as diagnostics
/// only — nothing measures them, so they never gate.
#[derive(Debug, Clone, Copy)]
struct EventCost {
    /// The traffic kind this prices.
    kind: EventKind,
    /// The route label the report table prints.
    route: &'static str,
    /// The scheduler calls one event makes.
    forwards: &'static [Forward],
    /// Dispatches the event causes inside a scheduler pass.
    claims: f64,
    /// Billed worker requests per event (index pulls are two).
    worker_requests: f64,
    /// Where the event's Worker CPU comes from.
    cpu: CpuPricing,
    /// Subrequests per event — diagnostic only.
    subrequests: f64,
    /// R2 ops per event — diagnostic only (zero today).
    r2_ops: f64,
}

impl EventCost {
    /// Billed DO invocations per event: one per whole scheduler call.
    fn do_requests(&self) -> f64 {
        self.forwards.iter().map(|forward| forward.requests).sum()
    }
}

/// Worker requests one build run's `workflow_run` deliveries bill.
const RUN_DELIVERIES: f64 = RunForwards::DELIVERIES as f64;

/// Per-event costs, from the route handlers in `edge/src/api.rs` and
/// the webhook in `edge/src/webhook.rs`. A route handler that is one
/// scheduler call names it in its comment; the webhook's and the human
/// request's counts come from `stow_types::forwards`, which the edge's
/// handler tests hold to what the handler sends. The DO drives are
/// billed per call from the measured row; subrequest counts are the
/// handler's lookup shapes (a callback's one subrequest is its forward
/// to the scheduler).
const EVENT_COSTS: &[EventCost] = &[
    EventCost {
        kind: EventKind::CliBytePathFetch,
        route: "GET /api/v1/bundles/{rustc_version}/{digest}",
        forwards: &[],
        claims: 0.0,
        worker_requests: 1.0,
        cpu: CpuPricing::Lanes(&[("bundle-fetch", 1.0)]),
        subrequests: 1.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::IndexPull,
        route: "GET /api/v1/index/* (pointer + slice)",
        forwards: &[],
        claims: 0.0,
        worker_requests: 2.0,
        cpu: CpuPricing::Lanes(&[("index-pull", 1.0)]),
        subrequests: 2.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::Admission,
        route: "POST /api/v1/admissions",
        // The route mints for the whole candidate tree and calls no
        // scheduler route — the merge's born-published check is the
        // coverage.
        forwards: &[],
        claims: 0.0,
        worker_requests: 1.0,
        cpu: CpuPricing::Lanes(&[("admission", 1.0)]),
        subrequests: 2.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::EnqueueRedemption,
        route: "POST /api/v1/enqueue",
        // `api::enqueue_admitted_task` makes one scheduler call, the
        // `send_enqueue` — the `GET /status` pre-check is gone
        // (stow#940): the object's own pending-depth cap answers 429 on
        // the same request. Its insert is one third of the accept
        // drive's three-task batch, priced on the accept path — an
        // accepted redemption pays the insert.
        forwards: &[Forward {
            row: "POST /enqueue (untrusted accept)",
            requests: 1.0,
            share: 1.0 / SUBMIT_BATCH_TASKS,
        }],
        claims: 0.0,
        worker_requests: 1.0,
        cpu: CpuPricing::Lanes(&[("enqueue-redeem", 1.0)]),
        subrequests: 0.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::HumanRequest,
        route: "POST /api/v1/requests",
        // The request's whole lifecycle per event: the admit (dedup +
        // budget probe + resolve dispatch), the resolve run's webhook
        // forwards, and the outcome post whose `enqueue_trusted` writes
        // the task rows and dispatches them inline. A run that fails
        // trades the outcome for the `completed` backstop at the same
        // request count (`human_request_forwards`), so the success path
        // prices both — its outcome is the heavier row. Worker
        // requests: the `POST /api/v1/requests`, the resolve run's
        // deliveries and the outcome post.
        forwards: &[
            call("POST /requests", forwards::HUMAN_REQUEST_ADMIT),
            call(
                "POST /requests/{id}/run-update (in_progress)",
                forwards::SUCCESSFUL_RESOLVE_RUN.in_progress,
            ),
            call(
                "POST /requests/{id}/run-update (completed)",
                forwards::SUCCESSFUL_RESOLVE_RUN.completed,
            ),
            call(
                "POST /requests/{id}/outcome",
                forwards::HUMAN_REQUEST_OUTCOME,
            ),
        ],
        claims: 0.0,
        worker_requests: forwards::human_request_worker_requests(true) as f64,
        cpu: CpuPricing::Unmeasured(
            "POST /api/v1/requests verifies Turnstile at challenges.cloudflare.com and reads the \
             stable channel manifest from static.rust-lang.org — no lane drives it off the \
             network, nor the resolve run's deliveries and outcome post",
        ),
        subrequests: 3.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::RequestStatusRead,
        route: "GET /api/v1/requests/{id}",
        // `api::crate_request_status` makes one scheduler call, the
        // `crate_request_status` read: the row plus the stored-roots
        // re-probe against the live queue.
        forwards: &[call("GET /requests/{id}", 1)],
        claims: 0.0,
        worker_requests: 1.0,
        cpu: CpuPricing::Lanes(&[("status-read", 1.0)]),
        subrequests: 0.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::SiteView,
        route: "GET /|install|requests/{id} (site)",
        forwards: &[],
        claims: 0.0,
        worker_requests: 1.0,
        cpu: CpuPricing::Lanes(&[("site", 1.0)]),
        subrequests: 0.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::StatsView,
        route: "GET /stats (+/api/v1/stats)",
        forwards: &[],
        claims: 0.0,
        worker_requests: 1.0,
        cpu: CpuPricing::Lanes(&[("stats", 1.0)]),
        subrequests: 0.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::MissNode,
        route: "miss nodes (drained insert)",
        // Every miss node is one task in an admission's drain batch —
        // one third of the accept drive's three-task enqueue, priced
        // on the accept path so a growing miss volume grows the bill.
        // It rides inside the enqueue's request, so it bills none.
        forwards: &[Forward {
            row: "POST /enqueue (untrusted accept)",
            requests: 0.0,
            share: 1.0 / SUBMIT_BATCH_TASKS,
        }],
        claims: 0.0,
        worker_requests: 0.0,
        cpu: CpuPricing::NoWorkerRequest,
        subrequests: 0.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::AdminOperation,
        route: "stow-admin operations",
        // `api::admin_status` makes one scheduler call.
        forwards: &[call("GET /admin/status", 1)],
        claims: 0.0,
        worker_requests: 1.0,
        cpu: CpuPricing::Lanes(&[("admin-status", 1.0)]),
        subrequests: 0.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::IndexPublish,
        route: "POST /api/v1/admin/index/published",
        // One report per publish run (stow#940):
        // `api::record_published_index` makes one scheduler call, which
        // applies the run's slices and dispatches what they release
        // inline. Worker requests: the report plus the
        // `index-publish.yml` run's own deliveries, which the webhook
        // consumes without a forward (`forwards::INDEX_PUBLISH_RUN`).
        forwards: &[call("POST /index/published (full)", 1)],
        claims: 0.0,
        worker_requests: 1.0 + RUN_DELIVERIES,
        cpu: CpuPricing::Unmeasured(
            "no lane drives POST /api/v1/admin/index/published or the publish run's deliveries",
        ),
        subrequests: 2.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::HealthProbe,
        route: "GET /api/v1/scheduler/health",
        // `api::scheduler_health` makes one scheduler call, the
        // `GET /health` read of state the object already holds —
        // `no-store`, so no cache answers it in the object's place.
        forwards: &[call("GET /health", 1)],
        claims: 0.0,
        worker_requests: 1.0,
        cpu: CpuPricing::Unmeasured("no lane drives GET /api/v1/scheduler/health"),
        subrequests: 1.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::HumanTask,
        route: "human-lane tasks (inside a claim)",
        forwards: &[],
        claims: 0.0,
        worker_requests: 0.0,
        cpu: CpuPricing::NoWorkerRequest,
        subrequests: 0.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::Build,
        route: "dispatched builds (claim marginal)",
        forwards: &[],
        claims: 1.0,
        worker_requests: 0.0,
        cpu: CpuPricing::NoWorkerRequest,
        subrequests: 0.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::BuildCallback,
        route: "POST /api/v1/github/workflow-run",
        // One task is one `build-crate.yml` run the scheduler
        // dispatched: GitHub delivers each of its actions to the
        // Worker, and the webhook forwards what `OWN_BUILD_RUN` says —
        // the `completed` alone (stow#940). The completion's inline
        // dispatch is the build's claim, priced under `Build`. Worker
        // CPU is priced at the `completed` delivery's measured cost for
        // every delivery — the heaviest of the three, so an upper bound.
        forwards: &[
            call(
                "POST /tasks/run-update (in_progress)",
                forwards::OWN_BUILD_RUN.in_progress,
            ),
            call(
                "POST /tasks/complete-run (success)",
                forwards::OWN_BUILD_RUN.completed,
            ),
        ],
        claims: 0.0,
        worker_requests: RUN_DELIVERIES,
        cpu: CpuPricing::Lanes(&[("workflow-callback", RUN_DELIVERIES)]),
        subrequests: 1.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::AlarmPass,
        route: "scheduler alarm pass",
        // Cloudflare's DO request billing explicitly includes alarm
        // invocations (HTTP requests, RPC sessions, WebSocket messages,
        // alarm invocations) — the pass is a billed request.
        forwards: &[call("alarm pass (idle)", 1)],
        claims: 0.0,
        worker_requests: 0.0,
        cpu: CpuPricing::NoWorkerRequest,
        subrequests: 0.0,
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
                        sql_rows_read: row.sql_rows_read as f64,
                        sql_rows_written: row.sql_rows_written as f64,
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
            sql_rows_read: (hot.sql_rows_read - idle.sql_rows_read).max(0.0) / claimed,
            sql_rows_written: (hot.sql_rows_written - idle.sql_rows_written).max(0.0) / claimed,
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

    /// What one event of `cost`'s kind costs the scheduler: its
    /// forwards' rows times their share, plus the claim price times its
    /// claims.
    fn event(&self, cost: &EventCost) -> Result<DriveCost, String> {
        let mut total = DriveCost::default();
        for forward in cost.forwards {
            total.add(forward.share, &self.drive(forward.row)?);
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
        self.sql_rows_read = calls.mul_add(other.sql_rows_read, self.sql_rows_read);
        self.sql_rows_written = calls.mul_add(other.sql_rows_written, self.sql_rows_written);
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
    /// The Cloudflare product: `workers`, `durable_objects`.
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
    /// `WORKER_CPU_BUDGETS` rows, each in the run's milliseconds: the
    /// relative budget times the run's reference).
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
    /// Diagnostic-only dimensions (subrequests, R2 ops).
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
    /// Projected monthly subrequests — diagnostic, not gated.
    diag_subrequests: f64,
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
                budget_ms = events.mul_add(cpu.lane_budget_ms(lane)?, budget_ms);
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
    projection.do_requests = monthly.mul_add(cost.do_requests(), projection.do_requests);
    projection.diag_subrequests = monthly.mul_add(cost.subrequests, projection.diag_subrequests);
    projection.diag_r2_ops = monthly.mul_add(cost.r2_ops, projection.diag_r2_ops);
    let kind_cpu_ms = fold_cpu(cost, cpu, monthly, projection)?;
    projection.worker_cpu_ms = monthly.mul_add(kind_cpu_ms, projection.worker_cpu_ms);
    let kind = drives.event(cost)?;
    projection.do_rows_read = monthly.mul_add(kind.rows_read, projection.do_rows_read);
    projection.do_rows_written = monthly.mul_add(kind.rows_written, projection.do_rows_written);
    projection.do_wall_s += monthly * kind.wall_ms / 1000.0;
    // The route's heaviest dimension decides its allowance share — the
    // number the top-N table ranks.
    let shares = [
        (
            "do_requests",
            monthly * cost.do_requests() / DO_REQUESTS_MONTHLY,
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
            // product prefix — `do_`, `worker_`.
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
    /// One wave's or one resubmit's measured per-node cost scaled to
    /// the production wave's node count and over its [`PREHEAT_BUDGET`]
    /// share — the totals bound the `Preheat cost` report cannot check
    /// itself, because the production count only exists here (stow#883).
    pub preheat_breaches: Vec<Breach>,
    /// The projection from the small report — the clean fixture.
    pub projection: GateEvaluation,
    /// The projection from the post-load report.
    pub projection_after_load: GateEvaluation,
}

impl ProjectionReport {
    /// Every failure, one line each.
    fn failures(&self) -> Vec<String> {
        let mut failures: Vec<String> = self
            .preheat_breaches
            .iter()
            .map(|breach| {
                format!(
                    "preheat budget: {} {:.3e} over bound {:.3e}",
                    breach.dimension, breach.projected, breach.bound
                )
            })
            .collect();
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

/// One preheat phase's measured per-node cost scaled to the production
/// wave's node count, against its [`PREHEAT_BUDGET`] share of the
/// allowance — a breach per over-budget dimension. `per-node × prod`
/// versus `share × monthly` is the same bound the per-run totals check
/// enforced at a checked-in wave-size constant; only the denominator
/// changed from that constant to the measured production wave
/// (stow#883).
#[allow(
    clippy::cast_precision_loss,
    reason = "node counts stay far below f64's exact-integer range"
)]
fn preheat_breaches(preheat: &PreheatMonthly) -> Vec<Breach> {
    let nodes = preheat.production_nodes as f64;
    let wave = PREHEAT_BUDGET.wave();
    let resubmit = PREHEAT_BUDGET.resubmit();
    let mut breaches = Vec::new();
    for (dimension, projected, bound) in [
        ("wave rows_read", preheat.wave.rows_read * nodes, wave.0),
        (
            "wave rows_written",
            preheat.wave.rows_written * nodes,
            wave.1,
        ),
        (
            "resubmit rows_read",
            preheat.resubmit.rows_read * nodes,
            resubmit.0,
        ),
        (
            "resubmit rows_written",
            preheat.resubmit.rows_written * nodes,
            resubmit.1,
        ),
    ] {
        if projected > bound {
            breaches.push(Breach {
                product: "durable_objects",
                dimension,
                projected,
                traffic: 0.0,
                preheat: projected,
                bound,
                top_route: PREHEAT_ROUTE,
            });
        }
    }
    breaches
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
        preheat_breaches: preheat_breaches(&preheat),
        projection: evaluate(model, small, cpu, &preheat)?,
        projection_after_load: evaluate(model, after, cpu, &preheat)?,
        preheat,
    })
}

/// Human rendering of the preheat share: its scale, the measured
/// per-node costs it multiplies, and the `build-crate.yml` runs the
/// measured phases dispatched.
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
        "runs",
    ]);
    for (label, cost, tasks) in [
        ("wave", &preheat.wave, preheat.wave_tasks),
        ("resubmit", &preheat.resubmit, preheat.resubmit_tasks),
    ] {
        table.push([
            label.to_owned(),
            format!("{:.2}", cost.requests),
            format!("{:.2}", cost.rows_read),
            format!("{:.2}", cost.rows_written),
            tasks.to_string(),
        ]);
    }
    let _ = writeln!(out, "{}", table.render());
    let mut budgets = Table::new(&[
        "at production",
        "rows read",
        "budget",
        "rows written",
        "budget",
    ]);
    let wave = PREHEAT_BUDGET.wave();
    let resubmit = PREHEAT_BUDGET.resubmit();
    for (label, cost, budget) in [
        ("wave", &preheat.wave, wave),
        ("resubmit", &preheat.resubmit, resubmit),
    ] {
        #[allow(
            clippy::cast_precision_loss,
            reason = "node counts stay far below f64's exact-integer range"
        )]
        let nodes = preheat.production_nodes as f64;
        budgets.push([
            label.to_owned(),
            format!("{:.3e}", cost.rows_read * nodes),
            format!("{budget:.3e}", budget = budget.0),
            format!("{:.3e}", cost.rows_written * nodes),
            format!("{budget:.3e}", budget = budget.1),
        ]);
    }
    let _ = write!(out, "{}", budgets.render());
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
        "bound (80%)",
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
    use crate::traffic_cost::preheat::{PerNode, PreheatMonthly};
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
            wave_tasks: 0,
            resubmit_tasks: 0,
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
            preheat_breaches: super::preheat_breaches(preheat),
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
        // `x` rows per node and phase is `20 x` a month. The fits case
        // must also stay under each phase's `PREHEAT_BUDGET` share at
        // the production node count — the resubmit's hundredth of the
        // wave share is the tighter bound, at 10 nodes a per-node cap
        // of `resubmit / 10`.
        let resubmit_cap = super::PREHEAT_BUDGET.resubmit().1 / 10.0;
        let fits = rows_written_per_node((headroom * 0.4 / 10.0).min(resubmit_cap * 0.9));
        let report = project_with(&small, &after, &preheat_of(fits, fits), &cpu).expect("project");
        assert!(report.failures().is_empty(), "{:?}", report.failures());

        // A month of preheat as large as the whole allowance: over the
        // bound, and larger than the traffic it joins. Each phase also
        // breaches its `PREHEAT_BUDGET` share at production scale.
        let overflows = rows_written_per_node(line.allowance / 20.0);
        let report =
            project_with(&small, &after, &preheat_of(overflows, overflows), &cpu).expect("project");
        assert_eq!(
            report.preheat_breaches.len(),
            2,
            "{:?}",
            report.preheat_breaches
        );
        let failures = report.failures();
        assert_eq!(
            failures.len(),
            4,
            "2 budgets + clean and post-load: {failures:?}"
        );
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
        // A hot alarm pass written cost far past its budget lifts the DO
        // rows_written projection past its bound.
        let report = fixture_report(
            100_000,
            |name| if name == "alarm pass" { 100_000.0 } else { 0.5 },
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
    fn every_event_cost_forward_has_a_report_row() {
        let report = fixture_report(100_000, |_| 0.5);
        let names: std::collections::BTreeSet<&str> =
            report.rows.iter().map(|row| row.name.as_str()).collect();
        for cost in super::EVENT_COSTS {
            for forward in cost.forwards {
                assert!(
                    names.contains(forward.row),
                    "no report row for `{}`",
                    forward.row
                );
            }
        }
    }

    fn cost_of(kind: stow_types::launch_model::EventKind) -> &'static super::EventCost {
        super::EVENT_COSTS
            .iter()
            .find(|cost| cost.kind == kind)
            .expect("every priced kind has a cost row")
    }

    /// A build run bills the Worker one request per `workflow_run`
    /// delivery and the object what the webhook forwards for a run the
    /// scheduler dispatched — the `completed` alone (stow#937,
    /// stow#940). Both come from `OWN_BUILD_RUN`, which the edge's
    /// webhook test holds to the handler, so a handler that forwards
    /// another delivery moves this price with it.
    #[test]
    fn a_build_run_prices_its_forwards_and_its_deliveries() {
        use stow_types::forwards::{OWN_BUILD_RUN, RunForwards};
        let cost = cost_of(stow_types::launch_model::EventKind::BuildCallback);
        assert!((cost.do_requests() - f64::from(OWN_BUILD_RUN.total())).abs() < 1e-12);
        assert!((cost.do_requests() - 1.0).abs() < 1e-12);
        assert!((cost.worker_requests - f64::from(RunForwards::DELIVERIES)).abs() < 1e-12);
        assert!((cost.worker_requests - 3.0).abs() < 1e-12);
        // Each forwarded action is a whole call to the route that
        // serves it; the `requested` delivery has no route.
        assert_eq!(OWN_BUILD_RUN.requested, 0);
        let row = |name: &str| {
            cost.forwards
                .iter()
                .find(|forward| forward.row == name)
                .expect("forward row")
                .requests
        };
        assert!(
            (row("POST /tasks/run-update (in_progress)") - f64::from(OWN_BUILD_RUN.in_progress))
                .abs()
                < 1e-12
        );
        assert!(
            (row("POST /tasks/complete-run (success)") - f64::from(OWN_BUILD_RUN.completed)).abs()
                < 1e-12
        );
    }

    /// A human request's lifecycle is three scheduler calls whether its
    /// resolve run succeeds or fails, and five Worker requests on the
    /// success path the projection prices.
    #[test]
    fn a_human_request_prices_its_whole_lifecycle() {
        use stow_types::forwards::{human_request_forwards, human_request_worker_requests};
        let cost = cost_of(stow_types::launch_model::EventKind::HumanRequest);
        for success in [true, false] {
            assert!(
                (cost.do_requests() - f64::from(human_request_forwards(success))).abs() < 1e-12,
                "success = {success}"
            );
        }
        assert!((cost.do_requests() - 3.0).abs() < 1e-12);
        assert!(
            (cost.worker_requests - f64::from(human_request_worker_requests(true))).abs() < 1e-12
        );
        assert!((cost.worker_requests - 5.0).abs() < 1e-12);
    }

    /// The per-request counts of the events whose handler is a single
    /// scheduler call, and of the alarm pass.
    #[test]
    fn single_call_events_bill_one_scheduler_request() {
        use stow_types::launch_model::EventKind;
        for (kind, do_requests, worker_requests) in [
            (EventKind::EnqueueRedemption, 1.0, 1.0),
            (EventKind::RequestStatusRead, 1.0, 1.0),
            (EventKind::AdminOperation, 1.0, 1.0),
            (EventKind::IndexPublish, 1.0, 4.0),
            (EventKind::HealthProbe, 1.0, 1.0),
            (EventKind::AlarmPass, 1.0, 0.0),
            (EventKind::Admission, 0.0, 1.0),
            (EventKind::MissNode, 0.0, 0.0),
        ] {
            let cost = cost_of(kind);
            assert!(
                (cost.do_requests() - do_requests).abs() < 1e-12,
                "{kind:?}: {}",
                cost.do_requests()
            );
            assert!(
                (cost.worker_requests - worker_requests).abs() < 1e-12,
                "{kind:?}: {}",
                cost.worker_requests
            );
        }
    }

    /// The health probe is priced at the once-a-minute cadence stow#940
    /// set: 43,200 DO and Worker requests a month on the checked-in
    /// model.
    #[test]
    fn the_health_probe_costs_43_200_requests_a_month() {
        let model = model();
        let probes = model.monthly_events(stow_types::launch_model::EventKind::HealthProbe);
        assert!((probes - 43_200.0).abs() < 1e-9, "{probes}");
        let cost = cost_of(stow_types::launch_model::EventKind::HealthProbe);
        assert!(probes.mul_add(cost.do_requests(), -43_200.0).abs() < 1e-9);
        assert!(probes.mul_add(cost.worker_requests, -43_200.0).abs() < 1e-9);
    }

    /// The DO request line is the sum over every event of its monthly
    /// count times its forwards — so removing a priced forward lowers
    /// it by exactly that event's volume.
    #[test]
    fn the_do_request_line_sums_every_events_forwards() {
        let report = fixture_report(100_000, |_| 0.5);
        let evaluation =
            evaluate(&model(), &report, &fixture_cpu(|_| 0.5), &no_preheat()).expect("evaluate");
        let expected: f64 = super::EVENT_COSTS
            .iter()
            .map(|cost| model().monthly_events(cost.kind) * cost.do_requests())
            .sum();
        let line = usage(&evaluation, "durable_objects", "requests");
        assert!((line.traffic - expected).abs() < 1e-6, "{}", line.traffic);
        // Every event kind the model counts is priced exactly once.
        let mut kinds: Vec<String> = super::EVENT_COSTS
            .iter()
            .map(|cost| format!("{:?}", cost.kind))
            .collect();
        let total = kinds.len();
        kinds.sort();
        kinds.dedup();
        assert_eq!(kinds.len(), total, "an event kind priced twice");
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
