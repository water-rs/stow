//! `stow-admin launch-gate` — the stow#452 deterministic launch-cost
//! gate.
//!
//! The gate multiplies the launch model's per-event monthly counts by
//! the per-event costs the `scheduler-budget` job measured in the same
//! CI run (`budget-report.json`), and fails the job when any projected
//! monthly usage exceeds its allowance. Nothing it reads is a checked-in
//! constant: the report's `*_budget` columns carry the in-code budget
//! each row was measured against, and the allowance lines come from
//! `watchdog`'s single allowance table.
//!
//! The Durable-Object numbers decompose per event kind rather than per
//! route: an alarm invocation is billed duration and rows but no
//! request, so the alarm lane is priced as `alarm pass (idle)`
//! invocations plus one claim's marginal cost per dispatched build —
//! the difference between the hot and idle pass rows, spread over the
//! claims the fixture fills.

use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::Args;
use stow_types::api::SchedulerBudgetReport;
use stow_types::launch_model::{EventKind, LaunchModel};
use stow_types::stow_error;

use crate::render::{Output, Table, emit};
use crate::watchdog::{
    D1_ROWS_READ_MONTHLY, D1_ROWS_WRITTEN_MONTHLY, DO_DURATION_GB_S_MONTHLY, DO_REQUESTS_MONTHLY,
    DO_ROWS_READ_MONTHLY, DO_ROWS_WRITTEN_MONTHLY, WORKER_CPU_MS_MONTHLY, WORKER_REQUESTS_MONTHLY,
};

/// The launch gate — `stow-admin launch-gate --report
/// budget-report-100000.json --model launch-model.toml`.
#[derive(Debug, Args)]
pub struct LaunchGateArgs {
    /// The `scheduler-budget` harness report from this CI run.
    #[arg(long)]
    pub report: PathBuf,
    /// The checked-in launch model `launch-model.toml`.
    #[arg(long, default_value = "launch-model.toml")]
    pub model: PathBuf,
}

/// The gate fires when a product's projected monthly usage exceeds this
/// fraction of its included allowance — stow#452 fixes half.
const ALLOWANCE_FRACTION: f64 = 0.5;

/// GB-s each serialized DO wall second is priced at. Cloudflare bills
/// Durable Object duration in GB-seconds of the isolate's memory
/// footprint; a single-object isolate is priced here at 0.25 GB — a
/// deliberate over-read of the ~128 MB a hot isolate measures, so the
/// projection errs on the bill's side.
const DO_DURATION_GB_PER_WALL_S: f64 = 0.25;

/// Claims the fixture's hot `"alarm pass"` row makes per pass —
/// `STOW_MAX_CONCURRENT_JOBS` (45) minus `FixtureShape::IN_FLIGHT_ROWS`
/// (30) open dispatch slots. The marginal claim price is `(hot − idle)
/// / HOT_PASS_CLAIMS` for each measured column.
const HOT_PASS_CLAIMS: f64 = 15.0;

/// The issue's peak requirement: a peak-second's serialized Durable
/// Object wall must stay under half a second.
const PEAK_SERIALIZED_S_PER_S: f64 = 0.5;

/// The edge's per-request CPU ceiling — a per-request sanity bound, not
/// a monthly projection (stow#452: "no route's per-request CPU may
/// approach its limit").
const REQUEST_CPU_LIMIT_MS: f64 = 15_000.0;

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
}

/// One traffic kind's fixed cost vector. `drives` names the report rows
/// the event invokes; `claims` the dispatches inside the pass lane it
/// causes (only [`EventKind::Build`] — one claim each). Everything else
/// is a per-event constant measured from the route itself.
#[derive(Debug, Clone, Copy)]
struct EventCost {
    /// The traffic kind this prices.
    kind: EventKind,
    /// The route label the report table prints.
    route: &'static str,
    /// (report row, calls per event).
    drives: &'static [(&'static str, f64)],
    /// Billed DO requests the drive calls count as — alarm invocations
    /// are not requests, so `false` for the alarm lane.
    do_requests: f64,
    /// Dispatches the event causes inside a scheduler pass.
    claims: f64,
    /// Billed worker requests per event (index pulls are two).
    worker_requests: f64,
    /// Worker CPU milliseconds per event.
    worker_cpu_ms: f64,
    /// Subrequests per event — collected, never gated (Workers Paid
    /// bills no subrequest dimension).
    subrequests: f64,
    /// D1 `rows_read` per event.
    d1_rows_read: f64,
    /// D1 `rows_written` per event.
    d1_rows_written: f64,
    /// R2 ops per event — zero today; the dimension stays in the
    /// report so a route that adds one is visible.
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
        route: "GET /api/v1/bundles/{digest}",
        drives: &[],
        do_requests: 0.0,
        claims: 0.0,
        worker_requests: 1.0,
        worker_cpu_ms: 3.0,
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
        worker_cpu_ms: 3.0,
        subrequests: 2.0,
        d1_rows_read: 0.0,
        d1_rows_written: 0.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::Admission,
        route: "POST /api/v1/admissions (+miss drain)",
        drives: &[("POST /enqueue (untrusted)", 1.0)],
        do_requests: 1.0,
        claims: 0.0,
        worker_requests: 1.0,
        worker_cpu_ms: 40.0,
        subrequests: 2.0,
        d1_rows_read: 64.0,
        d1_rows_written: 3.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::EnqueueRedemption,
        route: "POST /api/v1/enqueue",
        drives: &[("GET /status", 1.0), ("POST /enqueue (untrusted)", 1.0)],
        do_requests: 2.0,
        claims: 0.0,
        worker_requests: 1.0,
        worker_cpu_ms: 8.0,
        subrequests: 0.0,
        d1_rows_read: 1.0,
        d1_rows_written: 5.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::HumanRequest,
        route: "POST /api/v1/requests",
        drives: &[("POST /admin/enqueue (trusted)", 1.0)],
        do_requests: 1.0,
        claims: 0.0,
        worker_requests: 1.0,
        worker_cpu_ms: 50.0,
        subrequests: 3.0,
        d1_rows_read: 1.0,
        d1_rows_written: 10.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::RequestStatusRead,
        route: "GET /api/v1/requests/{id}",
        drives: &[("GET /tasks/status (batch)", 1.0)],
        do_requests: 1.0,
        claims: 0.0,
        worker_requests: 1.0,
        worker_cpu_ms: 5.0,
        subrequests: 0.0,
        d1_rows_read: 5.0,
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
        worker_cpu_ms: 3.0,
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
        worker_cpu_ms: 10.0,
        subrequests: 0.0,
        d1_rows_read: 30.0,
        d1_rows_written: 1.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::MissNode,
        route: "miss nodes (AE — no route)",
        drives: &[],
        do_requests: 0.0,
        claims: 0.0,
        worker_requests: 0.0,
        worker_cpu_ms: 0.0,
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
        worker_cpu_ms: 5.0,
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
        worker_cpu_ms: 10.0,
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
        worker_cpu_ms: 0.0,
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
        worker_cpu_ms: 0.0,
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
        worker_cpu_ms: 15.0,
        subrequests: 4.0,
        d1_rows_read: 2.0,
        d1_rows_written: 15.0,
        r2_ops: 0.0,
    },
    EventCost {
        kind: EventKind::AlarmPass,
        route: "scheduler alarm pass",
        drives: &[("alarm pass (idle)", 1.0)],
        do_requests: 0.0,
        claims: 0.0,
        worker_requests: 0.0,
        worker_cpu_ms: 0.0,
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

/// The gate's verdict: every usage line, the peak check, the top-N
/// routes and any breaches.
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
    /// Diagnostic-only dimensions (subrequests, R2 ops).
    pub diagnostics: Vec<UsageLine>,
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
/// report's top-N table.
#[derive(Debug, Default)]
struct Projection {
    /// Projected monthly worker requests.
    worker_requests: f64,
    /// Projected monthly worker CPU milliseconds.
    worker_cpu_ms: f64,
    /// Projected monthly DO invocations.
    do_requests: f64,
    /// Projected monthly DO rows read.
    do_rows_read: f64,
    /// Projected monthly DO rows written.
    do_rows_written: f64,
    /// Projected monthly DO wall seconds — duration is billed on this.
    do_wall_s: f64,
    /// Projected monthly D1 rows read.
    d1_read: f64,
    /// Projected monthly D1 rows written.
    d1_written: f64,
    /// Projected monthly subrequests — diagnostic, not gated.
    subrequests: f64,
    /// Projected monthly R2 ops — diagnostic, not gated.
    r2_ops: f64,
    /// Serialized scheduler wall milliseconds per second at peak —
    /// the stow#452 serialization bound's numerator.
    peak_serialized_ms: f64,
    /// One share entry per event kind, for the top-N table.
    per_route: Vec<RouteShare>,
}

/// Fold one event kind's monthly and peak counts into the projection.
/// Returns the route's heaviest allowance share.
fn fold_kind(
    model: &LaunchModel,
    cost: &EventCost,
    drive: &dyn Fn(&'static str) -> Result<DriveCost, String>,
    claim_marginal: &DriveCost,
    projection: &mut Projection,
) -> Result<(), String> {
    let monthly = model.monthly_events(cost.kind);
    let peak_per_s = model.peak_events_per_second(cost.kind);
    projection.worker_requests = monthly.mul_add(cost.worker_requests, projection.worker_requests);
    projection.worker_cpu_ms = monthly.mul_add(cost.worker_cpu_ms, projection.worker_cpu_ms);
    projection.do_requests = monthly.mul_add(cost.do_requests, projection.do_requests);
    projection.subrequests = monthly.mul_add(cost.subrequests, projection.subrequests);
    projection.r2_ops = monthly.mul_add(cost.r2_ops, projection.r2_ops);
    projection.d1_read = monthly.mul_add(cost.d1_rows_read, projection.d1_read);
    projection.d1_written = monthly.mul_add(cost.d1_rows_written, projection.d1_written);
    let mut kind_read = 0.0;
    let mut kind_written = 0.0;
    let mut kind_wall_ms = 0.0;
    for (name, calls) in cost.drives {
        let row = drive(name)?;
        kind_read = calls.mul_add(row.rows_read, kind_read);
        kind_written = calls.mul_add(row.rows_written, kind_written);
        kind_wall_ms = calls.mul_add(row.wall_ms, kind_wall_ms);
    }
    kind_read = cost.claims.mul_add(claim_marginal.rows_read, kind_read);
    kind_written = cost
        .claims
        .mul_add(claim_marginal.rows_written, kind_written);
    kind_wall_ms = cost.claims.mul_add(claim_marginal.wall_ms, kind_wall_ms);
    projection.do_rows_read = monthly.mul_add(kind_read, projection.do_rows_read);
    projection.do_rows_written = monthly.mul_add(kind_written, projection.do_rows_written);
    projection.do_wall_s += monthly * kind_wall_ms / 1000.0;
    projection.peak_serialized_ms = peak_per_s.mul_add(kind_wall_ms, projection.peak_serialized_ms);
    if cost.worker_cpu_ms >= REQUEST_CPU_LIMIT_MS {
        return Err(format!(
            "route `{}` projects {:.0}ms worker CPU per request — over the {REQUEST_CPU_LIMIT_MS:.0}ms request limit",
            cost.route, cost.worker_cpu_ms
        ));
    }
    // The route's heaviest dimension decides its allowance share — the
    // number the top-N table ranks.
    let shares = [
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
            monthly * cost.worker_cpu_ms / WORKER_CPU_MS_MONTHLY,
        ),
        (
            "d1_rows_read",
            monthly * cost.d1_rows_read / D1_ROWS_READ_MONTHLY,
        ),
        (
            "d1_rows_written",
            monthly * cost.d1_rows_written / D1_ROWS_WRITTEN_MONTHLY,
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

/// The product/dimension rows the gate bounds, projected by `fold`.
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

/// Ungated dimensions printed for context only — the issue's
/// allowances do not cover them, but the table does.
fn diagnostic_lines(projection: &Projection) -> Vec<UsageLine> {
    vec![
        UsageLine {
            product: "workers",
            dimension: "subrequests",
            projected: projection.subrequests,
            allowance: f64::INFINITY,
        },
        UsageLine {
            product: "r2",
            dimension: "ops",
            projected: projection.r2_ops,
            allowance: f64::INFINITY,
        },
    ]
}

/// Project the launch model's monthly events against the measured
/// report rows and the watchdog allowance table.
#[expect(
    clippy::cast_precision_loss,
    reason = "measured counters fit f64 exactly past any launch traffic"
)]
fn evaluate(model: &LaunchModel, report: &SchedulerBudgetReport) -> Result<GateEvaluation, String> {
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
    // The claims inside a hot pass are what the hot row buys over the
    // idle floor, spread over the slots the fixture fills.
    let claim_marginal = DriveCost {
        rows_read: (hot.rows_read - idle.rows_read).max(0.0) / HOT_PASS_CLAIMS,
        rows_written: (hot.rows_written - idle.rows_written).max(0.0) / HOT_PASS_CLAIMS,
        wall_ms: (hot.wall_ms - idle.wall_ms).max(0.0) / HOT_PASS_CLAIMS,
    };

    let mut projection = Projection::default();
    for cost in EVENT_COSTS {
        fold_kind(model, cost, &drive, &claim_marginal, &mut projection)?;
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
        breaches,
    })
}

/// Human rendering — the per-product projection table, the peak check,
/// the top-5 routes and the verdict.
fn render_evaluation(evaluation: &GateEvaluation) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
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
    let mut diag = Table::new(&["diagnostics (unbilled)", "projected/mo"]);
    for line in &evaluation.diagnostics {
        diag.push([line.dimension.to_owned(), format!("{:.3e}", line.projected)]);
    }
    let _ = writeln!(out, "\n{}", diag.render());
    if evaluation.passes() {
        let _ = writeln!(out, "\nlaunch-cost gate: PASS");
    } else {
        let _ = writeln!(out, "\nlaunch-cost gate: FAIL");
        for breach in &evaluation.breaches {
            let _ = writeln!(
                out,
                "  {} {} projected {:.3e} exceeds bound {:.3e} — driver: {}",
                breach.product, breach.dimension, breach.projected, breach.bound, breach.top_route
            );
        }
    }
    out
}

/// `stow-admin launch-gate` — evaluate and exit nonzero on a breach.
pub fn run(args: &LaunchGateArgs, output: Output) -> stow_types::error::Result<()> {
    let report_text = std::fs::read_to_string(&args.report)
        .map_err(|error| stow_error!("read budget report {}: {error}", args.report.display()))?;
    let report: SchedulerBudgetReport = serde_json::from_str(&report_text)
        .map_err(|error| stow_error!("parse budget report {}: {error}", args.report.display()))?;
    let model_text = std::fs::read_to_string(&args.model)
        .map_err(|error| stow_error!("read launch model {}: {error}", args.model.display()))?;
    let model = LaunchModel::from_toml(&model_text)
        .map_err(|error| stow_error!("load launch model {}: {error}", args.model.display()))?;
    let evaluation = evaluate(&model, &report).map_err(|error| stow_error!("{error}"))?;
    emit(output, &evaluation, render_evaluation)?;
    if evaluation.passes() {
        Ok(())
    } else {
        Err(stow_error!(
            "launch-cost gate: {} dimension(s) over bound",
            evaluation.breaches.len()
        ))
    }
}

#[cfg(test)]
mod tests {
    use stow_types::api::{SchedulerBudgetReport, SchedulerBudgetRow};
    use stow_types::do_budgets::DO_BUDGETS;
    use stow_types::launch_model::LaunchModel;

    use super::{evaluate, render_evaluation};

    /// A fixture report built on the absolute budget bounds: every
    /// drive's measurement sits at half its budget — the ~2× headroom
    /// the `DO_BUDGETS` table documents — so the fixture is the harness
    /// report a healthy run produces.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "fixture counters sit far inside both types' ranges"
    )]
    fn fixture_report(scale: impl Fn(&str) -> f64) -> SchedulerBudgetReport {
        SchedulerBudgetReport {
            queue_rows: 100_000,
            schema_version: 5,
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
                        statement_budget: budget.statements,
                        read_budget: budget.rows_read,
                        write_budget: budget.rows_written,
                        wall_budget: budget.wall_ms,
                        over_budget: factor > 1.0,
                        log: Vec::new(),
                    }
                })
                .collect(),
        }
    }

    /// The checked-in model — the gate test reads the real file so a
    /// regenerated model is always what the fixture is judged against.
    const MODEL_TOML: &str = include_str!("../../launch-model.toml");

    #[test]
    fn fixture_report_passes_the_gate() {
        let model = LaunchModel::from_toml(MODEL_TOML).expect("model");
        let report = fixture_report(|_| 0.5);
        let evaluation = evaluate(&model, &report).expect("evaluate");
        assert!(evaluation.passes(), "{}", render_evaluation(&evaluation));
        let rendered = render_evaluation(&evaluation);
        assert!(rendered.contains("launch-cost gate: PASS"), "{rendered}");
    }

    #[test]
    fn an_raised_drive_cost_fails_the_gate() {
        let model = LaunchModel::from_toml(MODEL_TOML).expect("model");
        // 30× the hot alarm pass's written cost lifts the DO
        // rows_written projection past its bound.
        let report = fixture_report(|name| if name == "alarm pass" { 15.0 } else { 0.5 });
        let evaluation = evaluate(&model, &report).expect("evaluate");
        assert!(!evaluation.passes(), "{}", render_evaluation(&evaluation));
        let rendered = render_evaluation(&evaluation);
        assert!(rendered.contains("launch-cost gate: FAIL"), "{rendered}");
        assert!(
            rendered.contains("durable_objects rows_written"),
            "{rendered}"
        );
    }

    #[test]
    fn every_event_cost_drive_has_a_report_row() {
        let report = fixture_report(|_| 0.5);
        let names: std::collections::BTreeSet<&str> =
            report.rows.iter().map(|row| row.name.as_str()).collect();
        for cost in super::EVENT_COSTS {
            for (name, _) in cost.drives {
                assert!(names.contains(name), "no report row for `{name}`");
            }
        }
    }
}
