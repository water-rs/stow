//! The traffic-cost budget tables, shared as data: the scheduler
//! Durable Object drives' row budgets and the traffic lanes' Worker CPU
//! budgets.
//!
//! Data only, so it compiles on every target and every consumer (the
//! edge's probe routes and host drift gate, the admin crate's budget
//! renderer, and the traffic-cost projection and CPU pass) reads the
//! same tables.

/// Durable Objects `rowsRead` included per month on Workers Paid (SQLite
/// storage billing): 25 billion.
/// <https://developers.cloudflare.com/durable-objects/platform/pricing/>
pub const DO_ROWS_READ_MONTHLY: f64 = 25e9;
/// Durable Objects `rowsWritten` included per month on Workers Paid:
/// 50 million — the scarcer of the two by three orders of magnitude, so
/// every write budget below is the one that binds first.
pub const DO_ROWS_WRITTEN_MONTHLY: f64 = 50e6;

/// The probe ledger's key for the scheduler alarm — the dispatch pass,
/// which has no route of its own. Every other ledger key is the
/// scheduler route as `<METHOD> <path>`.
pub const LEDGER_OP_ALARM: &str = "alarm";

/// The probe ledger's key for a build run's completion — the scheduler
/// route `POST /tasks/complete-run`, whose task id rides the body, so
/// every run's completion lands on one row.
pub const LEDGER_OP_TASK_COMPLETE: &str = "POST /tasks/complete-run";

/// The one cost line every allowance consumer derives from (stow#883):
/// each metered Cloudflare resource stays under 80% of its monthly
/// Workers Paid allowance (AGENTS.md).
///
/// The release gate's monthly projection bounds each product's total —
/// user traffic plus preheat — at this fraction of its allowance
/// (`stow-admin traffic-cost project`); the in-edge breaker and the
/// preheat budget derive from it through [`DAILY_SHARE`].
pub const ALLOWANCE_FRACTION: f64 = 0.8;

/// One UTC day's share of the line — `ALLOWANCE_FRACTION / 30`.
///
/// The in-edge cost breaker freezes dispatch once a UTC day's billed
/// rows pass this share of the monthly allowance
/// (`edge/src/scheduler/meter.rs`, [`daily_budget`]), so a sustained
/// burn at the line's pace trips within a day; and one preheat wave's
/// share is one day of the line (`PREHEAT_BUDGET`) — a wave must
/// complete inside a day.
pub const DAILY_SHARE: f64 = ALLOWANCE_FRACTION / 30.0;

/// The in-edge breaker's daily budget on `monthly`: one thirtieth of
/// the line, scaled by `STOW_COST_BUDGET_MULTIPLIER` so a shared
/// account can trip earlier.
#[must_use]
pub const fn daily_budget(monthly: f64, multiplier: f64) -> f64 {
    monthly * DAILY_SHARE * multiplier
}

/// The scheduler cost one preheat wave and one daily resubmit may spend
/// — the totals bound the monthly projection enforces at the measured
/// production wave's node count (stow#773, stow#883).
///
/// - **The wave** may spend one day of the line — [`DAILY_SHARE`] of the
///   monthly allowance — because a wave must complete inside a day;
///   spreading one over several days is not an option. A wave that does
///   not fit is a scheduler spending too many rows per node. User
///   traffic rides the same day's budget, so a wave plus a day of
///   line-pace traffic can cross the in-edge breaker's daily threshold:
///   the measured traffic share is far below the line, and the breaker
///   is the runtime guard for the day that stops being true.
/// - **The daily resubmit** (`preheat-cron.yml` fires every day) lands
///   on a graph that is already built: its work is recognising that, so
///   it is held to a hundredth of a wave — room to read its own runs,
///   none to rebuild or rewrite the graph.
///
/// The bound is evaluated where the measurement exists: the `Preheat
/// cost` report carries the measured per-node costs and the monthly
/// projection scales them to `production-wave.json`'s node count — a
/// per-node cost that would overrun the production wave fails there,
/// not against a checked-in wave size.
#[derive(Debug, Clone, Copy)]
pub struct PreheatBudget {
    /// Fraction of each monthly allowance one full production wave may
    /// spend.
    pub wave_share: f64,
    /// Fraction of the wave's share one resubmit may spend.
    pub resubmit_of_wave: f64,
}

impl PreheatBudget {
    /// The (`rowsRead`, `rowsWritten`) one production wave may spend.
    #[must_use]
    pub fn wave(&self) -> (f64, f64) {
        (
            DO_ROWS_READ_MONTHLY * self.wave_share,
            DO_ROWS_WRITTEN_MONTHLY * self.wave_share,
        )
    }

    /// The (`rowsRead`, `rowsWritten`) one production resubmit may
    /// spend.
    #[must_use]
    pub fn resubmit(&self) -> (f64, f64) {
        (
            DO_ROWS_READ_MONTHLY * self.wave_share * self.resubmit_of_wave,
            DO_ROWS_WRITTEN_MONTHLY * self.wave_share * self.resubmit_of_wave,
        )
    }
}

/// The preheat lane's split of the allowance — see [`PreheatBudget`].
pub const PREHEAT_BUDGET: PreheatBudget = PreheatBudget {
    wave_share: DAILY_SHARE,
    resubmit_of_wave: 0.01,
};

/// One probe budget row — statements, cursor counters and wall time.
///
/// These are the numbers that gate a merge: each was measured on the
/// 100k fixture under workerd and carries ~2× headroom. A drive that
/// goes queue-size-proportional exceeds its row by orders of magnitude,
/// not by slack. `wall_ms` is the serialized-Duration piece of the
/// stow#452 launch projection: the single object's pass can never run
/// in parallel with itself.
#[derive(Debug, Clone, Copy)]
pub struct DriveBudget {
    /// The route or pass the drive exercises — the report row's key.
    pub name: &'static str,
    /// Budgeted statement count.
    pub statements: u64,
    /// Budgeted `rowsRead` total.
    pub rows_read: u64,
    /// Budgeted `rowsWritten` total.
    pub rows_written: u64,
    /// Budgeted wall milliseconds.
    pub wall_ms: u64,
}

impl DriveBudget {
    /// `true` when the measured counts exceed a gated dimension —
    /// statements, `rowsRead`, or `rowsWritten`. Wall time is not in
    /// this set; see [`Self::over_wall`].
    #[must_use]
    pub const fn over_budget(&self, statements: u64, rows_read: u64, rows_written: u64) -> bool {
        statements > self.statements
            || rows_read > self.rows_read
            || rows_written > self.rows_written
    }

    /// `true` when the measured wall exceeded this budget — reported
    /// but never gated: the local workerd lane's `wall_ms` is mostly
    /// the in-window `db.sync()` durability barrier on the runner's
    /// own SQLite, storage latency rather than the code's cost
    /// (stow#567).
    #[must_use]
    pub const fn over_wall(&self, wall_ms: u64) -> bool {
        wall_ms > self.wall_ms
    }
}

/// The flatness tolerance a scale check applies between two fixture
/// sizes or wave layers (stow#433, stow#785): a per-event cost may
/// exceed its earlier value by this fraction ...
pub const GROWTH_TOLERANCE_FRACTION: f64 = 0.10;
/// ... plus this many rows.
pub const GROWTH_TOLERANCE_ROWS: f64 = 50.0;

/// `true` when `later` exceeds `earlier` past the growth tolerance —
/// the "same per event at every layer" assertion `stow#785` applies
/// to the alarm pass, slice report and submit reads.
#[must_use]
pub fn grew(earlier: f64, later: f64) -> bool {
    later > earlier.mul_add(1.0 + GROWTH_TOLERANCE_FRACTION, GROWTH_TOLERANCE_ROWS)
}

/// The workerd budget table the host gate carries.
///
/// Measured in the units Cloudflare bills, filled from the harness's
/// reported measurements; a regression fails `stow-admin scheduler
/// budget` nonzero.
pub const DO_BUDGETS: &[DriveBudget] = &[
    DriveBudget {
        name: "GET /status",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 100,
    },
    DriveBudget {
        name: "GET /health",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 100,
    },
    DriveBudget {
        name: "GET /admin/status",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 200,
    },
    DriveBudget {
        name: "GET /tasks",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 150,
    },
    DriveBudget {
        name: "GET /tasks?status=failed",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 150,
    },
    DriveBudget {
        name: "GET /tasks?status=pending",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 150,
    },
    DriveBudget {
        name: "GET /tasks?status=blocked",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 200,
    },
    DriveBudget {
        name: "GET /tasks?target=…",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 150,
    },
    DriveBudget {
        name: "GET /tasks?crate=…",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 150,
    },
    DriveBudget {
        name: "GET /tasks?older_than=86400",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 150,
    },
    DriveBudget {
        name: "GET /tasks?task_ids=…",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 100,
    },
    DriveBudget {
        name: "POST /tasks/retry",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 200,
    },
    DriveBudget {
        name: "POST /tasks/cancel",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 200,
    },
    DriveBudget {
        name: "POST /tasks/promote",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 200,
    },
    DriveBudget {
        name: "POST /tasks/purge",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 200,
    },
    DriveBudget {
        name: "GET /requests/{id}",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 200,
    },
    DriveBudget {
        name: "POST /requests",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 600,
    },
    DriveBudget {
        name: "POST /requests/{id}/run-update (in_progress)",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 150,
    },
    DriveBudget {
        name: "POST /requests/{id}/outcome",
        statements: 4,
        rows_read: 6,
        rows_written: 6,
        wall_ms: 600,
    },
    DriveBudget {
        name: "POST /requests/{id}/run-update (completed)",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 150,
    },
    DriveBudget {
        name: "POST /enqueue (untrusted)",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 300,
    },
    DriveBudget {
        name: "POST /enqueue (untrusted accept)",
        statements: 4,
        rows_read: 6,
        rows_written: 6,
        wall_ms: 600,
    },
    DriveBudget {
        name: "POST /admin/enqueue (trusted)",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 400,
    },
    DriveBudget {
        name: "POST /admin/enqueue (submit-ids)",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 500,
    },
    DriveBudget {
        name: "POST /admin/enqueue (resubmit)",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 400,
    },
    DriveBudget {
        name: "POST /tasks/submit (operations)",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 400,
    },
    DriveBudget {
        name: "POST /tasks/submit (preheat)",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 400,
    },
    DriveBudget {
        // The newreleases.io forward: signature already verified at the
        // edge, so the object only resolves its credential arm and
        // posts one `workflow_dispatch` — `preheat_release_pass` takes
        // no `DurableDb`, so the route bills no store row and the
        // settle writes none either (stow#931). The 0/0/0 is a code
        // read: the host drive's arm is a no-op, so its zero measures
        // nothing. The old 2/4/4 row was the removed `do_meter`
        // settle's, not this route's.
        name: "POST /preheat/release",
        statements: 0,
        rows_read: 0,
        rows_written: 0,
        wall_ms: 500,
    },
    DriveBudget {
        name: "POST /tasks/submit (inexact-hit)",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 400,
    },
    DriveBudget {
        name: "POST /demand",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 500,
    },
    DriveBudget {
        name: "POST /index/published (full)",
        statements: 4,
        rows_read: 6,
        rows_written: 6,
        wall_ms: 500,
    },
    DriveBudget {
        name: "POST /index/published (delta)",
        statements: 4,
        rows_read: 6,
        rows_written: 6,
        wall_ms: 500,
    },
    DriveBudget {
        name: "alarm pass (floor claim)",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 3,
    },
    DriveBudget {
        name: "alarm pass",
        statements: 4,
        rows_read: 6,
        rows_written: 6,
        wall_ms: 3,
    },
    DriveBudget {
        name: "alarm pass (idle)",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 300,
    },
    DriveBudget {
        name: "POST /tasks/complete-run (success)",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 400,
    },
    DriveBudget {
        name: "POST /tasks/complete-run (failure)",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 300,
    },
    DriveBudget {
        name: "POST /tasks/run-update (in_progress)",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 150,
    },
    DriveBudget {
        name: "alarm pass (stale recovery)",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 300,
    },
    DriveBudget {
        // stow#940 provisional: the completion's `RunFinished` append
        // (durable before the pass), then the inline pass's `Claims`
        // and `Bindings` — the host gate measured 3/3/3; the workerd
        // absolute awaits a mock-stack `stow-admin scheduler budget`
        // run.
        name: "POST /tasks/complete-run (dispatching)",
        statements: 5,
        rows_read: 7,
        rows_written: 7,
        wall_ms: 500,
    },
    DriveBudget {
        // stow#940 provisional: the slice append plus the inline
        // pass's `Claims` and `Bindings` — host-measured 3/3/3; the
        // workerd absolute awaits the same probe run.
        name: "POST /index/published (dispatching)",
        statements: 5,
        rows_read: 7,
        rows_written: 7,
        wall_ms: 500,
    },
    DriveBudget {
        // stow#940 provisional: the outcome's merge rows plus the
        // inline pass's `Claims` and `Bindings` — host-measured 3/3/3;
        // the workerd absolute awaits the same probe run.
        name: "POST /requests/{id}/outcome (dispatching)",
        statements: 5,
        rows_read: 7,
        rows_written: 7,
        wall_ms: 500,
    },
    DriveBudget {
        name: "GET /scheduler/demand-feed/status",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 40,
    },
    DriveBudget {
        name: "POST /scheduler/demand-feed/begin (fresh)",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 60,
    },
    DriveBudget {
        name: "POST /scheduler/demand-feed/begin (rotation)",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 120,
    },
    DriveBudget {
        name: "POST /scheduler/demand-feed/page (append)",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 60,
    },
    DriveBudget {
        name: "POST /scheduler/demand-feed/page (replay)",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 50,
    },
    DriveBudget {
        name: "POST /scheduler/demand-feed/complete (nonempty)",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 60,
    },
    DriveBudget {
        name: "POST /scheduler/demand-feed/complete (empty)",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 50,
    },
    DriveBudget {
        name: "POST /scheduler/demand-feed/deliver (page apply)",
        statements: 4,
        rows_read: 6,
        rows_written: 6,
        wall_ms: 600,
    },
    DriveBudget {
        name: "POST /scheduler/demand-feed/deliver (terminal)",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 200,
    },
    DriveBudget {
        name: "POST /scheduler/demand-feed/deliver (replay)",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 80,
    },
    DriveBudget {
        name: "POST /scheduler/demand-feed/cleanup (full chunk)",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 200,
    },
    DriveBudget {
        name: "POST /scheduler/demand-feed/cleanup (none obsolete)",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 60,
    },
    DriveBudget {
        name: "POST /tasks/submit (1k-node merge)",
        statements: 4,
        rows_read: 6,
        rows_written: 6,
        wall_ms: 5000,
    },
    DriveBudget {
        // stow#931 added the meter row's read and the wake
        // checkpoint's `UPDATE .. RETURNING` — +2 statements, +3
        // billed reads (the UPDATE reads the row it changes plus the
        // RETURNING row on workerd, release gate run 40186665163; the
        // host backend bills it identically), +1 billed write over
        // the pre-#931 row by construction. The workerd-scale absolute
        // stands for a mock-stack `stow-admin scheduler budget` run to
        // confirm.
        name: "wake (snapshot + log replay)",
        statements: 62,
        rows_read: 478,
        rows_written: 5,
        wall_ms: 5000,
    },
    DriveBudget {
        // stow#931 added the snapshot checkpoint's `UPDATE ..
        // RETURNING` after the covered-log drop — +1 statement, +2
        // billed reads (the changed row plus the RETURNING row,
        // release gate run 40186665163), +1 billed write by
        // construction; the host delta matches. The workerd-scale
        // absolute awaits the same mock-stack probe run.
        name: "snapshot write",
        statements: 67,
        rows_read: 481,
        rows_written: 533,
        wall_ms: 5000,
    },
];

/// One traffic lane's Worker CPU budget — isolate CPU per lane event,
/// relative to a fixed reference workload, measured by the Traffic cost
/// test's profiler pass (`stow-admin traffic-cost cpu`).
///
/// The measured quantity is the CPU the edge isolate spends executing
/// one event, sampled by V8's profiler through the dev inspector — the
/// Worker's own handler plus any scheduler Durable Object code the event
/// runs, which shares the isolate under `wrangler dev`. It therefore
/// reads at or above the Worker CPU Cloudflare bills for the event,
/// never below it.
///
/// Its milliseconds scale with the runner the pass lands on, so the
/// budget is not in milliseconds: the same pass profiles the reference
/// workload (`admin/src/traffic_cost/reference_workload.js`) in the same
/// isolate on the same runner, and a lane's figure is its CPU per event
/// over the reference's CPU. A budget of 0.25 lets one event spend a
/// quarter of what the reference spends, on whatever runner measures it.
#[derive(Debug, Clone, Copy)]
pub struct WorkerCpuBudget {
    /// The lane (`admin/src/traffic_cost/lanes.rs`) — the report row's
    /// key.
    pub lane: &'static str,
    /// Budgeted CPU per lane event over the reference workload's CPU.
    pub relative_cpu: f64,
}

impl WorkerCpuBudget {
    /// `true` when the measured per-event CPU, relative to the
    /// reference, exceeds the budget.
    #[must_use]
    pub fn over_budget(&self, relative_cpu: f64) -> bool {
        relative_cpu > self.relative_cpu
    }
}

/// The Worker CPU budget table, one row per traffic lane. A lane the
/// profiler pass measures without a row here fails the test, as a
/// scheduler route without a drive does.
///
/// How a row's number is derived: the lane's relative CPU per event —
/// the smallest of the profiler pass's three rounds over the reference,
/// read as `relative_cpu` from a Traffic cost run's `worker-cpu.json` —
/// times a 2× margin, rounded up to the next 0.05. The 2× is the same
/// headroom `DO_BUDGETS` keeps over its measured rows: room for ordinary
/// code growth, while a change that doubles a lane's CPU fails. Each
/// row's comment names the run and the measured value it came from.
///
/// A budget is also bounded by the allowance, not only by the
/// measurement: `stow-admin traffic-cost project` prices every route
/// at its full budget — in the run's milliseconds, the budget times that
/// run's reference — under the launch model, fails when that month
/// passes `ALLOWANCE_FRACTION` of the Worker CPU allowance
/// (`cpu_ms_at_budget`), and prints each route's share of the allowance
/// at its measured figure and at its budget.
pub const WORKER_CPU_BUDGETS: &[WorkerCpuBudget] = &[
    WorkerCpuBudget {
        // Run 40631853262: 0.027 (0.6 ms of a 22.2 ms reference).
        lane: "site",
        relative_cpu: 0.10,
    },
    WorkerCpuBudget {
        // Eight Analytics Engine SQL queries per page (stow#896);
        // Workers Cache serves the deployed route for an hour after
        // each. Run 40631853262: 0.149 (3.315 ms of 22.2 ms).
        lane: "stats",
        relative_cpu: 0.30,
    },
    WorkerCpuBudget {
        // The pointer GET plus the digest-addressed slice GET.
        // Run 40631853262: 0.118 (2.625 ms of 22.2 ms).
        lane: "index-pull",
        relative_cpu: 0.25,
    },
    WorkerCpuBudget {
        // A covered bundle streamed through the byte path — the
        // dominant CPU line at 9e5 events/mo. stow#738 measured 11–24 ms
        // mean on the deployed Worker, far above this local figure.
        // Run 40631853262: 0.041 (0.92 ms of 22.2 ms).
        lane: "bundle-fetch",
        relative_cpu: 0.10,
    },
    WorkerCpuBudget {
        // Provisional until a Traffic cost run measures the pending
        // index (stow#932). Run 40631853262 measured 0.214 (4.745 ms of
        // 22.2 ms) while `GET /status` and a human request's lane
        // position still walked the whole node arena.
        lane: "status-read",
        relative_cpu: 0.125,
    },
    WorkerCpuBudget {
        // Provisional until a Traffic cost run measures the pending
        // index (stow#932). Run 40631853262 measured 0.441 (9.8 ms of
        // 22.2 ms) while the counts and the oldest pending request still
        // walked the whole node arena.
        lane: "admin-status",
        relative_cpu: 0.25,
    },
    WorkerCpuBudget {
        // Run 40631853262: 0.319 (7.09 ms of 22.2 ms).
        lane: "queue-read",
        relative_cpu: 0.65,
    },
    WorkerCpuBudget {
        // Run 40631853262: 0.136 (3.025 ms of 22.2 ms).
        lane: "queue-mutate",
        relative_cpu: 0.30,
    },
    WorkerCpuBudget {
        // Run 40631853262: 0.118 (2.625 ms of 22.2 ms).
        lane: "trusted-submit",
        relative_cpu: 0.25,
    },
    WorkerCpuBudget {
        // Run 40631853262: 0.038 (0.85 ms of 22.2 ms).
        lane: "admission",
        relative_cpu: 0.10,
    },
    WorkerCpuBudget {
        // Run 40631853262: 0.113 (2.51 ms of 22.2 ms).
        lane: "enqueue-redeem",
        relative_cpu: 0.25,
    },
    WorkerCpuBudget {
        // The signed `workflow_run` callback: HMAC check, the run's
        // title decode and the forward to the scheduler.
        // Run 40631853262: 0.161 (3.575 ms of 22.2 ms).
        lane: "workflow-callback",
        relative_cpu: 0.35,
    },
];
