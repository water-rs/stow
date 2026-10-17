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

/// The scheduler cost one preheat wave and one daily resubmit may spend
/// — the `Preheat cost` lane's (stow#773) totals gate.
///
/// Derived from the Workers Paid allowance above and the two mechanisms
/// that already divide it:
///
/// - **The in-edge cost breaker** freezes dispatch once a UTC day's
///   billed rows pass a thirtieth of the monthly allowance
///   (`edge/src/scheduler/meter.rs`, `daily_budget`, at the production
///   multiplier of 1). A wave that crosses it stops itself mid-graph.
/// - **The launch gate** (stow#452) holds projected user traffic at half
///   of every allowance — half of each day's thirtieth.
///
/// So a wave gets the other half of one day: `1/30 × 1/2 = 1/60` of the
/// monthly allowance, and a full wave completes inside it in one go —
/// spreading a wave over several days is not an option. A wave that
/// does not fit is a scheduler spending too many rows per node. The daily resubmit (`preheat-cron.yml` fires every day)
/// lands on a graph that is already built: its work is recognising
/// that, so it is held to a hundredth of a wave — room to read its own
/// batches, none to rebuild or rewrite the graph.
///
/// Both shares are per node, over [`Self::FULL_WAVE_NODES`]: a run of
/// `n` nodes is held to `n / FULL_WAVE_NODES` of the share, so a
/// per-node cost that would overrun the full wave fails a reduced-scale
/// run too.
#[derive(Debug, Clone, Copy)]
pub struct PreheatBudget {
    /// Fraction of each monthly allowance one full wave may spend.
    pub wave_share: f64,
    /// Fraction of the wave's share one resubmit may spend.
    pub resubmit_of_wave: f64,
}

impl PreheatBudget {
    /// Nodes in a full production wave: the top-100 crates, the
    /// top-100 binaries' and the curated projects' lockfiles, resolved
    /// across every `CI_TARGET_TRIPLES` entry (stow#773's measured
    /// order of magnitude). The per-node share divides by it.
    pub const FULL_WAVE_NODES: f64 = 16_000.0;

    /// The (`rowsRead`, `rowsWritten`) one wave of `nodes` may spend.
    #[must_use]
    pub fn wave(&self, nodes: u64) -> (f64, f64) {
        Self::share(self.wave_share, nodes)
    }

    /// The (`rowsRead`, `rowsWritten`) one resubmit over `nodes` may
    /// spend.
    #[must_use]
    pub fn resubmit(&self, nodes: u64) -> (f64, f64) {
        Self::share(self.wave_share * self.resubmit_of_wave, nodes)
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "node counts stay far below f64's exact-integer range"
    )]
    fn share(share: f64, nodes: u64) -> (f64, f64) {
        let fraction = nodes as f64 / Self::FULL_WAVE_NODES;
        (
            DO_ROWS_READ_MONTHLY * share * fraction,
            DO_ROWS_WRITTEN_MONTHLY * share * fraction,
        )
    }
}

/// The preheat lane's split of the allowance — see [`PreheatBudget`].
pub const PREHEAT_BUDGET: PreheatBudget = PreheatBudget {
    wave_share: 1.0 / 60.0,
    resubmit_of_wave: 0.01,
};

/// The flatness tolerance the stow#433 scale check applies between
/// fixture sizes (`scripts/scheduler-budget.sh`): a per-event cost may
/// exceed its smaller-size value by this fraction ...
pub const GROWTH_TOLERANCE_FRACTION: f64 = 0.10;
/// ... plus this many rows.
pub const GROWTH_TOLERANCE_ROWS: f64 = 50.0;

/// `true` when `later` exceeds `earlier` past the stow#433 tolerance.
#[must_use]
pub fn grew(earlier: f64, later: f64) -> bool {
    later > earlier.mul_add(1.0 + GROWTH_TOLERANCE_FRACTION, GROWTH_TOLERANCE_ROWS)
}

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
        statements: 4,
        rows_read: 100,
        rows_written: 0,
        wall_ms: 100,
    },
    DriveBudget {
        name: "GET /admin/status",
        statements: 8,
        rows_read: 8_000,
        rows_written: 0,
        wall_ms: 200,
    },
    DriveBudget {
        name: "GET /tasks",
        statements: 3,
        rows_read: 2_000,
        rows_written: 0,
        wall_ms: 150,
    },
    DriveBudget {
        name: "GET /tasks?status=failed",
        statements: 3,
        rows_read: 2_000,
        rows_written: 0,
        wall_ms: 150,
    },
    DriveBudget {
        name: "GET /tasks?status=pending",
        statements: 3,
        rows_read: 2_000,
        rows_written: 0,
        wall_ms: 150,
    },
    DriveBudget {
        name: "GET /tasks?status=blocked",
        statements: 3,
        rows_read: 5_000,
        rows_written: 0,
        wall_ms: 200,
    },
    DriveBudget {
        name: "GET /tasks?target=…",
        statements: 3,
        rows_read: 2_000,
        rows_written: 0,
        wall_ms: 150,
    },
    DriveBudget {
        name: "GET /tasks?crate=…",
        statements: 3,
        rows_read: 600,
        rows_written: 0,
        wall_ms: 150,
    },
    DriveBudget {
        name: "GET /tasks?older_than=86400",
        statements: 3,
        rows_read: 2_000,
        rows_written: 0,
        wall_ms: 150,
    },
    DriveBudget {
        name: "GET /tasks?task_ids=…",
        statements: 3,
        rows_read: 100,
        rows_written: 0,
        wall_ms: 100,
    },
    DriveBudget {
        // The success arm also lands the bounded build-cost sample and
        // keyed dispatch-key refresh (stow#524): the sample window caps
        // at BUILD_SAMPLE_WINDOW rows per (crate, target) and the
        // refresh touches only that key's pending set.
        name: "POST /tasks/complete-run",
        statements: 16,
        rows_read: 300,
        rows_written: 300,
        wall_ms: 400,
    },
    DriveBudget {
        // The failure arm: same report resolution plus the dependents'
        // `blocked`-flag refresh — bounded by the failed row's
        // dependents, never the queue.
        name: "POST /tasks/complete-run (failure)",
        statements: 12,
        rows_read: 400,
        rows_written: 200,
        wall_ms: 300,
    },
    DriveBudget {
        name: "POST /tasks/retry",
        statements: 4,
        rows_read: 200,
        rows_written: 100,
        wall_ms: 200,
    },
    DriveBudget {
        name: "POST /tasks/cancel",
        statements: 4,
        rows_read: 200,
        rows_written: 100,
        wall_ms: 200,
    },
    DriveBudget {
        name: "POST /tasks/promote",
        statements: 4,
        rows_read: 200,
        rows_written: 100,
        wall_ms: 200,
    },
    DriveBudget {
        name: "POST /tasks/purge",
        statements: 4,
        rows_read: 200,
        rows_written: 100,
        wall_ms: 200,
    },
    DriveBudget {
        // An `enqueued` record's read: the row select, the stored-roots
        // parse and the live `tasks_status` re-probe — the pending human
        // root's lane-position walk dominates, bounded by the held lane
        // depth.
        name: "GET /requests/{id}",
        statements: 8,
        rows_read: 2_600,
        rows_written: 0,
        wall_ms: 200,
    },
    DriveBudget {
        // The request lane's admission: the freeze and human-budget
        // probes, the deduping insert, the credential read and the one
        // serialized `workflow_dispatch` hop — wall carries the HTTP.
        name: "POST /requests",
        statements: 10,
        rows_read: 100,
        rows_written: 10,
        wall_ms: 600,
    },
    DriveBudget {
        // The row read plus the conditional `accepted -> resolving`
        // update that stamps the run identity.
        name: "POST /requests/{id}/run-update (in_progress)",
        statements: 3,
        rows_read: 20,
        rows_written: 4,
        wall_ms: 150,
    },
    DriveBudget {
        // A `Resolved` report on a live record: the pre/post status
        // probes, the trusted enqueue of a one-dep batch and the
        // conditional `enqueued` write — the same insert machinery the
        // submit drives price, at this batch's size.
        name: "POST /requests/{id}/outcome",
        statements: 18,
        rows_read: 2_600,
        rows_written: 200,
        wall_ms: 600,
    },
    DriveBudget {
        // `completed` on an already-`enqueued` record — the row read plus
        // the one conditional update that correctly writes nothing.
        name: "POST /requests/{id}/run-update (completed)",
        statements: 3,
        rows_read: 20,
        rows_written: 4,
        wall_ms: 150,
    },
    DriveBudget {
        // The pending-depth check reads the trigger-maintained
        // `queue_status_counts` row — a handful of rows at any queue
        // size. The human-lane position walk is bounded by the lane's
        // depth, held at `FixtureShape::HUMAN_LANE_ROWS` across sizes.
        name: "POST /enqueue (untrusted)",
        statements: 4,
        rows_read: 2_200,
        rows_written: 10,
        wall_ms: 300,
    },
    DriveBudget {
        // The accept half of the untrusted route — the cap is lifted so
        // the drive measures the insert: the pending-count read, the
        // human-lane budget charge and position walk (bounded by the
        // lane's held depth), the task + edge writes.
        name: "POST /enqueue (untrusted accept)",
        statements: 20,
        rows_read: 2_500,
        rows_written: 600,
        wall_ms: 600,
    },
    DriveBudget {
        name: "POST /admin/enqueue (trusted)",
        statements: 16,
        rows_read: 300,
        rows_written: 400,
        wall_ms: 400,
    },
    DriveBudget {
        // submit-by-id (stow#588): resync-path writes; the walk reads
        // scale with the submitted ids' stored subgraphs.
        name: "POST /admin/enqueue (submit-ids)",
        statements: 24,
        rows_read: 2_000,
        rows_written: 110,
        wall_ms: 500,
    },
    DriveBudget {
        // Fully deduplicated resubmit (stow#784): an update is emitted
        // only when a request changes stored state, so the measured
        // shape is the status probe plus the task_nodes conflict
        // probes — and zero writes.
        name: "POST /admin/enqueue (resubmit)",
        statements: 4,
        rows_read: 100,
        rows_written: 0,
        wall_ms: 400,
    },
    DriveBudget {
        // The route's full statement count is apply (8) + `next_alarm`
        // (5): the batch probes, ledger write, settings reads and the
        // plan's freeze/active-count/wake/lease reads — 13 measured at
        // the 100k native gate (121 reads, 17 writes).
        name: "POST /demand",
        statements: 14,
        rows_read: 300,
        rows_written: 120,
        wall_ms: 500,
    },
    DriveBudget {
        // The whole route (stow#785): the report — with the
        // commit-time shape repair — plus the `dispatch_pending`
        // claiming tail. The 100k workerd lane measured 36
        // statements, 622 reads and 407 writes.
        name: "POST /index/published (full)",
        statements: 60,
        rows_read: 800,
        rows_written: 600,
        wall_ms: 500,
    },
    DriveBudget {
        // The delta's gate writes are the matched edges' `dep_met`
        // flips plus their owners' `unpublished_deps` adjustments —
        // 1 + the delta's direct dependents, never the queue or the
        // graph (stow#521) — plus the report-time repair, which can
        // requeue the deps the retire uncovered, and the claiming
        // tail. `rowsRead` counts workerd's internal index seeks:
        // the per-edge `dep_match` probes, the slice-row
        // re-evaluation per matched edge and the owner PK seeks.
        // The 100k workerd lane measured 39 statements, 1177 reads
        // and 614 writes.
        name: "POST /index/published (delta)",
        statements: 70,
        rows_read: 1_400,
        rows_written: 900,
        wall_ms: 500,
    },
    DriveBudget {
        // The full dispatch pass: binding reads, the claim paged at
        // `2 × open slots`, the per-page catalog coverage lookup (a
        // counted-D1 read, not object rows), the per-claim UPDATE and
        // the bounded-concurrent `trigger_build` hop — wall includes
        // the fan-out's slowest HTTP leg. The subgraph rebuild's
        // `task_nodes` walk is bounded by the claimed tasks' own
        // dependency closure (stow#588) — the fixture pins that closure
        // to `{claimed, one leaf}` at every size, so this row measures
        // stored bulk only and the scale check must report it flat.
        name: "alarm pass",
        statements: 120,
        rows_read: 1_000,
        rows_written: 700,
        wall_ms: 3_000,
    },
    DriveBudget {
        // The same pass with dispatch paused: the claim returns early,
        // so the row measures the per-invocation floor — stale-recovery
        // probes, the freeze and binding reads, the wake-time re-arm —
        // that every alarm wake pays regardless of what it claims. The
        // launch gate (stow#452) separates alarm invocations from the
        // claims they make through this row. The `claimed_at` lease
        // probes (re-arm MIN and the stale-recovery DELETE/UPDATE) read
        // the in-flight set — bounded by the dispatch cap
        // (`STOW_MAX_CONCURRENT_JOBS`), not by a stale-row range
        // (stow#786).
        name: "alarm pass (idle)",
        statements: 20,
        rows_read: 320,
        rows_written: 8,
        wall_ms: 300,
    },
    DriveBudget {
        // One real dispatch pass over the floored queue — the same
        // claim/dispatch/plan surface as the hot pass, priced
        // separately so the gate sees the planner and claim walk
        // under a positive persisted floor with under-floor bulk
        // deferred in the flags (stow#525). Setup stamps and teardown
        // restore live outside the metered window. The `task_nodes`
        // walk shares the hot pass's bound — the claimed tasks'
        // dependency closure, which the fixture pins flat (stow#588).
        name: "alarm pass (floor claim)",
        statements: 120,
        rows_read: 1_000,
        rows_written: 700,
        wall_ms: 3_000,
    },
    // The demand-feed caps below are native-calibrated (stow#523):
    // measured workerd billed rows on the fixture's fixed 384-task
    // delivery event, plus stated headroom where a shared planner
    // cost scales with the dispatch cap rather than the event. The
    // 31 existing budgets stay unchanged.
    DriveBudget {
        // The resume-cursor read: one watermark probe plus one
        // unfinished-index probe — flat in retained depth.
        name: "GET /scheduler/demand-feed/status",
        statements: 4,
        rows_read: 8,
        rows_written: 0,
        wall_ms: 40,
    },
    DriveBudget {
        // Fresh open: watermark guard, header insert, generation
        // read-back.
        name: "POST /scheduler/demand-feed/begin (fresh)",
        statements: 8,
        rows_read: 8,
        rows_written: 3,
        wall_ms: 60,
    },
    DriveBudget {
        // Restart with real debris: generation bump/counter reset
        // plus one full 256-row obsolete retire chunk and the
        // pending probe. Native-billed 1028 reads (the indexed
        // retire probe reads one archived page row per deleted key)
        // and 257 writes — flat at both fixture shapes.
        name: "POST /scheduler/demand-feed/begin (rotation)",
        statements: 14,
        rows_read: 1_250,
        rows_written: 520,
        wall_ms: 120,
    },
    DriveBudget {
        // One staged page: guards plus the payload insert whose
        // trigger bumps counters.
        name: "POST /scheduler/demand-feed/page (append)",
        statements: 6,
        rows_read: 8,
        rows_written: 5,
        wall_ms: 60,
    },
    DriveBudget {
        // Same-bytes replay: bounded reads, zero writes.
        name: "POST /scheduler/demand-feed/page (replay)",
        statements: 6,
        rows_read: 8,
        rows_written: 0,
        wall_ms: 50,
    },
    DriveBudget {
        // Completion barrier, populated hour: manifest verification
        // plus the guarded freeze.
        name: "POST /scheduler/demand-feed/complete (nonempty)",
        statements: 8,
        rows_read: 8,
        rows_written: 3,
        wall_ms: 60,
    },
    DriveBudget {
        // The same barrier with an empty generation.
        name: "POST /scheduler/demand-feed/complete (empty)",
        statements: 8,
        rows_read: 8,
        rows_written: 3,
        wall_ms: 50,
    },
    DriveBudget {
        // One page-apply delivery at the protocol's maximum
        // 256-entry page: the bounded next-page SELECT, the
        // `demand_pass` closure over the entries' touched
        // dependency graph — the drive's fixed event walks 384
        // pending tasks on 512 edges, not merely the 256 roots —
        // the ack flip and the wake re-plan, whose alarm probe cost
        // is bounded by the dispatch cap. Native-billed
        // 274/7188/3078 flat at both fixture shapes; the caps
        // carry ~22% headroom over the measured event.
        name: "POST /scheduler/demand-feed/deliver (page apply)",
        statements: 550,
        rows_read: 8_750,
        rows_written: 3_750,
        wall_ms: 600,
    },
    DriveBudget {
        // The terminal call — transition-only after every page has
        // applied: its probes plus the contiguous-watermark
        // `delivered` transition. Native-billed 11/151/2 — of which
        // ~141 reads are the shared wake planner's alarm probe over
        // the fixture's 30 in-flight rows — so the cap reserves
        // explicit headroom toward the production dispatch cap of
        // 45 rather than a native-45 measurement.
        name: "POST /scheduler/demand-feed/deliver (terminal)",
        statements: 18,
        rows_read: 250,
        rows_written: 4,
        wall_ms: 200,
    },
    DriveBudget {
        // Delivered-hour replay: the `delivered` early-out plus the
        // wake re-plan. Native-billed 6/143/0 — the same shared
        // wake-planner probe, so the cap carries the same
        // dispatch-cap headroom as the terminal call.
        name: "POST /scheduler/demand-feed/deliver (replay)",
        statements: 12,
        rows_read: 250,
        rows_written: 0,
        wall_ms: 80,
    },
    DriveBudget {
        // One full retirable chunk: `DELETE … LIMIT 256` plus its
        // probes — flat in archive depth. Native-billed 1026 reads
        // (the same indexed retire probe as rotation) and 256
        // writes — flat at both fixture shapes.
        name: "POST /scheduler/demand-feed/cleanup (full chunk)",
        statements: 8,
        rows_read: 1_250,
        rows_written: 260,
        wall_ms: 200,
    },
    DriveBudget {
        // The retire probe on an all-live generation.
        name: "POST /scheduler/demand-feed/cleanup (none obsolete)",
        statements: 8,
        rows_read: 8,
        rows_written: 2,
        wall_ms: 60,
    },
];

/// One traffic lane's Worker CPU budget — milliseconds of isolate CPU
/// per lane event, measured by the Traffic cost test's profiler pass
/// (`stow-admin traffic-cost cpu`).
///
/// The measured quantity is the CPU the edge isolate spends executing
/// one event, sampled by V8's profiler through the dev inspector — the
/// Worker's own handler plus any scheduler Durable Object code the event
/// runs, which shares the isolate under `wrangler dev`. It therefore
/// reads at or above the Worker CPU Cloudflare bills for the event,
/// never below it.
#[derive(Debug, Clone, Copy)]
pub struct WorkerCpuBudget {
    /// The lane (`admin/src/traffic_cost/lanes.rs`) — the report row's
    /// key.
    pub lane: &'static str,
    /// Budgeted CPU milliseconds per lane event.
    pub cpu_ms: f64,
}

impl WorkerCpuBudget {
    /// `true` when the measured per-event CPU exceeds the budget.
    #[must_use]
    pub fn over_budget(&self, cpu_ms: f64) -> bool {
        cpu_ms > self.cpu_ms
    }
}

/// The Worker CPU budget table, one row per traffic lane. A lane the
/// profiler pass measures without a row here fails the test, as a
/// scheduler route without a drive does.
///
/// How a row's number is derived: the lane's measured CPU per event —
/// the smallest of the profiler pass's three rounds in a Traffic cost
/// run, read from that run's `worker-cpu.json` — times a 2× margin,
/// rounded up to the next 5 ms. The 2× is the same headroom `DO_BUDGETS`
/// keeps over its measured rows: room for ordinary code growth, while a
/// change that doubles a lane's CPU fails. Each row's comment names the
/// run and the measured value it came from.
///
/// A budget is also bounded by the allowance, not only by the
/// measurement: `stow-admin traffic-cost project` prices every route
/// at its full budget under the launch model and fails when that month
/// passes half of the Worker CPU allowance (`cpu_ms_at_budget`), and
/// prints each route's share of the allowance at its measured figure
/// and at its budget.
pub const WORKER_CPU_BUDGETS: &[WorkerCpuBudget] = &[
    WorkerCpuBudget {
        // Run 39009034210: 0.38 ms.
        lane: "site",
        cpu_ms: 5.0,
    },
    WorkerCpuBudget {
        // Run 39009034210: 2.165 ms.
        lane: "stats",
        cpu_ms: 5.0,
    },
    WorkerCpuBudget {
        // The pointer GET plus the digest-addressed slice GET.
        // Run 39009034210: 2.1 ms.
        lane: "index-pull",
        cpu_ms: 5.0,
    },
    WorkerCpuBudget {
        // A covered bundle streamed through the byte path — the
        // dominant CPU line at 9e5 events/mo. stow#738 measured 11–24 ms
        // mean on the deployed Worker, far above this local figure.
        // Run 39009034210: 0.595 ms.
        lane: "bundle-fetch",
        cpu_ms: 5.0,
    },
    WorkerCpuBudget {
        // Run 39009034210: 1.38 ms.
        lane: "status-read",
        cpu_ms: 5.0,
    },
    WorkerCpuBudget {
        // Run 39009034210: 3.06 ms.
        lane: "admin-status",
        cpu_ms: 10.0,
    },
    WorkerCpuBudget {
        // Run 39009034210: 5.475 ms.
        lane: "queue-read",
        cpu_ms: 15.0,
    },
    WorkerCpuBudget {
        // Run 39009034210: 5.395 ms.
        lane: "queue-mutate",
        cpu_ms: 15.0,
    },
    WorkerCpuBudget {
        // Run 39009034210: 4.345 ms.
        lane: "trusted-submit",
        cpu_ms: 10.0,
    },
    WorkerCpuBudget {
        // Run 39009034210: 1.64 ms.
        lane: "admission",
        cpu_ms: 5.0,
    },
    WorkerCpuBudget {
        // Run 39009034210: 5.915 ms.
        lane: "enqueue-redeem",
        cpu_ms: 15.0,
    },
    WorkerCpuBudget {
        // The signed `workflow_run` callback: HMAC check, the records
        // artifact's cosign verification, and the completion.
        // Run 39009034210: 3.185 ms.
        lane: "workflow-callback",
        cpu_ms: 10.0,
    },
];
