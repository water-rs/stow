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

/// The default cost line: 80% of the monthly Workers Paid allowance.
/// Durable Object requests use [`DO_REQUEST_ALLOWANCE_FRACTION`].
///
/// The release gate's monthly projection bounds other dimensions' totals —
/// user traffic plus preheat — at this fraction of its allowance
/// (`stow-admin traffic-cost project`); the in-edge breaker derives
/// its runtime daily guard from it through [`DAILY_SHARE`].
pub const ALLOWANCE_FRACTION: f64 = 0.8;

/// Monthly request budget for the scheduler Durable Object.
pub const DO_REQUEST_ALLOWANCE_FRACTION: f64 = 0.9;

/// One UTC day's share of the line — `ALLOWANCE_FRACTION / 30`.
///
/// A 31-day month at this pace reaches 82.7% of the allowance, not 80%;
/// the watchdog's month-to-date usage trips judge the real month total
/// against `ALLOWANCE_FRACTION`, so that overshoot is caught at the line
/// at run time and the breaker's daily share stays an early guard.
///
/// The in-edge cost breaker freezes dispatch once a UTC day's billed
/// rows pass this share of the monthly allowance
/// (`edge/src/scheduler/meter.rs`, [`daily_budget`]), so a sustained
/// burn at the line's pace trips within a day.
pub const DAILY_SHARE: f64 = ALLOWANCE_FRACTION / 30.0;

/// The in-edge breaker's daily budget on `monthly`: one thirtieth of
/// the line, scaled by `STOW_COST_BUDGET_MULTIPLIER` so a shared
/// account can trip earlier.
#[must_use]
pub const fn daily_budget(monthly: f64, multiplier: f64) -> f64 {
    monthly * DAILY_SHARE * multiplier
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

/// The two drives whose work is the graph's bulk.
///
/// The wake reads the snapshot and the snapshot write stores it, so
/// their rows follow the stored state. No scale check compares them
/// across fixture sizes; their row budgets bound them at every size a
/// gate runs.
pub const BULK_DRIVES: &[&str] = &["wake (snapshot + log replay)", "snapshot write"];

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
        // stow#1378: the in-flight rows' task ids are minted from their
        // digest rows in one statement. A digest read bills two rows
        // read (the `json_each` list row and the `node_digests` row;
        // the sqlite test backend's meter counts only the table row).
        // The bound is the in-flight section, at most the dispatch cap
        // (45 at the gate's settings): 4 + 2×45 reads, 2 + 1 statements.
        name: "GET /admin/status",
        statements: 3,
        rows_read: 94,
        rows_written: 4,
        wall_ms: 200,
    },
    DriveBudget {
        // stow#1378: a listing mints the task id of each unnamed row it
        // returns and, for a blocked row, its failed dependency's, from
        // digest rows in one statement; each digest read bills two rows
        // read (the list row and the table row; the sqlite test
        // backend's meter counts only the table row). The bound is
        // `ADMIN_LIST_LIMIT` (500) rows plus at most as many blocked-by
        // ids: 4 + 2×1,000 reads, 2 + 1 statements, at any population.
        name: "GET /tasks",
        statements: 3,
        rows_read: 2004,
        rows_written: 4,
        wall_ms: 150,
    },
    DriveBudget {
        // stow#1378: failed rows name no blocked-by id, so the bound is
        // `ADMIN_LIST_LIMIT` (500) digest reads of two rows each:
        // 4 + 2×500, 2 + 1.
        name: "GET /tasks?status=failed",
        statements: 3,
        rows_read: 1004,
        rows_written: 4,
        wall_ms: 150,
    },
    DriveBudget {
        // stow#1378: as the unfiltered listing — a pending row may be
        // blocked: 4 + 2×(500 rows + 500 blocked-by ids) reads,
        // 2 + 1 statements.
        name: "GET /tasks?status=pending",
        statements: 3,
        rows_read: 2004,
        rows_written: 4,
        wall_ms: 150,
    },
    DriveBudget {
        // stow#1378: as the unfiltered listing — every row is blocked
        // and names its failed dependency: 4 + 2×(500 + 500) reads,
        // 2 + 1 statements.
        name: "GET /tasks?status=blocked",
        statements: 3,
        rows_read: 2004,
        rows_written: 4,
        wall_ms: 200,
    },
    DriveBudget {
        // stow#1378: as the unfiltered listing: 4 + 2×(500 + 500)
        // reads, 2 + 1 statements.
        name: "GET /tasks?target=…",
        statements: 3,
        rows_read: 2004,
        rows_written: 4,
        wall_ms: 150,
    },
    DriveBudget {
        // stow#1378: a listing like the others, bounded by
        // `ADMIN_LIST_LIMIT` rather than by the name's version set:
        // 4 + 2×(500 + 500) reads, 2 + 1 statements.
        name: "GET /tasks?crate=…",
        statements: 3,
        rows_read: 2004,
        rows_written: 4,
        wall_ms: 150,
    },
    DriveBudget {
        // stow#1378: as the unfiltered listing: 4 + 2×(500 + 500)
        // reads, 2 + 1 statements.
        name: "GET /tasks?older_than=86400",
        statements: 3,
        rows_read: 2004,
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
        // stow#1378: the tree's fresh nodes upsert their digest rows (at
        // most the tree's 2 nodes: 2 written, 1 statement) and the
        // post-merge probe mints at most one blocked-by id per root
        // (2 roots: 2 read, 1 statement). A digest write bills two rows
        // read and one written, a digest read two rows read: 4 + 2
        // statements, 6 + 2×2 + 2×2 reads, 6 + 2 writes.
        name: "POST /requests/{id}/outcome",
        statements: 6,
        rows_read: 14,
        rows_written: 8,
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
        // stow#1378: the batch's fresh nodes (3 named nodes over its two
        // trees) upsert their digest rows in one statement; a digest
        // write bills two rows read and one written: 4 + 1 statements,
        // 6 + 2×3 reads, 6 + 3 writes.
        name: "POST /enqueue (untrusted accept)",
        statements: 5,
        rows_read: 12,
        rows_written: 9,
        wall_ms: 600,
    },
    DriveBudget {
        // stow#1378: as the untrusted accept — 3 fresh nodes, one digest
        // upsert statement: 3 + 1 statements, 5 + 2×3 reads, 5 + 3
        // writes.
        name: "POST /admin/enqueue (trusted)",
        statements: 4,
        rows_read: 11,
        rows_written: 8,
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
        // stow#1378: one fresh node, one digest upsert statement:
        // 3 + 1 statements, 5 + 2×1 reads (a digest write bills two
        // rows read), 5 + 1 writes.
        name: "POST /tasks/submit (operations)",
        statements: 4,
        rows_read: 7,
        rows_written: 6,
        wall_ms: 400,
    },
    DriveBudget {
        // stow#1378: as the operations lane — one fresh node.
        name: "POST /tasks/submit (preheat)",
        statements: 4,
        rows_read: 7,
        rows_written: 6,
        wall_ms: 400,
    },
    DriveBudget {
        // The resident graph checks its recovery fence in memory;
        // successful dispatch writes no log row. Cold recovery is
        // measured separately by the wake drive. A limit response
        // appends one recovery event instead of making more CI calls.
        name: "POST /preheat/release",
        statements: 0,
        rows_read: 0,
        rows_written: 0,
        wall_ms: 500,
    },
    DriveBudget {
        // Periodic dispatch shares release preheat's in-memory fence
        // and credential path. No successful-path SQL is added; cold
        // recovery belongs to the separate wake drive.
        name: "POST /periodic/dispatch",
        statements: 0,
        rows_read: 0,
        rows_written: 0,
        wall_ms: 500,
    },
    DriveBudget {
        // stow#1378: as the operations lane — one fresh node.
        name: "POST /tasks/submit (inexact-hit)",
        statements: 4,
        rows_read: 7,
        rows_written: 6,
        wall_ms: 400,
    },
    DriveBudget {
        // stow#1378: each task the batch touches mints its id from its
        // digest row in one statement; a digest read bills two rows
        // read. The drive's closure is its keyed root plus the root's
        // 11 unmet dependencies, a fixture constant: 5 + 2×12 reads,
        // 3 + 1 statements.
        name: "POST /demand",
        statements: 4,
        rows_read: 29,
        rows_written: 5,
        wall_ms: 500,
    },
    DriveBudget {
        // stow#1378: the inline claim pass mints the ids it claims from
        // their digest rows in one statement, two rows read per digest
        // read; claims are bounded by the dispatch cap (45 at the
        // gate's settings): 4 + 1 statements, 6 + 2×45 reads.
        name: "POST /index/published (full)",
        statements: 5,
        rows_read: 96,
        rows_written: 6,
        wall_ms: 500,
    },
    DriveBudget {
        // stow#1378: as the full report — claims bounded by the dispatch
        // cap: 4 + 1 statements, 6 + 2×45 reads.
        name: "POST /index/published (part)",
        statements: 5,
        rows_read: 96,
        rows_written: 6,
        wall_ms: 500,
    },
    DriveBudget {
        // stow#1378: as the full report — claims bounded by the dispatch
        // cap: 4 + 1 statements, 6 + 2×45 reads.
        name: "POST /index/published (delta)",
        statements: 5,
        rows_read: 96,
        rows_written: 6,
        wall_ms: 500,
    },
    DriveBudget {
        // stow#1378: the claim mints its ids from their digest rows in
        // one statement, two rows read per digest read, at most the
        // dispatch cap (45): 3 + 1 statements, 5 + 2×45 reads.
        name: "alarm pass (floor claim)",
        statements: 4,
        rows_read: 95,
        rows_written: 5,
        wall_ms: 3,
    },
    DriveBudget {
        // stow#1378: as the floor claim — claims bounded by the dispatch
        // cap (45): 4 + 1 statements, 6 + 2×45 reads.
        name: "alarm pass",
        statements: 5,
        rows_read: 96,
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
        name: "GET /dispatch-cap",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 300,
    },
    DriveBudget {
        // stow#1039 provisional: the `DispatchCap` append plus the
        // freed slots' `Claims` and `Bindings` — the same shape as
        // `POST /tasks/complete-run (dispatching)`; the workerd
        // absolute awaits a probe run.
        // stow#1378: its `Claims` mint their ids from digest rows, at
        // most the dispatch cap (45) in one statement, two rows read
        // per digest read: 5 + 1 statements, 7 + 2×45 reads.
        name: "POST /dispatch-cap",
        statements: 6,
        rows_read: 97,
        rows_written: 7,
        wall_ms: 500,
    },
    DriveBudget {
        name: "GET /release-priority",
        statements: 2,
        rows_read: 4,
        rows_written: 4,
        wall_ms: 300,
    },
    DriveBudget {
        // stow#1012 provisional: one `ReleasePriority` append and no
        // dispatch pass — ranks are read at claim time.
        name: "POST /release-priority",
        statements: 3,
        rows_read: 5,
        rows_written: 5,
        wall_ms: 400,
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
        // stow#1378: the re-claim mints its ids from digest rows, one
        // read each in one statement; the stale claims are in flight,
        // so at most the dispatch cap (45); two rows read per digest
        // read: 2 + 1 statements, 4 + 2×45 reads.
        name: "alarm pass (stale recovery)",
        statements: 3,
        rows_read: 94,
        rows_written: 4,
        wall_ms: 300,
    },
    DriveBudget {
        // stow#940 provisional: the completion's `RunFinished` append
        // (durable before the pass), then the inline pass's `Claims`
        // and `Bindings` — the host gate measured 3/3/3; the workerd
        // absolute awaits a mock-stack `stow-admin scheduler budget`
        // run.
        // stow#1378: the pass's claims mint their ids from digest rows,
        // at most the dispatch cap (45) in one statement, two rows
        // read per digest read: 5 + 1 statements, 7 + 2×45 reads.
        name: "POST /tasks/complete-run (dispatching)",
        statements: 6,
        rows_read: 97,
        rows_written: 7,
        wall_ms: 500,
    },
    DriveBudget {
        // stow#940 provisional: the slice append plus the inline
        // pass's `Claims` and `Bindings` — host-measured 3/3/3; the
        // workerd absolute awaits the same probe run.
        // stow#1378: claims bounded by the dispatch cap (45), one
        // statement, two rows read per digest read: 5 + 1 statements,
        // 7 + 2×45 reads.
        name: "POST /index/published (dispatching)",
        statements: 6,
        rows_read: 97,
        rows_written: 7,
        wall_ms: 500,
    },
    DriveBudget {
        // stow#940 provisional: the outcome's merge rows plus the
        // inline pass's `Claims` and `Bindings` — host-measured 3/3/3;
        // the workerd absolute awaits the same probe run.
        // stow#1378: the outcome's costs (2 fresh digest writes, 2
        // probe reads) plus claims bounded by the dispatch cap (45); a
        // digest write bills two rows read and one written, a digest
        // read two rows read: 5 + 3 statements, 7 + 2×2 + 2×2 + 2×45
        // reads, 7 + 2 writes.
        name: "POST /requests/{id}/outcome (dispatching)",
        statements: 8,
        rows_read: 105,
        rows_written: 9,
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
        // stow#1378: the page's demand pass mints the id of each task
        // it touches from its digest row, one read each in one
        // statement. The drive's 256-entry page walks a closure of
        // exactly 256 roots + 128 dependencies (the event graph's
        // construction); two rows read per digest read: 6 + 2×384
        // reads, 4 + 1 statements.
        name: "POST /scheduler/demand-feed/deliver (page apply)",
        statements: 5,
        rows_read: 774,
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
        // stow#1378: the merge upserts its fresh slots' digest rows in
        // the same turn; a digest write bills two rows read and one
        // written per fresh node. The tree has 1,000 fresh nodes
        // (`MERGE_NODES`), under the 4,096 a statement carries: 4 + 1
        // statements, 6 + 2×1,000 reads, 6 + 1,000 writes.
        name: "POST /tasks/submit (1k-node merge)",
        statements: 5,
        rows_read: 2006,
        rows_written: 1006,
        wall_ms: 5000,
    },
    DriveBudget {
        // stow#931 added the meter row's read and the wake
        // checkpoint's `UPDATE .. RETURNING` — +2 statements, +3
        // billed reads (the UPDATE reads the row it changes plus the
        // RETURNING row on workerd, release gate run 40186665163; the
        // host backend bills it identically), +1 billed write over
        // the pre-#931 row by construction.
        //
        // stow#1380: rows are billed, statements are not, and a
        // snapshot row is 64 KiB (`CHUNK_TEXT_BYTES`) read 16 to a
        // statement (`STATEMENT_ROWS`). The largest fixture the gate
        // seeds (1M queue rows, 721,412 nodes, ~87 MB of snapshot
        // text) is 1,415 rows on workerd (1,404 on the host): 1,325
        // full rows plus the closing row of each range. The bound is
        // 96 statements x 16 = 1,536 snapshot rows, 8.5% over that. The
        // log tail reads in pages of 16 rows (`LOG_PAGE_ROWS`); the
        // fixture's tail is bounded at 128 rows, eight full pages and
        // the short one that ends the read. Statements: 96 snapshot +
        // 1 watermark + 1 meter row + 9 tail pages + 1 checkpoint =
        // 108. Rows read: 1,536 snapshot + 128 tail + 1 watermark + 1
        // meter + 2 checkpoint (UPDATE .. RETURNING) = 1,668. Measured
        // on workerd: 98 statements, 1,517 rows read.
        name: "wake (snapshot + log replay)",
        statements: 108,
        rows_read: 1668,
        rows_written: 5,
        wall_ms: 5000,
    },
    DriveBudget {
        // stow#931 added the snapshot checkpoint's `UPDATE ..
        // RETURNING` after the covered-log drop — +1 statement, +2
        // billed reads (the changed row plus the RETURNING row,
        // release gate run 40186665163), +1 billed write by
        // construction; the host delta matches.
        //
        // stow#1380: a dirty span rewrites its whole range, now several
        // 64 KiB rows (`CHUNK_TEXT_BYTES`) instead of one: the widest
        // ranges, nodes (8,192 x ~100 B) and interned strings (16,384
        // x ~50 B), are ~800 KB, 13 rows. The drive's fixed batch
        // dirties 28 spans (measured on the host at 1M queue rows; 262
        // rows upserted, 9.4 a span); the bound is 32 spans x 13 rows =
        // 416 upserted rows. Rows written: 416 + 16 covered-log rows
        // dropped (7 measured) + 1 watermark + 1 checkpoint = 434.
        // Statements: ceil(416 / 16) = 26 upserts + 32 stale-range
        // deletes (one per span) + 1 covered-seq read + 1 watermark +
        // 1 log drop + 1 checkpoint = 62. Rows read are unchanged by
        // the row size: the covered-seq read and the checkpoint,
        // under the pre-#1380 allowance. Measured on the host: 49
        // statements, 3 reads, 271 written (36 / 3 / 38 before).
        name: "snapshot write",
        statements: 62,
        rows_read: 481,
        rows_written: 434,
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
/// Newly covered lanes initially share the bound of the existing route class
/// named in their comment; their own calibration requires the first measurement.
///
/// A budget is also bounded by the allowance, not only by the
/// measurement: `stow-admin traffic-cost project` prices every route
/// at its full budget — in the run's milliseconds, the budget times that
/// run's reference — under the launch model, fails when that month
/// passes `ALLOWANCE_FRACTION` of the Worker CPU allowance
/// (`cpu_ms_at_budget`), and prints each route's share of the allowance
/// at its measured figure and at its budget.
pub const WORKER_CPU_BUDGETS: &[WorkerCpuBudget] = &[
    // Fixed preheat entrypoints compose the existing dispatch and signed
    // webhook route-class bounds; these are bounds, not measurements.
    WorkerCpuBudget {
        lane: "preheat-release",
        relative_cpu: 0.60,
    },
    WorkerCpuBudget {
        lane: "preheat-scheduled",
        relative_cpu: 0.25,
    },
    WorkerCpuBudget {
        lane: "preheat-requested",
        relative_cpu: 0.35,
    },
    WorkerCpuBudget {
        lane: "preheat-in-progress",
        relative_cpu: 0.35,
    },
    WorkerCpuBudget {
        lane: "preheat-completed",
        relative_cpu: 0.35,
    },
    WorkerCpuBudget {
        lane: "preheat-cron-requested",
        relative_cpu: 0.35,
    },
    WorkerCpuBudget {
        lane: "preheat-cron-in-progress",
        relative_cpu: 0.35,
    },
    WorkerCpuBudget {
        lane: "preheat-cron-completed",
        relative_cpu: 0.35,
    },
    // Initial bounds from status-read, trusted-submit and workflow-callback,
    // respectively; these are route-class bounds, not measurements of new lanes.
    WorkerCpuBudget {
        lane: "health-probe",
        relative_cpu: 0.15,
    },
    WorkerCpuBudget {
        lane: "index-report",
        relative_cpu: 0.25,
    },
    WorkerCpuBudget {
        lane: "index-requested",
        relative_cpu: 0.35,
    },
    WorkerCpuBudget {
        lane: "build-requested",
        relative_cpu: 0.35,
    },
    WorkerCpuBudget {
        lane: "index-in-progress",
        relative_cpu: 0.35,
    },
    WorkerCpuBudget {
        lane: "index-completed",
        relative_cpu: 0.35,
    },
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
        // Counters and the pending human-lane index (stow#932).
        // Run 40637518261: 0.069 (1.645 ms of 23.7 ms).
        lane: "status-read",
        relative_cpu: 0.15,
    },
    WorkerCpuBudget {
        // Counters and the pending-age index (stow#932). The lane is
        // authenticated by an OIDC token, so its CPU includes the
        // signature check: 0.116 before OIDC (run 40637518261), 0.2547
        // with the check in wasm big-integer code (release gate run
        // 40907504842), now WebCrypto with the key imported once per
        // `kid` (stow#1088).
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
        // One whole lifecycle: two scheduler mutations and three signed
        // deliveries, composed from their existing per-request bounds.
        lane: "human-lifecycle",
        relative_cpu: 2.0 * 0.25 + 3.0 * 0.35,
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
