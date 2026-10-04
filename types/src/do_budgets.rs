//! The workerd budget table, shared as data.
//!
//! Data only, so it compiles on every target and every consumer (the
//! edge's probe routes and host drift gate, the admin crate's budget
//! renderer, and the stow#452 launch gate's fixture) reads the same
//! table.

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
        name: "POST /admin/enqueue (resubmit)",
        statements: 16,
        rows_read: 1_600,
        rows_written: 100,
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
        // The accepted development ceiling is 303 reads — the latest
        // 100k workerd gate measured 157 under it, without wall-time
        // or write headroom.
        name: "POST /index/published (full)",
        statements: 8,
        rows_read: 303,
        rows_written: 800,
        wall_ms: 500,
    },
    DriveBudget {
        // The delta's gate writes are the matched edges' `dep_met`
        // flips plus their owners' `unpublished_deps` adjustments —
        // 1 + the delta's direct dependents, never the queue or the
        // graph (stow#521). `rowsRead` counts workerd's internal index
        // seeks: the per-edge `dep_match` probes, the slice-row
        // re-evaluation per matched edge and the owner PK seeks.
        // The accepted development ceiling is 488 reads — the latest
        // 100k workerd gate measured 486 under it.
        name: "POST /index/published (delta)",
        statements: 8,
        rows_read: 488,
        rows_written: 200,
        wall_ms: 500,
    },
    DriveBudget {
        // The full dispatch pass: binding reads, the claim paged at
        // `2 × open slots`, the per-page catalog coverage lookup (a
        // counted-D1 read, not object rows), the per-claim UPDATE and
        // the bounded-concurrent `trigger_build` hop — wall includes
        // the fan-out's slowest HTTP leg.
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
        // claims they make through this row.
        name: "alarm pass (idle)",
        statements: 20,
        rows_read: 300,
        rows_written: 8,
        wall_ms: 300,
    },
    DriveBudget {
        // One real dispatch pass over the floored queue — the same
        // claim/dispatch/plan surface as the hot pass, priced
        // separately so the gate sees the planner and claim walk
        // under a positive persisted floor with under-floor bulk
        // deferred in the flags (stow#525). Setup stamps and teardown
        // restore live outside the metered window.
        name: "alarm pass (floor claim)",
        statements: 120,
        rows_read: 1_000,
        rows_written: 700,
        wall_ms: 3_000,
    },
    // Every demand-feed cap below is PROVISIONAL: host-measured,
    // pending actual workerd billed measurements — only these
    // event-specific caps may be retuned from measured native costs
    // plus stated headroom; the 31 existing budgets stay unchanged
    // (stow#523).
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
        // pending probe — measured 7/4/257 on the 10k gate.
        name: "POST /scheduler/demand-feed/begin (rotation)",
        statements: 14,
        rows_read: 8,
        rows_written: 520,
        wall_ms: 120,
    },
    DriveBudget {
        // One staged page: guards plus the payload insert whose
        // trigger bumps counters.
        name: "POST /scheduler/demand-feed/page (append)",
        statements: 6,
        rows_read: 8,
        rows_written: 3,
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
        // `demand_pass` closure for 256 real fixture identities, the
        // ack flip and the wake re-plan.
        name: "POST /scheduler/demand-feed/deliver (page apply)",
        statements: 550,
        rows_read: 1300,
        rows_written: 650,
        wall_ms: 600,
    },
    DriveBudget {
        // The terminal call — transition-only after every page has
        // applied: its probes plus the contiguous-watermark
        // `delivered` transition.
        name: "POST /scheduler/demand-feed/deliver (terminal)",
        statements: 18,
        rows_read: 40,
        rows_written: 4,
        wall_ms: 200,
    },
    DriveBudget {
        // Delivered-hour replay: the `delivered` early-out plus the
        // wake re-plan.
        name: "POST /scheduler/demand-feed/deliver (replay)",
        statements: 12,
        rows_read: 30,
        rows_written: 0,
        wall_ms: 80,
    },
    DriveBudget {
        // One full retirable chunk: `DELETE … LIMIT 256` plus its
        // probes — flat in archive depth.
        name: "POST /scheduler/demand-feed/cleanup (full chunk)",
        statements: 8,
        rows_read: 8,
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
