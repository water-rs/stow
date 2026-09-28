//! The workerd budget table — data only, so it compiles on every
//! target and the host gate can assert the drive list and both budget
//! tables cover each other exactly (see `cost_gate`).

/// One probe budget row — statements and the real cursor counters. These
/// are the numbers that gate a merge: each was measured on the 100k
/// fixture under workerd and carries ~2× headroom. A drive that goes
/// queue-size-proportional exceeds its row by orders of magnitude, not
/// by slack.
pub struct DriveBudget {
    pub name: &'static str,
    pub statements: u64,
    pub rows_read: u64,
    pub rows_written: u64,
}

/// The workerd budget table — the same rows the host gate carries,
/// measured in the units Cloudflare bills. Filled from the harness's
/// reported measurements; a regression fails `stow-admin scheduler
/// budget` nonzero.
pub const DO_BUDGETS: &[DriveBudget] = &[
    DriveBudget {
        name: "GET /status",
        statements: 4,
        rows_read: 100,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /admin/status",
        statements: 8,
        rows_read: 8_000,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks",
        statements: 3,
        rows_read: 2_000,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks?status=failed",
        statements: 3,
        rows_read: 2_000,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks?status=pending",
        statements: 3,
        rows_read: 2_000,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks?status=blocked",
        statements: 3,
        rows_read: 5_000,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks?target=…",
        statements: 3,
        rows_read: 2_000,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks?crate=…",
        statements: 3,
        rows_read: 600,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks?older_than=86400",
        statements: 3,
        rows_read: 2_000,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks?task_ids=…",
        statements: 3,
        rows_read: 100,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks/status (batch)",
        statements: 4,
        rows_read: 2_500,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks/{id}",
        statements: 6,
        rows_read: 2_500,
        rows_written: 0,
    },
    DriveBudget {
        name: "POST /tasks/complete-run",
        statements: 10,
        rows_read: 200,
        rows_written: 200,
    },
    DriveBudget {
        name: "POST /builds/complete",
        statements: 8,
        rows_read: 200,
        rows_written: 200,
    },
    DriveBudget {
        name: "POST /tasks/retry",
        statements: 4,
        rows_read: 200,
        rows_written: 100,
    },
    DriveBudget {
        name: "POST /tasks/cancel",
        statements: 4,
        rows_read: 200,
        rows_written: 100,
    },
    DriveBudget {
        name: "POST /tasks/promote",
        statements: 4,
        rows_read: 200,
        rows_written: 100,
    },
    DriveBudget {
        name: "POST /tasks/purge",
        statements: 4,
        rows_read: 200,
        rows_written: 100,
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
    },
    DriveBudget {
        name: "POST /admin/enqueue (trusted)",
        statements: 16,
        rows_read: 300,
        rows_written: 400,
    },
    DriveBudget {
        name: "POST /admin/enqueue (resubmit)",
        statements: 16,
        rows_read: 1_600,
        rows_written: 100,
    },
    DriveBudget {
        name: "POST /index/published (full)",
        statements: 8,
        rows_read: 500,
        rows_written: 800,
    },
    DriveBudget {
        name: "POST /index/published (delta)",
        statements: 8,
        rows_read: 700,
        rows_written: 500,
    },
    // The claim pages at `2 × open slots` and the coverage oracle
    // sees one lookup per page: the pass's read is bounded by the
    // dispatch cap plus the fixed probes, never by the frontier.
    DriveBudget {
        name: "alarm pass",
        statements: 90,
        rows_read: 800,
        rows_written: 700,
    },
];
