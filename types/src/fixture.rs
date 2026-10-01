//! The production-shaped scheduler fixture's pure shape math.
//!
//! The seed SQL lives in `edge/src/scheduler/fixture.rs`; what lives
//! here is the *shape* — which queue-order `n` is pending, completed,
//! failed or in-flight, and the `%064x` task id it carries — so every
//! consumer computes the same row: the edge's seeders and drives, the
//! host drift gate, and `stow-admin launch-load`'s lanes (which name
//! seeded ids directly). A shape that exists in two places drifts —
//! the reason `DO_BUDGETS` moved here too.

use crate::api::CI_TARGET_TRIPLES;

/// The row-count shape the seeded database takes.
///
/// Every split below is derived from `queue_rows`, so the host gate and
/// the workerd harness share one shape at two scales and a drive whose
/// counters grow with the stored bulk fails — only `queue_rows` moves,
/// so every quantity a route may legitimately be bounded by is held
/// constant across shapes.
#[derive(Debug, Clone, Copy)]
pub struct FixtureShape {
    /// Total `queue` rows to seed.
    pub queue_rows: u32,
}

impl FixtureShape {
    /// The production shape — 100k rows — the workerd harness seeds by
    /// default (`STOW_BUDGET_SIZES` in `scripts/scheduler-budget.sh`
    /// adds the 20k shape to the pair).
    pub const PRODUCTION: Self = Self {
        queue_rows: 100_000,
    };
    /// The in-flight set — `dispatched`/`running` rows — capped so the
    /// dispatch limit still leaves slots for the claim pass to fill.
    /// Held constant across fixture sizes: the alarm's claim is bounded
    /// by this plus the dispatch cap, not by the queue.
    pub const IN_FLIGHT_ROWS: u32 = 30;
    /// Pending rows on the human lane — held constant so a lane-position
    /// probe reads the same depth at every fixture size.
    pub const HUMAN_LANE_ROWS: u32 = 2_000;
    /// The human lane's tail rows pin their single edge at a completed
    /// row, so they are unblocked at every fixture size — a lane-status
    /// drive can name a fixed id whose lane-position probe always runs
    /// instead of silently skipping when a size-dependent edge set
    /// flips `blocked`.
    pub const HUMAN_PROBE_ROWS: u32 = 16;
    /// Rows `updated_at` inside the last 24 h — held constant: an
    /// `/admin/status` outcome count is legitimately bounded by 24 h
    /// throughput, which the scale check must not let grow with the
    /// stored bulk.
    pub const LAST_24H_ROWS: u32 = 3_000;

    /// Rows `1..=pending_end` are `pending` — 60% of the queue.
    #[must_use]
    pub const fn pending_end(self) -> u32 {
        self.queue_rows / 10 * 6
    }

    /// Rows `pending_end < n <= completed_end` are `completed` — 35%.
    #[must_use]
    pub const fn completed_end(self) -> u32 {
        self.queue_rows / 20 * 19
    }

    /// Rows `completed_end < n <= failed_end` are `failed` — 2.5%.
    #[must_use]
    pub const fn failed_end(self) -> u32 {
        self.queue_rows / 40 * 39
    }

    /// A `pending` row id — `n` indexes the pending group.
    #[must_use]
    pub const fn pending_row(n: u32) -> u32 {
        n
    }

    /// A `completed` row id — `k` indexes the completed group.
    #[must_use]
    pub const fn completed_row(self, k: u32) -> u32 {
        self.pending_end() + 1 + k
    }

    /// A `failed` row id — `k` indexes the failed group.
    #[must_use]
    pub const fn failed_row(self, k: u32) -> u32 {
        self.completed_end() + 1 + k
    }

    /// The one `running` row the run-completion drive reports.
    #[must_use]
    pub const fn running_row(self) -> u32 {
        self.failed_end() + 3
    }

    /// A `dispatched`/`running` row id — `k` indexes the in-flight
    /// group; even `n` are `dispatched`, odd `running`.
    #[must_use]
    pub const fn in_flight_row(self, k: u32) -> u32 {
        self.failed_end() + 1 + k % Self::IN_FLIGHT_ROWS
    }

    /// A `dispatched` row id — the even `n` half of the in-flight
    /// group, first to last. The webhook lane completes these; a
    /// `running` row's run never finishes.
    #[must_use]
    pub const fn dispatched_row(self, k: u32) -> u32 {
        let first = if self.failed_end().is_multiple_of(2) {
            2
        } else {
            1
        };
        self.failed_end() + first + (k % (Self::IN_FLIGHT_ROWS / 2)) * 2
    }

    /// A `completed` dep for the submit batch's `depends_on` — `k` picks
    /// inside the completed group so the dep's node is real and
    /// published.
    #[must_use]
    pub const fn dep_row(self, k: u32) -> u32 {
        self.pending_end() + 1 + k % (self.completed_end() - self.pending_end())
    }

    /// The first `n % TARGETS == target_index` row inside the completed
    /// group — where the slice's live members start. Strictly greater
    /// than `pending_end`: the boundary row itself is still `pending`.
    #[must_use]
    pub fn slice_first_row(self, target_index: u32) -> u32 {
        let targets = target_count();
        let offset = (targets + target_index - self.pending_end() % targets) % targets;
        self.pending_end() + if offset == 0 { targets } else { offset }
    }

    /// How many live members the `(CI_TARGET_TRIPLES[target_index],
    /// '1.85.0')` slice carries — the completed rows whose `n` lands on
    /// the target index (and `n % 9 == 0` implies `n % 3 == 0`, the
    /// 1.85.0 rustc arm).
    #[must_use]
    pub fn slice_live_rows(self, target_index: u32) -> u32 {
        let first = self.slice_first_row(target_index);
        if first > self.completed_end() {
            return 0;
        }
        (self.completed_end() - first) / target_count() + 1
    }
}

/// How the fixture's `n % len` target spread maps onto
/// [`CI_TARGET_TRIPLES`].
fn target_count() -> u32 {
    u32::try_from(CI_TARGET_TRIPLES.len()).expect("target count fits u32")
}

/// A seeded queue row's task id — `printf('%064x', n)` in the seed SQL.
#[must_use]
pub fn task_hex_id(n: u64) -> String {
    format!("{n:064x}")
}
