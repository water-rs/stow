//! The production-shaped scheduler fixture's pure shape math.
//!
//! The seed SQL lives in `edge/src/scheduler/fixture.rs`; what lives
//! here is the *shape* — which queue-order `n` is pending, completed,
//! failed or in-flight, and the canonical task id it carries — so every
//! consumer computes the same row: the edge's seeders and drives, the
//! host drift gate, and `stow-admin traffic-cost`'s lanes (which
//! name seeded ids directly). A shape that exists in two places drifts —
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
    /// default (`STOW_TRAFFIC_SIZES` in `scripts/traffic-cost.sh`
    /// pairs it with the 1M shape).
    pub const PRODUCTION: Self = Self {
        queue_rows: 100_000,
    };
    /// The in-flight set — `dispatched`/`running` rows — capped so the
    /// dispatch limit still leaves slots for the claim pass to fill.
    /// Each row binds one `build-crate.yml` run, so the set holds
    /// exactly this many runner slots. Held constant across fixture
    /// sizes: the alarm's claim is bounded by this plus the dispatch
    /// cap, not by the queue.
    pub const IN_FLIGHT_ROWS: u32 = 30;
    /// Pending rows on the human lane — held constant so a lane-position
    /// probe reads the same depth at every fixture size.
    pub const HUMAN_LANE_ROWS: u32 = 2_000;
    /// The human lane's tail rows pin their single edge at a completed
    /// row, so they are unblocked at every fixture size — a lane-status
    /// drive can name a fixed id whose lane-position probe always runs
    /// instead of silently skipping when a size-dependent edge set
    /// flips `blocked`. The seed also parks them behind a future
    /// `not_before`: they stay `pending`, unblocked and
    /// `dispatch_eligible = 1`, but the claim's page predicate refuses
    /// them — a human pin would rank first and fill the pass with
    /// one-slot tasks, hiding the miss-row claim the gate exists to
    /// price.
    pub const HUMAN_PROBE_ROWS: u32 = 16;
    /// Rows `updated_at` inside the last 24 h — held constant: an
    /// `/admin/status` outcome count is legitimately bounded by 24 h
    /// throughput, which the scale check must not let grow with the
    /// stored bulk.
    pub const LAST_24H_ROWS: u32 = 3_000;
    /// The pending rows the fixture plants as dispatch-eligible — a
    /// fixed window just above the human lane, each with its edges met,
    /// so the dispatch claim has claimable rows to pick at any fixture
    /// size. Held constant because the claimable population itself is a
    /// fixture input: an eligible set that grows with the queue would
    /// make the claimed set's dependency closure — and the dependents a
    /// purge or a dep expansion walks — a function of stored bulk
    /// instead of the claim's own bound (stow#588).
    ///
    /// Sized so one dispatch pass cannot drain it and so the pass can
    /// reach its own bound: the claimable population is the window
    /// minus its parked `n % 20 = 1` rows — the human pins are parked
    /// behind `not_before` and no longer count — which must (a) exceed
    /// the most tasks a pass can claim — one per free slot, so the
    /// slots the in-flight rows leave free — and (b) feed that bound,
    /// not just exceed it. The floored pass admits only rows whose
    /// operand (its priority, stow#879) clears the floor — the
    /// window's stored demand is what lifts its rows past it — so the
    /// window must hold more than one full pass of claimable rows.
    /// At 640 the family spread gives the window about 142 Windows
    /// rows, of which the `n % 20 = 1` park leaves ~135 claimable —
    /// every one ahead of every bulk Windows row on the window's
    /// stored demand — so a pass fills from the window alone at any
    /// size. A window a pass can empty would let the claim reach rows
    /// an earlier drive left claimable, and the walk would then move
    /// with the drives' order instead of the fixture's shape. The
    /// edge's `planted_window_exceeds_one_full_pass` test holds the
    /// bound against the scheduler's defaults.
    pub const DISPATCH_ELIGIBLE_ROWS: u32 = 640;

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
    /// group, first to last.
    #[must_use]
    pub const fn dispatched_row(self, k: u32) -> u32 {
        let first = if self.failed_end().is_multiple_of(2) {
            2
        } else {
            1
        };
        self.failed_end() + first + (k % (Self::IN_FLIGHT_ROWS / 2)) * 2
    }

    /// The bound run of the `k`-th in-flight row — `k` indexes the
    /// in-flight group like [`Self::in_flight_row`]. The seed binds
    /// every in-flight row to its own `build-crate.yml` run
    /// (`in_flight_runs_update_sql` in the edge fixture): the run id is
    /// the row number and the rustc is the row's own.
    #[must_use]
    pub fn in_flight_run(self, k: u32) -> InFlightRun {
        let n = u64::from(self.in_flight_row(k));
        InFlightRun {
            run_id: n,
            rustc_version: seeded_rustc(n),
            task_id: fixture_task_id(n),
        }
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

/// One seeded in-flight run: a bound, undelivered `build-crate.yml`
/// run for one task — what a production dispatch looks like between
/// the run's creation and its `completed` delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InFlightRun {
    /// The run the task is bound to (`queue.github_run_id`).
    pub run_id: u64,
    /// The run's rustc — the run title's lead and the records tag's
    /// namespace.
    pub rustc_version: &'static str,
    /// The task's id.
    pub task_id: String,
}

/// A seeded row's rustc — the seed SQL's `RUSTC_CASE_SQL` over `n`.
#[must_use]
pub const fn seeded_rustc(n: u64) -> &'static str {
    if n % 3 < 2 { "1.85.0" } else { "1.86.0" }
}

/// How the fixture's `n % len` target spread maps onto
/// [`CI_TARGET_TRIPLES`].
fn target_count() -> u32 {
    u32::try_from(CI_TARGET_TRIPLES.len()).expect("target count fits u32")
}

/// Nodes one crate name covers — the fixture's pinned per-name bound.
///
/// `'crate' || (n / CRATE_NAME_ROWS)` bounds every name to at most
/// `CRATE_NAME_ROWS` nodes at any `queue_rows`, so a `crate_name =`
/// selector reads a size-invariant cardinality at every size.
pub const CRATE_NAME_ROWS: u32 = 50;

/// A fixture node's crate name and version. `(crate, version)` is
/// injective in `n` at any size — `n / 20000` carries the quotient in
/// the version and `n % 500` its low digits.
#[must_use]
pub fn crate_identity(n: u32) -> (String, String) {
    (
        format!("crate{}", n / CRATE_NAME_ROWS),
        format!("1.{}.{}", n / 20000, n % 500),
    )
}

/// A fixture node's target — the `n % len` spread over
/// [`CI_TARGET_TRIPLES`].
#[must_use]
pub const fn target_of(n: u32) -> &'static str {
    CI_TARGET_TRIPLES[n as usize % CI_TARGET_TRIPLES.len()]
}

/// A seeded node's dependency digest — its own number as 64 hex
/// digits, the formula the edges and slice rows agree on.
#[must_use]
pub fn digest_hex(n: u64) -> String {
    format!("{n:064x}")
}

/// The canonical task id of fixture node `n`.
///
/// The identity [`crate_identity`], [`target_of`] and [`seeded_rustc`] spread over
/// the row, host-side on every tenth, with [`digest_hex`] as its
/// dependency digest — the id the scheduler re-mints from the node.
///
/// # Panics
/// When `n` exceeds the fixture's `u32` row range.
#[must_use]
pub fn fixture_task_id(n: u64) -> String {
    let row = u32::try_from(n).expect("fixture rows fit u32");
    let (crate_name, version) = crate_identity(row);
    crate::task_graph::canonical_task_id(
        &crate_name,
        &version,
        &crate::identity::FeaturesJson::default().raw(),
        target_of(row),
        seeded_rustc(n),
        &digest_hex(n),
        row.is_multiple_of(10),
    )
}

/// The canonical task id of a drive-owned node outside the fixture's
/// row range: crate `name` at `1.0.0` on `target` under rustc `1.86.0`,
/// `seed` as its dependency digest.
#[must_use]
pub fn named_task_id(name: &str, seed: u64, target: &str) -> String {
    crate::task_graph::canonical_task_id(
        name,
        "1.0.0",
        &crate::identity::FeaturesJson::default().raw(),
        target,
        NAMED_RUSTC,
        &digest_hex(seed),
        false,
    )
}

/// The rustc every drive-owned node compiles under.
pub const NAMED_RUSTC: &str = "1.86.0";

/// The `enqueued` fixture request record's id.
///
/// `seed_requests` writes it and `GET /requests/{id}`-shaped drives name
/// it. The stored roots in its `outcome_json` point at seeded queue
/// rows, so the read exercises the live root re-probe at every fixture
/// size.
pub const REQUEST_FIXTURE_ENQUEUED: &str = "req-fixture-enqueued";

/// The `failed` fixture request record's id — a static read with no
/// root re-probe.
pub const REQUEST_FIXTURE_FAILED: &str = "req-fixture-failed";

#[cfg(test)]
mod tests {
    use super::{FixtureShape, seeded_rustc};

    /// Every in-flight row names its own bound run, and the k-th run
    /// is the k-th in-flight row's.
    #[test]
    fn each_in_flight_row_is_its_own_bound_run() {
        let shape = FixtureShape::PRODUCTION;
        let runs: Vec<_> = (0..FixtureShape::IN_FLIGHT_ROWS)
            .map(|k| shape.in_flight_run(k))
            .collect();
        for (k, run) in (0..).zip(&runs) {
            let n = u64::from(shape.in_flight_row(k));
            assert_eq!(run.run_id, n);
            assert_eq!(run.task_id, super::fixture_task_id(n));
            assert_eq!(run.rustc_version, seeded_rustc(n));
        }
        // Both rustc arms are in flight, so a lane that titled every
        // run with one rustc would misname a third of them.
        assert!(runs.iter().any(|run| run.rustc_version == "1.86.0"));
        assert!(runs.iter().any(|run| run.rustc_version == "1.85.0"));
    }
}
