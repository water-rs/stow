//! The scheduler route list both cost gates drive. The host-side gate
//! (`cost_gate.rs`, `cargo test -p stow-edge`) runs this same list on a
//! small fixture against `counting_memory_db` as a fast pre-check; the
//! workerd harness (`budget.rs`, `scripts/scheduler-budget.sh`) runs it
//! on the 100k production fixture inside the Durable Object, where
//! `CfDurableDb` reports the real `rowsRead`/`rowsWritten` Cloudflare
//! bills. One drive list keeps the two harnesses honest: a route that
//! only existed in one of them would be an unmeasured request path.
//!
//! Every entry is a cold-start measure — the drives deliberately skip
//! `migrate`, which is operations work, never request code.

#[cfg(not(target_arch = "wasm32"))]
use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;

use skyzen_services::durable::{Alarm, DurableDb};
use stow_types::api::{
    EnqueueDependency, EnqueueRequest, EnqueueSource, PublishedSliceRow, QueueSelector,
    QueueTaskStatus,
};
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};
use stow_types::public_cache::{UnitInvocation, UnitShape};

use super::fixture::FixtureShape;
use super::queue::{self, QueueMutation, SchedulerSettings};
#[cfg(not(target_arch = "wasm32"))]
use super::queue::{CoverageOracle, SemanticTaskIdentity};

/// What a [`Drive`] runs: the route's queue-layer calls exactly once
/// against `db`. `FixtureShape` is copied — four bytes.
type DriveRun = for<'a> fn(
    &'a DurableDb,
    FixtureShape,
    &'a SchedulerSettings,
    &'a DriveContext,
) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// The alarm state a drive found on entry — three real states the
/// cleanup distinguishes: platform alarm never read, nothing armed,
/// or an alarm armed at a unix-ms timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorAlarm {
    NotCaptured,
    Unarmed,
    Armed(i64),
}

/// The queue fields a focused claim probe must put back exactly —
/// the union of every column the pass's writers touch:
/// `claim_dispatchable_row` (`status`, `generation_id`, `dispatch_attempts`,
/// `github_run_id`, `claimed_at`, `updated_at`), `retire_covered_rows`
/// (`status`, `error_msg`), `recover_stale_active_tasks` (`status`,
/// `error_msg`, `deps_met`, `blocked`, `wake_at`),
/// `requeue_incomplete_shape_deps` (`status`, `attempt`, `error_msg`,
/// `request_count`, `deps_met`, `blocked`, `not_before`, `wake_at`,
/// `shape_requeue`), and `apply_key_updates` (`value`, `dispatch_key`,
/// `dispatch_eligible`) on the transitioned ids (stow#525).
#[derive(Debug, Clone, skyzen::FromRow)]
pub struct RestoreQueueRow {
    task_id: String,
    status: String,
    attempt: i64,
    error_msg: Option<String>,
    request_count: i64,
    deps_met: i64,
    blocked: i64,
    not_before: Option<String>,
    wake_at: Option<String>,
    /// The raw value as TEXT — values above the JS safe integer range
    /// (any banded human/Windows score) round-trip losslessly only
    /// through the `CAST AS TEXT` contract `RANK_SOURCE_SELECT` uses
    /// (stow#524).
    value: String,
    dispatch_key: String,
    dispatch_eligible: i64,
    generation_id: String,
    dispatch_attempts: i64,
    github_run_id: Option<String>,
    claimed_at: Option<String>,
    updated_at: Option<String>,
    shape_requeue: i64,
}

/// The `RestoreQueueRow` column list, kept beside the struct so the
/// snapshot queries and the restore UPDATE can't drift apart.
const RESTORE_COLUMNS: &str = "task_id, status, attempt, error_msg, request_count, \
     deps_met, blocked, not_before, wake_at, CAST(value AS TEXT) AS value, dispatch_key, \
     dispatch_eligible, \
     generation_id, dispatch_attempts, github_run_id, claimed_at, updated_at, shape_requeue";

/// What a drive may reach besides the metered queue `DurableDb`.
///
/// The host gate's context is empty. The workerd probe's carries the
/// Worker env and the catalog D1 handle wrapped in the counted backend,
/// so the pass drive runs the real dispatch path — binding resolution,
/// the paged claim with its per-page coverage lookup, and the
/// `MAX_OUTBOUND_INFLIGHT`-bounded `trigger_build` fan-out — and the
/// report can price the coverage lookup's D1 rows against what the
/// pass claimed.
pub struct DriveContext {
    /// The Worker env — set only on the wasm32 probe.
    #[cfg(target_arch = "wasm32")]
    pub env: Option<skyzen::runtime::wasm::WasmEnv>,
    /// The catalog D1 handle on the counted backend — set only on the
    /// wasm32 probe.
    #[cfg(target_arch = "wasm32")]
    pub d1: Option<skyzen_services::Db>,
    /// The durable-object alarm the `scheduler_budget` route extracted
    /// — the real handle the demand drive's arm helper writes and
    /// reads back (stow#522). `None` on the host gate, which has no
    /// platform alarm and asserts the `AlarmPlan` instead.
    pub alarm: Option<Alarm>,
    /// Σ D1 `meta` rows the counted backend observed — read back into
    /// the report row after each drive.
    pub d1_rows: std::sync::Arc<std::sync::Mutex<(u64, u64)>>,
    /// The claimed task ids, in claim order — the pass's own outcome.
    /// The launch gate's per-claim marginal price divides the
    /// hot-minus-idle delta by their count — never by a checked-in
    /// slots assumption — and the re-arm's restore set is exactly
    /// these rows rather than any predicate over row state that could
    /// name a row another lane moved. A focused probe that claims
    /// without being the measured hot pass restores from its
    /// `restore_rows` snapshot instead so this divisor stays honest.
    pub claimed_tasks: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    /// The claim-mutable fields every claimable row held before a
    /// focused probe's pass — captured in the unmetered setup so the
    /// cleanup restores the exact generation, stamps and counters the
    /// claim moved, not just `status`/`github_run_id` (stow#525).
    restore_rows: std::sync::Arc<std::sync::Mutex<Vec<RestoreQueueRow>>>,
    /// The alarm state a drive found on entry — so the cleanup
    /// restores exactly the pre-drive state instead of leaving a
    /// probe arm behind.
    prior_alarm: std::sync::Arc<std::sync::Mutex<PriorAlarm>>,
}

impl DriveContext {
    /// The host gate's context — no Worker env, no catalog. Only the
    /// host test harness calls it: on wasm the probe uses `worker`.
    #[cfg(all(test, not(target_arch = "wasm32")))]
    #[must_use]
    pub fn host() -> Self {
        Self {
            #[cfg(target_arch = "wasm32")]
            env: None,
            #[cfg(target_arch = "wasm32")]
            d1: None,
            alarm: None,
            d1_rows: std::sync::Arc::new(std::sync::Mutex::new((0, 0))),
            claimed_tasks: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            restore_rows: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            prior_alarm: std::sync::Arc::new(std::sync::Mutex::new(PriorAlarm::NotCaptured)),
        }
    }

    /// The workerd probe's context: the Worker env plus the catalog D1
    /// on the counted backend whose totals feed `d1_rows`, and the
    /// real durable-object alarm the demand drive's arm writes.
    #[cfg(target_arch = "wasm32")]
    pub fn worker(env: &skyzen::runtime::wasm::WasmEnv, alarm: &Alarm) -> Result<Self, String> {
        let d1_rows = std::sync::Arc::new(std::sync::Mutex::new((0u64, 0u64)));
        let d1 = super::budget::counted_d1(env, std::sync::Arc::clone(&d1_rows))?;
        Ok(Self {
            env: Some(env.clone()),
            d1: Some(d1),
            alarm: Some(alarm.clone()),
            d1_rows,
            claimed_tasks: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            restore_rows: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            prior_alarm: std::sync::Arc::new(std::sync::Mutex::new(PriorAlarm::NotCaptured)),
        })
    }

    /// Read the counted D1 totals so far.
    pub fn d1_counts(&self) -> (u64, u64) {
        *self.d1_rows.lock().expect("d1 counter")
    }

    /// Tasks claimed by the pass drives so far — the id record's own
    /// count, so the two can never drift.
    pub fn claims(&self) -> u64 {
        u64::try_from(self.claimed_tasks.lock().expect("claim record").len()).unwrap_or(u64::MAX)
    }

    /// Append the ids a claiming pass just moved out of `pending`.
    fn record_claimed(&self, task_ids: Vec<String>) {
        self.claimed_tasks
            .lock()
            .expect("claim record")
            .extend(task_ids);
    }

    /// Record the pre-claim field set the setup snapshot read.
    fn set_restore_rows(&self, rows: Vec<RestoreQueueRow>) {
        *self.restore_rows.lock().expect("restore snapshot") = rows;
    }

    /// Take the recorded pre-claim field set for the cleanup's exact
    /// restore.
    pub fn take_restore_rows(&self) -> Vec<RestoreQueueRow> {
        std::mem::take(&mut *self.restore_rows.lock().expect("restore snapshot"))
    }

    /// Record the alarm state a drive found on entry.
    fn set_prior_alarm(&self, armed: Option<i64>) {
        *self.prior_alarm.lock().expect("prior alarm") =
            armed.map_or(PriorAlarm::Unarmed, PriorAlarm::Armed);
    }

    /// Take the recorded entry alarm state for the cleanup's restore.
    pub fn take_prior_alarm(&self) -> PriorAlarm {
        std::mem::replace(
            &mut *self.prior_alarm.lock().expect("prior alarm"),
            PriorAlarm::NotCaptured,
        )
    }

    /// Every task id the pass drives claimed so far, in claim order.
    pub fn claimed_ids(&self) -> Vec<String> {
        self.claimed_tasks.lock().expect("claim record").clone()
    }
}

/// One route (or the alarm pass) driven against the seeded queue.
pub struct Drive {
    /// The route label — the budget table's row key.
    pub name: &'static str,
    /// Fixture preparation run *outside* the metered window — for a
    /// drive whose measurement must see a state the production path
    /// being priced doesn't create itself (a persisted floor's
    /// operator stamp/backfill, stow#525). Setup SQL is not the event
    /// cost, so the harnesses never count it against the budget row.
    pub setup: Option<DriveRun>,
    /// Run the route's queue-layer calls exactly once against `db`.
    pub run: DriveRun,
    /// Fixture restoration run *outside* the metered window — undoes
    /// whatever `setup`/the focused pass moved (flags, floor stamp,
    /// claimed rows) so later drives and repeat probes see canonical
    /// fixture state.
    pub cleanup: Option<DriveRun>,
}

/// The drives, in budget-table order. Read routes first, then the
/// state-changing ones: the submit/publish/alarm drives mutate the
/// fixture, and the ordering keeps those mutations from hiding behind
/// the read routes' measurements.
pub const DRIVES: &[Drive] = &[
    Drive {
        name: "GET /status",
        setup: None,
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::status(db)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        // Bounded by held quantities: the outcomes walk is the last
        // 24 h of completions (`FixtureShape::LAST_24H_ROWS`, an
        // `idx_queue_updated_at` range), and the in-flight section by
        // the dispatch cap (`FixtureShape::IN_FLIGHT_ROWS`) — neither
        // tracks the stored queue bulk.
        name: "GET /admin/status",
        setup: None,
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::admin_status(db)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        name: "GET /tasks",
        setup: None,
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::list_tasks(db, &QueueSelector::default())
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        name: "GET /tasks?status=failed",
        setup: None,
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::list_tasks(
                    db,
                    &QueueSelector {
                        status: Some(QueueTaskStatus::Failed),
                        ..QueueSelector::default()
                    },
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        name: "GET /tasks?status=pending",
        setup: None,
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::list_tasks(
                    db,
                    &QueueSelector {
                        status: Some(QueueTaskStatus::Pending),
                        ..QueueSelector::default()
                    },
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        name: "GET /tasks?status=blocked",
        setup: None,
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::list_tasks(
                    db,
                    &QueueSelector {
                        status: Some(QueueTaskStatus::Blocked),
                        ..QueueSelector::default()
                    },
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        name: "GET /tasks?target=…",
        setup: None,
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::list_tasks(
                    db,
                    &QueueSelector {
                        target: Some(
                            stow_types::api::CI_TARGET_TRIPLES[0]
                                .parse()
                                .map_err(|error| format!("target parse: {error}"))?,
                        ),
                        ..QueueSelector::default()
                    },
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        // The crate selector seeks `queue`'s identity index on
        // `crate_name`, so the read is the name's own version set —
        // pinned at `fixture::CRATE_NAME_ROWS` rows across sizes.
        name: "GET /tasks?crate=…",
        setup: None,
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::list_tasks(
                    db,
                    &QueueSelector {
                        crate_name: Some(
                            "crate123"
                                .parse()
                                .map_err(|error| format!("crate: {error}"))?,
                        ),
                        ..QueueSelector::default()
                    },
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        // The age selector walks `idx_queue_updated_at` — the rows it
        // reads are bounded by the page limit, and the 24 h window it
        // lands in is held at `FixtureShape::LAST_24H_ROWS`.
        name: "GET /tasks?older_than=86400",
        setup: None,
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::list_tasks(
                    db,
                    &QueueSelector {
                        older_than_secs: Some(86_400),
                        ..QueueSelector::default()
                    },
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        // The score-visibility wire check (stow#525): two seeded human
        // rows carry adjacent values above the JS-safe integer range —
        // the listing must return their exact decimal text on this
        // side of the Durable Object cursor, where a numeric read
        // would decode through f64 and lose the tail.
        name: "GET /tasks?task_ids=…",
        setup: None,
        run: |db, shape, _settings, _ctx| {
            Box::pin(async move {
                let tasks = queue::list_tasks(
                    db,
                    &QueueSelector {
                        task_ids: vec![
                            hex_id(u64::from(FixtureShape::pending_row(600))),
                            hex_id(u64::from(shape.failed_row(0))),
                            // Human rows 2 and 3 sit on non-Windows
                            // targets, so their seeded values are
                            // `2 * VALUE_BAND + n % 7`: the adjacent
                            // pair 36893574046765006/…65007.
                            hex_id(2),
                            hex_id(3),
                        ],
                        ..QueueSelector::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
                let value_of = |n: u64| {
                    tasks
                        .iter()
                        .find(|task| task.task_id == hex_id(n))
                        .map(|task| task.value.clone())
                };
                for (n, expected) in [(2, "36893574046765006"), (3, "36893574046765007")] {
                    let actual =
                        value_of(n).ok_or_else(|| format!("task {n} missing from the listing"))?;
                    if actual != expected {
                        return Err(format!(
                            "task {n} reports value {actual}, expected {expected}"
                        ));
                    }
                }
                Ok(())
            })
        },
        cleanup: None,
    },
    Drive {
        // The fixture's in-flight rows carry a bound `github_run_id`
        // (`run-{n}`) as a claimed generation does — the report must
        // name it or the run-binding gate rejects it.
        name: "POST /tasks/complete-run",
        setup: None,
        run: |db, shape, settings, _ctx| {
            Box::pin(async move {
                queue::complete_run(
                    db,
                    settings,
                    &stow_types::api::WorkflowRunComplete {
                        task_id: hex_id(u64::from(shape.running_row())),
                        success: true,
                        error: None,
                        github_run_id: Some(format!("run-{}", shape.running_row())),
                    },
                    crate::freeze::DEFAULT_FREEZE_WINDOW_MINUTES,
                )
                .await
                .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        // The failure arm: the row re-queues `pending` behind its
        // backoff (`attempt` under the cap), so this prices the
        // heavier of the two failure writes — the cap arm only parks
        // the row `failed`.
        name: "POST /tasks/complete-run (failure)",
        setup: None,
        run: |db, shape, settings, _ctx| {
            Box::pin(async move {
                queue::complete_run(
                    db,
                    settings,
                    &stow_types::api::WorkflowRunComplete {
                        task_id: hex_id(u64::from(shape.dispatched_row(0))),
                        success: false,
                        error: Some("build failed".to_owned()),
                        github_run_id: Some(format!("run-{}", shape.dispatched_row(0))),
                    },
                    crate::freeze::DEFAULT_FREEZE_WINDOW_MINUTES,
                )
                .await
                .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        name: "POST /tasks/retry",
        setup: None,
        run: |db, shape, settings, _ctx| {
            Box::pin(async move {
                queue::apply_mutation(
                    db,
                    settings,
                    QueueMutation::Retry,
                    &QueueSelector {
                        task_ids: vec![
                            hex_id(u64::from(shape.failed_row(0))),
                            hex_id(u64::from(shape.failed_row(1))),
                        ],
                        ..QueueSelector::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())
                .and_then(|mutated| {
                    // The selector names two failed rows — the reported
                    // count is exactly the tasks updated, never billed
                    // index or status-count writes.
                    (mutated == 2)
                        .then_some(())
                        .ok_or_else(|| format!("retry mutated {mutated}, expected 2"))
                })
            })
        },
        cleanup: None,
    },
    Drive {
        name: "POST /tasks/cancel",
        setup: None,
        run: |db, _shape, settings, _ctx| {
            Box::pin(async move {
                queue::apply_mutation(
                    db,
                    settings,
                    QueueMutation::Cancel,
                    &QueueSelector {
                        task_ids: vec![
                            hex_id(u64::from(FixtureShape::pending_row(701))),
                            hex_id(u64::from(FixtureShape::pending_row(702))),
                        ],
                        ..QueueSelector::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())
                .and_then(|mutated| {
                    (mutated == 2)
                        .then_some(())
                        .ok_or_else(|| format!("cancel mutated {mutated}, expected 2"))
                })
            })
        },
        cleanup: None,
    },
    Drive {
        name: "POST /tasks/promote",
        setup: None,
        run: |db, _shape, settings, _ctx| {
            Box::pin(async move {
                queue::apply_mutation(
                    db,
                    settings,
                    QueueMutation::Promote,
                    &QueueSelector {
                        // Row 4703 sits in the miss lane — the fixture's
                        // human prefix ends at `HUMAN_LANE_ROWS`, and a
                        // promote selects `lane = 'miss'`, so a smaller
                        // pending id would silently match nothing.
                        task_ids: vec![hex_id(u64::from(FixtureShape::pending_row(4703)))],
                        ..QueueSelector::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())
                .and_then(|mutated| {
                    (mutated == 1)
                        .then_some(())
                        .ok_or_else(|| format!("promote mutated {mutated}, expected 1"))
                })
            })
        },
        cleanup: None,
    },
    Drive {
        name: "POST /tasks/purge",
        setup: None,
        run: |db, shape, settings, _ctx| {
            Box::pin(async move {
                queue::apply_mutation(
                    db,
                    settings,
                    QueueMutation::Purge,
                    &QueueSelector {
                        task_ids: vec![
                            hex_id(u64::from(shape.completed_row(0))),
                            hex_id(u64::from(shape.completed_row(1))),
                        ],
                        ..QueueSelector::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())
                .and_then(|mutated| {
                    (mutated == 2)
                        .then_some(())
                        .ok_or_else(|| format!("purge mutated {mutated}, expected 2"))
                })
            })
        },
        cleanup: None,
    },
    Drive {
        // A settled `enqueued` record: the row read, the stored-roots
        // parse and the live `tasks_status` re-probe — a pending human
        // root pays the lane-position walk, bounded by the held lane
        // depth.
        name: "GET /requests/{id}",
        setup: None,
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::crate_request_status(db, stow_types::fixture::REQUEST_FIXTURE_ENQUEUED)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        // The request lane's admission end to end — on wasm the real
        // `admit_request_pass`: the freeze and budget probes, the
        // deduping insert and the serialized `trigger_resolve` hop to
        // the local-CI dispatcher (the production GitHub arm's token
        // read is the same cached row the alarm pass pays). On host the
        // queue-layer calls only — dedup read, budget probe, insert.
        name: "POST /requests",
        setup: None,
        run: |db, _shape, settings, ctx| {
            Box::pin(async move { admit_request_drive(db, settings, ctx).await })
        },
        cleanup: None,
    },
    Drive {
        // `in_progress` on the record the admit drive just inserted:
        // the row read plus the conditional `accepted -> resolving`
        // update that stamps the run id.
        name: "POST /requests/{id}/run-update (in_progress)",
        setup: None,
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::record_request_run_update(
                    db,
                    DRIVE_REQUEST_ID,
                    &stow_types::api::RequestRunUpdate {
                        attempt: 1,
                        action: stow_types::api::RequestRunAction::InProgress,
                        conclusion: None,
                        run_id: Some("43".to_owned()),
                        run_url: Some(
                            "https://github.com/water-rs/stow/actions/runs/43".to_owned(),
                        ),
                    },
                )
                .await
                .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        // A `Resolved` report on the live record: the pre/post
        // `tasks_status` probes, the trusted enqueue of its batch and
        // the conditional `enqueued` write — the same insert machinery
        // the submit drives price, at the request batch's size.
        name: "POST /requests/{id}/outcome",
        setup: None,
        run: |db, shape, settings, _ctx| {
            Box::pin(async move {
                queue::apply_request_outcome(db, settings, DRIVE_REQUEST_ID, &request_report(shape))
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        // `completed` on the now-`enqueued` record — the single
        // conditional update keyed on the current state, which is the
        // overwrite the backstop must never perform (stow#428 review):
        // the real event costs the row read plus one no-op write.
        name: "POST /requests/{id}/run-update (completed)",
        setup: None,
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                queue::record_request_run_update(
                    db,
                    DRIVE_REQUEST_ID,
                    &stow_types::api::RequestRunUpdate {
                        attempt: 1,
                        action: stow_types::api::RequestRunAction::Completed,
                        conclusion: Some("success".to_owned()),
                        run_id: Some("43".to_owned()),
                        run_url: Some(
                            "https://github.com/water-rs/stow/actions/runs/43".to_owned(),
                        ),
                    },
                )
                .await
                .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        // The pending-depth check is a `queue_status_counts` row read;
        // the human-lane position walk is bounded by the lane's depth
        // (`FixtureShape::HUMAN_LANE_ROWS`, held across sizes), not by
        // the queue.
        name: "POST /enqueue (untrusted)",
        setup: None,
        run: |db, shape, settings, _ctx| {
            Box::pin(async move {
                // A zero cap turns any queue depth into a refusal, so
                // the drive measures the refuse path deterministically
                // rather than betting the fixture stays over the
                // deploy's cap. QueueFull is the pass; anything else
                // is a failure.
                let mut refused = *settings;
                refused.max_queue_pending = 0;
                match queue::enqueue(db, &submit_batch(shape), &refused).await {
                    Ok(_) | Err(crate::errors::QueueError::QueueFull { .. }) => Ok(()),
                    Err(error) => Err(error.to_string()),
                }
            })
        },
        cleanup: None,
    },
    Drive {
        // The accept half of the untrusted route: the cap is lifted so
        // the probe measures the insert — pending-count read, the
        // human-lane budget charge and position walk, the edge sync.
        // The launch gate prices a miss-lane enqueue here: an accepted
        // redemption pays the insert, not the refusal, and pricing it
        // on the refusal row underreads the DO writes admissions cost.
        name: "POST /enqueue (untrusted accept)",
        setup: None,
        run: |db, shape, settings, _ctx| {
            let mut lifted = *settings;
            lifted.max_queue_pending = u32::MAX;
            Box::pin(async move {
                // Every identity in the accept batch is new — the
                // returned count is exactly the inserted records (the
                // billed write count would include index writes).
                queue::enqueue(db, &submit_accept_batch(shape), &lifted)
                    .await
                    .map_err(|error| error.to_string())
                    .and_then(|inserted| {
                        (inserted == 3)
                            .then_some(())
                            .ok_or_else(|| format!("accept submit inserted {inserted}, expected 3"))
                    })
            })
        },
        cleanup: None,
    },
    Drive {
        name: "POST /admin/enqueue (trusted)",
        setup: None,
        run: |db, shape, settings, _ctx| {
            Box::pin(async move {
                // One resync + two new identities — the returned count
                // is the new records only.
                queue::enqueue_trusted(db, &submit_batch(shape), settings)
                    .await
                    .map_err(|error| error.to_string())
                    .and_then(|inserted| {
                        (inserted == 2).then_some(()).ok_or_else(|| {
                            format!("trusted submit inserted {inserted}, expected 2")
                        })
                    })
            })
        },
        cleanup: None,
    },
    Drive {
        name: "POST /admin/enqueue (resubmit)",
        setup: None,
        run: |db, shape, settings, _ctx| {
            Box::pin(async move {
                // The same batch again lands nothing — the count must
                // be zero, which billed index writes cannot fake.
                queue::enqueue_trusted(db, &submit_batch(shape), settings)
                    .await
                    .map_err(|error| error.to_string())
                    .and_then(|inserted| {
                        (inserted == 0)
                            .then_some(())
                            .ok_or_else(|| format!("resubmit inserted {inserted}, expected 0"))
                    })
            })
        },
        cleanup: None,
    },
    Drive {
        name: "POST /demand",
        setup: Some(|_db, _shape, _settings, ctx| {
            Box::pin(async move {
                // Capture the alarm state before the drive arms its
                // probe timestamps — the cleanup restores exactly this
                // (or deletes the probe's arm when none was set), so a
                // real armed alarm never leaks past the drive into
                // later measurements.
                #[cfg(target_arch = "wasm32")]
                if let Some(alarm) = ctx.alarm.as_ref() {
                    let prior = alarm.get_alarm().await.map_err(|error| error.to_string())?;
                    ctx.set_prior_alarm(prior);
                }
                #[cfg(not(target_arch = "wasm32"))]
                let _ = ctx;
                Ok(())
            })
        }),
        run: |db, _shape, settings, ctx| {
            Box::pin(async move {
                // One durable batch on one keyed root — fixture row 101's
                // identity, pending with seeded unmet edges — so the
                // measure covers the whole route pass: identity probe,
                // closure walk, contribution inserts, the demand/key
                // fold, and the `next_alarm` planner the route then
                // arms — all bounded by the touched set (stow#522).
                // Event-size law: this drive holds a one-entry/
                // small-closure batch, so its budget is the small-event
                // constant — real cost scales with distinct identities,
                // operand/staged chunks and touched rows; the 30k
                // closure regression exercises the chunked boundary on
                // the host, and no maximum-request drive is added
                // unless it proves a distinct unmeasured native cost.
                let n = 101_u32;
                let (crate_name, version) = crate_identity(n);
                let request = stow_types::api::SchedulerDemandRequest {
                    batch_id: "costgate-demand".to_owned(),
                    entries: vec![stow_types::api::SchedulerDemandEntry {
                        crate_name: CrateName::parse(crate_name).map_err(|e| e.to_string())?,
                        version: CrateVersion::new(
                            semver::Version::parse(&version).map_err(|e| e.to_string())?,
                        ),
                        features_json: FeaturesJson::default(),
                        target: TargetTriple::parse(dep_target(n)).map_err(|e| e.to_string())?,
                        rustc_version: WireRustcVersion::parse("1.86.0")
                            .map_err(|e| e.to_string())?,
                        demand: 100,
                    }],
                };
                // The route's own clock on wasm (`alarm_inputs` reads
                // `Date::now` there); the deterministic epoch only on
                // the host gate.
                #[cfg(target_arch = "wasm32")]
                #[allow(clippy::cast_possible_truncation)]
                let now_ms = js_sys::Date::now() as i64;
                #[cfg(not(target_arch = "wasm32"))]
                let now_ms = 0_i64;
                let (report, plan) = queue::demand_pass(db, &request, now_ms, settings)
                    .await
                    .map_err(|error| error.to_string())?;
                if !(report.applied && report.touched_tasks > 0) {
                    return Err(format!(
                        "demand batch touched {} tasks, applied={}",
                        report.touched_tasks, report.applied
                    ));
                }
                #[cfg(target_arch = "wasm32")]
                {
                    let alarm = ctx
                        .alarm
                        .as_ref()
                        .ok_or_else(|| "demand drive needs the durable-object alarm".to_owned())?;
                    // Real arm + real read-back on the probe's
                    // durable-object alarm: a genuine future timestamp
                    // cannot have fired, so `get_alarm` must return
                    // exactly what the shared helper set — the same
                    // `set_alarm` call the route makes. Platform calls
                    // sit outside the SQL meter by design (stow#522).
                    #[allow(clippy::cast_possible_truncation)]
                    let future_ms = js_sys::Date::now() as i64 + 600_000;
                    queue::arm_alarm(alarm, queue::AlarmPlan::At(future_ms))
                        .await
                        .map_err(|error| error.to_string())?;
                    let armed = alarm.get_alarm().await.map_err(|error| error.to_string())?;
                    if armed != Some(future_ms) {
                        return Err(format!("alarm reads {armed:?} after arm at {future_ms}"));
                    }
                    // The route's own arm for this pass's plan — the
                    // cleanup restores the alarm captured on entry, so
                    // nothing armed survives the drive.
                    queue::arm_alarm(alarm, plan)
                        .await
                        .map_err(|error| error.to_string())?;
                }
                #[cfg(not(target_arch = "wasm32"))]
                {
                    let _ = ctx;
                    if !matches!(plan, queue::AlarmPlan::At(_)) {
                        return Err(format!("demand pass planned {plan:?}, expected At"));
                    }
                }
                Ok(())
            })
        },
        cleanup: Some(|_db, _shape, _settings, ctx| {
            Box::pin(async move {
                // Put the pre-drive alarm state back: re-arm the
                // captured timestamp, or delete the probe's arm when
                // nothing was set — a real armed alarm must not leak
                // into later drives.
                #[cfg(target_arch = "wasm32")]
                if let Some(alarm) = ctx.alarm.as_ref() {
                    match ctx.take_prior_alarm() {
                        PriorAlarm::Armed(ms) => {
                            alarm.set_alarm(ms).await.map_err(|e| e.to_string())?;
                        }
                        PriorAlarm::Unarmed => {
                            alarm.delete_alarm().await.map_err(|e| e.to_string())?;
                        }
                        PriorAlarm::NotCaptured => {}
                    }
                }
                #[cfg(not(target_arch = "wasm32"))]
                let _ = ctx;
                Ok(())
            })
        }),
    },
    Drive {
        name: "POST /index/published (full)",
        setup: None,
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                // A full report (`base_generation: None`) — the
                // first-publish and resync path — on a dedicated slice
                // whose size is held across fixtures. Its cost is
                // legitimately bounded by the report's own membership:
                // the report body carries every row it claims, and the
                // live-set fetch reads only that slice.
                queue::record_published_slice(
                    db,
                    stow_types::api::CI_TARGET_TRIPLES[8],
                    "9.9.9",
                    None,
                    None,
                    &full_slice_report(),
                    &[],
                )
                .await
                .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        name: "POST /index/published (delta)",
        setup: None,
        run: |db, shape, _settings, _ctx| {
            Box::pin(async move {
                // A routine per-wave report: `added`/`retired` carry only
                // what moved, `base_generation` is the live token, and
                // every read is bounded by the delta — the probe (1 row),
                // the retire's PK joins, and the dependent refresh.
                let target = stow_types::api::CI_TARGET_TRIPLES[0];
                let rustc = "1.85.0";
                let base = db
                    .query(
                        "SELECT applied_generation FROM published_slices \
                         WHERE target = ? AND rustc_version = ?",
                    )
                    .bind(target.to_owned())
                    .bind(rustc.to_owned())
                    .fetch_scalar_optional::<i64>()
                    .await
                    .map_err(|error| error.to_string())?;
                let (added, retired) = delta_slice_report(shape);
                queue::record_published_slice(db, target, rustc, base, None, &added, &retired)
                    .await
                    .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        // One real dispatch pass over a *floored* queue (stow#525):
        // the setup stamps `min_dispatch_value` at one band through the
        // operator migrate path — unmetered, setup is not the event —
        // so the persisted flags put the under-floor miss bulk outside
        // the eligible index span while the human lane and the one-band
        // windows family stay ready. The metered pass then pays the
        // real production queries: the planner's freeze/settings/
        // lease/family probes and the claim walk over the eligible
        // span only. The pass claims ready rows — non-empty proves the
        // ready side exists at scale — and its ids stay out of
        // `claimed_tasks` (the launch gate's marginal divisor counts
        // only the hot pass's claims), restored by the unmetered
        // cleanup instead. Under-floor bulk contributes nothing to
        // either probe — the cleanup asserts every claim was flagged
        // eligible, and the under-floor-arms-nothing direction is
        // pinned by `under_floor_bulk_arms_no_wake_and_starves_no_page`
        // on the host.
        name: "alarm pass (floor claim)",
        setup: Some(|db, _shape, settings, ctx| {
            Box::pin(async move {
                // The floor application's DML half — the same stored-
                // floor read, conditional backfill and stamp the
                // operator migrate runs — no index DDL, which belongs
                // to the migrate route alone.
                queue::apply_dispatch_floor(
                    db,
                    &queue::SchedulerSettings {
                        min_dispatch_value: queue::VALUE_BAND,
                        ..*settings
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
                // The fixture must hold BOTH under-floor directions —
                // ready-now rows the floor defers, and rows whose own
                // wake is already deferred — or the probe proves
                // nothing about the eligible span's boundary. Ready =
                // the page predicate's wake terms true; deferred =
                // `not_before` still ahead (the fixture's +30min
                // rows).
                let ready = db
                    .query(
                        "SELECT COUNT(*) FROM queue \
                         WHERE status = 'pending' AND deps_met = 1 \
                           AND dispatch_eligible != 1 \
                           AND (lane = 'human' OR first_requested_at <= datetime('now', ?)) \
                           AND not_before <= datetime('now')",
                    )
                    .bind(queue::dispatch_cutoff_modifier(
                        settings.dispatch_min_age_minutes,
                    ))
                    .fetch_scalar::<u64>()
                    .await
                    .map_err(|error| error.to_string())?;
                let deferred = db
                    .query(
                        "SELECT COUNT(*) FROM queue \
                         WHERE status = 'pending' AND deps_met = 1 \
                           AND dispatch_eligible != 1 \
                           AND not_before > datetime('now')",
                    )
                    .fetch_scalar::<u64>()
                    .await
                    .map_err(|error| error.to_string())?;
                if ready == 0 || deferred == 0 {
                    return Err(format!(
                        "floored fixture must hold ready and deferred under-floor bulk: \
                         ready={ready} deferred={deferred}"
                    ));
                }
                // Bound the snapshot to exactly the writers the pass
                // can touch (stow#525):
                // - claim/retire touch rows inside the claim pages —
                //   `select_dispatchable_frontier` returns the first
                //   `CLAIM_PAGE_ROWS * CLAIM_MAX_PAGES` rows of the
                //   production page selection under the live family
                //   exclusion, the only rows the paged walk can open;
                // - stale-lease recovery touches active rows past the
                //   stale window;
                // - shape requeue touches `completed` rows whose
                //   dependents are still unmet.
                // The candidate sets are hard-capped so a fixture that
                // outgrows the bound fails loudly instead of mutating
                // rows the restore can't reach.
                let frontier_ids = queue::select_dispatchable_frontier(db, settings)
                    .await
                    .map_err(|error| error.to_string())?;
                if frontier_ids.is_empty() {
                    return Err(
                        "floored fixture has no claimable row — nothing for the probe to measure"
                            .to_owned(),
                    );
                }
                let mut rows = Vec::new();
                for ids in frontier_ids.chunks(queue::ENQUEUE_JSON_BATCH_ROWS) {
                    rows.extend(
                        db.query(&format!(
                            "SELECT {RESTORE_COLUMNS} FROM queue \
                             WHERE task_id IN (SELECT value FROM json_each(?))"
                        ))
                        .bind(queue::enqueue_json(ids).map_err(|e| e.to_string())?)
                        .fetch_all::<RestoreQueueRow>()
                        .await
                        .map_err(|error| error.to_string())?,
                    );
                }
                // The snapshot must actually hold a banded value —
                // above the JS safe integer the TEXT cast is the only
                // lossless decode, so a fixture without one can't prove
                // the restore's wide path (stow#525).
                let has_wide = rows.iter().any(|row| {
                    row.value
                        .parse::<u64>()
                        .expect("queue.value TEXT must be a nonnegative integer")
                        > 9_007_199_254_740_992
                });
                if !has_wide {
                    return Err(
                        "floored snapshot holds no value above the JS safe integer — \
                         the wide-value restore path is unproven"
                            .to_owned(),
                    );
                }
                // Recovery precondition: stale-lease recovery runs
                // inside the claim BEFORE paging, so a fixture-holding
                // stale row would both escape the eligible-frontier
                // snapshot and change the `full_family` the frontier
                // was computed under. Assert the production candidate
                // set is empty — the fixture's in-flight leases run a
                // day out (stow#525).
                let stale = db
                    .query(
                        "SELECT COUNT(*) FROM queue \
                         WHERE status IN ('dispatched', 'running') \
                           AND updated_at <= datetime('now', ?)",
                    )
                    .bind(format!("-{} minutes", settings.stale_dispatch_minutes))
                    .fetch_scalar::<u64>()
                    .await
                    .map_err(|error| error.to_string())?;
                if stale > 0 {
                    return Err(format!(
                        "floored fixture holds {stale} stale-lease candidate(s) — \
                         the snapshot can't cover recovery or its capacity shift"
                    ));
                }
                // The shape-requeue writer is a real fixture case (the
                // canonical seed has one): include its candidates in
                // the snapshot, hard-capped so an oversized set fails
                // loudly instead of mutating rows the restore can't
                // reach.
                let candidates = db
                    .query(&format!(
                        "SELECT {RESTORE_COLUMNS} FROM queue c \
                         WHERE c.status = 'completed' AND c.shape_requeue = 0 \
                           AND EXISTS ( \
                               SELECT 1 FROM queue_dependencies d \
                               WHERE d.depends_on_task_id = c.task_id \
                                 AND d.dep_crate_name != '' AND d.dep_host_side >= 0 \
                                 AND d.dep_met = 0) LIMIT 256"
                    ))
                    .fetch_all::<RestoreQueueRow>()
                    .await
                    .map_err(|error| error.to_string())?;
                if candidates.len() == 256 {
                    return Err("shape requeue candidate set reached the snapshot bound — \
                         fixture contract broken"
                        .to_owned());
                }
                rows.extend(candidates);
                // Coverage precondition: `retire_covered_rows` is the
                // pass's one writer the queue snapshot can't see — it
                // consults the catalog oracle. Run the real
                // `CatalogCoverage` over the bounded frontier's
                // identities and assert it covers none — a silent
                // retire would corrupt the "claims only" cost reading
                // (stow#525).
                #[cfg(target_arch = "wasm32")]
                {
                    #[derive(skyzen::FromRow)]
                    struct FrontierIdentity {
                        crate_name: String,
                        version: String,
                        features_json: String,
                        target: String,
                        rustc_version: String,
                        host_side: i64,
                    }
                    let d1 = ctx
                        .d1
                        .as_ref()
                        .ok_or_else(|| "floor claim probe needs the counted D1".to_owned())?;
                    let mut identities = Vec::new();
                    for ids in frontier_ids.chunks(queue::ENQUEUE_JSON_BATCH_ROWS) {
                        identities.extend(
                            db.query(
                                "SELECT crate_name, version, features_json, target, \
                                        rustc_version, host_side FROM queue \
                                 WHERE task_id IN (SELECT value FROM json_each(?))",
                            )
                            .bind(queue::enqueue_json(ids).map_err(|e| e.to_string())?)
                            .fetch_all::<FrontierIdentity>()
                            .await
                            .map_err(|error| error.to_string())?
                            .into_iter()
                            .map(|row| queue::SemanticTaskIdentity {
                                crate_name: row.crate_name,
                                version: row.version,
                                features_json: row.features_json,
                                target: row.target,
                                rustc_version: row.rustc_version,
                                host_side: row.host_side != 0,
                            }),
                        );
                    }
                    let coverage = super::object::CatalogCoverage { db: d1.clone() };
                    let covered = queue::CoverageOracle::covered(&coverage, &identities)
                        .await
                        .map_err(|error| error.to_string())?;
                    if !covered.is_empty() {
                        return Err(format!(
                            "catalog covers {} frontier identity(s) — \
                             the pass could retire rows the snapshot can't distinguish",
                            covered.len()
                        ));
                    }
                }
                ctx.set_restore_rows(rows);
                Ok(())
            })
        }),
        run: |db, _shape, settings, ctx| {
            Box::pin(async move {
                let claimed = floor_claim_probe(db, settings, ctx).await?;
                if claimed.is_empty() {
                    return Err(
                        "floored claim probe claimed nothing — no eligible row reached the claim"
                            .to_owned(),
                    );
                }
                Ok(())
            })
        },
        cleanup: Some(|db, _shape, settings, ctx| {
            Box::pin(async move {
                let mut errors: Vec<String> = Vec::new();
                // Leak check FIRST, on the live post-pass flags: every
                // row the pass left `dispatched` must carry
                // `dispatch_eligible = 1`, or the eligible span
                // admitted under-floor bulk. A shape-requeued
                // under-floor row re-enters `pending` — legitimate,
                // not a claim — so the predicate reads `dispatched`
                // only. Done before the restore resets flags.
                let snapshot = ctx.take_restore_rows();
                let ids: Vec<String> = snapshot.iter().map(|row| row.task_id.clone()).collect();
                for chunk in ids.chunks(queue::ENQUEUE_JSON_BATCH_ROWS) {
                    match db
                        .query(
                            "SELECT COUNT(*) FROM queue \
                             WHERE task_id IN (SELECT value FROM json_each(?)) \
                               AND status = 'dispatched' AND dispatch_eligible != 1",
                        )
                        .bind(queue::enqueue_json(chunk).map_err(|e| e.to_string())?)
                        .fetch_scalar::<u64>()
                        .await
                    {
                        Ok(leaked) if leaked > 0 => {
                            errors.push(format!("floored pass claimed {leaked} under-floor row(s)"));
                        }
                        Ok(_) => {}
                        Err(error) => errors.push(format!("leak check: {error}")),
                    }
                }
                // Restore EVERY snapshot row unconditionally, full
                // preimage — a row recovered to `pending` and reclaimed
                // `dispatched` in one pass ends with its original
                // status but a fresh generation/stamp, which a status
                // diff would miss; only the whole mutable field set is
                // exact (stow#525).
                for row in &snapshot {
                    match db
                        .query(
                            "UPDATE queue SET status = ?, attempt = ?, error_msg = ?, \
                                 request_count = ?, deps_met = ?, blocked = ?, \
                                 not_before = ?, wake_at = ?, value = CAST(? AS INTEGER), \
                                 dispatch_key = ?, dispatch_eligible = ?, \
                                 generation_id = ?, dispatch_attempts = ?, \
                                 github_run_id = ?, claimed_at = ?, updated_at = ?, \
                                 shape_requeue = ? \
                             WHERE task_id = ?",
                        )
                        .bind(row.status.clone())
                        .bind(row.attempt)
                        .bind(row.error_msg.clone())
                        .bind(row.request_count)
                        .bind(row.deps_met)
                        .bind(row.blocked)
                        .bind(row.not_before.clone())
                        .bind(row.wake_at.clone())
                        .bind(row.value.clone())
                        .bind(row.dispatch_key.clone())
                        .bind(row.dispatch_eligible)
                        .bind(row.generation_id.clone())
                        .bind(row.dispatch_attempts)
                        .bind(row.github_run_id.clone())
                        .bind(row.claimed_at.clone())
                        .bind(row.updated_at.clone())
                        .bind(row.shape_requeue)
                        .bind(row.task_id.clone())
                        .execute()
                        .await
                    {
                        Ok(result) if result.rows_written == 0 => {
                            errors.push(format!("snapshot row {} vanished", row.task_id));
                        }
                        Ok(_) => {}
                        Err(error) => errors.push(format!("restore {}: {error}", row.task_id)),
                    }
                }
                // Restore the fixture's floor through the same
                // operator path — flags and stamp consistent again —
                // then surface every collected error.
                if let Err(error) = queue::apply_dispatch_floor(db, settings).await {
                    errors.push(format!("floor restore: {error}"));
                }
                if errors.is_empty() {
                    Ok(())
                } else {
                    Err(errors.join("; "))
                }
            })
        }),
    },
    Drive {
        // One dispatch pass end to end — on wasm the real
        // `dispatch_pass` (`object.rs`): binding resolution, the claim
        // paged at `2 × open slots` rows with its per-page catalog
        // coverage lookup, and the `MAX_OUTBOUND_INFLIGHT`-bounded
        // `trigger_build` fan-out — the HTTP wall the launch gate's
        // peak-wall bound exists to measure. On host the claim runs the
        // same queue code against the empty-catalog oracle — the host
        // gate checks statements and counters only.
        name: "alarm pass",
        setup: None,
        run: |db, _shape, settings, ctx| {
            Box::pin(async move {
                dispatch_pass_drive(db, settings, ctx, false)
                    .await
                    .map(|_| ())
            })
        },
        cleanup: None,
    },
    Drive {
        // The same pass with dispatch paused: the claim returns early,
        // so this measures the per-invocation floor — stale-recovery
        // probes, the freeze and binding reads, and the wake-time
        // re-arm — every alarm wake pays regardless of what it claims.
        // The launch gate (stow#452) prices an invocation from this
        // row and the claims inside a pass as the marginal cost
        // between it and the hot pass above.
        name: "alarm pass (idle)",
        setup: None,
        run: |db, _shape, settings, ctx| {
            Box::pin(async move {
                dispatch_pass_drive(db, settings, ctx, true)
                    .await
                    .map(|_| ())
            })
        },
        cleanup: None,
    },
];

/// One dispatch pass exactly as `run_alarm` runs it, minus the metering
/// tail. `idle` pauses dispatch inside the pass — the claim early-outs
/// after the stale-recovery and freeze probes every wake owes. Returns
/// the pass's claimed ids: with `record` they also enter the launch
/// gate's claim record, while a focused probe (the floored pass)
/// restores them from its own list so the gate's marginal divisor
/// keeps counting only the hot pass's claims (stow#525).
async fn dispatch_pass_drive(
    db: &DurableDb,
    settings: &SchedulerSettings,
    ctx: &DriveContext,
    idle: bool,
) -> Result<Vec<String>, String> {
    let mut pass_settings = *settings;
    if idle {
        pass_settings.dispatch = queue::Dispatch::Paused;
    }
    let task_ids = {
        #[cfg(target_arch = "wasm32")]
        {
            let env = ctx
                .env
                .as_ref()
                .ok_or_else(|| "dispatch pass drive needs a Worker env".to_owned())?;
            let d1 = ctx
                .d1
                .as_ref()
                .ok_or_else(|| "dispatch pass drive needs the counted D1".to_owned())?;
            let coverage = super::object::CatalogCoverage { db: d1.clone() };
            let task_ids = super::object::dispatch_pass(env, db, &pass_settings, &coverage)
                .await
                .map_err(|error| error.to_string())?;
            // Only a non-recording focused probe files its claims for
            // restore — the canonical hot/idle pass owns
            // `claimed_tasks`, and mixing its ids into the probe list
            // would let a cleanup re-pend rows it never owned.
            ctx.record_claimed(task_ids.clone());
            if !idle {
                // Under `LocalCi` `dispatch_pass` resolves no credential,
                // but a production claiming pass pays
                // `github_app::installation_token` — the cached-token
                // storage read, with a mint only on expiry. The probe seeds
                // the cache row (`budget::run`), so this call returns on the
                // read and the drive prices the step the GitHub arm pays.
                let config = crate::github_app::AppConfig {
                    app_id: "stow-budget-probe".to_owned(),
                    installation_id: "0".to_owned(),
                    private_key_pem: String::new(),
                };
                let _ = crate::github_app::installation_token(db, &config)
                    .await
                    .map_err(|error| error.to_string())?;
            }
            task_ids
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let claimed = queue::claim_dispatchable_tasks(db, &pass_settings, &NoCoverage)
                .await
                .map_err(|error| error.to_string())?;
            let task_ids: Vec<String> = claimed.iter().map(|task| task.task_id.clone()).collect();
            ctx.record_claimed(task_ids.clone());
            task_ids
        }
    };
    queue::next_alarm(db, 0, &pass_settings)
        .await
        .map_err(|error| error.to_string())?;
    Ok(task_ids)
}

/// The planner + claim half of a dispatch pass, with no workflow
/// fan-out: the real `claim_dispatchable_tasks` — stale-lease
/// recovery, shape requeue, freeze probe, capacity reads and the
/// paged eligible walk with its coverage oracle — then `next_alarm`
/// over the post-claim queue. A focused floor probe prices what an
/// alarm wake pays to plan and claim under the floor; running the
/// pass's `trigger_build` fan-out instead would dispatch unrecorded
/// workflows and contaminate the run/outcome/median state later
/// drives measure (stow#525). The rows it moves restore from the
/// drive's unmetered `restore_rows` snapshot — the claim ids never
/// enter `claimed_tasks`, so the launch gate's marginal divisor
/// counts only the measured hot pass.
async fn floor_claim_probe(
    db: &DurableDb,
    settings: &SchedulerSettings,
    #[allow(unused_variables)] ctx: &DriveContext,
) -> Result<Vec<String>, String> {
    let task_ids = {
        #[cfg(target_arch = "wasm32")]
        {
            let d1 = ctx
                .d1
                .as_ref()
                .ok_or_else(|| "floor claim probe needs the counted D1".to_owned())?;
            let coverage = super::object::CatalogCoverage { db: d1.clone() };
            queue::claim_dispatchable_tasks(db, settings, &coverage)
                .await
                .map_err(|error| error.to_string())?
                .iter()
                .map(|task| task.task_id.clone())
                .collect::<Vec<String>>()
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            queue::claim_dispatchable_tasks(db, settings, &NoCoverage)
                .await
                .map_err(|error| error.to_string())?
                .iter()
                .map(|task| task.task_id.clone())
                .collect::<Vec<String>>()
        }
    };
    // The drive's unmetered cleanup restores every touched row from
    // the setup snapshot — the claim ids stay out of `claimed_tasks`
    // (the launch gate's marginal divisor counts the hot pass only)
    // and out of the probe restore list the drain walks.
    // The real current time on wasm — the plan the pass would arm —
    // and the deterministic clock the host gate always uses.
    #[cfg(target_arch = "wasm32")]
    #[allow(clippy::cast_possible_truncation)]
    let now_ms = js_sys::Date::now() as i64;
    #[cfg(not(target_arch = "wasm32"))]
    let now_ms = 0_i64;
    queue::next_alarm(db, now_ms, settings)
        .await
        .map_err(|error| error.to_string())?;
    Ok(task_ids)
}

/// Slice rows a delta report moves — retired from the live set plus the
/// same number added. The dependent refresh must stay proportional to
/// this, not to the slice.
pub const DELTA_ROWS: u32 = 30;

/// A coverage oracle that answers "not covered" for every row — the
/// catalog is empty under the fixture, which is the shape a cold cache
/// presents. Host-side only: the wasm pass drive uses the real
/// `CatalogCoverage` over the counted D1.
#[cfg(not(target_arch = "wasm32"))]
struct NoCoverage;

#[cfg(not(target_arch = "wasm32"))]
impl CoverageOracle for NoCoverage {
    fn covered(
        &self,
        _identities: &[SemanticTaskIdentity],
    ) -> impl Future<Output = Result<BTreeSet<SemanticTaskIdentity>, crate::errors::QueueError>> + Send
    {
        std::future::ready(Ok(BTreeSet::new()))
    }
}

use stow_types::fixture::task_hex_id as hex_id;

/// The crate identity a queue row carries — the same formulas the seed
/// SQL uses, kept in one place so a drive always names a real row. The
/// pair is injective in `n` at any fixture size; the name's version
/// set is bounded at `CRATE_NAME_ROWS` (see fixture), so a
/// `crate_name =` probe's cardinality cannot grow with the table.
fn crate_identity(n: u32) -> (String, String) {
    (
        format!("crate{}", n / super::fixture::CRATE_NAME_ROWS),
        format!("1.{}.{}", n / 20000, n % 500),
    )
}

/// A submit batch: a resync of fixture row 101's identity (its edge set
/// is rewritten — the delta edge sync), one fresh miss task, and one
/// human-lane request — the request mix the enqueue path sees in
/// production. Deps name completed fixture rows, so the edges resolve.
fn submit_batch(shape: FixtureShape) -> Vec<EnqueueRequest> {
    submit_batch_named(
        shape,
        &crate_identity(101).0,
        "costgate-fresh",
        "costgate-human",
    )
}

/// The accept half's batch names its own tasks: an accepted submit
/// leaves rows and edges behind, so reusing the trusted pair's task
/// identities would move the later drives from the insert path they
/// measure onto a resync one (stow#452 — the merge-queue probe caught
/// the trusted drive resyncing the accept drive's task set).
fn submit_accept_batch(shape: FixtureShape) -> Vec<EnqueueRequest> {
    submit_batch_named(
        shape,
        "costgate-accept",
        "costgate-accept-fresh",
        "costgate-accept-human",
    )
}

fn submit_batch_named(
    shape: FixtureShape,
    resync_name: &str,
    fresh_name: &str,
    human_name: &str,
) -> Vec<EnqueueRequest> {
    let target_of = dep_target;
    let dep = dep_request;
    let (_resync_crate, resync_version) = crate_identity(101);
    let resync = EnqueueRequest {
        crate_name: resync_name.parse().expect("resync crate"),
        version: resync_version.parse().expect("resync version"),
        features_json: FeaturesJson::default(),
        target: target_of(101).parse().expect("resync target"),
        rustc_version: "1.86.0".parse().expect("resync rustc"),
        downloads: 10,
        source: EnqueueSource::CacheMiss,
        depends_on: (0..30).map(|k| dep(shape.dep_row(k))).collect(),
        preserve_lockfile: false,
        host_side: false,
    };
    let mut fresh = resync.clone();
    fresh.crate_name = fresh_name.parse().expect("fresh crate");
    fresh.depends_on = vec![dep(shape.dep_row(31))];
    let mut human = resync.clone();
    human.crate_name = human_name.parse().expect("human crate");
    human.source = EnqueueSource::HumanRequest;
    human.depends_on = Vec::new();
    vec![resync, fresh, human]
}

/// The request record the drives admit and settle — a `req-drive`
/// id `rearm_fixture` deletes between runs, so every probe measures the
/// fresh-admission path rather than a dedup hit.
const DRIVE_REQUEST_ID: &str = "req-costgate-drive";

/// The drive's admission — a fresh `req-` record per probe run.
fn drive_admission() -> stow_types::api::RequestAdmission {
    stow_types::api::RequestAdmission {
        request_id: DRIVE_REQUEST_ID.to_owned(),
        crate_name: "costgate-request".parse().expect("request crate"),
        version: "1.0.0".parse().expect("request version"),
        features_json: FeaturesJson::default(),
        rustc_version: "1.86.0".parse().expect("request rustc"),
        max_closure: 500,
    }
}

/// The `POST /requests` drive: the full pass on wasm (credential arm +
/// the dispatch hop), the queue-layer calls on host.
async fn admit_request_drive(
    db: &DurableDb,
    settings: &SchedulerSettings,
    ctx: &DriveContext,
) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        let env = ctx
            .env
            .as_ref()
            .ok_or_else(|| "requests drive needs a Worker env".to_owned())?;
        super::object::admit_request_pass(env, db, settings, &drive_admission(), 0)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = ctx;
        queue::admit_request(db, &drive_admission(), 0, settings)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

/// The outcome report the outcome drive applies — a one-dep
/// `HumanRequest` batch whose root is its own fresh task plus a root
/// that names an existing completed row (the `was_queued` arm).
fn request_report(shape: FixtureShape) -> stow_types::api::RequestOutcomeReport {
    let crate_name = "costgate-request-root";
    let version = "1.0.0";
    let target = stow_types::api::CI_TARGET_TRIPLES[0];
    let rustc = "1.86.0";
    let root_task = EnqueueRequest {
        crate_name: crate_name.parse().expect("request crate"),
        version: version.parse().expect("request version"),
        features_json: FeaturesJson::default(),
        target: target.parse().expect("request target"),
        rustc_version: rustc.parse().expect("request rustc"),
        downloads: 1,
        source: EnqueueSource::HumanRequest,
        depends_on: vec![dep_request(shape.dep_row(2))],
        preserve_lockfile: false,
        host_side: false,
    };
    let root_id = queue::task_id(crate_name, version, "[]", target, rustc, false);
    stow_types::api::RequestOutcomeReport {
        attempt: 1,
        outcome: stow_types::api::RequestOutcome::Resolved {
            tasks: vec![root_task],
            roots: vec![
                stow_types::api::RequestRootOutcome {
                    target: target.parse().expect("root target"),
                    task_id: Some(root_id),
                    cached: false,
                },
                stow_types::api::RequestRootOutcome {
                    target: stow_types::api::CI_TARGET_TRIPLES[1]
                        .parse()
                        .expect("second target"),
                    // An existing completed row — the `was_queued` arm.
                    // Row 3 stays clear of the purge drive's row-0/1
                    // deletes, which run earlier in this list.
                    task_id: Some(hex_id(u64::from(shape.completed_row(3)))),
                    cached: false,
                },
            ],
        },
    }
}

/// The fixture-row target the dep identities spread over.
fn dep_target(n: u32) -> &'static str {
    stow_types::api::CI_TARGET_TRIPLES[usize::try_from(n).unwrap() % 9]
}

/// One dependency edge on fixture row `n` — the same identity formulas
/// the queue seed wrote, so the edge resolves.
fn dep_request(n: u32) -> EnqueueDependency {
    let (crate_name, version) = crate_identity(n);
    EnqueueDependency {
        crate_name: crate_name.parse().expect("dep crate"),
        version: version.parse().expect("dep version"),
        features_json: FeaturesJson::default(),
        target: dep_target(n).parse().expect("dep target"),
        rustc_version: if n % 3 < 2 {
            "1.85.0".parse().expect("dep rustc")
        } else {
            "1.86.0".parse().expect("dep rustc")
        },
        host_side: n.is_multiple_of(10),
    }
}

/// A node's published membership — production's `required_unit_shapes`
/// at the node's own side and the invocation `for_task` assigns its
/// target on the family's host triple.
fn node_shapes(host_side: bool, target: &str) -> Vec<UnitShape> {
    let invocation = stow_types::api::runner_family(target)
        .map_or(UnitInvocation::Native, |family| {
            UnitInvocation::for_task(target, family.host_triple())
        });
    stow_types::public_cache::required_unit_shapes(host_side, invocation)
}

/// The full-report drive's slice: a held-size membership (100 rows) on
/// a dedicated slice — `CI_TARGET_TRIPLES[8]` / `9.9.9` — that the seed
/// never writes, so the same report shape applies at both fixture
/// sizes. Fifty identities carry both rows of their
/// `required_unit_shapes`, the membership a genuinely completed node
/// publishes.
fn full_slice_report() -> Vec<PublishedSliceRow> {
    let target = stow_types::api::CI_TARGET_TRIPLES[8];
    (0..50)
        .flat_map(|i| {
            node_shapes(false, target)
                .into_iter()
                .map(move |shape| PublishedSliceRow {
                    crate_name: format!("stow-gate-full-{i}").parse().expect("full crate"),
                    version: "1.0.0".parse().expect("full version"),
                    features_json: FeaturesJson::default(),
                    unit_shape: Some(shape),
                })
        })
        .collect()
}

/// The delta report for `(CI_TARGET_TRIPLES[0], '1.85.0')`: retire one
/// required shape row of each of the slice's [`DELTA_ROWS`] tail
/// members and add as many fresh rows (`DELTA_ROWS / 2` identities ×
/// their two shapes) — a `2 * DELTA_ROWS` change set. Every retired
/// row is one the fixture actually stores for that node — its first
/// `required_unit_shapes` entry — so each retire leaves a real node
/// partially published, the missing-shape probe the dependent refresh
/// measures; it is never a shape nobody published. The fixture's live
/// members are the completed rows whose `n % 9` lands on that target —
/// `n % 9 == 0` implies `n % 3 == 0`, the `1.85.0` rustc arm.
fn delta_slice_report(shape: FixtureShape) -> (Vec<PublishedSliceRow>, Vec<PublishedSliceRow>) {
    let live = shape.slice_live_rows(0);
    let first = shape.slice_first_row(0);
    let target = stow_types::api::CI_TARGET_TRIPLES[0];
    let mut retired = Vec::new();
    let mut added = Vec::new();
    for i in 0..DELTA_ROWS {
        let n = first + (live - 1 - i) * 9;
        let (crate_name, version) = crate_identity(n);
        retired.push(PublishedSliceRow {
            crate_name: crate_name.parse().expect("retire crate"),
            version: version.parse().expect("retire version"),
            features_json: FeaturesJson::default(),
            unit_shape: Some(node_shapes(n.is_multiple_of(10), target)[0]),
        });
    }
    for i in 0..DELTA_ROWS / 2 {
        added.extend(
            node_shapes(false, target)
                .into_iter()
                .map(|shape| PublishedSliceRow {
                    crate_name: format!("stow-gate-delta-{i}").parse().expect("delta crate"),
                    version: "9.9.9".parse().expect("delta version"),
                    features_json: FeaturesJson::default(),
                    unit_shape: Some(shape),
                }),
        );
    }
    (added, retired)
}
