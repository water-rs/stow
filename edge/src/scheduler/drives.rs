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

use super::feed;
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
    /// Σ D1 `meta` rows and Σ awaited wall the counted backend
    /// observed — read back into the report row after each drive.
    /// `(rows_read, rows_written, elapsed_ms)`.
    pub d1_rows: std::sync::Arc<std::sync::Mutex<(u64, u64, u64)>>,
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
            d1_rows: std::sync::Arc::new(std::sync::Mutex::new((0, 0, 0))),
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
        let d1_rows = std::sync::Arc::new(std::sync::Mutex::new((0u64, 0u64, 0u64)));
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
    pub fn d1_counts(&self) -> (u64, u64, u64) {
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

/// A phase of [`drive_lifecycle`], in execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecyclePhase {
    /// The unmetered fixture hook.
    Setup,
    /// The durability barrier confirming all earlier fixture writes
    /// before the measured window opens.
    PreSync,
    /// The metered pass itself.
    Run,
    /// The barrier confirming this drive's own writes — inside the
    /// measured window, so the drive pays its real commit cost.
    PostSync,
    /// The unconditional isolation hook.
    Cleanup,
}

impl LifecyclePhase {
    /// The phase's native log label — the exact token the probe's
    /// `phase=` traces and both harnesses' diagnostics share.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::PreSync => "pre_sync",
            Self::Run => "run",
            Self::PostSync => "post_sync",
            Self::Cleanup => "cleanup",
        }
    }
}

/// A boundary of [`drive_lifecycle`], delivered to the observer
/// immediately before (`Starting`) or after (`Finished`) the phase's
/// await resolves — the points a probe reads its clock and snapshots
/// its counters. The callback is synchronous and never awaits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseMark {
    /// The phase's await is about to begin.
    Starting(LifecyclePhase),
    /// The phase's await resolved.
    Finished(LifecyclePhase),
}

/// One drive's per-phase outcomes, kept separate so each caller
/// decides how to price or report the measured window. `None` marks
/// a phase that never ran: everything after `setup` stays `None` when
/// setup failed, and `run`/`post_sync` stay `None` when the pre-sync
/// barrier failed. The barrier errors carry their `pre_sync:`/
/// `post_sync:` phase labels; the hooks' errors are the drive's own.
#[derive(Debug)]
pub struct DriveOutcome {
    /// The unmetered fixture hook. `Err` aborts the lifecycle —
    /// neither barrier, the run, nor cleanup ran.
    pub setup: Result<(), String>,
    /// The fixture barrier — always attempted once setup succeeded.
    pub pre_sync: Option<Result<(), String>>,
    /// The measured pass — `None` when the pre-sync barrier failed.
    pub run: Option<Result<(), String>>,
    /// The in-window barrier — attempted whenever the run was, even
    /// when it failed.
    pub post_sync: Option<Result<(), String>>,
    /// The isolation hook — unconditional once setup succeeded,
    /// including when an earlier phase failed.
    pub cleanup: Option<Result<(), String>>,
}

/// The drive lifecycle every harness shares — the workerd probe's
/// `budget::run_drive` and the host gate's `cost_gate::run_one_drive`
/// call this one orchestration so the ordering contract exists once:
/// unmetered `setup` on `db`; `db.sync()` confirming every earlier
/// fixture write; the measured `run` against `run_db`; a second
/// `db.sync()` inside the window so the drive's own write
/// confirmation is part of its cost; then `cleanup` unconditionally.
/// A failed setup aborts the whole lifecycle; a failed barrier skips
/// the run but never cleanup; a failed run still post-syncs and
/// cleans up. `mark` fires at each phase boundary — where a probe
/// reads its clock — and is synchronous: it must not await, so it
/// cannot refresh the worker clock or move the span it measures.
pub async fn drive_lifecycle(
    drive: &Drive,
    db: &DurableDb,
    run_db: &DurableDb,
    shape: FixtureShape,
    settings: &SchedulerSettings,
    ctx: &DriveContext,
    mark: &mut (dyn FnMut(PhaseMark) + Send),
) -> DriveOutcome {
    let mut outcome = DriveOutcome {
        setup: Ok(()),
        pre_sync: None,
        run: None,
        post_sync: None,
        cleanup: None,
    };
    if let Some(setup) = drive.setup {
        mark(PhaseMark::Starting(LifecyclePhase::Setup));
        let result = setup(db, shape, settings, ctx).await;
        mark(PhaseMark::Finished(LifecyclePhase::Setup));
        if let Err(error) = result {
            // Setup's own contract is unchanged: its failure aborts
            // the drive — no run, no barriers, no cleanup.
            outcome.setup = Err(error);
            return outcome;
        }
    }
    mark(PhaseMark::Starting(LifecyclePhase::PreSync));
    let pre_sync = db
        .sync()
        .await
        .map_err(|error| format!("pre_sync: {error}"));
    mark(PhaseMark::Finished(LifecyclePhase::PreSync));
    if pre_sync.is_ok() {
        mark(PhaseMark::Starting(LifecyclePhase::Run));
        outcome.run = Some((drive.run)(run_db, shape, settings, ctx).await);
        mark(PhaseMark::Finished(LifecyclePhase::Run));
        mark(PhaseMark::Starting(LifecyclePhase::PostSync));
        outcome.post_sync = Some(
            db.sync()
                .await
                .map_err(|error| format!("post_sync: {error}")),
        );
        mark(PhaseMark::Finished(LifecyclePhase::PostSync));
    }
    outcome.pre_sync = Some(pre_sync);
    if let Some(cleanup) = drive.cleanup {
        mark(PhaseMark::Starting(LifecyclePhase::Cleanup));
        outcome.cleanup = Some(cleanup(db, shape, settings, ctx).await);
        mark(PhaseMark::Finished(LifecyclePhase::Cleanup));
    }
    outcome
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
        setup: Some(|db, shape, settings, _ctx| {
            Box::pin(async move {
                // Land the batch's resync entry first so the measured
                // submit hits it on its derived task id — seeded rows
                // carry synthetic ids no request can re-mint (stow#588),
                // so the row the resync probes must come from a real
                // enqueue. Setup statements are truncated out of the
                // measurement.
                queue::enqueue_trusted(db, &submit_batch(shape)[..1], settings)
                    .await
                    .map_err(|error| error.to_string())
                    .and_then(|inserted| {
                        (inserted == 1).then_some(()).ok_or_else(|| {
                            format!("trusted submit setup inserted {inserted}, expected 1")
                        })
                    })
            })
        }),
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
                            errors
                                .push(format!("floored pass claimed {leaked} under-floor row(s)"));
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
        // The claimed tasks' subgraph rebuild (stow#588) is priced in
        // the same pass: `load_claimed_subgraphs` pays one bounded
        // `task_id IN (…)` read per shared BFS level — at most
        // `SUBGRAPH_WALK_MAX_LEVELS` (64) statements and `O(Σ reachable
        // nodes)` rows read, bounded by the dispatched tasks' own
        // subgraphs, never the queue bulk.
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
    Drive {
        // The feed's resume-cursor read (stow#523): one watermark
        // probe plus the bounded unfinished-index probe — two point
        // reads, flat in retained depth.
        name: "GET /scheduler/demand-feed/status",
        setup: None,
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                feed::feed_status(db)
                    .await
                    .map(|_status| ())
                    .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        // Opening a fresh hour (stow#523): closed-hour check,
        // watermark guard, the header insert and generation
        // read-back — four statements, no rotation work.
        name: "POST /scheduler/demand-feed/begin (fresh)",
        setup: None,
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                feed::feed_begin(db, &feed_drive_hour(3), feed_drive_now_secs(3))
                    .await
                    .map(|_report| ())
                    .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        // Re-opening a staging hour with real debris (stow#523):
        // setup opens the hour and bulk-seeds 512 pages under its
        // live generation, so the measured rotate pays the full
        // restart — counter reset, generation bump, one 256-row
        // retire chunk, and a `stale_pages_pending` verdict that is
        // true — never an empty degenerate rotate.
        name: "POST /scheduler/demand-feed/begin (rotation)",
        setup: Some(|db, _shape, _settings, _ctx| {
            Box::pin(async move {
                let hour = feed_drive_hour(4);
                let generation = feed::feed_begin(db, &hour, feed_drive_now_secs(4))
                    .await
                    .map_err(|error| error.to_string())?
                    .generation;
                seed_stale_feed_pages(db, &hour, generation, 512).await
            })
        }),
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                let report = feed::feed_begin(db, &feed_drive_hour(4), feed_drive_now_secs(4))
                    .await
                    .map_err(|error| error.to_string())?;
                if !report.stale_pages_pending {
                    return Err("rotation begin must report obsolete pages pending".to_owned());
                }
                Ok(())
            })
        },
        cleanup: Some(|db, _shape, _settings, _ctx| {
            Box::pin(async move {
                // 512 seeded, the rotation retired one 256 chunk.
                let left = db
                    .query(
                        "SELECT COUNT(*) FROM demand_feed_pages \
                         WHERE hour = '2020-01-01T04' \
                           AND generation < (SELECT generation \
                                             FROM demand_feed_hours \
                                             WHERE hour = '2020-01-01T04')",
                    )
                    .fetch_scalar::<i64>()
                    .await
                    .map_err(|error| format!("rotation leftover probe: {error}"))?;
                if left != 256 {
                    return Err(format!("rotation left {left} obsolete pages, expected 256"));
                }
                Ok(())
            })
        }),
    },
    Drive {
        // Staging one bounded page (stow#523): setup opens the hour
        // and stages page 0 through the real `feed_page`, then builds
        // the exact wire request for page 1 from the live generation
        // — so the metered run is only the handler: closed-hour
        // check, header probe, in-order/matching-generation guards,
        // the payload insert and its trigger.
        name: "POST /scheduler/demand-feed/page (append)",
        setup: Some(|db, _shape, _settings, _ctx| {
            Box::pin(async move {
                feed_drive_begin(db, 5).await?;
                feed_seed_page(db, &feed_drive_hour(5), 0, 4, feed_drive_entries).await
            })
        }),
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                feed::feed_page(
                    db,
                    &feed_drive_page_request(5, 1, 4, feed_drive_entries)?,
                    feed_drive_now_secs(5),
                )
                .await
                .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        // A replayed page of the same bytes: the guards plus the
        // stored-hash compare that answers the replay as a no-op —
        // the bounded read a retried page call owes, with zero
        // writes.
        name: "POST /scheduler/demand-feed/page (replay)",
        setup: Some(|db, _shape, _settings, _ctx| {
            Box::pin(async move {
                feed_drive_begin(db, 6).await?;
                feed_seed_page(db, &feed_drive_hour(6), 0, 4, feed_drive_entries).await
            })
        }),
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                feed::feed_page(
                    db,
                    &feed_drive_page_request(6, 0, 4, feed_drive_entries)?,
                    feed_drive_now_secs(6),
                )
                .await
                .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        // The completion barrier on a populated hour: the manifest
        // verification read of the generation's page hashes plus the
        // guarded freeze transition — the one event that binds the
        // frozen set. The request's manifest comes from the real
        // staged rows, built unmetered.
        name: "POST /scheduler/demand-feed/complete (nonempty)",
        setup: Some(|db, _shape, _settings, _ctx| {
            Box::pin(async move {
                feed_drive_begin(db, 7).await?;
                let hour = feed_drive_hour(7);
                for page_no in 0..FEED_DRIVE_PAGES {
                    feed_seed_page(db, &hour, page_no, 4, feed_drive_entries).await?;
                }
                Ok(())
            })
        }),
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                feed::feed_complete(
                    db,
                    &feed_drive_complete_request(7, &[4; 3], feed_drive_entries)?,
                    feed_drive_now_secs(7),
                )
                .await
                .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        // The same barrier on an hour with zero staged pages: the
        // counter verification against an empty generation — the
        // zero-page hour must still pay its guarded transition, and
        // its reads must not scale with retained depth.
        name: "POST /scheduler/demand-feed/complete (empty)",
        setup: Some(|db, _shape, _settings, _ctx| {
            Box::pin(async move { feed_drive_begin(db, 8).await })
        }),
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                feed::feed_complete(
                    db,
                    &feed_drive_complete_request(8, &[], feed_drive_entries)?,
                    feed_drive_now_secs(8),
                )
                .await
                .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        // One delivery call that applies the protocol's maximum
        // 256-entry page (stow#523): header read, the bounded
        // next-unapplied-page SELECT, the `demand_pass` closure over
        // the entries' touched dependency graph, the acknowledged
        // flip and counter read-back, plus the wake re-plan — whose
        // alarm probe cost is bounded by the dispatch cap, not the
        // page. The page's entries name the setup's own fixed event
        // subgraph (`seed_feed_event_subgraph`), so the measured
        // closure is exactly 256 roots + 128 shared deps = 384
        // touched tasks at every fixture shape — the scale check
        // separates this event's work from stored bulk; a production
        // 256-root page is bounded by whatever dependency closure
        // its entries reach, which this fixture does not claim to
        // bound. The unmetered cleanup deletes exactly the
        // subgraph's own primary keys.
        name: "POST /scheduler/demand-feed/deliver (page apply)",
        setup: Some(|db, _shape, settings, _ctx| {
            Box::pin(async move {
                seed_feed_event_subgraph(db, settings).await?;
                seed_feed_hour_sized(db, 0, &[256, 4], feed_event_entries).await
            })
        }),
        run: |db, _shape, settings, _ctx| {
            Box::pin(async move {
                feed::feed_deliver(db, &feed_drive_hour(0), feed_drive_now_ms(0), settings)
                    .await
                    .map(|(_report, _plan)| ())
                    .map_err(|error| error.to_string())
            })
        },
        cleanup: Some(|db, _shape, _settings, _ctx| {
            Box::pin(async move { clear_feed_event_subgraph(db).await })
        }),
    },
    Drive {
        // The delivery call on an hour whose pages all applied
        // already: a transition-only event — header read, owed-page
        // probe, then the contiguous-watermark guarded transition to
        // `delivered`, priced separately from a mid-hour apply.
        name: "POST /scheduler/demand-feed/deliver (terminal)",
        setup: Some(|db, _shape, settings, _ctx| {
            Box::pin(async move {
                // Contiguity: T01's transition needs the watermark at
                // T00, so the predecessor delivers fully in unmetered
                // setup — then T01 stages and every page applies,
                // leaving the hour one call short of `delivered`.
                deliver_feed_hour_fully(db, 0, settings).await?;
                seed_feed_hour(db, 1, FEED_DRIVE_PAGES).await?;
                for _ in 0..FEED_DRIVE_PAGES {
                    feed::feed_deliver(db, &feed_drive_hour(1), feed_drive_now_ms(1), settings)
                        .await
                        .map_err(|error| error.to_string())?;
                }
                Ok(())
            })
        }),
        run: |db, _shape, settings, _ctx| {
            Box::pin(async move {
                feed::feed_deliver(db, &feed_drive_hour(1), feed_drive_now_ms(1), settings)
                    .await
                    .map(|(_report, _plan)| ())
                    .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        // A delivery replay on an already-delivered hour: the header
        // read that hits the `delivered` early-out plus the wake
        // re-plan — the bounded cost a lost-ack re-fire owes, with
        // zero ledger writes.
        name: "POST /scheduler/demand-feed/deliver (replay)",
        setup: Some(|db, _shape, settings, _ctx| {
            Box::pin(async move {
                seed_feed_hour(db, 2, FEED_DRIVE_PAGES).await?;
                deliver_feed_hour_fully(db, 2, settings).await
            })
        }),
        run: |db, _shape, settings, _ctx| {
            Box::pin(async move {
                feed::feed_deliver(db, &feed_drive_hour(2), feed_drive_now_ms(2), settings)
                    .await
                    .map(|(_report, _plan)| ())
                    .map_err(|error| error.to_string())
            })
        },
        cleanup: None,
    },
    Drive {
        // One bounded retire chunk with a full 256 obsolete pages
        // owed (stow#523): setup stages the hour, bulk-seeds 512
        // same-generation payloads, then rotates — the begin retire
        // chunk clears 256, leaving exactly one full chunk for the
        // measured `DELETE … LIMIT 256` plus its probes.
        name: "POST /scheduler/demand-feed/cleanup (full chunk)",
        setup: Some(|db, _shape, _settings, _ctx| {
            Box::pin(async move {
                // T03 is the watermark's canonical successor once
                // the deliver drives land T00–T02 — the only hour a
                // begin may still rotate.
                let hour = feed_drive_hour(3);
                let generation = feed::feed_begin(db, &hour, feed_drive_now_secs(9))
                    .await
                    .map_err(|error| error.to_string())?
                    .generation;
                seed_stale_feed_pages(db, &hour, generation, 512).await?;
                feed::feed_begin(db, &hour, feed_drive_now_secs(9))
                    .await
                    .map(|_report| ())
                    .map_err(|error| error.to_string())
            })
        }),
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                let report = feed::feed_cleanup(db, &feed_drive_hour(3), feed_drive_now_secs(3))
                    .await
                    .map_err(|error| error.to_string())?;
                if report.retired != 256 {
                    return Err(format!(
                        "cleanup full chunk retired {}, expected 256",
                        report.retired
                    ));
                }
                Ok(())
            })
        },
        cleanup: None,
    },
    Drive {
        // The retire probe on the bulk staging hour '2022-01-01T00'
        // (stow#523): setup deletes that hour's obsolete-generation
        // rows in one unmetered pass, so the measured cleanup scans
        // its `generation < current` predicate over the growing
        // current-generation bulk (queue_rows/16 pages, up to 64k at
        // 1M) and must match zero — proof the retire index stays
        // flat instead of walking live rows.
        name: "POST /scheduler/demand-feed/cleanup (none obsolete)",
        setup: Some(|db, _shape, _settings, _ctx| {
            Box::pin(async move {
                // The staging bulk arrives through the fixture's own
                // `FeedStaged` seed phase — this setup's only job is
                // draining the obsolete-generation tail so the
                // measured retire predicate must scan past the live
                // bulk and match nothing.
                db.query(
                    "DELETE FROM demand_feed_pages \
                     WHERE hour = '2022-01-01T00' AND generation < \
                           (SELECT generation FROM demand_feed_hours \
                            WHERE hour = '2022-01-01T00')",
                )
                .execute()
                .await
                .map_err(|error| format!("drain obsolete bulk pages: {error}"))?;
                Ok(())
            })
        }),
        run: |db, _shape, _settings, _ctx| {
            Box::pin(async move {
                let report = feed::feed_cleanup(db, &feed_bulk_drive_hour(), FEED_BULK_NOW_SECS)
                    .await
                    .map_err(|error| error.to_string())?;
                if report.retired != 0 || report.remaining {
                    return Err(format!(
                        "cleanup none-obsolete retired {}/remaining {}",
                        report.retired, report.remaining
                    ));
                }
                Ok(())
            })
        },
        cleanup: Some(|db, shape, _settings, _ctx| {
            Box::pin(async move {
                // The live bulk survived untouched: current-
                // generation pages still number exactly the seeded
                // staged_pages, growing 100k -> 1M with the shape.
                let expected = i64::from(super::fixture::feed_staged_pages(shape));
                let live = db
                    .query(
                        "SELECT COUNT(*) FROM demand_feed_pages \
                         WHERE hour = '2022-01-01T00' AND generation = 9",
                    )
                    .fetch_scalar::<i64>()
                    .await
                    .map_err(|error| format!("live bulk probe: {error}"))?;
                if live != expected {
                    return Err(format!(
                        "cleanup disturbed live bulk: {live} pages, expected {expected}"
                    ));
                }
                Ok(())
            })
        }),
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
            let pass_started_ms = super::budget::clock_ms();
            let task_ids = super::object::dispatch_pass(env, db, &pass_settings, &coverage)
                .await
                .map_err(|error| error.to_string())?;
            tracing::info!(
                "budget span pass=dispatch_pass idle={idle} elapsed_ms={}",
                super::budget::clock_ms() - pass_started_ms
            );
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
                let token_started_ms = super::budget::clock_ms();
                let _ = crate::github_app::installation_token(db, &config)
                    .await
                    .map_err(|error| error.to_string())?;
                tracing::info!(
                    "budget span pass=installation_token elapsed_ms={}",
                    super::budget::clock_ms() - token_started_ms
                );
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
    #[cfg(target_arch = "wasm32")]
    let alarm_started_ms = super::budget::clock_ms();
    let result = queue::next_alarm(db, 0, &pass_settings).await;
    #[cfg(target_arch = "wasm32")]
    tracing::info!(
        "budget span pass=next_alarm elapsed_ms={}",
        super::budget::clock_ms() - alarm_started_ms
    );
    result.map_err(|error| error.to_string())?;
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
/// Test subgraph carrying `deps` as the root's direct leaf deps
/// (stow#588).
fn subgraph_of(deps: &[stow_types::api::EnqueueDependency]) -> stow_types::api::TaskSubgraph {
    stow_types::api::TaskSubgraph {
        root_deps: (0..u32::try_from(deps.len()).expect("test dep count")).collect(),
        nodes: deps
            .iter()
            .map(|dep| stow_types::api::SubgraphNode {
                crate_name: dep.crate_name.clone(),
                version: dep.version.clone(),
                features_json: dep.features_json.clone(),
                host_side: dep.host_side,
                deps: Vec::new(),
            })
            .collect(),
    }
}

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
        dependency_subgraph: subgraph_of(
            &(0..30).map(|k| dep(shape.dep_row(k))).collect::<Vec<_>>(),
        ),
        preserve_lockfile: false,
        host_side: false,
    };
    let mut fresh = resync.clone();
    fresh.crate_name = fresh_name.parse().expect("fresh crate");
    fresh.dependency_subgraph = subgraph_of(&[dep(shape.dep_row(31))]);
    let mut human = resync.clone();
    human.crate_name = human_name.parse().expect("human crate");
    human.source = EnqueueSource::HumanRequest;
    human.dependency_subgraph = stow_types::api::TaskSubgraph {
        root_deps: Vec::new(),
        nodes: Vec::new(),
    };
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
        dependency_subgraph: subgraph_of(&[dep_request(shape.dep_row(2))]),
        preserve_lockfile: false,
        host_side: false,
    };
    let root_id = root_task.task_id().expect("derived root task id");
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

/// Feed drives stage on deterministic closed hours `2020-01-01T00`
/// through `T10` — each drive's own hour keeps protocol state
/// isolated, and `now` one second past its end passes `ensure_closed`
/// on both targets without a wall clock.
fn feed_drive_hour(idx: u32) -> stow_types::api::DemandFeedHour {
    stow_types::api::DemandFeedHour::parse(&format!("2020-01-01T{idx:02}"))
        .expect("feed drive hour is canonical")
}

/// Milliseconds one second past the end of drive hour `idx`.
const fn feed_drive_now_ms(idx: u32) -> i64 {
    (1_577_840_400 + idx as i64 * 3_600 + 1) * 1_000
}

/// The same instant in unix seconds for the staging routes.
const fn feed_drive_now_secs(idx: u32) -> i64 {
    feed_drive_now_ms(idx) / 1_000
}

/// Pages the feed drives stage — real fixture-identity pages whose
/// four entries touch queue rows the demand closure resolves.
const FEED_DRIVE_PAGES: u32 = 3;

/// The bulk staging hour the `FeedStaged` seed phase plants
/// current-generation
/// depth under — the none-obsolete cleanup drive's target.
fn feed_bulk_drive_hour() -> stow_types::api::DemandFeedHour {
    stow_types::api::DemandFeedHour::parse("2022-01-01T00").expect("bulk feed hour is canonical")
}

/// One second past the bulk staging hour's close — its
/// `ensure_closed` input (well below the wall clock, so the checked
/// hour math stays exercised).
const FEED_BULK_NOW_SECS: i64 = 1_672_531_201;

/// How a drive's staging resolves one page's entries — a pure
/// `(page_no, count) -> entries` map shared verbatim by the staged
/// payload bytes, the wire page request and the manifest hash, so
/// the run the measured `feed_deliver` decodes is exactly the
/// bytes setup froze (stow#523).
type FeedPageEntries = fn(u32, u32) -> Result<Vec<stow_types::api::SchedulerDemandEntry>, String>;

/// Page `page_no`'s deterministic entries — `count` rows at
/// `n = 100 + page_no·256 + k` use the same identity formulas the
/// demand drive's batch does, so a delivery closure touches real
/// fixture rows. The 256 spacing keeps every entry of the
/// protocol's maximum page on a distinct fixture node.
fn feed_drive_entries(
    page_no: u32,
    count: u32,
) -> Result<Vec<stow_types::api::SchedulerDemandEntry>, String> {
    (0..count)
        .map(
            |k| -> Result<stow_types::api::SchedulerDemandEntry, String> {
                let n = 100 + page_no * 256 + k;
                let (crate_name, version) = crate_identity(n);
                Ok(stow_types::api::SchedulerDemandEntry {
                    crate_name: CrateName::parse(&crate_name).map_err(|e| e.to_string())?,
                    version: CrateVersion::new(
                        semver::Version::parse(&version).map_err(|e| e.to_string())?,
                    ),
                    features_json: FeaturesJson::default(),
                    target: TargetTriple::parse(dep_target(n)).map_err(|e| e.to_string())?,
                    rustc_version: WireRustcVersion::parse("1.86.0").map_err(|e| e.to_string())?,
                    demand: 100,
                })
            },
        )
        .collect()
}

/// The generation every feed drive pins its hour to — the begin
/// report's wall-clock value varies run to run, so unmetered setup
/// stamps one deterministic number and the measured run builds its
/// wire request as a pure typed constructor against it, never
/// re-reading the row (stow#523).
const FEED_DRIVE_GENERATION: i64 = 7;

/// A begin plus the generation pin — unmetered setup for every
/// drive whose run posts a page or complete request.
async fn feed_drive_begin(db: &DurableDb, idx: u32) -> Result<(), String> {
    let hour = feed_drive_hour(idx);
    feed::feed_begin(db, &hour, feed_drive_now_secs(idx))
        .await
        .map_err(|error| error.to_string())?;
    db.query("UPDATE demand_feed_hours SET generation = ? WHERE hour = ?")
        .bind(FEED_DRIVE_GENERATION)
        .bind(hour.as_str())
        .execute()
        .await
        .map_err(|error| format!("pin {hour} generation: {error}"))?;
    Ok(())
}

/// The pure typed page request — known generation, entries from
/// the hour's own source.
fn feed_drive_page_request(
    idx: u32,
    page_no: u32,
    count: u32,
    entries: FeedPageEntries,
) -> Result<stow_types::api::DemandFeedPageRequest, String> {
    Ok(stow_types::api::DemandFeedPageRequest {
        hour: feed_drive_hour(idx),
        generation: FEED_DRIVE_GENERATION,
        page_no,
        entries: entries(page_no, count)?,
    })
}

/// The pure typed complete request — `counts[k]` is page `k`'s entry
/// count; counters and the manifest derive from the same wire
/// entries, never a probe SELECT.
fn feed_drive_complete_request(
    idx: u32,
    counts: &[u32],
    entries: FeedPageEntries,
) -> Result<stow_types::api::DemandFeedCompleteRequest, String> {
    let mut hashes = Vec::with_capacity(counts.len());
    let mut entry_count = 0_u64;
    for (page_no, count) in counts.iter().enumerate() {
        let entries = entries(u32::try_from(page_no).expect("page index"), *count)?;
        entry_count += u64::from(*count);
        hashes.push(stow_types::api::demand_feed_page_hash(&entries)?);
    }
    let manifest = stow_types::api::demand_feed_manifest(&hashes)
        .map(|hash| hash.to_hex().to_string())
        .unwrap_or_default();
    Ok(stow_types::api::DemandFeedCompleteRequest {
        hour: feed_drive_hour(idx),
        generation: FEED_DRIVE_GENERATION,
        page_count: u32::try_from(counts.len()).expect("page count"),
        entry_count,
        manifest_hash: manifest,
    })
}

/// Stage `page_no` under the pinned generation through the real
/// `feed_page`.
async fn feed_seed_page(
    db: &DurableDb,
    hour: &stow_types::api::DemandFeedHour,
    page_no: u32,
    count: u32,
    entries: FeedPageEntries,
) -> Result<(), String> {
    let request = feed_drive_page_request(hour_idx(hour), page_no, count, entries)?;
    feed::feed_page(db, &request, feed_drive_now_secs(hour_idx(hour)))
        .await
        .map_err(|error| error.to_string())
}

/// Recover the drive hour's index from its canonical string.
fn hour_idx(hour: &stow_types::api::DemandFeedHour) -> u32 {
    hour.as_str()[11..13].parse().expect("drive hour index")
}

/// Freeze the drive hour through the real `feed_complete` — the
/// pure typed request from the page sizes the setup staged.
async fn seed_feed_complete(
    db: &DurableDb,
    hour: &stow_types::api::DemandFeedHour,
    counts: &[u32],
    entries: FeedPageEntries,
) -> Result<(), String> {
    let request = feed_drive_complete_request(hour_idx(hour), counts, entries)?;
    feed::feed_complete(db, &request, feed_drive_now_secs(hour_idx(hour)))
        .await
        .map_err(|error| error.to_string())
}

/// Bulk-seed `count` obsolete-generation payloads for a staging hour —
/// retirable debris for the cleanup drives. Direct unmetered INSERT:
/// the rows' hashes/payloads are never applied or verified (stale
/// generations retire unseen), and the rotation that follows resets
/// the staged counters the insert trigger inflated.
async fn seed_stale_feed_pages(
    db: &DurableDb,
    hour: &stow_types::api::DemandFeedHour,
    generation: i64,
    count: u32,
) -> Result<(), String> {
    db.query(include_str!("feed_stale_pages.sql"))
        .bind(i64::from(count))
        .bind(hour.as_str())
        .bind(generation)
        .execute()
        .await
        .map_err(|error| format!("seed stale feed pages: {error}"))
        .map(|_| ())
}

/// Materialize drive hour `idx` through the feed's own calls —
/// begin under the pinned generation, the `counts` real
/// fixture-identity pages in order, then the manifest freeze — so
/// delivery sees a complete hour exactly as the cron path leaves it.
/// `counts[k]` is page `k`'s entry count, letting a drive stage the
/// protocol's maximum 256-entry page. Idempotent on a persisted
/// fixture: a watermark at or past the hour makes seeding a no-op.
async fn seed_feed_hour_sized(
    db: &DurableDb,
    idx: u32,
    counts: &[u32],
    entries: FeedPageEntries,
) -> Result<(), String> {
    let hour = feed_drive_hour(idx);
    if let Some(watermark) = feed::feed_status(db)
        .await
        .map_err(|error| error.to_string())?
        .watermark
        && watermark.as_str() >= hour.as_str()
    {
        return Ok(());
    }
    // A sibling drive may already have materialized the hour —
    // `complete`/`delivered` headers need no seed, and re-beginning a
    // frozen hour is the protocol's own refusal.
    let existing = db
        .query("SELECT state FROM demand_feed_hours WHERE hour = ?")
        .bind(hour.as_str())
        .fetch_scalar_optional::<String>()
        .await
        .map_err(|error| format!("read drive hour state: {error}"))?;
    if existing.is_some_and(|state| state != "staging") {
        return Ok(());
    }
    feed_drive_begin(db, idx).await?;
    for (page_no, count) in counts.iter().enumerate() {
        feed_seed_page(
            db,
            &hour,
            u32::try_from(page_no).expect("page index"),
            *count,
            entries,
        )
        .await?;
    }
    seed_feed_complete(db, &hour, counts, entries).await
}

/// The shared seed: `pages` uniform four-entry pages.
async fn seed_feed_hour(db: &DurableDb, idx: u32, pages: u32) -> Result<(), String> {
    seed_feed_hour_sized(
        db,
        idx,
        &vec![4; usize::try_from(pages).expect("pages")],
        feed_drive_entries,
    )
    .await
}

/// Drive a staged hour to `delivered` in unmetered setup — every
/// unapplied page plus the terminal transition, looping on the
/// report's own state so page-count changes never desync.
async fn deliver_feed_hour_fully(
    db: &DurableDb,
    idx: u32,
    settings: &SchedulerSettings,
) -> Result<(), String> {
    seed_feed_hour(db, idx, FEED_DRIVE_PAGES).await?;
    loop {
        let (report, _plan) =
            feed::feed_deliver(db, &feed_drive_hour(idx), feed_drive_now_ms(idx), settings)
                .await
                .map_err(|error| error.to_string())?;
        if report.state == "delivered" {
            return Ok(());
        }
    }
}

/// The page-apply drive's own event graph (stow#523): the stored
/// bulk's identity formulas — `crate{n}` rows with `seed_edges`
/// dependencies at `(n * k) % queue_rows` — name a *different*
/// closure at every fixture size, so a scaled-bulk run measured a
/// different event, not a bigger one. The measured 256-entry page
/// therefore names this fixed subgraph instead: 256 distinct roots,
/// each gating on two of 128 shared deps, every row born `pending`
/// and unpublished. The closure it walks is exactly 256 + 128 = 384
/// touched tasks at every bulk shape, which is what lets the scale
/// check attribute growth to stored bulk rather than a changed
/// event. The names are fixture-only (`stow-feed-*`), disjoint from
/// every seeded `crate*`/`costgate-*`/`stow-gate-*` identity, and
/// the cleanup deletes exactly these primary keys.
const FEED_EVENT_ROOTS: u32 = 256;

/// Shared deps the event subgraph's roots gate on.
const FEED_EVENT_DEPS: u32 = 128;

/// The subgraph's whole task set — roots plus shared deps — and the
/// measured page's exact closure cardinality at every fixture shape.
const FEED_EVENT_NODES: u32 = FEED_EVENT_ROOTS + FEED_EVENT_DEPS;

/// Root `k`'s crate name — one per wire entry of the max page.
fn feed_event_root_name(k: u32) -> String {
    format!("stow-feed-root-{k:03}")
}

/// Shared dep `d`'s crate name.
fn feed_event_dep_name(d: u32) -> String {
    format!("stow-feed-dep-{d:03}")
}

/// The queued `task_id` event dep `d`'s own request mints — the
/// digest-bearing id `enqueue_trusted` writes (stow#588). Fixture
/// validation names rows through the derived id, never a stored-id
/// lookup.
fn feed_event_dep_task_id(d: u32) -> String {
    feed_event_requests()[usize::try_from(d).expect("dep index")]
        .task_id()
        .expect("derived dep task id")
}

/// The queued `task_id` event root `k`'s request mints — its request
/// sits after the 128 dep requests in [`feed_event_requests`].
#[cfg(all(test, not(target_arch = "wasm32")))]
fn feed_event_root_task_id(k: u32) -> String {
    feed_event_requests()[usize::try_from(FEED_EVENT_DEPS + k).expect("root index")]
        .task_id()
        .expect("derived root task id")
}

/// The whole subgraph's task ids — 128 shared deps then 256 roots, in
/// request order — the exact primary-key set setup validates and
/// cleanup deletes.
fn feed_event_task_ids() -> Vec<String> {
    feed_event_requests()
        .iter()
        .map(|request| request.task_id().expect("derived event task id"))
        .collect()
}

/// Root `k`'s two shared deps — `k/2` and `(k/2 + 1) % 128` — so each
/// dep carries four owner edges (roots `2d`/`2d+1` on the first slot,
/// `2d-2`/`2d-1` on the second): real shared/diamond reaches a UNION
/// walk dedups, not a private tree.
const fn feed_event_deps(k: u32) -> [u32; 2] {
    [k / 2, (k / 2 + 1) % FEED_EVENT_DEPS]
}

/// The event subgraph's typed submit: 128 shared deps with no
/// outgoing edges, then 256 roots each on `feed_event_deps` — landed
/// through the real `enqueue_trusted`, so the rows and edge
/// requirement columns come from the same production code a real
/// submit runs (stow#523).
fn feed_event_requests() -> Vec<EnqueueRequest> {
    let dep_edge = |d: u32| EnqueueDependency {
        dependency_identity: stow_types::identity::DependencyIdentity::leaf().expect("leaf digest"),
        crate_name: feed_event_dep_name(d).parse().expect("event dep crate"),
        version: "1.0.0".parse().expect("event dep version"),
        features_json: FeaturesJson::default(),
        target: dep_target(d).parse().expect("event dep target"),
        rustc_version: "1.86.0".parse().expect("event dep rustc"),
        host_side: false,
    };
    (0..FEED_EVENT_DEPS)
        .map(|d| EnqueueRequest {
            dependency_subgraph: stow_types::api::TaskSubgraph {
                root_deps: Vec::new(),
                nodes: Vec::new(),
            },
            crate_name: feed_event_dep_name(d).parse().expect("event dep crate"),
            version: "1.0.0".parse().expect("event dep version"),
            features_json: FeaturesJson::default(),
            target: dep_target(0).parse().expect("event dep target"),
            rustc_version: "1.86.0".parse().expect("event dep rustc"),
            downloads: 1,
            source: EnqueueSource::CacheMiss,
            preserve_lockfile: false,
            host_side: false,
        })
        .chain((0..FEED_EVENT_ROOTS).map(|k| {
            let [first, second] = feed_event_deps(k);
            EnqueueRequest {
                crate_name: feed_event_root_name(k).parse().expect("event root crate"),
                version: "1.0.0".parse().expect("event root version"),
                features_json: FeaturesJson::default(),
                target: dep_target(0).parse().expect("event root target"),
                rustc_version: "1.86.0".parse().expect("event root rustc"),
                downloads: 1,
                source: EnqueueSource::CacheMiss,
                dependency_subgraph: subgraph_of(&[dep_edge(first), dep_edge(second)]),
                preserve_lockfile: false,
                host_side: false,
            }
        }))
        .collect()
}

/// The event hour's page-entry source (stow#523): page 0 is the
/// measured max page — its `count` entries name the seeded subgraph's
/// roots at their enqueued identities, so the delivered page's
/// closure is the fixed 384-task set at every fixture shape. Trailing
/// (and every other drive's) pages keep the fixture formula.
fn feed_event_entries(
    page_no: u32,
    count: u32,
) -> Result<Vec<stow_types::api::SchedulerDemandEntry>, String> {
    if page_no != 0 {
        return feed_drive_entries(page_no, count);
    }
    (0..count)
        .map(
            |k| -> Result<stow_types::api::SchedulerDemandEntry, String> {
                Ok(stow_types::api::SchedulerDemandEntry {
                    crate_name: CrateName::parse(feed_event_root_name(k))
                        .map_err(|e| e.to_string())?,
                    version: CrateVersion::new(
                        semver::Version::parse("1.0.0").map_err(|e| e.to_string())?,
                    ),
                    features_json: FeaturesJson::default(),
                    target: TargetTriple::parse(dep_target(0)).map_err(|e| e.to_string())?,
                    rustc_version: WireRustcVersion::parse("1.86.0").map_err(|e| e.to_string())?,
                    demand: 100,
                })
            },
        )
        .collect()
}

/// Seed and prove the page-apply event graph in unmetered setup,
/// BEFORE the measured run bills a statement: the typed batch lands
/// 384 rows through the real `enqueue_trusted`; then the exact
/// contract the walk and the fold rely on is verified — 384 unique
/// task ids, all `pending` (unbuilt), each root owning exactly its
/// two `dep_met = 0` edges into the shared-dep set, the deps owning
/// none (no out-edges), the max page's wire carrying 256 distinct
/// identities, and every entry's live closure through production's
/// own `demand_closure_tasks` equal to its expected three-task set —
/// the set, not just the cardinality. Any drift fails the drive
/// rather than measuring a different event.
async fn seed_feed_event_subgraph(
    db: &DurableDb,
    settings: &SchedulerSettings,
) -> Result<(), String> {
    // A previous pass's accepted fold moved these rows' demand/value —
    // a resubmit would leave them — so the event restarts from its
    // exact primary-key deletes, identical every run.
    clear_feed_event_subgraph(db).await?;
    let inserted = queue::enqueue_trusted(db, &feed_event_requests(), settings)
        .await
        .map_err(|error| error.to_string())?;
    if inserted != FEED_EVENT_NODES {
        return Err(format!(
            "event subgraph inserted {inserted} rows, expected {FEED_EVENT_NODES}"
        ));
    }
    validate_feed_event_subgraph(db).await
}

/// Prove the seeded subgraph is exactly the contract the measured
/// walk relies on — every check keyed by the explicit typed id list.
async fn validate_feed_event_subgraph(db: &DurableDb) -> Result<(), String> {
    let ids = feed_event_task_ids();
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    if unique.len() != usize::try_from(FEED_EVENT_NODES).expect("count") {
        return Err(format!(
            "event subgraph has {} unique task ids, expected {FEED_EVENT_NODES}",
            unique.len(),
        ));
    }
    let ids_json =
        serde_json::to_string(&ids).map_err(|error| format!("encode event task ids: {error}"))?;
    let deps_json = serde_json::to_string(&ids[..usize::try_from(FEED_EVENT_DEPS).expect("count")])
        .map_err(|error| format!("encode event dep ids: {error}"))?;
    let roots_json =
        serde_json::to_string(&ids[usize::try_from(FEED_EVENT_DEPS).expect("count")..])
            .map_err(|error| format!("encode event root ids: {error}"))?;
    let present: i64 = db
        .query("SELECT count(*) FROM queue WHERE task_id IN (SELECT value FROM json_each(?))")
        .bind(ids_json.clone())
        .fetch_scalar()
        .await
        .map_err(|error| format!("probe event rows: {error}"))?;
    let built: i64 = db
        .query(
            "SELECT count(*) FROM queue \
             WHERE task_id IN (SELECT value FROM json_each(?)) \
               AND status != 'pending'",
        )
        .bind(ids_json)
        .fetch_scalar()
        .await
        .map_err(|error| format!("probe event row status: {error}"))?;
    if i64::from(FEED_EVENT_NODES) != present || built != 0 {
        return Err(format!(
            "event subgraph has {present} rows ({built} built), expected {FEED_EVENT_NODES} pending"
        ));
    }
    validate_feed_event_edges(db, roots_json, deps_json).await?;
    validate_feed_event_closures(db, &ids).await
}

/// The edge contract each root's seeded rows must hold: exactly two
/// unmet edges (`dep_met = 0` — the deps publish nothing), every edge
/// pointing into the shared-dep set, the deps owning no outgoing
/// edges — the diamond shape whose UNION walk returns exactly the
/// 384-task set.
async fn validate_feed_event_edges(
    db: &DurableDb,
    roots_json: String,
    deps_json: String,
) -> Result<(), String> {
    let edges: i64 = db
        .query(
            "SELECT count(*) FROM queue_dependencies \
             WHERE task_id IN (SELECT value FROM json_each(?))",
        )
        .bind(roots_json.clone())
        .fetch_scalar()
        .await
        .map_err(|error| format!("probe event edges: {error}"))?;
    let unmet: i64 = db
        .query(
            "SELECT count(*) FROM queue_dependencies \
             WHERE task_id IN (SELECT value FROM json_each(?)) \
               AND dep_met = 0",
        )
        .bind(roots_json.clone())
        .fetch_scalar()
        .await
        .map_err(|error| format!("probe event edge flags: {error}"))?;
    let foreign: i64 = db
        .query(
            "SELECT count(*) FROM queue_dependencies \
             WHERE task_id IN (SELECT value FROM json_each(?)) \
               AND depends_on_task_id NOT IN (SELECT value FROM json_each(?))",
        )
        .bind(roots_json)
        .bind(deps_json.clone())
        .fetch_scalar()
        .await
        .map_err(|error| format!("probe event edge targets: {error}"))?;
    let dep_owned: i64 = db
        .query(
            "SELECT count(*) FROM queue_dependencies \
             WHERE task_id IN (SELECT value FROM json_each(?))",
        )
        .bind(deps_json)
        .fetch_scalar()
        .await
        .map_err(|error| format!("probe dep out-edges: {error}"))?;
    if edges != 2 * i64::from(FEED_EVENT_ROOTS) || unmet != edges || foreign != 0 || dep_owned != 0
    {
        return Err(format!(
            "event edges: {edges} owned ({unmet} unmet, {foreign} foreign), {dep_owned} dep-owned; \
             expected {} unmet root edges into the dep set and none dep-owned",
            2 * FEED_EVENT_ROOTS
        ));
    }
    Ok(())
}

/// The wire and walk contracts: the max page carries 256 distinct
/// identities — the entries the staged payload bytes and the manifest
/// hash must agree on — and every entry's live closure through the
/// production walk is the exact three-task set its root covers, so
/// the measured page's union is the seeded 384 by construction, not
/// by count.
async fn validate_feed_event_closures(db: &DurableDb, ids: &[String]) -> Result<(), String> {
    let page = feed_event_entries(0, FEED_EVENT_ROOTS)?;
    let mut identities: Vec<String> = page
        .iter()
        .map(|entry| {
            format!(
                "{}|{}|{}|{}|{}",
                entry.crate_name,
                entry.version,
                entry.features_json.raw(),
                entry.target,
                entry.rustc_version
            )
        })
        .collect();
    identities.sort();
    identities.dedup();
    if page.len() != usize::try_from(FEED_EVENT_ROOTS).expect("count")
        || identities.len() != page.len()
    {
        return Err(format!(
            "event page carries {} entries ({} distinct), expected {FEED_EVENT_ROOTS}",
            page.len(),
            identities.len()
        ));
    }
    for (k, root_id) in ids[usize::try_from(FEED_EVENT_DEPS).expect("count")..]
        .iter()
        .enumerate()
    {
        let k = u32::try_from(k).expect("root index");
        let mut expected: Vec<String> = feed_event_deps(k)
            .iter()
            .map(|&d| feed_event_dep_task_id(d))
            .collect();
        expected.push(root_id.clone());
        expected.sort();
        let mut touched = queue::demand_closure_tasks(
            db,
            &[
                feed_event_root_name(k),
                "1.0.0".to_owned(),
                "[]".to_owned(),
                dep_target(0).to_owned(),
                "1.86.0".to_owned(),
            ],
        )
        .await
        .map_err(|error| error.to_string())?;
        touched.sort();
        if touched != expected {
            return Err(format!(
                "event root {k} closure is {touched:?}, expected {expected:?}"
            ));
        }
    }
    Ok(())
}

/// Delete only the event subgraph's own records — the roots' 512
/// edges, then the 384 queue rows — every probe keyed by the explicit
/// typed id list (`json_each` feeds the `task_id` primary keys; no
/// prefix match or table walk). The queue's status counters live on
/// triggers over these deletes, so they stay consistent; nothing
/// else in the fixture moves. A first setup finds nothing; the
/// drive's post-apply cleanup must land the whole owned set — a
/// partial remnant would shrink the next run's event, so it errors
/// instead of drifting.
async fn clear_feed_event_subgraph(db: &DurableDb) -> Result<(), String> {
    let ids_json = serde_json::to_string(&feed_event_task_ids())
        .map_err(|error| format!("encode event task ids: {error}"))?;
    db.query(
        "DELETE FROM queue_dependencies \
         WHERE task_id IN (SELECT value FROM json_each(?))",
    )
    .bind(ids_json.clone())
    .execute()
    .await
    .map_err(|error| format!("clear event edges: {error}"))?;
    let edges = queue::changes(db)
        .await
        .map_err(|error| error.to_string())?;
    db.query("DELETE FROM queue WHERE task_id IN (SELECT value FROM json_each(?))")
        .bind(ids_json)
        .execute()
        .await
        .map_err(|error| format!("clear event rows: {error}"))?;
    let rows = queue::changes(db)
        .await
        .map_err(|error| error.to_string())?;
    let (want_edges, want_rows) = (2 * u64::from(FEED_EVENT_ROOTS), u64::from(FEED_EVENT_NODES));
    if (edges != 0 || rows != 0) && (edges != want_edges || rows != want_rows) {
        return Err(format!(
            "event subgraph cleanup removed {edges} edges / {rows} rows, \
             expected {want_edges} / {want_rows}"
        ));
    }
    Ok(())
}

/// One dependency edge on fixture row `n` — the same identity formulas
/// the queue seed wrote, so the edge resolves.
fn dep_request(n: u32) -> EnqueueDependency {
    let (crate_name, version) = crate_identity(n);
    EnqueueDependency {
        dependency_identity: stow_types::identity::DependencyIdentity::leaf().expect("leaf digest"),
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
                    dependency_identity: None,
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
            dependency_identity: None,
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
                    dependency_identity: None,
                    crate_name: format!("stow-gate-delta-{i}").parse().expect("delta crate"),
                    version: "9.9.9".parse().expect("delta version"),
                    features_json: FeaturesJson::default(),
                    unit_shape: Some(shape),
                }),
        );
    }
    (added, retired)
}

/// The durability-boundary contract of [`drive_lifecycle`], exercised
/// on the real orchestration against the scripted-sync backend: a
/// failed pre-sync skips the run but still cleans up, a failed run
/// still post-syncs and cleans up, a failed post-sync still cleans
/// up, and every phase failure lands in its own outcome slot. Host
/// coverage of the exact phase ordering the probe's measured window
/// brackets on wasm (stow#522).
#[cfg(all(test, not(target_arch = "wasm32")))]
mod lifecycle_tests {
    use std::sync::{Arc, Mutex};

    use super::{Drive, DriveContext, DriveOutcome, FixtureShape, SchedulerSettings};
    use crate::scheduler::fixture;
    use crate::scheduler::test_db::{BackendEvent, scripted_sync_db};

    async fn mark(db: &skyzen_services::durable::DurableDb, key: &str) -> Result<(), String> {
        db.query(&format!(
            "INSERT INTO settings (key, value) VALUES ('{key}', '1')"
        ))
        .execute()
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
    }

    fn marking_setup<'a>(
        db: &'a skyzen_services::durable::DurableDb,
        _shape: FixtureShape,
        _settings: &'a SchedulerSettings,
        _ctx: &'a DriveContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move { mark(db, "setup-marker").await })
    }

    fn marking_run<'a>(
        db: &'a skyzen_services::durable::DurableDb,
        _shape: FixtureShape,
        _settings: &'a SchedulerSettings,
        _ctx: &'a DriveContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move { mark(db, "run-marker").await })
    }

    fn marking_cleanup<'a>(
        db: &'a skyzen_services::durable::DurableDb,
        _shape: FixtureShape,
        _settings: &'a SchedulerSettings,
        _ctx: &'a DriveContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move { mark(db, "cleanup-marker").await })
    }

    fn failing_run<'a>(
        _db: &'a skyzen_services::durable::DurableDb,
        _shape: FixtureShape,
        _settings: &'a SchedulerSettings,
        _ctx: &'a DriveContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async { Err("injected run failure".to_owned()) })
    }

    fn failing_cleanup<'a>(
        _db: &'a skyzen_services::durable::DurableDb,
        _shape: FixtureShape,
        _settings: &'a SchedulerSettings,
        _ctx: &'a DriveContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async { Err("injected cleanup failure".to_owned()) })
    }

    struct Rig {
        db: skyzen_services::durable::DurableDb,
        events: Arc<Mutex<Vec<BackendEvent>>>,
        ctx: DriveContext,
        settings: SchedulerSettings,
    }

    impl Rig {
        async fn open(syncs: Vec<Result<(), String>>) -> Self {
            let (db, events) = scripted_sync_db(syncs).await.expect("scripted db");
            // Construction runs migrate + the permit gate — the log
            // the tests assert on starts at the drive itself.
            events.lock().expect("events").clear();
            Self {
                db,
                events,
                ctx: DriveContext::host(),
                settings: SchedulerSettings::default(),
            }
        }

        async fn drive(&self, drive: &Drive) -> DriveOutcome {
            super::drive_lifecycle(
                drive,
                &self.db,
                &self.db,
                fixture::GATE,
                &self.settings,
                &self.ctx,
                &mut |_| {},
            )
            .await
        }

        fn events(&self) -> Vec<BackendEvent> {
            self.events.lock().expect("events").clone()
        }
    }

    async fn marked(db: &skyzen_services::durable::DurableDb, key: &str) -> bool {
        db.query("SELECT value FROM settings WHERE key = ?")
            .bind(key.to_owned())
            .fetch_scalar_optional::<String>()
            .await
            .expect("marker read")
            .is_some()
    }

    #[tokio::test]
    async fn a_failed_pre_sync_skips_the_run_but_still_cleans_up() {
        let rig = Rig::open(vec![Err("fixture barrier refused".to_owned())]).await;
        let drive = Drive {
            name: "lifecycle probe",
            setup: None,
            run: marking_run,
            cleanup: Some(marking_cleanup),
        };
        let outcome = rig.drive(&drive).await;
        let events = rig.events();
        let pre_sync = outcome
            .pre_sync
            .expect("the fixture barrier ran")
            .expect_err("the barrier's own failure is retained");
        assert!(pre_sync.contains("pre_sync"), "{pre_sync}");
        assert!(outcome.run.is_none(), "the run was skipped");
        assert!(outcome.post_sync.is_none(), "no in-window barrier");
        assert!(
            outcome.cleanup.expect("cleanup ran").is_ok(),
            "cleanup succeeded",
        );
        assert!(!marked(&rig.db, "run-marker").await, "no run write");
        assert!(marked(&rig.db, "cleanup-marker").await, "cleanup wrote");
        assert_eq!(
            &[BackendEvent::Sync, BackendEvent::Execute],
            events.as_slice(),
            "only the fixture barrier fired, then cleanup's write",
        );
    }

    #[tokio::test]
    async fn a_failed_run_still_post_syncs_and_cleans_up() {
        let rig = Rig::open(vec![Ok(()), Ok(())]).await;
        let drive = Drive {
            name: "lifecycle probe",
            setup: None,
            run: failing_run,
            cleanup: Some(marking_cleanup),
        };
        let outcome = rig.drive(&drive).await;
        let events = rig.events();
        assert_eq!(
            outcome
                .run
                .expect("the run ran")
                .expect_err("the run's failure is retained"),
            "injected run failure",
        );
        assert!(
            outcome.post_sync.expect("in-window barrier ran").is_ok(),
            "the post-sync still ran after the run failed",
        );
        assert!(outcome.cleanup.expect("cleanup ran").is_ok());
        assert!(marked(&rig.db, "cleanup-marker").await, "cleanup wrote");
        assert_eq!(
            &[
                BackendEvent::Sync,
                BackendEvent::Sync,
                BackendEvent::Execute,
            ],
            events.as_slice(),
            "both barriers fired around the failed run, then cleanup's write",
        );
    }

    #[tokio::test]
    async fn a_failed_post_sync_still_cleans_up() {
        let rig = Rig::open(vec![Ok(()), Err("drive barrier refused".to_owned())]).await;
        let drive = Drive {
            name: "lifecycle probe",
            setup: None,
            run: marking_run,
            cleanup: Some(marking_cleanup),
        };
        let outcome = rig.drive(&drive).await;
        let post_sync = outcome
            .post_sync
            .expect("the in-window barrier ran")
            .expect_err("the barrier's own failure is retained");
        assert!(post_sync.contains("post_sync"), "{post_sync}");
        assert!(outcome.run.expect("the run ran").is_ok());
        assert!(outcome.cleanup.expect("cleanup ran").is_ok());
        assert!(marked(&rig.db, "run-marker").await, "the run landed");
        assert!(marked(&rig.db, "cleanup-marker").await, "cleanup wrote");
    }

    #[tokio::test]
    async fn every_phase_failure_is_retained_in_its_own_slot() {
        let rig = Rig::open(vec![Ok(()), Err("drive barrier refused".to_owned())]).await;
        let drive = Drive {
            name: "lifecycle probe",
            setup: None,
            run: failing_run,
            cleanup: Some(failing_cleanup),
        };
        let outcome = rig.drive(&drive).await;
        assert_eq!(
            outcome
                .run
                .expect("the run ran")
                .expect_err("run failure retained"),
            "injected run failure",
        );
        assert!(
            outcome
                .post_sync
                .expect("in-window barrier ran")
                .expect_err("post-sync failure retained")
                .contains("post_sync"),
        );
        assert_eq!(
            outcome
                .cleanup
                .expect("cleanup ran")
                .expect_err("cleanup failure retained"),
            "injected cleanup failure",
        );
    }

    #[tokio::test]
    async fn the_barriers_bracket_the_measured_window() {
        let rig = Rig::open(vec![Ok(()), Ok(())]).await;
        let drive = Drive {
            name: "lifecycle probe",
            setup: Some(marking_setup),
            run: marking_run,
            cleanup: Some(marking_cleanup),
        };
        let outcome = rig.drive(&drive).await;
        assert!(outcome.setup.is_ok());
        assert!(outcome.run.expect("the run ran").is_ok());
        assert_eq!(
            &[
                BackendEvent::Execute,
                BackendEvent::Sync,
                BackendEvent::Execute,
                BackendEvent::Sync,
                BackendEvent::Execute,
            ],
            rig.events().as_slice(),
            "setup writes, fixture barrier, run write, in-window barrier, cleanup",
        );
    }
}

/// The page-apply drive's fixed event graph (stow#523): the measured
/// max page must walk the same seeded 384-task set — 256 roots plus
/// 128 shared deps — at every stored-bulk size, on rows and edges the
/// real enqueue path wrote, and its cleanup must leave nothing
/// behind for the next pass.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod feed_event_tests {
    use super::{
        FEED_EVENT_NODES, FEED_EVENT_ROOTS, clear_feed_event_subgraph, feed_drive_hour,
        feed_drive_now_ms, feed_event_dep_task_id, feed_event_entries, feed_event_root_name,
        feed_event_root_task_id, feed_event_task_ids, seed_feed_event_subgraph,
        seed_feed_hour_sized,
    };
    use crate::scheduler::feed;
    use crate::scheduler::fixture::{self, FixtureShape};
    use crate::scheduler::queue::SchedulerSettings;
    use crate::scheduler::test_db::memory_db;
    use skyzen_services::durable::DurableDb;

    /// The persisted demand one event row carries.
    async fn demand_of(db: &DurableDb, task_id: &str) -> i64 {
        db.query("SELECT demand FROM queue WHERE task_id = ?")
            .bind(task_id)
            .fetch_scalar()
            .await
            .expect("demand")
    }

    /// The staged page 0 the event hour froze — the payload bytes the
    /// measured `feed_deliver` decodes — must name the subgraph's
    /// roots verbatim: the wire, the manifest input and the stored
    /// set are the same list.
    async fn assert_event_page_bytes(db: &DurableDb) {
        let payload: String = db
            .query(
                "SELECT payload FROM demand_feed_pages \
                 WHERE hour = '2020-01-01T00' AND generation = ? AND page_no = 0",
            )
            .bind(super::FEED_DRIVE_GENERATION)
            .fetch_scalar()
            .await
            .expect("staged page 0");
        let entries: Vec<stow_types::api::SchedulerDemandEntry> =
            serde_json::from_str(&payload).expect("page payload decodes");
        assert_eq!(
            entries.len(),
            usize::try_from(FEED_EVENT_ROOTS).expect("count"),
            "page 0 stages the full max page"
        );
        for (k, entry) in entries.iter().enumerate() {
            let k = u32::try_from(k).expect("entry index");
            assert_eq!(entry.crate_name.as_str(), feed_event_root_name(k));
            assert_eq!(entry.target.as_str(), super::dep_target(0));
        }
    }

    /// One full drive pass at `queue_rows`: seed the subgraph and the
    /// hour through the drive's own setup path, then measure the
    /// `feed_deliver` apply — the assertions a shape change must not
    /// move.
    async fn run_event_drive(db: &DurableDb, settings: &SchedulerSettings) {
        seed_feed_event_subgraph(db, settings)
            .await
            .expect("event subgraph");
        seed_feed_hour_sized(db, 0, &[256, 4], feed_event_entries)
            .await
            .expect("hour materialization");
        assert_event_page_bytes(db).await;
        let (report, _plan) =
            feed::feed_deliver(db, &feed_drive_hour(0), feed_drive_now_ms(0), settings)
                .await
                .expect("page apply");
        assert!(report.applied, "page 0 applies");
        assert_eq!(
            report.touched_tasks,
            u64::from(FEED_EVENT_NODES),
            "the measured event is the fixed subgraph's closure"
        );
        // The shared fold: each root takes its own entry's +100 once;
        // each dep sits in four roots' closures, so it folds +400 —
        // real diamond contributions, not a per-tree count.
        for k in [0_u32, 127, 255] {
            assert_eq!(
                demand_of(db, &feed_event_root_task_id(k)).await,
                100,
                "root {k} folds its own delta"
            );
        }
        for d in [0_u32, 64, 127] {
            assert_eq!(
                demand_of(db, &feed_event_dep_task_id(d)).await,
                400,
                "dep {d} folds its four owners' deltas"
            );
        }
    }

    /// The event's reachable set is bulk-invariant: seed the subgraph
    /// over two different stored-bulk sizes and the measured page
    /// touches exactly the same 384 tasks with the same fold deltas —
    /// the gate's scale check can then attribute any growth to the
    /// stored bulk, never to a changed event.
    #[tokio::test]
    async fn fixed_event_set_is_bulk_invariant() {
        let settings = SchedulerSettings::default();
        for queue_rows in [4_000_u32, 20_000] {
            let db = memory_db().await.expect("memory db");
            let shape = FixtureShape { queue_rows };
            fixture::seed_production_shape(&db, &shape, 0)
                .await
                .expect("fixture");
            run_event_drive(&db, &settings).await;
        }
    }

    /// Cleanup deletes exactly the subgraph's own primary keys — a
    /// typed-id probe proves nothing owned survives and nothing
    /// foreign moved — and restaging lands the identical validated
    /// event, the repeated-run contract the persisted fixture needs.
    #[tokio::test]
    async fn event_cleanup_restages_identically() {
        let db = memory_db().await.expect("memory db");
        let shape = FixtureShape { queue_rows: 4_000 };
        fixture::seed_production_shape(&db, &shape, 0)
            .await
            .expect("fixture");
        let settings = SchedulerSettings::default();
        seed_feed_event_subgraph(&db, &settings)
            .await
            .expect("first seed");
        clear_feed_event_subgraph(&db).await.expect("cleanup");
        let ids_json = serde_json::to_string(&feed_event_task_ids()).expect("ids");
        let rows: i64 = db
            .query("SELECT count(*) FROM queue WHERE task_id IN (SELECT value FROM json_each(?))")
            .bind(ids_json.clone())
            .fetch_scalar()
            .await
            .expect("rows");
        let edges: i64 = db
            .query(
                "SELECT count(*) FROM queue_dependencies \
                 WHERE task_id IN (SELECT value FROM json_each(?))",
            )
            .bind(ids_json)
            .fetch_scalar()
            .await
            .expect("edges");
        assert_eq!(
            (rows, edges),
            (0, 0),
            "cleanup leaves no event rows or edges"
        );
        // The bulk is untouched: seeded rows and the fixture's own
        // (formula-keyed) edges are all still in place.
        let seeded: i64 = db
            .query("SELECT count(*) FROM queue WHERE task_id NOT LIKE '%-%'")
            .fetch_scalar()
            .await
            .expect("seeded rows");
        assert_eq!(
            i64::from(shape.queue_rows),
            seeded,
            "cleanup never touches the stored bulk"
        );
        // Restaging sees the identical event — every setup validation
        // (ids, edges, statuses, per-root closure sets) runs again.
        seed_feed_event_subgraph(&db, &settings)
            .await
            .expect("restage");
        // And a fresh run of the measured call reads the same event:
        // re-materialize the hour through the rearm's live-window
        // contract, then deliver page 0 to the same 384 tasks.
        fixture::rearm(&db, shape, 0).await.expect("rearm");
        clear_feed_event_subgraph(&db).await.expect("post-rearm");
        seed_feed_event_subgraph(&db, &settings)
            .await
            .expect("reseed after rearm");
        seed_feed_hour_sized(&db, 0, &[256, 4], feed_event_entries)
            .await
            .expect("hour re-materialization");
        let (report, _plan) =
            feed::feed_deliver(&db, &feed_drive_hour(0), feed_drive_now_ms(0), &settings)
                .await
                .expect("second apply");
        assert_eq!(
            report.touched_tasks,
            u64::from(FEED_EVENT_NODES),
            "the restaged event measures identically"
        );
    }

    /// A half-cleared subgraph — owned edges surviving without their
    /// rows — is the partial remnant the cleanup must refuse, not
    /// absorb: the schema holds no foreign key tying
    /// `queue_dependencies` to `queue`, so deleting only the rows
    /// leaves a real edge-only state the exact-id accounting has to
    /// catch.
    #[tokio::test]
    async fn edge_only_remnant_fails_cleanup() {
        let db = memory_db().await.expect("memory db");
        let shape = FixtureShape { queue_rows: 4_000 };
        fixture::seed_production_shape(&db, &shape, 0)
            .await
            .expect("fixture");
        let settings = SchedulerSettings::default();
        seed_feed_event_subgraph(&db, &settings)
            .await
            .expect("seed");
        // Delete only the rows through the schema's own keys — no FK
        // cascades the 512 owned edges, so they survive alone.
        let ids_json = serde_json::to_string(&feed_event_task_ids()).expect("ids");
        db.query("DELETE FROM queue WHERE task_id IN (SELECT value FROM json_each(?))")
            .bind(ids_json.clone())
            .execute()
            .await
            .expect("row-only delete");
        let error = clear_feed_event_subgraph(&db)
            .await
            .expect_err("an edge-only remnant must fail the cleanup accounting");
        assert!(
            error.contains("cleanup removed"),
            "the remnant is reported, not absorbed: {error}"
        );
        // The delete still ran — the remnant is cleared and the error
        // is the accounting verdict, not a preserved state.
        let remaining: i64 = db
            .query(
                "SELECT count(*) FROM queue_dependencies \
                 WHERE task_id IN (SELECT value FROM json_each(?))",
            )
            .bind(ids_json)
            .fetch_scalar()
            .await
            .expect("remnant edges");
        assert_eq!(0, remaining, "the edge-only remnant was deleted");
    }
}
