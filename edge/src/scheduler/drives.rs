//! The scheduler route list both cost gates drive. The host-side gate
//! (`cost_gate.rs`, `cargo test -p stow-edge`) runs this same list on a
//! small fixture against `counting_memory_db` as a fast pre-check; the
//! workerd harness (`budget.rs`, `scripts/traffic-cost.sh`) runs it on
//! the production fixture inside the Durable Object, where `CfDurableDb`
//! reports the real `rowsRead`/`rowsWritten` Cloudflare bills. One drive
//! list keeps the two harnesses honest: a route that only existed in one
//! of them would be an unmeasured request path.
//!
//! Every drive runs the route's shared core (`routes.rs`, and on workerd
//! the `object.rs` pass the handler itself calls) against the fixture's
//! in-memory graph and its flat store (stow#878). The graph answers
//! reads from memory, so a read route bills nothing; a state change
//! bills its appended log rows; the wake and the snapshot have drives of
//! their own, because they are the only operations that read or write
//! the graph's bulk.
//!
//! Every entry is a cold-start measure — the drives deliberately skip
//! `reset`, which is operations work, never request code. A drive that
//! changes the graph touches nodes no other drive reads, and its cleanup
//! returns what a later drive's claim would otherwise meet: a claimed
//! node is cancelled and retried back to `pending`, a node a drive
//! submitted is cancelled.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use skyzen_services::durable::{Alarm, DurableDb};
use stow_types::api::{
    CI_TARGET_TRIPLES, DispatchBinding, DispatchClaim, MutationKind, PublishedSlice, QueueSelector,
    QueueTaskStatus, SchedulerEvent, SubmissionSource, SubmissionTree, SubmitTaskIdEntry,
};
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};

use super::fixture::{self, FixtureShape};
use super::graph::{GraphCell, LoadedGraph};
use super::queue::{self, SchedulerSettings};
use super::{feed, routes, store};

/// What a [`Drive`] runs: the route's graph-and-store calls exactly once
/// against `db`. `FixtureShape` is copied — four bytes.
type DriveRun = for<'a> fn(
    &'a DurableDb,
    FixtureShape,
    &'a SchedulerSettings,
    &'a DriveContext,
) -> DriveFuture<'a>;

/// A drive hook's future.
type DriveFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// The clock the host gate always uses — the instant the host fixture is
/// built at. The workerd probe reads `Date.now()` instead.
#[cfg(not(target_arch = "wasm32"))]
pub const HOST_NOW_MS: i64 = 1_800_000_000_000;

/// The alarm state a drive found on entry — three real states the
/// cleanup distinguishes: platform alarm never read, nothing armed,
/// or an alarm armed at a unix-ms timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorAlarm {
    NotCaptured,
    Unarmed,
    Armed(i64),
}

/// What a drive may reach besides the metered `DurableDb`: the graph
/// the routes mutate, the Worker env and the object's alarm on workerd.
pub struct DriveContext {
    /// The Worker env — set only on the wasm32 probe.
    #[cfg(target_arch = "wasm32")]
    pub env: Option<skyzen::runtime::wasm::WasmEnv>,
    /// The graph the drives' routes run against — the object's own cell
    /// on workerd, a fresh one on host.
    pub graph: GraphCell,
    /// The durable-object alarm the `scheduler_budget` route extracted
    /// — the real handle the demand drive's arm helper writes and
    /// reads back (stow#522). `None` on the host gate, which has no
    /// platform alarm and asserts the `AlarmPlan` instead.
    pub alarm: Option<Alarm>,
    /// The claimed task ids of the hot pass, in claim order — the
    /// pass's own outcome. The launch gate's per-claim marginal price
    /// divides the hot-minus-idle delta by their count, never by a
    /// checked-in slots assumption.
    claimed_tasks: Arc<Mutex<Vec<String>>>,
    /// The alarm state a drive found on entry.
    prior_alarm: Arc<Mutex<PriorAlarm>>,
    /// The task a run drive's setup bound and the run it bound it to.
    bound: Arc<Mutex<Option<BoundRun>>>,
    /// The next generation a drive's setup mints for a claim — past
    /// every generation the fixture or a live pass used.
    generation: Arc<AtomicU64>,
}

impl DriveContext {
    /// The first generation a drive mints.
    const FIRST_GENERATION: u64 = 9_000_000_000_000;

    /// The host gate's context over `graph`.
    #[cfg(all(test, not(target_arch = "wasm32")))]
    #[must_use]
    pub fn host(graph: GraphCell) -> Self {
        Self::new(graph, None)
    }

    /// The workerd probe's context: the Worker env, the object's graph
    /// and its alarm.
    #[cfg(target_arch = "wasm32")]
    #[must_use]
    pub fn worker(env: &skyzen::runtime::wasm::WasmEnv, graph: GraphCell, alarm: &Alarm) -> Self {
        Self {
            env: Some(env.clone()),
            ..Self::new(graph, Some(alarm.clone()))
        }
    }

    fn new(graph: GraphCell, alarm: Option<Alarm>) -> Self {
        Self {
            #[cfg(target_arch = "wasm32")]
            env: None,
            graph,
            alarm,
            claimed_tasks: Arc::new(Mutex::new(Vec::new())),
            prior_alarm: Arc::new(Mutex::new(PriorAlarm::NotCaptured)),
            bound: Arc::new(Mutex::new(None)),
            generation: Arc::new(AtomicU64::new(Self::FIRST_GENERATION)),
        }
    }

    /// The graph the drives run against, proven loaded. Every drive but
    /// the wake runs after the seed installed it; one that does not has
    /// a mis-ordered gate.
    pub fn loaded(&self) -> LoadedGraph<'_> {
        self.graph
            .loaded()
            .expect("drive ordering: the seed installs the graph before any drive reads it")
    }

    /// Tasks claimed by the hot pass so far.
    pub fn claims(&self) -> u64 {
        u64::try_from(self.claimed_tasks.lock().expect("claim record").len()).unwrap_or(u64::MAX)
    }

    /// Every task id the hot pass claimed so far, in claim order.
    pub fn claimed_ids(&self) -> Vec<String> {
        self.claimed_tasks.lock().expect("claim record").clone()
    }

    fn record_claimed(&self, task_ids: Vec<String>) {
        self.claimed_tasks
            .lock()
            .expect("claim record")
            .extend(task_ids);
    }

    fn set_prior_alarm(&self, armed: Option<i64>) {
        *self.prior_alarm.lock().expect("prior alarm") =
            armed.map_or(PriorAlarm::Unarmed, PriorAlarm::Armed);
    }

    /// Take the recorded entry alarm state for the cleanup's restore.
    #[cfg(target_arch = "wasm32")]
    fn take_prior_alarm(&self) -> PriorAlarm {
        std::mem::replace(
            &mut *self.prior_alarm.lock().expect("prior alarm"),
            PriorAlarm::NotCaptured,
        )
    }

    fn set_bound(&self, bound: BoundRun) {
        *self.bound.lock().expect("drive binding") = Some(bound);
    }

    fn bound_run(&self) -> Result<BoundRun, String> {
        self.bound
            .lock()
            .expect("drive binding")
            .clone()
            .ok_or_else(|| "the drive's setup bound no task".to_owned())
    }

    fn next_generation(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::Relaxed)
    }
}

/// The route clock: `Date.now()` on workerd.
#[cfg(target_arch = "wasm32")]
#[must_use]
pub fn now_ms() -> i64 {
    super::object::now_ms()
}

/// The route clock: [`HOST_NOW_MS`] on host.
#[cfg(not(target_arch = "wasm32"))]
#[must_use]
pub const fn now_ms() -> i64 {
    HOST_NOW_MS
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

/// `Some` when `sql` is a statement whose billed cost the metering
/// predicts and its counters differ from the prediction — carrying
/// the statement's label and its predicted (`rows_read`,
/// `rows_written`) — `None` when it bills the prediction or carries
/// none. The host cost gate and the workerd probe share this one
/// table, so a statement billed other than predicted fails the gate
/// instead of only logging.
///
/// stow#931: an `event_log` append is `INSERT .. RETURNING seq` and
/// bills exactly one read row plus one written row — the re-count a
/// wake's replay books must bill identically. The meter checkpoint's
/// `UPDATE meter .. RETURNING` — the edge's only UPDATE — bills
/// [`store::METER_CHECKPOINT_BILL`]: workerd reads one row for the
/// row it changes plus one for the RETURNING row (release gate run
/// 40186665163's statement log: `rows_returned 1`, `rows_read 2`,
/// `rows_written 1`), and the checkpoint folds the same cost into the
/// stored totals.
#[must_use]
pub fn predicted_bill_mismatch(
    sql: &str,
    rows_read: u64,
    rows_written: u64,
) -> Option<(&'static str, u64, u64)> {
    let predicted = if sql.starts_with("INSERT INTO event_log") {
        ("event_log append", 1, 1)
    } else if sql.starts_with("UPDATE meter") {
        (
            "meter checkpoint UPDATE",
            store::METER_CHECKPOINT_BILL.0,
            store::METER_CHECKPOINT_BILL.1,
        )
    } else {
        return None;
    };
    ((rows_read, rows_written) != (predicted.1, predicted.2)).then_some(predicted)
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

/// One route (or the alarm pass) driven against the seeded graph.
pub struct Drive {
    /// The route label — the budget table's row key.
    pub name: &'static str,
    /// Fixture preparation run *outside* the metered window — for a
    /// drive whose measurement must see a state the production path
    /// being priced doesn't create itself. Setup statements are not the
    /// event cost, so the harnesses never count them against the budget
    /// row.
    pub setup: Option<DriveRun>,
    /// Run the route's calls exactly once against `db`.
    pub run: DriveRun,
    /// Fixture restoration run *outside* the metered window — undoes
    /// whatever `setup`/the run moved so later drives see the canonical
    /// fixture state.
    pub cleanup: Option<DriveRun>,
}

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn id_of(n: u32) -> String {
    stow_types::fixture::fixture_task_id(u64::from(n))
}

/// Append `events` as the live route would — log first, then the
/// graph — at the drive clock.
async fn commit(
    ctx: &DriveContext,
    db: &DurableDb,
    events: &[SchedulerEvent],
    at: i64,
) -> Result<(), String> {
    routes::commit(ctx.loaded(), db, events, at)
        .await
        .map_err(text)
}

/// The tail every state-changing route pays: the wake plan over the
/// folded graph and the snapshot when the log has crossed its threshold.
async fn schedule(
    ctx: &DriveContext,
    db: &DurableDb,
    settings: &SchedulerSettings,
) -> Result<(), String> {
    let _plan = routes::wake_plan(ctx.loaded(), settings, now_ms());
    routes::snapshot_if_due(ctx.loaded(), db, now_ms())
        .await
        .map(|_| ())
        .map_err(text)
}

fn list(ctx: &DriveContext, selector: &QueueSelector) -> Result<(), String> {
    ctx.loaded()
        .with(|graph| graph.list(selector, now_ms()))
        .map(|_| ())
        .map_err(text)
}

/// The `actor` every authenticated-route drive appends under: a real
/// request attributes its first row to the verified run (stow#955), so
/// each drive prices the attributed row it writes.
const DRIVE_ACTOR: &str = "cost-drive";

async fn mutate(
    ctx: &DriveContext,
    db: &DurableDb,
    op: MutationKind,
    ids: Vec<String>,
) -> Result<u32, String> {
    routes::mutate(
        ctx.loaded(),
        db,
        op,
        &QueueSelector {
            task_ids: ids,
            ..QueueSelector::default()
        },
        Some(DRIVE_ACTOR),
        now_ms(),
    )
    .await
    .map_err(text)
}

async fn expect_mutated(
    ctx: &DriveContext,
    db: &DurableDb,
    op: MutationKind,
    ids: Vec<String>,
    expected: u32,
    label: &str,
) -> Result<(), String> {
    let mutated = mutate(ctx, db, op, ids).await?;
    (mutated == expected)
        .then_some(())
        .ok_or_else(|| format!("{label} mutated {mutated}, expected {expected}"))
}

/// Put claimed nodes back to `pending`: cancel the in-flight claim, then
/// retry the failure — the two operator verbs a graph offers for it.
async fn restore_claimed(
    ctx: &DriveContext,
    db: &DurableDb,
    ids: Vec<String>,
) -> Result<(), String> {
    if ids.is_empty() {
        return Ok(());
    }
    mutate(ctx, db, MutationKind::Cancel, ids.clone()).await?;
    mutate(ctx, db, MutationKind::Retry, ids).await?;
    Ok(())
}

/// Cancel what a drive submitted, so no later claim meets it.
async fn cancel_submitted(
    ctx: &DriveContext,
    db: &DurableDb,
    ids: Vec<String>,
) -> Result<(), String> {
    mutate(ctx, db, MutationKind::Cancel, ids).await.map(|_| ())
}

// ===== The submit batches =====

/// Seed base of every drive-owned node — far above the fixture's
/// `1..=queue_rows` range.
const DRIVE_SEED: u64 = 1 << 40;

/// One submit batch: a miss tree (a resync entry over thirty published
/// deps and a fresh one over one) and a one-node human tree — the
/// request mix the enqueue path sees in production. Every batch names
/// its own nodes through `tag`, so a drive's insert path is not turned
/// into a resync by an earlier drive.
struct SubmitBatch {
    trees: Vec<SubmissionTree>,
    /// Task ids of the batch's fresh nodes, in tree order.
    task_ids: Vec<String>,
}

fn submit_batch(shape: FixtureShape, tag: u64) -> SubmitBatch {
    let target = stow_types::fixture::target_of(101);
    let seed = DRIVE_SEED + tag * 1_000;
    let mut nodes = Vec::new();
    // Published deps enter as bare copies: an existing id merges as
    // itself, and the edge answers against the published masks.
    let resync_deps: Vec<u32> = (0..30)
        .map(|k| {
            nodes.push(fixture::fixture_node(shape.dep_row(k), Vec::new()));
            u32::try_from(nodes.len() - 1).expect("tree fits u32")
        })
        .collect();
    nodes.push(fixture::named_node(
        "costgate-resync",
        seed,
        target,
        resync_deps,
    ));
    let resync = u32::try_from(nodes.len() - 1).expect("tree fits u32");
    nodes.push(fixture::fixture_node(shape.dep_row(31), Vec::new()));
    let fresh_dep = u32::try_from(nodes.len() - 1).expect("tree fits u32");
    nodes.push(fixture::named_node(
        "costgate-fresh",
        seed + 1,
        target,
        vec![fresh_dep],
    ));
    let fresh = u32::try_from(nodes.len() - 1).expect("tree fits u32");
    let miss = SubmissionTree {
        source: SubmissionSource::CacheMiss,
        roots: vec![resync, fresh],
        nodes,
    };
    let human = SubmissionTree {
        source: SubmissionSource::HumanRequest,
        roots: vec![0],
        nodes: vec![fixture::named_node(
            "costgate-human",
            seed + 2,
            target,
            Vec::new(),
        )],
    };
    SubmitBatch {
        trees: vec![miss, human],
        task_ids: (0..3)
            .zip(["costgate-resync", "costgate-fresh", "costgate-human"])
            .map(|(k, name)| stow_types::fixture::named_task_id(name, seed + k, target))
            .collect(),
    }
}

/// Distinct node families per submit drive.
const TAG_TRUSTED: u64 = 1;
const TAG_IDS: u64 = 2;
const TAG_RESUBMIT: u64 = 3;
const TAG_ACCEPT: u64 = 4;
const TAG_UNTRUSTED: u64 = 5;
const TAG_MERGE: u64 = 6;
const TAG_OPS: u64 = 7;
const TAG_PREHEAT: u64 = 8;
const TAG_INEXACT: u64 = 9;
const TAG_SNAPSHOT: u64 = 10;
/// The snapshot drive's setup bindings' run ids — its own range, clear
/// of the host pass's and the run drives'.
const SNAPSHOT_RUN_BASE: u64 = 7_000_000_000;

/// A one-node submit tree under `source` — the shape the per-entry-point
/// drives (stow#879) measure: the `Submit` append plus the merge.
fn source_tree(source: SubmissionSource, name: &str, tag: u64) -> SubmissionTree {
    SubmissionTree {
        source,
        roots: vec![0],
        nodes: vec![fixture::named_node(
            name,
            DRIVE_SEED + tag * 1_000,
            stow_types::fixture::target_of(101),
            Vec::new(),
        )],
    }
}

/// The task id `source_tree` mints for `name` — its cleanup's cancel.
fn source_node_id(name: &str, tag: u64) -> String {
    stow_types::fixture::named_task_id(
        name,
        DRIVE_SEED + tag * 1_000,
        stow_types::fixture::target_of(101),
    )
}

/// Land `trees` the way the trusted lane does, returning the fresh node
/// count. The capped lane is the anonymous one, so only the trusted
/// lane's append is attributed — as on the object.
async fn submit(
    ctx: &DriveContext,
    db: &DurableDb,
    settings: &SchedulerSettings,
    trees: &[SubmissionTree],
    enforce_pending_cap: bool,
) -> Result<u32, String> {
    routes::submit(
        ctx.loaded(),
        db,
        settings,
        trees,
        enforce_pending_cap,
        (!enforce_pending_cap).then_some(DRIVE_ACTOR),
        now_ms(),
    )
    .await
    .map_err(text)
    .map(|(inserted, _unpublished)| inserted)
}

async fn submit_expect(
    ctx: &DriveContext,
    db: &DurableDb,
    settings: &SchedulerSettings,
    trees: &[SubmissionTree],
    expected: u32,
    label: &str,
) -> Result<(), String> {
    let inserted = submit(ctx, db, settings, trees, false).await?;
    if inserted != expected {
        return Err(format!("{label} inserted {inserted}, expected {expected}"));
    }
    schedule(ctx, db, settings).await
}

// ===== The request lane =====

/// The request record the drives admit and settle — a `req-` id the
/// reseed drops between runs, so every probe measures the fresh-admission
/// path rather than a dedup hit.
const DRIVE_REQUEST_ID: &str = "req-costgate-drive";

/// The outcome-(dispatching) drive's own request record — the
/// canonical one is settled `enqueued` by the time this drive runs,
/// and an outcome never applies over a settled record.
const DISPATCH_REQUEST_ID: &str = "req-costgate-dispatch";

fn dispatch_admission() -> stow_types::api::RequestAdmission {
    stow_types::api::RequestAdmission {
        request_id: DISPATCH_REQUEST_ID.to_owned(),
        ..drive_admission()
    }
}

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

/// The outcome report the outcome drive applies — a one-dep
/// `HumanRequest` tree whose root is its own fresh task, plus a root
/// that names an existing published node (the `was_queued` arm).
fn request_report(shape: FixtureShape) -> stow_types::api::RequestOutcomeReport {
    let target = CI_TARGET_TRIPLES[0];
    let seed = DRIVE_SEED + TAG_UNTRUSTED * 1_000 + 500;
    let nodes = vec![
        fixture::fixture_node(shape.dep_row(2), Vec::new()),
        fixture::named_node("costgate-request-root", seed, target, vec![0]),
    ];
    stow_types::api::RequestOutcomeReport {
        attempt: 1,
        outcome: stow_types::api::RequestOutcome::Resolved {
            trees: vec![SubmissionTree {
                source: SubmissionSource::HumanRequest,
                roots: vec![1],
                nodes,
            }],
            roots: vec![
                stow_types::api::RequestRootOutcome {
                    target: TargetTriple::parse(target).expect("root target"),
                    task_id: Some(stow_types::fixture::named_task_id(
                        "costgate-request-root",
                        seed,
                        target,
                    )),
                    cached: false,
                },
                stow_types::api::RequestRootOutcome {
                    target: TargetTriple::parse(CI_TARGET_TRIPLES[1]).expect("second target"),
                    // An existing published node — the `was_queued`
                    // arm. Row 3 stays clear of the purge drive's rows.
                    task_id: Some(id_of(shape.completed_row(3))),
                    cached: false,
                },
            ],
        },
    }
}

fn run_update(
    action: stow_types::api::RequestRunAction,
    conclusion: Option<&str>,
) -> stow_types::api::RequestRunUpdate {
    stow_types::api::RequestRunUpdate {
        attempt: 1,
        action,
        conclusion: conclusion.map(str::to_owned),
        run_id: Some("43".to_owned()),
        run_url: Some("https://github.com/water-rs/stow/actions/runs/43".to_owned()),
    }
}

/// The `POST /requests` drive: the full pass on wasm (freeze and budget
/// probes, the dedup, the `Admitted` append and the serialized hop to
/// the local-CI dispatcher), the core on host.
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
        super::object::admit_request_pass(ctx.loaded(), env, db, settings, &drive_admission(), 0)
            .await
            .map(|_| ())
            .map_err(text)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let step =
            routes::admit_request(ctx.loaded(), db, settings, &drive_admission(), 0, now_ms())
                .await
                .map_err(text)?;
        matches!(step, queue::RequestAdmissionStep::Dispatch { .. })
            .then_some(())
            .ok_or_else(|| "the drive's fresh request deduplicated".to_owned())
    }
}

// ===== The dispatch passes =====

/// One dispatch pass exactly as `run_alarm` runs it, minus the metering
/// tail. On workerd the real `dispatch_pass` (stale recovery, the claim,
/// the `MAX_OUTBOUND_INFLIGHT`-bounded dispatch fan-out to the local-CI
/// dispatcher); on host the claim, the `Claims` append and a synthetic
/// binding per claim. Returns the claimed ids.
async fn pass(
    db: &DurableDb,
    settings: &SchedulerSettings,
    ctx: &DriveContext,
) -> Result<Vec<String>, String> {
    #[cfg(target_arch = "wasm32")]
    {
        let env = ctx
            .env
            .as_ref()
            .ok_or_else(|| "dispatch pass drive needs a Worker env".to_owned())?;
        let started_ms = super::budget::clock_ms();
        let task_ids = super::object::dispatch_pass(
            &ctx.graph,
            env,
            db,
            settings,
            u32::MAX,
            super::object::PassReconcile::Due,
        )
        .await
        .map_err(text)?;
        tracing::info!(
            "budget span pass=dispatch_pass elapsed_ms={}",
            super::budget::clock_ms() - started_ms
        );
        Ok(task_ids)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let now = now_ms();
        let claims = routes::claim_pass(ctx.loaded(), db, settings, now, u32::MAX)
            .await
            .map_err(text)?;
        let bindings: Vec<DispatchBinding> = claims
            .iter()
            .zip(HOST_RUN_BASE..)
            .map(|(claim, run)| DispatchBinding {
                task_id: claim.task_id.clone(),
                generation: claim.generation,
                run_id: run.to_string(),
            })
            .collect();
        routes::settle_dispatch(ctx.loaded(), db, bindings, Vec::new(), now)
            .await
            .map_err(text)?;
        Ok(claims.into_iter().map(|claim| claim.task_id).collect())
    }
}

/// The first synthetic run id the host pass binds.
#[cfg(not(target_arch = "wasm32"))]
const HOST_RUN_BASE: u64 = 8_000_000_000;

/// A claiming pass without the workflow fan-out — the claim and its
/// `Claims` append, then the wake re-plan. Shared by the floor probe and
/// the `/index/published` drives' `dispatch_pending` tail: focused
/// probes never record into `claimed_tasks`, and dispatching them would
/// create unrecorded workflows that contaminate the run state later
/// drives measure (stow#525). The caller restores what the claim moved.
async fn focused_claim_pass(
    db: &DurableDb,
    settings: &SchedulerSettings,
    ctx: &DriveContext,
) -> Result<Vec<String>, String> {
    let claims = routes::claim_pass(ctx.loaded(), db, settings, now_ms(), u32::MAX)
        .await
        .map_err(text)?;
    let _plan = routes::wake_plan(ctx.loaded(), settings, now_ms());
    Ok(claims.into_iter().map(|claim| claim.task_id).collect())
}

// ===== The per-task run drives (stow#876) =====

/// The run a run drive binds its task to when nothing reads the run
/// upstream: the completion and the `in_progress` update are graph
/// transitions, and the stale sweep reads only the clock.
pub const RUN_DRIVE_RUN_ID: u64 = 9_000_000_001;

/// The run id the run-update drive's seeded external run carries —
/// its own namespace, disjoint from the ids runs bind.
const RUN_UPDATE_RUN_ID: u64 = 9_000_100_000;

/// Seed families of the run drives' own nodes. Each drive lands one
/// fresh node in setup and claims it, so the claimable surface nets out
/// to what it was: the node leaves `pending` again by completing or by
/// the cleanup's cancel.
const TAG_RUN_SUCCESS: u64 = 10;
const TAG_RUN_FAILURE: u64 = 11;
const TAG_RUN_UPDATE: u64 = 12;
const TAG_RUN_STALE: u64 = 13;
/// The dispatching complete-run drive's own node.
const TAG_RUN_DISPATCH: u64 = 14;

fn run_node_id(tag: u64) -> String {
    stow_types::fixture::named_task_id(
        &format!("costgate-run-{tag}"),
        DRIVE_SEED + tag * 1_000 + 500,
        stow_types::fixture::target_of(101),
    )
}

fn run_node_tree(tag: u64) -> SubmissionTree {
    SubmissionTree {
        source: SubmissionSource::CacheMiss,
        roots: vec![0],
        nodes: vec![fixture::named_node(
            &format!("costgate-run-{tag}"),
            DRIVE_SEED + tag * 1_000 + 500,
            stow_types::fixture::target_of(101),
            Vec::new(),
        )],
    }
}

/// A run drive's bound task: the claimed task and the run bound to it.
#[derive(Debug, Clone)]
struct BoundRun {
    task: String,
    run: u64,
}

/// Claim `task` at `claimed_at` and bind it to `run` — the log events a
/// dispatch pass leaves, appended and applied in unmetered setup.
async fn bind_node(
    ctx: &DriveContext,
    db: &DurableDb,
    task: String,
    run: u64,
    claimed_at: i64,
) -> Result<(), String> {
    let generation = ctx.next_generation();
    commit(
        ctx,
        db,
        &[SchedulerEvent::Claims {
            claims: vec![DispatchClaim {
                task_id: task.clone(),
                generation,
                attempt: 1,
            }],
        }],
        claimed_at,
    )
    .await?;
    commit(
        ctx,
        db,
        &[SchedulerEvent::Bindings {
            bindings: vec![DispatchBinding {
                task_id: task.clone(),
                generation,
                run_id: run.to_string(),
            }],
        }],
        claimed_at,
    )
    .await?;
    ctx.set_bound(BoundRun { task, run });
    Ok(())
}

/// Land the drive's own node and bind it to the shared run.
async fn bind_fresh(
    ctx: &DriveContext,
    db: &DurableDb,
    settings: &SchedulerSettings,
    tag: u64,
    claimed_at: i64,
) -> Result<(), String> {
    submit_expect(ctx, db, settings, &[run_node_tree(tag)], 1, "run node").await?;
    bind_node(ctx, db, run_node_id(tag), RUN_DRIVE_RUN_ID, claimed_at).await
}

/// `POST /tasks/complete-run`: the route's whole pass.
async fn complete_run_route(
    db: &DurableDb,
    settings: &SchedulerSettings,
    ctx: &DriveContext,
    success: bool,
) -> Result<(), String> {
    let bound = ctx.bound_run()?;
    let report = stow_types::api::WorkflowRunComplete {
        task_id: bound.task,
        success,
        error: (!success).then(|| "failure".to_owned()),
        cancelled: false,
        github_run_id: bound.run.to_string(),
    };
    #[cfg(target_arch = "wasm32")]
    {
        let env = ctx
            .env
            .as_ref()
            .ok_or_else(|| "complete-run drive needs a Worker env".to_owned())?;
        let alarm = ctx
            .alarm
            .as_ref()
            .ok_or_else(|| "complete-run drive needs the durable-object alarm".to_owned())?;
        // The pass reads the deploy's settings itself.
        let _ = settings;
        super::object::complete_run_pass(&ctx.graph, env, db, alarm, &report)
            .await
            .map(|_| ())
            .map_err(text)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        routes::complete_run(ctx.loaded(), db, &report, now_ms())
            .await
            .map_err(text)?;
        schedule(ctx, db, settings).await
    }
}

// ===== The demand feed =====

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

/// Pages the feed drives stage.
const FEED_DRIVE_PAGES: u32 = 3;

/// The generation every feed drive pins its hour to — the begin report's
/// wall-clock value varies run to run, so unmetered setup stamps one
/// deterministic number and the measured run builds its wire request as
/// a pure typed constructor against it, never re-reading the hour
/// (stow#523).
const FEED_DRIVE_GENERATION: i64 = 7;

/// How a drive's staging resolves one page's entries — a pure
/// `(page_no, count) -> entries` map shared verbatim by the staged
/// payload bytes, the wire page request and the manifest hash.
type FeedPageEntries = fn(u32, u32) -> Result<Vec<stow_types::api::SchedulerDemandEntry>, String>;

/// A fixture node's demand entry — the same identity formulas the
/// fixture used, so a delivery's closure touches real nodes.
fn fixture_entry(n: u32) -> Result<stow_types::api::SchedulerDemandEntry, String> {
    let (crate_name, version) = stow_types::fixture::crate_identity(n);
    Ok(stow_types::api::SchedulerDemandEntry {
        crate_name: CrateName::parse(&crate_name).map_err(text)?,
        version: CrateVersion::new(semver::Version::parse(&version).map_err(text)?),
        features_json: FeaturesJson::default(),
        target: TargetTriple::parse(stow_types::fixture::target_of(n)).map_err(text)?,
        rustc_version: WireRustcVersion::parse(stow_types::fixture::seeded_rustc(u64::from(n)))
            .map_err(text)?,
        demand: 100,
    })
}

/// Page `page_no`'s deterministic entries — `count` rows at
/// `n = 100 + page_no * 256 + k`. The 256 spacing keeps every entry of
/// the protocol's maximum page on a distinct fixture node.
fn feed_drive_entries(
    page_no: u32,
    count: u32,
) -> Result<Vec<stow_types::api::SchedulerDemandEntry>, String> {
    (0..count)
        .map(|k| fixture_entry(100 + page_no * 256 + k))
        .collect()
}

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
/// count; counters and the manifest derive from the same wire entries.
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

/// Open drive hour `idx` through the real `feed_begin`, then pin its
/// generation to [`FEED_DRIVE_GENERATION`].
async fn feed_drive_begin(ctx: &DriveContext, db: &DurableDb, idx: u32) -> Result<(), String> {
    let hour = feed_drive_hour(idx);
    routes::feed_begin(
        ctx.loaded(),
        db,
        &hour,
        DRIVE_ACTOR,
        feed_drive_now_secs(idx),
    )
    .await
    .map_err(text)?;
    commit(
        ctx,
        db,
        &[SchedulerEvent::Feed {
            hour: hour.as_str().to_owned(),
            kind: stow_types::api::FeedEvent::Begin {
                generation: FEED_DRIVE_GENERATION,
            },
        }],
        feed_drive_now_ms(idx),
    )
    .await
}

/// Stage `page_no` under the pinned generation through the real
/// `feed_page`.
async fn feed_seed_page(
    ctx: &DriveContext,
    db: &DurableDb,
    idx: u32,
    page_no: u32,
    count: u32,
    entries: FeedPageEntries,
) -> Result<(), String> {
    routes::feed_page(
        ctx.loaded(),
        db,
        &feed_drive_page_request(idx, page_no, count, entries)?,
        DRIVE_ACTOR,
        feed_drive_now_secs(idx),
    )
    .await
    .map_err(text)
}

/// Materialize drive hour `idx` through the feed's own calls — begin
/// under the pinned generation, the `counts` pages in order, then the
/// manifest freeze — so a delivery sees a complete hour exactly as the
/// cron path leaves it. A hour a sibling drive already materialized is
/// left as it is.
async fn seed_feed_hour_sized(
    ctx: &DriveContext,
    db: &DurableDb,
    idx: u32,
    counts: &[u32],
    entries: FeedPageEntries,
) -> Result<(), String> {
    let hour = feed_drive_hour(idx);
    let status = ctx.loaded().with(|graph| feed::feed_status(graph));
    if status
        .watermark
        .as_ref()
        .is_some_and(|watermark| watermark.as_str() >= hour.as_str())
    {
        return Ok(());
    }
    let existing = ctx.loaded().with(|graph| {
        graph
            .feed_sessions
            .get(hour.as_str())
            .map(|session| session.state.clone())
    });
    if existing.is_some_and(|state| state != "staging") {
        return Ok(());
    }
    feed_drive_begin(ctx, db, idx).await?;
    for (page_no, count) in counts.iter().enumerate() {
        feed_seed_page(
            ctx,
            db,
            idx,
            u32::try_from(page_no).expect("page index"),
            *count,
            entries,
        )
        .await?;
    }
    routes::feed_complete(
        ctx.loaded(),
        db,
        &feed_drive_complete_request(idx, counts, entries)?,
        DRIVE_ACTOR,
        feed_drive_now_secs(idx),
    )
    .await
    .map_err(text)
}

async fn seed_feed_hour(
    ctx: &DriveContext,
    db: &DurableDb,
    idx: u32,
    pages: u32,
) -> Result<(), String> {
    seed_feed_hour_sized(
        ctx,
        db,
        idx,
        &vec![4; usize::try_from(pages).expect("pages")],
        feed_drive_entries,
    )
    .await
}

/// One `feed_deliver` call at hour `idx`.
async fn feed_deliver_once(
    ctx: &DriveContext,
    db: &DurableDb,
    settings: &SchedulerSettings,
    idx: u32,
) -> Result<stow_types::api::DemandFeedDeliverReport, String> {
    routes::feed_deliver(
        ctx.loaded(),
        db,
        &feed_drive_hour(idx),
        settings,
        DRIVE_ACTOR,
        feed_drive_now_ms(idx),
    )
    .await
    .map(|(report, _plan)| report)
    .map_err(text)
}

/// Drive a staged hour to `delivered` in unmetered setup — every
/// unapplied page plus the terminal transition, looping on the report's
/// own state so page-count changes never desync.
async fn deliver_feed_hour_fully(
    ctx: &DriveContext,
    db: &DurableDb,
    settings: &SchedulerSettings,
    idx: u32,
) -> Result<(), String> {
    seed_feed_hour(ctx, db, idx, FEED_DRIVE_PAGES).await?;
    loop {
        if feed_deliver_once(ctx, db, settings, idx).await?.state == "delivered" {
            return Ok(());
        }
    }
}

/// The page-apply drive's own event graph (stow#523): 256 roots, each
/// gating on two of 128 shared deps, every node born `pending` and
/// unpublished. The page of 256 entries naming the roots walks a closure
/// of exactly 256 + 128 = 384 touched tasks at every fixture shape,
/// which is what lets the scale check attribute growth to stored bulk
/// rather than a changed event. The names are fixture-only
/// (`stow-feed-*`), disjoint from every `crate*`/`costgate-*`/
/// `stow-gate-*` identity.
const FEED_EVENT_ROOTS: u32 = 256;

/// Shared deps the event subgraph's roots gate on.
const FEED_EVENT_DEPS: u32 = 128;

/// Seed base of the event subgraph's nodes.
const FEED_EVENT_SEED: u64 = DRIVE_SEED + 100_000;

/// Root `k`'s two shared deps — `k/2` and `(k/2 + 1) % 128` — so each
/// dep carries four owner edges: real shared/diamond reaches a union
/// walk dedups, not a private tree.
const fn feed_event_deps(k: u32) -> [u32; 2] {
    [k / 2, (k / 2 + 1) % FEED_EVENT_DEPS]
}

fn feed_event_dep_name(d: u32) -> String {
    format!("stow-feed-dep-{d:03}")
}

fn feed_event_root_name(k: u32) -> String {
    format!("stow-feed-root-{k:03}")
}

/// The event subgraph as one submission tree: the shared deps, then the
/// roots on `feed_event_deps`.
fn feed_event_tree() -> SubmissionTree {
    let target = stow_types::fixture::target_of(0);
    let mut nodes: Vec<_> = (0..FEED_EVENT_DEPS)
        .map(|d| {
            fixture::named_node(
                &feed_event_dep_name(d),
                FEED_EVENT_SEED + u64::from(d),
                target,
                Vec::new(),
            )
        })
        .collect();
    nodes.extend((0..FEED_EVENT_ROOTS).map(|k| {
        fixture::named_node(
            &feed_event_root_name(k),
            FEED_EVENT_SEED + u64::from(FEED_EVENT_DEPS + k),
            target,
            feed_event_deps(k).to_vec(),
        )
    }));
    SubmissionTree {
        source: SubmissionSource::CacheMiss,
        roots: (FEED_EVENT_DEPS..FEED_EVENT_DEPS + FEED_EVENT_ROOTS).collect(),
        nodes,
    }
}

/// The event hour's page-entry source: page 0 is the measured max page —
/// its `count` entries name the subgraph's roots, so the delivered
/// page's closure is the fixed 384-task set at every fixture shape.
/// Trailing pages keep the fixture formula.
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
                    crate_name: CrateName::parse(feed_event_root_name(k)).map_err(text)?,
                    version: CrateVersion::new(semver::Version::new(1, 0, 0)),
                    features_json: FeaturesJson::default(),
                    target: TargetTriple::parse(stow_types::fixture::target_of(0)).map_err(text)?,
                    rustc_version: WireRustcVersion::parse("1.86.0").map_err(text)?,
                    demand: 100,
                })
            },
        )
        .collect()
}

/// Every task id of the event subgraph.
fn feed_event_task_ids() -> Vec<String> {
    let target = stow_types::fixture::target_of(0);
    let deps = (0..FEED_EVENT_DEPS).map(|d| (feed_event_dep_name(d), d));
    let roots = (0..FEED_EVENT_ROOTS).map(|k| (feed_event_root_name(k), FEED_EVENT_DEPS + k));
    deps.chain(roots)
        .map(|(name, k)| {
            stow_types::fixture::named_task_id(&name, FEED_EVENT_SEED + u64::from(k), target)
        })
        .collect()
}

// ===== The drive list =====

/// The drives, in budget-table order. Read routes first, then the
/// state-changing ones: the submit/publish/alarm drives mutate the
/// fixture, and the ordering keeps those mutations from hiding behind
/// the read routes' measurements. The wake and the snapshot — which
/// rewrite or reread the whole store — run last.
pub const DRIVES: &[Drive] = &[
    Drive {
        name: "GET /status",
        setup: None,
        run: |_db, _shape, _settings, ctx| {
            Box::pin(async move {
                ctx.loaded().with(|graph| graph.status());
                Ok(())
            })
        },
        cleanup: None,
    },
    Drive {
        // The health probe (stow#860): one read of state the graph
        // already holds — the same shape as `GET /status`.
        name: "GET /health",
        setup: None,
        run: |_db, _shape, _settings, ctx| {
            Box::pin(async move {
                ctx.loaded().with(|graph| graph.health(now_ms()));
                Ok(())
            })
        },
        cleanup: None,
    },
    Drive {
        // Bounded by held quantities: the outcome ring is capped, and
        // the in-flight section by the dispatch cap — neither tracks the
        // stored node bulk.
        name: "GET /admin/status",
        setup: None,
        run: |_db, _shape, _settings, ctx| {
            Box::pin(async move {
                ctx.loaded()
                    .with(|graph| graph.admin_status(now_ms()))
                    .map(|_| ())
                    .map_err(text)
            })
        },
        cleanup: None,
    },
    Drive {
        name: "GET /tasks",
        setup: None,
        run: |_db, _shape, _settings, ctx| {
            Box::pin(async move { list(ctx, &QueueSelector::default()) })
        },
        cleanup: None,
    },
    Drive {
        name: "GET /tasks?status=failed",
        setup: None,
        run: |_db, _shape, _settings, ctx| {
            Box::pin(async move {
                list(
                    ctx,
                    &QueueSelector {
                        status: Some(QueueTaskStatus::Failed),
                        ..QueueSelector::default()
                    },
                )
            })
        },
        cleanup: None,
    },
    Drive {
        name: "GET /tasks?status=pending",
        setup: None,
        run: |_db, _shape, _settings, ctx| {
            Box::pin(async move {
                list(
                    ctx,
                    &QueueSelector {
                        status: Some(QueueTaskStatus::Pending),
                        ..QueueSelector::default()
                    },
                )
            })
        },
        cleanup: None,
    },
    Drive {
        name: "GET /tasks?status=blocked",
        setup: None,
        run: |_db, _shape, _settings, ctx| {
            Box::pin(async move {
                list(
                    ctx,
                    &QueueSelector {
                        status: Some(QueueTaskStatus::Blocked),
                        ..QueueSelector::default()
                    },
                )
            })
        },
        cleanup: None,
    },
    Drive {
        name: "GET /tasks?target=…",
        setup: None,
        run: |_db, _shape, _settings, ctx| {
            Box::pin(async move {
                list(
                    ctx,
                    &QueueSelector {
                        target: Some(
                            CI_TARGET_TRIPLES[0]
                                .parse()
                                .map_err(|error| format!("target parse: {error}"))?,
                        ),
                        ..QueueSelector::default()
                    },
                )
            })
        },
        cleanup: None,
    },
    Drive {
        // The crate selector reads the name's own version set — pinned
        // at `fixture::CRATE_NAME_ROWS` nodes across sizes.
        name: "GET /tasks?crate=…",
        setup: None,
        run: |_db, _shape, _settings, ctx| {
            Box::pin(async move {
                list(
                    ctx,
                    &QueueSelector {
                        crate_name: Some(
                            "crate123"
                                .parse()
                                .map_err(|error| format!("crate: {error}"))?,
                        ),
                        ..QueueSelector::default()
                    },
                )
            })
        },
        cleanup: None,
    },
    Drive {
        // The age selector's window is the last 24 h, held at
        // `FixtureShape::LAST_24H_ROWS`.
        name: "GET /tasks?older_than=86400",
        setup: None,
        run: |_db, _shape, _settings, ctx| {
            Box::pin(async move {
                list(
                    ctx,
                    &QueueSelector {
                        older_than_secs: Some(86_400),
                        ..QueueSelector::default()
                    },
                )
            })
        },
        cleanup: None,
    },
    Drive {
        // The score-visibility wire check (stow#525): two human pins
        // carry adjacent values above the JS-safe integer range — the
        // listing must return their exact decimal text.
        name: "GET /tasks?task_ids=…",
        setup: None,
        run: |_db, shape, _settings, ctx| {
            Box::pin(async move {
                let tasks = ctx
                    .loaded()
                    .with(|graph| {
                        graph.list(
                            &QueueSelector {
                                task_ids: vec![
                                    id_of(FixtureShape::pending_row(600)),
                                    id_of(shape.failed_row(0)),
                                    id_of(1993),
                                    id_of(1994),
                                ],
                                ..QueueSelector::default()
                            },
                            now_ms(),
                        )
                    })
                    .map_err(text)?;
                let value_of = |n: u32| {
                    tasks
                        .iter()
                        .find(|task| task.task_id == id_of(n))
                        .map(|task| task.value.clone())
                };
                for (n, expected) in [(1993, "3000"), (1994, "3000")] {
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
        // The retried nodes re-enter `pending` with their dependents'
        // blocked flags recomputed; the cleanup cancels them again.
        name: "POST /tasks/retry",
        setup: None,
        run: |db, shape, settings, ctx| {
            Box::pin(async move {
                expect_mutated(
                    ctx,
                    db,
                    MutationKind::Retry,
                    vec![id_of(shape.failed_row(0)), id_of(shape.failed_row(1))],
                    2,
                    "retry",
                )
                .await?;
                schedule(ctx, db, settings).await
            })
        },
        cleanup: Some(|db, shape, _settings, ctx| {
            Box::pin(async move {
                cancel_submitted(
                    ctx,
                    db,
                    vec![id_of(shape.failed_row(0)), id_of(shape.failed_row(1))],
                )
                .await
            })
        }),
    },
    Drive {
        // The cancelled nodes leave `pending` for `failed` and their
        // dependents wake-block in the same request; the cleanup
        // retries them back.
        name: "POST /tasks/cancel",
        setup: None,
        run: |db, _shape, settings, ctx| {
            Box::pin(async move {
                expect_mutated(
                    ctx,
                    db,
                    MutationKind::Cancel,
                    vec![
                        id_of(FixtureShape::pending_row(701)),
                        id_of(FixtureShape::pending_row(702)),
                    ],
                    2,
                    "cancel",
                )
                .await?;
                schedule(ctx, db, settings).await
            })
        },
        cleanup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move {
                mutate(
                    ctx,
                    db,
                    MutationKind::Retry,
                    vec![
                        id_of(FixtureShape::pending_row(701)),
                        id_of(FixtureShape::pending_row(702)),
                    ],
                )
                .await
                .map(|_| ())
            })
        }),
    },
    Drive {
        // The promote moves only the matched node's lane. Row 2700 sits
        // in the miss lane — the human pins end at `HUMAN_LANE_ROWS` —
        // and no later drive reads it.
        name: "POST /tasks/promote",
        setup: None,
        run: |db, _shape, settings, ctx| {
            Box::pin(async move {
                expect_mutated(
                    ctx,
                    db,
                    MutationKind::Promote,
                    vec![id_of(FixtureShape::pending_row(2700))],
                    1,
                    "promote",
                )
                .await?;
                schedule(ctx, db, settings).await
            })
        },
        cleanup: None,
    },
    Drive {
        // The purge removes terminal live nodes — failed rows 2 and 3,
        // which no other drive reads.
        name: "POST /tasks/purge",
        setup: None,
        run: |db, shape, settings, ctx| {
            Box::pin(async move {
                expect_mutated(
                    ctx,
                    db,
                    MutationKind::Purge,
                    vec![id_of(shape.failed_row(2)), id_of(shape.failed_row(3))],
                    2,
                    "purge",
                )
                .await?;
                schedule(ctx, db, settings).await
            })
        },
        cleanup: None,
    },
    Drive {
        // A settled `enqueued` record: the stored-roots parse and the
        // live status re-probe against the graph.
        name: "GET /requests/{id}",
        setup: None,
        run: |_db, _shape, _settings, ctx| {
            Box::pin(async move {
                ctx.loaded()
                    .with(|graph| {
                        queue::crate_request_status(
                            graph,
                            stow_types::fixture::REQUEST_FIXTURE_ENQUEUED,
                            now_ms(),
                        )
                    })
                    .map_err(text)?
                    .map(|_| ())
                    .ok_or_else(|| "the fixture request record is missing".to_owned())
            })
        },
        cleanup: None,
    },
    Drive {
        // The request lane's admission end to end — on wasm the real
        // `admit_request_pass`: the freeze and budget probes, the
        // deduping record and the serialized `trigger_resolve` hop to
        // the local-CI dispatcher.
        name: "POST /requests",
        setup: None,
        run: |db, _shape, settings, ctx| {
            Box::pin(async move { admit_request_drive(db, settings, ctx).await })
        },
        cleanup: None,
    },
    Drive {
        // `in_progress` on the record the admit drive just inserted:
        // the fenced `accepted -> resolving` event.
        name: "POST /requests/{id}/run-update (in_progress)",
        setup: None,
        run: |db, _shape, _settings, ctx| {
            Box::pin(async move {
                routes::request_run_update(
                    ctx.loaded(),
                    db,
                    DRIVE_REQUEST_ID,
                    &run_update(stow_types::api::RequestRunAction::InProgress, None),
                    now_ms(),
                )
                .await
                .map_err(text)
            })
        },
        cleanup: None,
    },
    Drive {
        // A `Resolved` report on the live record: the trusted merge of
        // its tree, the pre/post status probes and the `enqueued`
        // event — the same merge machinery the submit drives price, at
        // the request batch's size.
        name: "POST /requests/{id}/outcome",
        setup: None,
        run: |db, shape, settings, ctx| {
            Box::pin(async move {
                routes::request_outcome(
                    ctx.loaded(),
                    db,
                    DRIVE_REQUEST_ID,
                    &request_report(shape),
                    Some(DRIVE_ACTOR),
                    now_ms(),
                )
                .await
                .map_err(text)?;
                schedule(ctx, db, settings).await
            })
        },
        // The outcome's trusted merge lands the report's root as a
        // human-lane `pending` node; left behind it would be claimable
        // by the next pass drive.
        cleanup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move {
                cancel_submitted(
                    ctx,
                    db,
                    vec![stow_types::fixture::named_task_id(
                        "costgate-request-root",
                        DRIVE_SEED + TAG_UNTRUSTED * 1_000 + 500,
                        CI_TARGET_TRIPLES[0],
                    )],
                )
                .await
            })
        }),
    },
    Drive {
        // `completed` on the now-`enqueued` record — the fenced event
        // the backstop must never apply over a settled record: the real
        // event costs one appended row.
        name: "POST /requests/{id}/run-update (completed)",
        setup: None,
        run: |db, _shape, _settings, ctx| {
            Box::pin(async move {
                routes::request_run_update(
                    ctx.loaded(),
                    db,
                    DRIVE_REQUEST_ID,
                    &run_update(
                        stow_types::api::RequestRunAction::Completed,
                        Some("success"),
                    ),
                    now_ms(),
                )
                .await
                .map_err(text)
            })
        },
        cleanup: None,
    },
    Drive {
        // The pending-depth check is a graph count; the cap's refusal
        // path is the deterministic one: a zero cap turns any depth into
        // a refusal, so the drive does not bet the fixture stays over
        // the deploy's cap.
        name: "POST /enqueue (untrusted)",
        setup: None,
        run: |db, shape, settings, ctx| {
            Box::pin(async move {
                let mut refused = *settings;
                refused.max_queue_pending = 0;
                match routes::submit(
                    ctx.loaded(),
                    db,
                    &refused,
                    &submit_batch(shape, TAG_UNTRUSTED).trees,
                    true,
                    None,
                    now_ms(),
                )
                .await
                {
                    Ok(_) | Err(crate::errors::QueueError::QueueFull { .. }) => Ok(()),
                    Err(error) => Err(text(error)),
                }
            })
        },
        cleanup: None,
    },
    Drive {
        // The accept half of the untrusted route: the cap is lifted so
        // the probe measures the merge and its append. The launch gate
        // prices a miss-lane enqueue here: an accepted redemption pays
        // the merge, not the refusal.
        name: "POST /enqueue (untrusted accept)",
        setup: None,
        run: |db, shape, settings, ctx| {
            Box::pin(async move {
                let mut lifted = *settings;
                lifted.max_queue_pending = u32::MAX;
                let batch = submit_batch(shape, TAG_ACCEPT);
                let inserted = submit(ctx, db, &lifted, &batch.trees, true).await?;
                if inserted != 3 {
                    return Err(format!("accept submit inserted {inserted}, expected 3"));
                }
                schedule(ctx, db, settings).await
            })
        },
        cleanup: Some(|db, shape, _settings, ctx| {
            Box::pin(async move {
                cancel_submitted(ctx, db, submit_batch(shape, TAG_ACCEPT).task_ids).await
            })
        }),
    },
    Drive {
        name: "POST /admin/enqueue (trusted)",
        setup: Some(|db, shape, settings, ctx| {
            Box::pin(async move {
                // Land the batch's resync entry first so the measured
                // submit finds it by its task id — the merge's
                // existing-id path.
                let batch = submit_batch(shape, TAG_TRUSTED);
                let miss = SubmissionTree {
                    roots: vec![batch.trees[0].roots[0]],
                    ..batch.trees[0].clone()
                };
                let inserted = submit(ctx, db, settings, &[miss], false).await?;
                // The miss tree carries the fresh dep's copy and the
                // fresh node too, so the setup lands two of the three.
                (inserted == 2)
                    .then_some(())
                    .ok_or_else(|| format!("trusted submit setup inserted {inserted}, expected 2"))
            })
        }),
        run: |db, shape, settings, ctx| {
            Box::pin(async move {
                // The resync and the fresh miss are held; the human is
                // new.
                submit_expect(
                    ctx,
                    db,
                    settings,
                    &submit_batch(shape, TAG_TRUSTED).trees,
                    1,
                    "trusted submit",
                )
                .await
            })
        },
        cleanup: Some(|db, shape, _settings, ctx| {
            Box::pin(async move {
                cancel_submitted(ctx, db, submit_batch(shape, TAG_TRUSTED).task_ids).await
            })
        }),
    },
    Drive {
        // `POST /tasks/submit/ids` — the missed lane's promote-by-id
        // route: one `SubmitIds` event over nodes the graph holds. The
        // setup lands the batch so the ids are known; an unknown id adds
        // nothing but its place in the response.
        name: "POST /admin/enqueue (submit-ids)",
        setup: Some(|db, shape, settings, ctx| {
            Box::pin(async move {
                submit_expect(
                    ctx,
                    db,
                    settings,
                    &submit_batch(shape, TAG_IDS).trees,
                    3,
                    "submit-ids setup",
                )
                .await
            })
        }),
        run: |db, shape, _settings, ctx| {
            Box::pin(async move {
                let entries: Vec<SubmitTaskIdEntry> = submit_batch(shape, TAG_IDS)
                    .task_ids
                    .into_iter()
                    .map(|task_id| SubmitTaskIdEntry {
                        task_id,
                        downloads: 1,
                    })
                    .collect();
                let (promoted, unknown) =
                    routes::submit_ids(ctx.loaded(), db, &entries, Some(DRIVE_ACTOR), now_ms())
                        .await
                        .map_err(text)?;
                (promoted == 3 && unknown.is_empty())
                    .then_some(())
                    .ok_or_else(|| {
                        format!("submit-ids promoted {promoted}, unknown {}", unknown.len())
                    })
            })
        },
        cleanup: Some(|db, shape, _settings, ctx| {
            Box::pin(async move {
                cancel_submitted(ctx, db, submit_batch(shape, TAG_IDS).task_ids).await
            })
        }),
    },
    Drive {
        name: "POST /admin/enqueue (resubmit)",
        setup: Some(|db, shape, settings, ctx| {
            Box::pin(async move {
                // The run resubmits nodes that already exist, so the
                // batch lands here — no earlier drive leaves it behind.
                submit_expect(
                    ctx,
                    db,
                    settings,
                    &submit_batch(shape, TAG_RESUBMIT).trees,
                    3,
                    "resubmit setup",
                )
                .await
            })
        }),
        run: |db, shape, settings, ctx| {
            Box::pin(async move {
                // The same batch again lands nothing — the count must
                // be zero.
                submit_expect(
                    ctx,
                    db,
                    settings,
                    &submit_batch(shape, TAG_RESUBMIT).trees,
                    0,
                    "resubmit",
                )
                .await
            })
        },
        cleanup: Some(|db, shape, _settings, ctx| {
            Box::pin(async move {
                cancel_submitted(ctx, db, submit_batch(shape, TAG_RESUBMIT).task_ids).await
            })
        }),
    },
    // One drive per submission entry point (stow#879): the source's
    // priority is what the node's `priority × waited` rank reads, so
    // each lane that sets it is measured through the same submit core.
    Drive {
        name: "POST /tasks/submit (operations)",
        setup: None,
        run: |db, _shape, settings, ctx| {
            Box::pin(async move {
                submit_expect(
                    ctx,
                    db,
                    settings,
                    &[source_tree(
                        SubmissionSource::Operations { priority: 200 },
                        "costgate-ops",
                        TAG_OPS,
                    )],
                    1,
                    "operations submit",
                )
                .await
            })
        },
        cleanup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move {
                cancel_submitted(ctx, db, vec![source_node_id("costgate-ops", TAG_OPS)]).await
            })
        }),
    },
    Drive {
        name: "POST /tasks/submit (preheat)",
        setup: None,
        run: |db, _shape, settings, ctx| {
            Box::pin(async move {
                submit_expect(
                    ctx,
                    db,
                    settings,
                    &[source_tree(
                        SubmissionSource::Preheat,
                        "costgate-preheat",
                        TAG_PREHEAT,
                    )],
                    1,
                    "preheat submit",
                )
                .await
            })
        },
        cleanup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move {
                cancel_submitted(
                    ctx,
                    db,
                    vec![source_node_id("costgate-preheat", TAG_PREHEAT)],
                )
                .await
            })
        }),
    },
    Drive {
        // The newreleases.io forward's object half (stow#880): on
        // wasm the real `preheat_release_pass` — credential arm plus
        // the `workflow_dispatch` POST to the local-CI dispatcher; on
        // host the arm is a no-op `Ok(())` — no store work runs and
        // there is nothing to measure.
        name: "POST /preheat/release",
        setup: None,
        run: |_db, _shape, _settings, ctx| {
            Box::pin(async move {
                #[cfg(target_arch = "wasm32")]
                {
                    let env = ctx
                        .env
                        .as_ref()
                        .ok_or_else(|| "preheat release drive needs a Worker env".to_owned())?;
                    super::object::preheat_release_pass(
                        &ctx.graph,
                        env,
                        &stow_types::api::PreheatReleaseRequest {
                            rustc_version: "1.90.0".parse().map_err(|error| {
                                format!("preheat release rustc version: {error}")
                            })?,
                        },
                    )
                    .await
                    .map_err(text)
                }
                #[cfg(not(target_arch = "wasm32"))]
                {
                    let _ = ctx;
                    Ok(())
                }
            })
        },
        cleanup: None,
    },
    Drive {
        name: "POST /tasks/submit (inexact-hit)",
        setup: None,
        run: |db, _shape, settings, ctx| {
            Box::pin(async move {
                submit_expect(
                    ctx,
                    db,
                    settings,
                    &[source_tree(
                        SubmissionSource::InexactHit,
                        "costgate-inexact",
                        TAG_INEXACT,
                    )],
                    1,
                    "inexact-hit submit",
                )
                .await
            })
        },
        cleanup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move {
                cancel_submitted(
                    ctx,
                    db,
                    vec![source_node_id("costgate-inexact", TAG_INEXACT)],
                )
                .await
            })
        }),
    },
    Drive {
        name: "POST /demand",
        setup: Some(|_db, _shape, _settings, ctx| {
            Box::pin(async move {
                // Capture the alarm state before the drive arms its
                // probe timestamps — the cleanup restores exactly this
                // (or deletes the probe's arm when none was set).
                #[cfg(target_arch = "wasm32")]
                if let Some(alarm) = ctx.alarm.as_ref() {
                    let prior = alarm.get_alarm().await.map_err(text)?;
                    ctx.set_prior_alarm(prior);
                }
                let _ = ctx;
                Ok(())
            })
        }),
        run: |db, _shape, settings, ctx| {
            Box::pin(async move {
                // One durable batch on one keyed root — fixture node
                // 101's identity, pending with unmet edges — so the
                // measure covers the whole route pass: the identity
                // probe, the closure walk, the fold, and the wake plan
                // the route then arms, all bounded by the touched set
                // (stow#522).
                let request = stow_types::api::SchedulerDemandRequest {
                    batch_id: "costgate-demand".to_owned(),
                    entries: vec![fixture_entry(101)?],
                };
                let (report, plan) = routes::demand(
                    ctx.loaded(),
                    db,
                    &request,
                    settings,
                    Some(DRIVE_ACTOR),
                    now_ms(),
                )
                .await
                .map_err(text)?;
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
                    let future_ms = now_ms() + 600_000;
                    queue::arm_alarm(alarm, queue::AlarmPlan::At(future_ms))
                        .await
                        .map_err(text)?;
                    let armed = alarm.get_alarm().await.map_err(text)?;
                    if armed != Some(future_ms) {
                        return Err(format!("alarm reads {armed:?} after arm at {future_ms}"));
                    }
                    queue::arm_alarm(alarm, plan).await.map_err(text)?;
                }
                #[cfg(not(target_arch = "wasm32"))]
                if !matches!(plan, queue::AlarmPlan::At(_)) {
                    return Err(format!("demand pass planned {plan:?}, expected At"));
                }
                Ok(())
            })
        },
        cleanup: Some(|_db, _shape, _settings, ctx| {
            Box::pin(async move {
                // The fold stays in the graph (a demand is additive and
                // no later drive reads node 101's closure). Put the
                // pre-drive alarm state back: re-arm the captured
                // timestamp, or delete the probe's arm when nothing was
                // set — a real armed alarm must not leak into later
                // drives.
                #[cfg(target_arch = "wasm32")]
                if let Some(alarm) = ctx.alarm.as_ref() {
                    match ctx.take_prior_alarm() {
                        PriorAlarm::Armed(ms) => alarm.set_alarm(ms).await.map_err(text)?,
                        PriorAlarm::Unarmed => alarm.delete_alarm().await.map_err(text)?,
                        PriorAlarm::NotCaptured => {}
                    }
                }
                let _ = ctx;
                Ok(())
            })
        }),
    },
    Drive {
        // The route's whole event: one `SliceReport` append and its
        // flips, plus the `dispatch_pending` tail `record_published_index`
        // runs. A full report (`base_generation: None`) — the
        // first-publish and resync path — on a dedicated slice whose
        // size is held across fixtures; its cost is bounded by the
        // report's own membership. The tail's claims are restored by the
        // cleanup, so the alarm-pass drives still see the planted window.
        name: "POST /index/published (full)",
        setup: None,
        run: |db, _shape, settings, ctx| {
            Box::pin(async move {
                routes::slice_reports(
                    ctx.loaded(),
                    db,
                    &[PublishedSlice {
                        target: TargetTriple::parse(CI_TARGET_TRIPLES[8]).map_err(text)?,
                        rustc_version: WireRustcVersion::parse("1.86.0").map_err(text)?,
                        base_generation: None,
                        generation: None,
                        added: fixture::full_slice_report(),
                        retired: Vec::new(),
                    }],
                    Some(DRIVE_ACTOR),
                    now_ms(),
                )
                .await
                .map_err(text)?;
                let claimed = focused_claim_pass(db, settings, ctx).await?;
                *ctx.bound.lock().expect("drive binding") = None;
                ctx.set_bound(BoundRun {
                    task: claimed.join(","),
                    run: 0,
                });
                Ok(())
            })
        },
        cleanup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move {
                let claimed = ctx.bound_run()?.task;
                let ids = claimed
                    .split(',')
                    .filter(|id| !id.is_empty())
                    .map(str::to_owned)
                    .collect();
                restore_claimed(ctx, db, ids).await?;
                routes::slice_reports(
                    ctx.loaded(),
                    db,
                    &[PublishedSlice {
                        target: TargetTriple::parse(CI_TARGET_TRIPLES[8]).map_err(text)?,
                        rustc_version: WireRustcVersion::parse("1.86.0").map_err(text)?,
                        base_generation: None,
                        generation: None,
                        added: Vec::new(),
                        retired: fixture::full_slice_report(),
                    }],
                    Some(DRIVE_ACTOR),
                    now_ms(),
                )
                .await
                .map_err(text)
            })
        }),
    },
    Drive {
        // A routine per-wave report: `added`/`retired` carry only what
        // moved, and every flip is bounded by the delta. The retired
        // rows leave real nodes partially published; the cleanup swaps
        // the report back.
        name: "POST /index/published (delta)",
        setup: None,
        run: |db, shape, settings, ctx| {
            Box::pin(async move {
                let (added, retired) = fixture::delta_slice_report(shape);
                routes::slice_reports(
                    ctx.loaded(),
                    db,
                    &[PublishedSlice {
                        target: TargetTriple::parse(CI_TARGET_TRIPLES[0]).map_err(text)?,
                        rustc_version: WireRustcVersion::parse("1.85.0").map_err(text)?,
                        base_generation: None,
                        generation: None,
                        added,
                        retired,
                    }],
                    Some(DRIVE_ACTOR),
                    now_ms(),
                )
                .await
                .map_err(text)?;
                let claimed = focused_claim_pass(db, settings, ctx).await?;
                ctx.set_bound(BoundRun {
                    task: claimed.join(","),
                    run: 0,
                });
                Ok(())
            })
        },
        cleanup: Some(|db, shape, _settings, ctx| {
            Box::pin(async move {
                let claimed = ctx.bound_run()?.task;
                let ids = claimed
                    .split(',')
                    .filter(|id| !id.is_empty())
                    .map(str::to_owned)
                    .collect();
                restore_claimed(ctx, db, ids).await?;
                let (added, retired) = fixture::delta_slice_report(shape);
                routes::slice_reports(
                    ctx.loaded(),
                    db,
                    &[PublishedSlice {
                        target: TargetTriple::parse(CI_TARGET_TRIPLES[0]).map_err(text)?,
                        rustc_version: WireRustcVersion::parse("1.85.0").map_err(text)?,
                        base_generation: None,
                        generation: None,
                        added: retired,
                        retired: added,
                    }],
                    Some(DRIVE_ACTOR),
                    now_ms(),
                )
                .await
                .map_err(text)
            })
        }),
    },
    Drive {
        // One focused claim over a *floored* queue (stow#525): the
        // floor sits at the window's stored demand, so the under-floor
        // miss bulk stays out of the ready set while the planted
        // window's rows remain claimable. The claim and its `Claims`
        // append are priced; the claimed ids never enter
        // `claimed_tasks` (the launch gate's marginal divisor counts
        // only the hot pass's claims), and the cleanup restores them.
        name: "alarm pass (floor claim)",
        setup: None,
        run: |db, _shape, settings, ctx| {
            Box::pin(async move {
                let floored = SchedulerSettings {
                    min_dispatch_value: fixture::WINDOW_DEMAND,
                    ..*settings
                };
                let claimed = focused_claim_pass(db, &floored, ctx).await?;
                if claimed.is_empty() {
                    return Err("the floored pass claimed nothing".to_owned());
                }
                ctx.set_bound(BoundRun {
                    task: claimed.join(","),
                    run: 0,
                });
                Ok(())
            })
        },
        cleanup: Some(|db, _shape, settings, ctx| {
            Box::pin(async move {
                let claimed = ctx.bound_run()?.task;
                let ids = claimed
                    .split(',')
                    .filter(|id| !id.is_empty())
                    .map(str::to_owned)
                    .collect();
                restore_claimed(ctx, db, ids).await?;
                // The unfloored floor goes back for the next pass.
                ctx.loaded()
                    .with(|graph| graph.set_floor(settings.min_dispatch_value));
                Ok(())
            })
        }),
    },
    Drive {
        // One real dispatch pass exactly as the alarm runs it: the
        // stale sweep, the claim, and on workerd the concurrent
        // fan-out of `workflow_dispatch` POSTs to the local-CI
        // dispatcher — the HTTP wall the launch gate's peak-wall bound
        // exists to measure — then the wake re-plan. External-run
        // occupancy (stow#877) reconciles at most once per ten minutes
        // and only while the graph holds work.
        name: "alarm pass",
        setup: None,
        run: |db, _shape, settings, ctx| {
            Box::pin(async move {
                let task_ids = pass(db, settings, ctx).await?;
                ctx.record_claimed(task_ids);
                let _plan = routes::wake_plan(ctx.loaded(), settings, now_ms());
                Ok(())
            })
        },
        // The claimed ids stay in `claimed_tasks` — the launch gate's
        // marginal divisor — but the nodes themselves go back to
        // `pending`, so no later drive measures the pass's claimed
        // frontier instead of the fixture's.
        cleanup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move { restore_claimed(ctx, db, ctx.claimed_ids()).await })
        }),
    },
    Drive {
        // The same pass with dispatch paused: the claim returns early,
        // so this measures the per-invocation floor — the stale sweep,
        // the freeze and binding reads, and the wake re-plan — every
        // alarm wake pays regardless of what it claims. The launch gate
        // (stow#452) prices an invocation from this row and the claims
        // inside a pass as the marginal cost between it and the hot
        // pass above.
        name: "alarm pass (idle)",
        setup: None,
        run: |db, _shape, settings, ctx| {
            Box::pin(async move {
                let mut idle = *settings;
                idle.dispatch = queue::Dispatch::Paused;
                pass(db, &idle, ctx).await?;
                let _plan = routes::wake_plan(ctx.loaded(), &idle, now_ms());
                Ok(())
            })
        },
        cleanup: None,
    },
    Drive {
        // The operator's caps read (stow#1039): one read of state the
        // graph holds — the same shape as `GET /admin/status`.
        name: "GET /dispatch-cap",
        setup: None,
        run: |_db, _shape, settings, ctx| {
            Box::pin(async move {
                ctx.loaded().with(|graph| {
                    graph.dispatch_cap_view(&settings.with_dispatch_cap(graph.dispatch_cap()))
                });
                Ok(())
            })
        },
        cleanup: None,
    },
    Drive {
        // The operator's `set` (stow#1039): one `DispatchCap` append,
        // then the route's own tail — the dispatch pass a raised cap's
        // freed slots run and the wake re-plan, both under the settings
        // the object builds after the append (the stored setting
        // replacing the bindings' caps). The setting is sized two slots
        // above the fixture's in-flight count so the pass claims like
        // production's raise does. The seed stores no setting and a
        // `set` has no clear, so the cleanup restores that state
        // exactly: the claimed tasks return, the in-memory setting is
        // dropped, and a snapshot makes that the store's state — the
        // log row it covered goes with the prefix, so no later wake
        // replays it.
        name: "POST /dispatch-cap",
        setup: Some(|_db, _shape, _settings, ctx| {
            Box::pin(async move {
                if ctx.loaded().with(|graph| graph.dispatch_cap().is_some()) {
                    return Err("POST /dispatch-cap drive expects the seed's unset caps".to_owned());
                }
                Ok(())
            })
        }),
        run: |db, _shape, settings, ctx| {
            Box::pin(async move {
                let (inflight, macos_inflight) = ctx.loaded().with(|graph| graph.inflight());
                routes::commit_as(
                    ctx.loaded(),
                    db,
                    Some(DRIVE_ACTOR),
                    &[SchedulerEvent::DispatchCap {
                        setting: Box::new(stow_types::api::DispatchCapSetting {
                            max_concurrent_jobs: inflight + 2,
                            max_concurrent_macos_jobs: Some(macos_inflight + 2),
                            set_at: "2026-01-01T00:00:00.000Z".to_owned(),
                            actor: DRIVE_ACTOR.to_owned(),
                        }),
                    }],
                    now_ms(),
                )
                .await
                .map_err(text)?;
                let raised = ctx
                    .loaded()
                    .with(|graph| settings.with_dispatch_cap(graph.dispatch_cap()));
                let claimed = pass(db, &raised, ctx).await?;
                let _plan = routes::wake_plan(ctx.loaded(), &raised, now_ms());
                ctx.set_bound(BoundRun {
                    task: claimed.join(","),
                    run: 0,
                });
                Ok(())
            })
        },
        cleanup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move {
                let claimed = ctx.bound_run()?.task;
                let ids = claimed
                    .split(',')
                    .filter(|id| !id.is_empty())
                    .map(str::to_owned)
                    .collect();
                restore_claimed(ctx, db, ids).await?;
                ctx.loaded()
                    .with(super::graph::Graph::restore_unset_dispatch_cap);
                routes::snapshot(ctx.loaded(), db, now_ms())
                    .await
                    .map_err(text)
            })
        }),
    },
    // The per-task run drives (stow#876). Each setup claims one window
    // node and binds it to a run, so the drive prices what a bound
    // in-flight task costs — event-sized, never the graph.
    Drive {
        // The webhook's `completed` forward: the `RunFinished` append,
        // the graph transition and its build sample, and the wake
        // re-plan the route's `schedule_alarm` runs.
        name: "POST /tasks/complete-run (success)",
        setup: Some(|db, _shape, settings, ctx| {
            Box::pin(async move { bind_fresh(ctx, db, settings, TAG_RUN_SUCCESS, now_ms()).await })
        }),
        run: |db, _shape, settings, ctx| {
            Box::pin(async move { complete_run_route(db, settings, ctx, true).await })
        },
        cleanup: None,
    },
    Drive {
        // The same route for a failed run: the conclusion is carried
        // verbatim, so the cost is the success delivery's; the failure
        // re-queues the node behind its dispatch backoff.
        name: "POST /tasks/complete-run (failure)",
        setup: Some(|db, _shape, settings, ctx| {
            Box::pin(async move { bind_fresh(ctx, db, settings, TAG_RUN_FAILURE, now_ms()).await })
        }),
        run: |db, _shape, settings, ctx| {
            Box::pin(async move { complete_run_route(db, settings, ctx, false).await })
        },
        cleanup: Some(|db, _shape, _settings, ctx| {
            Box::pin(
                async move { cancel_submitted(ctx, db, vec![run_node_id(TAG_RUN_FAILURE)]).await },
            )
        }),
    },
    Drive {
        // The webhook's `in_progress` forward serves external runs
        // only (stow#940): a run the scheduler never dispatched —
        // its task id attributes to a runner family but names no live
        // node — appends `ExternalRunStarted` occupancy. Own runs'
        // running state comes from the CI listing's reconcile instead.
        // The cleanup settles the run as an external completion does,
        // returning the occupancy the drive added.
        name: "POST /tasks/run-update (in_progress)",
        setup: None,
        run: |db, _shape, _settings, ctx| {
            Box::pin(async move {
                routes::task_run_update(
                    ctx.loaded(),
                    db,
                    &stow_types::api::TaskRunUpdate {
                        task_id: run_node_id(TAG_RUN_UPDATE),
                        github_run_id: RUN_UPDATE_RUN_ID.to_string(),
                    },
                    now_ms(),
                )
                .await
                .map(|_| ())
                .map_err(text)
            })
        },
        cleanup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move {
                routes::complete_run(
                    ctx.loaded(),
                    db,
                    &stow_types::api::WorkflowRunComplete {
                        task_id: run_node_id(TAG_RUN_UPDATE),
                        success: true,
                        error: None,
                        cancelled: false,
                        github_run_id: RUN_UPDATE_RUN_ID.to_string(),
                    },
                    now_ms(),
                )
                .await
                .map(|_| ())
                .map_err(text)
            })
        }),
    },
    Drive {
        // The alarm's clock-based recovery of one in-flight node whose
        // claim ran past `STOW_STALE_DISPATCH_MINUTES`: the claim pass's
        // stale sweep requeues it, bounded by the expired nodes the pass
        // finds — no run-status read, no cancel (stow#876). The cap is
        // saturated at the in-flight count, so the pass claims nothing
        // beyond the recovery.
        name: "alarm pass (stale recovery)",
        setup: Some(|db, _shape, settings, ctx| {
            Box::pin(async move {
                let stale_ms = i64::from(settings.stale_dispatch_minutes) * 60_000;
                bind_fresh(
                    ctx,
                    db,
                    settings,
                    TAG_RUN_STALE,
                    now_ms() - stale_ms - 60_000,
                )
                .await
            })
        }),
        run: |db, _shape, settings, ctx| {
            Box::pin(async move {
                let (inflight, _) = ctx.loaded().with(|graph| graph.inflight());
                let saturated = SchedulerSettings {
                    dispatch: queue::Dispatch::from_max_concurrent_jobs(inflight),
                    ..*settings
                };
                pass(db, &saturated, ctx).await.map(|_| ())
            })
        },
        cleanup: Some(|db, _shape, _settings, ctx| {
            Box::pin(
                async move { cancel_submitted(ctx, db, vec![run_node_id(TAG_RUN_STALE)]).await },
            )
        }),
    },
    // The stow#940 dispatching request shapes: the request that frees a
    // slot or releases work runs the dispatch pass itself, so each is
    // priced at its own row — the route's append plus the pass's claim
    // and fan-out.
    Drive {
        // `complete-run` with free capacity: the `RunFinished` +
        // `Claims` append in one, the `MAX_OUTBOUND_INFLIGHT`-bounded
        // fan-out and the `Bindings` row — on wasm the real
        // `complete_run_pass`, on host the same store half with
        // synthetic bindings. The claimed ids ride `bound` home for the
        // cleanup, which returns them to `pending`.
        name: "POST /tasks/complete-run (dispatching)",
        setup: Some(|db, _shape, settings, ctx| {
            Box::pin(async move { bind_fresh(ctx, db, settings, TAG_RUN_DISPATCH, now_ms()).await })
        }),
        run: |db, _shape, settings, ctx| {
            Box::pin(async move {
                let bound = ctx.bound_run()?;
                let report = stow_types::api::WorkflowRunComplete {
                    task_id: bound.task,
                    success: true,
                    error: None,
                    cancelled: false,
                    github_run_id: bound.run.to_string(),
                };
                #[cfg(target_arch = "wasm32")]
                let claimed = {
                    let env = ctx.env.as_ref().ok_or_else(|| {
                        "complete-run dispatching drive needs a Worker env".to_owned()
                    })?;
                    let alarm = ctx.alarm.as_ref().ok_or_else(|| {
                        "complete-run dispatching drive needs the alarm".to_owned()
                    })?;
                    let _ = settings;
                    super::object::complete_run_pass(&ctx.graph, env, db, alarm, &report)
                        .await
                        .map_err(text)?
                };
                #[cfg(not(target_arch = "wasm32"))]
                let claimed = {
                    let now = now_ms();
                    let outcome = routes::complete_run(ctx.loaded(), db, &report, now)
                        .await
                        .map_err(text)?;
                    debug_assert_eq!(outcome, super::graph::FinishOutcome::Applied);
                    let claims = routes::claim_pass(
                        ctx.loaded(),
                        db,
                        settings,
                        now,
                        u32::try_from(crate::fetch_guard::MAX_OUTBOUND_INFLIGHT)
                            .expect("the outbound bound fits u32"),
                    )
                    .await
                    .map_err(text)?;
                    let bindings: Vec<DispatchBinding> = claims
                        .iter()
                        .zip(HOST_RUN_BASE..)
                        .map(|(claim, run)| DispatchBinding {
                            task_id: claim.task_id.clone(),
                            generation: claim.generation,
                            run_id: run.to_string(),
                        })
                        .collect();
                    routes::settle_dispatch(ctx.loaded(), db, bindings, Vec::new(), now)
                        .await
                        .map_err(text)?;
                    let _plan = routes::wake_plan(ctx.loaded(), settings, now);
                    claims
                        .into_iter()
                        .map(|claim| claim.task_id)
                        .collect::<Vec<_>>()
                };
                ctx.set_bound(BoundRun {
                    task: claimed.join(","),
                    run: 0,
                });
                Ok(())
            })
        },
        cleanup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move {
                let claimed = ctx.bound_run()?.task;
                let ids = claimed
                    .split(',')
                    .filter(|id| !id.is_empty())
                    .map(str::to_owned)
                    .collect();
                restore_claimed(ctx, db, ids).await
            })
        }),
    },
    Drive {
        // `index/published` with claimable work behind it: the report's
        // append plus the inline pass over every free slot — on wasm
        // the real `published_index_pass`, on host the same store half
        // with synthetic bindings.
        name: "POST /index/published (dispatching)",
        setup: None,
        run: |db, _shape, settings, ctx| {
            Box::pin(async move {
                let slice = PublishedSlice {
                    target: TargetTriple::parse(CI_TARGET_TRIPLES[8]).map_err(text)?,
                    rustc_version: WireRustcVersion::parse("1.87.0").map_err(text)?,
                    base_generation: None,
                    generation: None,
                    added: fixture::full_slice_report(),
                    retired: Vec::new(),
                };
                #[cfg(target_arch = "wasm32")]
                let claimed = {
                    let env = ctx
                        .env
                        .as_ref()
                        .ok_or_else(|| "index dispatching drive needs a Worker env".to_owned())?;
                    let alarm = ctx
                        .alarm
                        .as_ref()
                        .ok_or_else(|| "index dispatching drive needs the alarm".to_owned())?;
                    // The pass reads the deploy's settings itself.
                    let _ = settings;
                    super::object::published_index_pass(
                        &ctx.graph,
                        env,
                        db,
                        alarm,
                        std::slice::from_ref(&slice),
                        DRIVE_ACTOR,
                    )
                    .await
                    .map_err(text)?
                };
                #[cfg(not(target_arch = "wasm32"))]
                let claimed = {
                    let now = now_ms();
                    routes::slice_reports(
                        ctx.loaded(),
                        db,
                        std::slice::from_ref(&slice),
                        Some(DRIVE_ACTOR),
                        now,
                    )
                    .await
                    .map_err(text)?;
                    let claims = routes::claim_pass(ctx.loaded(), db, settings, now, u32::MAX)
                        .await
                        .map_err(text)?;
                    let bindings: Vec<DispatchBinding> = claims
                        .iter()
                        .zip(HOST_RUN_BASE..)
                        .map(|(claim, run)| DispatchBinding {
                            task_id: claim.task_id.clone(),
                            generation: claim.generation,
                            run_id: run.to_string(),
                        })
                        .collect();
                    routes::settle_dispatch(ctx.loaded(), db, bindings, Vec::new(), now)
                        .await
                        .map_err(text)?;
                    claims
                        .into_iter()
                        .map(|claim| claim.task_id)
                        .collect::<Vec<_>>()
                };
                ctx.set_bound(BoundRun {
                    task: claimed.join(","),
                    run: 0,
                });
                Ok(())
            })
        },
        cleanup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move {
                let claimed = ctx.bound_run()?.task;
                let ids = claimed
                    .split(',')
                    .filter(|id| !id.is_empty())
                    .map(str::to_owned)
                    .collect();
                restore_claimed(ctx, db, ids).await?;
                routes::slice_reports(
                    ctx.loaded(),
                    db,
                    &[PublishedSlice {
                        target: TargetTriple::parse(CI_TARGET_TRIPLES[8]).map_err(text)?,
                        rustc_version: WireRustcVersion::parse("1.87.0").map_err(text)?,
                        base_generation: None,
                        generation: None,
                        added: Vec::new(),
                        retired: fixture::full_slice_report(),
                    }],
                    Some(DRIVE_ACTOR),
                    now_ms(),
                )
                .await
                .map_err(text)
            })
        }),
    },
    Drive {
        // `requests outcome` on a live record: the report's merge plus
        // the inline pass over every free slot — on wasm the real
        // `request_outcome_pass`, on host the same store half with
        // synthetic bindings.
        name: "POST /requests/{id}/outcome (dispatching)",
        setup: Some(|db, _shape, settings, ctx| {
            Box::pin(async move {
                #[cfg(target_arch = "wasm32")]
                {
                    let env = ctx
                        .env
                        .as_ref()
                        .ok_or_else(|| "outcome dispatching setup needs a Worker env".to_owned())?;
                    super::object::admit_request_pass(
                        ctx.loaded(),
                        env,
                        db,
                        settings,
                        &dispatch_admission(),
                        0,
                    )
                    .await
                    .map(|_| ())
                    .map_err(text)?;
                }
                #[cfg(not(target_arch = "wasm32"))]
                routes::admit_request(
                    ctx.loaded(),
                    db,
                    settings,
                    &dispatch_admission(),
                    0,
                    now_ms(),
                )
                .await
                .map(|_| ())
                .map_err(text)?;
                routes::request_run_update(
                    ctx.loaded(),
                    db,
                    DISPATCH_REQUEST_ID,
                    &run_update(stow_types::api::RequestRunAction::InProgress, None),
                    now_ms(),
                )
                .await
                .map_err(text)
            })
        }),
        run: |db, shape, settings, ctx| {
            Box::pin(async move {
                let report = request_report(shape);
                #[cfg(target_arch = "wasm32")]
                let claimed =
                    {
                        let env = ctx.env.as_ref().ok_or_else(|| {
                            "outcome dispatching drive needs a Worker env".to_owned()
                        })?;
                        let alarm = ctx.alarm.as_ref().ok_or_else(|| {
                            "outcome dispatching drive needs the alarm".to_owned()
                        })?;
                        // The pass reads the deploy's settings itself.
                        let _ = settings;
                        super::object::request_outcome_pass(
                            &ctx.graph,
                            env,
                            db,
                            alarm,
                            DISPATCH_REQUEST_ID,
                            &report,
                            DRIVE_ACTOR,
                        )
                        .await
                        .map_err(text)?
                        .1
                    };
                #[cfg(not(target_arch = "wasm32"))]
                let claimed = {
                    let now = now_ms();
                    routes::request_outcome(
                        ctx.loaded(),
                        db,
                        DISPATCH_REQUEST_ID,
                        &report,
                        Some(DRIVE_ACTOR),
                        now,
                    )
                    .await
                    .map_err(text)?;
                    let claims = routes::claim_pass(ctx.loaded(), db, settings, now, u32::MAX)
                        .await
                        .map_err(text)?;
                    let bindings: Vec<DispatchBinding> = claims
                        .iter()
                        .zip(HOST_RUN_BASE..)
                        .map(|(claim, run)| DispatchBinding {
                            task_id: claim.task_id.clone(),
                            generation: claim.generation,
                            run_id: run.to_string(),
                        })
                        .collect();
                    routes::settle_dispatch(ctx.loaded(), db, bindings, Vec::new(), now)
                        .await
                        .map_err(text)?;
                    claims
                        .into_iter()
                        .map(|claim| claim.task_id)
                        .collect::<Vec<_>>()
                };
                ctx.set_bound(BoundRun {
                    task: claimed.join(","),
                    run: 0,
                });
                Ok(())
            })
        },
        cleanup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move {
                let claimed = ctx.bound_run()?.task;
                let ids: Vec<String> = claimed
                    .split(',')
                    .filter(|id| !id.is_empty())
                    .map(str::to_owned)
                    .collect();
                restore_claimed(ctx, db, ids).await?;
                cancel_submitted(
                    ctx,
                    db,
                    vec![stow_types::fixture::named_task_id(
                        "costgate-request-root",
                        DRIVE_SEED + TAG_UNTRUSTED * 1_000 + 500,
                        CI_TARGET_TRIPLES[0],
                    )],
                )
                .await
            })
        }),
    },
    Drive {
        // The feed's resume-cursor read (stow#523): the graph's watermark
        // and oldest unfinished hour — memory only.
        name: "GET /scheduler/demand-feed/status",
        setup: None,
        run: |_db, _shape, _settings, ctx| {
            Box::pin(async move {
                ctx.loaded().with(|graph| feed::feed_status(graph));
                Ok(())
            })
        },
        cleanup: None,
    },
    Drive {
        // Opening a fresh hour (stow#523): the closed-hour and
        // watermark guards, then one `Begin` append.
        name: "POST /scheduler/demand-feed/begin (fresh)",
        setup: None,
        run: |db, _shape, _settings, ctx| {
            Box::pin(async move {
                routes::feed_begin(
                    ctx.loaded(),
                    db,
                    &feed_drive_hour(3),
                    DRIVE_ACTOR,
                    feed_drive_now_secs(3),
                )
                .await
                .map(|_| ())
                .map_err(text)
            })
        },
        cleanup: None,
    },
    Drive {
        // Re-opening a staging hour with real debris (stow#523): setup
        // opens the hour and stages pages under its live generation, so
        // the measured rotate pays the full restart — generation bump,
        // counter reset — never an empty degenerate rotate.
        name: "POST /scheduler/demand-feed/begin (rotation)",
        setup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move {
                feed_drive_begin(ctx, db, 4).await?;
                for page_no in 0..FEED_DRIVE_PAGES {
                    feed_seed_page(ctx, db, 4, page_no, 4, feed_drive_entries).await?;
                }
                Ok(())
            })
        }),
        run: |db, _shape, _settings, ctx| {
            Box::pin(async move {
                let report = routes::feed_begin(
                    ctx.loaded(),
                    db,
                    &feed_drive_hour(4),
                    DRIVE_ACTOR,
                    feed_drive_now_secs(4),
                )
                .await
                .map_err(text)?;
                if report.generation == FEED_DRIVE_GENERATION || report.stale_pages_pending {
                    return Err(format!(
                        "rotation must mint a new generation with nothing left to retire: {report:?}"
                    ));
                }
                Ok(())
            })
        },
        cleanup: None,
    },
    Drive {
        // Staging one bounded page (stow#523): setup opens the hour and
        // stages page 0, then the run stages page 1 against the live
        // generation — the guards plus one `Page` append.
        name: "POST /scheduler/demand-feed/page (append)",
        setup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move {
                feed_drive_begin(ctx, db, 5).await?;
                feed_seed_page(ctx, db, 5, 0, 4, feed_drive_entries).await
            })
        }),
        run: |db, _shape, _settings, ctx| {
            Box::pin(async move { feed_seed_page(ctx, db, 5, 1, 4, feed_drive_entries).await })
        },
        cleanup: None,
    },
    Drive {
        // A replayed page of the same bytes: the guards plus the
        // stored-hash compare that answers the replay as a no-op — zero
        // appended rows.
        name: "POST /scheduler/demand-feed/page (replay)",
        setup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move {
                feed_drive_begin(ctx, db, 6).await?;
                feed_seed_page(ctx, db, 6, 0, 4, feed_drive_entries).await
            })
        }),
        run: |db, _shape, _settings, ctx| {
            Box::pin(async move { feed_seed_page(ctx, db, 6, 0, 4, feed_drive_entries).await })
        },
        cleanup: None,
    },
    Drive {
        // The completion barrier on a populated hour: the manifest
        // verification plus the guarded freeze — the one event that
        // binds the frozen set. The request's manifest comes from the
        // same entries the setup staged.
        name: "POST /scheduler/demand-feed/complete (nonempty)",
        setup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move {
                feed_drive_begin(ctx, db, 7).await?;
                for page_no in 0..FEED_DRIVE_PAGES {
                    feed_seed_page(ctx, db, 7, page_no, 4, feed_drive_entries).await?;
                }
                Ok(())
            })
        }),
        run: |db, _shape, _settings, ctx| {
            Box::pin(async move {
                routes::feed_complete(
                    ctx.loaded(),
                    db,
                    &feed_drive_complete_request(7, &[4; 3], feed_drive_entries)?,
                    DRIVE_ACTOR,
                    feed_drive_now_secs(7),
                )
                .await
                .map_err(text)
            })
        },
        cleanup: None,
    },
    Drive {
        // The same barrier on an hour with zero staged pages: the
        // zero-page hour must still pay its guarded transition.
        name: "POST /scheduler/demand-feed/complete (empty)",
        setup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move { feed_drive_begin(ctx, db, 8).await })
        }),
        run: |db, _shape, _settings, ctx| {
            Box::pin(async move {
                routes::feed_complete(
                    ctx.loaded(),
                    db,
                    &feed_drive_complete_request(8, &[], feed_drive_entries)?,
                    DRIVE_ACTOR,
                    feed_drive_now_secs(8),
                )
                .await
                .map_err(text)
            })
        },
        cleanup: None,
    },
    Drive {
        // One delivery call that applies the protocol's maximum
        // 256-entry page (stow#523): the next-unapplied-page read, the
        // `demand_pass` closure over the entries' touched dependency
        // graph, and the `ApplyPage` + `Demand` appends, plus the wake
        // re-plan. The page's entries name the setup's own fixed event
        // subgraph, so the measured closure is exactly 256 roots + 128
        // shared deps = 384 touched tasks at every fixture shape — the
        // scale check separates this event's work from stored bulk.
        name: "POST /scheduler/demand-feed/deliver (page apply)",
        setup: Some(|db, shape, settings, ctx| {
            Box::pin(async move {
                submit_expect(
                    ctx,
                    db,
                    settings,
                    &[feed_event_tree()],
                    FEED_EVENT_ROOTS + FEED_EVENT_DEPS,
                    "feed event subgraph",
                )
                .await?;
                let _ = shape;
                seed_feed_hour_sized(ctx, db, 0, &[256, 4], feed_event_entries).await
            })
        }),
        run: |db, _shape, settings, ctx| {
            Box::pin(async move { feed_deliver_once(ctx, db, settings, 0).await.map(|_| ()) })
        },
        cleanup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move { cancel_submitted(ctx, db, feed_event_task_ids()).await })
        }),
    },
    Drive {
        // The delivery call on an hour whose pages all applied already:
        // a transition-only event — the owed-page probe, then the
        // contiguous-watermark transition to `delivered`, priced
        // separately from a mid-hour apply.
        name: "POST /scheduler/demand-feed/deliver (terminal)",
        setup: Some(|db, _shape, settings, ctx| {
            Box::pin(async move {
                // Contiguity: T01's transition needs the watermark at
                // T00, so the predecessor delivers fully in unmetered
                // setup — then T01 stages and every page applies,
                // leaving the hour one call short of `delivered`.
                deliver_feed_hour_fully(ctx, db, settings, 0).await?;
                seed_feed_hour(ctx, db, 1, FEED_DRIVE_PAGES).await?;
                for _ in 0..FEED_DRIVE_PAGES {
                    feed_deliver_once(ctx, db, settings, 1).await?;
                }
                Ok(())
            })
        }),
        run: |db, _shape, settings, ctx| {
            Box::pin(async move { feed_deliver_once(ctx, db, settings, 1).await.map(|_| ()) })
        },
        cleanup: None,
    },
    Drive {
        // A delivery replay on an already-delivered hour: the
        // `delivered` early-out plus the wake re-plan — the bounded cost
        // a lost-ack re-fire owes, with zero appended rows.
        name: "POST /scheduler/demand-feed/deliver (replay)",
        setup: Some(|db, _shape, settings, ctx| {
            Box::pin(async move {
                seed_feed_hour(ctx, db, 2, FEED_DRIVE_PAGES).await?;
                deliver_feed_hour_fully(ctx, db, settings, 2).await
            })
        }),
        run: |db, _shape, settings, ctx| {
            Box::pin(async move { feed_deliver_once(ctx, db, settings, 2).await.map(|_| ()) })
        },
        cleanup: None,
    },
    Drive {
        // One bounded retire of a delivered hour's acknowledged pages:
        // the apply retires the staged payloads in one `Cleanup` event.
        name: "POST /scheduler/demand-feed/cleanup (full chunk)",
        setup: Some(|db, _shape, settings, ctx| {
            Box::pin(async move {
                // T03 is the watermark's canonical successor once the
                // deliver drives land T00-T02: stage it, deliver it,
                // and leave its payloads owed a retire.
                feed_drive_begin(ctx, db, 3).await?;
                for page_no in 0..FEED_DRIVE_PAGES {
                    feed_seed_page(ctx, db, 3, page_no, 4, feed_drive_entries).await?;
                }
                routes::feed_complete(
                    ctx.loaded(),
                    db,
                    &feed_drive_complete_request(3, &[4; 3], feed_drive_entries)?,
                    DRIVE_ACTOR,
                    feed_drive_now_secs(3),
                )
                .await
                .map_err(text)?;
                loop {
                    if feed_deliver_once(ctx, db, settings, 3).await?.state == "delivered" {
                        return Ok(());
                    }
                }
            })
        }),
        run: |db, _shape, _settings, ctx| {
            Box::pin(async move {
                let report = routes::feed_cleanup(
                    ctx.loaded(),
                    db,
                    &feed_drive_hour(3),
                    DRIVE_ACTOR,
                    feed_drive_now_secs(3),
                )
                .await
                .map_err(text)?;
                if report.retired == 0 {
                    return Err("cleanup retired nothing from a delivered hour".to_owned());
                }
                Ok(())
            })
        },
        cleanup: None,
    },
    Drive {
        // The retire probe on a staging hour: nothing is owed, so the
        // cleanup answers from the session in memory, retiring zero.
        name: "POST /scheduler/demand-feed/cleanup (none obsolete)",
        setup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move { feed_drive_begin(ctx, db, 4).await })
        }),
        run: |db, _shape, _settings, ctx| {
            Box::pin(async move {
                let report = routes::feed_cleanup(
                    ctx.loaded(),
                    db,
                    &feed_drive_hour(4),
                    DRIVE_ACTOR,
                    feed_drive_now_secs(4),
                )
                .await
                .map_err(text)?;
                if report.retired != 0 || report.remaining {
                    return Err(format!(
                        "cleanup none-obsolete retired {}/remaining {}",
                        report.retired, report.remaining
                    ));
                }
                Ok(())
            })
        },
        cleanup: None,
    },
    Drive {
        // The submit lane at its merge: a 1,000-node tree — each node
        // gating on a published pool leaf — appended as its `Submit`
        // parts and merged into the graph. The cost is the log rows of
        // the tree's bytes, one per ~1 MiB part, plus the merge's CPU.
        name: "POST /tasks/submit (1k-node merge)",
        setup: None,
        run: |db, shape, settings, ctx| {
            Box::pin(async move {
                let inserted = submit(ctx, db, settings, &[merge_tree(shape)], false).await?;
                if inserted != MERGE_NODES {
                    return Err(format!("merge inserted {inserted}, expected {MERGE_NODES}"));
                }
                schedule(ctx, db, settings).await
            })
        },
        cleanup: Some(|db, _shape, _settings, ctx| {
            Box::pin(async move {
                cancel_submitted(
                    ctx,
                    db,
                    (0..MERGE_NODES)
                        .map(|k| {
                            stow_types::fixture::named_task_id(
                                &format!("costgate-merge-{k:04}"),
                                DRIVE_SEED + TAG_MERGE * 1_000_000 + u64::from(k),
                                stow_types::fixture::target_of(101),
                            )
                        })
                        .collect(),
                )
                .await
            })
        }),
    },
    Drive {
        // A cold wake: the snapshot's chunks and the log tail replayed
        // into a fresh graph — the only operation that reads the
        // graph's bulk. Bounded by the snapshot chunks plus the
        // `SNAPSHOT_EVENT_THRESHOLD`-bounded tail.
        name: "wake (snapshot + log replay)",
        // An evicted isolate wakes empty: the live graph is dropped
        // first, so the wake never sits beside a second graph.
        setup: Some(|_db, _shape, _settings, ctx| {
            Box::pin(async move {
                ctx.graph.clear();
                Ok(())
            })
        }),
        run: |db, _shape, _settings, ctx| {
            Box::pin(async move {
                routes::wake_graph(db, &ctx.graph, now_ms())
                    .await
                    .map_err(text)?;
                Ok(())
            })
        },
        cleanup: None,
    },
    Drive {
        // The recurring incremental snapshot (stow#902): setup writes
        // one unmeasured snapshot — the clean slate a live pass starts
        // from — then applies a fixed batch of events identical at
        // every fixture size (a merge, claims, completions and a
        // published-slice report), so the measured run rewrites only
        // the spans the batch dirtied. Each event touches a constant
        // number of chunks, so the snapshot's rows scale with the
        // events since the last one, never with the stored graph.
        name: "snapshot write",
        setup: Some(|db, shape, settings, ctx| {
            Box::pin(async move {
                routes::snapshot(ctx.loaded(), db, now_ms())
                    .await
                    .map_err(text)?;
                let inserted =
                    submit(ctx, db, settings, &[snapshot_merge_tree(shape)], false).await?;
                if inserted != SNAPSHOT_MERGE_NODES {
                    return Err(format!(
                        "snapshot setup merged {inserted}, expected {SNAPSHOT_MERGE_NODES}"
                    ));
                }
                // Two of the drive's own nodes claim and bind; the first
                // completes, so the batch holds claims, a binding and a
                // completion on nodes no other drive reads.
                for k in 0..2 {
                    bind_node(
                        ctx,
                        db,
                        snapshot_node_id(k),
                        SNAPSHOT_RUN_BASE + u64::from(k),
                        now_ms(),
                    )
                    .await?;
                }
                routes::complete_run(
                    ctx.loaded(),
                    db,
                    &stow_types::api::WorkflowRunComplete {
                        task_id: snapshot_node_id(0),
                        success: true,
                        error: None,
                        cancelled: false,
                        github_run_id: SNAPSHOT_RUN_BASE.to_string(),
                    },
                    now_ms(),
                )
                .await
                .map_err(text)?;
                snapshot_slice_report(db, ctx, shape, false).await
            })
        }),
        run: |db, _shape, _settings, ctx| {
            Box::pin(async move {
                routes::snapshot(ctx.loaded(), db, now_ms())
                    .await
                    .map_err(text)
            })
        },
        cleanup: Some(|db, shape, _settings, ctx| {
            Box::pin(async move {
                cancel_submitted(
                    ctx,
                    db,
                    (0..SNAPSHOT_MERGE_NODES).map(snapshot_node_id).collect(),
                )
                .await?;
                snapshot_slice_report(db, ctx, shape, true).await
            })
        }),
    },
];

/// Nodes in the merge drive's tree.
const MERGE_NODES: u32 = 1_000;

/// Nodes in the snapshot drive's setup tree.
const SNAPSHOT_MERGE_NODES: u32 = 24;

/// Task id of the snapshot drive's `k`-th own node.
fn snapshot_node_id(k: u32) -> String {
    stow_types::fixture::named_task_id(
        &format!("costgate-snap-{k:04}"),
        DRIVE_SEED + TAG_SNAPSHOT * 1_000_000 + u64::from(k),
        stow_types::fixture::target_of(101),
    )
}

/// The snapshot drive's setup tree: [`SNAPSHOT_MERGE_NODES`] fresh
/// nodes on published pool leaves, a merge identical at every fixture
/// size that dirties a constant number of spans.
fn snapshot_merge_tree(shape: FixtureShape) -> SubmissionTree {
    let target = stow_types::fixture::target_of(101);
    let pool = shape.pending_end() + 3;
    let mut nodes: Vec<_> = (0..64)
        .map(|leaf| fixture::fixture_node(pool + leaf, Vec::new()))
        .collect();
    nodes.extend((0..SNAPSHOT_MERGE_NODES).map(|k| {
        fixture::named_node(
            &format!("costgate-snap-{k:04}"),
            DRIVE_SEED + TAG_SNAPSHOT * 1_000_000 + u64::from(k),
            target,
            vec![k % 64],
        )
    }));
    SubmissionTree {
        source: SubmissionSource::CacheMiss,
        roots: (64..64 + SNAPSHOT_MERGE_NODES).collect(),
        nodes,
    }
}

/// The delta slice report the snapshot batch carries, or, with `undo`,
/// its inverse, which the cleanup applies.
async fn snapshot_slice_report(
    db: &DurableDb,
    ctx: &DriveContext,
    shape: FixtureShape,
    undo: bool,
) -> Result<(), String> {
    let (added, retired) = fixture::delta_slice_report(shape);
    let (added, retired) = if undo {
        (retired, added)
    } else {
        (added, retired)
    };
    routes::slice_reports(
        ctx.loaded(),
        db,
        &[PublishedSlice {
            target: TargetTriple::parse(CI_TARGET_TRIPLES[0]).map_err(text)?,
            rustc_version: WireRustcVersion::parse("1.85.0").map_err(text)?,
            base_generation: None,
            generation: None,
            added,
            retired,
        }],
        Some(DRIVE_ACTOR),
        now_ms(),
    )
    .await
    .map(drop)
    .map_err(text)
}

/// The merge drive's tree: [`MERGE_NODES`] fresh nodes, each on one of
/// the 64 published pool leaves, so every edge answers against the
/// published masks as it merges.
fn merge_tree(shape: FixtureShape) -> SubmissionTree {
    let target = stow_types::fixture::target_of(101);
    let pool = shape.pending_end() + 3;
    let mut nodes: Vec<_> = (0..64)
        .map(|leaf| fixture::fixture_node(pool + leaf, Vec::new()))
        .collect();
    nodes.extend((0..MERGE_NODES).map(|k| {
        fixture::named_node(
            &format!("costgate-merge-{k:04}"),
            DRIVE_SEED + TAG_MERGE * 1_000_000 + u64::from(k),
            target,
            vec![k % 64],
        )
    }));
    SubmissionTree {
        source: SubmissionSource::CacheMiss,
        roots: (64..64 + MERGE_NODES).collect(),
        nodes,
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod lifecycle_tests {
    use super::*;

    /// Resource: a drive that records which hooks ran, to hold the
    /// lifecycle's ordering contract.
    fn noop<'a>(
        _db: &'a DurableDb,
        _shape: FixtureShape,
        _settings: &'a SchedulerSettings,
        _ctx: &'a DriveContext,
    ) -> DriveFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn failing<'a>(
        _db: &'a DurableDb,
        _shape: FixtureShape,
        _settings: &'a SchedulerSettings,
        _ctx: &'a DriveContext,
    ) -> DriveFuture<'a> {
        Box::pin(async { Err("injected".to_owned()) })
    }

    /// A failed setup aborts the lifecycle: no barrier, no run, no
    /// cleanup.
    #[tokio::test]
    async fn a_failed_setup_aborts_the_lifecycle() {
        let db = super::super::test_db::memory_db().await.expect("memory db");
        let drive = Drive {
            name: "failing setup",
            setup: Some(failing),
            run: noop,
            cleanup: Some(noop),
        };
        let ctx = DriveContext::host(GraphCell::default());
        let settings = SchedulerSettings::default();
        let outcome = drive_lifecycle(
            &drive,
            &db,
            &db,
            fixture::GATE,
            &settings,
            &ctx,
            &mut |_| {},
        )
        .await;
        assert!(outcome.setup.is_err());
        assert!(outcome.pre_sync.is_none() && outcome.run.is_none() && outcome.cleanup.is_none());
    }

    /// A failed run still post-syncs and cleans up, and the error stays
    /// in the run's own slot.
    #[tokio::test]
    async fn a_failed_run_still_syncs_and_cleans_up() {
        let db = super::super::test_db::memory_db().await.expect("memory db");
        let drive = Drive {
            name: "failing run",
            setup: None,
            run: failing,
            cleanup: Some(noop),
        };
        let ctx = DriveContext::host(GraphCell::default());
        let settings = SchedulerSettings::default();
        let outcome = drive_lifecycle(
            &drive,
            &db,
            &db,
            fixture::GATE,
            &settings,
            &ctx,
            &mut |_| {},
        )
        .await;
        assert!(matches!(outcome.run, Some(Err(_))));
        assert!(matches!(outcome.post_sync, Some(Ok(()))));
        assert!(matches!(outcome.cleanup, Some(Ok(()))));
    }

    /// The predicted-bill predicate: the append and the checkpoint
    /// UPDATE hold their constants, and anything else passes
    /// unpriced.
    #[test]
    fn predicted_bill_mismatch_covers_the_priced_statements() {
        const APPEND: &str = "INSERT INTO event_log(at, event) VALUES (?, ?) RETURNING seq";
        const CHECKPOINT: &str = "UPDATE meter SET day = ? RETURNING id";
        assert_eq!(predicted_bill_mismatch(APPEND, 1, 1), None);
        assert_eq!(
            predicted_bill_mismatch(APPEND, 2, 1),
            Some(("event_log append", 1, 1))
        );
        assert_eq!(predicted_bill_mismatch(CHECKPOINT, 2, 1), None);
        assert_eq!(
            predicted_bill_mismatch(CHECKPOINT, 1, 1),
            Some(("meter checkpoint UPDATE", 2, 1))
        );
        assert_eq!(
            predicted_bill_mismatch("SELECT seq FROM event_log", 0, 0),
            None
        );
        assert_eq!(
            predicted_bill_mismatch("SELECT seq FROM event_log", 9, 9),
            None
        );
    }
}
