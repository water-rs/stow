use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::num::{NonZero, NonZeroU32};

use skyzen_services::durable::{Alarm, DbValue, DurableDb};
use stow_types::api::{
    AdminInFlight, AdminStatus, AdminTargetStats, BatchId, BuildTaskPayload, ClaimedLeg,
    DEFAULT_BATCH_MAX_TASKS, DEFAULT_BATCH_PARALLELISM, EnqueueRequest, EnqueueSource, LegRefusal,
    ManualBatchDispatch, ManualBatchRegistered, ManualBatchRegistration, ManualDispatchOutcome,
    ManualDispatchRecorded, ManualShare, PublishedSliceRow, QueueSelector, QueueTask,
    QueueTaskStatus, RefusedLeg, RequestStatus, RunnerFamily, SchedulerResetReport,
    SchedulerStatus, TaskHash, TaskLane, runner_family,
};
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};
use stow_types::runs::{LegFailure, LegOutcome, RunFailure, RunJobRow};

use crate::errors::{ManualRegistrationRefused, QueueError};
use crate::scheduler::batching::{
    BatchCandidate, BatchKey, FormedBatch, PlannedBatch, SlotAdmission, SlotPlan, form_batches,
};

/// The semantic identity of a crates.io task, as the artifact catalog
/// keys it: the identity a published closure member registers under.
/// `host_side` is part of the identity — the same crate mints both a
/// target-side node and a host-side node at the host triple, and each
/// side is covered only when the catalog serves that side's unit shapes.
/// `dependency_identity` is too (stow#787): two nodes sharing the tuple
/// but resolving different dependency closures are different nodes, and
/// a publication under another context serves neither the dependent's
/// digest-keyed edges nor a pending row waiting to build this one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemanticTaskIdentity {
    pub crate_name: String,
    pub version: String,
    pub features_json: String,
    pub target: String,
    pub rustc_version: String,
    pub host_side: bool,
    /// The Merkle digest the node's task id commits to — coverage is
    /// exact contextual identity, never the bare tuple.
    pub dependency_identity: String,
    /// The node's explicit-spelling flag (stow#736): semantic data,
    /// not identity — two catalog memberships of one node differ only
    /// in the shape set they require, never in the node's task id.
    pub explicit_spelling: stow_types::public_cache::ExplicitSpelling,
}

/// Answers, for a batch of pending crates.io tasks, which of them the
/// artifact catalog already covers — an artifact that published while
/// the row waited retires it at claim time instead of rebuilding what
/// is already served. Production asks D1; tests answer from a fixed set.
pub trait CoverageOracle: Sync {
    fn covered(
        &self,
        identities: &[SemanticTaskIdentity],
    ) -> impl Future<Output = Result<BTreeSet<SemanticTaskIdentity>, QueueError>> + Send;
}

/// One claimed queue row: the identity a batch leg is fenced and
/// backed off by.
#[derive(Debug, Clone, serde::Serialize)]
pub struct QueuedTask {
    pub task_id: String,
    /// Unique claim identity minted at dispatch claim time. It changes on
    /// every new claim, including after purge and recreation.
    pub generation_id: String,
}

/// One admitted queue row before its claim: a [`QueuedTask`] without
/// the `generation_id` the claim mints. Formation works on these, so a
/// row nothing claimed never carries an identity it does not own.
#[derive(Debug, Clone)]
pub struct PendingLeg {
    pub task_id: String,
    pub attempt: u32,
    pub crate_name: String,
    pub version: String,
    pub features_json: String,
    pub target: String,
    pub rustc_version: String,
    pub host_side: bool,
    pub explicit_spelling: stow_types::public_cache::ExplicitSpelling,
    pub preserve_lockfile: bool,
    pub dependency_subgraph: stow_types::api::TaskSubgraph,
}

impl PendingLeg {
    /// The claimed row, under the `generation_id` its claim minted.
    #[must_use]
    pub fn claimed(self, generation_id: String) -> QueuedTask {
        QueuedTask {
            task_id: self.task_id,
            generation_id,
        }
    }
}

/// Decode a stored `explicit_spelling` integer — the queue and
/// node-store columns carry 0 for `KeysAsNative`, 1 for `KeysApart`
/// (stow#736).
pub const fn spelling_of(stored: i64) -> stow_types::public_cache::ExplicitSpelling {
    if stored != 0 {
        stow_types::public_cache::ExplicitSpelling::KeysApart
    } else {
        stow_types::public_cache::ExplicitSpelling::KeysAsNative
    }
}

// Dispatch ceilings, sized against the org's 60 GitHub-hosted runners (20
// of them macOS): 45 total leaves 15 runners for the repo's own CI, and
// the macOS cap keeps a full wave from queueing on the smallest pool
// while leaving 4 macOS runners free.
const DEFAULT_MAX_CONCURRENT_JOBS: NonZeroU32 = NonZeroU32::new(45).unwrap();
const DEFAULT_MAX_CONCURRENT_MACOS_JOBS: u32 = 16;
/// Default for `STOW_HUMAN_RESERVED_JOBS` — the pool slots a
/// coordinated `preheat manual` wave always leaves free for the human
/// request lane (stow#854 §4.4). One slot per runner family is the
/// smallest reserve a human request's all-family frontier can start
/// under, however large the wave.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the runner-family count fits u32"
)]
const DEFAULT_HUMAN_RESERVED_JOBS: u32 = RunnerFamily::ALL.len() as u32;
/// Default for `STOW_HUMAN_RESERVED_MACOS_JOBS` — the same reserve
/// inside the macOS cap, which binds separately from the pool.
const DEFAULT_HUMAN_RESERVED_MACOS_JOBS: u32 = 1;
const DEFAULT_DISPATCH_MIN_AGE_MINUTES: u32 = 5;
// A single crate build on GitHub-hosted runners (toolchain install + compile
// + sign + push) can legitimately take tens of minutes and nothing updates
// the row while CI runs, so the stale-recovery cutoff must comfortably
// exceed the slowest expected build or long builds get double-dispatched.
const DEFAULT_STALE_DISPATCH_MINUTES: u32 = 60;
// Batch shape (stow#833 §1.3): `k` — the `max-parallel` runner slots
// one `build-batch.yml` matrix holds — and `B` — its leg bound, eight
// rounds at the default. `B` stays far under GitHub's 256-job matrix
// limit and its tasks pack under the workflow_dispatch input cap. The
// defaults live in `stow_types::api` so `preheat manual` reads the
// same values the bindings fall back to.
// Exponential dispatch-failure backoff cap.
const MAX_DISPATCH_BACKOFF_MINUTES: u32 = 60;

/// Failed-build retry cap: a failure reported while `attempt` is under
/// this re-queues the row under `not_before` backoff; a failure at the cap
/// parks it `failed` for an operator `retry`, which resets the cycle to 1.
const MAX_BUILD_ATTEMPTS: u32 = 4;

/// The bounded window of successful-build durations each
/// `(crate_name, target)` keeps in `crate_build_samples` — newest by
/// insertion. One completion's median recompute reads at most this
/// many rows and the cap delete keeps no more, so the statistic
/// never grows a historical scan (stow#524).
pub(super) const BUILD_SAMPLE_WINDOW: i64 = 32;

/// Default for `STOW_MAX_QUEUE_PENDING` — pending-queue depth at which
/// miss-lane submits start being refused. The edge handler reads the same
/// binding for its pre-forward check, so this constant is the shared
/// default for both.
pub const DEFAULT_MAX_QUEUE_PENDING: u32 = 2_000;
/// Default for `STOW_HUMAN_DAILY_TASK_BUDGET` — human-lane tasks the
/// scheduler accepts per UTC day.
pub const DEFAULT_HUMAN_DAILY_TASK_BUDGET: u32 = 2_000;

/// Whether the scheduler dispatches at all, and the in-flight bound when
/// it does.
///
/// `Paused` is a real operating state — the deployment doc's deliberate
/// pause via `STOW_MAX_CONCURRENT_JOBS = "0"` — not a zero-sized limit:
/// submits keep queueing and nothing is claimed until a redeploy restores
/// a non-zero value. Carrying it in the type keeps "no dispatch" from
/// ever being expressed as a number, where a `0` reads as a cap the queue
/// arithmetic must somehow honor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatch {
    /// Submits keep queueing; nothing is claimed. The alarm still wakes
    /// at the earliest in-flight lease expiry so stale recovery runs.
    Paused,
    /// At most this many tasks in flight (`dispatched`/`running`) across
    /// all runner families.
    Limited(NonZeroU32),
}

impl Dispatch {
    /// The `STOW_MAX_CONCURRENT_JOBS` value: `0` pauses dispatch, any
    /// other value bounds the in-flight set.
    #[must_use]
    pub const fn from_max_concurrent_jobs(raw: u32) -> Self {
        match NonZeroU32::new(raw) {
            Some(limit) => Self::Limited(limit),
            None => Self::Paused,
        }
    }
}

/// The runner slots a coordinated `preheat manual` wave always leaves
/// free for the human request lane (stow#854 §4.4). The register
/// route's grant keeps total occupancy at or below each cap minus its
/// reserve, so a human request's frontier can start on every family
/// however large the wave. The scheduler's own lane claims are not
/// bound by it — the reserve constrains the wave only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanReserve {
    /// Slots held back inside `STOW_MAX_CONCURRENT_JOBS`.
    pub shared: u32,
    /// Slots held back inside `STOW_MAX_CONCURRENT_MACOS_JOBS`.
    pub macos: u32,
}

impl HumanReserve {
    /// The production defaults — `STOW_HUMAN_RESERVED_JOBS` /
    /// `STOW_HUMAN_RESERVED_MACOS_JOBS` unset.
    pub const DEFAULT: Self = Self {
        shared: DEFAULT_HUMAN_RESERVED_JOBS,
        macos: DEFAULT_HUMAN_RESERVED_MACOS_JOBS,
    };
}

impl Default for HumanReserve {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Runtime-tunable scheduler knobs, read from Worker env bindings by the
/// Durable Object glue (`STOW_MAX_CONCURRENT_JOBS`,
/// `STOW_MAX_CONCURRENT_MACOS_JOBS`, `STOW_DISPATCH_MIN_AGE_MINUTES`,
/// `STOW_STALE_DISPATCH_MINUTES`, `STOW_MAX_QUEUE_PENDING`,
/// `STOW_HUMAN_DAILY_TASK_BUDGET`, `STOW_MIN_DISPATCH_VALUE`,
/// `STOW_BATCH_PARALLELISM`, `STOW_BATCH_MAX_TASKS`,
/// `STOW_HUMAN_RESERVED_JOBS`, `STOW_HUMAN_RESERVED_MACOS_JOBS`).
///
/// Defaults match production; the local mock lowers `dispatch` via `vars`
/// because miniflare's workerd OOMs under parallel complete
/// bursts.
#[derive(Debug, Clone, Copy)]
pub struct SchedulerSettings {
    /// The dispatch posture — see [`Dispatch`].
    pub dispatch: Dispatch,
    /// Cap on in-flight tasks whose target maps to the macOS runner
    /// family — the smallest pool in the org's fleet.
    pub max_concurrent_macos_jobs: u32,
    pub dispatch_min_age_minutes: u32,
    pub stale_dispatch_minutes: u32,
    /// Pending-queue depth at which [`enqueue`] refuses miss-lane
    /// submits. Human-lane tasks and [`enqueue_trusted`] callers are
    /// exempt.
    pub max_queue_pending: u32,
    /// Human-lane tasks accepted per UTC day, counted in the
    /// `human_daily_task_budget` table.
    pub human_daily_task_budget: u32,
    /// Admission floor on `queue.value` (stow#525 I10): a pending
    /// miss-lane row claims only while its score reaches this bound —
    /// under-floor work stays queued and visible rather than being
    /// built. `0` admits everything. The human lane is exempt: a
    /// request someone asked for by name is never held by the floor.
    /// Parsed from `STOW_MIN_DISPATCH_VALUE` as a nonnegative i64 —
    /// the *operator input* the reset route stamps into `settings` and
    /// derives `dispatch_eligible` from. A changed binding takes
    /// effect only through that pass: the queue's writers and probes
    /// read the persisted answer, never this field.
    pub min_dispatch_value: i64,
    /// `k` — the `max-parallel` runner slots one `build-batch.yml`
    /// matrix holds (stow#833 §1.3); the sum over in-flight batches is
    /// what the family caps bound.
    pub batch_parallelism: u32,
    /// `B` — the leg bound at which a batch closes (stow#833 §1.3).
    pub batch_max_tasks: u32,
    /// The human-lane reserve a manual wave's registrations must leave
    /// free (`STOW_HUMAN_RESERVED_JOBS`,
    /// `STOW_HUMAN_RESERVED_MACOS_JOBS`; stow#854 §4.4). Only the
    /// manual-batch register route reads it.
    pub human_reserve: HumanReserve,
}

impl Default for SchedulerSettings {
    fn default() -> Self {
        Self {
            dispatch: Dispatch::Limited(DEFAULT_MAX_CONCURRENT_JOBS),
            max_concurrent_macos_jobs: DEFAULT_MAX_CONCURRENT_MACOS_JOBS,
            dispatch_min_age_minutes: DEFAULT_DISPATCH_MIN_AGE_MINUTES,
            stale_dispatch_minutes: DEFAULT_STALE_DISPATCH_MINUTES,
            max_queue_pending: DEFAULT_MAX_QUEUE_PENDING,
            human_daily_task_budget: DEFAULT_HUMAN_DAILY_TASK_BUDGET,
            min_dispatch_value: DEFAULT_MIN_DISPATCH_VALUE,
            batch_parallelism: DEFAULT_BATCH_PARALLELISM,
            batch_max_tasks: DEFAULT_BATCH_MAX_TASKS,
            human_reserve: HumanReserve::DEFAULT,
        }
    }
}

/// Priority is the third precedence operand of `queue.value` — dispatch
/// orders on value before the FIFO tie-breakers.
fn compute_priority(downloads: u64, miss_count: u32) -> Result<i64, QueueError> {
    let downloads_bucket = downloads / 1000;
    let downloads_bucket = i64::try_from(downloads_bucket)
        .map_err(|_| format!("downloads bucket exceeds i64: {downloads_bucket}"))?;
    Ok(downloads_bucket + i64::from(miss_count) * 10)
}

/// The largest priority [`compute_priority`] can return, derived from
/// its operand types — `u64::MAX / 1000 + 10 × u32::MAX` — not a
/// guessed cap: a precedence band this wide can never alias a priority
/// across a band boundary.
const PRIORITY_MAX: i64 = (u64::MAX / 1000 + 10 * u32::MAX as u64).cast_signed();

/// Width of one precedence band in `queue.value`. The persisted value
/// is `bands × VALUE_BAND + MAX(0, priority) + MAX(0, demand)`, with
/// the human lane contributing two bands and the Windows family one —
/// today's "human first, then Windows, then priority" claim order
/// encoded additively in one descending number (stow#442 I6), with
/// accumulated demand folding into the same priority band (stow#522).
/// The largest value a row can take is `3 × VALUE_BAND + PRIORITY_MAX
/// = 4 × PRIORITY_MAX + 3 = 73,787,148,093,530,007`, below
/// `i64::MAX`, so no operand can overflow the column.
pub(super) const VALUE_BAND: i64 = PRIORITY_MAX + 1;

/// The queue-identity columns of one enqueue request.
struct TaskIdentity {
    crate_name: String,
    version: String,
    features_json: String,
    target: String,
    rustc_version: String,
    host_side: bool,
}

impl TaskIdentity {
    fn from_request(request: &EnqueueRequest) -> Self {
        // FeaturesJson is already validated + canonicalized at deserialize
        // time; raw() emits the same JSON-encoded string the column expects.
        Self {
            crate_name: request.crate_name.as_str().to_owned(),
            version: request.version.to_string(),
            features_json: request.features_json.raw(),
            target: request.target.as_str().to_owned(),
            rustc_version: request.rustc_version.as_str().to_owned(),
            host_side: request.host_side,
        }
    }
}

/// The lane a request lands in. A human re-request of an existing task
/// promotes it; a miss-path re-request of a human task must never demote
/// it, so the UPDATE only ever moves a row toward 'human'.
const fn request_lane(source: EnqueueSource) -> TaskLane {
    match source {
        EnqueueSource::HumanRequest => TaskLane::Human,
        EnqueueSource::CrateUpdate | EnqueueSource::RustcUpdate | EnqueueSource::CacheMiss => {
            TaskLane::Miss
        }
    }
}

/// Whether a re-request puts a terminal row back in the queue.
///
/// A completed row revives only through the human lane, where someone
/// asked for this exact crate again — the unattended preheat lanes
/// re-submit the whole top-N list on every wave, so resurrecting
/// completions there would rebuild the entire pool on a timer.
/// `failed` never revives: a failed build re-queues itself inside
/// `complete` under `not_before` backoff until the attempt cap lands
/// it on `failed`, which only the operator's `retry` clears.
const fn resurrects(status: &str, lane: TaskLane) -> bool {
    matches!(status.as_bytes(), b"completed") && matches!(lane, TaskLane::Human)
}

/// Entries per `json_each`-fed statement in the batched enqueue. One bound
/// parameter carries the whole array; the Durable Object SQL API caps
/// bound parameters at 100 but a bound *string* at 2MB, so a JSON array
/// sidesteps the parameter ceiling entirely. 2000 identities (~300B
/// each) or edges (~200B each) stay well under the string limit.
pub const ENQUEUE_JSON_BATCH_ROWS: usize = 2000;

/// Retired slice rows delete in `rowid IN (…)` batches. workerd caps a
/// statement at ~100 bound variables, so the batch stays under it by
/// half; a full-slice retire then costs ~45 statements.
const SLICE_ROWID_DELETE_BATCH: usize = 90;

/// One re-request folded per task for the bulk `UPDATE queue` — emitted
/// only when the request changes stored state (`plan_enqueue` decides):
/// `downloads` the highest the chunk reported, `redispatch` the
/// at-most-one resurrection a row can take in one batch (once `pending`
/// it cannot resurrect again in the same pass), and `human` whether any
/// occurrence promoted the lane.
#[derive(serde::Serialize)]
struct BatchedUpdate {
    task_id: String,
    downloads: i64,
    redispatch: u8,
    human: u8,
    /// Any occurrence's explicit-spelling flag (stow#736): the flag
    /// upgrades a row the request proves `KeysApart` — the UPDATE
    /// writes the max while the row is uncommitted or redispatching.
    explicit: u8,
}

/// A first-occurrence row for the bulk `INSERT INTO queue`.
#[derive(serde::Serialize)]
struct BatchedInsert {
    task_id: String,
    crate_name: String,
    version: String,
    features_json: String,
    target: String,
    rustc_version: String,
    host_side: u8,
    explicit_spelling: u8,
    dependency_identity: String,
    downloads: i64,
    priority: i64,
    preserve_lockfile: u8,
    lane: &'static str,
}

/// One node-store row for the bulk `INSERT OR IGNORE INTO task_nodes`:
/// the node's canonical identity plus its dependency digest and the
/// JSON-encoded list of its direct-dependency task ids (stow#588).
#[derive(Clone, serde::Serialize)]
struct BatchedNodeRow {
    task_id: String,
    crate_name: String,
    version: String,
    features_json: String,
    target: String,
    rustc_version: String,
    host_side: u8,
    explicit_spelling: u8,
    dependency_identity: String,
    children_json: String,
}

/// One stored edge's readiness as probed for an insert chunk: whether
/// the dep's required publication is missing (`unpub`) and whether that
/// edge also blocks (`blocker` — the dep failed).
#[derive(Debug, skyzen::FromRow)]
struct EdgeFlag {
    owner: String,
    unpub: i64,
    blocker: i64,
}

/// The serialized form the `INSERT INTO queue` payload takes: the
/// first-occurrence identity plus the readiness flags the per-edge
/// probe and Rust fold already answered, so the statement never
/// re-evaluates them — and the rank fields the shared abstraction
/// derived (`value` as decimal text, the `dispatch_key`, and the two
/// timestamps the key embeds so column and key agree byte-for-byte).
#[derive(serde::Serialize)]
struct InsertRow<'a> {
    #[serde(flatten)]
    insert: &'a BatchedInsert,
    unpublished_deps: u64,
    deps_met: u8,
    blocked: u8,
    first_requested_at: String,
    created_at: String,
    value: String,
    dispatch_key: String,
}

/// The chunk's serialized first-occurrence rows — readiness flags from
/// the edge probe, rank fields from the shared abstraction on the
/// event-local cost lookup (absent stats explicitly
/// `UNMEASURED_COST`).
fn insert_rows<'a>(
    chunk: &'a [BatchedInsert],
    readiness: &std::collections::HashMap<&str, (u64, u64)>,
    costs: &std::collections::HashMap<(&str, &str), NonZero<i64>>,
    now: &str,
) -> Vec<InsertRow<'a>> {
    chunk
        .iter()
        .map(|insert| {
            let (unmet, blocked) = readiness
                .get(insert.task_id.as_str())
                .copied()
                .unwrap_or_default();
            InsertRow {
                insert,
                unpublished_deps: unmet,
                deps_met: u8::from(unmet == 0),
                blocked: u8::from(blocked > 0),
                first_requested_at: now.to_owned(),
                created_at: now.to_owned(),
                value: crate::scheduler::rank::raw_value(
                    insert.lane,
                    crate::scheduler::rank::dispatch_family(&insert.target),
                    insert.priority,
                    // A fresh row has no accumulated demand yet — a
                    // demand closure only ever touches existing rows.
                    0,
                )
                .to_string(),
                dispatch_key: crate::scheduler::rank::dispatch_key(
                    &crate::scheduler::rank::KeyOperands {
                        lane: insert.lane,
                        family: crate::scheduler::rank::dispatch_family(&insert.target),
                        priority: insert.priority,
                        demand: 0,
                        cost_ms: costs
                            .get(&(insert.crate_name.as_str(), insert.target.as_str()))
                            .copied()
                            .unwrap_or(crate::scheduler::rank::UNMEASURED_COST),
                        first_requested_at: now,
                        created_at: now,
                        task_id: &insert.task_id,
                    },
                ),
            }
        })
        .collect()
}

/// A `(crate_name, target)` median as the insert-path cost probe
/// returns it — `median_ms` NULL for a genuinely unmeasured pair,
/// TEXT otherwise (the JSON number crossing truncates past `2^53`).
#[derive(Debug, skyzen::FromRow)]
struct BuildCostRow {
    crate_name: String,
    target: String,
    median_ms: Option<String>,
    now: String,
}

/// One `(crate_name, target)` pair's expected-cost row for the
/// batch's distinct inputs — the probe starts from the event's own
/// keys and LEFT JOINs `crate_build_stats` by its primary key, so an
/// enqueue reads in proportion to the batch's distinct pairs, never
/// to stored build history.
const INSERT_COST_PROBE: &str = "SELECT k.crate_name, k.target, CAST(s.median_ms AS TEXT) AS median_ms, \
            (SELECT datetime('now')) AS now \
     FROM (SELECT DISTINCT value ->> 'crate_name' AS crate_name, \
                  value ->> 'target' AS target FROM json_each(?)) AS k \
     LEFT JOIN crate_build_stats s \
       ON s.crate_name = k.crate_name AND s.target = k.target";

async fn probe_insert_costs(
    db: &DurableDb,
    inserts: &[BatchedInsert],
) -> Result<Vec<BuildCostRow>, QueueError> {
    Ok(db
        .query(INSERT_COST_PROBE)
        .bind(enqueue_json(inserts)?)
        .fetch_all::<BuildCostRow>()
        .await
        .map_err(|error| format!("probe insert build costs: {error}"))?)
}

/// One dependency edge, fully resolved for the bulk insert: the dep's
/// task id and the gate's invocation-mask / shape-count pair are
/// computed in Rust so the statement only has to write them.
#[derive(serde::Serialize)]
struct BatchedDepEdge {
    task_id: String,
    depends_on_task_id: String,
    dep_crate_name: String,
    dep_version: String,
    dep_features_json: String,
    dep_target: String,
    dep_rustc_version: String,
    dep_host_side: u8,
    dep_dependency_identity: String,
    dep_invocations: i64,
    dep_shapes: i64,
}

/// Serialize one statement's JSON-array payload.
pub(super) fn enqueue_json<T: serde::Serialize>(rows: &[T]) -> Result<String, QueueError> {
    serde_json::to_string(rows)
        .map_err(|error| QueueError::Sql(format!("encode enqueue batch json: {error}")))
}

/// The prospective `priority + demand` bound for every row an update
/// batch is about to recompute — checked before the write phase so a
/// refused resubmit leaves the queue, edges and demand state untouched
/// (stow#522). Written as `new_priority > bound - demand`, every
/// operand stays inside i64 (demand is already bounded by the same
/// rule), so the compare can never promote to REAL — and on overflow
/// the batch errors with the offenders named rather than clamping or
/// erasing demand.
async fn check_update_band_bound(
    db: &DurableDb,
    updates: &[BatchedUpdate],
) -> Result<(), QueueError> {
    let mut offending: Vec<String> = Vec::new();
    for chunk in updates.chunks(ENQUEUE_JSON_BATCH_ROWS) {
        offending.extend(
            db.query(&format!(
                "SELECT q.task_id FROM queue q \
                 JOIN (SELECT value AS e FROM json_each(?)) j \
                      ON q.task_id = j.e ->> 'task_id' \
                 WHERE MAX(0, (MAX(q.downloads, CAST(j.e ->> 'downloads' AS INTEGER)) / 1000) \
                       + q.miss_count * 10) > {PRIORITY_MAX} - q.demand"
            ))
            .bind(enqueue_json(chunk)?)
            .fetch_scalars::<String>()
            .await
            .map_err(|error| format!("update band-bound check: {error}"))?,
        );
    }
    if !offending.is_empty() {
        return Err(QueueError::Invariant(format!(
            "resubmit would overflow the priority band on {} task(s): {}",
            offending.len(),
            offending.join(", ")
        )));
    }
    Ok(())
}

/// `UPDATE queue` for every re-requested row in the chunk, one statement
/// per slice. The batch only holds rows the request actually moves
/// (`plan_enqueue` filters pure re-requests out — stow#784), so every
/// write here is a real state change: downloads keep the max, priority
/// recomputes from downloads and
/// `miss_count` (`first_requested_at` untouched — the FIFO operand stays
/// put, though a higher recomputed priority can still move the row up in
/// `value` order), resurrection bumps the retry-cycle `attempt`, and the
/// lane only ever
/// moves toward 'human'.
async fn apply_batched_updates(
    db: &DurableDb,
    settings: &SchedulerSettings,
    updates: &[BatchedUpdate],
) -> Result<(), QueueError> {
    // `wake_at` recomputes on a redispatch or a lane move to `human` —
    // both change the wake expression's operands. The CASE'd `lane` the
    // same statement assigns must re-appear inside it: SET terms see
    // the old row.
    let next_lane = "CASE WHEN e ->> 'human' = 1 THEN 'human' ELSE lane END";
    for chunk in updates.chunks(ENQUEUE_JSON_BATCH_ROWS) {
        db.query(&format!(
            "UPDATE queue \
             SET downloads = MAX(downloads, e ->> 'downloads'), \
                 priority = (MAX(downloads, e ->> 'downloads') / 1000) + miss_count * 10, \
                 status = CASE WHEN e ->> 'redispatch' = 1 THEN 'pending' ELSE status END, \
                 attempt = attempt + (e ->> 'redispatch'), \
                 error_msg = CASE WHEN e ->> 'redispatch' = 1 THEN '' ELSE error_msg END, \
                 deps_met = CASE WHEN e ->> 'redispatch' = 1 \
                     THEN {deps_met} ELSE deps_met END, \
                 blocked = CASE WHEN e ->> 'redispatch' = 1 \
                     THEN {blocked} ELSE blocked END, \
                 wake_at = CASE WHEN (e ->> 'redispatch' = 1 OR e ->> 'human' = 1) \
                     THEN {wake} ELSE wake_at END, \
                 updated_at = datetime('now'), \
                 lane = {next_lane}, \
                 dispatch_eligible = {eligible}, \
                 explicit_spelling = CASE \
                     WHEN status NOT IN ('dispatched', 'running') OR e ->> 'redispatch' = 1 \
                     THEN MAX(explicit_spelling, e ->> 'explicit') \
                     ELSE explicit_spelling END \
             FROM (SELECT value AS e FROM json_each(?)) AS j \
             WHERE queue.task_id = j.e ->> 'task_id'",
            deps_met = deps_met_sql("queue.task_id"),
            blocked = blocked_sql("queue.task_id"),
            wake = wake_at_sql(
                next_lane,
                "first_requested_at",
                "not_before",
                settings.dispatch_min_age_minutes,
            ),
            // The lane can only move toward 'human' here, and a human
            // lane is unconditionally floor-eligible; the CASE still
            // evaluates the stored value so a miss row keeps its
            // current answer byte-for-byte.
            eligible = dispatch_eligible_sql(next_lane, "value"),
        ))
        .bind(enqueue_json(chunk)?)
        .execute()
        .await
        .map_err(|error| format!("update existing tasks: {error}"))?;
    }
    // Redispatched rows may be dependencies leaving `failed` — their
    // pending dependents' `blocked` answer can only change at a dep's
    // status flip, so refresh them now. The refresh is proportional to
    // the batch's dependents, not the queue, and a batch holding no
    // redispatch skips it so a pure insert chunk stays a constant
    // statement count.
    if updates.iter().any(|update| update.redispatch != 0) {
        refresh_dependents(
            db,
            "SELECT value ->> 'task_id' AS task_id FROM json_each(?) \
             WHERE value ->> 'redispatch' = 1",
            &[DbValue::Text(enqueue_json(updates)?)],
        )
        .await?;
    }
    // Priority or lane may have moved: recompute the persisted
    // claim-order key on the touched rows (unchanged keys write nothing).
    refresh_dispatch_keys(
        db,
        &updates
            .iter()
            .map(|update| update.task_id.clone())
            .collect::<Vec<_>>(),
    )
    .await
}

/// Rows the last completed statement changed — SQLite's `changes()`
/// counts the statement's own record writes only: index maintenance
/// and trigger effects are excluded by definition, so unlike the
/// backend's billed `rows_written` it names real row deltas (an
/// `ON CONFLICT DO NOTHING` insert reports just the rows that
/// landed). Read it as the statement immediately after the write —
/// the synchronous backend runs them back to back, so nothing
/// interleaves and the count belongs to the write.
pub async fn changes(db: &DurableDb) -> Result<u64, QueueError> {
    db.query("SELECT changes()")
        .fetch_scalar::<u64>()
        .await
        .map_err(|error| QueueError::Sql(format!("read changes(): {error}")))
}

/// `INSERT INTO queue` for the batch's first occurrences, one statement
/// per slice; `ON CONFLICT DO NOTHING` is a belt under the Rust-side
/// existence fold — a task another submit landed between the probe and
/// the write stays untouched, and `RETURNING` hands back exactly the
/// rows the batch inserted — the logical record count the billed
/// `rows_written` cannot give (it includes the identity index's
/// writes).
async fn apply_batched_inserts(
    db: &DurableDb,
    settings: &SchedulerSettings,
    inserts: &[BatchedInsert],
) -> Result<u64, QueueError> {
    // Each owner's stored edge flags are folded once in Rust, then the
    // direct INSERT reads the resulting counter and booleans from its
    // payload. `dep_met` was initialized by dependency insertion, so
    // this probe only reads the persisted flag; it never repeats the
    // signed-slice membership query. An owner with no edge row yields no
    // flag row: zero unmet proves unblocked — the row is born
    // (unpublished_deps=0, deps_met=1, blocked=0).
    let unpub = "d.dep_met = 0";
    // Load the batch's build costs once — every first occurrence keys
    // on the exact `value / median_ms` rank, the unmeasured answer
    // `UNMEASURED_COST` — and stamp the batch's claim-order
    // timestamps once so a row's key and columns carry the same
    // instant. A present stat must decode positive; corruption fails
    // the batch rather than silently repricing to 1.
    // A pure resubmit batch carries no inserts — skip the cost probe
    // entirely rather than running an empty `json_each` (stow#784).
    if inserts.is_empty() {
        return Ok(0);
    }
    let stats = probe_insert_costs(db, inserts).await?;
    // The probe rides its `now` column on the same statement — one
    // probe per batch, so the batch's key/column timestamps agree.
    let Some(now) = stats.first().map(|row| row.now.clone()) else {
        return Ok(0);
    };
    let mut costs: std::collections::HashMap<(&str, &str), NonZero<i64>> =
        std::collections::HashMap::new();
    for row in &stats {
        if let Some(median) = row.median_ms.as_deref() {
            costs.insert(
                (row.crate_name.as_str(), row.target.as_str()),
                crate::scheduler::rank::checked_cost(median)?,
            );
        }
    }
    let mut inserted = 0u64;
    for chunk in inserts.chunks(ENQUEUE_JSON_BATCH_ROWS) {
        let owners: Vec<&str> = chunk.iter().map(|insert| insert.task_id.as_str()).collect();
        let flags = db
            .query(&format!(
                "SELECT d.task_id AS owner, \
                        CASE WHEN {unpub} THEN 1 ELSE 0 END AS unpub, \
                        CASE WHEN bdep.status = 'failed' \
                             THEN 1 ELSE 0 END AS blocker \
                 FROM queue_dependencies d \
                 LEFT JOIN queue bdep ON bdep.task_id = d.depends_on_task_id \
                 WHERE d.task_id IN (SELECT value FROM json_each(?))",
            ))
            .bind(enqueue_json(&owners)?)
            .fetch_all::<EdgeFlag>()
            .await
            .map_err(|error| format!("probe insert edge readiness: {error}"))?;
        let mut readiness: std::collections::HashMap<&str, (u64, u64)> =
            std::collections::HashMap::new();
        for flag in &flags {
            let (unmet, blocked) = readiness.entry(flag.owner.as_str()).or_default();
            *unmet += u64::try_from(flag.unpub).unwrap_or(0);
            *blocked += u64::try_from(flag.unpub * flag.blocker).unwrap_or(0);
        }
        let rows = insert_rows(chunk, &readiness, &costs, &now);
        let inserted_rows = db
            .query(&format!(
                "INSERT INTO queue \
                 (task_id, crate_name, version, features_json, target, rustc_version, host_side, explicit_spelling, dependency_identity, downloads, miss_count, priority, status, preserve_lockfile, lane, attempt, generation_id, first_requested_at, created_at, unpublished_deps, deps_met, blocked, wake_at, dispatch_family, value, dispatch_key, dispatch_eligible) \
                 SELECT e ->> 'task_id', e ->> 'crate_name', e ->> 'version', e ->> 'features_json', \
                        e ->> 'target', e ->> 'rustc_version', e ->> 'host_side', e ->> 'explicit_spelling', e ->> 'dependency_identity', e ->> 'downloads', \
                        0, e ->> 'priority', 'pending', e ->> 'preserve_lockfile', e ->> 'lane', \
                        1, lower(hex(randomblob(16))), e ->> 'first_requested_at', \
                        e ->> 'created_at', \
                        e ->> 'unpublished_deps', e ->> 'deps_met', e ->> 'blocked', \
                        {wake}, {family}, CAST(e ->> 'value' AS INTEGER), e ->> 'dispatch_key', \
                        {eligible} \
                 FROM (SELECT value AS e FROM json_each(?)) e \
                 WHERE TRUE \
                 ON CONFLICT DO NOTHING \
                 RETURNING task_id",
                // `not_before` takes its epoch default, so the wake is
                // the age gate alone for a miss row, epoch for human.
                wake = wake_at_sql(
                    "e ->> 'lane'",
                    "e ->> 'first_requested_at'",
                    "'1970-01-01 00:00:00'",
                    settings.dispatch_min_age_minutes,
                ),
                family = dispatch_family_sql("e ->> 'target'"),
                // The floor CASE evaluates inside SQLite on the same
                // bound TEXT value — no wire narrowing joins the check.
                eligible = dispatch_eligible_sql(
                    "e ->> 'lane'",
                    "CAST(e ->> 'value' AS INTEGER)",
                ),
            ))
            .bind(enqueue_json(&rows)?)
            .fetch_scalars::<String>()
            .await
            .map_err(|error| format!("insert tasks: {error}"))?;
        inserted = inserted
            .checked_add(u64::try_from(inserted_rows.len()).unwrap_or(u64::MAX))
            .ok_or(QueueError::Overflow {
                field: "inserted task count",
                value: inserted,
            })?;
    }
    Ok(inserted)
}

/// Insert the edges of the tasks this request inserts, each carrying
/// its `dep_met` — the slice answer at insert time, the same EXISTS
/// the gate used to evaluate — so the owner's `unpublished_deps`
/// count and every later slice-delta flip read a stored flag instead
/// of re-joining the published rows per edge. `ON CONFLICT` tolerates
/// a stale edge row outliving its queue row (edges are a function of
/// the owner task id, so the row is identical by construction), and
/// the slice deltas' `dep_met` maintenance keeps it current while the
/// owner is gone.
async fn insert_dep_edges(db: &DurableDb, edges: &[BatchedDepEdge]) -> Result<(), QueueError> {
    for chunk in edges.chunks(ENQUEUE_JSON_BATCH_ROWS) {
        db.query(&format!(
            "INSERT INTO queue_dependencies \
             (task_id, depends_on_task_id, dep_crate_name, dep_version, dep_features_json, dep_target, dep_rustc_version, dep_host_side, dep_dependency_identity, dep_invocations, dep_shapes, dep_met) \
             SELECT d.task_id, d.depends_on_task_id, d.dep_crate_name, \
                    d.dep_version, d.dep_features_json, d.dep_target, \
                    d.dep_rustc_version, d.dep_host_side, d.dep_dependency_identity, \
                    d.dep_invocations, \
                    d.dep_shapes, CASE WHEN {unpub} THEN 0 ELSE 1 END \
             FROM (SELECT e ->> 'task_id' AS task_id, \
                         e ->> 'depends_on_task_id' AS depends_on_task_id, \
                         e ->> 'dep_crate_name' AS dep_crate_name, \
                         e ->> 'dep_version' AS dep_version, \
                         e ->> 'dep_features_json' AS dep_features_json, \
                         e ->> 'dep_target' AS dep_target, \
                         e ->> 'dep_rustc_version' AS dep_rustc_version, \
                         e ->> 'dep_host_side' AS dep_host_side, \
                         e ->> 'dep_dependency_identity' AS dep_dependency_identity, \
                         e ->> 'dep_invocations' AS dep_invocations, \
                         e ->> 'dep_shapes' AS dep_shapes \
                   FROM (SELECT value AS e FROM json_each(?))) AS d \
             WHERE TRUE \
             ON CONFLICT(task_id, depends_on_task_id) DO NOTHING",
            unpub = dep_edge_unpublished_sql("d"),
        ))
        .bind(enqueue_json(chunk)?)
        .execute()
        .await
        .map_err(|error| format!("insert task dependencies: {error}"))?;
    }
    Ok(())
}

/// Upsert every resolved-subgraph node into `task_nodes` — the
/// submit-side half of the node store (stow#588). `INSERT` with an
/// `ON CONFLICT` that only lifts `explicit_spelling`: a task id is a
/// content address, so a node another request already wrote is
/// identical by construction — except the flag, which two subgraphs
/// minting the same id can disagree on (it derives from the unit
/// graph, a finer input than the task-id digest commits to). A
/// flagged resubmission upgrades the stored row's `KeysAsNative` so
/// the next dispatch payload and edge requirement see the real
/// contract; `KeysApart` never lowers. The `WHERE` confines the
/// write to a real upgrade — `MAX` would leave the value unchanged
/// otherwise, and an unchanged row is not an event worth billing.
async fn upsert_task_nodes(db: &DurableDb, rows: &[BatchedNodeRow]) -> Result<(), QueueError> {
    for chunk in rows.chunks(ENQUEUE_JSON_BATCH_ROWS) {
        db.query(
            "INSERT INTO task_nodes \
             (task_id, crate_name, version, features_json, target, rustc_version, host_side, explicit_spelling, dependency_identity, children_json) \
             SELECT e ->> 'task_id', e ->> 'crate_name', e ->> 'version', \
                    e ->> 'features_json', e ->> 'target', e ->> 'rustc_version', \
                    e ->> 'host_side', e ->> 'explicit_spelling', e ->> 'dependency_identity', \
                    e ->> 'children_json' \
             FROM (SELECT value AS e FROM json_each(?)) e \
             WHERE TRUE \
             ON CONFLICT(task_id) DO UPDATE SET \
                explicit_spelling = excluded.explicit_spelling \
             WHERE excluded.explicit_spelling > task_nodes.explicit_spelling",
        )
        .bind(enqueue_json(chunk)?)
        .execute()
        .await
        .map_err(|error| format!("upsert task nodes: {error}"))?;
    }
    Ok(())
}

/// Pending rows in the queue — the count the `STOW_MAX_QUEUE_PENDING`
/// gate compares against. `queue_status_counts` maintains it, so the
/// read is a handful of counter rows rather than a walk over every
/// pending index entry — the counters are one statement ahead of any
/// queue write on this database.
async fn pending_count(db: &DurableDb) -> Result<u32, QueueError> {
    let pending = db
        .query(
            "SELECT COALESCE(SUM(n), 0) AS count FROM queue_status_counts \
             WHERE status = 'pending'",
        )
        .fetch_scalar::<u64>()
        .await
        .map_err(|error| format!("count pending tasks: {error}"))?;
    u64_to_u32(pending, "pending task count")
}

/// Seconds from `now_unix` to the next UTC midnight — the `Retry-After`
/// the edge attaches to a daily-budget refusal, matching the
/// `date('now')` rollover the `human_daily_task_budget` table keys on.
#[must_use]
pub const fn seconds_until_utc_midnight(now_unix: i64) -> u64 {
    // rem_euclid keeps the offset positive even for a pre-epoch input.
    #[expect(
        clippy::cast_sign_loss,
        reason = "86_400 - rem_euclid(86_400) is in 1..=86_400, always positive"
    )]
    let seconds = (86_400 - now_unix.rem_euclid(86_400)) as u64;
    seconds
}

/// Charge `tasks` against today's human-lane budget in one statement: the
/// conditional upsert inserts today's row or increments it only while the
/// charge fits under `budget`, so concurrent submits cannot split the
/// check from the spend. `false` means the charge does not fit — the
/// caller refuses the submit.
async fn charge_human_daily_budget(
    db: &DurableDb,
    tasks: u32,
    budget: u32,
) -> Result<bool, QueueError> {
    // A submit larger than the whole budget can never fit, and skipping
    // the upsert keeps it from being recorded as spend.
    if tasks > budget {
        return Ok(false);
    }
    let charged = db
        .query(
            "INSERT INTO human_daily_task_budget (day, task_count) \
             VALUES (date('now'), ?) \
             ON CONFLICT(day) DO UPDATE SET task_count = task_count + excluded.task_count \
             WHERE task_count + excluded.task_count <= ? \
             RETURNING task_count",
        )
        .bind(i64::from(tasks))
        .bind(i64::from(budget))
        .fetch_scalar_optional::<i64>()
        .await
        .map_err(|error| format!("charge human daily task budget: {error}"))?;
    // A satisfied UPDATE returns the new total; a rejected one returns
    // no row at all.
    Ok(charged.is_some())
}

/// Enqueue submissions from the anonymous paths (redeemed miss tickets,
/// drained admitted misses, Turnstile-verified human requests), enforcing
/// the `STOW_MAX_QUEUE_PENDING` gate on miss-lane work and charging
/// human-lane tasks against `STOW_HUMAN_DAILY_TASK_BUDGET`.
pub async fn enqueue(
    db: &DurableDb,
    requests: &[EnqueueRequest],
    settings: &SchedulerSettings,
) -> Result<u32, QueueError> {
    enqueue_inner(db, requests, settings, true).await
}

/// Enqueue submissions from a repo-writer-trusted caller: the
/// pending-depth gate does not apply — the credential check already
/// bounds this path — but human-lane tasks still spend the daily budget.
pub async fn enqueue_trusted(
    db: &DurableDb,
    requests: &[EnqueueRequest],
    settings: &SchedulerSettings,
) -> Result<u32, QueueError> {
    enqueue_inner(db, requests, settings, false).await
}

async fn enqueue_inner(
    db: &DurableDb,
    requests: &[EnqueueRequest],
    settings: &SchedulerSettings,
    enforce_pending_cap: bool,
) -> Result<u32, QueueError> {
    // Both gates run before any insert so a refused submit leaves no
    // trace: the depth cap turns away miss-lane batches once the queue is
    // full, and the human lane spends from a per-UTC-day budget.
    if enforce_pending_cap
        && requests
            .iter()
            .any(|request| request_lane(request.source) == TaskLane::Miss)
    {
        let pending = pending_count(db).await?;
        if pending >= settings.max_queue_pending {
            return Err(QueueError::QueueFull {
                pending,
                cap: settings.max_queue_pending,
            });
        }
    }
    // Prepare the batch in Rust: queue identity, deterministic task id
    // and lane per request, skipping targets no CI runner builds.
    let mut prepared = Vec::with_capacity(requests.len());
    for request in requests {
        let identity = TaskIdentity::from_request(request);
        // Belt to the edge's brace: a row whose target has no runner can
        // only ever become a dispatch that dies before any job starts, so
        // it never enters the queue whatever route brought it here.
        if !stow_types::api::is_ci_target(&identity.target) {
            tracing::info!(
                crate_name = %identity.crate_name,
                target = %identity.target,
                "skipped enqueue: no CI runner builds this target"
            );
            continue;
        }
        // The request's subgraph resolves once: the task id, dep edges
        // and node-store rows all derive from that one resolution — the
        // validation `resolve` runs (indexes, self-edges, cycles) is the
        // refusal for a request whose declared context cannot re-derive
        // its ids (stow#588).
        let graph = request.resolved_dependency_graph().map_err(|error| {
            QueueError::Invariant(format!("resolve dependency subgraph: {error}"))
        })?;
        let deps = request
            .depends_on()
            .map_err(|error| QueueError::Invariant(format!("derive dep edges: {error}")))?;
        let dep_task_ids = deps
            .iter()
            .map(stow_types::api::EnqueueDependency::task_id)
            .collect();
        let nodes = node_store_rows(&graph)?;
        let root_dependency_identity = graph
            .dependency_identity(0)
            .ok_or_else(|| QueueError::Invariant("root node yields no digest".into()))?
            .to_string();
        prepared.push(Prepared {
            request,
            task_id: request
                .task_id()
                .map_err(|error| QueueError::Invariant(format!("derive task id: {error}")))?,
            identity,
            deps,
            dep_task_ids,
            root_dependency_identity,
            nodes,
        });
    }
    if prepared.is_empty() {
        return Ok(0);
    }

    let mut statuses = probe_task_statuses(db, &prepared).await?;
    let plan = plan_enqueue(&prepared, &mut statuses)?;

    // The write phase. `DurableDb` exposes no transaction primitive,
    // but on the Durable Object every statement below runs inside one
    // uninterrupted storage tick: the backend's futures resolve without
    // yielding, and a write sequence with no intervening yields commits
    // atomically per the documented input-gate batching — a failure
    // mid-phase leaves nothing behind.
    //
    // Edges land before the task rows: the inserts evaluate `deps_met`
    // against the edge set just written, so a task is born gated and no
    // statement revisits it. `queue_dependencies` carries no foreign key,
    // so an edge for a not-yet-inserted task is sound. Inserts precede
    // updates so a later occurrence of a just-inserted task lands on
    // the update path the per-request loop applied through
    // `update_existing_task`.
    // Resubmits recompute `priority` from the new downloads max —
    // the prospective `priority + demand` of every updated row must
    // stay under `PRIORITY_MAX` before a single write lands, or the
    // persisted demand an accepted batch folded would push value out
    // of its band (stow#522). Fresh inserts carry `demand = 0` and a
    // priority that cannot exceed `compute_priority`'s own bound, so
    // only the update set needs the probe.
    check_update_band_bound(db, &plan.updates).await?;
    // The human lane spends from a per-UTC-day budget — a mutating
    // charge, so it runs only after every read-only preflight above
    // has passed, and before the write phase below so a refused batch
    // leaves no trace. The plan counts what the batch actually moves
    // (stow#796): only requests that insert a human-lane row, promote
    // an existing row to the human lane or resurrect a completed row
    // pay — a resubmit of an already-queued human task issues no
    // statement at all.
    if plan.human_charges > 0
        && !charge_human_daily_budget(db, plan.human_charges, settings.human_daily_task_budget)
            .await?
    {
        return Err(QueueError::HumanDailyBudgetExhausted {
            attempted: u64::from(plan.human_charges),
            budget: u64::from(settings.human_daily_task_budget),
        });
    }
    // The content-addressed node store: every submit upserts every
    // node of each request's resolved subgraph, root included, so a
    // claimed task's `dependency_subgraph` can later be rebuilt by
    // walking task ids alone (stow#588). Dedup is by task id —
    // `batch_node_rows` folds the duplicates shared subgraphs carry,
    // so storage and upsert probes grow with distinct nodes, not
    // requests.
    let node_rows = batch_node_rows(&prepared);
    upsert_task_nodes(db, &node_rows).await?;
    let edge_owner_ids: Vec<String> = plan.edge_inserts.keys().cloned().collect();
    let edges: Vec<BatchedDepEdge> = plan.edge_inserts.into_values().flatten().collect();
    insert_dep_edges(db, &edges).await?;
    let inserted = apply_batched_inserts(db, settings, &plan.inserts).await?;
    apply_batched_updates(db, settings, &plan.updates).await?;

    // The batch's edge set is settled — recount the gate answer on the
    // tasks the request inserted. Their INSERT already folded the
    // edges just written, so this only moves a row whose insert hit a
    // conflict (a stale edge set from a deleted queue row, maintained
    // by slice deltas in between); an empty set issues no statement.
    refresh_deps_met_tasks(db, &edge_owner_ids).await?;

    u64_to_u32(inserted, "inserted task count")
}

/// What `submit_task_ids` reports: new queue rows inserted, plus the
/// submitted ids the node store does not hold — reported as unknown,
/// never re-minted (stow#588).
#[derive(Debug, Default)]
pub struct SubmitTaskIdsOutcome {
    pub inserted: u32,
    pub unknown: Vec<String>,
}

/// `POST /tasks/submit/ids` — the missed lane's promote path (stow#588):
/// each entry names an exact task id whose nodes a verified admission's
/// submit already upserted into `task_nodes`. The store is the only
/// context source — every known id's subgraph is rebuilt by the same
/// BFS walk dispatch uses and minted into a cache-miss `EnqueueRequest`
/// with the entry's recorded demand, then enqueued on the trusted lane.
/// An id the store does not hold is reported as `unknown` — never
/// re-minted, never a leaf substitute; a store chain that breaks
/// mid-walk is likewise reported rather than guessed at.
pub async fn submit_task_ids(
    db: &DurableDb,
    entries: &[stow_types::api::SubmitTaskIdEntry],
    settings: &SchedulerSettings,
) -> Result<SubmitTaskIdsOutcome, QueueError> {
    let ids: Vec<String> = entries.iter().map(|entry| entry.task_id.clone()).collect();
    let (walks, found, failed) = walk_task_ids(db, &ids).await?;
    let mut broken: std::collections::HashSet<usize> =
        failed.iter().map(|(index, _)| *index).collect();
    for (index, slot) in walks.iter().enumerate() {
        if slot.is_none() && !broken.contains(&index) {
            broken.insert(index);
        }
    }
    let mut requests = Vec::with_capacity(entries.len());
    let mut unknown = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let Some(walk) = walks.get(index).and_then(Option::as_ref) else {
            unknown.push(entry.task_id.clone());
            continue;
        };
        let Some(root) = found.get(&entry.task_id) else {
            unknown.push(entry.task_id.clone());
            continue;
        };
        let dependency_subgraph = build_task_subgraph(&entry.task_id, walk, &found)
            .map_err(|error| QueueError::Invariant(format!("submit task ids: {error}")))?;
        let request = EnqueueRequest {
            crate_name: CrateName::parse(root.crate_name.as_str()).map_err(|error| {
                QueueError::Invariant(format!("node {}: {error}", root.task_id))
            })?,
            version: CrateVersion::new(semver::Version::parse(&root.version).map_err(|error| {
                QueueError::Invariant(format!("node {}: {error}", root.task_id))
            })?),
            features_json: FeaturesJson::from_sorted(
                serde_json::from_str(&root.features_json).map_err(|error| {
                    QueueError::Invariant(format!("node {}: {error}", root.task_id))
                })?,
            )
            .map_err(|error| QueueError::Invariant(format!("node {}: {error}", root.task_id)))?,
            target: stow_types::identity::TargetTriple::parse(root.target.as_str()).map_err(
                |error| QueueError::Invariant(format!("node {}: {error}", root.task_id)),
            )?,
            rustc_version: stow_types::identity::WireRustcVersion::parse(
                root.rustc_version.as_str(),
            )
            .map_err(|error| QueueError::Invariant(format!("node {}: {error}", root.task_id)))?,
            downloads: entry.downloads,
            source: stow_types::api::EnqueueSource::CacheMiss,
            dependency_subgraph,
            preserve_lockfile: false,
            host_side: root.host_side != 0,
            explicit_spelling: spelling_of(root.explicit_spelling),
        };
        // The rebuilt context must re-derive the submitted id exactly —
        // a store that produces anything else is corrupt, never
        // re-minted under a fresh id.
        let derived = request
            .task_id()
            .map_err(|error| QueueError::Invariant(format!("derive task id: {error}")))?;
        if derived != entry.task_id {
            return Err(QueueError::Invariant(format!(
                "node store re-derived task id {derived} for submitted {} — refusing to re-mint",
                entry.task_id
            )));
        }
        requests.push(request);
    }
    let inserted = if requests.is_empty() {
        0
    } else {
        enqueue_inner(db, &requests, settings, false).await?
    };
    Ok(SubmitTaskIdsOutcome { inserted, unknown })
}

/// One request precomputed for the batched enqueue: queue identity,
/// its deterministic task id, the resolved deps of its carried
/// subgraph, and the node-store rows the submit upserts (stow#588).
struct Prepared<'r> {
    request: &'r EnqueueRequest,
    task_id: String,
    identity: TaskIdentity,
    /// The request's direct dependencies, resolved from its carried
    /// subgraph once.
    deps: Vec<stow_types::api::EnqueueDependency>,
    /// `task_id` of each `deps` entry, in the same order.
    dep_task_ids: Vec<String>,
    /// The root node's dependency digest — what `task_id`'s `-d`
    /// segment commits to; written to `queue.dependency_identity`.
    root_dependency_identity: String,
    /// Every node of the request's resolved subgraph, root included —
    /// upserted into `task_nodes` by the write phase.
    nodes: Vec<BatchedNodeRow>,
}

/// The batch's node-store rows, deduplicated by task id: a node
/// several requests share arrives once per subgraph, and the id
/// commits to every column but `explicit_spelling`, so the kept row
/// carries the batch's strongest flag and each duplicate would only
/// re-probe the upsert's conflict — a billed read for nothing
/// (stow#786).
fn batch_node_rows(prepared: &[Prepared]) -> Vec<BatchedNodeRow> {
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    let mut rows: Vec<BatchedNodeRow> = Vec::new();
    for row in prepared.iter().flat_map(|entry| &entry.nodes) {
        if let Some(&slot) = seen.get(row.task_id.as_str()) {
            rows[slot].explicit_spelling = rows[slot].explicit_spelling.max(row.explicit_spelling);
        } else {
            seen.insert(row.task_id.as_str(), rows.len());
            rows.push(row.clone());
        }
    }
    rows
}

/// The node-store rows one request's resolved subgraph contributes:
/// every node of the graph, root included, with its children's task
/// ids encoded as JSON — the upsert set `enqueue` writes so dispatch
/// can later walk the closure by task id alone (stow#588).
fn node_store_rows(
    graph: &stow_types::task_graph::ResolvedTaskGraph,
) -> Result<Vec<BatchedNodeRow>, QueueError> {
    let nodes = graph.nodes();
    let mut rows = Vec::with_capacity(nodes.len());
    for (index, node) in nodes.iter().enumerate() {
        let task_id = graph
            .task_id(index)
            .ok_or_else(|| {
                QueueError::Invariant(format!("resolved node {index} yields no task id"))
            })?
            .to_owned();
        let dependency_identity = graph
            .dependency_identity(index)
            .ok_or_else(|| {
                QueueError::Invariant(format!("resolved node {index} yields no digest"))
            })?
            .to_string();
        let children = node
            .dependencies
            .iter()
            .map(|&dep| {
                graph.task_id(dep).map(str::to_owned).ok_or_else(|| {
                    QueueError::Invariant(format!(
                        "resolved node {index} dep {dep} yields no task id"
                    ))
                })
            })
            .collect::<Result<Vec<String>, QueueError>>()?;
        rows.push(BatchedNodeRow {
            task_id,
            crate_name: node.identity.crate_name.as_str().to_owned(),
            version: node.identity.version.to_string(),
            features_json: node.identity.features_json.raw(),
            target: node.identity.target.as_str().to_owned(),
            rustc_version: node.identity.rustc_version.as_str().to_owned(),
            host_side: u8::from(node.identity.host_side),
            explicit_spelling: u8::from(
                node.explicit_spelling == stow_types::public_cache::ExplicitSpelling::KeysApart,
            ),
            dependency_identity,
            children_json: serde_json::to_string(&children)
                .map_err(|error| QueueError::Sql(format!("encode node children json: {error}")))?,
        });
    }
    Ok(rows)
}

/// Everything the write phase emits for one chunk, with the per-request
/// ordering already resolved in Rust.
struct EnqueuePlan {
    updates: Vec<BatchedUpdate>,
    inserts: Vec<BatchedInsert>,
    /// Edge sets of the tasks this chunk inserts — keyed by owner task
    /// id. Only fresh rows get edges: a task id commits to its whole
    /// dependency subgraph, so an existing id's stored edges are already
    /// exactly these (stow#588).
    edge_inserts: BTreeMap<String, Vec<BatchedDepEdge>>,
    /// The human-lane requests this plan moves stored state for — the
    /// count `charge_human_daily_budget` spends (stow#796): a fresh
    /// human-lane insert, a re-request that promotes an existing row
    /// to the human lane, or a human-lane resurrect of a completed
    /// row — each creates or speeds up a build. A resubmit of an
    /// already-queued human task plans none of them, so it charges
    /// nothing.
    human_charges: u32,
}

/// One existence probe's answer for a chunk task id: the row's status
/// and the explicit-spelling flag it stored (stow#736). The flag is
/// what a `KeysApart` resubmission resurrects a `KeysAsNative`
/// `completed` row against — the row's published native-only set
/// cannot serve the consumers the flag describes.
#[derive(Debug)]
struct TaskStatusProbe {
    status: String,
    explicit_spelling: i64,
    lane: String,
    downloads: i64,
}

/// One existence probe for the chunk, over every task id it can
/// touch. `task_id` is the queue's primary key, so this answers every
/// existence check the row-at-a-time loop ran.
async fn probe_task_statuses(
    db: &DurableDb,
    prepared: &[Prepared<'_>],
) -> Result<BTreeMap<String, TaskStatusProbe>, QueueError> {
    let probe_ids: Vec<&str> = prepared
        .iter()
        .map(|entry| entry.task_id.as_str())
        .collect();
    let mut statuses: BTreeMap<String, TaskStatusProbe> = BTreeMap::new();
    for chunk in probe_ids.chunks(ENQUEUE_JSON_BATCH_ROWS) {
        let rows = db
            .query(
                "SELECT task_id, status, explicit_spelling, lane, downloads \
                 FROM queue \
                 WHERE task_id IN (SELECT value FROM json_each(?))",
            )
            .bind(enqueue_json(chunk)?)
            .fetch_all::<TaskStatusRow>()
            .await
            .map_err(|error| format!("select existing tasks: {error}"))?;
        for row in rows {
            statuses.insert(
                row.task_id,
                TaskStatusProbe {
                    status: row.status,
                    explicit_spelling: row.explicit_spelling,
                    lane: row.lane,
                    downloads: row.downloads,
                },
            );
        }
    }
    Ok(statuses)
}

/// One request's edge rows, fully resolved: the dep's required unit
/// shapes for the gate and a self-edge rejection.
fn dep_edges(entry: &Prepared<'_>) -> Result<Vec<BatchedDepEdge>, QueueError> {
    let mut edges = Vec::with_capacity(entry.deps.len());
    for (dependency, dep_task_id) in entry.deps.iter().zip(entry.dep_task_ids.iter()) {
        let dep_features = dependency.features_json.raw();
        let dep_version = dependency.version.to_string();
        // The gate needs every required unit shape of the dep's
        // semantic identity — the shapes the dependent's own build
        // compiles the dep's units at. The mask and the pair count go
        // on the edge so the gate SQL stays a row-count compare; the
        // dep's explicit-spelling flag is the fourth input — a
        // `KeysApart` dep owes its explicit `Native`-spelling shapes
        // too (stow#736).
        let (dep_invocations, dep_shapes) = dep_edge_requirements(
            entry.request.target.as_str(),
            entry.request.host_side,
            entry.request.explicit_spelling,
            dependency.target.as_str(),
            dependency.host_side,
            dependency.explicit_spelling,
        );
        if *dep_task_id == entry.task_id {
            return Err(QueueError::Sql(format!(
                "task {} cannot depend on itself",
                entry.task_id
            )));
        }
        edges.push(BatchedDepEdge {
            task_id: entry.task_id.clone(),
            depends_on_task_id: dep_task_id.clone(),
            dep_crate_name: dependency.crate_name.as_str().to_owned(),
            dep_version,
            dep_features_json: dep_features,
            dep_target: dependency.target.as_str().to_owned(),
            dep_rustc_version: dependency.rustc_version.as_str().to_owned(),
            dep_host_side: u8::from(dependency.host_side),
            dep_dependency_identity: dependency.dependency_identity.to_string(),
            dep_invocations,
            dep_shapes,
        });
    }
    Ok(edges)
}

/// Fold one re-request's contribution into the task's [`BatchedUpdate`]
/// — the first moving occurrence seeds it, and every occurrence lifts
/// the maxima its flags describe (`plan_enqueue` emits it only when
/// the row's stored state actually changes).
fn fold_update(
    updates: &mut BTreeMap<String, BatchedUpdate>,
    entry: &Prepared<'_>,
    downloads: i64,
    redispatch: bool,
    lane: TaskLane,
    request_explicit: u8,
) {
    let update = updates
        .entry(entry.task_id.clone())
        .or_insert_with(|| BatchedUpdate {
            task_id: entry.task_id.clone(),
            downloads,
            redispatch: 0,
            human: 0,
            explicit: 0,
        });
    update.downloads = update.downloads.max(downloads);
    update.redispatch |= u8::from(redispatch);
    update.human |= u8::from(lane == TaskLane::Human);
    update.explicit |= request_explicit;
}

/// Replay the per-request loop's state machine in memory, in request
/// order: each request's own insert/update, then its dep sync. A task
/// appearing twice in one chunk sees what its earlier occurrence left
/// (a fresh insert reads as 'pending', a resurrected row as 'pending'),
/// so duplicates land identically to the row-at-a-time loop.
/// `edge_inserts` holds the first occurrence's dependency list per
/// task — only a task the chunk inserts can carry new edges. `statuses`
/// carries the existence probe in and is advanced to the row each
/// occurrence leaves.
fn plan_enqueue(
    prepared: &[Prepared<'_>],
    statuses: &mut BTreeMap<String, TaskStatusProbe>,
) -> Result<EnqueuePlan, QueueError> {
    let mut updates: BTreeMap<String, BatchedUpdate> = BTreeMap::new();
    let mut plan = EnqueuePlan {
        updates: Vec::new(),
        inserts: Vec::new(),
        edge_inserts: BTreeMap::new(),
        human_charges: 0,
    };
    for entry in prepared {
        let lane = request_lane(entry.request.source);
        let downloads = u64_to_i64(entry.request.downloads, "downloads")?;
        let request_explicit = u8::from(
            entry.request.explicit_spelling
                == stow_types::public_cache::ExplicitSpelling::KeysApart,
        );
        if let Some(probe) = statuses.get(&entry.task_id) {
            // Beyond the lane resurrection: a request proving the node
            // `KeysApart` against a row stored `KeysAsNative` resurrects
            // a `completed` row on any lane — its published native-only
            // shapes cannot serve the explicit-spelling consumers the
            // flag describes (stow#736). `failed` still never revives,
            // and the claim's coverage retirement applies the same
            // requirement to rows that never complete again.
            let flaggap = probe.status == "completed"
                && request_explicit == 1
                && probe.explicit_spelling == 0;
            let redispatch = resurrects(probe.status.as_str(), lane) || flaggap;
            // stow#784: a re-request that moves nothing writes nothing —
            // a fully deduplicated resubmit must not rewrite every row
            // just to bump bookkeeping. An update is emitted only for a
            // real change: a resurrection, a miss→human lane move, an
            // explicit-spelling upgrade the row can still take, or a
            // higher downloads value — which stow#818 bounds to rows
            // still pending dispatch, the only status `priority`
            // orders; every other row takes the count inside the next
            // move it makes (a resurrection carries it anyway).
            let lane_move = lane == TaskLane::Human && probe.lane != "human";
            let explicit_upgrade = request_explicit == 1
                && probe.explicit_spelling == 0
                && (redispatch || !matches!(probe.status.as_str(), "dispatched" | "running"));
            let downloads_bump = downloads > probe.downloads && probe.status == "pending";
            let moved = redispatch || lane_move || explicit_upgrade || downloads_bump;
            if moved {
                fold_update(
                    &mut updates,
                    entry,
                    downloads,
                    redispatch,
                    lane,
                    request_explicit,
                );
            }
            // The stored-state moves the budget pays for (stow#796):
            // the lane promotion, or a human request putting a
            // completed row back to `pending` — the budget prices
            // human-triggered builds, and a resurrect creates one
            // whether or not the lane moves. A later occurrence of
            // this task in the same batch already reads lane 'human'
            // and status 'pending' from `statuses`, so it cannot
            // double-charge.
            if lane_move || (redispatch && lane == TaskLane::Human) {
                plan.human_charges += 1;
            }
            statuses.insert(
                entry.task_id.clone(),
                TaskStatusProbe {
                    status: if redispatch {
                        "pending".to_owned()
                    } else {
                        probe.status.clone()
                    },
                    explicit_spelling: probe.explicit_spelling.max(i64::from(request_explicit)),
                    lane: if lane == TaskLane::Human {
                        "human".to_owned()
                    } else {
                        probe.lane.clone()
                    },
                    // Only a written row takes the count — the mirror
                    // holds what the row will carry, so a later
                    // occurrence's mover still compares the truth.
                    downloads: if moved {
                        probe.downloads.max(downloads)
                    } else {
                        probe.downloads
                    },
                },
            );
        } else {
            plan.inserts.push(BatchedInsert {
                task_id: entry.task_id.clone(),
                crate_name: entry.identity.crate_name.clone(),
                version: entry.identity.version.clone(),
                features_json: entry.identity.features_json.clone(),
                target: entry.identity.target.clone(),
                rustc_version: entry.identity.rustc_version.clone(),
                host_side: u8::from(entry.identity.host_side),
                explicit_spelling: request_explicit,
                dependency_identity: entry.root_dependency_identity.clone(),
                downloads,
                priority: compute_priority(entry.request.downloads, 0)?,
                preserve_lockfile: u8::from(entry.request.preserve_lockfile),
                lane: lane.as_str(),
            });
            statuses.insert(
                entry.task_id.clone(),
                TaskStatusProbe {
                    status: "pending".to_owned(),
                    explicit_spelling: i64::from(request_explicit),
                    lane: lane.as_str().to_owned(),
                    downloads,
                },
            );
            // A fresh human-lane row is the other move the budget pays
            // for (stow#796).
            if lane == TaskLane::Human {
                plan.human_charges += 1;
            }
            // A task id commits to its whole dependency subgraph, so a
            // task's edge set is a function of the id (stow#588): edges
            // are written only for the row this request inserts — a
            // re-enqueue of an existing id can carry nothing new.
            if !entry.deps.is_empty() {
                let edges = dep_edges(entry)?;
                plan.edge_inserts.insert(entry.task_id.clone(), edges);
            }
        }
    }
    plan.updates = updates.into_values().collect();
    Ok(plan)
}

/// One batch leg's completion as [`complete`] applies it.
#[derive(Debug)]
struct BuildCompleteReport {
    task_id: String,
    generation_id: String,
    attempt: u32,
    success: bool,
    error: Option<String>,
    github_run_id: Option<String>,
    /// The build-cost sample's duration: a batch leg's runner time,
    /// measured on GitHub's clock across the leg's own two jobs
    /// (stow#833 §4.1 — `claimed_at` stays only for the lease). `None`
    /// for a failed leg.
    sample_ms: Option<i64>,
}

#[derive(Debug, skyzen::FromRow)]
struct CompletedTargetRow {
    target: String,
    crate_name: String,
    status: String,
}

/// `window_minutes` bounds the outcome evidence the record keeps: the
/// freeze breaker's window, so the expiry deletes carried inside the
/// insert drop exactly what the trip check can no longer read.
async fn complete(
    db: &DurableDb,
    settings: &SchedulerSettings,
    report: &BuildCompleteReport,
    window_minutes: u32,
) -> Result<(), QueueError> {
    let generation_id = report.generation_id.clone();
    // The `RETURNING` columns feed the outcome counter and the
    // build-cost sample below without a second read.
    // The report must name the row's live attempt in an in-flight status:
    // without that predicate a late or duplicate report for a superseded
    // attempt would overwrite the state of the attempt the row has since
    // been resurrected into (resurrection bumps `attempt`).
    //
    // A failure under `MAX_BUILD_ATTEMPTS` re-queues the row behind the
    // same exponential backoff a dispatch failure applies — 2^cycle
    // minutes, capped — with `attempt` bumped so the next dispatch is a
    // new generation; at the cap the row parks `failed` until an
    // operator `retry` returns it to `pending` at attempt 1. SET terms
    // see the old row, so `attempt` is the cycle position that failed.
    let retry = format!("attempt < {MAX_BUILD_ATTEMPTS}");
    let next_not_before = format!(
        "datetime('now', '+' || {} || ' minutes')",
        backoff_minutes_sql("attempt")
    );
    let statement = if report.success {
        "UPDATE queue \
         SET status = 'completed', error_msg = ?, github_run_id = COALESCE(?, github_run_id), \
             updated_at = datetime('now') \
         WHERE task_id = ? AND generation_id = ? \
           AND status IN ('dispatched', 'running') \
         RETURNING target, crate_name, status"
            .to_owned()
    } else {
        format!(
            "UPDATE queue \
             SET status = CASE WHEN {retry} THEN 'pending' ELSE 'failed' END, \
                 attempt = attempt + CASE WHEN {retry} THEN 1 ELSE 0 END, \
                 error_msg = ?, \
                 github_run_id = COALESCE(?, github_run_id), \
                 not_before = CASE WHEN {retry} THEN {next_not_before} ELSE not_before END, \
                 deps_met = CASE WHEN {retry} THEN {deps_met} ELSE deps_met END, \
                 blocked = CASE WHEN {retry} THEN {blocked} ELSE blocked END, \
                 wake_at = CASE WHEN {retry} THEN {wake} ELSE wake_at END, \
                 updated_at = datetime('now') \
             WHERE task_id = ? AND generation_id = ? \
               AND status IN ('dispatched', 'running') \
             RETURNING target, crate_name, status",
            deps_met = deps_met_sql("queue.task_id"),
            blocked = blocked_sql("queue.task_id"),
            wake = wake_at_sql(
                "lane",
                "first_requested_at",
                &next_not_before,
                settings.dispatch_min_age_minutes,
            ),
        )
    };
    let updated = db
        .query(&statement)
        .bind(report.error.clone().unwrap_or_default())
        .bind(report.github_run_id.clone())
        .bind(report.task_id.clone())
        .bind(generation_id.clone())
        .fetch_optional::<CompletedTargetRow>()
        .await
        .map_err(|error| format!("complete task: {error}"))?;
    // A report that applied to no row is never a silent success: an
    // unknown task id is a 404 at the handler, and a known row whose live
    // generation/status no longer matches is a stale or duplicate report —
    // logged and answered 409 so the reporter sees the conflict rather
    // than believing it completed the current generation.
    if updated.is_none() {
        return reject_stale_completion(db, report).await;
    }
    // A dep whose attempt just exhausted is the one outside-the-row
    // event that flips a pending dependent's `blocked` flag — refresh
    // exactly its dependents.
    if !report.success {
        refresh_dependents(
            db,
            "SELECT value AS task_id FROM json_each(?)",
            &[DbValue::Text(enqueue_json(std::slice::from_ref(
                &report.task_id,
            ))?)],
        )
        .await?;
    }
    // The row landed — count the attempt's outcome so the
    // dispatch-freeze breaker's sliding window sees it even after a
    // re-request flips the queue row back to pending.
    let completed = updated.expect("checked above");
    // A failure that re-queued the row owes it a fresh key: the
    // median may have moved while it was dispatched (the keyed
    // cost-refresh only touches `pending` rows), and the parked row's
    // stored key carries the stale cost.
    if completed.status == "pending" {
        refresh_dispatch_keys(db, std::slice::from_ref(&report.task_id)).await?;
    }
    record_attempt_outcome(
        db,
        report,
        &generation_id,
        &completed.target,
        window_minutes,
    )
    .await?;
    // A success is the build cost's only honest measurement, and the
    // generation fence above is what keeps a late or duplicate report
    // out of the sample window.
    if report.success
        && let Some(duration_ms) = report.sample_ms
    {
        record_build_sample(
            db,
            report,
            &completed.crate_name,
            &completed.target,
            duration_ms,
        )
        .await?;
    }
    Ok(())
}

/// Diagnose why a completion report matched no row: unknown task id,
/// or a row whose live generation/status moved past the report.
async fn reject_stale_completion(
    db: &DurableDb,
    report: &BuildCompleteReport,
) -> Result<(), QueueError> {
    let row = db
        .query("SELECT attempt, status FROM queue WHERE task_id = ?")
        .bind(report.task_id.clone())
        .fetch_optional::<AttemptStatusRow>()
        .await
        .map_err(|error| {
            format!(
                "load task {} after rejected report: {error}",
                report.task_id
            )
        })?;
    let Some(row) = row else {
        return Err(QueueError::UnknownTask(report.task_id.clone()));
    };
    tracing::warn!(
        task_id = %report.task_id,
        attempt = report.attempt,
        row_attempt = row.attempt,
        row_status = %row.status,
        "rejected completion report for a superseded or inactive attempt"
    );
    Err(QueueError::StaleCompletion {
        task_id: report.task_id.clone(),
        attempt: report.attempt,
        row_attempt: row.attempt,
        row_status: row.status,
    })
}

/// File one successful build's duration in the bounded per-(crate,
/// target) sample window, recompute the median and refresh the
/// dispatch keys of the pending rows whose score just moved.
///
/// The read/write set is constant in queue size and traffic: the
/// sample insert keys on the claim generation (a replay of the same
/// generation inserts nothing and exits — the completion fence above
/// already rejected any report naming a dead generation), the cap
/// delete drops the tail past `BUILD_SAMPLE_WINDOW`, the median
/// recompute reads the window's at-most-`BUILD_SAMPLE_WINDOW` rows,
/// the stats upsert writes one row, and the dispatch-key refresh —
/// only when the median actually moved — is a keyed probe touching
/// the pending rows of exactly this (`crate_name`, `target`).
///
/// `duration_ms` is the caller's measurement: claim-to-completion for
/// the per-task path, the leg's runner time for a batch leg
/// (stow#833 §4.1) — the sample is the cost operand the rank reads,
/// so it must measure the build itself.
async fn record_build_sample(
    db: &DurableDb,
    report: &BuildCompleteReport,
    crate_name: &str,
    target: &str,
    duration_ms: i64,
) -> Result<(), QueueError> {
    let inserted = db
        .query(
            "INSERT INTO crate_build_samples \
             (crate_name, target, generation_id, duration_ms) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT DO NOTHING",
        )
        .bind(crate_name.to_owned())
        .bind(target.to_owned())
        .bind(report.generation_id.clone())
        .bind(duration_ms)
        .execute()
        .await
        .map_err(|error| format!("record build sample: {error}"))?;
    if inserted.rows_written == 0 {
        return Ok(());
    }
    // Keep only the newest window: rows past it are the samples a
    // recompute can no longer read anyway.
    db.query(&format!(
        "DELETE FROM crate_build_samples \
         WHERE rowid IN (SELECT rowid FROM crate_build_samples \
                         WHERE crate_name = ? AND target = ? \
                         ORDER BY rowid DESC LIMIT -1 OFFSET {BUILD_SAMPLE_WINDOW})",
    ))
    .bind(crate_name.to_owned())
    .bind(target.to_owned())
    .execute()
    .await
    .map_err(|error| format!("cap build sample window: {error}"))?;
    let old_median = db
        .query(
            "SELECT CAST(median_ms AS TEXT) AS median_ms FROM crate_build_stats \
             WHERE crate_name = ? AND target = ?",
        )
        .bind(crate_name.to_owned())
        .bind(target.to_owned())
        .fetch_optional::<BuildStatsRow>()
        .await
        .map_err(|error| format!("read build stats: {error}"))?
        .map(|row| row.median_ms.parse::<i64>())
        .transpose()
        .map_err(|_| {
            QueueError::Invariant(format!(
                "stored median_ms for {crate_name}/{target} is not an integer"
            ))
        })?;
    // Duration columns cross the wire as TEXT and parse to `i64` — a
    // `julianday` span can exceed `2^53` and the JSON number crossing
    // would truncate it.
    let mut durations = db
        .query(
            "SELECT CAST(duration_ms AS TEXT) AS duration_ms FROM crate_build_samples \
             WHERE crate_name = ? AND target = ? ORDER BY duration_ms",
        )
        .bind(crate_name.to_owned())
        .bind(target.to_owned())
        .fetch_scalars::<String>()
        .await
        .map_err(|error| format!("read build sample window: {error}"))?
        .into_iter()
        .map(|text| {
            text.parse::<i64>().map_err(|_| {
                QueueError::Invariant(format!("stored duration_ms {text:?} is not an integer"))
            })
        })
        .collect::<Result<Vec<i64>, _>>()?;
    durations.sort_unstable();
    let Some(&median_ms) = durations.get((durations.len() - 1) / 2) else {
        return Ok(());
    };
    // The stored cost domain is positive: a build faster than the
    // millisecond unit measures 0 and floors at the unit, while a
    // negative duration can only be clock corruption.
    let median_ms = if median_ms < 0 {
        return Err(QueueError::Invariant(format!(
            "negative build duration median {median_ms}"
        )));
    } else {
        median_ms.max(1)
    };
    db.query(
        "INSERT INTO crate_build_stats (crate_name, target, builds, median_ms) \
         VALUES (?, ?, 1, CAST(? AS INTEGER)) \
         ON CONFLICT (crate_name, target) DO UPDATE SET \
             builds = builds + 1, median_ms = excluded.median_ms",
    )
    .bind(crate_name.to_owned())
    .bind(target.to_owned())
    .bind(median_ms.to_string())
    .execute()
    .await
    .map_err(|error| format!("upsert build stats: {error}"))?;
    // The keyed refresh only pays its probe when the median moved:
    // an unchanged median leaves every key what it was.
    if Some(median_ms) != old_median {
        refresh_pending_keys_for_cost(db, crate_name, target, median_ms).await?;
    }
    Ok(())
}

/// Reprice the one `(crate_name, target)` pending set after its median
/// moved: the SELECT seeks `idx_queue_pending_crate_target` — it reads
/// precisely this pair's pending rows, never the crate's terminal or
/// other-target history — and the new median arrives as a bound TEXT
/// constant, so no stats re-read joins the walk.
async fn refresh_pending_keys_for_cost(
    db: &DurableDb,
    crate_name: &str,
    target: &str,
    median_ms: i64,
) -> Result<(), QueueError> {
    let rows = db
        .query(
            "SELECT q.task_id, q.target, q.lane, q.dispatch_family, \
                    CAST(q.priority AS TEXT) AS priority, \
                    CAST(q.demand AS TEXT) AS demand, \
                    q.first_requested_at, q.created_at, \
                    CAST(q.value AS TEXT) AS value, q.dispatch_key, \
                    ? AS median_ms \
             FROM queue q \
             WHERE q.status = 'pending' AND q.crate_name = ? AND q.target = ?",
        )
        .bind(median_ms.to_string())
        .bind(crate_name.to_owned())
        .bind(target.to_owned())
        .fetch_all::<RankSourceRow>()
        .await
        .map_err(|error| format!("load pending rows for cost refresh: {error}"))?;
    let updates = rank_updates(&rows)?;
    apply_key_updates(db, &updates).await
}

#[derive(Debug, skyzen::FromRow)]
struct BuildStatsRow {
    median_ms: String,
}

/// The time granularity `attempt_outcome_buckets` counts in — five
/// minutes, so a 60-minute window sums at most 12 buckets per target
/// whatever the completion traffic.
pub const OUTCOME_BUCKET_SECS: i64 = 300;

/// Count one completion report against the breaker's window and expire
/// what aged out. The read set of a completion is constant in traffic:
/// the `UPDATE … RETURNING target` in `complete` names the row's target,
/// one bucket upsert counts it, and — for failures — one raw
/// `attempt_outcomes_v2` row keeps the trip alert's class and run-id
/// evidence; successes never land a raw row at all. Both expiry deletes
/// bound on `window_minutes` (the same horizon the trip check reads), so
/// each insert removes at most what just aged out — the tables never
/// outgrow the window.
async fn record_attempt_outcome(
    db: &DurableDb,
    report: &BuildCompleteReport,
    generation_id: &str,
    target: &str,
    window_minutes: u32,
) -> Result<(), QueueError> {
    // The bucket width is SQL text, never a bound parameter: the
    // Durable Object binds every JS number as a double, so
    // `(unixepoch('now') / ?) * ?` was float arithmetic and the
    // "bucket" landed as the current second — one row per completion
    // instead of one per five minutes (stow#816).
    db.query(&format!(
        "INSERT INTO attempt_outcome_buckets (target, bucket, outcomes, failures) \
         VALUES (?, (unixepoch('now') / {OUTCOME_BUCKET_SECS}) * {OUTCOME_BUCKET_SECS}, 1, ?) \
         ON CONFLICT(target, bucket) DO UPDATE SET \
             outcomes = outcomes + 1, failures = failures + excluded.failures"
    ))
    .bind(target.to_owned())
    .bind(i64::from(!report.success))
    .execute()
    .await
    .map_err(|error| format!("count attempt outcome in its bucket: {error}"))?;
    if !report.success {
        db.query(
            "INSERT INTO attempt_outcomes_v2 \
                 (task_id, generation_id, attempt, target, failure_class, \
                  github_run_id, finished_at) \
             VALUES (?, ?, ?, ?, ?, ?, datetime('now')) \
             ON CONFLICT(task_id, generation_id) DO NOTHING",
        )
        .bind(report.task_id.clone())
        .bind(generation_id.to_owned())
        .bind(i64::from(report.attempt))
        .bind(target.to_owned())
        .bind(failure_class(report))
        .bind(report.github_run_id.clone())
        .execute()
        .await
        .map_err(|error| format!("record attempt failure evidence: {error}"))?;
    }
    db.query("DELETE FROM attempt_outcomes_v2 WHERE finished_at < datetime('now', ?)")
        .bind(format!("-{window_minutes} minutes"))
        .execute()
        .await
        .map_err(|error| format!("expire old generation outcome rows: {error}"))?;
    db.query(
        "DELETE FROM attempt_outcome_buckets WHERE bucket < unixepoch('now') - CAST(? AS INTEGER)",
    )
    .bind(i64::from(window_minutes) * 60)
    .execute()
    .await
    .map_err(|error| format!("expire old attempt outcome buckets: {error}"))?;
    Ok(())
}

/// The label a failed attempt is counted under — the error's first line,
/// capped so a stack dump cannot explode the class list, or `unknown`
/// for a failure that carried no error.
fn failure_class(report: &BuildCompleteReport) -> Option<String> {
    const MAX_PREFIX_CHARS: usize = 200;
    if report.success {
        return None;
    }
    Some(
        report
            .error
            .as_deref()
            .and_then(|error| error.lines().next())
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map_or_else(
                || "unknown".to_owned(),
                |line| line.chars().take(MAX_PREFIX_CHARS).collect::<String>(),
            ),
    )
}

/// Bind the run a `build-batch.yml` dispatch response returned to its
/// `build_batches` row — one bind per batch, however many legs it
/// carries (stow#833 §4.2). The claim left `github_run_id` NULL, and
/// the `IS NULL` guard makes the bind write-once: a rebind never
/// overwrites the run a completion is matched against
/// (`done_run_id = github_run_id`). A `completed` delivery that beat
/// this bind is already on the row, so it becomes resolvable the
/// moment the bind lands — provided it names this run: the bind lands
/// only when `done_run_id` is NULL or equal to `github_run_id`, so a
/// row never holds two different runs.
///
/// Returns `true` when the binding landed. `false` means the row is
/// gone or already bound — the caller logs and moves on.
///
/// # Errors
/// [`QueueError::Invariant`] when an early completion from a different
/// run is already on the row: the bind would leave a batch no pass can
/// consume, so the caller fails the dispatch instead.
pub async fn bind_batch_run(
    db: &DurableDb,
    batch_id: &str,
    github_run_id: &str,
) -> Result<bool, QueueError> {
    let result = db
        .query(
            "UPDATE build_batches SET github_run_id = ? \
             WHERE batch_id = ? AND github_run_id IS NULL \
               AND (done_run_id IS NULL OR done_run_id = ?)",
        )
        .bind(github_run_id.to_owned())
        .bind(batch_id.to_owned())
        .bind(github_run_id.to_owned())
        .execute()
        .await
        .map_err(|error| format!("bind dispatch run for batch {batch_id}: {error}"))?;
    if result.rows_written > 0 {
        return Ok(true);
    }
    // Nothing wrote: the row is gone, already bound, or holds an early
    // completion from another run. Only the last is an error.
    let held = db
        .query("SELECT done_run_id FROM build_batches WHERE batch_id = ? AND github_run_id IS NULL")
        .bind(batch_id.to_owned())
        .fetch_scalar_optional::<Option<String>>()
        .await
        .map_err(|error| format!("probe batch {batch_id}: {error}"))?
        .flatten();
    match held {
        Some(done_run_id) if done_run_id != github_run_id => Err(QueueError::Invariant(format!(
            "batch {batch_id} was dispatched as run {github_run_id} but already holds a \
                 completion from run {done_run_id}"
        ))),
        _ => Ok(false),
    }
}

/// A batch whose dispatch failed — the POST, the network, an unreadable
/// response or the token mint (stow#833 §4.2): every leg backs off
/// through [`back_off_dispatch_legs`] and the batch row is deleted,
/// which releases its runner slots. Any run the failure left behind is
/// an orphan whose completion finds no batch row.
async fn fail_batch_dispatch(
    db: &DurableDb,
    settings: &SchedulerSettings,
    batch: &FormedBatch,
    error: &str,
) -> Result<(), QueueError> {
    back_off_dispatch_legs(db, settings, &batch.tasks, error).await?;
    db.query("DELETE FROM build_batches WHERE batch_id = ?")
        .bind(batch.batch_id.as_str().to_owned())
        .execute()
        .await
        .map_err(|db_error| {
            format!(
                "delete failed-dispatch batch {}: {db_error}",
                batch.batch_id
            )
        })?;
    Ok(())
}

/// Persist one batch's dispatch outcome: a returned run id binds the
/// batch row once ([`bind_batch_run`]); a dispatch error — or a bind
/// that could not be written — backs off every leg and deletes the
/// row ([`fail_batch_dispatch`]).
pub async fn persist_batch_dispatch(
    db: &DurableDb,
    settings: &SchedulerSettings,
    batch: &FormedBatch,
    outcome: Result<u64, String>,
) -> Result<(), QueueError> {
    match outcome {
        Ok(run_id) => {
            match bind_batch_run(db, batch.batch_id.as_str(), &run_id.to_string()).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::warn!(
                        batch_id = %batch.batch_id,
                        run_id,
                        "dispatch run binding skipped — the batch row is gone or already bound"
                    );
                }
                Err(error) => {
                    tracing::error!(batch_id = %batch.batch_id, %error, "failed to bind batch dispatch run");
                    fail_batch_dispatch(db, settings, batch, &error.to_string()).await?;
                }
            }
        }
        Err(error) => {
            tracing::error!(batch_id = %batch.batch_id, %error, "failed to dispatch build batch");
            fail_batch_dispatch(db, settings, batch, &error).await?;
        }
    }
    Ok(())
}

/// Record a `build-batch.yml` run's `workflow_run` `completed`
/// delivery on its `build_batches` row — `POST
/// /batches/{batch_id}/complete`'s whole write (stow#833 §3.2).
///
/// The report lands verbatim — `done_run_id`, `done_attempt`,
/// `conclusion`, `done_at` — and the row is marked resolvable now
/// (`resolve_after = now`) for the alarm's resolution pass. The write
/// lands whether or not the dispatch response has bound
/// `github_run_id` yet (§4.2's early-webhook case: resolution later
/// requires `done_run_id = github_run_id`, so the batch row itself
/// holds the early completion), but only for the run the row is bound
/// to: `github_run_id IS NULL OR github_run_id = <run>`. The
/// `done_run_id IS NULL` guard makes a duplicate delivery of the same
/// run a no-op: it touches nothing and still answers Ok.
///
/// # Errors
/// [`QueueError::UnknownBatch`] when no `build_batches` row carries
/// the id — an orphan run from an abandoned dispatch.
/// [`QueueError::Invariant`] when the delivered run is not the one the
/// row is bound to or already recorded: a row naming two runs is in
/// neither the resolution pass's nor the lease check's set.
pub async fn record_batch_completion(
    db: &DurableDb,
    batch_id: &str,
    report: &stow_types::api::BatchRunComplete,
) -> Result<(), QueueError> {
    let run_id = report.run_id.to_string();
    let written = db
        .query(
            "UPDATE build_batches \
             SET done_run_id = ?, done_attempt = ?, conclusion = ?, \
                 done_at = datetime('now'), resolve_after = datetime('now') \
             WHERE batch_id = ? AND done_run_id IS NULL \
               AND (github_run_id IS NULL OR github_run_id = ?)",
        )
        .bind(run_id.clone())
        .bind(i64::from(report.run_attempt))
        .bind(report.conclusion.clone())
        .bind(batch_id.to_owned())
        .bind(run_id.clone())
        .execute()
        .await
        .map_err(|error| format!("record batch completion for {batch_id}: {error}"))?;
    if written.rows_written > 0 {
        return Ok(());
    }
    // Nothing wrote: a duplicate delivery, a run the row is not bound
    // to, or no such batch row.
    let held = db
        .query("SELECT github_run_id, done_run_id FROM build_batches WHERE batch_id = ?")
        .bind(batch_id.to_owned())
        .fetch_optional::<HeldRunsRow>()
        .await
        .map_err(|error| format!("probe batch {batch_id}: {error}"))?
        .ok_or_else(|| QueueError::UnknownBatch(batch_id.to_owned()))?;
    if held.done_run_id.as_deref() == Some(run_id.as_str()) {
        return Ok(());
    }
    Err(QueueError::Invariant(format!(
        "batch {batch_id} is bound to run {} and recorded run {} but a completion named run {run_id}",
        held.github_run_id.as_deref().unwrap_or("-"),
        held.done_run_id.as_deref().unwrap_or("-"),
    )))
}

/// The run ids a `build_batches` row holds, for
/// [`record_batch_completion`]'s mismatch probe.
#[derive(Debug, skyzen::FromRow)]
struct HeldRunsRow {
    github_run_id: Option<String>,
    done_run_id: Option<String>,
}

/// The runner slots a manual wave may still take: the pool and the
/// macOS cap, each less its human-lane reserve and everything in flight
/// (stow#854 §3.2 step 0, §4.4). Pure — the share is computed from the
/// same `count_active_by_family` the claim pass runs, so a registration
/// needs no schema or provenance to stay inside the reserve.
fn manual_share(
    limit: NonZeroU32,
    settings: &SchedulerSettings,
    active: &ActiveByFamily,
) -> ManualShare {
    ManualShare {
        shared: limit
            .get()
            .saturating_sub(settings.human_reserve.shared)
            .saturating_sub(active.total),
        macos: settings
            .max_concurrent_macos_jobs
            .saturating_sub(settings.human_reserve.macos)
            .saturating_sub(active.of(RunnerFamily::MacOs)),
    }
}

/// The slice of a [`ManualShare`] a batch on `family` may draw on: the
/// pool for Linux and Windows, and — a macOS leg needs a pool slot and
/// a macOS slot — the smaller of both for macOS.
fn manual_family_share(share: ManualShare, family: RunnerFamily) -> u32 {
    match family {
        RunnerFamily::MacOs => share.shared.min(share.macos),
        RunnerFamily::Linux | RunnerFamily::Windows => share.shared,
    }
}

/// One leg's queue row as the registration's claim probe reads it.
#[derive(Debug, skyzen::FromRow)]
struct ManualLegProbeRow {
    task_id: String,
    status: String,
    attempt: u32,
    batch_id: Option<String>,
    not_before: String,
    backing_off: i64,
}

/// `POST /manual-batches` — register one `build-batch.yml` batch
/// `preheat manual` is about to dispatch (stow#854 §3.2). The legs'
/// queue rows are claimed into `dispatched` under the driver's own
/// batch id — minted before the send, never here — and one
/// `build_batches` row charges the granted slots. From this call's
/// return onward a lane enqueue writes nothing for the legs and the
/// alarm cannot claim them; the driver then sends the
/// `workflow_dispatch` and reports its outcome to
/// [`record_manual_dispatch`].
///
/// Every statement is a `DurableDb` call with no outbound await, so the
/// whole registration commits in one input-gate tick — the same
/// atomicity `enqueue_inner` relies on, so no claim pass can interleave
/// between the share read and the batch row that charges it.
///
/// The batch's runner family is derived from the legs' targets, never
/// sent. The dispatch-min-age, `deps_met` and `dispatch_eligible` gates
/// are deliberately not applied: the wave's own index-rooted layering
/// is its dependency gate (§4.2).
///
/// # Errors
/// [`QueueError::InvalidManualBatch`] on a malformed batch (mixed rustc
/// or family, a non-CI target, a duplicate or out-of-bounds leg list) —
/// nothing is written. [`QueueError::ManualRegistrationRefused`] while
/// the scheduler is frozen, paused, or carries a reserve at or above
/// its cap — nothing is written. [`QueueError::ManualBatchConflict`] on
/// a batch id that is already a live `build_batches` row.
/// [`QueueError::Invariant`] when the claim probe finds a row
/// `enqueue_inner` just wrote missing, or the claim writes fewer legs
/// than planned — impossible inside the tick.
pub async fn register_manual_batch(
    db: &DurableDb,
    settings: &SchedulerSettings,
    registration: &ManualBatchRegistration,
) -> Result<ManualBatchRegistered, QueueError> {
    let batch_id = registration.batch_id.as_str();
    // Validation — a refused registration writes nothing.
    let (family, task_ids) = validate_manual_legs(registration, settings)?;

    // The scheduler's own postures refuse before anything is written.
    if freeze_enabled(db).await? {
        return Err(QueueError::ManualRegistrationRefused(
            ManualRegistrationRefused::Frozen,
        ));
    }
    let Dispatch::Limited(limit) = settings.dispatch else {
        return Err(QueueError::ManualRegistrationRefused(
            ManualRegistrationRefused::Paused,
        ));
    };
    manual_reserve_within_caps(settings, limit)?;

    // Step 0 — the share, before anything is written: the same
    // `GROUP BY dispatch_family` occupancy the claim pass reads.
    let active = count_active_by_family(db).await?;
    let share = manual_share(limit, settings, &active);
    let family_share = manual_family_share(share, family);
    if family_share == 0 {
        return Ok(ManualBatchRegistered::ShareFull { share });
    }

    // Step 1 — insert absent rows `pending` and apply the existing
    // re-request rules (a `KeysApart` flag gap resurrects a `completed`
    // row); a no-op for everything else.
    enqueue_inner(db, &registration.legs, settings, false).await?;

    // Step 2 — the claim probe, one read per leg by primary key.
    let (claimable, refused) = probe_manual_legs(db, &task_ids).await?;
    // Nothing claimable means no statements at all: `parallelism: 0`
    // carries no `build_batches` row.
    if claimable.is_empty() {
        return Ok(ManualBatchRegistered::Registered {
            parallelism: 0,
            claimed: Vec::new(),
            refused,
            share,
        });
    }
    // Steps 3–5 — mint, claim, and refresh the dependents of legs
    // claimed out of `failed`.
    claim_manual_legs(db, batch_id, &claimable).await?;

    // Step 6 — the batch row. `parallelism` is the granted
    // `max-parallel`: request, claimed legs and the family's share,
    // whichever binds.
    let granted = registration
        .parallelism
        .get()
        .min(u32::try_from(claimable.len()).expect("legs fit u32"))
        .min(family_share);
    insert_manual_batch_row(db, registration, settings, family, granted, claimable.len()).await?;
    let claimed: Vec<ClaimedLeg> = claimable
        .into_iter()
        .enumerate()
        .map(|(leg, (task_id, _, attempt))| ClaimedLeg {
            task_id,
            leg: u32::try_from(leg).expect("a leg index is bounded by batch_max_tasks"),
            attempt,
        })
        .collect();
    // The answer's share is step 0's less this grant — the macOS slot
    // only when the batch actually draws on that cap.
    let share = ManualShare {
        shared: share.shared.saturating_sub(granted),
        macos: if family == RunnerFamily::MacOs {
            share.macos.saturating_sub(granted)
        } else {
            share.macos
        },
    };
    Ok(ManualBatchRegistered::Registered {
        parallelism: granted,
        claimed,
        refused,
        share,
    })
}

/// `register_manual_batch`'s validation, before anything is written:
/// the leg list's bounds and uniformity, and each leg's derived task
/// id. A leg `enqueue_inner` would skip is unreachable — the family
/// check already refused it (the `CI_TARGET_TRIPLES` partition
/// invariant).
fn validate_manual_legs(
    registration: &ManualBatchRegistration,
    settings: &SchedulerSettings,
) -> Result<(RunnerFamily, Vec<String>), QueueError> {
    let legs = registration.legs.as_slice();
    if legs.is_empty() {
        return Err(QueueError::InvalidManualBatch(
            "a manual batch names no legs".to_owned(),
        ));
    }
    if legs.len() as u64 > u64::from(settings.batch_max_tasks) {
        return Err(QueueError::InvalidManualBatch(format!(
            "manual batch of {} legs exceeds STOW_BATCH_MAX_TASKS {}",
            legs.len(),
            settings.batch_max_tasks
        )));
    }
    let mut family: Option<RunnerFamily> = None;
    let mut task_ids: Vec<String> = Vec::with_capacity(legs.len());
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for leg in legs {
        if leg.rustc_version != registration.rustc_version {
            return Err(QueueError::InvalidManualBatch(format!(
                "leg {} builds under rustc {} but the batch is {}",
                leg.crate_name, leg.rustc_version, registration.rustc_version
            )));
        }
        let leg_family = runner_family(leg.target.as_str()).ok_or_else(|| {
            QueueError::InvalidManualBatch(format!(
                "leg {} targets {}, which no CI runner builds",
                leg.crate_name, leg.target
            ))
        })?;
        match family {
            None => family = Some(leg_family),
            Some(batch_family) if batch_family != leg_family => {
                return Err(QueueError::InvalidManualBatch(format!(
                    "leg {} targets {} — a batch never mixes runner families",
                    leg.crate_name, leg.target
                )));
            }
            Some(_) => {}
        }
        let task_id = leg
            .task_id()
            .map_err(|error| QueueError::InvalidManualBatch(error.to_string()))?;
        if !seen.insert(task_id.clone()) {
            return Err(QueueError::InvalidManualBatch(format!(
                "duplicate leg {task_id}"
            )));
        }
        task_ids.push(task_id);
    }
    Ok((
        family.expect("non-empty legs carry a runner family"),
        task_ids,
    ))
}

/// A human reserve at or above its cap leaves a manual wave no slot in
/// any state — a misconfiguration the route fails (the wave's 500)
/// rather than a `ShareFull` it could never leave (§3.2). The check
/// lives here, not in `scheduler_settings`: that function runs on every
/// scheduler route, and a knob only manual registration reads must not
/// take the lanes down.
const fn manual_reserve_within_caps(
    settings: &SchedulerSettings,
    limit: NonZeroU32,
) -> Result<(), QueueError> {
    if settings.human_reserve.shared >= limit.get() {
        return Err(QueueError::ManualRegistrationRefused(
            ManualRegistrationRefused::ReserveExceedsCap {
                binding: "STOW_HUMAN_RESERVED_JOBS",
                reserve: settings.human_reserve.shared,
                cap_binding: "STOW_MAX_CONCURRENT_JOBS",
                cap: limit.get(),
            },
        ));
    }
    if settings.human_reserve.macos >= settings.max_concurrent_macos_jobs {
        return Err(QueueError::ManualRegistrationRefused(
            ManualRegistrationRefused::ReserveExceedsCap {
                binding: "STOW_HUMAN_RESERVED_MACOS_JOBS",
                reserve: settings.human_reserve.macos,
                cap_binding: "STOW_MAX_CONCURRENT_MACOS_JOBS",
                cap: settings.max_concurrent_macos_jobs,
            },
        ));
    }
    Ok(())
}

/// §3.2 step 2 — the claim probe, one keyed read per leg, partitioned
/// claimable/refused in request order. A `failed` row claims as an
/// operator retry (`attempt` restarts at 1); everything else the probe
/// cannot name is `Invariant` — `enqueue_inner` just wrote each row.
async fn probe_manual_legs(
    db: &DurableDb,
    task_ids: &[String],
) -> Result<(Vec<(String, bool, u32)>, Vec<RefusedLeg>), QueueError> {
    let probes = db
        .query(
            "SELECT q.task_id, q.status, q.attempt, q.batch_id, q.not_before, \
                    q.not_before > datetime('now') AS backing_off \
             FROM (SELECT value AS task_id FROM json_each(?) LIMIT -1) AS e \
             JOIN queue q ON q.task_id = e.task_id",
        )
        .bind(enqueue_json(task_ids)?)
        .fetch_all::<ManualLegProbeRow>()
        .await
        .map_err(|error| format!("probe manual batch legs: {error}"))?;
    let probes: BTreeMap<String, ManualLegProbeRow> = probes
        .into_iter()
        .map(|row| (row.task_id.clone(), row))
        .collect();
    // `(task_id, was_failed, attempt)` per claimable leg, in request
    // order.
    let mut claimable: Vec<(String, bool, u32)> = Vec::new();
    let mut refused: Vec<RefusedLeg> = Vec::new();
    for task_id in task_ids {
        let probe = probes.get(task_id).ok_or_else(|| {
            QueueError::Invariant(format!(
                "registered leg {task_id} has no queue row after its enqueue"
            ))
        })?;
        match probe.status.as_str() {
            "failed" => claimable.push((task_id.clone(), true, 1)),
            "pending" if probe.backing_off == 0 => {
                claimable.push((task_id.clone(), false, probe.attempt));
            }
            "pending" => refused.push(RefusedLeg {
                task_id: task_id.clone(),
                reason: LegRefusal::BackingOff {
                    until: probe.not_before.clone(),
                },
            }),
            "dispatched" | "running" => refused.push(RefusedLeg {
                task_id: task_id.clone(),
                reason: LegRefusal::InFlight {
                    batch_id: probe
                        .batch_id
                        .as_deref()
                        .map(str::parse::<BatchId>)
                        .transpose()
                        .map_err(|error| {
                            QueueError::Invariant(format!(
                                "queue row {task_id} carries an unparsable batch id: {error}"
                            ))
                        })?,
                },
            }),
            "completed" => refused.push(RefusedLeg {
                task_id: task_id.clone(),
                reason: LegRefusal::Completed,
            }),
            status => {
                return Err(QueueError::Invariant(format!(
                    "queue row {task_id} holds an unknown status {status:?}"
                )));
            }
        }
    }
    Ok((claimable, refused))
}

/// §3.2 steps 3–5 — one `generation_id` per leg, the single claim
/// statement fenced the way `claim_and_bind`'s is (only `failed` and
/// un-backed-off `pending` rows move, and the `RETURNING` count must
/// match the plan inside one input-gate tick), then
/// `refresh_dependents` for the legs leaving `failed`, as in the
/// `retry` verb.
async fn claim_manual_legs(
    db: &DurableDb,
    batch_id: &str,
    claimable: &[(String, bool, u32)],
) -> Result<(), QueueError> {
    let generation_ids = mint_ids(db, claimable.len()).await?;
    let claims: Vec<LegClaim> = claimable
        .iter()
        .zip(generation_ids)
        .enumerate()
        .map(|(leg, ((task_id, _, _), generation_id))| LegClaim {
            task_id: task_id.clone(),
            generation_id,
            batch_id: batch_id.to_owned(),
            leg: i64::try_from(leg).expect("a leg index is bounded by batch_max_tasks"),
        })
        .collect();
    let won = db
        .query(
            "UPDATE queue \
             SET status = 'dispatched', generation_id = e.generation_id, \
                 attempt = CASE WHEN queue.status = 'failed' THEN 1 ELSE queue.attempt END, \
                 error_msg = CASE WHEN queue.status = 'failed' THEN '' ELSE queue.error_msg END, \
                 dispatch_attempts = dispatch_attempts + 1, github_run_id = NULL, \
                 batch_id = e.batch_id, batch_leg = e.leg, \
                 claimed_at = datetime('now'), updated_at = datetime('now') \
             FROM (SELECT value ->> 'task_id' AS task_id, \
                          value ->> 'generation_id' AS generation_id, \
                          value ->> 'batch_id' AS batch_id, \
                          CAST(value ->> 'leg' AS INTEGER) AS leg \
                   FROM json_each(?) LIMIT -1) AS e \
             WHERE queue.task_id = e.task_id \
               AND (queue.status = 'failed' \
                    OR (queue.status = 'pending' \
                        AND queue.not_before <= datetime('now'))) \
             RETURNING queue.task_id",
        )
        .bind(enqueue_json(&claims)?)
        .fetch_scalars::<String>()
        .await
        .map_err(|error| format!("claim {} manual legs: {error}", claims.len()))?;
    if won.len() != claimable.len() {
        return Err(QueueError::Invariant(format!(
            "manual batch {batch_id} planned {} legs but claimed {}",
            claimable.len(),
            won.len()
        )));
    }
    let retried: Vec<String> = claimable
        .iter()
        .filter(|(_, was_failed, _)| *was_failed)
        .map(|(task_id, _, _)| task_id.clone())
        .collect();
    if !retried.is_empty() {
        refresh_dependents(
            db,
            "SELECT value AS task_id FROM json_each(?)",
            &[DbValue::Text(enqueue_json(&retried)?)],
        )
        .await?;
    }
    Ok(())
}

/// §3.2 step 6 — the batch row, the `insert_batch_rows` shape with
/// `parallelism` already the granted `min`. `DO NOTHING RETURNING`
/// turns the primary-key conflict — a driver never reuses a batch id —
/// into the route's 409 without error-string matching.
async fn insert_manual_batch_row(
    db: &DurableDb,
    registration: &ManualBatchRegistration,
    settings: &SchedulerSettings,
    family: RunnerFamily,
    parallelism: u32,
    legs: usize,
) -> Result<(), QueueError> {
    let batch_id = registration.batch_id.as_str();
    let inserted = db
        .query(
            "INSERT INTO build_batches \
                 (batch_id, rustc_version, dispatch_family, lane, parallelism, legs, \
                  claimed_at, lease_at) \
             VALUES (?, ?, ?, 'miss', ?, ?, datetime('now'), datetime('now', ?)) \
             ON CONFLICT(batch_id) DO NOTHING \
             RETURNING batch_id",
        )
        .bind(batch_id.to_owned())
        .bind(registration.rustc_version.as_str().to_owned())
        .bind(dispatch_family_label(family).to_owned())
        .bind(i64::from(parallelism))
        .bind(i64::try_from(legs).expect("legs fit i64"))
        .bind(format!("+{} minutes", settings.stale_dispatch_minutes))
        .fetch_scalar_optional::<String>()
        .await
        .map_err(|error| format!("insert manual batch {batch_id}: {error}"))?;
    if inserted.is_none() {
        return Err(QueueError::ManualBatchConflict(format!(
            "batch id {batch_id} is already a live batch"
        )));
    }
    Ok(())
}

/// `POST /manual-batches/dispatch` — record what the driver's
/// `workflow_dispatch` came back with (stow#854 §3.3). `Dispatched`
/// binds the run id to the batch row — the same [`bind_batch_run`] the
/// scheduler's own dispatch runs — so the webhook's completion can
/// resolve it. `NotDispatched` releases the claim: the legs return to
/// `pending` and the batch row is deleted. This route never refuses
/// while frozen — the run already exists, and a release is cleanup.
///
/// # Errors
/// [`QueueError::ManualBatchConflict`] when the report disagrees with
/// the row: a `Dispatched` naming a run other than the bound one, or a
/// `NotDispatched` against a row that carries a run or a completion.
/// [`QueueError::Invariant`] from the underlying probes.
pub async fn record_manual_dispatch(
    db: &DurableDb,
    settings: &SchedulerSettings,
    dispatch: &ManualBatchDispatch,
) -> Result<ManualDispatchRecorded, QueueError> {
    let batch_id = dispatch.batch_id.as_str();
    match dispatch.outcome {
        ManualDispatchOutcome::Dispatched { run_id } => {
            let run = run_id.to_string();
            match bind_batch_run(db, batch_id, &run).await {
                Ok(true) => Ok(ManualDispatchRecorded::Bound),
                Ok(false) => {
                    let held = db
                        .query(
                            "SELECT github_run_id, done_run_id FROM build_batches \
                             WHERE batch_id = ?",
                        )
                        .bind(batch_id.to_owned())
                        .fetch_optional::<HeldRunsRow>()
                        .await
                        .map_err(|error| format!("probe batch {batch_id}: {error}"))?;
                    match held {
                        None => Ok(ManualDispatchRecorded::Unknown),
                        Some(row) if row.github_run_id.as_deref() == Some(run.as_str()) => {
                            Ok(ManualDispatchRecorded::AlreadyBound)
                        }
                        Some(row) => Err(QueueError::ManualBatchConflict(format!(
                            "batch {batch_id} is bound to run {} but the driver \
                             reports run {run}",
                            row.github_run_id.as_deref().unwrap_or("-")
                        ))),
                    }
                }
                // An early completion from a different run is the
                // bind's own conflict case (stow#833 §4.2).
                Err(QueueError::Invariant(message)) => {
                    Err(QueueError::ManualBatchConflict(message))
                }
                Err(error) => Err(error),
            }
        }
        ManualDispatchOutcome::NotDispatched => {
            let held = db
                .query(
                    "SELECT github_run_id, done_run_id FROM build_batches \
                     WHERE batch_id = ?",
                )
                .bind(batch_id.to_owned())
                .fetch_optional::<HeldRunsRow>()
                .await
                .map_err(|error| format!("probe batch {batch_id}: {error}"))?;
            match held {
                None => Ok(ManualDispatchRecorded::Unknown),
                Some(row) if row.github_run_id.is_some() || row.done_run_id.is_some() => {
                    Err(QueueError::ManualBatchConflict(format!(
                        "batch {batch_id} holds run {} but the driver reports \
                         nothing was sent",
                        row.github_run_id
                            .as_deref()
                            .or(row.done_run_id.as_deref())
                            .unwrap_or("-")
                    )))
                }
                Some(_) => {
                    requeue_unbound_batch(db, settings, batch_id).await?;
                    Ok(ManualDispatchRecorded::Released)
                }
            }
        }
    }
}

/// A `build_batches` row ready for the alarm's resolution pass, with
/// the queue rows bound to it (stow#833 §3.2).
#[derive(Debug)]
pub struct ReadyBatch {
    /// `build_batches.batch_id`.
    pub batch_id: String,
    /// The run the batch is bound to and its completion named —
    /// `done_run_id = github_run_id` guards the same id twice.
    pub run_id: u64,
    /// The run attempt the completion named — the jobs page is read
    /// pinned to it.
    pub done_attempt: u32,
    /// The batch key's rustc — the records tag namespace each
    /// leg's artifact check reads.
    pub rustc_version: String,
    /// The run's reported conclusion (`success`, `failure`,
    /// `startup_failure`, …) — the leg classifier's run-level input.
    pub conclusion: String,
    /// The batch's legs — queue rows carrying its `batch_id`, ordered
    /// by `batch_leg`, the leg index in the dispatched payload's
    /// `tasks` list.
    pub legs: Vec<ReadyBatchLeg>,
    /// The batch's absolute deadline in epoch milliseconds
    /// ([`batch_ceiling_ms`]): a resolution that still has no answer at
    /// this instant fails the batch ([`defer_unresolved_batch`]).
    pub ceiling_ms: i64,
}

/// One leg row of a [`ReadyBatch`] — the generation `resolve_batch`
/// applies the leg's outcome under.
#[derive(Debug)]
pub struct ReadyBatchLeg {
    /// The leg's queue task.
    pub task_id: String,
    /// The generation the claim minted for this leg — the completion
    /// fence's operand.
    pub generation_id: String,
    /// The queue attempt the dispatch carried.
    pub attempt: u32,
    /// The leg's index in the batch's `tasks` list — its position in
    /// `classify_legs`' outcome order, which `resolve_batch`'s
    /// `resolutions` indexing follows.
    pub batch_leg: u32,
}

/// The `build_batches` columns [`ready_batches`] selects.
#[derive(Debug, skyzen::FromRow)]
struct ReadyBatchRow {
    batch_id: String,
    rustc_version: String,
    done_run_id: String,
    done_attempt: u32,
    conclusion: String,
    legs: u32,
    parallelism: u32,
    claimed_epoch: i64,
}

/// A queue row as a batch's leg walk reads it.
#[derive(Debug, skyzen::FromRow)]
struct BatchLegRow {
    batch_id: String,
    task_id: String,
    generation_id: String,
    attempt: u32,
    batch_leg: Option<i64>,
}

/// The batches whose `completed` delivery is bound and due —
/// `done_run_id = github_run_id` (an early completion before the
/// dispatch response's binding waits) and `resolve_after <= now` (a
/// deferred jobs page inside its settle window waits) — each carrying
/// its legs in `batch_leg` order.
///
/// `now_ms` is the caller's epoch-ms clock, rendered to the
/// `datetime()` text `resolve_after` stores by the predicate itself.
///
/// The read is bounded by the batches in flight, not by queue size:
/// at most the scheduler's family slot caps over
/// `STOW_BATCH_PARALLELISM` — ⌈45/k⌉ miss batches plus the human
/// lane's — rows, each holding at most `STOW_BATCH_MAX_TASKS` legs.
/// The alarm's resolution drive names this as its stated bound
/// (stow#833 §3.2). No `ORDER BY`: no caller depends on batch order
/// (legs arrive keyed by `batch_id`), and ordering by `batch_id`
/// would steer the planner onto the primary key — a walk of every
/// in-flight batch — instead of `idx_build_batches_resolve`'s bounded
/// `resolve_after<?` range.
///
/// # Errors
/// [`QueueError::Invariant`] when a row's run id is not numeric or its
/// `parallelism` is zero — corrupt state.
pub async fn ready_batches(db: &DurableDb, now_ms: i64) -> Result<Vec<ReadyBatch>, QueueError> {
    let batches = db
        .query(
            "SELECT batch_id, rustc_version, done_run_id, done_attempt, conclusion, \
                    legs, parallelism, \
                    CAST(strftime('%s', claimed_at) AS INTEGER) AS claimed_epoch \
             FROM build_batches \
             WHERE done_run_id = github_run_id \
               AND resolve_after <= datetime(CAST(? AS INTEGER) / 1000, 'unixepoch')",
        )
        .bind(now_ms)
        .fetch_all::<ReadyBatchRow>()
        .await
        .map_err(|error| format!("list resolvable batches: {error}"))?;
    if batches.is_empty() {
        return Ok(Vec::new());
    }
    // One keyed read for every ready batch's legs — `idx_queue_batch`
    // serves each batch's `batch_leg` walk, never a queue scan.
    let ids: Vec<String> = batches.iter().map(|batch| batch.batch_id.clone()).collect();
    let mut legs = batch_legs(db, &ids).await?;
    batches
        .into_iter()
        .map(|batch| {
            let run_id = batch.done_run_id.parse::<u64>().map_err(|error| {
                QueueError::Invariant(format!(
                    "batch {} is bound to run {:?}: {error}",
                    batch.batch_id, batch.done_run_id
                ))
            })?;
            let ceiling_ms = batch_ceiling_ms(
                &batch.batch_id,
                batch.claimed_epoch,
                batch.legs,
                batch.parallelism,
            )?;
            Ok(ReadyBatch {
                legs: legs.remove(&batch.batch_id).unwrap_or_default(),
                batch_id: batch.batch_id,
                rustc_version: batch.rustc_version,
                run_id,
                done_attempt: batch.done_attempt,
                conclusion: batch.conclusion,
                ceiling_ms,
            })
        })
        .collect()
}

/// The leg rows of the named batches, grouped by `batch_id` in
/// `batch_leg` order — one `json_each`-bound read no matter how many
/// batches the pass holds.
async fn batch_legs(
    db: &DurableDb,
    batch_ids: &[String],
) -> Result<BTreeMap<String, Vec<ReadyBatchLeg>>, QueueError> {
    let rows = db
        .query(
            "SELECT batch_id, task_id, generation_id, attempt, batch_leg \
             FROM queue \
             WHERE batch_id IN (SELECT value FROM json_each(?)) \
             ORDER BY batch_id, batch_leg",
        )
        .bind(enqueue_json(batch_ids)?)
        .fetch_all::<BatchLegRow>()
        .await
        .map_err(|error| format!("load batch legs: {error}"))?;
    let mut legs: BTreeMap<String, Vec<ReadyBatchLeg>> = BTreeMap::new();
    for row in rows {
        legs.entry(row.batch_id.clone())
            .or_default()
            .push(ready_leg(&row)?);
    }
    Ok(legs)
}

/// Decode one stored leg row — a queue row carrying `batch_id` always
/// carries its `batch_leg` index with it, so a `NULL` or unreadable
/// index is corrupt state, not a leg to skip.
fn ready_leg(row: &BatchLegRow) -> Result<ReadyBatchLeg, QueueError> {
    let batch_leg = row
        .batch_leg
        .and_then(|leg| u32::try_from(leg).ok())
        .ok_or_else(|| {
            QueueError::Invariant(format!(
                "task {} is bound to batch {} with batch_leg {:?}",
                row.task_id, row.batch_id, row.batch_leg
            ))
        })?;
    Ok(ReadyBatchLeg {
        task_id: row.task_id.clone(),
        generation_id: row.generation_id.clone(),
        attempt: row.attempt,
        batch_leg,
    })
}

/// One settled leg's resolution — what [`resolve_batch`] applies to
/// the leg's queue row (stow#833 §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegResolution {
    /// The leg's jobs succeeded and its signed records artifact is in
    /// GHCR. The build-cost sample is the leg's runner time — its
    /// build job's `started_at` to its publish job's `completed_at`,
    /// in whole milliseconds — never claim-to-completion across the
    /// batch's rounds.
    Succeeded {
        /// The leg's runner time in milliseconds.
        duration_ms: i64,
    },
    /// The leg failed — `error` is the §4.1 text the queue row's
    /// `error_msg`, the outcome evidence's `failure_class` and the
    /// breaker's trip report all read.
    Failed {
        /// The §4.1 error text.
        error: String,
    },
}

/// Map one classified leg to its queue resolution (stow#833 §4.1).
///
/// `None` is "no answer yet" — a leg job still running, or a failed
/// job's step rows inside their settle window: the caller defers the
/// batch with [`defer_batch`] rather than resolving it.
///
/// `records_present` is the GHCR check's answer for a [`LegOutcome::
/// Succeeded`] leg — a success without its signed records artifact
/// resolves as the records-absent failure (stow#655). `task_id`
/// names the leg's task in that text and `run_url` is the run's
/// Actions URL — the only pointer a `startup_failure` run, which
/// holds no jobs at all, can carry for its legs. Both are ignored
/// otherwise: every other row of the table reads off the failure the
/// classifier carried.
#[must_use]
pub fn leg_resolution(
    outcome: &LegOutcome,
    records_present: bool,
    task_id: &str,
    run_url: &str,
) -> Option<LegResolution> {
    match outcome {
        LegOutcome::Unsettled => None,
        LegOutcome::Succeeded {
            started_at,
            completed_at,
            ..
        } if records_present => Some(LegResolution::Succeeded {
            duration_ms: i64::try_from((*completed_at - *started_at).whole_milliseconds())
                .expect("a leg's runner time fits i64"),
        }),
        LegOutcome::Succeeded { .. } => Some(LegResolution::Failed {
            error: stow_types::records::missing_records_error(task_id),
        }),
        LegOutcome::Failed(failure) => Some(LegResolution::Failed {
            error: match failure {
                LegFailure::Run(RunFailure::Verdict {
                    job,
                    step,
                    html_url,
                }) => format!("verdict: {job} / {step} ({html_url})"),
                // `job: "-"` is the classifier's documented mark of a
                // run no job ever failed — `startup_failure` — so the
                // run itself is the pointer.
                LegFailure::Run(RunFailure::Infrastructure { job, .. }) if job == "-" => {
                    format!("infrastructure: startup_failure ({run_url})")
                }
                LegFailure::Run(RunFailure::Infrastructure {
                    job,
                    step,
                    html_url,
                }) => {
                    format!(
                        "infrastructure: {job} / {} ({html_url})",
                        step.as_deref().unwrap_or("-")
                    )
                }
                LegFailure::Concluded {
                    job,
                    conclusion,
                    html_url,
                } => format!("{conclusion}: {job} ({html_url})"),
                LegFailure::Invariant(message) => format!("invariant: {message}"),
            },
        }),
    }
}

/// Every expected leg's outcome for a ready batch, indexed by leg
/// number — `classify_legs` over the legs' task hashes (stow#833
/// §4.1). A leg index with no queue row still occupies its slot: its
/// placeholder hash mismatches whatever the page carries for it,
/// which is exactly that phantom leg's invariant failure.
///
/// A structural `classify_legs` error — an unreadable job name, a
/// leg index past the batch — becomes every leg's
/// [`LegFailure::Invariant`]: the run is ours, so an undecodable
/// page fails the batch once, never retries it forever.
#[must_use]
pub fn leg_outcomes(
    batch: &ReadyBatch,
    jobs: &[RunJobRow],
    now: time::OffsetDateTime,
) -> Vec<LegOutcome> {
    let leg_count = batch
        .legs
        .iter()
        .map(|leg| leg.batch_leg)
        .max()
        .map_or(0, |max| {
            usize::try_from(max + 1).expect("leg index + 1 fits usize")
        });
    let mut expected = vec![TaskHash::of(""); leg_count];
    for leg in &batch.legs {
        expected[usize::try_from(leg.batch_leg).expect("u32 leg index fits usize")] =
            TaskHash::of(&leg.task_id);
    }
    match stow_types::runs::classify_legs(&expected, &batch.conclusion, jobs, now) {
        Ok(outcomes) => outcomes,
        Err(error) => vec![LegOutcome::Failed(LegFailure::Invariant(error.to_string())); leg_count],
    }
}

/// Each leg's settled resolution for a ready batch, indexed by leg
/// number — `None` where the leg's outcome is still unsettled, which
/// defers the whole batch (stow#833 §3.2).
///
/// `records_present(leg)` answers the GHCR check for a `Succeeded`
/// leg's records artifact; it is consulted only on successes.
#[must_use]
pub fn batch_resolutions(
    batch: &ReadyBatch,
    jobs: &[RunJobRow],
    records_present: impl Fn(u32) -> bool,
    now: time::OffsetDateTime,
) -> Vec<Option<LegResolution>> {
    let outcomes = leg_outcomes(batch, jobs, now);
    let run_url = stow_types::runs::run_url(&batch.run_id.to_string());
    let task_ids: BTreeMap<u32, &str> = batch
        .legs
        .iter()
        .map(|leg| (leg.batch_leg, leg.task_id.as_str()))
        .collect();
    outcomes
        .iter()
        .enumerate()
        .map(|(index, outcome)| {
            let leg_index = u32::try_from(index).expect("leg index fits u32");
            leg_resolution(
                outcome,
                records_present(leg_index),
                task_ids.get(&leg_index).copied().unwrap_or(""),
                &run_url,
            )
        })
        .collect()
}

/// Apply a resolved batch's legs to their queue rows and release the
/// batch's slots (stow#833 §3.2, §4.1).
///
/// Every leg goes through [`complete`]'s own contract under the
/// batch's run id — the generation fence, the under-`MAX_BUILD_
/// ATTEMPTS` retry/backoff write and the outcome evidence — with the
/// leg's `generation_id`/`attempt` read live from its queue row, and
/// its build sample carrying the resolution's runner-time
/// `duration_ms` rather than claim-to-completion. A leg whose row
/// moved on — cancelled, requeued, claimed into another generation —
/// is refused by that fence and ignored, never an error (§4.2's
/// "binding misses" case). Deleting the `build_batches` row last is
/// what releases the batch's `parallelism` slots.
///
/// `resolutions[i]` is leg `i`'s settled outcome — the order
/// `classify_legs` answers in. Every leg is settled: an unsettled leg
/// is the caller's [`defer_batch`] case, not this function's.
///
/// Returns whether any *applied* leg failed, so the caller evaluates
/// the freeze breaker once per batch — a fenced-off leg applied
/// nothing, so its outcome counts for nothing either.
///
/// # Errors
/// [`QueueError::Invariant`] when a leg row's `batch_leg` is unreadable
/// or names a leg `resolutions` does not cover — corrupt state, never
/// a skippable leg.
pub async fn resolve_batch(
    db: &DurableDb,
    settings: &SchedulerSettings,
    batch: &ReadyBatch,
    resolutions: &[LegResolution],
    window_minutes: u32,
) -> Result<bool, QueueError> {
    let batch_id = batch.batch_id.as_str();
    let mut any_failure = false;
    for leg in &batch.legs {
        let resolution = resolutions
            .get(usize::try_from(leg.batch_leg).expect("u32 fits usize on every stow target"))
            .ok_or_else(|| {
                QueueError::Invariant(format!(
                    "batch {batch_id} resolved {} legs but task {} names leg {}",
                    resolutions.len(),
                    leg.task_id,
                    leg.batch_leg
                ))
            })?;
        let (success, error, sample_ms) = match resolution {
            LegResolution::Succeeded { duration_ms } => (true, None, Some(*duration_ms)),
            LegResolution::Failed { error } => (false, Some(error.clone()), None),
        };
        let report = BuildCompleteReport {
            task_id: leg.task_id.clone(),
            generation_id: leg.generation_id.clone(),
            attempt: leg.attempt,
            success,
            error,
            github_run_id: Some(batch.run_id.to_string()),
            sample_ms,
        };
        let applied = match complete(db, settings, &report, window_minutes).await {
            Ok(()) => true,
            Err(QueueError::UnknownTask(_) | QueueError::StaleCompletion { .. }) => false,
            Err(error) => return Err(error),
        };
        any_failure |= applied && !report.success;
    }
    db.query("DELETE FROM build_batches WHERE batch_id = ?")
        .bind(batch_id.to_owned())
        .execute()
        .await
        .map_err(|error| format!("delete resolved batch {batch_id}: {error}"))?;
    Ok(any_failure)
}

/// Push a batch's resolution out to `until_ms`: any leg still
/// unsettled — a job not yet `completed`, or a failed job's step rows
/// inside their settle window — keeps the batch open for the next
/// pass (stow#833 §3.2's 30 s deferral).
///
/// The push itself has no bound; the deadline is the batch's ceiling,
/// which [`defer_unresolved_batch`] applies — the pass defers a ready
/// batch only through it.
pub async fn defer_batch(db: &DurableDb, batch_id: &str, until_ms: i64) -> Result<(), QueueError> {
    db.query(
        "UPDATE build_batches \
         SET resolve_after = datetime(CAST(? AS INTEGER) / 1000, 'unixepoch') \
         WHERE batch_id = ?",
    )
    .bind(until_ms)
    .bind(batch_id.to_owned())
    .execute()
    .await
    .map_err(|error| format!("defer batch {batch_id}: {error}"))?;
    Ok(())
}

/// What became of a batch a pass could not settle this time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchRetry {
    /// The batch is inside its ceiling: its next look moved out.
    Deferred,
    /// The batch reached its ceiling still unreadable or unsettled: its
    /// in-flight legs failed and the row is released.
    Failed,
}

/// A ready batch the resolution pass has no answer for — a jobs page
/// read error, a records check error, legs still settling, a token
/// mint failure. Inside the batch's ceiling its resolution moves out to
/// `now_ms + defer_ms`; at or past it the batch fails
/// ([`fail_batch_past_ceiling`]) so the row never holds its slots or the
/// alarm beyond its deadline.
pub async fn defer_unresolved_batch(
    db: &DurableDb,
    batch: &ReadyBatch,
    now_ms: i64,
    defer_ms: i64,
) -> Result<BatchRetry, QueueError> {
    if now_ms >= batch.ceiling_ms {
        tracing::error!(
            batch_id = %batch.batch_id,
            run_id = batch.run_id,
            "batch results unreadable or unsettled past its ceiling — failing its legs"
        );
        fail_batch_past_ceiling(db, &batch.batch_id, CeilingFailure::ResolutionStalled).await?;
        return Ok(BatchRetry::Failed);
    }
    defer_batch(db, &batch.batch_id, now_ms + defer_ms).await?;
    Ok(BatchRetry::Deferred)
}

pub async fn status(db: &DurableDb) -> Result<SchedulerStatus, QueueError> {
    // The counts are trigger-maintained (schema.sql's
    // `queue_counts_on_*`): this read is the handful of (status, lane)
    // counter rows, never a pass over the queue.
    let rows = db
        .query("SELECT status, lane, blocked, n AS count FROM queue_status_counts")
        .fetch_all::<StatusLaneCountRow>()
        .await
        .map_err(|error| format!("count queue by status and lane: {error}"))?;
    let mut pending = 0_u64;
    let mut human_pending = 0_u64;
    let mut dispatched = 0_u64;
    let mut running = 0_u64;
    let mut completed = 0_u64;
    let mut failed = 0_u64;
    let mut blocked = 0_u64;
    for row in rows {
        match row.status.as_str() {
            "pending" => {
                pending += row.count;
                if row.blocked != 0 {
                    blocked += row.count;
                }
                if row.lane == TaskLane::Human.as_str() {
                    human_pending += row.count;
                }
            }
            "dispatched" => dispatched += row.count,
            "running" => running += row.count,
            "completed" => completed += row.count,
            "failed" => failed += row.count,
            _ => {}
        }
    }
    Ok(SchedulerStatus {
        pending: u64_to_u32(pending, "pending task count")?,
        human_pending: u64_to_u32(human_pending, "human pending task count")?,
        dispatched: u64_to_u32(dispatched, "dispatched task count")?,
        running: u64_to_u32(running, "running task count")?,
        completed: u64_to_u32(completed, "completed task count")?,
        failed: u64_to_u32(failed, "failed task count")?,
        blocked: u64_to_u32(blocked, "blocked task count")?,
    })
}

/// Point-in-time view of one queue row. `None` when the task id is not in
/// the queue; the request API batches through [`tasks_status`], so the
/// single-id form exists for tests.
#[cfg(test)]
pub async fn task_status(
    db: &DurableDb,
    task_id: &str,
) -> Result<Option<RequestStatus>, QueueError> {
    let row = db
        .query(&format!(
            "SELECT task_id, crate_name, version, features_json, target, rustc_version, lane, \
             ({}) AS status, preserve_lockfile, dispatch_key, \
             ({}) AS blocked_by \
             FROM queue WHERE task_id = ?",
            effective_status_sql(),
            blocked_by_sql()
        ))
        .bind(task_id.to_owned())
        .fetch_optional::<RequestStatusRow>()
        .await
        .map_err(|error| format!("load task {task_id}: {error}"))?;
    match row {
        Some(row) => Ok(Some(request_status(db, row).await?)),
        None => Ok(None),
    }
}

/// Batch form of [`task_status`] for the request API's per-target root
/// lookups; skips ids with no queue row and preserves the input order.
pub async fn tasks_status(
    db: &DurableDb,
    task_ids: &[String],
) -> Result<Vec<RequestStatus>, QueueError> {
    if task_ids.is_empty() {
        return Ok(Vec::new());
    }
    // One IN-clause select per batch: a per-id loop issued a point
    // select for every id — an N+1 on a hot request path.
    let mut by_id =
        std::collections::HashMap::<String, RequestStatusRow>::with_capacity(task_ids.len());
    for chunk in task_ids.chunks(crate::sql_batch::SQLITE_IN_CLAUSE_BATCH_SIZE) {
        let sql = format!(
            "SELECT task_id, crate_name, version, features_json, target, rustc_version, lane, \
             ({}) AS status, preserve_lockfile, dispatch_key, \
             ({}) AS blocked_by \
             FROM queue WHERE task_id IN ({})",
            effective_status_sql(),
            blocked_by_sql(),
            crate::sql_batch::placeholders(chunk.len())
        );
        let mut query = db.query(&sql);
        for task_id in chunk {
            query = query.bind(task_id.clone());
        }
        let rows = query
            .fetch_all::<RequestStatusRow>()
            .await
            .map_err(|error| format!("load tasks status batch: {error}"))?;
        for row in rows {
            by_id.insert(row.task_id.clone(), row);
        }
    }
    let mut statuses = Vec::with_capacity(by_id.len());
    for task_id in task_ids {
        if let Some(row) = by_id.remove(task_id) {
            statuses.push(request_status(db, row).await?);
        }
    }
    Ok(statuses)
}

/// Map a queue row to its wire status, computing the human-lane position
/// for pending human rows.
async fn request_status(
    db: &DurableDb,
    row: RequestStatusRow,
) -> Result<RequestStatus, QueueError> {
    let lane = TaskLane::parse(&row.lane).ok_or_else(|| {
        QueueError::Invariant(format!(
            "task {} has unknown lane `{}`",
            row.task_id, row.lane
        ))
    })?;
    let status = QueueTaskStatus::parse(&row.status).ok_or_else(|| {
        QueueError::Invariant(format!(
            "task {} has unknown status `{}`",
            row.task_id, row.status
        ))
    })?;
    let human_lane_position = if lane == TaskLane::Human && status == QueueTaskStatus::Pending {
        Some(human_lane_position(db, &row).await?)
    } else {
        None
    };
    Ok(RequestStatus {
        task_id: row.task_id,
        crate_name: CrateName::parse(row.crate_name)?,
        version: CrateVersion::new(semver::Version::parse(&row.version).map_err(|error| {
            QueueError::Invariant(format!("stored version `{}`: {error}", row.version))
        })?),
        features_json: FeaturesJson::from_sorted(
            serde_json::from_str(&row.features_json)
                .map_err(|error| QueueError::Invariant(format!("stored features_json: {error}")))?,
        )?,
        target: TargetTriple::parse(row.target)?,
        rustc_version: WireRustcVersion::parse(row.rustc_version)?,
        lane,
        status,
        human_lane_position,
        preserve_lockfile: row.preserve_lockfile != 0,
        blocked_by: row.blocked_by,
    })
}

/// 1-based position of a pending human task in dispatch order: the number
/// of pending human rows that sort ahead of it (matching the
/// `claim_dispatchable_tasks` ordering) plus one.
async fn human_lane_position(db: &DurableDb, row: &RequestStatusRow) -> Result<u32, QueueError> {
    // The position must equal `claim_dispatchable_tasks` dispatch order,
    // so it compares the same persisted ordering tuple the claim walk
    // orders on: `dispatch_key` (inverted `value` first, then the FIFO
    // tie-breakers), one TEXT column instead of a duplicated comparison
    // formula. TEXT is also the only lossless transport for this
    // magnitude — `value` outgrows the JS-safe integer range the
    // workerd cursor can decode (>2^53), so no `value` scalar may cross
    // the row/bind boundary.
    let sql = "SELECT count(*) AS count FROM queue q \
         WHERE q.lane = 'human' AND q.status = 'pending' \
           AND q.dispatch_key < ?";
    let ahead = db
        .query(sql)
        .bind(row.dispatch_key.clone())
        .fetch_scalar::<u64>()
        .await
        .map_err(|error| format!("compute human lane position: {error}"))?;
    u64_to_u32(ahead + 1, "human lane position")
}

// --------------------------------------------------------------------
// Human request records (`requests` table, stow#428)
//
// One row per admitted request id. The edge's admission writes it and
// the same call dispatches the resolve run; the `workflow_run`
// `in_progress` event flips it to `resolving`; the job's outcome report
// lands the tasks and flips `enqueued` — or `failed` — and the
// `completed` event is the backstop for a run that dies mid-flight.
// The stored `outcome_json` roots are re-probed against the live queue
// on every status read, so a `queued` report keeps answering where the
// row actually is rather than where it was at submit time.

/// A `requests` row as stored — `state` holds a [`CrateRequestPhase`]'s
/// `snake_case` name and `outcome_json` the settled attempt's stored roots.
#[derive(Debug, skyzen::FromRow)]
struct RequestRecord {
    request_id: String,
    attempt: i64,
    crate_name: String,
    version: String,
    features_json: String,
    rustc_version: String,
    state: String,
    github_run_id: Option<String>,
    github_run_url: Option<String>,
    outcome_json: Option<String>,
    error: Option<String>,
}

/// The per-target root `outcome_json` stores: the resolve job's
/// [`RequestRootOutcome`] plus whether the root's queue row already
/// existed when the outcome's enqueue ran — the fact a status read
/// needs to tell `queued` (the request's own work) from
/// `already_queued` (a row the request found).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RequestStoredRoot {
    /// The CI target this root serves.
    target: String,
    /// The lib-root task id — `None` for a crate with no library.
    task_id: Option<String>,
    /// The published slice already served the root at resolve time.
    cached: bool,
    /// The root's queue row existed before the outcome's enqueue.
    was_queued: bool,
}

/// The dedup decision `admit_request` hands back.
#[derive(Debug)]
pub enum RequestAdmissionStep {
    /// The record inserted (or a `failed` one re-attempted): dispatch the
    /// resolve run for this attempt.
    Dispatch {
        /// The record's live attempt — stamps the run name and payload.
        attempt: u32,
    },
    /// A live record already serves this request id — answer it as-is.
    Existing,
}

/// The `requests` table's `state` strings ↔ [`CrateRequestPhase`].
fn request_phase(state: &str) -> Result<stow_types::api::CrateRequestPhase, QueueError> {
    use stow_types::api::CrateRequestPhase as Phase;
    match state {
        "accepted" => Ok(Phase::Accepted),
        "resolving" => Ok(Phase::Resolving),
        "enqueued" => Ok(Phase::Enqueued),
        "failed" => Ok(Phase::Failed),
        other => Err(QueueError::Invariant(format!(
            "stored request state `{other}`"
        ))),
    }
}

/// Read one request record, or `None` when the id is unknown.
async fn load_request(
    db: &DurableDb,
    request_id: &str,
) -> Result<Option<RequestRecord>, QueueError> {
    db.query(
        "SELECT request_id, attempt, crate_name, version, features_json, \
         rustc_version, state, github_run_id, github_run_url, \
         outcome_json, error FROM requests WHERE request_id = ?",
    )
    .bind(request_id.to_owned())
    .fetch_optional::<RequestRecord>()
    .await
    .map_err(|error| format!("load request {request_id}: {error}").into())
}

/// `POST /requests` admission. A live record answers as found (the
/// request deduplicates on its deterministic id); a `failed` one
/// re-attempts — `attempt + 1` in the same conditional write, so the
/// run-name's `a{attempt}` leg keeps a stale run's webhook events off
/// the live attempt. Both spend a resolve run, so the insertion is
/// gated on today's human-lane budget having any room at all — the
/// enqueue's own charge still applies at outcome time; this probe only
/// refuses a dispatch whose tasks can never land.
pub async fn admit_request(
    db: &DurableDb,
    admission: &stow_types::api::RequestAdmission,
    dispatched_at: i64,
    settings: &SchedulerSettings,
) -> Result<RequestAdmissionStep, QueueError> {
    if let Some(record) = load_request(db, &admission.request_id).await?
        && record.state != "failed"
    {
        return Ok(RequestAdmissionStep::Existing);
    }
    let spent = db
        .query("SELECT task_count FROM human_daily_task_budget WHERE day = date('now')")
        .fetch_scalar_optional::<i64>()
        .await
        .map_err(|error| format!("probe human daily task budget: {error}"))?
        .unwrap_or(0);
    if spent >= i64::from(settings.human_daily_task_budget) {
        return Err(QueueError::HumanDailyBudgetExhausted {
            attempted: 1,
            budget: u64::from(settings.human_daily_task_budget),
        });
    }
    // One conditional write: a fresh id inserts at attempt 1; the
    // conflict arm only fires for a `failed` row, re-attempting it.
    let attempt = db
        .query(
            "INSERT INTO requests (request_id, attempt, crate_name, version, \
             features_json, rustc_version, state, dispatched_at) \
             VALUES (?, 1, ?, ?, ?, ?, 'accepted', ?) \
             ON CONFLICT(request_id) DO UPDATE SET \
             attempt = attempt + 1, state = 'accepted', \
             dispatched_at = excluded.dispatched_at, github_run_id = NULL, \
             github_run_url = NULL, outcome_json = NULL, error = NULL \
             WHERE requests.state = 'failed' \
             RETURNING attempt",
        )
        .bind(admission.request_id.clone())
        .bind(admission.crate_name.as_str().to_owned())
        .bind(admission.version.to_string())
        .bind(admission.features_json.raw().clone())
        .bind(admission.rustc_version.as_str().to_owned())
        .bind(dispatched_at)
        .fetch_scalar_optional::<i64>()
        .await
        .map_err(|error| format!("admit request {}: {error}", admission.request_id))?;
    match attempt {
        Some(attempt) => Ok(RequestAdmissionStep::Dispatch {
            attempt: u64_to_u32(
                u64::try_from(attempt).unwrap_or_default(),
                "request attempt",
            )?,
        }),
        // The conflict arm's `state = 'failed'` guard rejected the
        // update: a live record exists — answer it rather than
        // dispatching a second run.
        None => Ok(RequestAdmissionStep::Existing),
    }
}

/// The dispatch-failure write — flips the live attempt `failed` naming
/// the dispatch error, so a later re-request's re-attempt (which keys on
/// `failed`) can retry.
pub async fn fail_request_dispatch(
    db: &DurableDb,
    request_id: &str,
    attempt: u32,
    error: &str,
) -> Result<(), QueueError> {
    db.query(
        "UPDATE requests SET state = 'failed', error = ? \
         WHERE request_id = ? AND attempt = ? AND state = 'accepted'",
    )
    .bind(error.to_owned())
    .bind(request_id.to_owned())
    .bind(i64::from(attempt))
    .execute()
    .await
    .map_err(|error| format!("mark request {request_id} dispatch-failed: {error}"))?;
    Ok(())
}

/// `POST /requests/{id}/outcome` — apply the resolve job's report.
///
/// A `Resolved` report enqueues its batch through the trusted lane
/// (verbatim — the resolver already pinned each identity, so the
/// canonicalization the admin submit route applies would only rewrite
/// the ids the report names), computes `was_queued` from a pre-enqueue
/// probe, stores the per-target roots, and flips the record `enqueued`
/// in one conditional write. A `Failed` report — or the trusted
/// enqueue's own refusal — flips it `failed` with the reason. Reports
/// naming a superseded attempt answer `RequestAttemptSuperseded`; a
/// report on an already-settled record is a no-op that re-answers the
/// stored state.
pub async fn apply_request_outcome(
    db: &DurableDb,
    settings: &SchedulerSettings,
    request_id: &str,
    report: &stow_types::api::RequestOutcomeReport,
) -> Result<stow_types::api::CrateRequestStatus, QueueError> {
    let mut record = load_request(db, request_id)
        .await?
        .ok_or_else(|| QueueError::UnknownRequest(request_id.to_owned()))?;
    if record.attempt != i64::from(report.attempt) {
        return Err(QueueError::RequestAttemptSuperseded {
            request_id: request_id.to_owned(),
            live: u64_to_u32(
                u64::try_from(record.attempt).unwrap_or_default(),
                "request attempt",
            )?,
            reported: report.attempt,
        });
    }
    if matches!(record.state.as_str(), "enqueued" | "failed") {
        return request_record_status(db, &record).await;
    }
    match &report.outcome {
        stow_types::api::RequestOutcome::Failed { error } => {
            fail_request(db, request_id, report.attempt, error).await?;
            record.state.clone_from(&"failed".to_owned());
            record.error = Some(error.clone());
            request_record_status(db, &record).await
        }
        stow_types::api::RequestOutcome::Resolved { tasks, roots } => {
            resolve_request_record(db, settings, &mut record, report.attempt, tasks, roots).await
        }
    }
}

/// The `Resolved` arm of [`apply_request_outcome`]: probe the roots for
/// `was_queued` before the enqueue, run the batch through the trusted
/// insert path, then settle the record `enqueued` with its stored roots
/// in one conditional write — the `state IN ('accepted', 'resolving')`
/// guard keeps a `completed` webhook racing the other way from erasing
/// the outcome.
async fn resolve_request_record(
    db: &DurableDb,
    settings: &SchedulerSettings,
    record: &mut RequestRecord,
    attempt: u32,
    tasks: &[EnqueueRequest],
    roots: &[stow_types::api::RequestRootOutcome],
) -> Result<stow_types::api::CrateRequestStatus, QueueError> {
    // `was_queued` distinguishes the request's own enqueue from a
    // row it found — probe before the insert, assemble after it.
    let root_ids: Vec<String> = roots
        .iter()
        .filter_map(|root| root.task_id.clone())
        .collect();
    let queued_before: BTreeSet<String> = tasks_status(db, &root_ids)
        .await?
        .into_iter()
        .map(|status| status.task_id)
        .collect();
    if let Err(error) = enqueue_trusted(db, tasks, settings).await {
        fail_request(db, &record.request_id, attempt, &error.to_string()).await?;
        return Err(error);
    }
    let by_id: BTreeMap<String, RequestStatus> = tasks_status(db, &root_ids)
        .await?
        .into_iter()
        .map(|status| (status.task_id.clone(), status))
        .collect();
    let mut stored = Vec::with_capacity(roots.len());
    let mut targets = Vec::with_capacity(roots.len());
    for root in roots {
        let root_id = root.task_id.as_deref().unwrap_or_default();
        let outcome = crate::dependency_resolver::crate_request_target(
            &root.target,
            root_id,
            root.cached,
            root.task_id.is_some(),
            queued_before.contains(root_id),
            by_id.get(root_id),
        )
        .map_err(|error| QueueError::Invariant(format!("request root {}: {error}", root.target)))?;
        targets.push(outcome);
        stored.push(RequestStoredRoot {
            target: root.target.as_str().to_owned(),
            task_id: root.task_id.clone(),
            cached: root.cached,
            was_queued: queued_before.contains(root_id),
        });
    }
    let outcome_json = serde_json::to_string(&stored)
        .map_err(|error| QueueError::Invariant(format!("encode request roots: {error}")))?;
    db.query(
        "UPDATE requests SET state = 'enqueued', outcome_json = ? \
         WHERE request_id = ? AND attempt = ? AND state IN ('accepted', 'resolving')",
    )
    .bind(outcome_json)
    .bind(record.request_id.clone())
    .bind(i64::from(attempt))
    .execute()
    .await
    .map_err(|error| format!("settle request {} outcome: {error}", record.request_id))?;
    record.state.clone_from(&"enqueued".to_owned());
    record.error = None;
    Ok(stow_types::api::CrateRequestStatus {
        request_id: record.request_id.clone(),
        crate_name: CrateName::parse(record.crate_name.clone())?,
        version: CrateVersion::new(semver::Version::parse(&record.version).map_err(|error| {
            QueueError::Invariant(format!("stored version `{}`: {error}", record.version))
        })?),
        features_json: FeaturesJson::from_sorted(
            serde_json::from_str(&record.features_json)
                .map_err(|error| QueueError::Invariant(format!("stored features_json: {error}")))?,
        )?,
        rustc_version: WireRustcVersion::parse(record.rustc_version.clone())?,
        status: stow_types::api::CrateRequestPhase::Enqueued,
        targets,
        error: None,
        github_run_id: record.github_run_id.clone(),
        github_run_url: record.github_run_url.clone(),
    })
}

/// The `failed` transition the outcome route shares — one conditional
/// write so the report and the run-update backstop can never disagree
/// about which settled a live attempt first.
async fn fail_request(
    db: &DurableDb,
    request_id: &str,
    attempt: u32,
    error: &str,
) -> Result<(), QueueError> {
    db.query(
        "UPDATE requests SET state = 'failed', error = ? \
         WHERE request_id = ? AND attempt = ? AND state IN ('accepted', 'resolving')",
    )
    .bind(error.to_owned())
    .bind(request_id.to_owned())
    .bind(i64::from(attempt))
    .execute()
    .await
    .map_err(|error| format!("fail request {request_id}: {error}"))?;
    Ok(())
}

/// `POST /requests/{id}/run-update` — the `workflow_run` webhook's
/// resolve-run lifecycle signal.
///
/// `in_progress` flips `accepted` → `resolving` and records the run id.
/// `completed` is the backstop: one conditional `UPDATE` flips a
/// still-live attempt to `failed`, so a record already `enqueued`
/// through its outcome route is never overwritten — a successful run's
/// outcome report lands before its `completed` event almost always, and
/// when it doesn't the record fails as "completed without an outcome".
pub async fn record_request_run_update(
    db: &DurableDb,
    request_id: &str,
    update: &stow_types::api::RequestRunUpdate,
) -> Result<(), QueueError> {
    let record = load_request(db, request_id)
        .await?
        .ok_or_else(|| QueueError::UnknownRequest(request_id.to_owned()))?;
    if record.attempt != i64::from(update.attempt) {
        return Err(QueueError::RequestAttemptSuperseded {
            request_id: request_id.to_owned(),
            live: u64_to_u32(
                u64::try_from(record.attempt).unwrap_or_default(),
                "request attempt",
            )?,
            reported: update.attempt,
        });
    }
    match update.action {
        stow_types::api::RequestRunAction::InProgress => {
            db.query(
                "UPDATE requests SET state = 'resolving', \
                 github_run_id = ?, github_run_url = ? \
                 WHERE request_id = ? AND attempt = ? AND state = 'accepted'",
            )
            .bind(update.run_id.clone())
            .bind(update.run_url.clone())
            .bind(request_id.to_owned())
            .bind(i64::from(update.attempt))
            .execute()
            .await
            .map_err(|error| format!("mark request {request_id} resolving: {error}"))?;
        }
        stow_types::api::RequestRunAction::Completed => {
            let error = match update.conclusion.as_deref() {
                Some("success") => "resolve run completed without an outcome report".to_owned(),
                conclusion => {
                    let url = update
                        .run_url
                        .as_deref()
                        .map_or_else(String::new, |url| format!(" ({url})"));
                    format!(
                        "resolve run concluded '{}'{url}",
                        conclusion.unwrap_or("unknown")
                    )
                }
            };
            db.query(
                "UPDATE requests SET state = 'failed', error = ?, \
                 github_run_id = ?, github_run_url = ? \
                 WHERE request_id = ? AND attempt = ? \
                 AND state IN ('accepted', 'resolving')",
            )
            .bind(error)
            .bind(update.run_id.clone())
            .bind(update.run_url.clone())
            .bind(request_id.to_owned())
            .bind(i64::from(update.attempt))
            .execute()
            .await
            .map_err(|error| format!("mark request {request_id} run-failed: {error}"))?;
        }
    }
    Ok(())
}

/// `GET /requests/{id}` — the request record's live status, or `None`
/// when the id is unknown. An `enqueued` record's stored roots re-probe
/// the live queue on every read, so the per-target states keep moving
/// (`queued` → `building` → `cached`) after the outcome landed.
pub async fn crate_request_status(
    db: &DurableDb,
    request_id: &str,
) -> Result<Option<stow_types::api::CrateRequestStatus>, QueueError> {
    match load_request(db, request_id).await? {
        Some(record) => Ok(Some(request_record_status(db, &record).await?)),
        None => Ok(None),
    }
}

/// Assemble the wire status for a record — re-probing stored roots
/// against the live queue when the record settled `enqueued`.
async fn request_record_status(
    db: &DurableDb,
    record: &RequestRecord,
) -> Result<stow_types::api::CrateRequestStatus, QueueError> {
    let phase = request_phase(&record.state)?;
    let targets = if phase == stow_types::api::CrateRequestPhase::Enqueued {
        let roots: Vec<RequestStoredRoot> = serde_json::from_str(
            record.outcome_json.as_deref().unwrap_or("[]"),
        )
        .map_err(|error| QueueError::Invariant(format!("stored request outcome_json: {error}")))?;
        let ids: Vec<String> = roots
            .iter()
            .filter_map(|root| root.task_id.clone())
            .collect();
        let by_id: BTreeMap<String, RequestStatus> = tasks_status(db, &ids)
            .await?
            .into_iter()
            .map(|status| (status.task_id.clone(), status))
            .collect();
        roots
            .iter()
            .map(|root| {
                let root_id = root.task_id.as_deref().unwrap_or_default();
                crate::dependency_resolver::crate_request_target(
                    &TargetTriple::parse(root.target.clone())?,
                    root_id,
                    root.cached,
                    root.task_id.is_some(),
                    root.was_queued,
                    by_id.get(root_id),
                )
                .map_err(|error| {
                    QueueError::Invariant(format!("stored request root {}: {error}", root.target))
                })
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };
    Ok(stow_types::api::CrateRequestStatus {
        request_id: record.request_id.clone(),
        crate_name: CrateName::parse(record.crate_name.clone())?,
        version: CrateVersion::new(semver::Version::parse(&record.version).map_err(|error| {
            QueueError::Invariant(format!("stored version `{}`: {error}", record.version))
        })?),
        features_json: FeaturesJson::from_sorted(
            serde_json::from_str(&record.features_json)
                .map_err(|error| QueueError::Invariant(format!("stored features_json: {error}")))?,
        )?,
        rustc_version: WireRustcVersion::parse(record.rustc_version.clone())?,
        status: phase,
        targets,
        error: record.error.clone(),
        github_run_id: record.github_run_id.clone(),
        github_run_url: record.github_run_url.clone(),
    })
}

/// The dependency edge's unsatisfied half: the live published generation
/// for the dependency's own `(target, rustc_version)` slice does not
/// serve every unit shape the dependent's build looks the dep up under.
/// `dep` is the `queue_dependencies` alias, `owner` the dependent's
/// `queue` alias — they differ between the gate (`d`/`q`) and the status
/// derivation (`bd`/`queue`).
///
/// The shapes an edge needs are the ones the dependent's own build
/// compiles the dep's units at. The enqueue's dependency resync
/// computes them at edge-write time into `dep_invocations` — the bitmask of cargo
/// invocation spellings (bit 0 = native, bit 1 = `--target`) the dep's
/// units must be published under — and `dep_shapes`, the
/// distinct-(invocation, linked) pairs that implies:
/// * a target-side dep needs the linked and unlinked units of its own
///   node's one invocation spelling — the build shape and the check
///   shape `cargo check` serves;
/// * a host-side dep needs only linked units — cargo links host units
///   in every phase, so the unlinked host shape does not exist — under
///   each spelling the dependent compiles: a native dependent the
///   native shape, a cross dependent the `--target` shape, a host-side
///   dependent — which compiles deps under both spellings — both.
///
/// `p.unit_invocation + 1` maps the stored invocation (0 = native,
/// 1 = `--target`) onto its bit.
pub(super) fn dep_edge_unpublished_sql(dep: &str) -> String {
    // The live generation is a scalar lookup on the slice marker's
    // primary key `(target, rustc_version)`, so each edge probes one
    // marker row instead of joining the marker table. A missing marker
    // yields NULL and therefore matches no published generation.
    dep_edge_unpublished_sql_at(
        dep,
        &format!(
            "(SELECT s.generation FROM published_slices s \
             WHERE s.target = {dep}.dep_target \
               AND s.rustc_version = {dep}.dep_rustc_version)"
        ),
    )
}

/// [`dep_edge_unpublished_sql`] with the live generation supplied by
/// the caller as a SQL expression — a literal or a bound `?` — for the
/// one caller that already knows it: the slice-commit gate delta, where
/// a correlated probe would re-seek the same marker row once per edge.
fn dep_edge_unpublished_sql_at(dep: &str, generation: &str) -> String {
    // The BETWEEN bounds are the enum domains phrased so SQLite keeps a
    // bounded suffix range on the published-row primary key.
    format!(
        "(SELECT count(*) \
             FROM published_slice_rows p \
             WHERE p.target = {dep}.dep_target \
               AND p.rustc_version = {dep}.dep_rustc_version \
               AND p.generation = {generation} \
               AND p.crate_name = {dep}.dep_crate_name \
               AND p.version = {dep}.dep_version \
               AND p.features_json = {dep}.dep_features_json \
               AND p.dependency_identity = {dep}.dep_dependency_identity \
               AND p.unit_side = {dep}.dep_host_side \
               AND p.unit_invocation BETWEEN 0 AND 1 \
               AND p.unit_linked BETWEEN 0 AND 1 \
               AND ({dep}.dep_host_side = 0 OR p.unit_linked = 1) \
               AND ({dep}.dep_invocations & (p.unit_invocation + 1)) != 0 \
            ) < {dep}.dep_shapes"
    )
}

/// The gate itself: a task is dispatchable only when every dependency
/// edge resolves to a row the latest published index slice serves for
/// the dependency's own `(target, rustc_version)` — the host slice for a
/// host unit. The slice's membership is what the index-publish path last
/// reported it serves; the dependency's queue status never enters the
/// gate.
///
/// Ordering is correctness, not a cache-locality optimization: a
/// dependent dispatched before its dependency is servable compiles the
/// dependency itself instead of being served it from the signed slice.
/// A dependency that fails keeps its dependents waiting through its
/// retries' backoffs; a dependency that exhausts them leaves the
/// dependents settled behind it undispatched, released only when it
/// is later built and published.
///
/// `unpublished_deps` as a SQL expression over the owner's row: the
/// count of its unmet edges. Each edge's `dep_met` flag is written at
/// insert and flipped by slice deltas, so the count is a keyed probe of
/// the owner's own edges — never a slice join (stow#521).
pub(super) fn unpublished_deps_sql(owner_task: &str) -> String {
    format!(
        "(SELECT count(*) FROM queue_dependencies d \
            WHERE d.task_id = {owner_task} AND d.dep_met = 0)"
    )
}

/// `deps_met` as a SQL expression over the owner's row: `1` while every
/// edge resolves to units the live published slice serves — the
/// `unpublished_deps = 0` derivation, evaluated as a count of unmet
/// edges rather than a slice EXISTS per edge. Written at edge sync and
/// refreshed by slice publish — the two places an edge's answer can
/// change — so the claim walk and the
/// alarm's wake probes read the flag instead of re-evaluating the gate
/// per pending row.
pub(super) fn deps_met_sql(owner_task: &str) -> String {
    format!(
        "CASE WHEN {} = 0 THEN 1 ELSE 0 END",
        unpublished_deps_sql(owner_task)
    )
}

/// `blocked` as a SQL expression over the owner's row: `1` while a
/// pending row owns an edge whose dep failed AND whose required units
/// the live published slice does not serve — exactly the predicate the
/// derived `blocked` status evaluated per row on every read before the
/// flag existed. Written wherever `deps_met` is, and refreshed on the
/// dependents of a task that flips into or out of `failed` — dep
/// failure is the one event outside an owner's own writes that moves
/// the answer.
pub(super) fn blocked_sql(owner_task: &str) -> String {
    format!(
        "CASE WHEN EXISTS ( \
            SELECT 1 FROM queue_dependencies bd \
            LEFT JOIN queue bdep ON bdep.task_id = bd.depends_on_task_id \
            WHERE bd.task_id = {owner_task} \
              AND bdep.status = 'failed' \
              AND bd.dep_met = 0 \
        ) THEN 1 ELSE 0 END"
    )
}

/// `wake_at` as a SQL expression — the earliest instant the row is
/// dispatchable: the later of `first_requested_at + dispatch_min_age`
/// and the `not_before` backoff gate. The human lane pays no minimum
/// age, so its wake is just `not_before`. The operands take SQL
/// expressions — a statement assigning `not_before` in the same UPDATE
/// must pass the assigned expression, since SET terms read the
/// pre-update row.
pub(super) fn wake_at_sql(
    lane: &str,
    first_at: &str,
    not_before: &str,
    min_age_minutes: u32,
) -> String {
    format!(
        "CASE WHEN {lane} = 'human' THEN {not_before} \
         ELSE MAX(datetime({first_at}, '+{min_age_minutes} minutes'), {not_before}) END"
    )
}

/// Default for `STOW_MIN_DISPATCH_VALUE`: no admission floor — every
/// dispatchable row claims, as before the floor existed.
const DEFAULT_MIN_DISPATCH_VALUE: i64 = 0;

/// The `dispatch_eligible` column's derivation (stow#525 I10):
/// `lane = 'human' OR value >= floor`. The human lane is exempt by
/// contract — a request someone asked for by name is never held by the
/// floor. `floor` is the authoritative `min_dispatch_value` row the
/// operator reset stamps into `settings` — decimal text, `CAST` to
/// SQLite's integer domain in place, so no wide value ever crosses a
/// JS bind/cursor boundary; an absent row reads as the default `0`
/// (admit everything). Every writer that assigns `value` or
/// `lane` evaluates this expression in the same statement — SET terms
/// see the pre-update row, so the `value` operand is the expression
/// being assigned ([`value_sql`]), never the stale column.
///
/// The admission expression with an explicit floor operand — the shape
/// the settings-row formula shares, used by
/// [`apply_dispatch_floor`]'s pass, which must evaluate against the
/// configured value before the row recording it exists, and by the cost
/// gate's floor snapshot.
pub(super) fn dispatch_eligible_at_floor_sql(lane: &str, value: &str, floor: &str) -> String {
    format!("CASE WHEN ({lane}) = 'human' OR ({value}) >= ({floor}) THEN 1 ELSE 0 END")
}

pub(super) fn dispatch_eligible_sql(lane: &str, value: &str) -> String {
    dispatch_eligible_at_floor_sql(
        lane,
        value,
        "COALESCE((SELECT CAST(s.value AS INTEGER) \
             FROM settings s WHERE s.key = 'min_dispatch_value'), 0)",
    )
}

/// The runner family of a `target` column/expression as SQL — persisted
/// as `dispatch_family` so the alarm's probes equality-filter by family
/// without carrying the target list into Rust.
pub(super) fn dispatch_family_sql(target_sql: &str) -> String {
    let list = |family: RunnerFamily| {
        family
            .targets()
            .iter()
            .map(|target| format!("'{target}'"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "CASE WHEN {target_sql} IN ({}) THEN 'macos' \
              WHEN {target_sql} IN ({}) THEN 'windows' ELSE 'linux' END",
        list(RunnerFamily::MacOs),
        list(RunnerFamily::Windows)
    )
}

/// The `dispatch_family` value a `RunnerFamily` maps to — the literal
/// half of [`dispatch_family_sql`]'s CASE, for the alarm's exclusion
/// probes. `Windows` and `MacOs` have their own labels; every other
/// family shares `linux` (the only other runner pool).
const fn dispatch_family_label(family: RunnerFamily) -> &'static str {
    match family {
        RunnerFamily::MacOs => "macos",
        RunnerFamily::Windows => "windows",
        RunnerFamily::Linux => "linux",
    }
}

/// `AND <column> IN ('<family>', …)` — "every family except the
/// saturated ones" rendered as equality over `RunnerFamily::ALL` minus
/// `saturated`, derived from the type so a new family can never drift
/// from the exclusion, and never `!=` or `NOT IN`. Both callers get the
/// term unconditionally: on `idx_queue_wake` the family column is the
/// last equality column before the `wake_at` range, where a missing
/// term — like an inequality — cannot bound the range, so SQLite falls
/// back to reading every eligible pending row, which made a burst of N
/// future-wake misses cost N reads on every alarm pass and every
/// deliver (stow#833). The IN list expands into one seek per surviving
/// family, so each probe reads only the families that can dispatch
/// (stow#588) — an empty `saturated` renders `IN` over every family.
/// The claim page's [`dispatchable_page_sql`] puts `dispatch_family`
/// behind its `dispatch_key` range, where the extra `IN` is a residual
/// term and the page's plan is unchanged.
fn dispatch_family_in_sql(column: &str, saturated: &[RunnerFamily]) -> String {
    let families = RunnerFamily::ALL
        .iter()
        .filter(|family| !saturated.contains(family))
        .map(|family| format!("'{}'", dispatch_family_label(*family)))
        .collect::<Vec<_>>();
    if families.is_empty() {
        // Every family saturated: no row can dispatch — a literal
        // false keeps the probe's shape.
        return "AND 0".to_owned();
    }
    format!("AND {column} IN ({})", families.join(", "))
}

/// `queue.value` as a SQL expression — the persisted raw integer the
/// dispatch rank divides by expected cost: precedence bands over the
/// baseline `priority` plus accumulated `demand` (stow#522 — kept
/// inside the priority band by the route's `PRIORITY_MAX` bound).
/// The writers derive this in Rust through
/// [`crate::scheduler::rank::raw_value`]; the SQL form survives only
/// for the fixture's bulk seed, where per-row Rust computation is not
/// possible inside the `INSERT … SELECT`. A statement assigning an
/// operand column in the same UPDATE must pass the assigned
/// expression, since SET terms read the pre-update row.
pub(super) fn value_sql(lane: &str, family: &str, priority: &str, demand: &str) -> String {
    format!(
        "((CASE WHEN ({lane}) = 'human' THEN 2 ELSE 0 END) + \
          (CASE WHEN ({family}) = 'windows' THEN 1 ELSE 0 END)) * {VALUE_BAND} \
         + MAX(0, ({priority})) + MAX(0, ({demand}))"
    )
}

/// The `(task_id, value, dispatch_key)` pair a keyed rank refresh
/// binds — `value` travels as decimal text (never a JSON number, whose
/// IEEE-754 parse would round bands above `2^53`) and the statement
/// casts it back to the INTEGER column.
#[derive(serde::Serialize)]
struct KeyUpdate {
    task_id: String,
    lane: String,
    value: String,
    dispatch_key: String,
}

/// The operand columns a rank refresh loads losslessly per touched
/// row — everything [`crate::scheduler::rank::dispatch_key`] consumes
/// — plus the row's stored pair for the no-op diff and its
/// `(crate_name, target)` median via `crate_build_stats` (1 while
/// unmeasured, matching a fresh insert's answer).
#[derive(Debug, skyzen::FromRow)]
struct RankSourceRow {
    task_id: String,
    lane: String,
    dispatch_family: String,
    priority: String,
    demand: String,
    first_requested_at: String,
    created_at: String,
    value: String,
    dispatch_key: String,
    median_ms: Option<String>,
}

/// The SELECT every keyed refresh shares — operand columns plus the
/// pair's stored state and the keyed cost join. Every potentially
/// wide INTEGER crosses the wire as TEXT: the Durable Object's JSON
/// number crossing loses integer precision past `2^53`, the very
/// range the exact rank exists to preserve.
const RANK_SOURCE_SELECT: &str = "SELECT q.task_id, q.lane, q.dispatch_family, \
            CAST(q.priority AS TEXT) AS priority, \
            CAST(q.demand AS TEXT) AS demand, \
            q.first_requested_at, q.created_at, \
            CAST(q.value AS TEXT) AS value, q.dispatch_key, \
            CAST(s.median_ms AS TEXT) AS median_ms \
     FROM queue q LEFT JOIN crate_build_stats s \
       ON s.crate_name = q.crate_name AND s.target = q.target";

/// The parsed, invariant-checked form of a [`RankSourceRow`]: every
/// field the rank abstraction consumes as a checked Rust type.
/// `cost_ms` is [`crate::scheduler::rank::UNMEASURED_COST`] only for a
/// genuinely absent stat — a present stat that fails `checked_cost`
/// fails the writer, never silently reverts to 1.
struct RankRow {
    task_id: String,
    lane: String,
    dispatch_family: String,
    priority: i64,
    demand: i64,
    first_requested_at: String,
    created_at: String,
    value: i64,
    dispatch_key: String,
    cost_ms: NonZero<i64>,
}

impl RankSourceRow {
    fn checked(&self) -> Result<RankRow, QueueError> {
        let parse_i64 = |field: &str, text: &str| {
            text.parse::<i64>().map_err(|_| {
                QueueError::Invariant(format!(
                    "queue task {}: {field} {text:?} is not an integer",
                    self.task_id
                ))
            })
        };
        let cost_ms = match self.median_ms.as_deref() {
            None => crate::scheduler::rank::UNMEASURED_COST,
            Some(median) => crate::scheduler::rank::checked_cost(median)?,
        };
        Ok(RankRow {
            task_id: self.task_id.clone(),
            lane: self.lane.clone(),
            dispatch_family: self.dispatch_family.clone(),
            priority: parse_i64("priority", &self.priority)?,
            demand: parse_i64("demand", &self.demand)?,
            first_requested_at: self.first_requested_at.clone(),
            created_at: self.created_at.clone(),
            value: parse_i64("value", &self.value)?,
            dispatch_key: self.dispatch_key.clone(),
            cost_ms,
        })
    }
}

/// One row's fresh `(value, dispatch_key)` from its operands —
/// `None` when the stored pair already agrees, so a refresh writes
/// only the rows that actually moved.
fn key_update_for(row: &RankRow) -> Option<KeyUpdate> {
    let value = crate::scheduler::rank::raw_value(
        &row.lane,
        &row.dispatch_family,
        row.priority,
        row.demand,
    );
    let dispatch_key = crate::scheduler::rank::dispatch_key(&crate::scheduler::rank::KeyOperands {
        lane: &row.lane,
        family: &row.dispatch_family,
        priority: row.priority,
        demand: row.demand,
        cost_ms: row.cost_ms,
        first_requested_at: &row.first_requested_at,
        created_at: &row.created_at,
        task_id: &row.task_id,
    });
    (value != row.value || dispatch_key != row.dispatch_key).then(|| KeyUpdate {
        task_id: row.task_id.clone(),
        lane: row.lane.clone(),
        value: value.to_string(),
        dispatch_key,
    })
}

/// Checked-parse a batch of loaded [`RankSourceRow`]s and derive the
/// pairs that moved — the checked form is what the rank abstraction
/// may consume, and any violated invariant fails the writer rather
/// than writing a key from clamped data.
fn rank_updates(rows: &[RankSourceRow]) -> Result<Vec<KeyUpdate>, QueueError> {
    rows.iter()
        .map(|row| row.checked().map(|checked| key_update_for(&checked)))
        .collect::<Result<Vec<_>, _>>()
        .map(|updates| updates.into_iter().flatten().collect())
}

/// Write the recomputed pairs the diff produced, keyed by task id —
/// an empty update list skips the statement entirely.
async fn apply_key_updates(db: &DurableDb, updates: &[KeyUpdate]) -> Result<(), QueueError> {
    if updates.is_empty() {
        return Ok(());
    }
    // One bound JSON operand per chunk — a refresh over an unbounded
    // pending set must not serialize the whole key list into one
    // statement, same as every other keyed batch.
    for chunk in updates.chunks(ENQUEUE_JSON_BATCH_ROWS) {
        db.query(&format!(
            "UPDATE queue \
             SET value = CAST(j.e ->> 'value' AS INTEGER), \
                 dispatch_key = j.e ->> 'dispatch_key', \
                 dispatch_eligible = {eligible} \
             FROM (SELECT value AS e FROM json_each(?)) AS j \
             WHERE queue.task_id = j.e ->> 'task_id'",
            // A moved pair may flip the floor answer (lane or value
            // changed): it re-derives in the same statement from the
            // bound row, so eligibility never trails the key it guards.
            eligible = dispatch_eligible_sql("j.e ->> 'lane'", "CAST(j.e ->> 'value' AS INTEGER)",),
        ))
        .bind(enqueue_json(chunk)?)
        .execute()
        .await
        .map_err(|error| format!("write refreshed dispatch keys: {error}"))?;
    }
    Ok(())
}

/// Recount `unpublished_deps` for a task-id set — the only places an
/// edge's answer changes are edge writes (here, after the batch's
/// resync) and slice writes ([`record_published_slice`], which moves the
/// counter by ±1 per flipped edge). The recount is unconditional: the
/// counter stays live on every status — a resynced non-pending row's
/// stale count would otherwise corrupt the ±1 arithmetic the next
/// slice delta applies. `deps_met` re-derives alongside the count;
/// `blocked` recomputes on pending rows alone — a stale value on
/// another status is never observed. The `!=` guards keep `changes()`
/// honest: an unchanged row does not count as written.
///
/// The `task_id IN` drives the update — the statement visits exactly
/// the named rows, never the pending group.
async fn refresh_deps_met_tasks(db: &DurableDb, task_ids: &[String]) -> Result<(), QueueError> {
    for chunk in task_ids.chunks(ENQUEUE_JSON_BATCH_ROWS) {
        db.query(&format!(
            // `f` materializes the named rows' fresh answers — one
            // queue probe, one unmet-edge count, and (pending rows
            // only) one `blocked` evaluation each — so `deps_met` and
            // the `!=` guards read columns instead of re-running the
            // probes (the `LIMIT -1` stops the flattening that would
            // duplicate them). Non-pending rows keep `blocked` from
            // their own row: the flag is never observed there.
            "UPDATE queue \
             SET unpublished_deps = f.unpublished, deps_met = f.met, \
                 blocked = f.blocked \
             FROM (SELECT y.tid, y.unpublished, \
                          CASE WHEN y.unpublished = 0 THEN 1 ELSE 0 END AS met, \
                          CASE WHEN y.status = 'pending' THEN {bexpr} \
                               ELSE y.blocked END AS blocked \
                   FROM (SELECT j.value AS tid, {uexpr} AS unpublished, \
                                q.status AS status, q.blocked AS blocked \
                         FROM json_each(?) AS j \
                         CROSS JOIN queue q ON q.task_id = j.value \
                         LIMIT -1) AS y \
                   LIMIT -1) AS f \
             WHERE queue.task_id = f.tid \
               AND (queue.unpublished_deps != f.unpublished \
                    OR queue.deps_met != f.met \
                    OR queue.blocked != f.blocked)",
            uexpr = unpublished_deps_sql("j.value"),
            bexpr = blocked_sql("y.tid"),
        ))
        .bind(enqueue_json(chunk)?)
        .execute()
        .await
        .map_err(|error| format!("refresh gate counters for enqueued tasks: {error}"))?;
    }
    Ok(())
}

/// Recompute `blocked` on the pending dependents of a set of dep tasks —
/// the refresh a dep's own status change owes them (`unpublished_deps`
/// never moves on a status flip: the counter counts slice answers, not
/// dep statuses). `dep_set` is a SELECT yielding the dep task ids (a
/// `json_each` arm, a queue subquery re-running a mutation's selector,
/// or a single `SELECT ?`): it drives `idx_queue_dependencies_dep` in
/// pinned `CROSS JOIN` order, then the owners' id list drives the
/// UPDATE, so the pass reads in proportion to the dep set's dependents
/// — never the queue.
async fn refresh_dependents(
    db: &DurableDb,
    dep_set_sql: &str,
    binds: &[DbValue],
) -> Result<(), QueueError> {
    let sql = format!(
        "UPDATE queue SET blocked = {bexpr} \
         WHERE task_id IN ( \
             SELECT o.task_id FROM ({dep_set_sql}) AS s \
             CROSS JOIN queue_dependencies d ON d.depends_on_task_id = s.task_id \
             CROSS JOIN queue o ON o.task_id = d.task_id AND o.status = 'pending') \
           AND blocked != {bexpr}",
        bexpr = blocked_sql("queue.task_id"),
    );
    let mut query = db.query(&sql);
    for bind in binds {
        query = query.bind(bind.clone());
    }
    query
        .execute()
        .await
        .map_err(|error| format!("refresh dependents' gate answers: {error}"))?;
    Ok(())
}

/// Recompute `value` and `dispatch_key` for a task-id set after a
/// mutation that may have moved a row's lane or priority (re-request
/// humanization, revive priority bump) — the two claim-order columns
/// always refresh together, since the key orders on the exact
/// `value / expected_cost` rank. The rows and their medians load
/// losslessly in one keyed probe, the shared Rust abstraction derives
/// each pair, and the write is a keyed `json_each` update over only
/// the rows whose pair actually moved — a row already carrying the
/// right pair writes nothing, and a chunk with none skips the UPDATE.
async fn refresh_dispatch_keys(db: &DurableDb, task_ids: &[String]) -> Result<(), QueueError> {
    for chunk in task_ids.chunks(ENQUEUE_JSON_BATCH_ROWS) {
        let rows = db
            .query(&format!(
                "{RANK_SOURCE_SELECT} \
                 WHERE q.task_id IN (SELECT value FROM json_each(?))"
            ))
            .bind(enqueue_json(chunk)?)
            .fetch_all::<RankSourceRow>()
            .await
            .map_err(|error| format!("load rows for dispatch-key refresh: {error}"))?;
        let updates = rank_updates(&rows)?;
        apply_key_updates(db, &updates).await?;
    }
    Ok(())
}

/// The largest `batch_id` a demand request may carry.
const MAX_DEMAND_BATCH_ID_BYTES: usize = 128;

/// The entry cap one demand batch may carry — each entry is one keyed
/// closure walk, so the cap also bounds a request's statement count.
const MAX_DEMAND_BATCH_ENTRIES: usize = 256;

/// The statuses demand may touch: rows that can still dispatch. The
/// walk stops at `completed` and in-flight (`dispatched`/`running`)
/// rows — those nodes either are served or already own a runner — and
/// at edges whose slice answer is `dep_met = 1`.
const UNBUILT_STATUSES: &str = "'pending', 'failed'";

/// `POST /demand` — a trusted demand batch (stow#522 I7). Every entry
/// names a host-side-free node identity (the Analytics Engine source
/// omits the side): the union of its unbuilt root rows — both compile
/// sides — and their unbuilt dependency closures over unmet edges is
/// its touched set. The entry's delta lands once per touched task —
/// the `UNION` walk dedups diamonds and cycles — while distinct
/// identities contribute their own deltas to a task they share.
///
/// Durability is a typed batch record, not a payload blob:
/// `demand_batches` stores the canonical input's blake3 fingerprint,
/// the touched count, and a `prepared`/`accepted` state — never the
/// contribution set itself, which lives relationally as
/// `demand_contributions` rows keyed by `(task_id, batch_id)` and
/// staged in JSON chunks bounded well under the workerd string limit.
/// A delivery whose record says `accepted` answers from the header —
/// stored count, no writes, no live walk — and a same-id delivery
/// whose canonical fingerprint differs fails before any write, draft
/// or accepted. Only a `prepared` record may be retried: staging is
/// not a promise, so the same input recomputes the CURRENT closure,
/// clears only this batch's own staged rows, re-stages, and accepts —
/// a later admission can never wedge an accepted remainder, because
/// no such state exists.
///
/// Acceptance is the last statement, and it is atomic: the guarded
/// `UPDATE` flipping `prepared` to `accepted` fires the `demand_fold`
/// trigger, which folds every staged delta into
/// `demand`/`value`/`dispatch_key` inside that one statement, verifies
/// the staged count reached the accepted count, then retires this
/// batch's staged rows — an accepted batch's replay reads only the
/// header, so consumed staging cannot accumulate (stow#523). A
/// failure anywhere — including the trigger's own `RAISE(ABORT)` —
/// rolls back the transition AND all triggered queue effects, staged
/// rows preserved for accept-or-retry. Once it returns, the batch is
/// complete; nothing accepted is ever applied again. `value` and
/// `dispatch_key` refresh for the event's own closure only.
///
/// A batch id is a window identity, not a lookup key: the first
/// accepted payload wins the id. Input order and duplicate identities
/// are canonicalized by summing per-identity deltas into the sorted
/// `BTreeMap` below, so two spellings of the same observation share
/// one fingerprint; a legitimately different hour is a different
/// batch id (#523 names them).
///
/// Validation precedes every mutation: deltas are `u64` checked into
/// `i64`, per-task sums use checked arithmetic, and the band bound —
/// `priority + demand <= PRIORITY_MAX`, the guard that keeps demand
/// inside the priority band so lane/family precedence cannot break —
/// is verified in SQL over the exact row set this event will fold,
/// before a single write. An overrun answers as an error, never a
/// clamp or a REAL promotion.
pub async fn apply_demand(
    db: &DurableDb,
    request: &stow_types::api::SchedulerDemandRequest,
) -> Result<stow_types::api::SchedulerDemandReport, QueueError> {
    demand_batch_shape(request)?;
    let deltas = demand_deltas(&request.entries)?;
    let input_hash = demand_input_fingerprint(&deltas)?;

    // The durable batch record decides whether this delivery walks or
    // replays — and a recorded id carrying a different canonical
    // fingerprint refuses before a single write, draft or accepted.
    let stored = db
        .query(
            "SELECT input_hash, touched_count, state \
             FROM demand_batches WHERE batch_id = ?",
        )
        .bind(request.batch_id.clone())
        .fetch_optional::<DemandBatchRow>()
        .await
        .map_err(|error| format!("probe demand batch record: {error}"))?;
    if let Some(batch) = &stored {
        if batch.input_hash != input_hash {
            return Err(QueueError::Invariant(format!(
                "demand batch {} already delivered with a different payload",
                request.batch_id
            )));
        }
        match batch.state.as_str() {
            "accepted" => {
                // Fully accepted replay: the stored header answers —
                // no writes, no live walk, whatever the graph looks
                // like now.
                return Ok(stow_types::api::SchedulerDemandReport {
                    batch_id: request.batch_id.clone(),
                    entries: u64::try_from(deltas.len()).unwrap_or(u64::MAX),
                    touched_tasks: u64::try_from(batch.touched_count).unwrap_or(u64::MAX),
                    applied: false,
                });
            }
            // An unaccepted draft of the same input may retry — its
            // staging is not a frozen set and is replaced below.
            "prepared" => {}
            state => {
                return Err(QueueError::Invariant(format!(
                    "demand batch {} in unexpected state {state:?}",
                    request.batch_id
                )));
            }
        }
    }

    // New batch or unaccepted retry: recompute the live closure —
    // union/diamond/cycle semantics exactly as first delivery — and
    // stage it. Every preflight precedes every mutation: the closure
    // walk, the stored-floor read, the operand probe and the staged
    // precompute are all read-only until the first ledger write.
    let contributions = demand_event_rows(db, &deltas).await?;
    let floor = db
        .query(
            "SELECT CAST(value AS TEXT) AS value FROM settings \
             WHERE key = 'min_dispatch_value'",
        )
        .fetch_scalar_optional::<String>()
        .await
        .map_err(|error| format!("read stored dispatch floor: {error}"))?
        .map(|raw| {
            raw.parse::<i64>().map_err(|_| {
                QueueError::Invariant("stored dispatch floor is not an integer".to_owned())
            })
        })
        .transpose()?
        .unwrap_or(0);
    let rows = prepare_demand_rows(db, &contributions, floor).await?;
    let chunks = contribution_chunks(&rows)?;

    let touched = i64::try_from(rows.len()).unwrap_or(i64::MAX);
    demand_commit_batch(
        db,
        &request.batch_id,
        input_hash,
        touched,
        &chunks,
        stored.is_some(),
    )
    .await?;

    Ok(stow_types::api::SchedulerDemandReport {
        batch_id: request.batch_id.clone(),
        entries: u64::try_from(deltas.len()).unwrap_or(u64::MAX),
        touched_tasks: u64::try_from(touched).unwrap_or(u64::MAX),
        applied: true,
    })
}

/// `POST /demand`'s full storage pass — the batch apply plus the
/// alarm plan the caller then arms. Shared by the wasm route and the
/// cost-gate drive so the metered statement set is the real route
/// path: the same apply, then the same freeze/settings/family/lease
/// `next_alarm` probes the route's `schedule_alarm` runs — nothing
/// read or written outside them (stow#522).
pub async fn demand_pass(
    db: &DurableDb,
    request: &stow_types::api::SchedulerDemandRequest,
    now_ms: i64,
    settings: &SchedulerSettings,
) -> Result<(stow_types::api::SchedulerDemandReport, AlarmPlan), QueueError> {
    let report = apply_demand(db, request).await?;
    let plan = next_alarm(db, now_ms, settings).await?;
    Ok((report, plan))
}

/// Perform the plan `next_alarm` decided on the real durable-object
/// alarm — shared by the wasm routes and the budget probe's demand
/// drive so the drive performs the same set/delete sequence the route
/// does. Alarm calls are platform operations, not SQL: they sit
/// outside the statement/rows meter by design (stow#522).
pub(super) async fn arm_alarm(alarm: &Alarm, plan: AlarmPlan) -> Result<(), QueueError> {
    match plan {
        AlarmPlan::Delete => alarm
            .delete_alarm()
            .await
            .map_err(|error| QueueError::Sql(format!("delete scheduler alarm: {error}"))),
        AlarmPlan::At(next_ms) => alarm
            .set_alarm(next_ms)
            .await
            .map_err(|error| QueueError::Sql(format!("set scheduler alarm {next_ms}: {error}"))),
    }
}

/// The write tail of a new or retried delivery: land the `prepared`
/// header — or clear an unaccepted draft's own staging, which is
/// replaceable material, never an obligation — stage every chunk
/// relationally, then flip the state. That last UPDATE is the atomic
/// acceptance: `demand_fold` folds every staged delta into
/// `demand`/`value`/`dispatch_key` inside the same statement, the guard's
/// staged-count keeps a partial set from accepting, and a failure
/// anywhere — trigger included — aborts the transition AND every
/// triggered effect.
async fn demand_commit_batch(
    db: &DurableDb,
    batch_id: &str,
    input_hash: String,
    touched: i64,
    chunks: &[String],
    reprepare: bool,
) -> Result<(), QueueError> {
    if reprepare {
        db.query("DELETE FROM demand_contributions WHERE batch_id = ?")
            .bind(batch_id.to_owned())
            .execute()
            .await
            .map_err(|error| format!("clear demand staging: {error}"))?;
    } else {
        db.query(
            "INSERT INTO demand_batches \
             (batch_id, input_hash, touched_count, state) \
             VALUES (?, ?, ?, 'prepared')",
        )
        .bind(batch_id.to_owned())
        .bind(input_hash)
        .bind(touched)
        .execute()
        .await
        .map_err(|error| format!("record demand batch: {error}"))?;
    }
    // Stage the event's set relationally, in bounded JSON chunks —
    // deltas cross as decimal text SQLite decodes as INTEGER, so no
    // value above 2^53 ever rides a JS number.
    for chunk in chunks {
        db.query(
            "INSERT INTO demand_contributions \
                 (task_id, batch_id, delta, value, dispatch_key, dispatch_eligible) \
             SELECT j.value ->> 'tid', ?, \
                    CAST(j.value ->> 'delta' AS INTEGER), \
                    j.value ->> 'value', j.value ->> 'key', \
                    j.value ->> 'eligible' \
             FROM json_each(?) j",
        )
        .bind(batch_id.to_owned())
        .bind(chunk.clone())
        .execute()
        .await
        .map_err(|error| format!("stage demand contributions: {error}"))?;
    }
    db.query(
        "UPDATE demand_batches \
         SET state = 'accepted', touched_count = ? \
         WHERE batch_id = ? AND state = 'prepared' \
           AND (SELECT count(*) FROM demand_contributions c \
                WHERE c.batch_id = ?) = ?",
    )
    .bind(touched)
    .bind(batch_id.to_owned())
    .bind(batch_id.to_owned())
    .bind(touched)
    .execute()
    .await
    .map_err(|error| format!("accept demand batch: {error}"))?;
    if changes(db).await? == 0 {
        return Err(QueueError::Invariant(format!(
            "demand batch {batch_id} staging incomplete at acceptance"
        )));
    }
    Ok(())
}

/// One staged row of a demand batch's fold payload — the delta plus
/// the task's post-fold `value`, `dispatch_key` and
/// `dispatch_eligible`, every one computed in Rust through the shared
/// rank abstraction at the event's post-fold demand BEFORE any ledger
/// or header write, so the acceptance trigger is a static
/// prepared-field copy with no ranking formula in SQL. `value`
/// serializes as decimal text (the band range exceeds a JS Number's
/// exact band); the serialization also survives as the batch record's
/// frozen set, so it must read back identically.
#[derive(serde::Serialize, serde::Deserialize)]
struct ContributionRow {
    tid: String,
    delta: i64,
    value: String,
    key: String,
    eligible: u8,
}

/// One canonical demand-batch input entry — the five identity fields
/// plus the summed delta, emitted in sorted order.
#[derive(serde::Serialize)]
struct CanonicalEntry {
    crate_name: String,
    version: String,
    features_json: String,
    target: String,
    rustc_version: String,
    delta: i64,
}

/// A `demand_batches` row: the canonical input's blake3 fingerprint,
/// the touched count recorded at acceptance, and the typed state —
/// `prepared` (unaccepted draft; staging may be replaced on a same-
/// input retry) or `accepted` (complete, immutable).
#[derive(Debug, skyzen::FromRow)]
struct DemandBatchRow {
    input_hash: String,
    touched_count: i64,
    state: String,
}

/// The request's shape bounds, checked before any read or write: a
/// bounded batch id and a bounded, non-empty entry list.
fn demand_batch_shape(request: &stow_types::api::SchedulerDemandRequest) -> Result<(), QueueError> {
    if request.batch_id.is_empty() || request.batch_id.len() > MAX_DEMAND_BATCH_ID_BYTES {
        return Err(QueueError::Invariant(format!(
            "demand batch_id must be 1..={MAX_DEMAND_BATCH_ID_BYTES} bytes"
        )));
    }
    if request.entries.is_empty() || request.entries.len() > MAX_DEMAND_BATCH_ENTRIES {
        return Err(QueueError::Invariant(format!(
            "demand batch must carry 1..={MAX_DEMAND_BATCH_ENTRIES} entries"
        )));
    }
    Ok(())
}

/// One batch's deduped per-identity deltas: an entry repeated under
/// the same identity is one demand report, and summing before the
/// walk keeps "once per task" true at identity granularity too. The
/// `BTreeMap`'s ordering is the canonicalization — the serialized
/// form below compares equal regardless of entry order or
/// duplication.
fn demand_deltas(
    entries: &[stow_types::api::SchedulerDemandEntry],
) -> Result<BTreeMap<[String; 5], i64>, QueueError> {
    let mut deltas: BTreeMap<[String; 5], i64> = BTreeMap::new();
    for entry in entries {
        let delta = u64_to_i64(entry.demand, "demand entry delta")?;
        let key = [
            entry.crate_name.as_str().to_owned(),
            entry.version.to_string(),
            entry.features_json.raw(),
            entry.target.as_str().to_owned(),
            entry.rustc_version.as_str().to_owned(),
        ];
        let total = deltas
            .get(&key)
            .copied()
            .unwrap_or(0)
            .checked_add(delta)
            .ok_or(QueueError::Overflow {
                field: "demand entry delta sum",
                value: u64::MAX,
            })?;
        deltas.insert(key, total);
    }
    Ok(deltas)
}

/// The batch id's payload fingerprint: blake3 of the sorted, summed
/// canonical entry serialization — the identity a redelivery of the
/// same observation must carry, and the cheap comparison a changed
/// payload fails (stow#522).
fn demand_input_fingerprint(deltas: &BTreeMap<[String; 5], i64>) -> Result<String, QueueError> {
    Ok(blake3::hash(canonical_demand_input(deltas)?.as_bytes())
        .to_hex()
        .to_string())
}

/// The batch id's accepted-payload fingerprint: the summed per-identity
/// deltas serialized in `BTreeMap` order, so two spellings of the same
/// observations — any entry order, any duplication — compare equal and
/// a changed payload compares different (stow#522).
fn canonical_demand_input(deltas: &BTreeMap<[String; 5], i64>) -> Result<String, QueueError> {
    enqueue_json(
        &deltas
            .iter()
            .map(|(identity, delta)| CanonicalEntry {
                crate_name: identity[0].clone(),
                version: identity[1].clone(),
                features_json: identity[2].clone(),
                target: identity[3].clone(),
                rustc_version: identity[4].clone(),
                delta: *delta,
            })
            .collect::<Vec<_>>(),
    )
}

/// The event's contribution set: one keyed walk per distinct identity,
/// `UNION` deduped — a task reached through two roots or two diamond
/// paths is visited once, and cycles cannot recur — merged into the
/// (task, delta) pairs a delivery stages. `BTreeMap` order keeps the
/// staging order deterministic.
async fn demand_event_rows(
    db: &DurableDb,
    deltas: &BTreeMap<[String; 5], i64>,
) -> Result<Vec<(String, i64)>, QueueError> {
    let mut contributions: BTreeMap<String, i64> = BTreeMap::new();
    for (key, delta) in deltas {
        for task_id in demand_closure_tasks(db, key).await? {
            let total = contributions
                .get(&task_id)
                .copied()
                .unwrap_or(0)
                .checked_add(*delta)
                .ok_or(QueueError::Overflow {
                    field: "task demand contribution",
                    value: u64::MAX,
                })?;
            contributions.insert(task_id, total);
        }
    }
    Ok(contributions.into_iter().collect())
}

/// The event's staged set with every post-fold answer precomputed:
/// for each touched task the operands load once through
/// `RANK_SOURCE_SELECT` (task ids cross as TEXT via chunked
/// `json_each` joins; `priority`/`demand`/`value`/`median_ms` as TEXT
/// under the same checked parse every writer shares), then the fold
/// result derives in Rust — `demand + delta` feeds the shared
/// `raw_value`/`dispatch_key`, and the eligibility answer evaluates
/// against the STORED floor the other writers' flags were set by.
/// All of it happens before the first ledger write: a violated cost
/// or band invariant fails the event while the store is untouched.
async fn prepare_demand_rows(
    db: &DurableDb,
    contributions: &[(String, i64)],
    floor: i64,
) -> Result<Vec<ContributionRow>, QueueError> {
    // One keyed load per tid-chunk — the staged set can far exceed a
    // single bound JSON operand, so the probe pages exactly like the
    // ranked-key refreshes.
    let mut operands: std::collections::HashMap<String, RankRow> =
        std::collections::HashMap::with_capacity(contributions.len());
    for tids in contributions.chunks(ENQUEUE_JSON_BATCH_ROWS) {
        let ids = enqueue_json(&tids.iter().map(|(tid, _)| tid.clone()).collect::<Vec<_>>())?;
        let rows = db
            .query(&format!(
                "{RANK_SOURCE_SELECT}                  WHERE q.task_id IN (SELECT value FROM json_each(?))"
            ))
            .bind(ids)
            .fetch_all::<RankSourceRow>()
            .await
            .map_err(|error| format!("load demand fold operands: {error}"))?;
        for source in &rows {
            let row = source.checked()?;
            operands.insert(row.task_id.clone(), row);
        }
    }
    // The band bound runs on the typed row BEFORE any rank math —
    // `MAX(0, priority) + post-fold demand` must stay under
    // `PRIORITY_MAX`, so a delta too large for the task's headroom
    // names its offenders as a request error while the store is still
    // untouched, instead of overflowing `raw_value`'s band addition
    // mid-derivation (stow#522).
    let mut offending = Vec::new();
    let mut staged = Vec::with_capacity(contributions.len());
    for (tid, delta) in contributions {
        let row = operands.get(tid).ok_or_else(|| {
            QueueError::Invariant(format!(
                "demand closure named queue task {tid} that no longer exists"
            ))
        })?;
        let demand = row.demand.checked_add(*delta).ok_or(QueueError::Overflow {
            field: "task demand fold",
            value: u64::MAX,
        })?;
        if *delta
            > PRIORITY_MAX
                .saturating_sub(row.priority.max(0))
                .saturating_sub(row.demand.max(0))
        {
            offending.push(tid.clone());
            continue;
        }
        let value = crate::scheduler::rank::raw_value(
            &row.lane,
            &row.dispatch_family,
            row.priority,
            demand,
        );
        let key = crate::scheduler::rank::dispatch_key(&crate::scheduler::rank::KeyOperands {
            lane: &row.lane,
            family: &row.dispatch_family,
            priority: row.priority,
            demand,
            cost_ms: row.cost_ms,
            first_requested_at: &row.first_requested_at,
            created_at: &row.created_at,
            task_id: &row.task_id,
        });
        staged.push(ContributionRow {
            tid: tid.clone(),
            delta: *delta,
            value: value.to_string(),
            key,
            eligible: u8::from(row.lane == "human" || value >= floor),
        });
    }
    if !offending.is_empty() {
        return Err(QueueError::Invariant(format!(
            "demand would overflow the priority band on {} task(s): {}",
            offending.len(),
            offending.join(", ")
        )));
    }
    Ok(staged)
}

/// The largest serialized JSON one staging or preflight statement may
/// bind: workerd bounds a bound string (and a stored row) at 2 MiB,
/// so chunks stay under a quarter of that — tens of thousands of rows
/// per statement, never a giant bound string or a giant ledger row.
const DEMAND_STAGE_CHUNK_BYTES: usize = 512 * 1024;

/// A staged set split into JSON arrays each under
/// `DEMAND_STAGE_CHUNK_BYTES` of serialized text — a closure whose
/// whole snapshot would exceed the platform string bound still lands,
/// row by row, with nothing truncated. The partition measures each
/// row's own serialized length, but every chunk is serde-serialized
/// from the typed rows themselves. Deltas serialize as decimal text
/// SQLite decodes as INTEGER — no number binds, so a delta above
/// 2^53 survives the workerd cursor an i64 parameter could not cross.
fn contribution_chunks(rows: &[ContributionRow]) -> Result<Vec<String>, QueueError> {
    let mut chunks = Vec::new();
    let mut start = 0_usize;
    let mut size = 2_usize; // "[]"
    for (index, row) in rows.iter().enumerate() {
        let encoded = serde_json::to_string(row)
            .map_err(|error| QueueError::Sql(format!("encode contribution row: {error}")))?;
        let needed = encoded.len() + usize::from(index > start);
        if size + needed > DEMAND_STAGE_CHUNK_BYTES && index > start {
            chunks.push(enqueue_json(&rows[start..index])?);
            start = index;
            size = 2 + encoded.len();
        } else {
            size += needed;
        }
    }
    if start < rows.len() {
        chunks.push(enqueue_json(&rows[start..])?);
    }
    Ok(chunks)
}

/// The unbuilt tasks one demand entry's closure touches: roots are
/// every unbuilt row the identity names regardless of `host_side`, and
/// the recursive step follows each touched row's unmet edges into
/// unbuilt dep rows. `UNION` dedups the walk, so a task reached
/// through two roots or two diamond paths appears once and cycles
/// cannot recur. Task ids are TEXT, so this set crosses the workerd
/// cursor losslessly.
pub(super) async fn demand_closure_tasks(
    db: &DurableDb,
    identity: &[String; 5],
) -> Result<Vec<String>, QueueError> {
    db.query(&format!(
        "WITH RECURSIVE walk(task_id) AS ( \
             SELECT task_id FROM queue \
             WHERE crate_name = ? AND version = ? AND features_json = ? \
               AND target = ? AND rustc_version = ? \
               AND status IN ({UNBUILT_STATUSES}) \
             UNION \
             SELECT d.depends_on_task_id \
             FROM walk w \
             JOIN queue_dependencies d ON d.task_id = w.task_id AND d.dep_met = 0 \
             JOIN queue q ON q.task_id = d.depends_on_task_id \
                AND q.status IN ({UNBUILT_STATUSES}) \
         ) SELECT task_id FROM walk"
    ))
    .bind(identity[0].clone())
    .bind(identity[1].clone())
    .bind(identity[2].clone())
    .bind(identity[3].clone())
    .bind(identity[4].clone())
    .fetch_scalars::<String>()
    .await
    .map_err(|error| format!("demand closure walk: {error}").into())
}

/// Status projection read paths use so a dependent parked behind a
/// terminally failed dependency surfaces as `blocked` instead of
/// `pending`: a `failed` dependency is done until it
/// publishes, and "waiting for that" is a different thing to see than
/// "waiting for a publish". The answer is the persisted `blocked` flag
/// — `blocked_sql` is its definition — written alongside `deps_met`
/// and on the dependents of a dep whose status flips, so reads are a
/// column lookup rather than an EXISTS per row. The stored status
/// stays `pending`, so the dependency eventually publishing returns
/// the dependent to `pending` with nothing to reconcile.
fn effective_status_sql() -> String {
    "CASE WHEN queue.status = 'pending' AND queue.blocked != 0 \
         THEN 'blocked' ELSE queue.status END"
        .to_owned()
}

/// The first blocking edge a pending row names — the `blocked_by`
/// companion to [`effective_status_sql`]: the failed dependency's task
/// id.
fn blocked_by_sql() -> String {
    "CASE WHEN queue.status = 'pending' AND queue.blocked != 0 THEN ( \
        SELECT bd.depends_on_task_id \
            FROM queue_dependencies bd \
            JOIN queue bdep ON bdep.task_id = bd.depends_on_task_id \
            WHERE bd.task_id = queue.task_id \
              AND bdep.status = 'failed' \
              AND bd.dep_met = 0 \
            ORDER BY bd.depends_on_task_id LIMIT 1 \
    ) END"
        .to_owned()
}

/// A page row as the pre-claim leg formation works on — the subgraph
/// loads later.
fn pending_leg(row: TaskRow) -> PendingLeg {
    PendingLeg {
        task_id: row.task_id,
        attempt: row.attempt,
        crate_name: row.crate_name,
        version: row.version,
        features_json: row.features_json,
        target: row.target,
        rustc_version: row.rustc_version,
        host_side: row.host_side != 0,
        explicit_spelling: spelling_of(row.explicit_spelling),
        preserve_lockfile: row.preserve_lockfile != 0,
        dependency_subgraph: stow_types::api::TaskSubgraph {
            root_deps: Vec::new(),
            nodes: Vec::new(),
        },
    }
}

/// What a pending row's page record says beside the [`PendingLeg`]
/// itself — its batch uniformity key, the leg-ordering cost, and the
/// pre-claim row state an [`unclaim_rows`] restore writes back.
struct ClaimSide {
    /// `(rustc_version, family, lane)` — the batch key (§1.1).
    key: BatchKey,
    /// `crate_build_stats.median_ms` — `None` while unmeasured, which
    /// sorts a leg last like it sorts the rank.
    median_ms: Option<i64>,
    /// The row's pre-claim `generation_id` — restored if the row's
    /// batch is dropped after a lost race.
    generation_id: String,
    /// The row's pre-claim `claimed_at` — restored with it.
    claimed_at: Option<String>,
}

/// One page row's `ClaimSide`: the runner family and lane decode from
/// columns an enqueue wrote, so a value they cannot parse is corrupt
/// state, never a skippable row.
fn claim_side(row: &TaskRow) -> Result<ClaimSide, QueueError> {
    let family = runner_family(&row.target).ok_or_else(|| {
        QueueError::Invariant(format!(
            "pending task {} targets `{}`, which maps to no runner family",
            row.task_id, row.target
        ))
    })?;
    let lane = TaskLane::parse(&row.lane).ok_or_else(|| {
        QueueError::Invariant(format!(
            "pending task {} carries lane {:?}",
            row.task_id, row.lane
        ))
    })?;
    let median_ms = row
        .median_ms
        .as_deref()
        .map(|median| crate::scheduler::rank::checked_cost(median).map(NonZero::get))
        .transpose()?;
    let rustc_version = WireRustcVersion::parse(&row.rustc_version).map_err(|error| {
        QueueError::Invariant(format!(
            "pending task {} rustc_version {:?}: {error}",
            row.task_id, row.rustc_version
        ))
    })?;
    Ok(ClaimSide {
        key: BatchKey {
            rustc_version,
            family,
            lane,
        },
        median_ms,
        generation_id: row.generation_id.clone(),
        claimed_at: row.claimed_at.clone(),
    })
}

/// The `BuildTaskPayload` one pending row encodes as a batch leg —
/// the same fields the per-task dispatch serializes today. A stored
/// column that fails to parse is corrupt state: the row came in
/// through enqueue, which validates every field.
fn task_payload(task: &PendingLeg) -> Result<BuildTaskPayload, QueueError> {
    fn invalid(task_id: &str, error: impl std::fmt::Display) -> QueueError {
        QueueError::Invariant(format!("pending task {task_id}: {error}"))
    }
    Ok(BuildTaskPayload {
        task_id: task.task_id.clone(),
        attempt: task.attempt,
        crate_name: CrateName::parse(&task.crate_name)
            .map_err(|error| invalid(&task.task_id, error))?,
        version: CrateVersion::new(
            semver::Version::parse(&task.version).map_err(|error| invalid(&task.task_id, error))?,
        ),
        features_json: FeaturesJson::from_sorted(
            serde_json::from_str(&task.features_json)
                .map_err(|error| invalid(&task.task_id, error))?,
        )
        .map_err(|error| invalid(&task.task_id, error))?,
        target: TargetTriple::parse(&task.target).map_err(|error| invalid(&task.task_id, error))?,
        rustc_version: WireRustcVersion::parse(&task.rustc_version)
            .map_err(|error| invalid(&task.task_id, error))?,
        preserve_lockfile: task.preserve_lockfile,
        host_side: task.host_side,
        explicit_spelling: task.explicit_spelling,
        dependency_subgraph: task.dependency_subgraph.clone(),
    })
}

/// One row of the [`unclaim_rows`] restore set — the pre-claim
/// identity stamps the claim overwrote.
#[derive(serde::Serialize)]
struct UnclaimedRow {
    task_id: String,
    generation_id: String,
    claimed_at: Option<String>,
}

impl UnclaimedRow {
    /// The restore entry for `task_id` from its page-read `side`.
    fn of(task_id: &str, sides: &std::collections::HashMap<String, ClaimSide>) -> Self {
        let side = sides.get(task_id).expect("a claimed row has its side");
        Self {
            task_id: task_id.to_owned(),
            generation_id: side.generation_id.clone(),
            claimed_at: side.claimed_at.clone(),
        }
    }
}

/// Undo the claim and the batch binding on rows this pass won inside a
/// batch it then dropped: status, `generation_id` and `claimed_at`
/// restore to the pre-claim values the page read, `batch_id` and
/// `batch_leg` clear, and `dispatch_attempts` steps back — a dropped
/// leg burned no attempt. One `json_each` update for the whole set; an
/// empty set issues none, so only a lost race writes here. The
/// subquery's `LIMIT -1` makes the `json_each` side drive a primary-key
/// seek instead of walking the `dispatched` status group.
async fn unclaim_rows(db: &DurableDb, rows: &[UnclaimedRow]) -> Result<(), QueueError> {
    if rows.is_empty() {
        return Ok(());
    }
    db.query(
        "UPDATE queue \
         SET status = 'pending', generation_id = e.generation_id, \
             claimed_at = e.claimed_at, \
             dispatch_attempts = dispatch_attempts - 1, \
             batch_id = NULL, batch_leg = NULL, \
             updated_at = datetime('now') \
         FROM (SELECT value ->> 'task_id' AS task_id, \
                      value ->> 'generation_id' AS generation_id, \
                      value ->> 'claimed_at' AS claimed_at \
               FROM json_each(?) LIMIT -1) AS e \
         WHERE queue.task_id = e.task_id \
           AND queue.status = 'dispatched' AND queue.github_run_id IS NULL",
    )
    .bind(enqueue_json(rows)?)
    .execute()
    .await
    .map_err(|error| format!("restore dropped batch legs: {error}"))?;
    Ok(())
}

/// One leg of the single claim-and-bind statement: the row it claims,
/// the generation it mints, and the batch slot it takes.
#[derive(serde::Serialize)]
struct LegClaim {
    task_id: String,
    generation_id: String,
    batch_id: String,
    /// The leg's index in `tasks`, the matrix order `form_batches`
    /// sorted.
    leg: i64,
}

/// One formed batch's `build_batches` row in the `json_each` set.
#[derive(serde::Serialize)]
struct FormedBatchRow {
    batch_id: String,
    rustc_version: String,
    dispatch_family: String,
    lane: String,
    parallelism: i64,
    legs: i64,
}

/// Mint `count` ids in one statement — one `randomblob` row per id,
/// bounded by the claim itself (at most `CLAIM_PAGE_ROWS ×
/// CLAIM_MAX_PAGES` legs plus their batches), never a query per id.
async fn mint_ids(db: &DurableDb, count: usize) -> Result<Vec<String>, QueueError> {
    let ids = db
        .query("SELECT lower(hex(randomblob(16))) FROM json_each(?)")
        .bind(enqueue_json(&vec![0_u8; count])?)
        .fetch_scalars::<String>()
        .await
        .map_err(|error| format!("mint {count} ids: {error}"))?;
    if ids.len() != count {
        return Err(QueueError::Invariant(format!(
            "minted {} ids for a request of {count}",
            ids.len()
        )));
    }
    Ok(ids)
}

/// Mint every id the formation needs in one statement — a batch id per
/// batch, then a `generation_id` per leg — and seal each planned batch
/// with its own.
async fn seal_batches(
    db: &DurableDb,
    planned: Vec<PlannedBatch>,
    candidates: &[BatchCandidate],
) -> Result<Vec<FormedBatch>, QueueError> {
    if planned.is_empty() {
        return Ok(Vec::new());
    }
    let legs: usize = planned.iter().map(|batch| batch.legs.len()).sum();
    let mut ids = mint_ids(db, planned.len() + legs).await?.into_iter();
    let batch_ids = ids
        .by_ref()
        .take(planned.len())
        .map(|id| {
            id.parse::<BatchId>()
                .map_err(|error| QueueError::Invariant(format!("minted batch id {id:?}: {error}")))
        })
        .collect::<Result<Vec<BatchId>, QueueError>>()?;
    planned
        .into_iter()
        .zip(batch_ids)
        .map(|(batch, batch_id)| batch.seal(batch_id, candidates, &mut ids))
        .collect()
}

/// Claim and bind every leg of every sealed batch in ONE statement:
/// status, the minted `generation_id`, the attempt, the batch id and
/// the leg index land together, so each queue row is written once. The
/// `status = 'pending'` predicate is the race fence — the coverage
/// lookup that preceded it is a D1 await, so a concurrent pass can
/// claim a row in between — and the returned set is the legs this
/// pass won.
async fn claim_and_bind(
    db: &DurableDb,
    batches: &[FormedBatch],
) -> Result<std::collections::HashSet<String>, QueueError> {
    if batches.is_empty() {
        return Ok(std::collections::HashSet::new());
    }
    let claims: Vec<LegClaim> = batches
        .iter()
        .flat_map(|batch| {
            batch.tasks.iter().enumerate().map(|(leg, task)| LegClaim {
                task_id: task.task_id.clone(),
                generation_id: task.generation_id.clone(),
                batch_id: batch.batch_id.as_str().to_owned(),
                leg: i64::try_from(leg).expect("a leg index is bounded by batch_max_tasks"),
            })
        })
        .collect();
    let won = db
        .query(
            // `claimed_at` is the immutable claim instant of the
            // generation just minted — the one timestamp no in-flight
            // writer may rewrite, so the completion samples a real
            // claim-to-completion duration even after re-requests
            // bumped `updated_at` (stow#524). The subquery's `LIMIT -1`
            // makes the `json_each` side drive a primary-key seek
            // instead of walking the `pending` status group.
            "UPDATE queue \
             SET status = 'dispatched', generation_id = e.generation_id, \
                 dispatch_attempts = dispatch_attempts + 1, \
                 github_run_id = NULL, \
                 batch_id = e.batch_id, batch_leg = e.leg, \
                 claimed_at = datetime('now'), \
                 updated_at = datetime('now') \
             FROM (SELECT value ->> 'task_id' AS task_id, \
                          value ->> 'generation_id' AS generation_id, \
                          value ->> 'batch_id' AS batch_id, \
                          CAST(value ->> 'leg' AS INTEGER) AS leg \
                   FROM json_each(?) LIMIT -1) AS e \
             WHERE queue.task_id = e.task_id AND queue.status = 'pending' \
             RETURNING queue.task_id",
        )
        .bind(enqueue_json(&claims)?)
        .fetch_scalars::<String>()
        .await
        .map_err(|error| format!("claim {} legs: {error}", claims.len()))?;
    Ok(won.into_iter().collect())
}

/// Drop every batch that lost a leg to a concurrent pass: its won legs
/// go back to `pending` with the pre-claim stamps, it is warned once,
/// and it never gets a `build_batches` row. Returns the surviving
/// batches. Writes only when a race happened.
async fn drop_raced_batches(
    db: &DurableDb,
    sealed: Vec<FormedBatch>,
    won: &std::collections::HashSet<String>,
    sides: &std::collections::HashMap<String, ClaimSide>,
) -> Result<Vec<FormedBatch>, QueueError> {
    let (kept, dropped): (Vec<FormedBatch>, Vec<FormedBatch>) = sealed
        .into_iter()
        .partition(|batch| batch.tasks.iter().all(|task| won.contains(&task.task_id)));
    let mut restore = Vec::new();
    for batch in &dropped {
        tracing::warn!(
            batch_id = %batch.batch_id,
            "dropping batch — a leg was claimed by a concurrent dispatch"
        );
        restore.extend(
            batch
                .tasks
                .iter()
                .filter(|task| won.contains(&task.task_id))
                .map(|task| UnclaimedRow::of(&task.task_id, sides)),
        );
    }
    unclaim_rows(db, &restore).await?;
    Ok(kept)
}

/// Insert the surviving batches' `build_batches` rows, carrying each
/// batch's `parallelism` slots, in one `json_each` statement; an empty
/// set writes none. The legs are bound before their row exists — a
/// bound leg without its row is harmless, while a legless row would
/// look releasable to a racing pass.
async fn insert_batch_rows(
    db: &DurableDb,
    batches: &[FormedBatch],
    stale_dispatch_minutes: u32,
) -> Result<(), QueueError> {
    if batches.is_empty() {
        return Ok(());
    }
    let rows = batches
        .iter()
        .map(|batch| {
            Ok(FormedBatchRow {
                batch_id: batch.batch_id.as_str().to_owned(),
                rustc_version: batch.rustc_version.as_str().to_owned(),
                dispatch_family: dispatch_family_label(batch.family).to_owned(),
                lane: batch.lane.as_str().to_owned(),
                parallelism: i64::from(batch.parallelism),
                legs: i64::try_from(batch.tasks.len())
                    .map_err(|_| QueueError::Invariant("batch leg count exceeds i64".to_owned()))?,
            })
        })
        .collect::<Result<Vec<FormedBatchRow>, QueueError>>()?;
    db.query(
        "INSERT INTO build_batches \
             (batch_id, rustc_version, dispatch_family, lane, parallelism, legs, \
              claimed_at, lease_at) \
         SELECT e ->> 'batch_id', e ->> 'rustc_version', e ->> 'dispatch_family', \
                e ->> 'lane', CAST(e ->> 'parallelism' AS INTEGER), \
                CAST(e ->> 'legs' AS INTEGER), \
                datetime('now'), datetime('now', ?) \
         FROM (SELECT value AS e FROM json_each(?))",
    )
    .bind(format!("+{stale_dispatch_minutes} minutes"))
    .bind(enqueue_json(&rows)?)
    .execute()
    .await
    .map_err(|error| format!("insert formed batches: {error}"))?;
    Ok(())
}

/// What the page walk hands the formation stage: the rows
/// [`SlotPlan::admit`] admitted, in page order, each with its
/// [`ClaimSide`], and how many candidate rows the pages selected.
/// Every row is still `pending` — the walk claims nothing.
struct ClaimWalk {
    admitted: Vec<(TaskRow, ClaimSide)>,
    selected: usize,
}

/// The `dispatch_key` page walk of [`claim_dispatchable_tasks`]:
/// page, retire and admit interleaved — a pass reads rows in
/// proportion to the rows it can still admit, never to the frontier
/// depth. `plan.remaining()` sizes each page and `family_saturated`
/// keeps a spent family's backlog out of it. The walk only decides
/// which rows may go out; it writes nothing for them, so a row that
/// formation then leaves unbatched costs no write at all.
async fn claim_page_walk(
    db: &DurableDb,
    settings: &SchedulerSettings,
    coverage: &impl CoverageOracle,
    plan: &mut SlotPlan,
) -> Result<ClaimWalk, QueueError> {
    let mut walk = ClaimWalk {
        admitted: Vec::new(),
        selected: 0,
    };
    let mut after = String::new();
    for _ in 0..CLAIM_MAX_PAGES {
        if plan.remaining() == 0 {
            break;
        }
        // About two candidates per open slot: covered retirements
        // rarely force a second page, and the page cap keeps a deep
        // frontier on the next alarm tick.
        let page_rows = CLAIM_PAGE_ROWS.min(i64::from(plan.remaining()) * 2);
        let saturated: Vec<RunnerFamily> = RunnerFamily::ALL
            .into_iter()
            .filter(|family| plan.family_saturated(*family))
            .collect();
        let page = select_dispatchable_page(db, settings, &saturated, &after, page_rows).await?;
        walk.selected += page.len();
        let full_page =
            page.len() == usize::try_from(page_rows).expect("claim page rows fits usize");
        if let Some(last) = page.last() {
            after.clone_from(&last.dispatch_key);
        }
        // `admit` commits the count rule at once; a `Denied` row stays
        // pending — and so does every worse-ranked row of its key. A
        // racing pass can still win an admitted row before the claim
        // statement; that statement's `status = 'pending'` fence
        // catches it.
        for row in retire_covered_rows(db, page, coverage).await? {
            if plan.remaining() == 0 {
                break;
            }
            let side = claim_side(&row)?;
            if matches!(plan.admit(&side.key)?, SlotAdmission::Denied) {
                continue;
            }
            walk.admitted.push((row, side));
        }
        if !full_page {
            break;
        }
    }
    Ok(walk)
}

/// Claim pending rows into `build-batch.yml` dispatches (stow#833
/// §1.2). The walk keeps its shape — stale/lease recovery, the freeze
/// and pause gates, the capacity read, the `dispatch_key` page walk
/// with `retire_covered_rows` retiring each page's covered rows — but
/// a row is *admitted* only while [`SlotPlan::admit`] admits it, and
/// capacity counts runner slots (`build_batches.parallelism` sums), not
/// rows.
///
/// Admission claims nothing. The admitted rows' subgraphs load once,
/// [`form_batches`] packs them on a fresh plan over the same budget —
/// the walk's plan is spent deciding *whether* to take a row, and
/// replaying the same decisions on a fresh plan can only differ where
/// an encoder refusal it never saw loosens them (the equivalence is
/// host-tested in `batching`) — and one statement mints every batch
/// and generation id. A second statement then claims and binds every
/// formed leg at once, so a row is written exactly once and a row
/// formation leaves unbatched is not written at all; a batch that lost
/// a leg to a concurrent pass is dropped whole, and the surviving
/// batches get their `build_batches` rows in a third.
pub async fn claim_dispatchable_tasks(
    db: &DurableDb,
    settings: &SchedulerSettings,
    coverage: &impl CoverageOracle,
) -> Result<Vec<FormedBatch>, QueueError> {
    // The lease check ran ahead of this claim (`object.rs`); what is
    // left is releasing the slots of batches with no leg in flight.
    release_legless_batches(db).await?;
    // The dispatch freeze is the gate, and it lives here — the enqueue
    // side of the queue never consults it, so misses keep arriving and
    // stay pending for the first pass after a human lifts the freeze.
    if freeze_enabled(db).await? {
        tracing::info!("dispatch frozen — claiming nothing");
        return Ok(Vec::new());
    }
    let Dispatch::Limited(limit) = settings.dispatch else {
        tracing::info!("scheduler dispatch paused — claiming nothing");
        return Ok(Vec::new());
    };
    // The shape-coverage repair lives in `record_published_slice`
    // (stow#785): whether a completed dep's published rows cover a
    // dependent's edge is decidable only at the report that publishes
    // them — an alarm pass precedes that data and cannot know.
    let active = count_active_by_family(db).await?;
    let shared_free = limit.get().saturating_sub(active.total);
    let macos_free = settings
        .max_concurrent_macos_jobs
        .saturating_sub(active.of(RunnerFamily::MacOs));
    tracing::info!(
        running = active.total,
        available = shared_free,
        macos_available = macos_free,
        ?settings,
        "scheduler claim_dispatchable_tasks capacity"
    );
    if shared_free == 0 {
        return Ok(Vec::new());
    }
    let fresh_plan = || {
        SlotPlan::new(
            shared_free,
            std::collections::HashMap::from([(RunnerFamily::MacOs, macos_free)]),
            settings.batch_parallelism,
            settings.batch_max_tasks,
        )
    };

    let walk = claim_page_walk(db, settings, coverage, &mut fresh_plan()).await?;
    tracing::info!(
        selected = walk.selected,
        "scheduler claim_dispatchable_tasks selected rows"
    );
    let mut legs = Vec::with_capacity(walk.admitted.len());
    let mut sides = std::collections::HashMap::with_capacity(walk.admitted.len());
    for (row, side) in walk.admitted {
        sides.insert(row.task_id.clone(), side);
        legs.push(pending_leg(row));
    }
    load_admitted_subgraphs(db, &mut legs).await?;
    if legs.is_empty() {
        return Ok(Vec::new());
    }

    let mut candidates = Vec::with_capacity(legs.len());
    for task in legs {
        let side = &sides[&task.task_id];
        candidates.push(BatchCandidate {
            payload: task_payload(&task)?,
            lane: side.key.lane,
            family: side.key.family,
            median_ms: side.median_ms,
            task,
        });
    }
    let formation = form_batches(&candidates, &mut fresh_plan())?;
    tracing::info!(
        batches = formation.batches.len(),
        unbatched = formation.unbatched.len(),
        rejected = formation.rejected.len(),
        "scheduler claim_dispatchable_tasks formed batches"
    );
    let sealed = seal_batches(db, formation.batches, &candidates).await?;
    let won = claim_and_bind(db, &sealed).await?;
    let batches = drop_raced_batches(db, sealed, &won, &sides).await?;
    insert_batch_rows(db, &batches, settings.stale_dispatch_minutes).await?;
    // Rows the encoder refused are still `pending`, which
    // `fail_claimed_task` allows; unbatched rows are not written.
    for &(index, ref error) in &formation.rejected {
        fail_claimed_task(db, &candidates[index].task.task_id, error).await?;
    }
    Ok(batches)
}

/// One `task_nodes` row as the dispatch walk reads it.
#[derive(Debug, skyzen::FromRow)]
struct TaskNodeRow {
    task_id: String,
    crate_name: String,
    version: String,
    features_json: String,
    target: String,
    rustc_version: String,
    host_side: i64,
    explicit_spelling: i64,
    children_json: String,
}

/// The deepest BFS level the node-store walk expands before declaring
/// the stored graph cyclic — a resolved task graph is acyclic by
/// construction, so a store that keeps growing past this bound is
/// corrupt and the walk fails rather than looping.
const SUBGRAPH_WALK_MAX_LEVELS: usize = 64;

/// The per-level fetch bound: `json_each` over every claimed task's
/// current frontier in a single statement. A level wider than this —
/// impossible under real graphs, which stay far narrower — splits into
/// successive bounded statements of the same shape.
const SUBGRAPH_WALK_LEVEL_ROWS: usize = 512;

/// Rebuild every claimed task's `BuildTaskPayload.dependency_subgraph`
/// by walking the `task_nodes` store breadth-first from the task id
/// (stow#588).
///
/// Cost shape: one bounded `task_id IN (…)` SELECT per BFS level shared
/// by the whole claimed batch — never one query per node — so a pass
/// costs `O(max depth over the claimed subgraphs)` statements and reads
/// `O(Σ reachable nodes)` rows. A claimed task whose store chain is
/// broken (its own node or any reachable node absent) cannot produce a
/// payload whose `verified_dependency_graph` would hold, so it fails
/// dispatch with the missing task id named — never a leaf substitute —
/// and the rest of the batch still dispatches.
/// Per-task walk state for [`load_admitted_subgraphs`]: the ordered
/// list of discovered dependency node ids (the future `nodes` array —
/// the root itself is implicit in the wire), the set for dedup, the
/// level frontier, and the root node's own children (the future
/// `root_deps`).
struct SubgraphWalk {
    node_ids: Vec<String>,
    seen: std::collections::HashSet<String>,
    frontier: Vec<String>,
    root_children: Vec<String>,
}

async fn load_admitted_subgraphs(
    db: &DurableDb,
    claimed: &mut Vec<PendingLeg>,
) -> Result<(), QueueError> {
    if claimed.is_empty() {
        return Ok(());
    }
    let ids: Vec<String> = claimed.iter().map(|task| task.task_id.clone()).collect();
    let (mut walks, found, failed) = walk_task_ids(db, &ids).await?;
    // Fail the unbuildable tasks, naming the missing/unreached node id.
    for (index, missing) in &failed {
        let task = &claimed[*index];
        let error = format!(
            "node store cannot serve task {}: node {missing} absent ({} nodes walked)",
            task.task_id,
            walks[*index].as_ref().map_or(0, |w| w.node_ids.len())
        );
        fail_claimed_task(db, &task.task_id, &error).await?;
    }
    // Drop failures from the claimed set (descending order keeps
    // earlier indexes valid); `walks` entries for dropped tasks stay
    // None and line up with `claimed` afterward.
    for (index, _) in failed.iter().rev() {
        claimed.remove(*index);
        walks.remove(*index);
    }

    // Build each survivor's wire subgraph: `nodes` in discovery order,
    // `root_deps` = the root row's children as node indexes. A store
    // row whose own fields fail to parse is the same class of
    // corruption as an absent node — fail that task too.
    let mut build_failed: Vec<usize> = Vec::new();
    for (index, task) in claimed.iter_mut().enumerate() {
        let walk = walks[index].take().expect("surviving walk exists");
        match build_task_subgraph(&task.task_id, &walk, &found) {
            Ok(subgraph) => task.dependency_subgraph = subgraph,
            Err(error) => {
                tracing::error!(task_id = %task.task_id, error = %error, "dispatch subgraph build failed");
                fail_claimed_task(
                    db,
                    &task.task_id,
                    &format!("node store row invalid for {}: {error}", task.task_id),
                )
                .await?;
                build_failed.push(index);
            }
        }
    }
    for index in build_failed.into_iter().rev() {
        claimed.remove(index);
    }
    Ok(())
}

/// The walk half of [`load_admitted_subgraphs`]: level-0 roots in one
/// `IN` query, then the union-of-frontiers expansion bounded per level,
/// returning every task's `SubgraphWalk` (None where the walk broke),
/// the fetched row set, and the (claimed index, missing id) pairs.
async fn walk_task_ids(
    db: &DurableDb,
    task_ids: &[String],
) -> Result<
    (
        Vec<Option<SubgraphWalk>>,
        std::collections::HashMap<String, TaskNodeRow>,
        Vec<(usize, String)>,
    ),
    QueueError,
> {
    let mut found: std::collections::HashMap<String, TaskNodeRow> =
        std::collections::HashMap::new();
    for chunk in task_ids.chunks(SUBGRAPH_WALK_LEVEL_ROWS) {
        for row in fetch_task_nodes(db, chunk).await? {
            found.insert(row.task_id.clone(), row);
        }
    }
    let mut failed: Vec<(usize, String)> = Vec::new();
    let mut walks: Vec<Option<SubgraphWalk>> = Vec::with_capacity(task_ids.len());
    for (index, task_id) in task_ids.iter().enumerate() {
        let Some(row) = found.get(task_id) else {
            walks.push(None);
            failed.push((index, task_id.clone()));
            continue;
        };
        let children = parse_node_children(task_id, &row.children_json)?;
        walks.push(Some(SubgraphWalk {
            node_ids: Vec::new(),
            seen: std::collections::HashSet::from([task_id.clone()]),
            root_children: children.clone(),
            frontier: children,
        }));
    }

    // BFS levels: the union of every live walk's frontier goes out as
    // one `IN` query; each walk then consumes its own slice.
    for _level in 0..SUBGRAPH_WALK_MAX_LEVELS {
        let union: Vec<String> = walks
            .iter()
            .filter_map(|walk| walk.as_ref())
            .flat_map(|walk| walk.frontier.iter().cloned())
            .collect();
        if union.is_empty() {
            break;
        }
        for chunk in union.chunks(SUBGRAPH_WALK_LEVEL_ROWS) {
            for row in fetch_task_nodes(db, chunk).await? {
                found.entry(row.task_id.clone()).or_insert(row);
            }
        }
        for (index, slot) in walks.iter_mut().enumerate() {
            let Some(walk) = slot else { continue };
            let mut next: Vec<String> = Vec::new();
            let mut missing: Option<String> = None;
            for id in walk.frontier.drain(..) {
                let Some(row) = found.get(&id) else {
                    missing = Some(id);
                    break;
                };
                if walk.seen.insert(id.clone()) {
                    let children = parse_node_children(&id, &row.children_json)?;
                    next.extend(children.into_iter().filter(|c| !walk.seen.contains(c)));
                    walk.node_ids.push(id);
                }
            }
            if let Some(id) = missing {
                failed.push((index, id));
                *slot = None;
            } else {
                walk.frontier = next;
            }
        }
    }
    // Any walk still holding a frontier grew past the level cap — the
    // stored graph under it is cyclic/corrupt; fail it naming where.
    for (index, slot) in walks.iter_mut().enumerate() {
        if let Some(walk) = slot.take() {
            if walk.frontier.is_empty() {
                *slot = Some(walk);
            } else {
                failed.push((index, walk.frontier[0].clone()));
            }
        }
    }
    Ok((walks, found, failed))
}

/// Assemble one claimed task's `TaskSubgraph` from its finished walk —
/// `nodes` in discovery order, `root_deps` mapped through the same
/// positions. Any unbuildable store row is reported, never defaulted.
fn build_task_subgraph(
    task_id: &str,
    walk: &SubgraphWalk,
    found: &std::collections::HashMap<String, TaskNodeRow>,
) -> Result<stow_types::api::TaskSubgraph, String> {
    let position: std::collections::HashMap<&str, u32> = walk
        .node_ids
        .iter()
        .enumerate()
        .map(|(i, id)| (id.as_str(), u32::try_from(i).expect("node count fits u32")))
        .collect();
    let mut nodes = Vec::with_capacity(walk.node_ids.len());
    for id in &walk.node_ids {
        nodes.push(subgraph_node_from_store(&found[id], &position)?);
    }
    let root_deps: Vec<u32> = walk
        .root_children
        .iter()
        .filter_map(|id| position.get(id.as_str()).copied())
        .collect();
    if root_deps.len() != walk.root_children.len() {
        return Err(format!("root child missing from walked set for {task_id}"));
    }
    Ok(stow_types::api::TaskSubgraph { root_deps, nodes })
}

/// Persist the hard dispatch failure for one claimed task — the node
/// store could not serve its subgraph, so it can never verify a
/// payload; the error message names the offending id.
async fn fail_claimed_task(db: &DurableDb, task_id: &str, error: &str) -> Result<(), QueueError> {
    tracing::error!(task_id = %task_id, error = %error, "dispatch subgraph walk failed");
    db.query(
        "UPDATE queue SET status = 'failed', error_msg = ?, updated_at = datetime('now')          WHERE task_id = ?",
    )
    .bind(error.to_owned())
    .bind(task_id.to_owned())
    .execute()
    .await
    .map_err(|error| format!("mark undispatchable task failed: {error}"))?;
    Ok(())
}

/// One bounded `task_id IN (…)` SELECT against the node store — the
/// only read shape the dispatch walk uses (stow#588).
async fn fetch_task_nodes(
    db: &DurableDb,
    task_ids: &[String],
) -> Result<Vec<TaskNodeRow>, QueueError> {
    db.query(
        "SELECT task_id, crate_name, version, features_json, target, rustc_version, host_side, explicit_spelling, children_json \
         FROM task_nodes \
         WHERE task_id IN (SELECT value FROM json_each(?))",
    )
    .bind(enqueue_json(task_ids)?)
    .fetch_all::<TaskNodeRow>()
    .await
    .map_err(|error| format!("fetch task nodes: {error}").into())
}

/// Decode a node row's `children_json` — the task ids of its direct
/// dependencies, in stored edge order. A malformed array is a corrupt
/// store row, an invariant error naming the node.
fn parse_node_children(task_id: &str, children_json: &str) -> Result<Vec<String>, QueueError> {
    serde_json::from_str::<Vec<String>>(children_json).map_err(|error| {
        QueueError::Invariant(format!(
            "task node {task_id}: invalid children_json: {error}"
        ))
    })
}

/// Project a `task_nodes` row into the wire's `SubgraphNode`, mapping
/// its children's task ids to positions in this task's node list.
fn subgraph_node_from_store(
    row: &TaskNodeRow,
    position: &std::collections::HashMap<&str, u32>,
) -> Result<stow_types::api::SubgraphNode, String> {
    let children =
        parse_node_children(&row.task_id, &row.children_json).map_err(|error| error.to_string())?;
    Ok(stow_types::api::SubgraphNode {
        crate_name: CrateName::parse(row.crate_name.as_str())
            .map_err(|error| format!("node {}: invalid crate name: {error}", row.task_id))?,
        version: CrateVersion::new(
            semver::Version::parse(&row.version)
                .map_err(|error| format!("node {}: invalid version: {error}", row.task_id))?,
        ),
        features_json: FeaturesJson::from_sorted(
            serde_json::from_str(&row.features_json)
                .map_err(|error| format!("node {}: invalid features: {error}", row.task_id))?,
        )
        .map_err(|error| format!("node {}: invalid features: {error}", row.task_id))?,
        host_side: row.host_side != 0,
        keys_apart: row.explicit_spelling != 0,
        deps: children
            .iter()
            .map(|id| {
                position
                    .get(id.as_str())
                    .copied()
                    .ok_or_else(|| format!("node {}: child {id} not in walked set", row.task_id))
            })
            .collect::<Result<Vec<u32>, String>>()?,
    })
}

/// Retire every candidate row whose semantic identity the artifact
/// catalog already covers — the artifact published while the row
/// waited — and return the rows that still need a build. Only plain
/// crates.io tasks are asked about: a lockfile-preserving overlay build is
/// a different artifact from the unlocked one the catalog row describes.
async fn retire_covered_rows(
    db: &DurableDb,
    rows: Vec<TaskRow>,
    coverage: &impl CoverageOracle,
) -> Result<Vec<TaskRow>, QueueError> {
    let identities = rows
        .iter()
        .filter(|row| row.preserve_lockfile == 0)
        .map(|row| SemanticTaskIdentity {
            crate_name: row.crate_name.clone(),
            version: row.version.clone(),
            features_json: row.features_json.clone(),
            target: row.target.clone(),
            rustc_version: row.rustc_version.clone(),
            host_side: row.host_side != 0,
            dependency_identity: row.dependency_identity.clone(),
            explicit_spelling: spelling_of(row.explicit_spelling),
        })
        .collect::<Vec<_>>();
    if identities.is_empty() {
        return Ok(rows);
    }
    let covered = coverage.covered(&identities).await?;
    if covered.is_empty() {
        return Ok(rows);
    }
    let mut remaining = Vec::with_capacity(rows.len());
    for row in rows {
        let identity = SemanticTaskIdentity {
            crate_name: row.crate_name.clone(),
            version: row.version.clone(),
            features_json: row.features_json.clone(),
            target: row.target.clone(),
            rustc_version: row.rustc_version.clone(),
            host_side: row.host_side != 0,
            dependency_identity: row.dependency_identity.clone(),
            explicit_spelling: spelling_of(row.explicit_spelling),
        };
        if row.preserve_lockfile == 0 && covered.contains(&identity) {
            let result = db
                .query(
                    "UPDATE queue \
                     SET status = 'completed', error_msg = '', updated_at = datetime('now') \
                     WHERE task_id = ? AND status = 'pending'",
                )
                .bind(row.task_id.clone())
                .execute()
                .await
                .map_err(|error| format!("retire covered task {}: {error}", row.task_id))?;
            if result.rows_written == 0 {
                tracing::warn!(
                    task_id = %row.task_id,
                    "covered task was claimed by a concurrent dispatch before retirement"
                );
                continue;
            }
            tracing::info!(
                task_id = %row.task_id,
                crate_name = %row.crate_name,
                version = %row.version,
                "retired pending task: the artifact catalog already covers it"
            );
            continue;
        }
        remaining.push(row);
    }
    Ok(remaining)
}

/// Upper bound on a claim page's row count — the actual limit is
/// `min(CLAIM_PAGE_ROWS, 2 × open slots)`, so a pass reads in
/// proportion to the slots it fills, not to the frontier depth.
pub(super) const CLAIM_PAGE_ROWS: i64 = 256;

/// Pages per claim pass — a frontier deeper than this defers to the
/// next alarm tick, which the still-full queue reschedules immediately.
pub(super) const CLAIM_MAX_PAGES: usize = 8;

/// Dispatchable pending rows in claim order, paged through
/// `idx_queue_dispatch` — the index ordered `(status, deps_met,
/// dispatch_key)` with the residual-filter columns (`dispatch_family`,
/// `lane`, `first_requested_at`, `not_before`) trailing so a skipped
/// entry never needs the row — so a pass reads rows in proportion to
/// the slots it can fill, not to the queue size. `deps_met` is the
/// dependency gate's persisted answer (refreshed where an edge or slice
/// write can change it) and `dispatch_key` is the persisted claim-order
/// tuple (the `value` descending — human lane and Windows bands over
/// priority — then FIFO by `first_requested_at` with creation and id
/// tie breakers), so neither is evaluated per row.
///
/// `saturated` names runner families with no free slot — their rows
/// are excluded in SQL, the same predicate the wake probes build: a
/// saturated family's backlog must not spend the page budget while
/// other families have claimable rows past the frontier. One page of at
/// most `page_rows` rows resumes the keyset walk from `after` (the last
/// `dispatch_key` the previous page read): the caller sizes the page to
/// the rows the plan can still admit and pages again only while that
/// page came back full, because a family that fills mid-pass is still
/// skipped in Rust and the walk must see past it.
/// The production page selection — WHERE terms, family exclusion,
/// ORDER BY and LIMIT — shared by the paged claim walk and the
/// floor probe's bounded frontier so the two can't drift (stow#525).
fn dispatchable_page_sql(columns: &str, join_stats: bool, saturated: &[RunnerFamily]) -> String {
    let family_filter = dispatch_family_in_sql("q.dispatch_family", saturated);
    // The claim walk needs `median_ms` — the leg-ordering cost —
    // from the keyed stats join; the frontier probe reads ids only
    // and does not pay it.
    let stats = if join_stats {
        "LEFT JOIN crate_build_stats s \
         ON s.crate_name = q.crate_name AND s.target = q.target"
    } else {
        ""
    };
    format!(
        "SELECT {columns} FROM queue q {stats} \
         WHERE q.status = 'pending' AND q.deps_met = 1 \
           AND q.dispatch_eligible = 1 \
           AND (q.lane = 'human' OR q.first_requested_at <= datetime('now', ?)) \
           AND q.not_before <= datetime('now') \
           AND q.dispatch_key > ? \
           {family_filter} \
         ORDER BY q.dispatch_key \
         LIMIT ?",
    )
}

/// The bounded eligible frontier one claim pass can touch — the first
/// `CLAIM_PAGE_ROWS * CLAIM_MAX_PAGES` rows of the production page
/// selection under the live family exclusion — for the floor probe's
/// pre-image snapshot (stow#525). The paged walk reads contiguous
/// keyset slices of exactly this ordered set, so the bound covers
/// every row the pass can open.
pub(super) async fn select_dispatchable_frontier(
    db: &DurableDb,
    settings: &SchedulerSettings,
) -> Result<Vec<String>, QueueError> {
    let active = count_active_by_family(db).await?;
    let macos_slots = settings
        .max_concurrent_macos_jobs
        .saturating_sub(active.of(RunnerFamily::MacOs));
    let saturated: &[RunnerFamily] = if macos_slots == 0 {
        &[RunnerFamily::MacOs]
    } else {
        &[]
    };
    db.query(&dispatchable_page_sql("q.task_id", false, saturated))
        .bind(dispatch_cutoff_modifier(settings.dispatch_min_age_minutes))
        .bind(String::new())
        .bind(CLAIM_PAGE_ROWS * i64::try_from(CLAIM_MAX_PAGES).unwrap_or(i64::MAX))
        .fetch_scalars::<String>()
        .await
        .map_err(|error| QueueError::Sql(format!("select dispatchable frontier: {error}")))
}

async fn select_dispatchable_page(
    db: &DurableDb,
    settings: &SchedulerSettings,
    saturated: &[RunnerFamily],
    after: &str,
    page_rows: i64,
) -> Result<Vec<TaskRow>, QueueError> {
    let sql = dispatchable_page_sql(
        "q.task_id, q.attempt, q.crate_name, q.version, q.features_json, q.target, q.rustc_version, q.host_side, q.explicit_spelling, q.preserve_lockfile, q.dependency_identity, q.dispatch_attempts, q.dispatch_key, \
         q.lane, q.generation_id, q.claimed_at, \
         CAST(s.median_ms AS TEXT) AS median_ms",
        true,
        saturated,
    );
    let cutoff = dispatch_cutoff_modifier(settings.dispatch_min_age_minutes);
    // The keyset cursor: every real key starts with an inverted-value
    // digit, so '' orders before all of them. The admission floor is
    // the persisted `dispatch_eligible` equality — an index term ahead
    // of `dispatch_key`, so under-floor rows are outside the range the
    // walk opens, not rows it visits and rejects.
    db.query(&sql)
        .bind(cutoff)
        .bind(after.to_owned())
        .bind(page_rows)
        .fetch_all::<TaskRow>()
        .await
        .map_err(|error| QueueError::Sql(format!("select dispatchable tasks: {error}")))
}

/// The dispatch-failure backoff in minutes as a SQL expression of
/// `attempts_column`: `min(2^min(attempts, 6), MAX_DISPATCH_BACKOFF_MINUTES)`,
/// so a persistent failure (GitHub outage, bad token) never spins the
/// alarm in a zero-delay retry loop.
fn backoff_minutes_sql(attempts_column: &str) -> String {
    format!("MIN(1 << MIN({attempts_column}, 6), {MAX_DISPATCH_BACKOFF_MINUTES})")
}

/// Back off every leg of a batch whose dispatch failed, in one
/// statement. Each leg whose `(task_id, generation_id)` still names a
/// `dispatched`/`running` row with no bound run re-enters `pending`
/// behind the backoff of its own `dispatch_attempts` (incremented at
/// claim time); a late external-I/O failure for a superseded or
/// already-bound generation matches nothing and must not overwrite the
/// live row.
///
/// The row re-enters `pending`: `unpublished_deps`/`deps_met` stay live
/// on every status, so the recompute is a cheap count-derived
/// re-derivation — and `blocked`, maintained for pending rows only, may
/// have gone stale while it was in-flight. `wake_at` is the later of
/// the age gate and the backoff this statement writes (the SET operand
/// is spelled out again — SET terms see the old row); the human lane
/// ignores the age gate. The subquery's `LIMIT -1` makes the `json_each`
/// side drive a primary-key seek instead of walking the
/// `dispatched`/`running` status groups.
pub async fn back_off_dispatch_legs(
    db: &DurableDb,
    settings: &SchedulerSettings,
    legs: &[QueuedTask],
    error: &str,
) -> Result<(), QueueError> {
    if legs.is_empty() {
        return Ok(());
    }
    let next_not_before = format!(
        "datetime('now', '+' || {} || ' minutes')",
        backoff_minutes_sql("dispatch_attempts")
    );
    let updated = db
        .query(&format!(
            "UPDATE queue \
             SET status = 'pending', error_msg = ?, \
                 not_before = {next_not_before}, \
                 deps_met = {deps_met}, blocked = {blocked}, \
                 wake_at = {wake}, \
                 updated_at = datetime('now') \
             FROM (SELECT value ->> 'task_id' AS task_id, \
                          value ->> 'generation_id' AS generation_id \
                   FROM json_each(?) LIMIT -1) AS e \
             WHERE queue.task_id = e.task_id AND queue.generation_id = e.generation_id \
               AND queue.status IN ('dispatched', 'running') \
               AND queue.github_run_id IS NULL \
             RETURNING queue.task_id",
            deps_met = deps_met_sql("queue.task_id"),
            blocked = blocked_sql("queue.task_id"),
            wake = wake_at_sql(
                "queue.lane",
                "queue.first_requested_at",
                &next_not_before,
                settings.dispatch_min_age_minutes,
            ),
        ))
        .bind(error.to_owned())
        .bind(enqueue_json(legs)?)
        .fetch_scalars::<String>()
        .await
        .map_err(|db_error| format!("back off {} dispatch legs: {db_error}", legs.len()))?;

    if !updated.is_empty() {
        // The rows re-entered `pending` carrying the rank written
        // before the last cost move; refresh it through the shared
        // abstraction, scoped to the rows that transitioned.
        refresh_dispatch_keys(db, &updated).await?;
    }

    Ok(())
}

/// Seconds of validity that must remain on the cached GitHub App
/// installation token for a dispatch to reuse it. Installation tokens
/// live an hour; a five-minute floor keeps a dispatch from riding a
/// token that dies mid-flight.
const GITHUB_APP_TOKEN_MIN_REMAINING_SECS: i64 = 300;

/// Load the cached GitHub App installation token, or `None` when none is
/// stored or fewer than [`GITHUB_APP_TOKEN_MIN_REMAINING_SECS`] of
/// validity remain.
///
/// The freshness check runs in SQL (`strftime('%s', ...)`) so both the
/// GitHub `expires_at` RFC 3339 format and `SQLite` datetime strings
/// compare correctly.
pub async fn github_app_token(
    db: &DurableDb,
) -> Result<Option<crate::github_app::InstallationToken>, QueueError> {
    let row = db
        .query(&format!(
            "SELECT token, expires_at FROM github_app_token \
             WHERE id = 1 AND CAST(strftime('%s', expires_at) AS INTEGER) \
             > CAST(strftime('%s', 'now') AS INTEGER) + {GITHUB_APP_TOKEN_MIN_REMAINING_SECS}"
        ))
        .fetch_optional::<GitHubAppTokenRow>()
        .await
        .map_err(|error| format!("load github app token: {error}"))?;
    Ok(row.map(|row| crate::github_app::InstallationToken {
        token: row.token,
        expires_at: row.expires_at,
    }))
}

/// Persist a freshly minted GitHub App installation token over the
/// singleton cache row.
pub async fn store_github_app_token(
    db: &DurableDb,
    token: &crate::github_app::InstallationToken,
) -> Result<(), QueueError> {
    db.query(
        "INSERT INTO github_app_token (id, token, expires_at) VALUES (1, ?, ?) \
         ON CONFLICT(id) DO UPDATE \
         SET token = excluded.token, expires_at = excluded.expires_at",
    )
    .bind(token.token.clone())
    .bind(token.expires_at.clone())
    .execute()
    .await
    .map_err(|error| format!("store github app token: {error}"))?;
    Ok(())
}

// ===== Admin operations (`stow-admin` through the DO's `/tasks*` routes) =====
// ===== Dispatch freeze (`settings` key `dispatch_freeze`) =====
//
// A separate flag from the zone's WAF maintenance rules for a separate
// purpose: the rules shed anonymous edge traffic to protect the worker;
// `dispatch_freeze` stops
// the Durable Object from handing queue rows to CI runners while a
// systematic breakage or an over-budget day is burning the org's
// allowance. The row's presence is the flag — its value is the
// serialized `DispatchFreezeRecord` (trigger, notify outcome) so
// `GET /dispatch-freeze` answers the full picture from one read.

/// Read the stored freeze record; `None` means dispatch is live. A value
/// that fails to deserialize violates the key's contract and is an
/// invariant error rather than a guess.
pub async fn freeze_record(
    db: &DurableDb,
) -> Result<Option<stow_types::api::DispatchFreezeRecord>, QueueError> {
    let value = db
        .query("SELECT value FROM settings WHERE key = 'dispatch_freeze'")
        .fetch_scalar_optional::<String>()
        .await
        .map_err(|error| format!("read dispatch freeze record: {error}"))?;
    value
        .map(|json| {
            serde_json::from_str::<stow_types::api::DispatchFreezeRecord>(&json).map_err(|error| {
                QueueError::Invariant(format!(
                    "settings row `dispatch_freeze` holds an unparseable record: {error}"
                ))
            })
        })
        .transpose()
}

/// Whether dispatch is frozen — the `dispatch_freeze` row's presence is
/// the flag.
pub async fn freeze_enabled(db: &DurableDb) -> Result<bool, QueueError> {
    let count = db
        .query("SELECT count(*) AS count FROM settings WHERE key = 'dispatch_freeze'")
        .fetch_scalar::<u64>()
        .await
        .map_err(|error| format!("read dispatch freeze flag: {error}"))?;
    Ok(count > 0)
}

/// Write the freeze record — `record.notify` is whatever the alert send
/// already resolved to, so a failed send is persisted rather than
/// propagated: the freeze is the load-bearing action.
pub async fn set_freeze(
    db: &DurableDb,
    record: &stow_types::api::DispatchFreezeRecord,
) -> Result<(), QueueError> {
    let value = serde_json::to_string(record).map_err(|error| {
        QueueError::Invariant(format!("serialize dispatch freeze record: {error}"))
    })?;
    db.query(
        "INSERT INTO settings (key, value) VALUES ('dispatch_freeze', ?) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(value)
    .execute()
    .await
    .map_err(|error| format!("write dispatch freeze record: {error}"))?;
    record_freeze_transition(
        db,
        stow_types::api::FreezeTransitionEvent::Engaged,
        Some(&record.trigger),
    )
    .await?;
    tracing::warn!("dispatch freeze engaged — dispatch stops, enqueue stays open");
    Ok(())
}

/// Lift the freeze by deleting the record row — the caller already
/// holds the record for the cleared-transition alert. The transition
/// log still records the cleared record's trigger so the watchdog's
/// issue can name what had been engaged.
pub async fn delete_freeze(db: &DurableDb) -> Result<(), QueueError> {
    let trigger = freeze_record(db).await?.map(|record| record.trigger);
    db.query("DELETE FROM settings WHERE key = 'dispatch_freeze'")
        .execute()
        .await
        .map_err(|error| format!("clear dispatch freeze record: {error}"))?;
    record_freeze_transition(
        db,
        stow_types::api::FreezeTransitionEvent::Cleared,
        trigger.as_ref(),
    )
    .await?;
    tracing::warn!("dispatch freeze cleared — dispatch resumes");
    Ok(())
}

/// Append one `dispatch_freeze_log` row — the transition log the #450
/// watchdog reads over `dispatch-freeze status` to write the
/// `incident` issue record the edge deliberately cannot. Bounded: the
/// oldest rows past 200 drop off on each append.
async fn record_freeze_transition(
    db: &DurableDb,
    event: stow_types::api::FreezeTransitionEvent,
    trigger: Option<&stow_types::api::DispatchFreezeTrigger>,
) -> Result<(), QueueError> {
    let event = match event {
        stow_types::api::FreezeTransitionEvent::Engaged => "engaged",
        stow_types::api::FreezeTransitionEvent::Cleared => "cleared",
    };
    let trigger = trigger
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| QueueError::Invariant(format!("serialize freeze trigger: {error}")))?;
    db.query("INSERT INTO dispatch_freeze_log (event, trigger) VALUES (?, ?)")
        .bind(event)
        .bind(trigger)
        .execute()
        .await
        .map_err(|error| format!("write freeze transition: {error}"))?;
    db.query(
        "DELETE FROM dispatch_freeze_log WHERE id <= \
         (SELECT MAX(id) FROM dispatch_freeze_log) - 200",
    )
    .execute()
    .await
    .map_err(|error| format!("prune freeze transition log: {error}"))?;
    Ok(())
}

/// One `dispatch_freeze_log` row.
#[derive(Debug, skyzen::FromRow)]
struct FreezeLogRow {
    at: String,
    event: String,
    trigger: Option<String>,
}

/// The freeze transition log, newest first, capped at `limit` —
/// `GET /dispatch-freeze` (and so `stow-admin dispatch-freeze status`
/// and the watchdog) answers with it.
pub async fn freeze_transitions(
    db: &DurableDb,
    limit: u32,
) -> Result<Vec<stow_types::api::DispatchFreezeTransition>, QueueError> {
    let rows = db
        .query(
            "SELECT at, event, trigger FROM dispatch_freeze_log \
             ORDER BY id DESC LIMIT ?",
        )
        .bind(i64::from(limit))
        .fetch_all::<FreezeLogRow>()
        .await
        .map_err(|error| format!("read freeze transitions: {error}"))?;
    rows.into_iter()
        .map(|row| {
            let event = serde_json::from_value::<stow_types::api::FreezeTransitionEvent>(
                serde_json::Value::String(row.event.clone()),
            )
            .map_err(|error| {
                QueueError::Invariant(format!(
                    "dispatch_freeze_log row holds unknown event `{}`: {error}",
                    row.event
                ))
            })?;
            let trigger =
                row.trigger
                    .map(|json| {
                        serde_json::from_str::<stow_types::api::DispatchFreezeTrigger>(&json)
                            .map_err(|error| {
                                QueueError::Invariant(format!(
                                    "dispatch_freeze_log row holds unparseable trigger: {error}"
                                ))
                            })
                    })
                    .transpose()?;
            Ok(stow_types::api::DispatchFreezeTransition {
                at: row.at,
                event,
                trigger,
            })
        })
        .collect()
}

/// The evidence a failure-rate trip verdict becomes: the evaluated
/// window plus the dominant failure classes and the freshest failing
/// runs for the alert.
#[derive(Debug)]
pub struct FreezeTripDraft {
    /// The pure trip verdict over the window tallies.
    pub eval: crate::freeze::TripEval,
    /// Failure classes by descending count (`step: error-prefix`) — the
    /// lines the trip email leads with.
    pub classes: Vec<stow_types::api::DispatchFreezeClass>,
    /// `github_run_id`s of the most recent failures in the window.
    pub example_run_ids: Vec<String>,
}

/// Example run ids the trip email names — enough to click through, not
/// enough to bury the counts.
const TRIP_EXAMPLE_RUNS: i64 = 3;

/// Sum the in-window outcome buckets per target and run the pure trip
/// decision. The read is `attempt_outcome_buckets`, not the raw rows:
/// the window is at most `window_minutes / 5 + 1` buckets per target
/// (13 × 9 targets under the defaults) whatever the traffic, so the
/// cost of the check is constant in the number of completions it
/// covers. The sample is the outcome tally, not the queue rows: a
/// retried task flips back to `pending` and would otherwise erase its
/// earlier attempts from the window — exactly the retry-storm shape
/// this breaker exists to catch. Dispatch failures never land there
/// (no run was burned), so they are not the signal this watches.
pub async fn evaluate_freeze_trip(
    db: &DurableDb,
    settings: &crate::freeze::FreezeSettings,
) -> Result<Option<FreezeTripDraft>, QueueError> {
    // The bucket SELECT's range is bounded on both ends, so it returns
    // the rows it scans — at most (`window_minutes` / 5 + 1) ×
    // `CI_TARGET_TRIPLES` — and the host backend's `rows_read` equals
    // what the Durable Object bills. No ORDER BY: the fold is a
    // `BTreeMap`, and ordering would steer the planner onto the
    // (target, bucket) primary key — a full scan — instead of
    // `idx_attempt_outcome_buckets_bucket`'s bounded range (stow#833).
    let buckets = db
        .query(
            "SELECT target, outcomes, failures FROM attempt_outcome_buckets \
             WHERE bucket >= unixepoch('now') - CAST(? AS INTEGER) \
               AND bucket <= unixepoch('now')",
        )
        .bind(i64::from(settings.window_minutes) * 60)
        .fetch_all::<OutcomeBucketRow>()
        .await
        .map_err(|error| format!("read freeze-window outcome buckets: {error}"))?;
    let mut by_target: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for bucket in buckets {
        let entry = by_target.entry(bucket.target).or_default();
        entry.0 += bucket.outcomes;
        entry.1 += bucket.failures;
    }
    let mut tallies = Vec::with_capacity(by_target.len());
    for (target, (outcomes, failures)) in by_target {
        tallies.push(crate::freeze::OutcomeTally {
            target,
            outcomes: u64_to_u32(outcomes, "window outcomes")?,
            failures: u64_to_u32(failures, "window failures")?,
        });
    }
    let Some(eval) = crate::freeze::evaluate(&tallies, settings) else {
        return Ok(None);
    };
    // The verdict is a trip — assemble its evidence from the
    // failure-only raw rows. Failure classes rank `step: error-prefix`
    // counts; example run ids name the freshest failing Actions runs
    // the alert links.
    let window = format!("-{} minutes", settings.window_minutes);
    let class_rows = db
        .query(
            "SELECT failure_class, count(*) AS count FROM attempt_outcomes_v2 \
             WHERE finished_at >= datetime('now', ?) \
             GROUP BY failure_class ORDER BY count DESC, failure_class",
        )
        .bind(window.clone())
        .fetch_all::<FailureClassRow>()
        .await
        .map_err(|error| format!("count freeze-window failure classes: {error}"))?;
    let mut classes = Vec::with_capacity(class_rows.len());
    for row in class_rows {
        classes.push(stow_types::api::DispatchFreezeClass {
            class: row.failure_class.unwrap_or_else(|| "unknown".to_owned()),
            count: u64_to_u32(row.count, "window failure class count")?,
        });
    }
    let example_run_ids = db
        .query(
            "SELECT github_run_id FROM attempt_outcomes_v2 \
             WHERE github_run_id IS NOT NULL \
               AND finished_at >= datetime('now', ?) \
             GROUP BY github_run_id ORDER BY MAX(finished_at) DESC LIMIT ?",
        )
        .bind(window)
        .bind(TRIP_EXAMPLE_RUNS)
        .fetch_all::<RunIdRow>()
        .await
        .map_err(|error| format!("load example failed run ids: {error}"))?
        .into_iter()
        .map(|row| row.github_run_id)
        .collect();
    Ok(Some(FreezeTripDraft {
        eval,
        classes,
        example_run_ids,
    }))
}

/// The database half of the post-failure freeze check — the
/// already-frozen short-circuit plus the window evaluation, so a
/// failure drive pays exactly the reads the Durable Object's check
/// runs. `None` covers both "a freeze already holds" (the cheap gate
/// skips the window read) and "the window does not trip"; the caller
/// applies an `Ok(Some(_))` draft through
/// `freeze::apply_transition` — the record write and the one alert —
/// which stays request-side with the alert sink.
///
/// # Errors
/// [`QueueError::Sql`] when a read fails.
pub async fn freeze_trip_draft(
    db: &DurableDb,
    settings: &crate::freeze::FreezeSettings,
) -> Result<Option<FreezeTripDraft>, QueueError> {
    if freeze_enabled(db).await? {
        return Ok(None);
    }
    evaluate_freeze_trip(db, settings).await
}

/// One `attempt_outcome_buckets` row inside the trip window — the
/// read set [`evaluate_freeze_trip`] folds over.
#[derive(Debug, skyzen::FromRow)]
struct OutcomeBucketRow {
    target: String,
    outcomes: u64,
    failures: u64,
}

/// One failure-class count for the trip evidence.
#[derive(Debug, skyzen::FromRow)]
struct FailureClassRow {
    failure_class: Option<String>,
    count: u64,
}

/// One run-id row for the trip evidence's example links.
#[derive(Debug, skyzen::FromRow)]
struct RunIdRow {
    github_run_id: String,
}

/// Row cap for admin queue listings and the mutation preview the CLI
/// renders — an unbounded scan on a hot queue would stall the Durable
/// Object's single thread, so operators narrow with filters.
const ADMIN_LIST_LIMIT: u32 = 500;

/// One queue row for the admin listing — every field [`QueueTask`] carries.
#[derive(Debug, skyzen::FromRow)]
struct AdminTaskRow {
    task_id: String,
    crate_name: String,
    version: String,
    features_json: String,
    target: String,
    rustc_version: String,
    lane: String,
    status: String,
    attempt: u32,
    error_msg: Option<String>,
    downloads: i64,
    miss_count: i64,
    dispatch_attempts: u32,
    preserve_lockfile: i64,
    github_run_id: Option<String>,
    first_requested_at: String,
    created_at: String,
    updated_at: String,
    blocked_by: Option<String>,
    host_side: i64,
    /// The persisted `value` projected as TEXT — the column outgrows
    /// the JS-safe integer range, so a numeric decode would lose the
    /// tail (stow#525 I10).
    value: String,
}

const ADMIN_TASK_COLUMNS: &str = "task_id, crate_name, version, features_json, target, \
     rustc_version, lane, attempt, error_msg, downloads, miss_count, \
     dispatch_attempts, preserve_lockfile, \
     github_run_id, first_requested_at, created_at, updated_at, host_side, \
     CAST(value AS TEXT) AS value";

impl AdminTaskRow {
    fn into_queue_task(self) -> Result<QueueTask, QueueError> {
        let task_id = self.task_id;
        let invariant =
            |message: String| QueueError::Invariant(format!("task {task_id} stored {message}"));
        Ok(QueueTask {
            task_id: task_id.clone(),
            crate_name: CrateName::parse(self.crate_name)
                .map_err(|error| invariant(format!("crate_name: {error}")))?,
            version: CrateVersion::new(
                semver::Version::parse(&self.version)
                    .map_err(|error| invariant(format!("version `{}`: {error}", self.version)))?,
            ),
            features_json: FeaturesJson::from_sorted(
                serde_json::from_str(&self.features_json)
                    .map_err(|error| invariant(format!("features_json: {error}")))?,
            )
            .map_err(|error| invariant(format!("features_json: {error}")))?,
            target: TargetTriple::parse(self.target)
                .map_err(|error| invariant(format!("target: {error}")))?,
            rustc_version: WireRustcVersion::parse(self.rustc_version)
                .map_err(|error| invariant(format!("rustc_version: {error}")))?,
            lane: TaskLane::parse(&self.lane)
                .ok_or_else(|| invariant(format!("unknown lane `{}`", self.lane)))?,
            status: QueueTaskStatus::parse(&self.status)
                .ok_or_else(|| invariant(format!("unknown status `{}`", self.status)))?,
            attempt: self.attempt,
            error: self.error_msg.unwrap_or_default(),
            downloads: u64::try_from(self.downloads).map_err(|_| QueueError::Overflow {
                field: "downloads",
                value: self.downloads.cast_unsigned(),
            })?,
            miss_count: u32::try_from(self.miss_count).map_err(|_| QueueError::Overflow {
                field: "miss_count",
                value: self.miss_count.cast_unsigned(),
            })?,
            dispatch_attempts: self.dispatch_attempts,
            preserve_lockfile: self.preserve_lockfile != 0,
            github_run_id: self.github_run_id,
            first_requested_at: self.first_requested_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
            blocked_by: self.blocked_by,
            host_side: self.host_side != 0,
            value: self.value,
        })
    }
}

/// The `WHERE` clause and bound values a [`QueueSelector`] describes. With
/// a non-empty `task_ids` the ids select the rows; otherwise the filter
/// predicates apply.
/// `qualifier` prefixes every column reference (e.g. `q.` when the
/// predicate runs against an aliased `queue q LEFT JOIN` scan whose
/// other table shares column names); pass `""` where the bare names
/// already bind.
fn selector_predicate(
    selector: &QueueSelector,
    qualifier: &str,
) -> Result<(String, Vec<DbValue>), QueueError> {
    let mut predicates: Vec<String> = Vec::new();
    let mut values: Vec<DbValue> = Vec::new();
    if selector.task_ids.is_empty() {
        if let Some(status) = selector.status {
            match status {
                // `blocked`/`pending` exist only on stored `pending`
                // rows (the derived status is the raw one for every
                // other state): the persisted `blocked` flag splits the
                // two, and `idx_queue_pending_first (blocked,
                // first_requested_at) WHERE status = 'pending'` bounds
                // each arm's listing to its own group, newest first.
                QueueTaskStatus::Pending | QueueTaskStatus::Blocked => {
                    predicates.push(format!("{qualifier}status = 'pending'"));
                    predicates.push(format!("{qualifier}blocked = ?"));
                    values.push(i64::from(matches!(status, QueueTaskStatus::Blocked)).into());
                }
                // The terminal partial `idx_queue_terminal_updated`
                // (`WHERE status IN ('completed','failed')`) is used
                // only when the literal IN term is spelled, so the
                // terminal arms carry it alongside the equality.
                QueueTaskStatus::Completed | QueueTaskStatus::Failed => {
                    predicates.push(format!("{qualifier}status IN ('completed', 'failed')"));
                    predicates.push(format!("{qualifier}status = ?"));
                    values.push(status.as_str().into());
                }
                _ => {
                    predicates.push(format!("{qualifier}status = ?"));
                    values.push(status.as_str().into());
                }
            }
        }
        if let Some(target) = &selector.target {
            predicates.push(format!("{qualifier}target = ?"));
            values.push(target.as_str().into());
        }
        if let Some(rustc_version) = &selector.rustc_version {
            predicates.push(format!("{qualifier}rustc_version = ?"));
            values.push(rustc_version.as_str().into());
        }
        if let Some(crate_name) = &selector.crate_name {
            predicates.push(format!("{qualifier}crate_name = ?"));
            values.push(crate_name.as_str().into());
        }
        if let Some(older_than_secs) = selector.older_than_secs {
            // The exact predicate (time since the last transition) plus
            // the implied bound it carries: `first_requested_at` is
            // never ahead of `updated_at`, so every row old enough to
            // match the first also matches the second. The second term
            // gives the planner an index range on an immutable column
            // when no terminal index applies (stow#786).
            predicates.push(format!("{qualifier}updated_at <= datetime('now', ?)"));
            values.push(format!("-{older_than_secs} seconds").into());
            predicates.push(format!(
                "{qualifier}first_requested_at <= datetime('now', ?)"
            ));
            values.push(format!("-{older_than_secs} seconds").into());
        }
        if predicates.is_empty() {
            return Err(QueueError::EmptySelector);
        }
    } else {
        predicates.push(format!(
            "{qualifier}task_id IN ({})",
            crate::sql_batch::placeholders(selector.task_ids.len())
        ));
        for task_id in &selector.task_ids {
            values.push(task_id.clone().into());
        }
    }
    Ok((predicates.join(" AND "), values))
}

/// Queue rows matching a selector, ordered newest first — by state
/// transition for terminal statuses, by request instant otherwise:
/// `first_requested_at` is immutable, so non-terminal listings walk an
/// index no queue-row write rewrites (stow#786).
pub async fn list_tasks(
    db: &DurableDb,
    selector: &QueueSelector,
) -> Result<Vec<QueueTask>, QueueError> {
    // A listing accepts a fully empty selector — it means "everything" —
    // so the EmptySelector refusal a mutation gets cannot apply here.
    let (predicate, values) = match selector_predicate(selector, "") {
        Ok(pair) => pair,
        Err(QueueError::EmptySelector) => (String::new(), Vec::new()),
        Err(error) => return Err(error),
    };
    let where_clause = if predicate.is_empty() {
        String::new()
    } else {
        format!("WHERE {predicate}")
    };
    let limit = selector
        .limit
        .map_or(ADMIN_LIST_LIMIT, |limit| limit.clamp(1, ADMIN_LIST_LIMIT));
    let order_column = if matches!(
        selector.status,
        Some(QueueTaskStatus::Completed | QueueTaskStatus::Failed)
    ) {
        "updated_at"
    } else {
        "first_requested_at"
    };
    let sql = format!(
        "SELECT {ADMIN_TASK_COLUMNS}, ({}) AS status, \
         ({}) AS blocked_by FROM queue {where_clause} \
         ORDER BY {order_column} DESC LIMIT {limit}",
        effective_status_sql(),
        blocked_by_sql()
    );
    let mut query = db.query(&sql);
    for value in values {
        query = query.bind(value);
    }
    let rows = query
        .fetch_all::<AdminTaskRow>()
        .await
        .map_err(|error| format!("list queue tasks: {error}"))?;
    rows.into_iter()
        .map(AdminTaskRow::into_queue_task)
        .collect()
}

/// The mutation a `POST /tasks/{verb}` route applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueMutation {
    /// `failed → pending`, clearing the error and the dispatch-failure
    /// backoff gate (`not_before`).
    Retry,
    /// `pending/dispatched → failed` with the operator's reason recorded.
    Cancel,
    /// `pending` miss-lane row → the human lane.
    Promote,
    /// Delete `completed`/`failed` rows; the selector must carry
    /// `older_than_secs` so a purge can never sweep live work.
    Purge,
}

/// Apply one admin mutation to every row the selector matches.
///
/// The verb's own status/lane predicates conjoin into the WHERE clause,
/// so a selector can only narrow the transition domain, never widen it:
/// `retry` cannot resurrect a dispatched row, `cancel` cannot fail a
/// completed one, `promote` cannot move a human or non-pending row, and
/// `purge` cannot delete anything still capable of running.
pub async fn apply_mutation(
    db: &DurableDb,
    settings: &SchedulerSettings,
    mutation: QueueMutation,
    selector: &QueueSelector,
) -> Result<u32, QueueError> {
    // A promote's SELECT joins the stats probe, so its predicate must
    // qualify against the `queue q` alias; the other verbs run
    // `UPDATE queue` statements where SQLite takes only bare names.
    let qualifier = if mutation == QueueMutation::Promote {
        "q."
    } else {
        ""
    };
    let (predicate, values) = selector_predicate(selector, qualifier)?;
    // A promote moves the lane, and the rank abstraction — not a SQL
    // SET expression — derives the promoted row's pair, so it prices
    // the matched rows under the human lane in Rust and applies the
    // move keyed by task id.
    if mutation == QueueMutation::Promote {
        return promote_matched(db, &predicate, values).await;
    }
    let sql = match mutation {
        QueueMutation::Retry => format!(
            // Rows re-enter `pending`: `deps_met` re-derives from the
            // live counter, and `blocked` — maintained for pending
            // rows only — may be stale on a failed row; both recompute
            // in the same statement. `not_before` resets to epoch, so
            // `wake_at` is the age gate (miss lane) or epoch (human).
            // The operator retry starts a fresh four-attempt cycle. The
            // generation_id remains the sole dispatch identity fence.
            "UPDATE queue SET status = 'pending', attempt = 1, error_msg = '', \
             not_before = '1970-01-01 00:00:00', deps_met = {deps_met}, \
             blocked = {blocked}, wake_at = {wake}, \
             updated_at = datetime('now') \
             WHERE status IN ('completed', 'failed') \
                 AND status = 'failed' AND {predicate}",
            deps_met = deps_met_sql("queue.task_id"),
            blocked = blocked_sql("queue.task_id"),
            wake = wake_at_sql(
                "lane",
                "first_requested_at",
                "'1970-01-01 00:00:00'",
                settings.dispatch_min_age_minutes,
            ),
        ),
        QueueMutation::Cancel => format!(
            "UPDATE queue SET status = 'failed', error_msg = 'cancelled by operator', \
             updated_at = datetime('now') \
             WHERE status IN ('pending', 'dispatched') AND {predicate}"
        ),
        QueueMutation::Promote => unreachable!("handled above"),
        QueueMutation::Purge => {
            // A purge needs a concrete age floor: deleting a row that
            // finished a second ago while its run is still reporting
            // would resurrect it as a cache miss. Requiring the
            // selector's own `older_than_secs` means the plan the CLI
            // rendered and the rows the purge deletes saw the same
            // cutoff.
            if selector.task_ids.is_empty() && selector.older_than_secs.is_none() {
                return Err(QueueError::PurgeRequiresAge);
            }
            format!("DELETE FROM queue WHERE status IN ('completed', 'failed') AND {predicate}")
        }
    };
    // `RETURNING` hands back the rows the one statement mutated —
    // the logical count the billed `rows_written` cannot give (index
    // maintenance inflates it) — atomically inside the statement, so
    // no extra round-trip exists to interpose.
    let returning = format!("{sql} RETURNING task_id");
    let mut query = db.query(&returning);
    for value in values {
        query = query.bind(value);
    }
    let mutated = query
        .fetch_scalars::<String>()
        .await
        .map_err(|error| format!("apply queue mutation: {error}"))?;
    // The pinned DO backend completes each statement synchronously: no
    // external await separates the mutation, cleanup and dependent refresh.
    // RETURNING keeps both follow-up writes scoped to precisely changed rows.
    if mutation != QueueMutation::Promote && !mutated.is_empty() {
        // `Retry` moved failed rows back to `pending`; their stored
        // rank predates the last cost move, so re-price exactly the
        // transitioned ids through the shared refresh.
        if mutation == QueueMutation::Retry {
            refresh_dispatch_keys(db, &mutated).await?;
        }
        // A broad filter (Retry/Purge over a large set) can return
        // more ids than one bound JSON operand should carry — chunk
        // the event-local follow-up writes at the shared bound like
        // every keyed batch.
        for ids in mutated.chunks(ENQUEUE_JSON_BATCH_ROWS) {
            let ids = enqueue_json(ids)?;
            refresh_dependents(
                db,
                "SELECT value AS task_id FROM json_each(?)",
                &[DbValue::Text(ids)],
            )
            .await?;
        }
    }
    u64_to_u32(
        u64::try_from(mutated.len()).unwrap_or(u64::MAX),
        "mutated row count",
    )
}

/// The `promote` verb's two-statement form: the matched pending
/// miss-lane rows load losslessly (operands plus their stored pair and
/// the keyed cost join), the shared rank abstraction prices each under
/// the human lane, and one keyed statement applies the lane move, the
/// `not_before` wake (the human lane pays no age gate) and the fresh
/// pair. The match is the SELECT: its `pending`/`miss` predicates
/// bound the write's domain to exactly the rows the selector matched,
/// so the UPDATE's only term is the `task_id` key — the probe shape
/// `apply_key_updates` already measures; any extra queue predicate
/// invites a queue-driven plan that scans the table per batch.
/// `RETURNING` counts the rows actually moved, as every mutation does.
async fn promote_matched(
    db: &DurableDb,
    predicate: &str,
    values: Vec<DbValue>,
) -> Result<u32, QueueError> {
    let select_sql = format!(
        "{RANK_SOURCE_SELECT} \
         WHERE q.status = 'pending' AND q.lane = 'miss' AND {predicate}"
    );
    let mut select = db.query(&select_sql);
    for value in values {
        select = select.bind(value);
    }
    let rows = select
        .fetch_all::<RankSourceRow>()
        .await
        .map_err(|error| format!("load rows for promote: {error}"))?;
    let mut updates: Vec<KeyUpdate> = Vec::with_capacity(rows.len());
    for source in &rows {
        let row = source.checked()?;
        let value = crate::scheduler::rank::raw_value(
            "human",
            &row.dispatch_family,
            row.priority,
            row.demand,
        );
        updates.push(KeyUpdate {
            task_id: row.task_id.clone(),
            lane: "human".to_string(),
            value: value.to_string(),
            dispatch_key: crate::scheduler::rank::dispatch_key(
                &crate::scheduler::rank::KeyOperands {
                    lane: "human",
                    family: &row.dispatch_family,
                    priority: row.priority,
                    demand: row.demand,
                    cost_ms: row.cost_ms,
                    first_requested_at: &row.first_requested_at,
                    created_at: &row.created_at,
                    task_id: &row.task_id,
                },
            ),
        });
    }
    if updates.is_empty() {
        return Ok(0);
    }
    // Chunked like every keyed batch: a promote selector can match
    // far more rows than one bound JSON operand should carry.
    let mut mutated = 0_usize;
    for chunk in updates.chunks(ENQUEUE_JSON_BATCH_ROWS) {
        mutated += db
            .query(
                "UPDATE queue \
                 SET lane = 'human', updated_at = datetime('now'), \
                     wake_at = not_before, \
                     value = CAST(j.e ->> 'value' AS INTEGER), \
                     dispatch_key = j.e ->> 'dispatch_key', \
                     dispatch_eligible = 1 \
                 FROM (SELECT value AS e FROM json_each(?)) AS j \
                 WHERE queue.task_id = j.e ->> 'task_id' \
                 RETURNING task_id",
            )
            .bind(enqueue_json(chunk)?)
            .fetch_scalars::<String>()
            .await
            .map_err(|error| format!("apply queue promote: {error}"))?
            .len();
    }
    u64_to_u32(
        u64::try_from(mutated).unwrap_or(u64::MAX),
        "mutated row count",
    )
}

/// Operator view of the whole queue for `GET /admin/status`: lane depths,
/// the oldest pending row's age, the in-flight set, per-target outcome
/// tallies over the trailing 24 hours.
pub async fn admin_status(db: &DurableDb) -> Result<AdminStatus, QueueError> {
    let queue_status = status(db).await?;
    let oldest_pending_seconds = db
        .query(
            "SELECT CAST(strftime('%s','now') AS INTEGER) \
                 - CAST(strftime('%s', MIN(first_requested_at)) AS INTEGER) AS age \
             FROM queue WHERE status = 'pending'",
        )
        .fetch_scalar::<Option<i64>>()
        .await
        .map_err(|error| format!("load oldest pending age: {error}"))?
        .map(|age| u64::try_from(age.max(0)))
        .transpose()
        .map_err(|_| QueueError::Overflow {
            field: "oldest_pending_seconds",
            value: u64::MAX,
        })?;
    let in_flight_rows = db
        .query(
            "SELECT task_id, crate_name, version, target, rustc_version, status, \
             attempt, dispatch_attempts, claimed_at, github_run_id \
             FROM queue WHERE status IN ('dispatched', 'running') \
             ORDER BY claimed_at",
        )
        .fetch_all::<AdminInFlightRow>()
        .await
        .map_err(|error| format!("list in-flight tasks: {error}"))?;
    let mut in_flight = Vec::with_capacity(in_flight_rows.len());
    for row in in_flight_rows {
        in_flight.push(row.into_in_flight()?);
    }
    let outcome_rows = db
        .query(
            "SELECT target, status, count(*) AS count FROM queue \
             WHERE status IN ('completed', 'failed') \
               AND updated_at >= datetime('now', '-24 hours') \
             GROUP BY target, status",
        )
        .fetch_all::<TargetOutcomeRow>()
        .await
        .map_err(|error| format!("count 24h outcomes by target: {error}"))?;
    let mut by_target: std::collections::BTreeMap<String, (u32, u32)> =
        std::collections::BTreeMap::new();
    for row in outcome_rows {
        let entry = by_target.entry(row.target).or_default();
        match row.status.as_str() {
            "completed" => entry.0 = u64_to_u32(row.count, "completed count")?,
            "failed" => entry.1 = u64_to_u32(row.count, "failed count")?,
            _ => {}
        }
    }
    let targets = by_target
        .into_iter()
        .map(|(target, (completed_24h, failed_24h))| {
            Ok(AdminTargetStats {
                target: TargetTriple::parse(target)?,
                completed_24h,
                failed_24h,
            })
        })
        .collect::<Result<Vec<_>, QueueError>>()?;
    Ok(AdminStatus {
        pending_miss: queue_status
            .pending
            .saturating_sub(queue_status.human_pending),
        pending_human: queue_status.human_pending,
        blocked: queue_status.blocked,
        oldest_pending_seconds,
        in_flight,
        targets,
        dispatch_frozen: freeze_enabled(db).await?,
    })
}

/// One in-flight queue row for [`admin_status`].
#[derive(Debug, skyzen::FromRow)]
struct AdminInFlightRow {
    task_id: String,
    crate_name: String,
    version: String,
    target: String,
    rustc_version: String,
    status: String,
    attempt: u32,
    dispatch_attempts: u32,
    claimed_at: Option<String>,
    github_run_id: Option<String>,
}

impl AdminInFlightRow {
    fn into_in_flight(self) -> Result<AdminInFlight, QueueError> {
        let task_id = self.task_id;
        let invariant =
            |message: String| QueueError::Invariant(format!("task {task_id} stored {message}"));
        Ok(AdminInFlight {
            task_id: task_id.clone(),
            crate_name: CrateName::parse(self.crate_name)
                .map_err(|error| invariant(format!("crate_name: {error}")))?,
            version: CrateVersion::new(
                semver::Version::parse(&self.version)
                    .map_err(|error| invariant(format!("version `{}`: {error}", self.version)))?,
            ),
            target: TargetTriple::parse(self.target)
                .map_err(|error| invariant(format!("target: {error}")))?,
            rustc_version: WireRustcVersion::parse(self.rustc_version)
                .map_err(|error| invariant(format!("rustc_version: {error}")))?,
            status: QueueTaskStatus::parse(&self.status)
                .ok_or_else(|| invariant(format!("unknown status `{}`", self.status)))?,
            attempt: self.attempt,
            dispatch_attempts: self.dispatch_attempts,
            claimed_at: self
                .claimed_at
                .ok_or_else(|| invariant("an in-flight row carries no claimed_at".to_owned()))?,
            github_run_id: self.github_run_id,
        })
    }
}

/// One `GROUP BY target, status` outcome row for [`admin_status`].
#[derive(Debug, skyzen::FromRow)]
struct TargetOutcomeRow {
    target: String,
    status: String,
    count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmPlan {
    /// Nothing can wake the queue: no unblocked pending rows and no active
    /// rows that could go stale.
    Delete,
    /// Wake at this epoch-millisecond timestamp.
    At(i64),
}

/// The dispatch capacity `next_alarm` read off settings and queue state.
/// `Paused` is its own state, not "no slots free": pending eligibility
/// can never wake the alarm through it, while `Exhausted` does so the
/// moment an in-flight lease expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchCapacity {
    /// Dispatch is paused (`Dispatch::Paused`): nothing may be claimed no
    /// matter how many rows wait.
    Paused,
    /// `active_total < limit` — a dispatch slot is free.
    Available,
    /// Every slot is taken: at least one dispatched/running row exists,
    /// so `earliest_batch_wake_ms` must be `Some`.
    Exhausted,
}

/// Everything [`plan_alarm`] needs, pre-fetched from the queue so the
/// decision itself is a pure function unit tests can drive on the host.
#[derive(Debug, Clone, Copy)]
pub struct AlarmInputs {
    /// Current time in epoch milliseconds.
    pub now_ms: i64,
    /// Whether a dispatch slot is free — see [`DispatchCapacity`]. Family
    /// saturation is already folded into `earliest_pending_eligible_ms`,
    /// whose query only covers rows whose family has a free slot, so
    /// `Some(..)` there plus `Available` always means a claim can proceed.
    pub capacity: DispatchCapacity,
    /// Earliest moment any unblocked pending row in a family with a free
    /// dispatch slot becomes dispatchable.
    pub earliest_pending_eligible_ms: Option<i64>,
    /// Earliest moment an in-flight batch needs a pass — its lease
    /// expiry, or its `resolve_after` once its completion is recorded
    /// (see [`earliest_batch_wake_ms`]). Must be
    /// `Some` whenever `capacity` is `Exhausted`; `next_alarm` enforces
    /// this before delegating.
    pub earliest_batch_wake_ms: Option<i64>,
}

/// Pure alarm decision; see [`AlarmInputs`] for the meaning of each field.
///
/// A wake-up is needed not only for pending rows becoming eligible but also
/// for the lease check: it only runs inside the dispatch pass, so an in-flight
/// batch whose completion webhook never arrives would never be settled unless
/// the alarm fires at its lease expiry.
pub fn plan_alarm(inputs: &AlarmInputs) -> AlarmPlan {
    match (inputs.capacity, inputs.earliest_pending_eligible_ms) {
        // A free slot plus an eligible row: wake when it can be claimed.
        (DispatchCapacity::Available, Some(eligible_ms)) => {
            AlarmPlan::At(eligible_ms.max(inputs.now_ms))
        }
        // Every slot is taken, so the earliest wake-up that can make
        // progress is the oldest lease expiring — never `now`, which would
        // spin the Durable Object in a zero-delay alarm loop.
        (DispatchCapacity::Exhausted, Some(_)) => inputs.earliest_batch_wake_ms.map_or_else(
            || unreachable!("exhausted dispatch capacity implies an active queue row"),
            |lease_ms| AlarmPlan::At(lease_ms.max(inputs.now_ms)),
        ),
        // Paused, or no dispatchable row: the only wake that can still
        // make progress is stale recovery on an in-flight build — pending
        // rows blocked on an active dependency unblock when it completes
        // or goes stale too. Nothing in flight means nothing to wake for.
        (_, _) => inputs
            .earliest_batch_wake_ms
            .map_or(AlarmPlan::Delete, |lease_ms| {
                AlarmPlan::At(lease_ms.max(inputs.now_ms))
            }),
    }
}

/// Decide the next scheduler alarm from live queue state.
///
/// While the dispatch freeze is engaged there is nothing to wake for —
/// dispatch is gated, so the alarm is deleted; the manual clear re-arms
/// it through the `/dispatch-freeze` route's dispatch pass.
pub async fn next_alarm(
    db: &DurableDb,
    now_ms: i64,
    settings: &SchedulerSettings,
) -> Result<AlarmPlan, QueueError> {
    if freeze_enabled(db).await? {
        return Ok(AlarmPlan::Delete);
    }
    let active = count_active_by_family(db).await?;
    let capacity = match settings.dispatch {
        Dispatch::Paused => DispatchCapacity::Paused,
        Dispatch::Limited(limit) if active.total < limit.get() => DispatchCapacity::Available,
        Dispatch::Limited(_) => DispatchCapacity::Exhausted,
    };
    // A capped family whose slots are all taken must not feed the
    // eligibility query: a queue whose only eligible pending rows belong
    // to it would otherwise re-arm the alarm at `now` forever.
    let macos_saturated = active.of(RunnerFamily::MacOs) >= settings.max_concurrent_macos_jobs;
    let inputs = AlarmInputs {
        now_ms,
        capacity,
        earliest_pending_eligible_ms: earliest_pending_eligible_ms(
            db,
            if macos_saturated {
                &[RunnerFamily::MacOs]
            } else {
                &[]
            },
            now_ms,
        )
        .await?,
        earliest_batch_wake_ms: earliest_batch_wake_ms(db).await?,
    };
    // Exhausted capacity means at least one dispatched/running row exists, so
    // a missing lease expiry contradicts the count just read — fail loudly
    // rather than letting plan_alarm pick a wake-up.
    if matches!(inputs.capacity, DispatchCapacity::Exhausted)
        && inputs.earliest_batch_wake_ms.is_none()
    {
        return Err(QueueError::Invariant(
            "dispatch capacity exhausted but no dispatched/running rows".to_owned(),
        ));
    }
    Ok(plan_alarm(&inputs))
}

/// Earliest epoch-ms at which an unblocked pending row in a family with a
/// free dispatch slot becomes dispatchable — `MIN(wake_at)` over the
/// eligible set, the persisted lane-aware wake instant. May be in the
/// past (already eligible).
///
/// `saturated` names capped runner families whose slots are all taken;
/// their pending rows are excluded so an eligibility the scheduler
/// could not act on cannot wake the alarm at `now`.
async fn earliest_pending_eligible_ms(
    db: &DurableDb,
    saturated: &[RunnerFamily],
    now_ms: i64,
) -> Result<Option<i64>, QueueError> {
    // Two probes over `idx_queue_wake (status, deps_met,
    // dispatch_eligible, dispatch_family, wake_at)`: `wake_at` is the
    // persisted earliest dispatch instant (the lane-aware later of age
    // gate and backoff), so eligibility collapses to one ordering — no
    // per-lane arms, no MIN over a CASE. The claim re-checks the live
    // columns, so a stale wake_at costs at most one wasted pass, never
    // a wrong dispatch. `dispatch_eligible = 1` is the admission
    // floor's persisted answer (stow#525): equality ahead of the
    // `wake_at` range means under-floor rows are outside the index
    // span the probes walk — a queue of them arms nothing immediate
    // and contributes nothing to the deferred MIN's read set.
    // The family term renders as `dispatch_family IN (…)` —
    // `RunnerFamily::ALL` minus the saturated families, all of them
    // when none is — equality over the column ahead of `wake_at`, so
    // SQLite expands the list into one seek per family and each
    // `wake_at` range stays bounded (stow#588). A missing term
    // (stow#833) or a `!=` leaves the range unbounded: every eligible
    // pending row read, on every alarm pass and every deliver.
    let family_filter = dispatch_family_in_sql("dispatch_family", saturated);
    // The plan is a pure function of `now_ms`; bind the rendered clock
    // rather than calling wall-clock `datetime('now')` inside the probes.
    let now = db
        .query("SELECT datetime(CAST(? AS INTEGER) / 1000, 'unixepoch')")
        .bind(now_ms)
        .fetch_scalar::<String>()
        .await
        .map_err(|error| format!("render probe clock: {error}"))?;

    // An already-eligible row wakes the alarm now — the probe stops at
    // the first index match. `0` is a past sentinel `plan_alarm` clamps.
    let hit = db
        .query(&format!(
            "SELECT 1 FROM queue WHERE status = 'pending' AND deps_met = 1 \
               AND dispatch_eligible = 1 \
               AND wake_at <= ? {family_filter} LIMIT 1"
        ))
        .bind(now.clone())
        .fetch_scalar_optional::<i64>()
        .await
        .map_err(|error| format!("probe pending eligibility: {error}"))?;
    if hit.is_some() {
        return Ok(Some(0));
    }

    // Nothing eligible now — the alarm's wake is the smallest wake_at
    // still in the future, one index-range read past `now`.
    let epoch = db
        .query(&format!(
            "SELECT CAST(strftime('%s', MIN(wake_at)) AS INTEGER) \
               FROM queue WHERE status = 'pending' AND deps_met = 1 \
                 AND dispatch_eligible = 1 \
                 AND wake_at > ? {family_filter}"
        ))
        .bind(now)
        .fetch_scalar::<Option<i64>>()
        .await
        .map_err(|error| format!("probe deferred eligibility: {error}"))?;
    epoch
        .map(|epoch| {
            epoch
                .checked_mul(1000)
                .ok_or_else(|| format!("eligible epoch overflow: {epoch}").into())
        })
        .transpose()
}

/// Earliest epoch-ms at which an in-flight batch needs a pass. A batch
/// whose completion is recorded against its bound run belongs to the
/// resolution pass and wakes at its `resolve_after`; every other batch
/// wakes at its `lease_at` for the lease check — the same split
/// [`expired_batches`] makes, so a recorded batch whose resolution is
/// deferred never holds the alarm at its past lease. May be in the
/// past (already due). The lease clocks the claim, not the last
/// transition (stow#786), and is pushed forward only by the lease
/// check finding the run still going. Two `MIN` probes over
/// `build_batches`, whose rows are bounded by the dispatch slot cap.
async fn earliest_batch_wake_ms(db: &DurableDb) -> Result<Option<i64>, QueueError> {
    let lease_epoch = db
        .query(
            "SELECT CAST(strftime('%s', MIN(wake)) AS INTEGER) AS lease_epoch FROM ( \
                 SELECT MIN(lease_at) AS wake FROM build_batches \
                 WHERE done_run_id IS NULL OR github_run_id IS NULL \
                 UNION ALL \
                 SELECT MIN(resolve_after) FROM build_batches \
                 WHERE done_run_id IS NOT NULL AND github_run_id IS NOT NULL)",
        )
        .fetch_scalar::<Option<i64>>()
        .await
        .map_err(|error| format!("load earliest active lease expiry: {error}"))?;
    let Some(lease_epoch) = lease_epoch else {
        return Ok(None);
    };

    lease_epoch
        .checked_mul(1000)
        .map(Some)
        .ok_or_else(|| format!("lease epoch overflow: {lease_epoch}").into())
}

/// The invocation-spelling mask a dependent's edges carry: the cargo
/// invocations its own build compiles the dep's units under. A
/// host-side task runs every phase both natively and under `--target`
/// (its deps are host units under either spelling); so does a
/// `KeysApart` target-side task at the host triple, which compiles its
/// deps under both spellings too (stow#736); any other target-side
/// task runs the one spelling its target implies.
pub fn dep_invocation_mask(
    owner_target: &str,
    owner_host_side: bool,
    owner_explicit_spelling: stow_types::public_cache::ExplicitSpelling,
) -> i64 {
    let runs_both_spellings = owner_host_side
        || (owner_explicit_spelling == stow_types::public_cache::ExplicitSpelling::KeysApart
            && stow_types::api::runner_family(owner_target)
                .is_some_and(|family| family.host_triple() == owner_target));
    if runs_both_spellings {
        return 0b11;
    }
    match stow_types::api::runner_family(owner_target) {
        Some(family) if family.host_triple() == owner_target => 0b01,
        _ => 0b10,
    }
}

/// The `(invocation mask, required shape count)` one dependency edge
/// carries. The mask is the invocation spellings the dep's published
/// rows must cover; the count is the number of distinct
/// `(invocation, linked)` pairs the gate sums to. A host-side dep edge
/// needs the linked row under each spelling the owner compiles — host
/// units always link, so the check phase publishes the same shape the
/// build does. A target-side dep edge needs both kinds at the dep
/// node's own invocation spelling — except a `KeysApart` dep invoked
/// `Native`, which owes the four shapes of both spellings (stow#736).
pub fn dep_edge_requirements(
    owner_target: &str,
    owner_host_side: bool,
    owner_explicit_spelling: stow_types::public_cache::ExplicitSpelling,
    dep_target: &str,
    dep_host_side: bool,
    dep_explicit_spelling: stow_types::public_cache::ExplicitSpelling,
) -> (i64, i64) {
    if dep_host_side {
        let mask = dep_invocation_mask(owner_target, owner_host_side, owner_explicit_spelling);
        return (mask, i64::from(mask.count_ones()));
    }
    let mask = dep_invocation_mask(
        dep_target,
        false,
        stow_types::public_cache::ExplicitSpelling::KeysAsNative,
    );
    if mask == 0b01
        && dep_explicit_spelling == stow_types::public_cache::ExplicitSpelling::KeysApart
    {
        return (0b11, 4);
    }
    (mask, 2)
}

/// Record what one published index slice serves — the semantic identities
/// the index-publish path reports after the slice goes live. The report
/// covers the whole slice, so membership is replaced wholesale: a row an
/// earlier report served that the new slice no longer does must not keep
/// a dependent's gate open. Queue status never enters here — a
/// dependency's presence in the slice is the only release signal the
/// gate knows.
///
/// The live set is edited in place rather than rewritten under a fresh
/// generation: a wholesale rewrite cost two writes per served row per
/// report (~30M rows written a day in production), while the delta
/// writes only what changed. `DurableDb` exposes no transaction, so the
/// delta orders delete-before-insert — a report that dies mid-write
/// leaves a subset of its intent live, never a row the report dropped.
/// One row of a published slice report (or of `published_slice_rows`):
/// the crate identity plus the unit shape the gate compares an edge's
/// required shapes against.
#[derive(Clone, serde::Serialize, skyzen::FromRow)]
struct SliceRowJson {
    /// Rowid is populated only on rows read back from the live set —
    /// report rows carry `0` and the retire delete keys on it. Skipped
    /// in serialization so a report row and its JSON are identical.
    #[serde(skip_serializing)]
    rowid: i64,
    crate_name: String,
    version: String,
    features_json: String,
    /// The published row's contextual digest (stow#588) — the column
    /// is NOT NULL, so a stored or reported row always carries one.
    dependency_identity: String,
    unit_side: i64,
    unit_invocation: i64,
    unit_linked: i64,
}

/// One explicit delta row with the direction that changed the live set.
/// The direction is private wire data for the delta gate; full reports keep
/// the generic changed-row path because their retirements are inferred from
/// the whole replacement set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum SliceChangeKind {
    Added,
    Retired,
}

struct ChangedSliceRow {
    row: SliceRowJson,
    kind: SliceChangeKind,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GateIdentity {
    crate_name: String,
    version: String,
    features_json: String,
    dependency_identity: String,
    unit_side: i64,
    kind: Option<SliceChangeKind>,
}

#[derive(Debug, serde::Serialize)]
struct NormalizedGateRow {
    crate_name: String,
    version: String,
    features_json: String,
    dependency_identity: String,
    unit_side: i64,
    invocations: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<SliceChangeKind>,
}

struct GateChangeSet {
    json: String,
    directional: bool,
}

#[derive(skyzen::FromRow)]
struct FlippedDepEdge {
    task_id: String,
    dep_met: i64,
    is_blocking: i64,
}

#[derive(serde::Serialize)]
struct OwnerDepDelta {
    owner: String,
    delta: i64,
    new_blocker: i64,
    cleared_blocker: i64,
}

#[derive(Default)]
struct OwnerDelta {
    delta: i64,
    new_blocker: i64,
    cleared_blocker: i64,
}

fn slice_row_key(row: &SliceRowJson) -> (String, String, String, String, i64, i64, i64) {
    (
        row.crate_name.clone(),
        row.version.clone(),
        row.features_json.clone(),
        row.dependency_identity.clone(),
        row.unit_side,
        row.unit_invocation,
        row.unit_linked,
    )
}

/// Fold changed slice rows into the gate's per-`(crate identity,
/// side)` invocation masks. A stored leg outside its enum — a `-1`
/// included — is corruption (stow#730): the decode fails loudly rather
/// than dropping the row from the edge-refresh set. A host-side row
/// that does not link is a real but useless shape — the gate never
/// requires it — so it folds to nothing.
fn normalize_gate_rows(
    rows: impl IntoIterator<Item = (SliceRowJson, Option<SliceChangeKind>)>,
) -> Result<Vec<NormalizedGateRow>, QueueError> {
    let mut normalized = std::collections::BTreeMap::<GateIdentity, i64>::new();
    for (row, kind) in rows {
        let invalid = |leg: &str, value: i64| {
            QueueError::Invariant(format!(
                "published slice row {}/{}/{}: {leg} = {value} is off-enum",
                row.crate_name, row.version, row.features_json
            ))
        };
        let Some(invocation) =
            stow_types::public_cache::UnitInvocation::from_int(row.unit_invocation)
        else {
            return Err(invalid("unit_invocation", row.unit_invocation));
        };
        let Some(side) = stow_types::public_cache::UnitSide::from_int(row.unit_side) else {
            return Err(invalid("unit_side", row.unit_side));
        };
        let linked = match row.unit_linked {
            0 => false,
            1 => true,
            _ => return Err(invalid("unit_linked", row.unit_linked)),
        };
        if side == stow_types::public_cache::UnitSide::Host && !linked {
            continue;
        }
        let identity = GateIdentity {
            crate_name: row.crate_name,
            version: row.version,
            features_json: row.features_json,
            dependency_identity: row.dependency_identity,
            unit_side: side.to_int(),
            kind,
        };
        let bit = 1_i64 << invocation.to_int();
        *normalized.entry(identity).or_default() |= bit;
    }
    Ok(normalized
        .into_iter()
        .map(|(identity, invocations)| NormalizedGateRow {
            crate_name: identity.crate_name,
            version: identity.version,
            features_json: identity.features_json,
            dependency_identity: identity.dependency_identity,
            unit_side: identity.unit_side,
            invocations,
            kind: identity.kind,
        })
        .collect())
}

fn normalized_gate_json(
    rows: impl IntoIterator<Item = (SliceRowJson, Option<SliceChangeKind>)>,
) -> Result<Option<String>, QueueError> {
    let normalized = normalize_gate_rows(rows)?;
    if normalized.is_empty() {
        return Ok(None);
    }
    serde_json::to_string(&normalized)
        .map(Some)
        .map_err(|error| QueueError::Sql(format!("encode slice gate json: {error}")))
}

pub async fn record_published_slice(
    db: &DurableDb,
    settings: &SchedulerSettings,
    target: &str,
    rustc_version: &str,
    report: &stow_types::api::PublishedSliceReport,
) -> Result<(), QueueError> {
    let (base_generation, generation, added, retired) = (
        report.base_generation,
        report.generation,
        report.added.as_slice(),
        report.retired.as_slice(),
    );
    // The live generation is edited in place: delete the rows the new
    // report drops, insert the rows it adds, then refresh `published_at`.
    // The ordering is delete-first so a dependent's gate never sees a
    // row the new slice dropped — the transient under-coverage (a row
    // already published to the index not yet registered here) can only
    // delay a release, and a crashed report self-heals on the next one.
    // Written rows are the report's delta — the common steady-state
    // case (same slice republished) writes one `published_slices` row —
    // and the delta is computed exactly, because only the dependents of
    // a changed row can have a new gate answer.
    let live = db
        .query(
            "SELECT generation, applied_generation FROM published_slices \
             WHERE target = ? AND rustc_version = ?",
        )
        .bind(target.to_owned())
        .bind(rustc_version.to_owned())
        .fetch_optional::<LiveSliceRow>()
        .await
        .map_err(|error| format!("read live slice {target}/{rustc_version}: {error}"))?;
    let live_generation = live.as_ref().map_or(1, |row| row.generation);
    let live_applied = live.as_ref().map(|row| row.applied_generation);
    let (changed, delta_changed_json, run_stale_cleanup) = match (base_generation, live_applied) {
        (Some(base), Some(applied)) if applied == base => {
            // Delta report on a live base: apply `added`/`retired`
            // directly — no live-slice read — and the stale-generation
            // sweep stays on the full path (it reads in proportion to
            // the slice, which a per-wave delta must not pay).
            let directional = apply_slice_delta(
                db,
                target,
                rustc_version,
                live_generation,
                &to_slice_rows(added),
                &to_slice_rows(retired),
            )
            .await?;
            let changed = directional
                .iter()
                .map(|change| change.row.clone())
                .collect::<Vec<_>>();
            let changed_json = normalized_gate_json(
                directional
                    .iter()
                    .map(|change| (change.row.clone(), Some(change.kind))),
            )?;
            (changed, changed_json, false)
        }
        (Some(base), applied) => {
            return Err(QueueError::SliceGenerationConflict {
                base_generation: base,
                live_generation: applied.unwrap_or(0),
            });
        }
        (None, _) => {
            // Full report: `added` is the whole membership and the delta
            // is computed here — the first-publish and `--full` resync
            // path. `retired` is meaningless on this shape and must be
            // empty.
            if !retired.is_empty() {
                return Err(QueueError::Sql(
                    "a full slice report carries `retired`: leave it empty for a full report"
                        .to_owned(),
                ));
            }
            let changed = apply_slice_row_delta(
                db,
                target,
                rustc_version,
                live_generation,
                &to_slice_rows(added),
            )
            .await?;
            (changed, None, true)
        }
    };
    // The applied generation the marker stamps: on a delta it is the
    // reporter's own index generation (`base + 1` when the reporter
    // does not declare one); on a full report the declared generation
    // resynchronizes the counter — without it a resync could never
    // bring `applied_generation` back onto the index sequence — and an
    // empty delta bumps nothing, so an unchanged publish leaves the
    // counter on the generation the registry's tag still resolves to.
    let next_applied = match base_generation {
        Some(_) if changed.is_empty() => None,
        Some(base) => Some(generation.unwrap_or(base + 1)),
        None => Some(generation.unwrap_or_else(|| live_applied.map_or(1, |applied| applied + 1))),
    };
    // `None` when the report changed no live row — no dependent's gate
    // answer can have moved, and the refresh statement is skipped whole.
    let gate_changes = match delta_changed_json {
        Some(json) => Some(GateChangeSet {
            json,
            directional: true,
        }),
        None if changed.is_empty() => None,
        None => normalized_gate_json(changed.into_iter().map(|row| (row, None)))?.map(|json| {
            GateChangeSet {
                json,
                directional: false,
            }
        }),
    };
    let marker_generation = live.as_ref().map_or(1, |row| row.generation);
    commit_published_slice(
        db,
        settings,
        target,
        rustc_version,
        marker_generation,
        SliceCommit {
            gate_changes,
            run_stale_cleanup,
            next_applied,
        },
    )
    .await
}

/// The tail of a slice commit — everything past the marker row itself:
/// the gate work the delta implies, whether the stale-generation sweep
/// runs, and the applied-generation the marker records.
struct SliceCommit {
    /// Edge-flip payload `apply_slice_gate_delta` runs, when the report
    /// changed live rows.
    gate_changes: Option<GateChangeSet>,
    /// Whether this commit runs the full-report stale-generation sweep.
    run_stale_cleanup: bool,
    /// The report generation the marker adopts, when it moves.
    next_applied: Option<i64>,
}

/// The live marker row of one slice — its membership epoch and the last
/// applied report generation a delta's `base_generation` is checked
/// against.
#[derive(skyzen::FromRow)]
struct LiveSliceRow {
    generation: i64,
    applied_generation: i64,
}

/// Map report rows onto the stored 6-column identity — `rowid` zeroes
/// out (only live-read rows carry one). Every report row carries a
/// digest and a unit shape: both are required on the wire, so this map
/// cannot fail.
fn to_slice_rows(rows: &[PublishedSliceRow]) -> Vec<SliceRowJson> {
    rows.iter()
        .map(|row| SliceRowJson {
            crate_name: row.crate_name.to_string(),
            version: row.version.to_string(),
            features_json: row.features_json.raw(),
            dependency_identity: row.dependency_identity.to_string(),
            unit_side: row.unit_shape.side.to_int(),
            unit_invocation: row.unit_shape.invocation.to_int(),
            unit_linked: row.unit_shape.kind.to_int(),
            rowid: 0,
        })
        .collect()
}

/// The delta-report apply: the reporter already knows the change set, so
/// the stored membership is edited by exactly `retired` then `added` —
/// never a read of the live set. Retire resolves identities through the
/// PK in one statement: the tuple IN probes the complete primary key
/// directly, without a join that first materializes the same rowids.
/// Returns the changed row set for the dependent refresh.
async fn apply_slice_delta(
    db: &DurableDb,
    target: &str,
    rustc_version: &str,
    live_generation: i64,
    added: &[SliceRowJson],
    retired: &[SliceRowJson],
) -> Result<Vec<ChangedSliceRow>, QueueError> {
    if !retired.is_empty() {
        let retired_json = serde_json::to_string(retired)
            .map_err(|error| QueueError::Sql(format!("encode slice retire json: {error}")))?;
        // `json_each` drives: each retired row is one row-value probe
        // of the table's primary key — the ten-column tuple in PK order,
        // `dependency_identity` included (NOT NULL, so row-value
        // equality is exact; stow#588). One PK lookup per retired row,
        // proportional to the delta, never a slice scan — and no rowid
        // second seek.
        db.query(
            "DELETE FROM published_slice_rows \
             WHERE (target, rustc_version, generation, crate_name, version, features_json, dependency_identity, unit_side, unit_invocation, unit_linked) IN ( \
                 SELECT ?, ?, ?, e ->> 'crate_name', e ->> 'version', \
                        e ->> 'features_json', e ->> 'dependency_identity', \
                        e ->> 'unit_side', e ->> 'unit_invocation', e ->> 'unit_linked' \
                 FROM (SELECT value AS e FROM json_each(?)))",
        )
        .bind(target.to_owned())
        .bind(rustc_version.to_owned())
        .bind(live_generation)
        .bind(retired_json)
        .execute()
        .await
        .map_err(|error| format!("drop retired slice rows {target}/{rustc_version}: {error}"))?;
    }
    let mut changed = retired
        .iter()
        .cloned()
        .map(|row| ChangedSliceRow {
            row,
            kind: SliceChangeKind::Retired,
        })
        .collect::<Vec<_>>();
    if !added.is_empty() {
        let added_json = serde_json::to_string(added)
            .map_err(|error| QueueError::Sql(format!("encode slice insert json: {error}")))?;
        db.query(
            "INSERT INTO published_slice_rows \
             (target, rustc_version, generation, crate_name, version, features_json, dependency_identity, unit_side, unit_invocation, unit_linked) \
             SELECT ?, ?, ?, e ->> 'crate_name', e ->> 'version', e ->> 'features_json', \
                    e ->> 'dependency_identity', e ->> 'unit_side', \
                    e ->> 'unit_invocation', e ->> 'unit_linked' \
             FROM (SELECT value AS e FROM json_each(?)) \
             WHERE TRUE \
             ON CONFLICT DO NOTHING",
        )
        .bind(target.to_owned())
        .bind(rustc_version.to_owned())
        .bind(live_generation)
        .bind(added_json)
        .execute()
        .await
        .map_err(|error| format!("record published slice rows {target}/{rustc_version}: {error}"))?;
        changed.extend(added.iter().cloned().map(|row| ChangedSliceRow {
            row,
            kind: SliceChangeKind::Added,
        }));
    }
    Ok(changed)
}

/// The write half of [`record_published_slice`]: diff the live
/// generation against the report in Rust, delete exactly the retired
/// keys and insert exactly the new ones, and return the changed row
/// set. The tuple `NOT IN` retire this replaces never materialized an
/// auto-index on workerd — each candidate row re-evaluated the whole
/// report (128k reads on one publish). One PK-prefix SELECT of the
/// slice's live members is a bounded read instead, and the writes are
/// proportional to the delta.
async fn apply_slice_row_delta(
    db: &DurableDb,
    target: &str,
    rustc_version: &str,
    live_generation: i64,
    report_rows: &[SliceRowJson],
) -> Result<Vec<SliceRowJson>, QueueError> {
    let live_rows = db
        .query(
            "SELECT rowid, crate_name, version, features_json, dependency_identity, unit_side, unit_invocation, unit_linked \
             FROM published_slice_rows \
             WHERE target = ? AND rustc_version = ? AND generation = ?",
        )
        .bind(target.to_owned())
        .bind(rustc_version.to_owned())
        .bind(live_generation)
        .fetch_all::<SliceRowJson>()
        .await
        .map_err(|error| format!("read live slice rows {target}/{rustc_version}: {error}"))?;
    let report_keys: std::collections::BTreeSet<_> =
        report_rows.iter().map(slice_row_key).collect();
    let live_keys: std::collections::BTreeSet<_> = live_rows.iter().map(slice_row_key).collect();
    let retire: Vec<SliceRowJson> = live_rows
        .into_iter()
        .filter(|row| !report_keys.contains(&slice_row_key(row)))
        .collect();
    // Retire by rowid — a tuple `IN` over six columns would need six
    // binds per row and workerd caps a statement at ~100 variables, so
    // a full-slice retire must chunk by the cheapest key it has.
    for chunk in retire.chunks(SLICE_ROWID_DELETE_BATCH) {
        let mut query_sql = String::from("DELETE FROM published_slice_rows WHERE rowid IN (");
        for (index, _) in chunk.iter().enumerate() {
            if index > 0 {
                query_sql.push(',');
            }
            query_sql.push('?');
        }
        query_sql.push(')');
        let mut query = db.query(&query_sql);
        for row in chunk {
            query = query.bind(row.rowid);
        }
        query.execute().await.map_err(|error| {
            format!("drop retired slice rows {target}/{rustc_version}: {error}")
        })?;
    }
    let mut changed: Vec<SliceRowJson> = retire;
    // `report − live` names the rows entering the set — insert exactly
    // those, keyed point writes proportional to the delta.
    let added: Vec<SliceRowJson> = report_rows
        .iter()
        .filter(|row| !live_keys.contains(&slice_row_key(row)))
        .cloned()
        .collect();
    if !added.is_empty() {
        let added_json = serde_json::to_string(&added)
            .map_err(|error| QueueError::Sql(format!("encode slice insert json: {error}")))?;
        db.query(
            "INSERT INTO published_slice_rows \
             (target, rustc_version, generation, crate_name, version, features_json, dependency_identity, unit_side, unit_invocation, unit_linked) \
             SELECT ?, ?, ?, e ->> 'crate_name', e ->> 'version', e ->> 'features_json', \
                    e ->> 'dependency_identity', e ->> 'unit_side', \
                    e ->> 'unit_invocation', e ->> 'unit_linked' \
             FROM (SELECT value AS e FROM json_each(?)) \
             WHERE TRUE \
             ON CONFLICT DO NOTHING",
        )
        .bind(target.to_owned())
        .bind(rustc_version.to_owned())
        .bind(live_generation)
        .bind(added_json)
        .execute()
        .await
        .map_err(|error| format!("record published slice rows {target}/{rustc_version}: {error}"))?;
        changed.extend(added);
    }
    Ok(changed)
}

/// The commit tail of [`record_published_slice`]: flip the live
/// generation's marker row (advancing `applied_generation`, the token
/// the next delta report bases on), retire rows a crashed earlier
/// report left at never-published generations — full reports only; a
/// delta report never writes outside the live generation — then flip
/// the persisted `dep_met` on exactly the edges a changed row matched,
/// moving each owner's `unpublished_deps` counter by the flip delta
/// (stow#521). `changed_json` is the exact set of slice rows this
/// report added or retired, so the pass probes edges through
/// `idx_queue_dependencies_dep_match` — one index walk per changed row
/// — and touches the owners of flipped edges alone. Every statement is
/// one batched write: a publish costs 1 + the delta's dependents, never
/// the queue or the edge graph.
async fn commit_published_slice(
    db: &DurableDb,
    settings: &SchedulerSettings,
    target: &str,
    rustc_version: &str,
    live_generation: i64,
    commit: SliceCommit,
) -> Result<(), QueueError> {
    let SliceCommit {
        gate_changes,
        run_stale_cleanup,
        next_applied,
    } = commit;
    if let Some(next_applied) = next_applied {
        db.query(
            "INSERT INTO published_slices \
             (target, rustc_version, generation, applied_generation) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT(target, rustc_version) DO UPDATE \
             SET published_at = datetime('now'), applied_generation = ?",
        )
        .bind(target.to_owned())
        .bind(rustc_version.to_owned())
        .bind(live_generation)
        .bind(next_applied)
        .bind(next_applied)
        .execute()
        .await
        .map_err(|error| format!("publish slice {target}/{rustc_version}: {error}"))?;
    } else {
        db.query(
            "INSERT INTO published_slices (target, rustc_version, generation) \
             VALUES (?, ?, ?) \
             ON CONFLICT(target, rustc_version) DO UPDATE \
             SET published_at = datetime('now')",
        )
        .bind(target.to_owned())
        .bind(rustc_version.to_owned())
        .bind(live_generation)
        .execute()
        .await
        .map_err(|error| format!("publish slice {target}/{rustc_version}: {error}"))?;
    }
    if run_stale_cleanup {
        // Rows a crashed pre-delta report left at a never-published
        // generation have no live-set claim; delete them so they cannot
        // merge into the answer the gate reads. Two disjoint PK ranges
        // avoid reading the live generation merely to exclude it.
        db.query(
            "DELETE FROM published_slice_rows \
             WHERE rowid IN ( \
                 SELECT rowid FROM published_slice_rows \
                 WHERE target = ? AND rustc_version = ? AND generation < ? \
                 UNION ALL \
                 SELECT rowid FROM published_slice_rows \
                 WHERE target = ? AND rustc_version = ? AND generation > ?)",
        )
        .bind(target.to_owned())
        .bind(rustc_version.to_owned())
        .bind(live_generation)
        .bind(target.to_owned())
        .bind(rustc_version.to_owned())
        .bind(live_generation)
        .execute()
        .await
        .map_err(|error| format!("retire stale slice rows {target}/{rustc_version}: {error}"))?;
    }
    let Some(gate_changes) = gate_changes else {
        return Ok(());
    };
    apply_slice_gate_delta(
        db,
        target,
        rustc_version,
        gate_changes.json.clone(),
        live_generation,
        gate_changes.directional,
    )
    .await?;
    // The shape-coverage repair (stow#785): only now is it decidable
    // whether the deps this report touched cover their dependents'
    // edges — before this commit a completed dep always looked
    // uncovered, so no earlier event could judge it.
    requeue_incomplete_shape_deps(db, settings, &gate_changes.json, target, rustc_version).await
}

/// Build the direct-dependent join, optionally restricting explicit delta
/// rows by the only old flag each direction can change.
fn matched_edges_sql(directional_delta: bool) -> String {
    let direction_filter = if directional_delta {
        "AND ((j.c ->> 'kind' = 'added' AND d.dep_met = 0) \
              OR (j.c ->> 'kind' = 'retired' AND d.dep_met = 1))"
    } else {
        ""
    };
    format!(
        "FROM (SELECT value AS c FROM json_each(?)) AS j \
         CROSS JOIN queue_dependencies d \
           ON d.dep_target = ? AND d.dep_rustc_version = ? \
          AND d.dep_crate_name = j.c ->> 'crate_name' \
          AND d.dep_version = j.c ->> 'version' \
          AND d.dep_features_json = j.c ->> 'features_json' \
          AND d.dep_host_side = j.c ->> 'unit_side' \
          AND d.dep_dependency_identity = j.c ->> 'dependency_identity' \
          AND (d.dep_invocations & (j.c ->> 'invocations')) != 0 \
          {direction_filter}",
    )
}

fn fold_owner_deltas(flipped: &[FlippedDepEdge]) -> Vec<OwnerDepDelta> {
    let mut deltas = std::collections::BTreeMap::<String, OwnerDelta>::new();
    for edge in flipped {
        let owner = deltas.entry(edge.task_id.clone()).or_default();
        owner.delta += 1 - 2 * edge.dep_met;
        if edge.is_blocking != 0 {
            if edge.dep_met == 0 {
                owner.new_blocker = 1;
            } else {
                owner.cleared_blocker = 1;
            }
        }
    }
    deltas
        .into_iter()
        .map(|(owner, delta)| OwnerDepDelta {
            owner,
            delta: delta.delta,
            new_blocker: delta.new_blocker,
            cleared_blocker: delta.cleared_blocker,
        })
        .collect()
}

/// The gate half of a slice commit: membership changed for exactly the
/// `changed_json` rows, so flip the persisted `dep_met` on the edges
/// they match and move each owner's `unpublished_deps` counter by the
/// flip delta — a publish touches 1 + the delta's direct dependents,
/// never the queue or the graph (stow#521). The matched-edge set —
/// edges whose dep identity a changed row can flip — is bounded in the
/// flip statement: Rust normalizes duplicate shapes before JSON, then
/// `json_each` drives the indexed match join and `GROUP BY d.rowid` emits
/// one answer per changed edge. `RETURNING` hands the flips
/// back so the one `queue` update that follows keys off the flipped owners
/// instead of re-walking the matched set.
/// `live_generation` is the generation the marker commit already
/// wrote — bound once into the edge probe instead of seeking the
/// marker per edge.
async fn apply_slice_gate_delta(
    db: &DurableDb,
    target: &str,
    rustc_version: &str,
    changed_json: String,
    live_generation: i64,
    directional_delta: bool,
) -> Result<(), QueueError> {
    let matched_edges = matched_edges_sql(directional_delta);
    // Materialize one answer per matched edge. GROUP BY d.rowid collapses
    // duplicate changed shapes before the membership expression is projected,
    // while the MATERIALIZED boundary prevents UPDATE/filter planning from
    // reevaluating that bounded answer probe. The write guard still avoids
    // touching an edge whose persisted flag already equals that answer.
    let flipped = db
        .query(&format!(
            "WITH answers AS MATERIALIZED ( \
                 SELECT d.rowid AS rid, d.dep_met AS old_met, \
                        CASE WHEN {unpub} THEN 0 ELSE 1 END AS new_met \
                 {matched_edges} \
                 GROUP BY d.rowid \
             ) \
             UPDATE queue_dependencies \
             SET dep_met = answers.new_met \
             FROM answers \
             WHERE queue_dependencies.rowid = answers.rid \
               AND answers.old_met != answers.new_met \
             RETURNING queue_dependencies.task_id, queue_dependencies.dep_met, \
                       CASE WHEN EXISTS ( \
                                      SELECT 1 FROM queue bdep \
                                      WHERE bdep.task_id = queue_dependencies.depends_on_task_id \
                                        AND bdep.status = 'failed' \
                                  ) \
                            THEN 1 ELSE 0 END AS is_blocking",
            unpub = dep_edge_unpublished_sql_at("d", "?"),
        ))
        .bind(live_generation)
        .bind(changed_json)
        .bind(target.to_owned())
        .bind(rustc_version.to_owned())
        .fetch_all::<FlippedDepEdge>()
        .await
        .map_err(|error| format!("flip dep_met for slice {target}/{rustc_version}: {error}"))?;
    if flipped.is_empty() {
        return Ok(());
    }
    // 2. Fold the flips into per-owner counter deltas — a flip to
    //    `dep_met = 0` (met→unmet) is +1, a flip to 1 is −1 — then one
    //    statement applies counter, `deps_met` and `blocked` per
    //    owner row. Every flipped owner rides the payload, even a
    //    net-zero one: its edges moved even when its counter did not,
    //    so `blocked` can still move. `blocked` evaluates on pending
    //    rows only — the `status = 'pending'` restriction stays inside
    //    the CASE, not as an outer literal, so the planner never walks
    //    the status index over the whole pending group (measured 60k
    //    reads on the 100k fixture) — and non-pending owners keep their
    //    stored flag. Join the unique owner payload directly to the
    //    target: a second owner lookup and materialization would read
    //    the same row again just to assign these expressions. The
    //    returned blocking bit also proves two owner-local cases without
    //    rewalking that owner's edges: a newly unmet fatal edge sets
    //    blocked, while no fatal edge cleared leaves it unchanged. Only
    //    a clear without a new blocker needs the exact residual probe;
    //    net-zero owners still take that path when it is ambiguous, and
    //    a zero counter takes the direct zero case.
    let owners = fold_owner_deltas(&flipped);
    db.query(&format!(
        "UPDATE queue \
         SET unpublished_deps = queue.unpublished_deps + j.delta, \
             deps_met = (queue.unpublished_deps + j.delta = 0), \
             blocked = CASE WHEN queue.status != 'pending' THEN queue.blocked \
                            WHEN queue.unpublished_deps + j.delta = 0 THEN 0 \
                            WHEN j.new_blocker != 0 THEN 1 \
                            WHEN j.cleared_blocker = 0 THEN queue.blocked \
                            ELSE {blocked} END \
         FROM (SELECT value ->> 'owner' AS owner, value ->> 'delta' AS delta, \
                      value ->> 'new_blocker' AS new_blocker, \
                      value ->> 'cleared_blocker' AS cleared_blocker \
               FROM json_each(?)) AS j \
         WHERE queue.task_id = j.owner",
        blocked = blocked_sql("queue.task_id"),
    ))
    .bind(enqueue_json(&owners)?)
    .execute()
    .await
    .map_err(|error| format!("adjust owners for slice {target}/{rustc_version}: {error}"))?;
    Ok(())
}

/// One `sqlite_master` row — the store objects [`reset`] drops.
#[derive(Debug, skyzen::FromRow)]
struct SchemaObject {
    kind: String,
    name: String,
}

/// Reset the scheduler store — the only code that may issue DDL on the
/// queue database. Drops every table, index, trigger and view the store
/// holds, then executes `schema.sql`; it reads no row data — a schema
/// change is applied by this reset, never by reading an older shape,
/// and the store refills from the lanes that feed it. Reached from
/// `POST /api/v1/admin/scheduler/reset` (→ the Durable Object's
/// `/reset` handler); `stow-admin scheduler reset --yes` is the manual
/// path. A store that was never initialized gets the same pass. Request
/// code and the alarm assume the schema exists — when it does not,
/// their own SQL fails loudly, which is the fail-fast.
pub async fn reset(db: &DurableDb) -> Result<SchedulerResetReport, QueueError> {
    // The lease and stale recovery clock `claimed_at` (stow#786): a
    // store carrying an in-flight row without one would hold a task no
    // recovery can ever reclaim — `MIN`/`<=` skip NULL — so the
    // migration refuses to land over it. The probe only runs where a
    // queue table already stands.
    let queue_exists = db
        .query(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'table' AND name = 'queue'",
        )
        .fetch_scalar::<i64>()
        .await
        .map_err(|error| format!("probe queue table presence: {error}"))?
        > 0;
    if queue_exists {
        let unclocked = db
            .query(
                "SELECT COUNT(*) FROM queue \
                 WHERE status IN ('dispatched', 'running') AND claimed_at IS NULL",
            )
            .fetch_scalar::<i64>()
            .await
            .map_err(|error| format!("probe unclocked in-flight rows: {error}"))?;
        if unclocked > 0 {
            return Err(QueueError::Invariant(format!(
                "refusing to migrate: {unclocked} in-flight queue row(s) carry a NULL claimed_at"
            )));
        }
    }
    // The store's objects minus SQLite's own (`sqlite_sequence` and
    // friends) and the platform's internal tables — GLOB keeps the
    // `_` literals.
    let objects = db
        .query(
            "SELECT type AS kind, name FROM sqlite_master \
             WHERE type IN ('table', 'index', 'trigger', 'view') \
               AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*'",
        )
        .fetch_all::<SchemaObject>()
        .await
        .map_err(|error| format!("list scheduler store objects: {error}"))?;
    // A table's drop takes its indexes and triggers with it, so the
    // `IF EXISTS` statements below only ever fire on objects still
    // standing — an orphaned name is a no-op, never an error.
    for (kind, keyword) in [
        ("trigger", "TRIGGER"),
        ("view", "VIEW"),
        ("table", "TABLE"),
        ("index", "INDEX"),
    ] {
        for object in objects.iter().filter(|object| object.kind == kind) {
            db.query(&format!("DROP {keyword} IF EXISTS {}", object.name))
                .execute()
                .await
                .map_err(|error| format!("drop {kind} {}: {error}", object.name))?;
        }
    }
    db.query(include_str!("schema.sql"))
        .execute()
        .await
        .map_err(|error| format!("create scheduler schema: {error}"))?;
    Ok(SchedulerResetReport {
        dropped: objects.len() as u64,
    })
}

/// The operator floor application — pure row work (a stored-floor read,
/// the conditional backfill, the stamp), no DDL. The reset route's
/// handler runs it after [`reset`] recreates the schema: on the empty
/// queue the conditional backfill is a zero-row pass and the stamp
/// lands the configured floor as `settings.min_dispatch_value`, the
/// value every writer's eligibility expression reads. The cost-gate's
/// floored-pass fixture calls it directly from an unmetered setup hook
/// so the probe's floor and flags take the same code path (stow#525).
///
/// The stamp is the pass's success record, so it writes LAST: the
/// backfill evaluates against the configured floor as its operand — an
/// i64 literal, since the settings row it must not read is the row this
/// same pass is about to write — and only a completed backfill earns
/// the stamp. A statement failure leaves the pass unstamped, so a
/// retried call sees the old stored value (or none) and runs the full
/// repair again; a completed pass needs no re-verification because the
/// writers' flags stayed consistent with the stored value throughout.
pub(super) async fn apply_dispatch_floor(
    db: &DurableDb,
    settings: &SchedulerSettings,
) -> Result<(), QueueError> {
    let stored = db
        .query("SELECT value FROM settings WHERE key = 'min_dispatch_value'")
        .fetch_scalar_optional::<String>()
        .await
        .map_err(|error| format!("read applied dispatch floor: {error}"))?
        .map(|raw| raw.parse::<i64>())
        .transpose()
        .map_err(|error| format!("parse applied dispatch floor: {error}"))?;
    if stored != Some(settings.min_dispatch_value) {
        let eligible = dispatch_eligible_at_floor_sql(
            "lane",
            "value",
            &settings.min_dispatch_value.to_string(),
        );
        db.query(&format!(
            "UPDATE queue SET dispatch_eligible = {eligible} \
             WHERE dispatch_eligible != {eligible}",
        ))
        .execute()
        .await
        .map_err(|error| format!("backfill dispatch eligibility: {error}"))?;
        db.query(
            "INSERT INTO settings (key, value) VALUES ('min_dispatch_value', ?) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(settings.min_dispatch_value.to_string())
        .execute()
        .await
        .map_err(|error| format!("stamp applied dispatch floor: {error}"))?;
    }
    Ok(())
}

/// The longest one build-batch round may run: the build job's
/// 120-minute timeout plus the publish job's 60.
const BATCH_ROUND_CEILING_MINUTES: i64 = 180;

/// A runner-queue allowance on top of a batch's rounds — the run can
/// never legitimately outlast its rounds plus this.
const BATCH_CEILING_ALLOWANCE_MINUTES: i64 = 60;

/// The most expired batches one lease pass reads. The in-flight batch
/// set is already bounded by the family slot caps over
/// `STOW_BATCH_PARALLELISM`, so this only caps a pass's run lookups; a
/// batch left over keeps its past `lease_at` and the alarm re-arms at
/// once.
const EXPIRED_BATCH_LIMIT: i64 = 32;

/// Why a batch past its ceiling fails — the error its in-flight legs
/// record, and whether a completion recorded since the caller's lookup
/// wins over the failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeilingFailure {
    /// The lease check found the run still going past the ceiling and
    /// cancelled it.
    RunOutlived,
    /// The lease check could not learn the run's state — the lookup, the
    /// cancel or the token mint kept failing — until the ceiling.
    RunUnreadable,
    /// The resolution pass could not read or settle the completed run's
    /// results until the ceiling.
    ResolutionStalled,
}

impl CeilingFailure {
    /// The `error_msg` the failed legs record.
    const fn error(self) -> &'static str {
        match self {
            Self::RunOutlived => "infrastructure: run exceeded its ceiling",
            Self::RunUnreadable => "infrastructure: run state unreadable past its ceiling",
            Self::ResolutionStalled => {
                "infrastructure: run results unreadable or unsettled past its ceiling"
            }
        }
    }

    /// Whether a completion recorded since the caller's lookup wins: the
    /// lease check's batches are the ones without a recorded completion,
    /// and one that landed meanwhile is the resolution pass's. The
    /// resolution pass's own batches always carry one.
    const fn recorded_completion_wins(self) -> bool {
        match self {
            Self::RunOutlived | Self::RunUnreadable => true,
            Self::ResolutionStalled => false,
        }
    }
}

/// A batch's absolute deadline in epoch milliseconds:
/// `claimed_at + ⌈legs / parallelism⌉ × 180 min + 60 min`. Both passes
/// read it — the lease check cancels a run past it, the resolution pass
/// stops deferring at it.
///
/// # Errors
/// [`QueueError::Invariant`] when `parallelism` is zero.
fn batch_ceiling_ms(
    batch_id: &str,
    claimed_epoch: i64,
    legs: u32,
    parallelism: u32,
) -> Result<i64, QueueError> {
    if parallelism == 0 {
        return Err(QueueError::Invariant(format!(
            "batch {batch_id} has zero parallelism"
        )));
    }
    let rounds = i64::from(legs.div_ceil(parallelism));
    let ceiling_minutes = rounds * BATCH_ROUND_CEILING_MINUTES + BATCH_CEILING_ALLOWANCE_MINUTES;
    Ok((claimed_epoch + ceiling_minutes * 60) * 1000)
}

/// A `build_batches` row whose lease has run out, with the facts the
/// lease check decides on (stow#833 §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredBatch {
    /// `build_batches.batch_id`.
    pub batch_id: String,
    /// The run the dispatch response bound, `None` when that response
    /// was lost — an unbound batch has no run to ask about.
    pub run_id: Option<u64>,
    /// Whether `now` is past the batch's hard ceiling,
    /// `claimed_at + ⌈legs / parallelism⌉ × 180 min + 60 min`.
    pub past_ceiling: bool,
}

#[derive(Debug, skyzen::FromRow)]
struct ExpiredBatchRow {
    batch_id: String,
    github_run_id: Option<String>,
    legs: u32,
    parallelism: u32,
    claimed_epoch: i64,
}

/// The batches whose lease has expired — `lease_at <= now`, earliest
/// first, at most [`EXPIRED_BATCH_LIMIT`]. A batch whose completion is
/// recorded against its bound run is the resolution pass's, not the
/// lease check's, and stays out.
///
/// # Errors
/// [`QueueError::Invariant`] when a row's run id is not numeric or its
/// `parallelism` is zero — corrupt state.
pub async fn expired_batches(db: &DurableDb, now_ms: i64) -> Result<Vec<ExpiredBatch>, QueueError> {
    let rows = db
        .query(
            "SELECT batch_id, github_run_id, legs, parallelism, \
                    CAST(strftime('%s', claimed_at) AS INTEGER) AS claimed_epoch \
             FROM build_batches \
             WHERE lease_at <= datetime(CAST(? AS INTEGER) / 1000, 'unixepoch') \
               AND (done_run_id IS NULL OR github_run_id IS NULL) \
             ORDER BY lease_at, batch_id \
             LIMIT ?",
        )
        .bind(now_ms)
        .bind(EXPIRED_BATCH_LIMIT)
        .fetch_all::<ExpiredBatchRow>()
        .await
        .map_err(|error| format!("list expired batches: {error}"))?;
    rows.into_iter()
        .map(|row| {
            let ceiling_ms =
                batch_ceiling_ms(&row.batch_id, row.claimed_epoch, row.legs, row.parallelism)?;
            let run_id = row
                .github_run_id
                .map(|run| {
                    run.parse::<u64>().map_err(|error| {
                        QueueError::Invariant(format!(
                            "batch {} is bound to run {run:?}: {error}",
                            row.batch_id
                        ))
                    })
                })
                .transpose()?;
            Ok(ExpiredBatch {
                batch_id: row.batch_id,
                run_id,
                past_ceiling: now_ms >= ceiling_ms,
            })
        })
        .collect()
}

/// Requeue an unbound expired batch's legs and release its row — the
/// dispatch response was lost, so there is no run to ask about.
///
/// Legs re-enter `pending`: `deps_met` re-derives from the live
/// counter, and `blocked` — maintained for pending rows only — may be
/// stale on an in-flight row; both recompute in the same statement.
/// `not_before` is untouched, so `wake_at` re-derives from the live
/// columns. One statement for the legs, then the row delete that frees
/// the batch's slots.
pub async fn requeue_unbound_batch(
    db: &DurableDb,
    settings: &SchedulerSettings,
    batch_id: &str,
) -> Result<(), QueueError> {
    let recovered = db
        .query(&format!(
            "UPDATE queue \
             SET status = 'pending', error_msg = '', deps_met = {deps_met}, \
                 blocked = {blocked}, wake_at = {wake}, \
                 updated_at = datetime('now') \
             WHERE batch_id = ? AND status IN ('dispatched', 'running') \
             RETURNING task_id",
            deps_met = deps_met_sql("queue.task_id"),
            blocked = blocked_sql("queue.task_id"),
            wake = wake_at_sql(
                "lane",
                "first_requested_at",
                "not_before",
                settings.dispatch_min_age_minutes,
            ),
        ))
        .bind(batch_id.to_owned())
        .fetch_scalars::<String>()
        .await
        .map_err(|error| format!("requeue legs of unbound batch {batch_id}: {error}"))?;
    if !recovered.is_empty() {
        // Re-entered `pending` rows carry the rank written before the
        // last cost move; re-price exactly the transitioned ids.
        refresh_dispatch_keys(db, &recovered).await?;
    }
    db.query("DELETE FROM build_batches WHERE batch_id = ?")
        .bind(batch_id.to_owned())
        .execute()
        .await
        .map_err(|error| format!("delete requeued batch {batch_id}: {error}"))?;
    Ok(())
}

/// Push a bound batch's lease out by `stale_dispatch_minutes` from
/// `now_ms` — its run is still going. A completion recorded since the
/// lookup is the resolution pass's and is left alone.
pub async fn extend_batch_lease(
    db: &DurableDb,
    settings: &SchedulerSettings,
    batch_id: &str,
    now_ms: i64,
) -> Result<(), QueueError> {
    set_batch_lease(
        db,
        batch_id,
        now_ms + i64::from(settings.stale_dispatch_minutes) * 60_000,
    )
    .await
}

/// Move a batch's `lease_at` to `lease_ms` — the lease check's single
/// write for a batch it leaves alive, either extended after a live
/// run or deferred a moment after a failed lookup so the alarm does not
/// re-arm at `now`. A completion recorded since the lookup is the
/// resolution pass's and is left alone.
pub async fn set_batch_lease(
    db: &DurableDb,
    batch_id: &str,
    lease_ms: i64,
) -> Result<(), QueueError> {
    db.query(
        "UPDATE build_batches \
         SET lease_at = datetime(CAST(? AS INTEGER) / 1000, 'unixepoch') \
         WHERE batch_id = ? AND done_run_id IS NULL",
    )
    .bind(lease_ms)
    .bind(batch_id.to_owned())
    .execute()
    .await
    .map_err(|error| format!("set lease of batch {batch_id}: {error}"))?;
    Ok(())
}

/// Fail a batch that reached its ceiling: the legs still in flight fail
/// in one statement with `cause`'s error and the row is released. For a
/// cause where [`CeilingFailure::recorded_completion_wins`], a
/// completion recorded since the lookup wins — the legs and the row are
/// left to the resolution pass.
pub async fn fail_batch_past_ceiling(
    db: &DurableDb,
    batch_id: &str,
    cause: CeilingFailure,
) -> Result<(), QueueError> {
    let guarded = i64::from(cause.recorded_completion_wins());
    let failed = db
        .query(
            "UPDATE queue \
             SET status = 'failed', error_msg = ?, updated_at = datetime('now') \
             WHERE batch_id = ? AND status IN ('dispatched', 'running') \
               AND (? = 0 OR EXISTS (SELECT 1 FROM build_batches \
                                     WHERE batch_id = ? AND done_run_id IS NULL)) \
             RETURNING task_id",
        )
        .bind(cause.error().to_owned())
        .bind(batch_id.to_owned())
        .bind(guarded)
        .bind(batch_id.to_owned())
        .fetch_scalars::<String>()
        .await
        .map_err(|error| format!("fail legs of batch {batch_id}: {error}"))?;
    if !failed.is_empty() {
        // A dep that just failed is the one outside-the-row event that
        // flips a pending dependent's `blocked` flag.
        refresh_dependents(
            db,
            "SELECT value AS task_id FROM json_each(?)",
            &[DbValue::Text(enqueue_json(&failed)?)],
        )
        .await?;
    }
    db.query("DELETE FROM build_batches WHERE batch_id = ? AND (? = 0 OR done_run_id IS NULL)")
        .bind(batch_id.to_owned())
        .bind(guarded)
        .execute()
        .await
        .map_err(|error| format!("delete failed batch {batch_id}: {error}"))?;
    Ok(())
}

/// A lease check that could not learn or settle a bound batch's run —
/// the lookup, the cancel or the token mint failed. Inside the batch's
/// ceiling the lease moves `retry_ms` out and the next pass asks again;
/// at the ceiling the batch fails ([`fail_batch_past_ceiling`]), so a
/// run GitHub never answers for cannot hold its slots or the alarm
/// forever.
pub async fn retry_unreadable_batch(
    db: &DurableDb,
    batch: &ExpiredBatch,
    now_ms: i64,
    retry_ms: i64,
) -> Result<BatchRetry, QueueError> {
    if batch.past_ceiling {
        tracing::error!(
            batch_id = %batch.batch_id,
            run_id = ?batch.run_id,
            "run state unreadable at the batch's ceiling — failing its legs"
        );
        fail_batch_past_ceiling(db, &batch.batch_id, CeilingFailure::RunUnreadable).await?;
        return Ok(BatchRetry::Failed);
    }
    set_batch_lease(db, &batch.batch_id, now_ms + retry_ms).await?;
    Ok(BatchRetry::Deferred)
}

/// A batch whose legs all left flight — resolved individually or
/// failed — holds no slots: its `parallelism` must stop counting
/// against the family's pools. Stale in-flight rows are not requeued
/// here: the lease check ([`expired_batches`]) decides each expired
/// batch from its run's own state.
async fn release_legless_batches(db: &DurableDb) -> Result<(), QueueError> {
    db.query(
        "DELETE FROM build_batches \
         WHERE NOT EXISTS ( \
             SELECT 1 FROM queue \
             WHERE queue.batch_id = build_batches.batch_id \
               AND queue.status IN ('dispatched', 'running') \
         )",
    )
    .execute()
    .await
    .map_err(|error| format!("release legless batches: {error}"))?;
    Ok(())
}

/// A `completed` dependency is not done until its published slice rows
/// cover every unit shape a dependent's edge requires — a verdict that
/// is decidable only at the report publishing the dep's own rows
/// (stow#785: at claim time a freshly built dep always looks
/// uncovered). The slice commit drives it from `changed_json`, the
/// report's own changed rows: each matches its queue row through the
/// unique queue identity in one probe, and `idx_queue_dependencies_dep`
/// answers whether a dependent edge still stands `dep_met = 0`. Cost is
/// the changed-row count times their direct dependents — event-sized,
/// never the stored queue. Re-queue once behind the same backoff the
/// failed-dependency requeue applies; `shape_requeue` latches the
/// repair so it runs at most once.
async fn requeue_incomplete_shape_deps(
    db: &DurableDb,
    settings: &SchedulerSettings,
    changed_json: &str,
    target: &str,
    rustc_version: &str,
) -> Result<(), QueueError> {
    // Rows re-enter `pending`: `deps_met` re-derives from the live
    // counter, and `blocked` — maintained for pending rows only — is
    // stale on a completed row; both recompute in the same statement,
    // alongside the `not_before` bump's `wake_at`.
    let next_not_before = "MAX(not_before, datetime('now', '+' || MIN(1 << MIN(dispatch_attempts, 6), 60) || ' minutes'))";
    // The candidates first, payload-driven: each changed row probes the
    // queue's unique identity index once and `idx_queue_dependencies_dep`
    // answers whether a dependent edge still stands unmet — the read set
    // is the changed-row count plus their matched rows, never a queue
    // range (an UPDATE-side `status` predicate scanned the completed
    // band, ~350k billed reads at 1M rows).
    let candidates = db
        .query(
            "SELECT q.task_id FROM (SELECT value AS c FROM json_each(?)) AS j \
             CROSS JOIN queue q \
                 ON q.crate_name = j.c ->> 'crate_name' \
                AND q.version = j.c ->> 'version' \
                AND q.features_json = j.c ->> 'features_json' \
                AND q.host_side = j.c ->> 'unit_side' \
                AND q.dependency_identity = j.c ->> 'dependency_identity' \
             WHERE q.target = ? AND q.rustc_version = ? \
               AND q.status = 'completed' AND q.shape_requeue = 0 \
               AND EXISTS ( \
                   SELECT 1 FROM queue_dependencies d \
                   WHERE d.depends_on_task_id = q.task_id \
                     AND d.dep_met = 0 \
               )",
        )
        .bind(changed_json.to_owned())
        .bind(target.to_owned())
        .bind(rustc_version.to_owned())
        .fetch_scalars::<String>()
        .await
        .map_err(|error| format!("find shape-incomplete dependencies: {error}"))?;
    if candidates.is_empty() {
        return Ok(());
    }
    let requeued = db
        .query(&format!(
            "UPDATE queue \
             SET status = 'pending', \
                 attempt = attempt + 1, \
             error_msg = '', \
             deps_met = {deps_met}, \
             blocked = {blocked}, \
             not_before = {next_not_before}, \
             wake_at = {wake}, \
             updated_at = datetime('now'), \
             shape_requeue = 1 \
         WHERE task_id IN (SELECT value FROM json_each(?)) \
         RETURNING task_id",
            deps_met = deps_met_sql("queue.task_id"),
            blocked = blocked_sql("queue.task_id"),
            wake = wake_at_sql(
                "lane",
                "first_requested_at",
                next_not_before,
                settings.dispatch_min_age_minutes,
            ),
        ))
        .bind(enqueue_json(&candidates).map_err(|error| error.to_string())?)
        .fetch_scalars::<String>()
        .await
        .map_err(|error| format!("requeue shape-incomplete dependencies: {error}"))?;
    if !requeued.is_empty() {
        // Re-entered `pending` rows carry the rank written before the
        // last cost move; re-price exactly the transitioned ids.
        refresh_dispatch_keys(db, &requeued).await?;
    }
    Ok(())
}

/// In-flight runner slots counted by family — the `parallelism` sums
/// of the live `build_batches` rows, not leg counts (stow#833 §1.2):
/// one row read per in-flight batch, at most about ⌈slots/k⌉ plus
/// the human lane's.
struct ActiveByFamily {
    total: u32,
    by_family: std::collections::HashMap<RunnerFamily, u32>,
}

impl ActiveByFamily {
    /// Active slots building on `family`'s runner pool.
    fn of(&self, family: RunnerFamily) -> u32 {
        self.by_family.get(&family).copied().unwrap_or(0)
    }
}

/// The `dispatch_family` label a stored row carries, inverted through
/// [`dispatch_family_label`] so the two can never drift apart.
fn family_of_label(label: &str) -> Option<RunnerFamily> {
    RunnerFamily::ALL
        .into_iter()
        .find(|family| dispatch_family_label(*family) == label)
}

async fn count_active_by_family(db: &DurableDb) -> Result<ActiveByFamily, QueueError> {
    let rows = db
        .query(
            "SELECT dispatch_family, SUM(parallelism) AS count FROM build_batches \
             GROUP BY dispatch_family",
        )
        .fetch_all::<FamilyCountRow>()
        .await
        .map_err(|error| format!("count active batch slots by family: {error}"))?;
    let mut by_family = std::collections::HashMap::new();
    let mut total = 0_u32;
    for row in rows {
        let family = family_of_label(&row.dispatch_family).ok_or_else(|| {
            QueueError::Invariant(format!(
                "build_batches dispatch_family {:?} maps to no runner family",
                row.dispatch_family
            ))
        })?;
        let count = u64_to_u32(row.count, "active slot count")?;
        *by_family.entry(family).or_insert(0) += count;
        total += count;
    }
    Ok(ActiveByFamily { total, by_family })
}

pub(super) fn dispatch_cutoff_modifier(dispatch_min_age_minutes: u32) -> String {
    format!("-{dispatch_min_age_minutes} minutes")
}

fn u64_to_i64(value: u64, field: &'static str) -> Result<i64, QueueError> {
    i64::try_from(value).map_err(|_| QueueError::Overflow { field, value })
}

fn u64_to_u32(value: u64, field: &'static str) -> Result<u32, QueueError> {
    u32::try_from(value).map_err(|_| QueueError::Overflow { field, value })
}

/// The enqueue probe's per-row answer — status plus the stored
/// explicit-spelling flag (stow#736).
#[derive(Debug, skyzen::FromRow)]
struct TaskStatusRow {
    task_id: String,
    status: String,
    explicit_spelling: i64,
    lane: String,
    downloads: i64,
}

/// One `GROUP BY status, lane, blocked` aggregate row from [`status`].
#[derive(Debug, skyzen::FromRow)]
struct StatusLaneCountRow {
    status: String,
    lane: String,
    blocked: i64,
    count: u64,
}

#[derive(Debug, skyzen::FromRow)]
struct TaskRow {
    task_id: String,
    attempt: u32,
    crate_name: String,
    version: String,
    features_json: String,
    target: String,
    rustc_version: String,
    host_side: i64,
    explicit_spelling: i64,
    preserve_lockfile: i64,
    dependency_identity: String,
    dispatch_key: String,
    lane: String,
    generation_id: String,
    claimed_at: Option<String>,
    median_ms: Option<String>,
}

/// One queue row as needed to build a [`RequestStatus`].
#[derive(Debug, skyzen::FromRow)]
struct RequestStatusRow {
    task_id: String,
    crate_name: String,
    version: String,
    features_json: String,
    target: String,
    rustc_version: String,
    lane: String,
    status: String,
    preserve_lockfile: i64,
    dispatch_key: String,
    blocked_by: Option<String>,
}

/// The live `(attempt, status)` of a row a completion report failed to
/// match — read after the conditional UPDATE writes nothing so the
/// rejection can name what the report conflicted with.
#[derive(Debug, skyzen::FromRow)]
struct AttemptStatusRow {
    attempt: u32,
    status: String,
}

/// One `GROUP BY dispatch_family` slot sum over `build_batches`.
#[derive(Debug, skyzen::FromRow)]
struct FamilyCountRow {
    dispatch_family: String,
    count: u64,
}

/// One `github_app_token` row — the singleton cached installation token.
/// No `Debug`: `token` is a credential and must not be printable by
/// accident.
#[derive(skyzen::FromRow)]
struct GitHubAppTokenRow {
    token: String,
    expires_at: String,
}

#[cfg(test)]
mod tests {
    use super::{
        AlarmInputs, AlarmPlan, DispatchCapacity, SliceChangeKind, SliceRowJson,
        normalize_gate_rows, plan_alarm, seconds_until_utc_midnight,
    };
    const NOW_MS: i64 = 1_000_000;

    fn inputs() -> AlarmInputs {
        AlarmInputs {
            now_ms: NOW_MS,
            capacity: DispatchCapacity::Available,
            earliest_pending_eligible_ms: None,
            earliest_batch_wake_ms: None,
        }
    }

    #[test]
    fn normalizes_gate_shapes_by_identity_direction_and_eligibility() {
        let row = |unit_side, unit_invocation, unit_linked| SliceRowJson {
            rowid: 0,
            crate_name: "crate".to_owned(),
            version: "1.0.0".to_owned(),
            features_json: "[]".to_owned(),
            dependency_identity: "dep".to_owned(),
            unit_side,
            unit_invocation,
            unit_linked,
        };
        let added = [
            (row(0, 0, 0), Some(SliceChangeKind::Added)),
            (row(0, 0, 1), Some(SliceChangeKind::Added)),
            (row(0, 1, 0), Some(SliceChangeKind::Added)),
            (row(1, 0, 0), Some(SliceChangeKind::Added)),
            (row(1, 0, 1), Some(SliceChangeKind::Added)),
            (row(1, 1, 1), Some(SliceChangeKind::Added)),
        ];
        let normalized = normalize_gate_rows(added).expect("normalize valid rows");
        let shapes = normalized
            .iter()
            .map(|row| (row.unit_side, row.invocations, row.kind))
            .collect::<Vec<_>>();
        assert_eq!(
            shapes,
            vec![
                (0, 3, Some(SliceChangeKind::Added)),
                (1, 3, Some(SliceChangeKind::Added)),
            ]
        );

        let retired = normalize_gate_rows([(row(0, 0, 1), Some(SliceChangeKind::Retired))])
            .expect("normalize retired row");
        assert_eq!(
            retired
                .iter()
                .map(|row| (row.unit_side, row.invocations, row.kind))
                .collect::<Vec<_>>(),
            vec![(0, 1, Some(SliceChangeKind::Retired))]
        );

        let full =
            normalize_gate_rows([(row(0, 0, 0), None), (row(0, 1, 1), None)]).expect("normalize");
        assert_eq!(
            full.iter()
                .map(|row| (row.unit_side, row.invocations, row.kind))
                .collect::<Vec<_>>(),
            vec![(0, 3, None)]
        );
        // Off-enum legs are corrupt storage (stow#730): an invariant
        // error, not a skipped row.
        for bad in [(-1, 0, 1), (0, -1, 1), (0, 0, 9)] {
            let error = normalize_gate_rows([(row(bad.0, bad.1, bad.2), None)])
                .expect_err("off-enum legs are an invariant failure");
            assert!(error.to_string().contains("off-enum"), "{error}");
        }
    }

    #[test]
    fn deletes_alarm_when_no_pending_and_no_active_rows() {
        assert_eq!(plan_alarm(&inputs()), AlarmPlan::Delete);
    }

    #[test]
    fn wakes_at_pending_eligibility_when_capacity_free() {
        let inputs = AlarmInputs {
            earliest_pending_eligible_ms: Some(NOW_MS + 60_000),
            ..inputs()
        };
        assert_eq!(plan_alarm(&inputs), AlarmPlan::At(NOW_MS + 60_000));
    }

    #[test]
    fn wakes_now_for_overdue_pending_row_when_capacity_free() {
        let inputs = AlarmInputs {
            earliest_pending_eligible_ms: Some(NOW_MS - 60_000),
            ..inputs()
        };
        assert_eq!(plan_alarm(&inputs), AlarmPlan::At(NOW_MS));
    }

    #[test]
    fn wakes_at_lease_expiry_when_capacity_exhausted() {
        // The pending row is already eligible, but every slot is taken:
        // waking at `now` would spin the Durable Object in a zero-delay
        // alarm loop, so the alarm must target the earliest lease expiry.
        let inputs = AlarmInputs {
            capacity: DispatchCapacity::Exhausted,
            earliest_pending_eligible_ms: Some(NOW_MS - 60_000),
            earliest_batch_wake_ms: Some(NOW_MS + 300_000),
            ..inputs()
        };
        assert_eq!(plan_alarm(&inputs), AlarmPlan::At(NOW_MS + 300_000));
    }

    #[test]
    fn clamps_past_lease_expiry_to_now_when_capacity_exhausted() {
        let inputs = AlarmInputs {
            capacity: DispatchCapacity::Exhausted,
            earliest_pending_eligible_ms: Some(NOW_MS - 60_000),
            earliest_batch_wake_ms: Some(NOW_MS - 1),
            ..inputs()
        };
        assert_eq!(plan_alarm(&inputs), AlarmPlan::At(NOW_MS));
    }

    #[test]
    fn paused_with_nothing_in_flight_deletes_alarm() {
        // Pending rows are eligible and waiting, but a paused scheduler
        // has no lease to expire and nothing to wake for.
        let inputs = AlarmInputs {
            capacity: DispatchCapacity::Paused,
            earliest_pending_eligible_ms: Some(NOW_MS - 60_000),
            ..inputs()
        };
        assert_eq!(plan_alarm(&inputs), AlarmPlan::Delete);
    }

    #[test]
    fn paused_with_in_flight_row_wakes_at_lease_expiry() {
        // Pending eligibility is ignored while paused; the only wake is
        // the in-flight row's lease going stale, so stale recovery runs.
        let inputs = AlarmInputs {
            capacity: DispatchCapacity::Paused,
            earliest_pending_eligible_ms: Some(NOW_MS - 60_000),
            earliest_batch_wake_ms: Some(NOW_MS + 300_000),
            ..inputs()
        };
        assert_eq!(plan_alarm(&inputs), AlarmPlan::At(NOW_MS + 300_000));
    }

    #[test]
    fn paused_clamps_past_lease_expiry_to_now() {
        let inputs = AlarmInputs {
            capacity: DispatchCapacity::Paused,
            earliest_batch_wake_ms: Some(NOW_MS - 1),
            ..inputs()
        };
        assert_eq!(plan_alarm(&inputs), AlarmPlan::At(NOW_MS));
    }

    #[test]
    fn wakes_at_lease_expiry_when_only_active_rows_remain() {
        // No pending rows (or all blocked on active dependencies): the alarm
        // still has to fire so a build whose completion webhook was lost
        // gets reclaimed once its lease goes stale.
        let inputs = AlarmInputs {
            earliest_batch_wake_ms: Some(NOW_MS + 120_000),
            ..inputs()
        };
        assert_eq!(plan_alarm(&inputs), AlarmPlan::At(NOW_MS + 120_000));
    }

    #[test]
    fn clamps_past_lease_expiry_to_now_without_pending_rows() {
        let inputs = AlarmInputs {
            earliest_batch_wake_ms: Some(NOW_MS - 1),
            ..inputs()
        };
        assert_eq!(plan_alarm(&inputs), AlarmPlan::At(NOW_MS));
    }

    #[test]
    fn seconds_until_midnight_counts_to_day_end() {
        // `1_767_225_600` is 2026-01-01 00:00:00 UTC — an exact day
        // boundary, where the hold-off is a full day.
        assert_eq!(seconds_until_utc_midnight(1_767_225_600), 86_400);
        assert_eq!(seconds_until_utc_midnight(1_767_225_600 + 3_600), 82_800);
        assert_eq!(seconds_until_utc_midnight(1_767_225_600 + 86_399), 1);
        assert_eq!(seconds_until_utc_midnight(0), 86_400);
    }

    #[test]
    #[should_panic(expected = "exhausted dispatch capacity")]
    fn panics_on_exhausted_capacity_without_active_lease() {
        // Contract violation: `next_alarm` rejects this input combination
        // with a `QueueError` before delegating.
        let inputs = AlarmInputs {
            capacity: DispatchCapacity::Exhausted,
            earliest_pending_eligible_ms: Some(NOW_MS),
            earliest_batch_wake_ms: None,
            ..inputs()
        };
        let _ = plan_alarm(&inputs);
    }
}

/// SQL-level tests: drive `next_alarm` against a real in-memory `SQLite` so a
/// wrong column, `status IN` list, or datetime-modifier sign in the queue
/// queries fails the test instead of compiling past the pure `plan_alarm`
/// suite.
#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "queue_tests.rs"]
mod sqlite_tests;
