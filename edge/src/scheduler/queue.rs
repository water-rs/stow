use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::num::{NonZero, NonZeroU32};

use skyzen_services::durable::{DbValue, DurableDb};
pub use stow_types::api::task_id;
use stow_types::api::{
    AdminInFlight, AdminStatus, AdminTargetStats, EnqueueRequest, EnqueueSource, PublishedSliceRow,
    QueueSelector, QueueTask, QueueTaskStatus, RequestStatus, RunnerFamily, SchedulerStatus,
    SchemaMigrationReport, TaskLane, runner_family,
};
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};

use crate::errors::QueueError;

/// The semantic identity of a crates.io task, as the artifact catalog
/// keys it: the identity a published closure member registers under.
/// `host_side` is part of the identity — the same crate mints both a
/// target-side node and a host-side node at the host triple, and each
/// side is covered only when the catalog serves that side's unit shapes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemanticTaskIdentity {
    pub crate_name: String,
    pub version: String,
    pub features_json: String,
    pub target: String,
    pub rustc_version: String,
    pub host_side: bool,
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

/// One claimed queue row, ready to dispatch to a build runner.
#[derive(Debug, Clone)]
pub struct QueuedTask {
    pub task_id: String,
    /// Unique claim identity minted at dispatch claim time. It changes on
    /// every new claim, including after purge and recreation.
    pub generation_id: String,
    /// The row's enqueue epoch at claim time. The `workflow_run` event
    /// names no attempt — `complete_run` resolves the row's live one —
    /// so a late report for a superseded attempt cannot overwrite the
    /// live one.
    pub attempt: u32,
    pub crate_name: String,
    pub version: String,
    pub features_json: String,
    pub target: String,
    pub rustc_version: String,
    /// Whether the task builds the crate as a host-side unit — passed
    /// through to `BuildTaskPayload` so the CI builder shapes the
    /// wrapper package's dependency as the unit's consumers compile it.
    pub host_side: bool,
    pub preserve_lockfile: bool,
    /// The task's `queue_dependencies` rows at claim time — the published
    /// identity of every dep the unit needs. Dispatch carries them to
    /// `BuildTaskPayload.dep_pins` so the generated wrapper package pins
    /// each dep to the identity its own task published.
    pub dep_pins: Vec<stow_types::api::BuildDepPin>,
}

// Dispatch ceilings, sized against the org's 60 GitHub-hosted runners (20
// of them macOS): 45 total leaves 15 runners for the repo's own CI, and
// the macOS cap keeps a full wave from queueing on the smallest pool
// while leaving 4 macOS runners free.
const DEFAULT_MAX_CONCURRENT_JOBS: NonZeroU32 = NonZeroU32::new(45).unwrap();
const DEFAULT_MAX_CONCURRENT_MACOS_JOBS: u32 = 16;
const DEFAULT_DISPATCH_MIN_AGE_MINUTES: u32 = 5;
// A single crate build on GitHub-hosted runners (toolchain install + compile
// + sign + push) can legitimately take tens of minutes and nothing updates
// the row while CI runs, so the stale-recovery cutoff must comfortably
// exceed the slowest expected build or long builds get double-dispatched.
const DEFAULT_STALE_DISPATCH_MINUTES: u32 = 60;
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
const BUILD_SAMPLE_WINDOW: i64 = 32;

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

/// Runtime-tunable scheduler knobs, read from Worker env bindings by the
/// Durable Object glue (`STOW_MAX_CONCURRENT_JOBS`,
/// `STOW_MAX_CONCURRENT_MACOS_JOBS`, `STOW_DISPATCH_MIN_AGE_MINUTES`,
/// `STOW_STALE_DISPATCH_MINUTES`, `STOW_MAX_QUEUE_PENDING`,
/// `STOW_HUMAN_DAILY_TASK_BUDGET`, `STOW_MIN_DISPATCH_VALUE`).
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
    /// the *operator input* `migrate` stamps into `settings` and
    /// backfills `dispatch_eligible` from. A changed binding takes
    /// effect only through that pass: the queue's writers and probes
    /// read the persisted answer, never this field.
    pub min_dispatch_value: i64,
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
        }
    }
}

/// Priority is the third precedence operand of `queue.value` — dispatch
/// orders on value before the FIFO tie-breakers, and `request_count` is
/// deliberately absent from it: hammering one pending task must never
/// inflate its value to overtake older work.
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
/// is `bands × VALUE_BAND + priority`, with the human lane contributing
/// two bands and the Windows family one — today's "human first, then
/// Windows, then priority" claim order encoded additively in one
/// descending number (stow#442 I6). The largest value a row can take is
/// `3 × VALUE_BAND + PRIORITY_MAX = 4 × PRIORITY_MAX + 3 =
/// 73,787,148,093,530,007`, below `i64::MAX`, so no operand can
/// overflow the column.
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
const ENQUEUE_JSON_BATCH_ROWS: usize = 2000;

/// Retired slice rows delete in `rowid IN (…)` batches. workerd caps a
/// statement at ~100 bound variables, so the batch stays under it by
/// half; a full-slice retire then costs ~45 statements.
const SLICE_ROWID_DELETE_BATCH: usize = 90;

/// One re-request folded per task for the bulk `UPDATE queue`:
/// `occurrences` counts how many requests in the chunk named the row,
/// `downloads` the highest the chunk reported, `redispatch` the
/// at-most-one resurrection a row can take in one batch (once `pending`
/// it cannot resurrect again in the same pass), and `human` whether any
/// occurrence promoted the lane.
#[derive(serde::Serialize)]
struct BatchedUpdate {
    task_id: String,
    occurrences: u32,
    downloads: i64,
    redispatch: u8,
    human: u8,
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
    downloads: i64,
    priority: i64,
    preserve_lockfile: u8,
    lane: &'static str,
}

/// One stored edge's readiness as probed for an insert chunk: whether
/// the dep's required publication is missing (`unpub`) and whether that
/// edge also blocks (`blocker` — the dep failed, names no crate, or
/// carries an unresolved legacy side).
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
    dep_invocations: i64,
    dep_shapes: i64,
}

/// Serialize one statement's JSON-array payload.
fn enqueue_json<T: serde::Serialize>(rows: &[T]) -> Result<String, QueueError> {
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
/// per slice. Semantics of the old per-request `update_existing_task`,
/// carried per JSON entry: downloads keep the max, `request_count`
/// grows by the occurrence count, priority recomputes from downloads and
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
                 request_count = request_count + (e ->> 'occurrences'), \
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
                 dispatch_eligible = {eligible} \
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
                        CASE WHEN bdep.status = 'failed' OR d.dep_crate_name = '' \
                                  OR d.dep_host_side < 0 \
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
                 (task_id, crate_name, version, features_json, target, rustc_version, host_side, downloads, miss_count, request_count, priority, status, preserve_lockfile, lane, attempt, generation_id, first_requested_at, created_at, unpublished_deps, deps_met, blocked, wake_at, dispatch_family, value, dispatch_key, dispatch_eligible) \
                 SELECT e ->> 'task_id', e ->> 'crate_name', e ->> 'version', e ->> 'features_json', \
                        e ->> 'target', e ->> 'rustc_version', e ->> 'host_side', e ->> 'downloads', \
                        0, 1, e ->> 'priority', 'pending', e ->> 'preserve_lockfile', e ->> 'lane', \
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

/// Sync the dependency edges of every task the chunk resynced as a
/// delta, not a rewrite: the DELETE drops only edges the task's new
/// report no longer carries — a reported edge whose stored columns
/// already match survives untouched, so a resubmit with an unchanged
/// dependency set writes nothing. Rewriting wholesale (delete all +
/// reinsert) billed `2 × edges` rows per resubmit; at ~20k submits a
/// day with production-size dep lists that was the dominant rows-written
/// source. A content-changed edge counts as dropped and the INSERT
/// re-adds it with the new columns; a legacy `dep_side_known = 0` row
/// never matches a resolver-written report, so it is deleted and
/// reinserted as known rather than left failing closed.
async fn apply_batched_dependency_sync(
    db: &DurableDb,
    resync_ids: &[String],
    edges: &[BatchedDepEdge],
) -> Result<(), QueueError> {
    for chunk in resync_ids.chunks(ENQUEUE_JSON_BATCH_ROWS) {
        // The reported edge set is scoped to the tasks in this chunk so
        // a keep-check never consults another chunk's report.
        let chunk_ids: std::collections::HashSet<&str> = chunk.iter().map(String::as_str).collect();
        let chunk_edges: Vec<&BatchedDepEdge> = edges
            .iter()
            .filter(|edge| chunk_ids.contains(edge.task_id.as_str()))
            .collect();
        db.query(
            "DELETE FROM queue_dependencies \
             WHERE task_id IN (SELECT value FROM json_each(?)) \
               AND (dep_side_known != 1 OR NOT EXISTS ( \
                   SELECT 1 FROM (SELECT value AS e FROM json_each(?)) AS j \
                   WHERE j.e ->> 'task_id' = queue_dependencies.task_id \
                     AND j.e ->> 'depends_on_task_id' = queue_dependencies.depends_on_task_id \
                     AND j.e ->> 'dep_crate_name' = queue_dependencies.dep_crate_name \
                     AND j.e ->> 'dep_version' = queue_dependencies.dep_version \
                     AND j.e ->> 'dep_features_json' = queue_dependencies.dep_features_json \
                     AND j.e ->> 'dep_target' = queue_dependencies.dep_target \
                     AND j.e ->> 'dep_rustc_version' = queue_dependencies.dep_rustc_version \
                     AND j.e ->> 'dep_host_side' = queue_dependencies.dep_host_side \
                     AND j.e ->> 'dep_invocations' = queue_dependencies.dep_invocations \
                     AND j.e ->> 'dep_shapes' = queue_dependencies.dep_shapes \
               ))",
        )
        .bind(enqueue_json(chunk)?)
        .bind(enqueue_json(&chunk_edges)?)
        .execute()
        .await
        .map_err(|error| format!("clear dropped task dependencies: {error}"))?;
    }
    insert_dep_edges(db, edges).await?;
    Ok(())
}

/// Insert the resync's surviving edges, each carrying its `dep_met` —
/// the slice answer at insert time, the same EXISTS the gate used to
/// evaluate — so the owner's `unpublished_deps` count and every later
/// slice-delta flip read a stored flag instead of re-joining the
/// published rows per edge.
async fn insert_dep_edges(db: &DurableDb, edges: &[BatchedDepEdge]) -> Result<(), QueueError> {
    for chunk in edges.chunks(ENQUEUE_JSON_BATCH_ROWS) {
        db.query(&format!(
            "INSERT INTO queue_dependencies \
             (task_id, depends_on_task_id, dep_crate_name, dep_version, dep_features_json, dep_target, dep_rustc_version, dep_host_side, dep_invocations, dep_shapes, dep_met, dep_side_known) \
             SELECT d.task_id, d.depends_on_task_id, d.dep_crate_name, \
                    d.dep_version, d.dep_features_json, d.dep_target, \
                    d.dep_rustc_version, d.dep_host_side, d.dep_invocations, \
                    d.dep_shapes, CASE WHEN {unpub} THEN 0 ELSE 1 END, 1 \
             FROM (SELECT e ->> 'task_id' AS task_id, \
                         e ->> 'depends_on_task_id' AS depends_on_task_id, \
                         e ->> 'dep_crate_name' AS dep_crate_name, \
                         e ->> 'dep_version' AS dep_version, \
                         e ->> 'dep_features_json' AS dep_features_json, \
                         e ->> 'dep_target' AS dep_target, \
                         e ->> 'dep_rustc_version' AS dep_rustc_version, \
                         e ->> 'dep_host_side' AS dep_host_side, \
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
        // Each named dep's task id resolves here once — the edge rows
        // `dep_edges` builds key on them.
        let dep_task_ids = request
            .depends_on
            .iter()
            .map(|dependency| {
                task_id(
                    dependency.crate_name.as_str(),
                    dependency.version.to_string().as_str(),
                    dependency.features_json.raw().as_str(),
                    dependency.target.as_str(),
                    dependency.rustc_version.as_str(),
                    dependency.host_side,
                )
            })
            .collect();
        prepared.push(Prepared {
            request,
            task_id: task_id(
                &identity.crate_name,
                &identity.version,
                identity.features_json.as_str(),
                &identity.target,
                &identity.rustc_version,
                identity.host_side,
            ),
            identity,
            dep_task_ids,
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
    // updates so a later occurrence of a just-inserted task lands its
    // `request_count` contribution — the per-request loop applied it
    // through `update_existing_task`.
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
    // has passed; a refused resubmit must not consume budget.
    let human_tasks = u32::try_from(
        requests
            .iter()
            .filter(|request| {
                request_lane(request.source) == TaskLane::Human
                    && stow_types::api::is_ci_target(request.target.as_str())
            })
            .count(),
    )
    .map_err(|_| QueueError::Overflow {
        field: "human-lane task count",
        value: requests.len() as u64,
    })?;
    if human_tasks > 0
        && !charge_human_daily_budget(db, human_tasks, settings.human_daily_task_budget).await?
    {
        return Err(QueueError::HumanDailyBudgetExhausted {
            attempted: u64::from(human_tasks),
            budget: u64::from(settings.human_daily_task_budget),
        });
    }
    let resync_ids: Vec<String> = plan.resync.keys().cloned().collect();
    let edges: Vec<BatchedDepEdge> = plan.resync.into_values().flatten().collect();
    apply_batched_dependency_sync(db, &resync_ids, &edges).await?;
    let inserted = apply_batched_inserts(db, settings, &plan.inserts).await?;
    apply_batched_updates(db, settings, &plan.updates).await?;

    // The batch's edge set is settled — refresh the gate answer on
    // pre-existing tasks whose edges the sync rewrote. Fresh inserts
    // computed theirs inside the INSERT; an empty resync set issues
    // no statement at all.
    refresh_deps_met_tasks(db, &resync_ids).await?;

    u64_to_u32(inserted, "inserted task count")
}

/// One request precomputed for the batched enqueue: queue identity,
/// its deterministic task id, and the resolved task ids of its deps.
struct Prepared<'r> {
    request: &'r EnqueueRequest,
    task_id: String,
    identity: TaskIdentity,
    /// `task_id` of each `request.depends_on` entry, in the same order.
    dep_task_ids: Vec<String>,
}

/// Everything the write phase emits for one chunk, with the per-request
/// ordering already resolved in Rust.
struct EnqueuePlan {
    updates: Vec<BatchedUpdate>,
    inserts: Vec<BatchedInsert>,
    /// Task ids whose edge set is rewritten this chunk — the key set
    /// feeds the bulk DELETE, the rows the bulk INSERT.
    resync: BTreeMap<String, Vec<BatchedDepEdge>>,
}

/// One existence probe for the chunk, over every task id it can
/// touch. `task_id` is the queue's primary key, so this answers every
/// existence check the row-at-a-time loop ran.
async fn probe_task_statuses(
    db: &DurableDb,
    prepared: &[Prepared<'_>],
) -> Result<BTreeMap<String, String>, QueueError> {
    let probe_ids: Vec<&str> = prepared
        .iter()
        .map(|entry| entry.task_id.as_str())
        .collect();
    let mut statuses: BTreeMap<String, String> = BTreeMap::new();
    for chunk in probe_ids.chunks(ENQUEUE_JSON_BATCH_ROWS) {
        let rows = db
            .query(
                "SELECT task_id, status FROM queue \
                 WHERE task_id IN (SELECT value FROM json_each(?))",
            )
            .bind(enqueue_json(chunk)?)
            .fetch_all::<TaskIdRow>()
            .await
            .map_err(|error| format!("select existing tasks: {error}"))?;
        for row in rows {
            statuses.insert(row.task_id, row.status);
        }
    }
    Ok(statuses)
}

/// One request's edge rows, fully resolved: the dep's required unit
/// shapes for the gate and a self-edge rejection — the checks
/// `sync_task_dependencies` ran per dep before each edge INSERT.
fn dep_edges(entry: &Prepared<'_>) -> Result<Vec<BatchedDepEdge>, QueueError> {
    let mut edges = Vec::with_capacity(entry.request.depends_on.len());
    for (dependency, dep_task_id) in entry
        .request
        .depends_on
        .iter()
        .zip(entry.dep_task_ids.iter())
    {
        let dep_features = dependency.features_json.raw();
        let dep_version = dependency.version.to_string();
        // The gate needs every required unit shape of the dep's
        // semantic identity — the shapes the dependent's own build
        // compiles the dep's units at. The mask and the pair count go
        // on the edge so the gate SQL stays a row-count compare.
        let (dep_invocations, dep_shapes) = dep_edge_requirements(
            entry.request.target.as_str(),
            entry.request.host_side,
            dependency.target.as_str(),
            dependency.host_side,
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
            dep_invocations,
            dep_shapes,
        });
    }
    Ok(edges)
}

/// Replay the per-request loop's state machine in memory, in request
/// order: each request's own insert/update, then its dep sync. A task
/// appearing twice in one chunk sees what its earlier occurrence left
/// (a fresh insert reads as 'pending', a resurrected row as 'pending'),
/// so duplicates land identically to the row-at-a-time loop. `resync`
/// keeps the last occurrence's dependency list per task — the old
/// loop's per-occurrence DELETE+INSERT made the last sync the
/// surviving one. `statuses` carries the existence probe in and is
/// advanced to the row each occurrence leaves.
fn plan_enqueue(
    prepared: &[Prepared<'_>],
    statuses: &mut BTreeMap<String, String>,
) -> Result<EnqueuePlan, QueueError> {
    let mut updates: BTreeMap<String, BatchedUpdate> = BTreeMap::new();
    let mut plan = EnqueuePlan {
        updates: Vec::new(),
        inserts: Vec::new(),
        resync: BTreeMap::new(),
    };
    for entry in prepared {
        let lane = request_lane(entry.request.source);
        let downloads = u64_to_i64(entry.request.downloads, "downloads")?;
        if let Some(status) = statuses.get(&entry.task_id) {
            let redispatch = resurrects(status.as_str(), lane);
            let update = updates
                .entry(entry.task_id.clone())
                .or_insert_with(|| BatchedUpdate {
                    task_id: entry.task_id.clone(),
                    occurrences: 0,
                    downloads,
                    redispatch: 0,
                    human: 0,
                });
            update.occurrences += 1;
            update.downloads = update.downloads.max(downloads);
            update.redispatch |= u8::from(redispatch);
            update.human |= u8::from(lane == TaskLane::Human);
            if redispatch {
                statuses.insert(entry.task_id.clone(), "pending".to_owned());
            }
        } else {
            plan.inserts.push(BatchedInsert {
                task_id: entry.task_id.clone(),
                crate_name: entry.identity.crate_name.clone(),
                version: entry.identity.version.clone(),
                features_json: entry.identity.features_json.clone(),
                target: entry.identity.target.clone(),
                rustc_version: entry.identity.rustc_version.clone(),
                host_side: u8::from(entry.identity.host_side),
                downloads,
                priority: compute_priority(entry.request.downloads, 0)?,
                preserve_lockfile: u8::from(entry.request.preserve_lockfile),
                lane: lane.as_str(),
            });
            statuses.insert(entry.task_id.clone(), "pending".to_owned());
        }
        // A re-request without dependency info (exact/semantic miss
        // paths always send an empty list) must not erase ordering
        // edges a graph-analysis enqueue established.
        if entry.request.depends_on.is_empty() {
            continue;
        }
        let edges = dep_edges(entry)?;
        plan.resync.insert(entry.task_id.clone(), edges);
    }
    plan.updates = updates.into_values().collect();
    Ok(plan)
}

/// A queue row's completion as [`complete`] applies it — reduced to the
/// fields the `workflow_run` completion path fills; the old CI
/// `POST /api/v1/scheduler/complete` wire type carried the same name.
/// `complete_run` resolves `attempt` from the live row and fills the
/// rest from the webhook event.
#[derive(Debug)]
struct BuildCompleteReport {
    task_id: String,
    generation_id: String,
    attempt: u32,
    success: bool,
    error: Option<String>,
    github_run_id: Option<String>,
    /// The instant the run finished — `None` for a live report
    /// (completion is now); a completion applied later through
    /// `pending_run_completions` carries its stored `received_at`, so
    /// the duration sample measures claim-to-completion, not
    /// claim-to-deferred-application (stow#524).
    finished_at: Option<String>,
}

#[derive(Debug, skyzen::FromRow)]
struct CompletedTargetRow {
    target: String,
    crate_name: String,
    claimed_at: Option<String>,
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
        "datetime('now', '+' || MIN(1 << MIN(attempt, 6), {MAX_DISPATCH_BACKOFF_MINUTES}) || ' minutes')"
    );
    let statement = if report.success {
        "UPDATE queue \
         SET status = 'completed', error_msg = ?, github_run_id = COALESCE(?, github_run_id), \
             updated_at = datetime('now') \
         WHERE task_id = ? AND generation_id = ? \
           AND status IN ('dispatched', 'running') \
         RETURNING target, crate_name, claimed_at, status"
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
             RETURNING target, crate_name, claimed_at, status",
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
    if report.success {
        record_build_sample(
            db,
            report,
            &completed.crate_name,
            &completed.target,
            completed.claimed_at.as_deref(),
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
/// `claimed_at` `NULL` means the row predates the column or its
/// completion applied to a generation minted before the stamp existed
/// — there is no real claim instant to measure from, so no sample is
/// taken at all. `report.finished_at` is the run's real completion
/// instant (the pending-completion path's `received_at`), falling
/// back to now for a live report.
async fn record_build_sample(
    db: &DurableDb,
    report: &BuildCompleteReport,
    crate_name: &str,
    target: &str,
    claimed_at: Option<&str>,
) -> Result<(), QueueError> {
    let Some(claimed_at) = claimed_at else {
        return Ok(());
    };
    let inserted = db
        .query(
            "INSERT INTO crate_build_samples \
             (crate_name, target, generation_id, duration_ms) \
             VALUES (?, ?, ?, \
                     CAST((julianday(COALESCE(?, datetime('now'))) \
                           - julianday(?)) * 86400000.0 AS INTEGER)) \
             ON CONFLICT DO NOTHING",
        )
        .bind(crate_name.to_owned())
        .bind(target.to_owned())
        .bind(report.generation_id.clone())
        .bind(report.finished_at.clone())
        .bind(claimed_at.to_owned())
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
const OUTCOME_BUCKET_SECS: i64 = 300;

/// Count one completion report against the breaker's window and expire
/// what aged out. The read set of a completion is constant in traffic:
/// the `UPDATE … RETURNING target` in `complete` names the row's target,
/// one bucket upsert counts it, and — for failures — one raw
/// `attempt_outcomes` row keeps the trip alert's class and run-id
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
    db.query(
        "INSERT INTO attempt_outcome_buckets (target, bucket, outcomes, failures) \
         VALUES (?, (unixepoch('now') / ?) * ?, 1, ?) \
         ON CONFLICT(target, bucket) DO UPDATE SET \
             outcomes = outcomes + 1, failures = failures + excluded.failures",
    )
    .bind(target.to_owned())
    .bind(OUTCOME_BUCKET_SECS)
    .bind(OUTCOME_BUCKET_SECS)
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
    let window = format!("-{window_minutes} minutes");
    db.query("DELETE FROM attempt_outcomes WHERE finished_at < datetime('now', ?)")
        .bind(window)
        .execute()
        .await
        .map_err(|error| format!("expire old attempt outcome rows: {error}"))?;
    db.query("DELETE FROM attempt_outcomes_v2 WHERE finished_at < datetime('now', ?)")
        .bind(format!("-{window_minutes} minutes"))
        .execute()
        .await
        .map_err(|error| format!("expire old generation outcome rows: {error}"))?;
    db.query("DELETE FROM attempt_outcome_buckets WHERE bucket < unixepoch('now') - ?")
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

/// Apply a GitHub `workflow_run` completion — the webhook's wire report,
/// which names the task and its outcome but no scheduler attempt number.
///
/// The webhook carries the platform run id, not the scheduler attempt; the
/// bound generation resolves the exact in-flight claim and fences stale
/// events before the records check can settle it.
///
/// # Errors
///
/// [`QueueError::UnknownTask`] when no queue row carries the task id;
/// [`QueueError::StaleCompletion`] when the live row's attempt or status
/// has moved past what the event describes, or when an in-flight row is
/// bound to a different run than the one reporting;
/// A completion that beats its dispatch response is persisted and
/// acknowledged; the exact response binding later applies it.
pub async fn complete_run(
    db: &DurableDb,
    settings: &SchedulerSettings,
    report: &stow_types::api::WorkflowRunComplete,
    window_minutes: u32,
) -> Result<(), QueueError> {
    let mut row = load_run_binding(db, &report.task_id).await?;
    let Some(mut row) = row.take() else {
        return Err(QueueError::UnknownTask(report.task_id.clone()));
    };
    // An in-flight row answers only to the run its generation bound at
    // dispatch: the claim cleared `github_run_id` and the
    // `workflow_dispatch` response's `workflow_run_id` wrote it. A
    // report naming a different run belongs to a stale generation —
    // timed automatic retries make that path real: run A fails, retry B
    // is claimed and bound, and A's delayed duplicate would otherwise
    // apply to B. A row on a terminal or pending state takes no binding
    // check — `complete`'s own generation/status predicate is the fence
    // there.
    if matches!(row.status.as_str(), "dispatched" | "running") {
        match row.github_run_id.as_deref() {
            Some(bound) if report.github_run_id.as_deref() == Some(bound) => {}
            Some(bound) => {
                tracing::warn!(
                    task_id = %report.task_id,
                    bound_run = %bound,
                    reported_run = ?report.github_run_id,
                    "rejected completion report from a run the generation is not bound to"
                );
                return Err(QueueError::StaleCompletion {
                    task_id: report.task_id.clone(),
                    attempt: row.attempt,
                    row_attempt: row.attempt,
                    row_status: row.status,
                });
            }
            None => {
                // GitHub does not redeliver a webhook merely because the
                // receiver answered 500. Persist the verified event while
                // the native dispatch response is still in flight. The
                // response binds by this exact run id; an old run with the
                // same title can therefore never apply to this generation.
                if persist_pending_completion(db, report).await? {
                    return Ok(());
                }

                // The binding may have landed between the first read and
                // the guarded insert. Re-read the identity and apply only
                // when it is now the exact run that sent this event.
                row = load_run_binding(db, &report.task_id)
                    .await?
                    .ok_or_else(|| QueueError::UnknownTask(report.task_id.clone()))?;
                match row.github_run_id.as_deref() {
                    Some(bound) if report.github_run_id.as_deref() == Some(bound) => {}
                    Some(_) | None => {
                        return Err(QueueError::StaleCompletion {
                            task_id: report.task_id.clone(),
                            attempt: row.attempt,
                            row_attempt: row.attempt,
                            row_status: row.status,
                        });
                    }
                }
            }
        }
    }
    complete(
        db,
        settings,
        &BuildCompleteReport {
            task_id: report.task_id.clone(),
            generation_id: row.generation_id.clone(),
            attempt: row.attempt,
            success: report.success,
            error: report.error.clone(),
            github_run_id: report.github_run_id.clone(),
            finished_at: None,
        },
        window_minutes,
    )
    .await
}

async fn load_run_binding(
    db: &DurableDb,
    task_id: &str,
) -> Result<Option<RunBindingRow>, QueueError> {
    db.query("SELECT generation_id, attempt, status, github_run_id FROM queue WHERE task_id = ?")
        .bind(task_id.to_owned())
        .fetch_optional::<RunBindingRow>()
        .await
        .map_err(|error| format!("load task {task_id} for run completion: {error}").into())
}

#[derive(Debug, skyzen::FromRow)]
struct RunBindingRow {
    generation_id: String,
    attempt: u32,
    status: String,
    github_run_id: Option<String>,
}

/// Store a verified completion that arrived before the dispatch response
/// bound its run id. The guarded INSERT is the race fence: it writes only
/// while the task is still in the same unbound in-flight state.
async fn persist_pending_completion(
    db: &DurableDb,
    report: &stow_types::api::WorkflowRunComplete,
) -> Result<bool, QueueError> {
    let Some(github_run_id) = report.github_run_id.as_deref() else {
        return Ok(false);
    };
    let inserted = db
        .query(
            "INSERT INTO pending_run_completions \
                 (github_run_id, task_id, success, error) \
             SELECT ?, task_id, ?, ? FROM queue \
             WHERE task_id = ? AND status IN ('dispatched', 'running') \
               AND github_run_id IS NULL \
             ON CONFLICT(github_run_id) DO NOTHING",
        )
        .bind(github_run_id.to_owned())
        .bind(i64::from(report.success))
        .bind(report.error.clone())
        .bind(report.task_id.clone())
        .execute()
        .await
        .map_err(|error| format!("persist pending completion for {github_run_id}: {error}"))?;
    if inserted.rows_written > 0 {
        return Ok(true);
    }

    let existing = db
        .query(
            "SELECT github_run_id, task_id, success, error, received_at \
             FROM pending_run_completions WHERE github_run_id = ?",
        )
        .bind(github_run_id.to_owned())
        .fetch_optional::<PendingCompletionRow>()
        .await
        .map_err(|error| format!("load pending completion for {github_run_id}: {error}"))?;
    match existing {
        None => Ok(false),
        Some(existing)
            if existing.task_id == report.task_id
                && existing.success == i64::from(report.success)
                && existing.error == report.error =>
        {
            Ok(true)
        }
        Some(existing) => Err(QueueError::Invariant(format!(
            "run {github_run_id} was already pending for task {}",
            existing.task_id
        ))),
    }
}

/// Apply one exact pending event after its run id has been bound. The event
/// stays durable until `complete` succeeds; a stale row consumes it without
/// allowing it to affect a later generation.
async fn apply_pending_completion_for_binding(
    db: &DurableDb,
    settings: &SchedulerSettings,
    task_id: &str,
    generation_id: &str,
    github_run_id: &str,
    window_minutes: u32,
) -> Result<(), QueueError> {
    db.query(
        "DELETE FROM pending_run_completions \
         WHERE task_id = ? AND github_run_id != ?",
    )
    .bind(task_id.to_owned())
    .bind(github_run_id.to_owned())
    .execute()
    .await
    .map_err(|error| format!("discard stale pending completions for {task_id}: {error}"))?;

    let pending = db
        .query(
            "SELECT github_run_id, task_id, success, error, received_at \
             FROM pending_run_completions \
             WHERE task_id = ? AND github_run_id = ?",
        )
        .bind(task_id.to_owned())
        .bind(github_run_id.to_owned())
        .fetch_optional::<PendingCompletionRow>()
        .await
        .map_err(|error| format!("load bound pending completion for {task_id}: {error}"))?;
    let Some(pending) = pending else {
        return Ok(());
    };
    let report = BuildCompleteReport {
        task_id: pending.task_id,
        generation_id: generation_id.to_owned(),
        attempt: db
            .query("SELECT attempt FROM queue WHERE task_id = ? AND generation_id = ?")
            .bind(task_id.to_owned())
            .bind(generation_id.to_owned())
            .fetch_scalar::<u32>()
            .await
            .map_err(|error| format!("load bound attempt for {task_id}: {error}"))?,
        success: pending.success != 0,
        error: pending.error,
        github_run_id: Some(pending.github_run_id.clone()),
        finished_at: Some(pending.received_at),
    };
    match complete(db, settings, &report, window_minutes).await {
        Ok(()) | Err(QueueError::UnknownTask(_) | QueueError::StaleCompletion { .. }) => {
            db.query("DELETE FROM pending_run_completions WHERE github_run_id = ?")
                .bind(pending.github_run_id)
                .execute()
                .await
                .map_err(|error| format!("consume pending completion for {task_id}: {error}"))?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Recover pending events after a DO restart. The join is driven by the
/// currently bound in-flight rows, so it reads only identities that can
/// still apply and never scans historical workflow runs.
pub async fn reconcile_pending_completions(
    db: &DurableDb,
    settings: &SchedulerSettings,
    window_minutes: u32,
) -> Result<(), QueueError> {
    let rows = db
        .query(
            "SELECT q.task_id, q.generation_id, q.github_run_id \
             FROM queue q \
             JOIN pending_run_completions p \
               ON p.task_id = q.task_id AND p.github_run_id = q.github_run_id \
             WHERE q.status IN ('dispatched', 'running') \
               AND q.github_run_id IS NOT NULL",
        )
        .fetch_all::<BoundPendingCompletionRow>()
        .await
        .map_err(|error| format!("list bound pending completions: {error}"))?;
    for row in rows {
        apply_pending_completion_for_binding(
            db,
            settings,
            &row.task,
            &row.generation,
            &row.run,
            window_minutes,
        )
        .await?;
    }
    Ok(())
}

/// Bind the run a `workflow_dispatch` response returned to the claimed
/// row's generation. The claim cleared `github_run_id`, so the write is
/// gated on the generation the dispatch was made for: a row that has
/// since moved on (cancelled, failed over) takes no binding, and the
/// orphan run's own report is rejected as stale when it lands.
///
/// The id is also what #526's reconciliation compares against — the
/// persisted binding is the source of truth for which run a generation
/// dispatched, where name-matching alone cannot tell two generations
/// of `<rustc>-<task_id>` apart.
///
/// Returns `true` when the binding landed. `false` means the row no
/// longer sits in the bound generation's claim — the caller logs and
/// moves on.
pub async fn bind_dispatch_run(
    db: &DurableDb,
    task_id: &str,
    generation_id: &str,
    github_run_id: &str,
) -> Result<bool, QueueError> {
    let result = db
        .query(
            "UPDATE queue SET github_run_id = ? \
             WHERE task_id = ? AND generation_id = ? \
                 AND status IN ('dispatched', 'running') AND github_run_id IS NULL",
        )
        .bind(github_run_id.to_owned())
        .bind(task_id.to_owned())
        .bind(generation_id.to_owned())
        .execute()
        .await
        .map_err(|error| format!("bind dispatch run for {task_id}: {error}"))?;
    if result.rows_written == 0 {
        return Ok(false);
    }
    // A completion from an orphaned run can arrive while this generation is
    // claimed but still unbound. Once the native response binds Y, every
    // pending event for the task except Y belongs to an older or ambiguous
    // generation and must be consumed here, even when Y had no early event.
    db.query(
        "DELETE FROM pending_run_completions \
         WHERE task_id = ? AND github_run_id != ?",
    )
    .bind(task_id.to_owned())
    .bind(github_run_id.to_owned())
    .execute()
    .await
    .map_err(|error| format!("discard superseded pending completions for {task_id}: {error}"))?;
    Ok(true)
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
/// 1 = `--target`) onto its bit. Rows reported before the unit-shape
/// columns existed carry `-1` legs: they match no clause, so a
/// shapeless dep stays gated until the node republishes — legacy rows
/// are unreachable under this lookup, never migrated into it.
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
    // Keep legacy -1 shape legs out of coverage. The integer enums are
    // stored as 0/1 and legacy rows as -1, so BETWEEN is equivalent to
    // the accepted domain while letting SQLite retain a bounded suffix
    // range on the published-row primary key.
    format!(
        "({dep}.dep_shapes = 0 \
         OR (SELECT count(*) \
             FROM published_slice_rows p \
             WHERE p.target = {dep}.dep_target \
               AND p.rustc_version = {dep}.dep_rustc_version \
               AND p.generation = {generation} \
               AND p.crate_name = {dep}.dep_crate_name \
               AND p.version = {dep}.dep_version \
               AND p.features_json = {dep}.dep_features_json \
               AND p.unit_side = {dep}.dep_host_side \
               AND p.unit_invocation BETWEEN 0 AND 1 \
               AND p.unit_linked BETWEEN 0 AND 1 \
               AND ({dep}.dep_host_side = 0 OR p.unit_linked = 1) \
               AND ({dep}.dep_invocations & (p.unit_invocation + 1)) != 0 \
            ) < {dep}.dep_shapes)"
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
/// edges rather than a slice EXISTS per edge. Written at edge sync,
/// refreshed by slice publish and the schema migration — the three
/// places an edge's answer can change — so the claim walk and the
/// alarm's wake probes read the flag instead of re-evaluating the gate
/// per pending row.
pub(super) fn deps_met_sql(owner_task: &str) -> String {
    format!(
        "CASE WHEN {} = 0 THEN 1 ELSE 0 END",
        unpublished_deps_sql(owner_task)
    )
}

/// `blocked` as a SQL expression over the owner's row: `1` while a
/// pending row owns an edge whose dep failed or was never resolved
/// (`dep_crate_name = ''`, `dep_host_side < 0`) AND whose required units
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
              AND (bdep.status = 'failed' OR bd.dep_crate_name = '' \
                   OR bd.dep_host_side < 0) \
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
/// operator migrate stamps into `settings` — decimal text, `CAST` to
/// SQLite's integer domain in place, so no wide value ever crosses a
/// JS bind/cursor boundary; an absent row reads as the default `0`
/// (admit everything), which is also the answer before the first
/// migrate of a fresh deploy. Every writer that assigns `value` or
/// `lane` evaluates this expression in the same statement — SET terms
/// see the pre-update row, so the `value` operand is the expression
/// being assigned ([`value_sql`]), never the stale column.
///
/// The admission expression with an explicit floor operand — the shape
/// the settings-row formula shares, used only by the operator
/// migrate's backfill, which must evaluate against the configured
/// value before the row recording it exists.
fn dispatch_eligible_at_floor_sql(lane: &str, value: &str, floor: &str) -> String {
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
    target: String,
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
const RANK_SOURCE_SELECT: &str = "SELECT q.task_id, q.target, q.lane, q.dispatch_family, \
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
    target: String,
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
            target: self.target.clone(),
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

/// The operator migration's rank-column backfill — one paged pass over
/// the whole queue, legal only inside operations code. Every row's
/// `dispatch_family`, `value` and `dispatch_key` re-derive through the
/// same shared Rust abstraction the writers use: the family recomputes
/// from `target`, never the stored column, so a stale family cannot
/// bake into the `value` it feeds, and the stored-pair diff writes
/// only rows whose triple actually moved. Paging by `task_id` keyset
/// keeps worker memory flat across a million-row queue.
async fn backfill_rank_pairs(db: &DurableDb) -> Result<(), QueueError> {
    #[derive(serde::Serialize)]
    struct BackfillUpdate {
        task_id: String,
        lane: String,
        dispatch_family: String,
        value: String,
        dispatch_key: String,
    }
    let mut after = String::new();
    loop {
        let rows = db
            .query(&format!(
                "{RANK_SOURCE_SELECT} \
                 WHERE q.task_id > ? ORDER BY q.task_id LIMIT 2048"
            ))
            .bind(after.clone())
            .fetch_all::<RankSourceRow>()
            .await
            .map_err(|error| format!("page queue rows for backfill: {error}"))?;
        if rows.is_empty() {
            break;
        }
        after = rows
            .last()
            .map(|row| row.task_id.clone())
            .unwrap_or_default();
        let mut updates: Vec<BackfillUpdate> = Vec::new();
        for source in &rows {
            let row = source.checked()?;
            let family = crate::scheduler::rank::dispatch_family(&row.target).to_owned();
            let value =
                crate::scheduler::rank::raw_value(&row.lane, &family, row.priority, row.demand);
            let dispatch_key =
                crate::scheduler::rank::dispatch_key(&crate::scheduler::rank::KeyOperands {
                    lane: &row.lane,
                    family: &family,
                    priority: row.priority,
                    demand: row.demand,
                    cost_ms: row.cost_ms,
                    first_requested_at: &row.first_requested_at,
                    created_at: &row.created_at,
                    task_id: &row.task_id,
                });
            if family != row.dispatch_family
                || value != row.value
                || dispatch_key != row.dispatch_key
            {
                updates.push(BackfillUpdate {
                    task_id: row.task_id.clone(),
                    lane: row.lane.clone(),
                    dispatch_family: family,
                    value: value.to_string(),
                    dispatch_key,
                });
            }
        }
        for chunk in updates.chunks(ENQUEUE_JSON_BATCH_ROWS) {
            db.query(&format!(
                "UPDATE queue \
                 SET dispatch_family = j.e ->> 'dispatch_family', \
                     value = CAST(j.e ->> 'value' AS INTEGER), \
                     dispatch_key = j.e ->> 'dispatch_key', \
                     dispatch_eligible = {eligible} \
                 FROM (SELECT value AS e FROM json_each(?)) AS j \
                 WHERE queue.task_id = j.e ->> 'task_id'",
                eligible =
                    dispatch_eligible_sql("j.e ->> 'lane'", "CAST(j.e ->> 'value' AS INTEGER)",),
            ))
            .bind(enqueue_json(chunk)?)
            .execute()
            .await
            .map_err(|error| format!("backfill dispatch keys: {error}"))?;
        }
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
/// `demand`/`value`/`dispatch_key` inside that one statement, and a
/// failure anywhere — including the trigger's own staged-count
/// `RAISE(ABORT)` — rolls back the transition AND all triggered queue
/// effects. Once it returns, the batch is complete; nothing accepted
/// is ever applied again. `value` and `dispatch_key` refresh for the
/// event's own closure only.
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
    for chunk in &chunks {
        check_demand_band_bound(db, chunk).await?;
    }

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
async fn demand_closure_tasks(
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

/// The demand band bound, checked over exactly the rows this event
/// will fold — the chunk about to stage — before any write: `MAX(0,
/// priority) + demand + delta` must stay under `PRIORITY_MAX` so
/// demand cannot outrank a lane or family band. Written as `delta >
/// bound - priority - demand`, every operand stays inside i64, so the
/// compare can never promote to REAL — and on overflow the request
/// errors with the offenders named rather than clamping.
async fn check_demand_band_bound(db: &DurableDb, payload: &str) -> Result<(), QueueError> {
    let offending: Vec<String> = db
        .query(&format!(
            "SELECT f.tid FROM ( \
                 SELECT j.value ->> 'tid' AS tid, \
                        CAST(j.value ->> 'delta' AS INTEGER) AS delta \
                 FROM json_each(?) j \
             ) f \
             JOIN queue q ON q.task_id = f.tid \
             WHERE f.delta > {PRIORITY_MAX} - MAX(0, q.priority) - q.demand"
        ))
        .bind(payload.to_owned())
        .fetch_scalars::<String>()
        .await
        .map_err(|error| format!("demand band-bound check: {error}"))?;
    if !offending.is_empty() {
        return Err(QueueError::Invariant(format!(
            "demand would overflow the priority band on {} task(s): {}",
            offending.len(),
            offending.join(", ")
        )));
    }
    Ok(())
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
/// companion to [`effective_status_sql`]. A failed dependency reports
/// its task id; an edge whose identity was never resolved reports
/// `unknown dependency identity`, since no task names it.
fn blocked_by_sql() -> String {
    "CASE WHEN queue.status = 'pending' AND queue.blocked != 0 THEN ( \
        SELECT CASE WHEN bd.dep_crate_name = '' THEN 'unknown dependency identity' \
                    ELSE bd.depends_on_task_id END \
            FROM queue_dependencies bd \
            LEFT JOIN queue bdep ON bdep.task_id = bd.depends_on_task_id \
            WHERE bd.task_id = queue.task_id \
              AND (bdep.status = 'failed' OR bd.dep_crate_name = '' OR bd.dep_host_side < 0) \
              AND bd.dep_met = 0 \
            ORDER BY bd.depends_on_task_id LIMIT 1 \
    ) END"
        .to_owned()
}

async fn claim_dispatchable_row(
    db: &DurableDb,
    row: TaskRow,
) -> Result<Option<QueuedTask>, QueueError> {
    let claimed_generation = db
        .query(
            // `claimed_at` is the immutable claim instant of the
            // generation just minted — the one timestamp no in-flight
            // writer may rewrite, so the completion samples a real
            // claim-to-completion duration even after re-requests
            // bumped `updated_at` (stow#524).
            "UPDATE queue \
             SET status = 'dispatched', generation_id = lower(hex(randomblob(16))), \
                 dispatch_attempts = dispatch_attempts + 1, \
                 github_run_id = NULL, claimed_at = datetime('now'), \
                 updated_at = datetime('now') \
             WHERE task_id = ? AND status = 'pending' \
             RETURNING generation_id",
        )
        .bind(row.task_id.clone())
        .fetch_optional::<ClaimGenerationRow>()
        .await
        .map_err(|error| format!("claim task {}: {error}", row.task_id))?;

    let Some(claimed_generation) = claimed_generation else {
        tracing::warn!(
            task_id = %row.task_id,
            "skipping task claim — already claimed by concurrent dispatch"
        );
        return Ok(None);
    };

    Ok(Some(QueuedTask {
        task_id: row.task_id,
        generation_id: claimed_generation.generation_id,
        attempt: row.attempt,
        crate_name: row.crate_name,
        version: row.version,
        features_json: row.features_json,
        target: row.target,
        rustc_version: row.rustc_version,
        host_side: row.host_side != 0,
        preserve_lockfile: row.preserve_lockfile != 0,
        dep_pins: Vec::new(),
    }))
}

pub async fn claim_dispatchable_tasks(
    db: &DurableDb,
    settings: &SchedulerSettings,
    coverage: &impl CoverageOracle,
) -> Result<Vec<QueuedTask>, QueueError> {
    // Stale recovery runs ahead of the pause check: a paused scheduler
    // owes its in-flight builds the same lease-expiry reclaim.
    recover_stale_active_tasks(db, settings).await?;
    // A completed dependency whose published rows do not cover the
    // shapes a dependent's edge requires is not done — re-queue it once
    // so it rebuilds and republishes rather than gating dependents
    // forever. Repair, not dispatch: it runs paused or not.
    requeue_incomplete_shape_deps(db, settings).await?;
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
    let active = count_active_by_family(db).await?;
    let mut total_slots = limit.get().saturating_sub(active.total);
    let mut macos_slots = settings
        .max_concurrent_macos_jobs
        .saturating_sub(active.of(RunnerFamily::MacOs));
    tracing::info!(
        running = active.total,
        available = total_slots,
        macos_available = macos_slots,
        ?settings,
        "scheduler claim_dispatchable_tasks capacity"
    );
    if total_slots == 0 {
        return Ok(Vec::new());
    }

    // A family with zero free slots is excluded in the claim query
    // itself: its backlog would otherwise spend the page budget while
    // claimable rows of other families sit past the frontier.
    let full_family = (macos_slots == 0).then_some(RunnerFamily::MacOs);
    // Page, retire and claim interleaved: a pass reads rows in
    // proportion to the slots it fills, never to the frontier depth —
    // a page sized to the open slots goes to the coverage oracle as one
    // lookup, and the next page is read only while slots remain and the
    // last page came back full.
    let mut claimed = Vec::new();
    let mut selected = 0usize;
    let mut after = String::new();
    for _ in 0..CLAIM_MAX_PAGES {
        if total_slots == 0 {
            break;
        }
        // About two candidates per open slot: covered retirements
        // rarely force a second page, and the page cap keeps a deep
        // frontier on the next alarm tick.
        let page_rows = CLAIM_PAGE_ROWS.min(i64::from(total_slots) * 2);
        let page = select_dispatchable_page(db, settings, full_family, &after, page_rows).await?;
        selected += page.len();
        let full_page =
            page.len() == usize::try_from(page_rows).expect("claim page rows fits usize");
        if let Some(last) = page.last() {
            after.clone_from(&last.dispatch_key);
        }
        for row in retire_covered_rows(db, page, coverage).await? {
            if total_slots == 0 {
                break;
            }
            // Enqueue only admits CI targets, so a pending row whose target
            // maps to no runner family means the queue state is corrupt.
            let family = runner_family(&row.target).ok_or_else(|| {
                QueueError::Invariant(format!(
                    "pending task {} targets `{}`, which maps to no runner family",
                    row.task_id, row.target
                ))
            })?;
            if family == RunnerFamily::MacOs && macos_slots == 0 {
                continue;
            }
            let Some(task) = claim_dispatchable_row(db, row).await? else {
                continue;
            };
            total_slots -= 1;
            if family == RunnerFamily::MacOs {
                macos_slots -= 1;
            }

            claimed.push(task);
        }
        if !full_page {
            break;
        }
    }
    tracing::info!(selected, "scheduler claim_dispatchable_tasks selected rows");

    load_claimed_dep_pins(db, &mut claimed).await?;

    Ok(claimed)
}

/// Fill each claimed task's `dep_pins` from its `queue_dependencies` rows:
/// the (name, version, unified features, side) the dep's own task was
/// published at, which is exactly what the dependent's wrapper manifest
/// pins so its resolve lands on the published unit (stow#431).
async fn load_claimed_dep_pins(
    db: &DurableDb,
    claimed: &mut [QueuedTask],
) -> Result<(), QueueError> {
    if claimed.is_empty() {
        return Ok(());
    }
    let task_ids = claimed
        .iter()
        .map(|task| task.task_id.clone())
        .collect::<Vec<_>>();
    let rows = db
        .query(
            "SELECT task_id, dep_crate_name, dep_version, dep_features_json, dep_host_side \
             FROM queue_dependencies \
             WHERE task_id IN (SELECT value FROM json_each(?))",
        )
        .bind(enqueue_json(&task_ids)?)
        .fetch_all::<DepPinRow>()
        .await
        .map_err(|error| format!("load claimed task dep pins: {error}"))?;
    let mut by_task: std::collections::HashMap<String, Vec<stow_types::api::BuildDepPin>> =
        std::collections::HashMap::new();
    for row in rows {
        let pin = stow_types::api::BuildDepPin {
            crate_name: CrateName::parse(row.dep_crate_name).map_err(|error| {
                QueueError::Invariant(format!(
                    "dep pin for {}: invalid crate name: {error}",
                    row.task_id
                ))
            })?,
            version: CrateVersion::new(semver::Version::parse(&row.dep_version).map_err(
                |error| {
                    QueueError::Invariant(format!(
                        "dep pin for {}: invalid version: {error}",
                        row.task_id
                    ))
                },
            )?),
            features_json: FeaturesJson::from_sorted(
                serde_json::from_str(&row.dep_features_json).map_err(|error| {
                    QueueError::Invariant(format!(
                        "dep pin for {}: invalid features: {error}",
                        row.task_id
                    ))
                })?,
            )
            .map_err(|error| {
                QueueError::Invariant(format!(
                    "dep pin for {}: invalid features: {error}",
                    row.task_id
                ))
            })?,
            host_side: row.dep_host_side != 0,
        };
        by_task.entry(row.task_id).or_default().push(pin);
    }
    for task in claimed.iter_mut() {
        if let Some(pins) = by_task.remove(&task.task_id) {
            task.dep_pins = pins;
        }
    }
    Ok(())
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
const CLAIM_PAGE_ROWS: i64 = 256;

/// Pages per claim pass — a frontier deeper than this defers to the
/// next alarm tick, which the still-full queue reschedules immediately.
const CLAIM_MAX_PAGES: usize = 8;

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
/// `full_family` names a runner family with zero free slots — its rows
/// are excluded in SQL, the same predicate the wake probes build: a
/// saturated family's backlog must not spend the page budget while
/// other families have claimable rows past the frontier. One page of at
/// most `page_rows` rows resumes the keyset walk from `after` (the last
/// `dispatch_key` the previous page read): the caller sizes the page to
/// its open slots and pages again only while that page came back full,
/// because a family that fills mid-pass is still skipped in Rust and
/// the walk must see past it.
async fn select_dispatchable_page(
    db: &DurableDb,
    settings: &SchedulerSettings,
    full_family: Option<RunnerFamily>,
    after: &str,
    page_rows: i64,
) -> Result<Vec<TaskRow>, QueueError> {
    let family_filter = full_family.map_or_else(String::new, |family| {
        format!(
            "AND q.dispatch_family != '{}'",
            dispatch_family_label(family)
        )
    });
    let sql = format!(
        "SELECT q.task_id, q.attempt, q.crate_name, q.version, q.features_json, q.target, q.rustc_version, q.host_side, q.preserve_lockfile, q.dispatch_attempts, q.dispatch_key \
         FROM queue q \
         WHERE q.status = 'pending' AND q.deps_met = 1 \
           AND q.dispatch_eligible = 1 \
           AND (q.lane = 'human' OR q.first_requested_at <= datetime('now', ?)) \
           AND q.not_before <= datetime('now') \
           AND q.dispatch_key > ? \
           {family_filter} \
         ORDER BY q.dispatch_key \
         LIMIT ?",
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

pub async fn mark_dispatch_failed(
    db: &DurableDb,
    settings: &SchedulerSettings,
    task_id: &str,
    generation_id: &str,
    error: &str,
) -> Result<(), QueueError> {
    // Exponential backoff keyed on dispatch_attempts (incremented at claim
    // time): a persistent dispatch failure (GitHub outage, bad token) must
    // not spin the alarm in a zero-delay retry loop.
    let Some(dispatch_attempts) = db
        .query(
            "SELECT dispatch_attempts FROM queue \
             WHERE task_id = ? AND generation_id = ? \
               AND status IN ('dispatched', 'running') AND github_run_id IS NULL",
        )
        .bind(task_id.to_owned())
        .bind(generation_id.to_owned())
        .fetch_scalar_optional::<u32>()
        .await
        .map_err(|db_error| format!("load dispatch attempts for {task_id}: {db_error}"))?
    else {
        // A late external-I/O failure for a superseded or already-bound
        // generation must not overwrite the live row.
        return Ok(());
    };
    let backoff_minutes = dispatch_backoff_minutes(dispatch_attempts);
    // The row re-enters `pending`: `unpublished_deps`/`deps_met` stay
    // live on every status, so the recompute is a cheap count-derived
    // re-derivation — and `blocked`, maintained for pending rows only,
    // may have gone stale while it was in-flight. `wake_at` is the
    // later of the age gate and the backoff this statement writes (the
    // SET operand is spelled out again — SET terms see the old row);
    // the human lane ignores the age gate.
    let next_not_before = "datetime('now', ?)";
    let updated = db
        .query(&format!(
            "UPDATE queue \
         SET status = 'pending', error_msg = ?, \
             not_before = {next_not_before}, \
             deps_met = {deps_met}, blocked = {blocked}, \
             wake_at = {wake}, \
             updated_at = datetime('now') \
         WHERE task_id = ? AND generation_id = ? \
           AND status IN ('dispatched', 'running') AND github_run_id IS NULL \
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
        .bind(error.to_owned())
        .bind(format!("+{backoff_minutes} minutes"))
        .bind(format!("+{backoff_minutes} minutes"))
        .bind(format!("+{backoff_minutes} minutes"))
        .bind(task_id.to_owned())
        .bind(generation_id.to_owned())
        .fetch_scalars::<String>()
        .await
        .map_err(|db_error| {
            format!("mark dispatch failed for {task_id} generation {generation_id}: {db_error}")
        })?;

    if !updated.is_empty() {
        discard_pending_completions(db, task_id, generation_id).await?;
        // The row re-entered `pending` carrying the rank written
        // before the last cost move; refresh it through the shared
        // abstraction, scoped to the row that transitioned.
        refresh_dispatch_keys(db, &updated).await?;
    }

    Ok(())
}

async fn discard_pending_completions(
    db: &DurableDb,
    task_id: &str,
    generation_id: &str,
) -> Result<(), QueueError> {
    db.query(
        "DELETE FROM pending_run_completions \
         WHERE task_id = ? AND EXISTS ( \
             SELECT 1 FROM queue \
             WHERE task_id = ? AND generation_id = ? AND status = 'pending' \
         )",
    )
    .bind(task_id.to_owned())
    .bind(task_id.to_owned())
    .bind(generation_id.to_owned())
    .execute()
    .await
    .map_err(|error| {
        format!("discard pending completions for {task_id} generation {generation_id}: {error}")
    })?;
    Ok(())
}

fn dispatch_backoff_minutes(attempts: u32) -> u32 {
    2u32.checked_pow(attempts.min(6))
        .unwrap_or(MAX_DISPATCH_BACKOFF_MINUTES)
        .min(MAX_DISPATCH_BACKOFF_MINUTES)
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
        .query(
            "SELECT token, expires_at FROM github_app_token \
             WHERE id = 1 AND CAST(strftime('%s', expires_at) AS INTEGER) \
             > CAST(strftime('%s', 'now') AS INTEGER) + ?",
        )
        .bind(GITHUB_APP_TOKEN_MIN_REMAINING_SECS)
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
/// the window is at most `window_minutes / 5` buckets per target
/// (12 × 9 targets under the defaults) whatever the traffic, so the
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
    // The bucket SELECT returns the rows it scans — the host backend's
    // `rows_read` then equals what the Durable Object bills.
    let buckets = db
        .query(
            "SELECT target, outcomes, failures FROM attempt_outcome_buckets \
             WHERE bucket >= unixepoch('now') - ? \
             ORDER BY target, bucket",
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
            "SELECT failure_class, count(*) AS count FROM ( \
                 SELECT failure_class, finished_at FROM attempt_outcomes \
                 UNION ALL \
                 SELECT failure_class, finished_at FROM attempt_outcomes_v2 \
             ) \
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
            "SELECT github_run_id FROM ( \
                 SELECT github_run_id, finished_at FROM attempt_outcomes \
                 UNION ALL \
                 SELECT github_run_id, finished_at FROM attempt_outcomes_v2 \
             ) \
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
    request_count: i64,
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
     request_count, dispatch_attempts, preserve_lockfile, \
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
            request_count: u32::try_from(self.request_count).map_err(|_| QueueError::Overflow {
                field: "request_count",
                value: self.request_count.cast_unsigned(),
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
                // two, and `idx_queue_pending_live (blocked, updated_at)
                // WHERE status = 'pending'` bounds each arm's listing to
                // its own group, newest first.
                QueueTaskStatus::Pending | QueueTaskStatus::Blocked => {
                    predicates.push(format!("{qualifier}status = 'pending'"));
                    predicates.push(format!("{qualifier}blocked = ?"));
                    values.push(i64::from(matches!(status, QueueTaskStatus::Blocked)).into());
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
            predicates.push(format!("{qualifier}updated_at <= datetime('now', ?)"));
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

/// Queue rows matching a selector, newest state transition first.
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
    let sql = format!(
        "SELECT {ADMIN_TASK_COLUMNS}, ({}) AS status, \
         ({}) AS blocked_by FROM queue {where_clause} \
         ORDER BY updated_at DESC LIMIT {limit}",
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
             WHERE status = 'failed' AND {predicate}",
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
            db.query(
                "DELETE FROM pending_run_completions \
                 WHERE task_id IN (SELECT value FROM json_each(?))",
            )
            .bind(ids.clone())
            .execute()
            .await
            .map_err(|error| format!("discard pending completions after mutation: {error}"))?;
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
/// pair — the `pending`/`miss` guards on the write narrow its domain
/// to exactly the rows the selector matched. `RETURNING` counts the
/// rows actually moved, as every mutation does.
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
                   AND queue.status = 'pending' AND queue.lane = 'miss' \
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
             attempt, dispatch_attempts, updated_at, github_run_id \
             FROM queue WHERE status IN ('dispatched', 'running') \
             ORDER BY updated_at",
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
    updated_at: String,
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
            updated_at: self.updated_at,
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
    /// so `earliest_active_lease_expiry_ms` must be `Some`.
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
    /// Earliest `updated_at + stale_dispatch_minutes` over dispatched/running
    /// rows — when the oldest in-flight build becomes recoverable. Must be
    /// `Some` whenever `capacity` is `Exhausted`; `next_alarm` enforces
    /// this before delegating.
    pub earliest_active_lease_expiry_ms: Option<i64>,
}

/// Pure alarm decision; see [`AlarmInputs`] for the meaning of each field.
///
/// A wake-up is needed not only for pending rows becoming eligible but also
/// for stale recovery: `recover_stale_active_tasks` only runs inside
/// `claim_dispatchable_tasks`, so an in-flight build whose completion
/// webhook never arrives would never be reclaimed unless the alarm fires at
/// its lease expiry.
pub fn plan_alarm(inputs: &AlarmInputs) -> AlarmPlan {
    match (inputs.capacity, inputs.earliest_pending_eligible_ms) {
        // A free slot plus an eligible row: wake when it can be claimed.
        (DispatchCapacity::Available, Some(eligible_ms)) => {
            AlarmPlan::At(eligible_ms.max(inputs.now_ms))
        }
        // Every slot is taken, so the earliest wake-up that can make
        // progress is the oldest lease expiring — never `now`, which would
        // spin the Durable Object in a zero-delay alarm loop.
        (DispatchCapacity::Exhausted, Some(_)) => {
            inputs.earliest_active_lease_expiry_ms.map_or_else(
                || unreachable!("exhausted dispatch capacity implies an active queue row"),
                |lease_ms| AlarmPlan::At(lease_ms.max(inputs.now_ms)),
            )
        }
        // Paused, or no dispatchable row: the only wake that can still
        // make progress is stale recovery on an in-flight build — pending
        // rows blocked on an active dependency unblock when it completes
        // or goes stale too. Nothing in flight means nothing to wake for.
        (_, _) => inputs
            .earliest_active_lease_expiry_ms
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
            macos_saturated.then_some(RunnerFamily::MacOs),
            now_ms,
        )
        .await?,
        earliest_active_lease_expiry_ms: earliest_active_lease_expiry_ms(db, settings).await?,
    };
    // Exhausted capacity means at least one dispatched/running row exists, so
    // a missing lease expiry contradicts the count just read — fail loudly
    // rather than letting plan_alarm pick a wake-up.
    if matches!(inputs.capacity, DispatchCapacity::Exhausted)
        && inputs.earliest_active_lease_expiry_ms.is_none()
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
/// `full_family` names a capped runner family whose slots are all taken;
/// its pending rows are excluded so an eligibility the scheduler could
/// not act on cannot wake the alarm at `now`.
async fn earliest_pending_eligible_ms(
    db: &DurableDb,
    full_family: Option<RunnerFamily>,
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
    let family_filter = full_family.map_or_else(String::new, |family| {
        format!("AND dispatch_family != '{}'", dispatch_family_label(family))
    });
    // The plan is a pure function of `now_ms`; bind the rendered clock
    // rather than calling wall-clock `datetime('now')` inside the probes.
    let now = db
        .query("SELECT datetime(? / 1000, 'unixepoch')")
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

/// Earliest epoch-ms at which an in-flight (dispatched/running) row's lease
/// goes stale: `updated_at + stale_dispatch_minutes`, minimized. May be in
/// the past (already recoverable).
async fn earliest_active_lease_expiry_ms(
    db: &DurableDb,
    settings: &SchedulerSettings,
) -> Result<Option<i64>, QueueError> {
    let lease_epoch = db
        .query(
            "SELECT CAST(strftime('%s', MIN(datetime(updated_at, ?))) AS INTEGER) AS lease_epoch \
             FROM queue \
             WHERE status IN ('dispatched', 'running')",
        )
        .bind(format!("+{} minutes", settings.stale_dispatch_minutes))
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
/// (its deps are host units under either spelling); a target-side task
/// runs the one spelling its target implies.
pub fn dep_invocation_mask(owner_target: &str, owner_host_side: bool) -> i64 {
    if owner_host_side {
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
/// node's own invocation spelling — the only one a target task
/// produces.
pub fn dep_edge_requirements(
    owner_target: &str,
    owner_host_side: bool,
    dep_target: &str,
    dep_host_side: bool,
) -> (i64, i64) {
    if dep_host_side {
        let mask = dep_invocation_mask(owner_target, owner_host_side);
        return (mask, i64::from(mask.count_ones()));
    }
    (dep_invocation_mask(dep_target, false), 2)
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
    unit_side: i64,
    kind: Option<SliceChangeKind>,
}

#[derive(serde::Serialize)]
struct NormalizedGateRow {
    crate_name: String,
    version: String,
    features_json: String,
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

fn slice_row_key(row: &SliceRowJson) -> (String, String, String, i64, i64, i64) {
    (
        row.crate_name.clone(),
        row.version.clone(),
        row.features_json.clone(),
        row.unit_side,
        row.unit_invocation,
        row.unit_linked,
    )
}

fn normalize_gate_rows(
    rows: impl IntoIterator<Item = (SliceRowJson, Option<SliceChangeKind>)>,
) -> Vec<NormalizedGateRow> {
    let mut normalized = std::collections::BTreeMap::<GateIdentity, i64>::new();
    for (row, kind) in rows {
        let Some(invocation) =
            stow_types::public_cache::UnitInvocation::from_int(row.unit_invocation)
        else {
            continue;
        };
        let Some(side) = stow_types::public_cache::UnitSide::from_int(row.unit_side) else {
            continue;
        };
        let linked = match row.unit_linked {
            0 => false,
            1 => true,
            _ => continue,
        };
        if side == stow_types::public_cache::UnitSide::Host && !linked {
            continue;
        }
        let identity = GateIdentity {
            crate_name: row.crate_name,
            version: row.version,
            features_json: row.features_json,
            unit_side: side.to_int(),
            kind,
        };
        let bit = 1_i64 << invocation.to_int();
        *normalized.entry(identity).or_default() |= bit;
    }
    normalized
        .into_iter()
        .map(|(identity, invocations)| NormalizedGateRow {
            crate_name: identity.crate_name,
            version: identity.version,
            features_json: identity.features_json,
            unit_side: identity.unit_side,
            invocations,
            kind: identity.kind,
        })
        .collect()
}

fn normalized_gate_json(
    rows: impl IntoIterator<Item = (SliceRowJson, Option<SliceChangeKind>)>,
) -> Result<Option<String>, QueueError> {
    let normalized = normalize_gate_rows(rows);
    if normalized.is_empty() {
        return Ok(None);
    }
    serde_json::to_string(&normalized)
        .map(Some)
        .map_err(|error| QueueError::Sql(format!("encode slice gate json: {error}")))
}

pub async fn record_published_slice(
    db: &DurableDb,
    target: &str,
    rustc_version: &str,
    base_generation: Option<i64>,
    generation: Option<i64>,
    added: &[PublishedSliceRow],
    retired: &[PublishedSliceRow],
) -> Result<(), QueueError> {
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
        target,
        rustc_version,
        marker_generation,
        gate_changes,
        run_stale_cleanup,
        next_applied,
    )
    .await
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
/// out (only live-read rows carry one) and a missing unit shape writes
/// the `-1` legs that satisfy no coverage clause.
fn to_slice_rows(rows: &[PublishedSliceRow]) -> Vec<SliceRowJson> {
    rows.iter()
        .map(|row| SliceRowJson {
            crate_name: row.crate_name.to_string(),
            version: row.version.to_string(),
            features_json: row.features_json.raw(),
            unit_side: row.unit_shape.map_or(-1, |shape| shape.side.to_int()),
            unit_invocation: row.unit_shape.map_or(-1, |shape| shape.invocation.to_int()),
            unit_linked: row.unit_shape.map_or(-1, |shape| shape.kind.to_int()),
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
        db.query(
            "DELETE FROM published_slice_rows \
             WHERE (target, rustc_version, generation, crate_name, version, features_json, \
                    unit_side, unit_invocation, unit_linked) IN ( \
                 SELECT ?, ?, ?, value ->> 'crate_name', value ->> 'version', \
                        value ->> 'features_json', value ->> 'unit_side', \
                        value ->> 'unit_invocation', value ->> 'unit_linked' \
                 FROM json_each(?))",
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
             (target, rustc_version, generation, crate_name, version, features_json, unit_side, unit_invocation, unit_linked) \
             SELECT ?, ?, ?, e ->> 'crate_name', e ->> 'version', e ->> 'features_json', \
                    e ->> 'unit_side', e ->> 'unit_invocation', e ->> 'unit_linked' \
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
            "SELECT rowid, crate_name, version, features_json, unit_side, unit_invocation, unit_linked \
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
             (target, rustc_version, generation, crate_name, version, features_json, unit_side, unit_invocation, unit_linked) \
             SELECT ?, ?, ?, e ->> 'crate_name', e ->> 'version', e ->> 'features_json', \
                    e ->> 'unit_side', e ->> 'unit_invocation', e ->> 'unit_linked' \
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
    target: &str,
    rustc_version: &str,
    live_generation: i64,
    gate_changes: Option<GateChangeSet>,
    run_stale_cleanup: bool,
    next_applied: Option<i64>,
) -> Result<(), QueueError> {
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
        gate_changes.json,
        live_generation,
        gate_changes.directional,
    )
    .await
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
                       CASE WHEN queue_dependencies.dep_crate_name = '' \
                                  OR queue_dependencies.dep_host_side < 0 \
                                  OR EXISTS ( \
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

/// The scheduler schema version this build serves, recorded in the
/// `scheduler_schema_version` singleton row once [`migrate`] has applied
/// it — `PRAGMA user_version` is the usual carrier but the Durable
/// Object SQL authorizer refuses it
/// (<https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/>),
/// so the version lives in a table. Bump it whenever `schema.sql` or
/// any step of [`migrate_schema`] changes — and keep every change
/// additive (expand, then contract): `deploy-edge.yml` runs the
/// migration right after `skyzen deploy`, while the previous build may
/// still be serving requests, so nothing the running code reads may
/// stop existing while the pass applies.
const SCHEMA_VERSION: i64 = 13;

/// The version-4 queue step on top of #470's version-3 tables: the
/// persisted dispatch-gate forms — `deps_met` (the dependency gate's
/// answer per row), `blocked`, `wake_at`, `dispatch_family` and
/// `dispatch_key` (the claim-order tuple) — backfilled on every row;
/// `queue_status_counts` and the `queue_counts_on_*` triggers, created
/// in `schema.sql` with the table's initial contents rebuilt here from
/// the queue itself; and the `idx_queue_dependencies_dep_match` /
/// `idx_queue_{target,crate}_updated` indexes. The columns are added by
/// `migrate_schema`'s modern branch (ahead of the schema.sql include,
/// whose new indexes build on them) and exist from creation on fresh
/// and dev-era-recreated queues. The backfill stays unconditional: a
/// re-run writes the same values.
async fn migrate_dispatch_gate(
    db: &DurableDb,
    settings: &SchedulerSettings,
) -> Result<(), QueueError> {
    // The (status, lane, blocked) counter table must be in shape before
    // the backfills below run: they fire `queue_counts_on_move`, and an
    // old-shape counts table — pre-`blocked`, which an earlier rebuild's
    // rename may have stranded here — makes the new-shape trigger fail
    // inside the UPDATE. Rebuild it first, then the triggers and the
    // repopulate agree on the key.
    let has_blocked = db
        .query("PRAGMA table_info(queue_status_counts)")
        .fetch_all::<QueueTableInfoRow>()
        .await
        .map_err(|error| format!("inspect status counts shape: {error}"))?
        .iter()
        .any(|column| column.name == "blocked");
    if !has_blocked {
        for statement in [
            "DROP TRIGGER IF EXISTS queue_counts_on_insert",
            "DROP TRIGGER IF EXISTS queue_counts_on_delete",
            "DROP TRIGGER IF EXISTS queue_counts_on_move",
            "DROP TABLE IF EXISTS queue_status_counts",
        ] {
            db.query(statement)
                .execute()
                .await
                .map_err(|error| format!("drop old-shape status counts: {error}"))?;
        }
        migrate_schema(db).await?;
    }
    // The claim-order columns are derived from columns every row
    // carries — `value`'s lane/family/priority/demand bands, the
    // `dispatch_family` from `target`, and the `dispatch_key` that
    // ranks the exact value/cost ratio — so one pass backfills all
    // three (`value` came in the version-10 step; a key written under
    // an older format rebuilds under the current one through the
    // stored-pair diff). `dep_met` replays each edge's slice EXISTS
    // once — the seed for the per-owner counter — then
    // `unpublished_deps` counts those flags, `deps_met` is the `= 0`
    // derivation, and `blocked`/`wake_at` carry their stored
    // expressions. Queue-wide passes are legal here and only here —
    // this is operations code. The pass pages by task id rather than
    // holding the queue in memory, and each row's family/value/key
    // derives in the same shared Rust abstraction the writers use —
    // `dispatch_family` recomputes from `target`, not the stored
    // column, so a stale family cannot bake into the value it feeds.
    backfill_rank_pairs(db).await?;
    // Backfill the edge flags first: the counter recount below reads
    // `dep_met`, so edges must carry real answers before it runs. `f`
    // materializes each edge's fresh answer once (`LIMIT -1`) so the
    // `!=` guard compares against it instead of re-running the probe.
    db.query(&format!(
        "UPDATE queue_dependencies \
         SET dep_met = f.new_met \
         FROM (SELECT d.rowid AS rid, CASE WHEN {unpub} THEN 0 ELSE 1 END AS new_met \
               FROM queue_dependencies d \
               LIMIT -1) AS f \
         WHERE queue_dependencies.rowid = f.rid \
           AND queue_dependencies.dep_met != f.new_met",
        unpub = dep_edge_unpublished_sql("d"),
    ))
    .execute()
    .await
    .map_err(|error| format!("backfill edge dep_met flags: {error}"))?;
    // Same materialization the enqueue refresh uses: `y` evaluates
    // each row's probes once (`LIMIT -1` keeps it a co-routine —
    // flattening would re-run the count per reference) and the `!=`
    // guards compare stored against computed columns.
    let unpublished = unpublished_deps_sql("q.task_id");
    let blocked = blocked_sql("q.task_id");
    let wake = wake_at_sql(
        "lane",
        "first_requested_at",
        "not_before",
        settings.dispatch_min_age_minutes,
    );
    db.query(&format!(
        "UPDATE queue \
         SET unpublished_deps = f.unpublished, deps_met = f.met, \
             blocked = f.blocked, wake_at = f.wake \
         FROM (SELECT y.tid, y.unpublished, y.blocked, y.wake, \
                      CASE WHEN y.unpublished = 0 THEN 1 ELSE 0 END AS met \
               FROM (SELECT q.task_id AS tid, {unpublished} AS unpublished, \
                            {blocked} AS blocked, {wake} AS wake \
                     FROM queue q \
                     LIMIT -1) AS y \
               LIMIT -1) AS f \
         WHERE queue.task_id = f.tid \
           AND (queue.unpublished_deps != f.unpublished \
                OR queue.deps_met != f.met OR queue.blocked != f.blocked \
                OR queue.wake_at != f.wake)",
    ))
    .execute()
    .await
    .map_err(|error| format!("backfill dependency-gate columns: {error}"))?;
    // This rebuild plants the trigger-maintained counts on a queue whose
    // writes predate them — the one place a whole-queue GROUP BY is
    // legal.
    db.query("DELETE FROM queue_status_counts")
        .execute()
        .await
        .map_err(|error| format!("clear status counts for rebuild: {error}"))?;
    db.query(
        "INSERT INTO queue_status_counts (status, lane, blocked, n) \
         SELECT status, lane, blocked, count(*) FROM queue GROUP BY status, lane, blocked",
    )
    .execute()
    .await
    .map_err(|error| format!("rebuild status counts: {error}"))?;
    Ok(())
}

/// Run the scheduler schema migration — the only code that may issue
/// DDL or a backfill against the queue database. Migrations are
/// operations work: no request handler, and not the alarm, calls this.
/// The deploy pipeline drives it through
/// `POST /api/v1/admin/scheduler/migrate` (→ the Durable Object's
/// `/migrate` handler) right after `skyzen deploy`; `stow-admin
/// scheduler migrate` is the manual path. Request code assumes the
/// schema exists — when it does not, its own SQL fails loudly, which is
/// the fail-fast.
///
/// A stored version newer than `SCHEMA_VERSION` means the database was
/// migrated by newer code — fail fast rather than silently serve it.
/// The stamp is written only after every migration step has succeeded
/// — the same per-statement commit discipline `migrate_queue_schema`
/// and the column migrations already use — so a pass that dies midway
/// leaves the version behind and re-runs: every step is idempotent, and
/// a queue already at `SCHEMA_VERSION` reports `before == after`.
pub async fn migrate(
    db: &DurableDb,
    settings: &SchedulerSettings,
) -> Result<SchemaMigrationReport, QueueError> {
    let before = stored_schema_version(db).await?;
    if before > SCHEMA_VERSION {
        return Err(QueueError::Invariant(format!(
            "scheduler schema version {before} exceeds the {SCHEMA_VERSION} \
             this build understands — the database was migrated by newer code"
        )));
    }
    migrate_schema(db).await?;
    migrate_queue_dependencies_columns(db).await?;
    migrate_published_slice_row_shape(db).await?;
    migrate_published_slice_columns(db).await?;
    migrate_dispatch_gate(db, settings).await?;
    migrate_generation_identity(db, settings).await?;
    migrate_dispatch_eligible(db, settings).await?;
    migrate_demand_ledger(db).await?;
    // Every `migrate_schema` path has applied `schema.sql`, so `settings`
    // exists here. Its `panic` row belonged to the in-Worker circuit
    // breaker the zone's WAF maintenance rules replaced; nothing reads it.
    db.query("DELETE FROM settings WHERE key = 'panic'")
        .execute()
        .await
        .map_err(|error| format!("delete retired panic setting: {error}"))?;
    db.query(
        "INSERT INTO scheduler_schema_version (id, version) VALUES (1, ?) \
         ON CONFLICT(id) DO UPDATE SET version = excluded.version",
    )
    .bind(SCHEMA_VERSION)
    .execute()
    .await
    .map_err(|error| format!("stamp scheduler schema version: {error}"))?;
    Ok(SchemaMigrationReport {
        before,
        after: SCHEMA_VERSION,
    })
}

/// The stored schema version, or 0 on a queue that predates the marker
/// table or was never stamped. Both mean the migration pass has not run
/// under this versioning scheme — the pass is idempotent and is what
/// creates the table (via `schema.sql`) and the row in the first place.
/// Whether the table exists is asked of `PRAGMA table_info`, which the
/// Durable Object authorizer admits and which answers an empty set for a
/// missing table, rather than read off a failed query's message.
async fn stored_schema_version(db: &DurableDb) -> Result<i64, QueueError> {
    let marker_columns = db
        .query("PRAGMA table_info(scheduler_schema_version)")
        .fetch_all::<QueueTableInfoRow>()
        .await
        .map_err(|error| format!("load scheduler_schema_version table_info: {error}"))?;
    if marker_columns.is_empty() {
        return Ok(0);
    }
    let version = db
        .query("SELECT version FROM scheduler_schema_version WHERE id = 1")
        .fetch_scalar_optional::<i64>()
        .await
        .map_err(|error| format!("read scheduler schema version: {error}"))?;
    Ok(version.unwrap_or(0))
}

/// The full schema migration pass [`migrate`] runs. Re-running it is a
/// no-op on a current queue — every step is idempotent — so the operator
/// route is safe to call from a deploy retry. No transaction exists on
/// `DurableDb`, so every step is written to be safe to re-run after a
/// mid-pass failure. Every statement may run while the previous build
/// still serves requests: additive only, expand then contract.
async fn migrate_schema(db: &DurableDb) -> Result<(), QueueError> {
    let columns = db
        .query("PRAGMA table_info(queue)")
        .fetch_all::<QueueTableInfoRow>()
        .await
        .map_err(|error| format!("load queue table_info: {error}"))?
        .into_iter()
        .map(|row| row.name)
        .collect::<BTreeSet<_>>();

    // Nothing reads `rust_stable_channel` — stable resolution lives in
    // the Worker's Cache API — so the drop is additive-safe. It runs
    // ahead of the queue-shape branches so a database holding the
    // retired table alone loses it too; `IF EXISTS` keeps every other
    // pass a no-op.
    db.query("DROP TABLE IF EXISTS rust_stable_channel")
        .execute()
        .await
        .map_err(|error| format!("drop rust_stable_channel: {error}"))?;

    if columns.is_empty() {
        db.query(include_str!("schema.sql"))
            .execute()
            .await
            .map_err(|error| format!("ensure scheduler schema: {error}"))?;
        return Ok(());
    }

    if columns.contains("features_json")
        && columns.contains("request_count")
        && columns.contains("first_requested_at")
        && columns.contains("rustc_version")
        && !columns.contains("source_json")
    {
        migrate_queue_columns(db, &columns).await?;
        // 'partial' is gone as a terminal state: a stopped-early build
        // was a failure anyway (the task's own artifact is still
        // missing), so rows it left behind collapse onto the failure
        // state its semantics already shared.
        db.query("UPDATE queue SET status = 'failed' WHERE status = 'partial'")
            .execute()
            .await
            .map_err(|error| format!("collapse partial queue rows: {error}"))?;
        // Tables added after the queue schema (github_app_token) land
        // here rather than through the drop-and-recreate path: every
        // statement in schema.sql is IF NOT EXISTS, so re-running it on
        // an existing modern queue only creates what is missing.
        db.query(include_str!("schema.sql"))
            .execute()
            .await
            .map_err(|error| format!("ensure scheduler schema additions: {error}"))?;
        if !columns.contains("host_side") {
            migrate_queue_host_side(db).await?;
        }
        return Ok(());
    }

    migrate_queue_schema(db).await
}

/// Add every column a modern `queue` carries that `columns` lacks.
/// Each column is guarded separately — a pass that dies between ALTERs
/// must retry the ones it missed rather than skip them all on the first
/// column's presence (one shared guard wedged a retry behind
/// `no such column: dispatch_key`, stow#433). The dispatch-gate columns
/// (`deps_met`, `dispatch_family`, `dispatch_key`) must exist before the
/// schema.sql include creates the indexes built on them; their values
/// backfill in `migrate_dispatch_gate` after the whole pass.
async fn migrate_queue_columns(
    db: &DurableDb,
    columns: &BTreeSet<String>,
) -> Result<(), QueueError> {
    for (column, statement) in [
        (
            "preserve_lockfile",
            "ALTER TABLE queue ADD COLUMN preserve_lockfile INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "dispatch_attempts",
            "ALTER TABLE queue ADD COLUMN dispatch_attempts INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "attempt",
            "ALTER TABLE queue ADD COLUMN attempt INTEGER NOT NULL DEFAULT 1",
        ),
        (
            "generation_id",
            "ALTER TABLE queue ADD COLUMN generation_id TEXT NOT NULL DEFAULT ''",
        ),
        (
            "not_before",
            "ALTER TABLE queue ADD COLUMN not_before TEXT NOT NULL DEFAULT '1970-01-01 00:00:00'",
        ),
        (
            "lane",
            "ALTER TABLE queue ADD COLUMN lane TEXT NOT NULL DEFAULT 'miss' \
             CHECK (lane IN ('miss', 'human'))",
        ),
        (
            "github_run_id",
            "ALTER TABLE queue ADD COLUMN github_run_id TEXT",
        ),
        (
            "shape_requeue",
            "ALTER TABLE queue ADD COLUMN shape_requeue INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "unpublished_deps",
            "ALTER TABLE queue ADD COLUMN unpublished_deps INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "deps_met",
            "ALTER TABLE queue ADD COLUMN deps_met INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "blocked",
            "ALTER TABLE queue ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "wake_at",
            "ALTER TABLE queue ADD COLUMN wake_at TEXT NOT NULL DEFAULT '1970-01-01 00:00:00'",
        ),
        (
            "dispatch_family",
            "ALTER TABLE queue ADD COLUMN dispatch_family TEXT NOT NULL DEFAULT ''",
        ),
        (
            "value",
            "ALTER TABLE queue ADD COLUMN value INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "demand",
            "ALTER TABLE queue ADD COLUMN demand INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "dispatch_key",
            "ALTER TABLE queue ADD COLUMN dispatch_key TEXT NOT NULL DEFAULT ''",
        ),
        ("claimed_at", "ALTER TABLE queue ADD COLUMN claimed_at TEXT"),
        (
            "dispatch_eligible",
            "ALTER TABLE queue ADD COLUMN dispatch_eligible INTEGER NOT NULL DEFAULT 1",
        ),
    ] {
        if !columns.contains(column) {
            db.query(statement)
                .execute()
                .await
                .map_err(|error| format!("add queue.{column} column: {error}"))?;
        }
    }
    Ok(())
}

/// Give every queue row a unique dispatch identity and expand the raw
/// failure evidence key beyond the resettable attempt counter. This is
/// operator migration work: request paths only read and write the columns.
async fn migrate_generation_identity(
    db: &DurableDb,
    settings: &SchedulerSettings,
) -> Result<(), QueueError> {
    let next_not_before =
        "datetime('now', '+' || MIN(1 << MIN(dispatch_attempts, 6), 60) || ' minutes')";
    db.query(&format!(
        "UPDATE queue SET status = 'pending', \
             error_msg = 'legacy in-flight dispatch requeued during generation migration', \
             not_before = {next_not_before}, \
             deps_met = {deps_met}, blocked = {blocked}, wake_at = {wake}, \
             updated_at = datetime('now') \
         WHERE generation_id = '' AND status IN ('dispatched', 'running') \
           AND github_run_id IS NULL",
        deps_met = deps_met_sql("queue.task_id"),
        blocked = blocked_sql("queue.task_id"),
        wake = wake_at_sql(
            "lane",
            "first_requested_at",
            next_not_before,
            settings.dispatch_min_age_minutes,
        ),
    ))
    .execute()
    .await
    .map_err(|error| format!("requeue unbound legacy dispatches: {error}"))?;
    db.query(
        "UPDATE queue SET generation_id = lower(hex(randomblob(16))) \
         WHERE generation_id = ''",
    )
    .execute()
    .await
    .map_err(|error| format!("backfill queue generation identities: {error}"))?;

    Ok(())
}

/// The combined schema's dispatch-eligible step (stow#525 I10): the
/// admission floor becomes a
/// persisted `dispatch_eligible` answer — `lane = 'human' OR value >=
/// floor` — maintained by every writer and equality-indexed ahead of
/// the claim's `dispatch_key` order and the wake probes' `wake_at`
/// range. The column itself lands in `migrate_queue_columns` (ahead of
/// the schema include, which creates the replacement indexes); this
/// step retires the floor-blind index names once the eligible-aware
/// ones exist — additive-create then drop, inside this operator pass —
/// and applies the configured floor: the authoritative value is stored
/// in `settings` as decimal text (every writer's eligibility
/// expression reads it there, so a changed env binding cannot produce
/// mixed flags before its migrate runs), then the queue backfills only
/// when that stored value differs. Re-runs are no-ops — an unchanged
/// floor backfills nothing and re-stamps nothing.
async fn migrate_dispatch_eligible(
    db: &DurableDb,
    settings: &SchedulerSettings,
) -> Result<(), QueueError> {
    for statement in [
        "DROP INDEX IF EXISTS idx_queue_dispatch",
        "DROP INDEX IF EXISTS idx_queue_wake_eligible",
    ] {
        db.query(statement)
            .execute()
            .await
            .map_err(|error| format!("retire floor-blind queue index: {error}"))?;
    }
    let stored = db
        .query("SELECT value FROM settings WHERE key = 'min_dispatch_value'")
        .fetch_scalar_optional::<String>()
        .await
        .map_err(|error| format!("read applied dispatch floor: {error}"))?
        .map(|raw| raw.parse::<i64>())
        .transpose()
        .map_err(|error| format!("parse applied dispatch floor: {error}"))?;
    if stored != Some(settings.min_dispatch_value) {
        // The stamp is the pass's success record, so it writes LAST:
        // the backfill evaluates against the configured floor as its
        // operand — an i64 literal, since the settings row it must not
        // read is the row this same pass is about to write — and only a
        // completed backfill earns the stamp. A statement failure
        // leaves the pass unstamped, so a retried migrate sees the old
        // stored value (or none) and runs the full repair again; a
        // completed pass needs no re-verification because the writers'
        // flags stayed consistent with the stored value throughout.
        // This is the caught-statement-failure contract — an
        // application-level SQL error aborts this function here, with
        // no claim that earlier or later calls share a transaction.
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

/// The demand ledger's runtime piece (stow#522): `demand_batches` and
/// `demand_contributions` are pure DDL in `schema.sql`, created by
/// `migrate_schema`'s `schema.sql` application on every path; the step
/// that remains is the `demand_fold` trigger. The trigger writes only
/// the staged prepared fields — `delta`, `value`, `dispatch_key`,
/// `dispatch_eligible` — all of which the demand route computes in
/// Rust through the shared rank abstraction before staging, so no SQL
/// ranking formula exists anywhere. The migrate replaces the
/// definition outright each run — DROP then CREATE — so a redeploy
/// always carries the current trigger and an obsolete formula-writing
/// definition an older deploy left cannot survive an `IF NOT EXISTS`.
async fn migrate_demand_ledger(db: &DurableDb) -> Result<(), QueueError> {
    // Dev-era `demand_contributions` tables predate the prepared
    // fields — `CREATE TABLE IF NOT EXISTS` never adds a column, so
    // the three staging columns land additively here. Orphaned draft
    // rows keep the defaults; a reprepare clears and restages them
    // wholesale before any acceptance can read them.
    let columns = db
        .query("PRAGMA table_info(demand_contributions)")
        .fetch_all::<QueueTableInfoRow>()
        .await
        .map_err(|error| format!("load demand staging table_info: {error}"))?
        .into_iter()
        .map(|row| row.name)
        .collect::<BTreeSet<_>>();
    for (column, statement) in [
        (
            "value",
            "ALTER TABLE demand_contributions \
             ADD COLUMN value TEXT NOT NULL DEFAULT ''",
        ),
        (
            "dispatch_key",
            "ALTER TABLE demand_contributions \
             ADD COLUMN dispatch_key TEXT NOT NULL DEFAULT ''",
        ),
        (
            "dispatch_eligible",
            "ALTER TABLE demand_contributions \
             ADD COLUMN dispatch_eligible INTEGER NOT NULL DEFAULT 0 \
             CHECK (dispatch_eligible IN (0, 1))",
        ),
    ] {
        if !columns.contains(column) {
            db.query(statement)
                .execute()
                .await
                .map_err(|error| format!("add demand staging column {column}: {error}"))?;
        }
    }
    db.query("DROP TRIGGER IF EXISTS demand_fold")
        .execute()
        .await
        .map_err(|error| format!("drop draft demand fold trigger: {error}"))?;
    // Acceptance is one statement: flipping the batch's state to
    // `accepted` fires this trigger, which folds the whole staged set
    // into the queue inside that statement — `demand` accumulates the
    // staged delta while `value`, `dispatch_key` and
    // `dispatch_eligible` land the event's precomputed answers — then
    // verifies the staged count reached the accepted count:
    // `RAISE(ABORT)` on a shortfall rolls the transition AND every
    // triggered queue effect back out of the same statement. A staged
    // row naming no queue task simply matches nothing.
    db.query(
        "CREATE TRIGGER demand_fold \
         AFTER UPDATE OF state ON demand_batches \
         WHEN NEW.state = 'accepted' AND OLD.state = 'prepared' \
         BEGIN \
             UPDATE queue \
             SET demand = queue.demand + c.delta, \
                 value = CAST(c.value AS INTEGER), \
                 dispatch_key = c.dispatch_key, \
                 dispatch_eligible = c.dispatch_eligible \
             FROM demand_contributions c \
             WHERE c.batch_id = NEW.batch_id AND queue.task_id = c.task_id \
               AND (queue.demand != queue.demand + c.delta \
                    OR queue.value != CAST(c.value AS INTEGER) \
                    OR queue.dispatch_key != c.dispatch_key \
                    OR queue.dispatch_eligible != c.dispatch_eligible); \
             SELECT RAISE(ABORT, 'demand batch staged set short of accepted count') \
             WHERE (SELECT count(*) FROM demand_contributions c \
                    WHERE c.batch_id = NEW.batch_id) != NEW.touched_count; \
         END",
    )
    .execute()
    .await
    .map_err(|error| format!("create demand fold trigger: {error}"))?;
    Ok(())
}

/// A `queue_dependencies` edge whose shape mask was never written —
/// joined to its owner task's identity so the migration can recompute
/// the same values the enqueue's dependency resync writes.
#[derive(Debug, skyzen::FromRow)]
struct UnmaskedEdge {
    task_id: String,
    depends_on_task_id: String,
    owner_target: Option<String>,
    owner_host_side: Option<i64>,
    dep_target: String,
    dep_host_side: i64,
}

/// Columns added to `queue_dependencies` after the table first shipped:
/// the dependency's semantic identity, denormalized so the published-slice
/// gate reads it without the dependency's queue row. Rows written before
/// the columns existed backfill from the queue row their
/// `depends_on_task_id` still points at; an edge whose dependency left
/// the queue keeps '' and never satisfies the gate. `dep_host_side`
/// defaults to the target-side requirement the gate always applied.
async fn migrate_queue_dependencies_columns(db: &DurableDb) -> Result<(), QueueError> {
    let columns = db
        .query("PRAGMA table_info(queue_dependencies)")
        .fetch_all::<QueueTableInfoRow>()
        .await
        .map_err(|error| format!("load queue_dependencies table_info: {error}"))?
        .into_iter()
        .map(|row| row.name)
        .collect::<BTreeSet<_>>();
    if columns.is_empty() {
        return Ok(());
    }
    // Guarded per column: a pass dying between ALTERs retries the ones
    // it missed rather than skipping the block on the first column's
    // presence.
    for column in [
        "dep_crate_name",
        "dep_version",
        "dep_features_json",
        "dep_target",
        "dep_rustc_version",
    ] {
        if !columns.contains(column) {
            db.query(&format!(
                "ALTER TABLE queue_dependencies ADD COLUMN {column} TEXT NOT NULL DEFAULT ''"
            ))
            .execute()
            .await
            .map_err(|error| format!("add queue_dependencies.{column} column: {error}"))?;
        }
    }
    // The identity backfill is gated on the never-written marker rather
    // than on whether the ALTERs just ran: an edge whose dep resolves
    // but whose `dep_crate_name` is still '' was missed by a pass that
    // died mid-block, while an already-backfilled edge always carries a
    // real name and an unresolved one fails the EXISTS — so re-running
    // costs the unresolved set, once, and the pass stays idempotent.
    db.query(
        "UPDATE queue_dependencies SET \
            dep_crate_name = (SELECT crate_name FROM queue WHERE task_id = queue_dependencies.depends_on_task_id), \
            dep_version = (SELECT version FROM queue WHERE task_id = queue_dependencies.depends_on_task_id), \
            dep_features_json = (SELECT features_json FROM queue WHERE task_id = queue_dependencies.depends_on_task_id), \
            dep_target = (SELECT target FROM queue WHERE task_id = queue_dependencies.depends_on_task_id), \
            dep_rustc_version = (SELECT rustc_version FROM queue WHERE task_id = queue_dependencies.depends_on_task_id) \
         WHERE dep_crate_name = '' \
           AND EXISTS (SELECT 1 FROM queue WHERE task_id = queue_dependencies.depends_on_task_id)",
    )
    .execute()
    .await
    .map_err(|error| format!("backfill queue_dependencies identity columns: {error}"))?;
    if !columns.contains("dep_host_side") {
        db.query(
            "ALTER TABLE queue_dependencies ADD COLUMN dep_host_side INTEGER NOT NULL DEFAULT 0",
        )
        .execute()
        .await
        .map_err(|error| format!("add queue_dependencies.dep_host_side column: {error}"))?;
    }
    // Guarded per column: a pass dying between ALTERs retries the ones
    // it missed rather than skipping the block on the first column's
    // presence.
    for (column, statement) in [
        (
            "dep_invocations",
            "ALTER TABLE queue_dependencies ADD COLUMN dep_invocations INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "dep_shapes",
            "ALTER TABLE queue_dependencies ADD COLUMN dep_shapes INTEGER NOT NULL DEFAULT 0",
        ),
    ] {
        if !columns.contains(column) {
            db.query(statement)
                .execute()
                .await
                .map_err(|error| format!("add queue_dependencies.{column} column: {error}"))?;
        }
    }
    if !columns.contains("dep_side_known") {
        db.query(
            "ALTER TABLE queue_dependencies ADD COLUMN dep_side_known INTEGER NOT NULL DEFAULT 0",
        )
        .execute()
        .await
        .map_err(|error| format!("add queue_dependencies.dep_side_known column: {error}"))?;
    }
    if !columns.contains("dep_met") {
        db.query("ALTER TABLE queue_dependencies ADD COLUMN dep_met INTEGER NOT NULL DEFAULT 0")
            .execute()
            .await
            .map_err(|error| format!("add queue_dependencies.dep_met column: {error}"))?;
    }
    migrate_queue_dependencies_indexes(db).await?;
    derive_dev_era_edge_sides(db).await?;
    backfill_dev_era_edge_masks(db).await
}

/// The indexes this migration's columns make possible — kept out of
/// `schema.sql` because a dev-era edges table only gains the columns
/// here. The two marker selects (`dep_side_known = 0`,
/// `dep_invocations = 0`) scanned every edge in the queue without them
/// (stow#432); the unresolved-edge and slice probes serve the request
/// paths that read them, and `dep_match` bounds the publish delta's
/// dependent refresh to the rows a report actually changed.
async fn migrate_queue_dependencies_indexes(db: &DurableDb) -> Result<(), QueueError> {
    for (statement, error) in [
        (
            "CREATE INDEX IF NOT EXISTS idx_queue_dependencies_side_unknown \
             ON queue_dependencies(task_id) WHERE dep_side_known = 0",
            "index edges with an unknown side",
        ),
        (
            "CREATE INDEX IF NOT EXISTS idx_queue_dependencies_unmasked \
             ON queue_dependencies(task_id) WHERE dep_invocations = 0",
            "index edges without a shape mask",
        ),
        (
            "CREATE INDEX IF NOT EXISTS idx_queue_dependencies_unresolved \
             ON queue_dependencies(task_id) WHERE dep_crate_name = '' OR dep_host_side < 0",
            "index unresolved dependency edges",
        ),
        (
            "CREATE INDEX IF NOT EXISTS idx_queue_dependencies_slice \
             ON queue_dependencies(dep_target, dep_rustc_version, task_id)",
            "index edges by published slice",
        ),
        (
            "CREATE INDEX IF NOT EXISTS idx_queue_dependencies_dep_match \
             ON queue_dependencies(dep_target, dep_rustc_version, dep_crate_name, dep_version)",
            "index edges by dep identity",
        ),
    ] {
        db.query(statement)
            .execute()
            .await
            .map_err(|e| format!("{error}: {e}"))?;
    }
    Ok(())
}

/// Edges written before the columns carried no required-shape set:
/// recompute each one's mask from its owner task's identity — the
/// same values the enqueue's dependency resync writes.
/// `dep_invocations = 0` marks an unbackfilled edge (every mask
/// `dep_edge_requirements` produces is non-zero), so the backfill
/// stands on the rows themselves rather than on which ALTERs just
/// ran: a retry after a migration that committed the column adds but
/// failed mid-backfill heals here instead of gating dependents on a
/// permanently-zero mask.
async fn backfill_dev_era_edge_masks(db: &DurableDb) -> Result<(), QueueError> {
    let edges = db
        .query(
            "SELECT d.task_id, d.depends_on_task_id, \
                    q.target AS owner_target, q.host_side AS owner_host_side, \
                    d.dep_target, d.dep_host_side \
             FROM queue_dependencies d \
             LEFT JOIN queue q ON q.task_id = d.task_id \
             WHERE d.dep_invocations = 0",
        )
        .fetch_all::<UnmaskedEdge>()
        .await
        .map_err(|error| format!("load unmasked dependency edges: {error}"))?;
    for edge in edges {
        // An edge whose owner row is gone takes the requirement
        // for a masked-off owner — moot on a task that no longer
        // exists.
        let (mask, shapes) = dep_edge_requirements(
            edge.owner_target.as_deref().unwrap_or(""),
            edge.owner_host_side.unwrap_or(0) != 0,
            edge.dep_target.as_str(),
            edge.dep_host_side != 0,
        );
        db.query(
            "UPDATE queue_dependencies \
             SET dep_invocations = ?, dep_shapes = ? \
             WHERE task_id = ? AND depends_on_task_id = ?",
        )
        .bind(mask)
        .bind(shapes)
        .bind(edge.task_id)
        .bind(edge.depends_on_task_id)
        .execute()
        .await
        .map_err(|error| format!("backfill dependency edge shape mask: {error}"))?;
    }
    Ok(())
}

/// Edges written before the side model carry `dep_host_side = 0` — the
/// wire could not name a side, so the required side is derived from the
/// only honest signal left: where the dep's task minted relative to the
/// owner's target and the family's host triple. `dep_side_known` runs
/// the derivation exactly once — resolver-written edges carry 1.
async fn derive_dev_era_edge_sides(db: &DurableDb) -> Result<(), QueueError> {
    let side_edges = db
        .query(
            "SELECT d.task_id, d.depends_on_task_id, \
                    q.target AS owner_target, q.host_side AS owner_host_side, \
                    d.dep_target, d.dep_host_side \
             FROM queue_dependencies d \
             LEFT JOIN queue q ON q.task_id = d.task_id \
             WHERE d.dep_side_known = 0",
        )
        .fetch_all::<UnmaskedEdge>()
        .await
        .map_err(|error| format!("load unestablished dependency edges: {error}"))?;
    for edge in side_edges {
        let owner_target = edge.owner_target.as_deref().unwrap_or("");
        let owner_host_side = edge.owner_host_side.unwrap_or(0) != 0;
        let side = derive_edge_side(owner_target, owner_host_side, &edge.dep_target);
        // The mask is moot on a -1 edge — `p.unit_side = -1` matches no
        // published row — but a non-zero shape count keeps the edge out
        // of the unbackfilled-0 marker class.
        let (mask, shapes) =
            dep_edge_requirements(owner_target, owner_host_side, &edge.dep_target, side > 0);
        db.query(
            "UPDATE queue_dependencies \
             SET dep_host_side = ?, dep_invocations = ?, dep_shapes = ?, dep_side_known = 1 \
             WHERE task_id = ? AND depends_on_task_id = ?",
        )
        .bind(side)
        .bind(mask)
        .bind(shapes)
        .bind(edge.task_id)
        .bind(edge.depends_on_task_id)
        .execute()
        .await
        .map_err(|error| format!("derive dependency edge side: {error}"))?;
    }
    Ok(())
}

/// The required side a pre-side-model edge left derivable: the dep's own
/// target says which task minted it — a host dep mints on the owner
/// family's host triple, a target dep on the owner's target. Where the
/// two coincide nothing in the row distinguishes them, so the edge's
/// side stays unestablished (-1) until the resolver rewrites it.
fn derive_edge_side(owner_target: &str, owner_host_side: bool, dep_target: &str) -> i64 {
    if owner_host_side {
        // A host-side node's whole dependency subtree compiles host-side.
        return 1;
    }
    let host_triple = stow_types::api::runner_family(owner_target)
        .map_or(owner_target, |family| family.host_triple());
    if dep_target == host_triple && dep_target != owner_target {
        // A cross owner's dep on the family host triple can only be a
        // host unit — its target deps mint on its own target.
        1
    } else if dep_target == owner_target && dep_target != host_triple {
        // A dep on the owner's own target off the family host triple
        // can only be a target unit.
        0
    } else {
        // dep_target == owner_target == host_triple is ambiguous — a
        // lib's target dep and a proc-macro's host dep mint alike — and
        // a dep matching neither is a corrupt edge. Either way the side
        // was never established; -1 satisfies no gate clause, so the
        // dependent waits for the resolver to rewrite the edge rather
        // than dispatching on a guess.
        -1
    }
}

/// `host_side` is part of the queue's `UNIQUE` identity — `SQLite` cannot
/// alter a constraint in place, so the table is rebuilt: renamed aside,
/// recreated from schema.sql, copied back with `host_side = 0`, and
/// dropped. Rows keep their target-side identity: `task_id`s and
/// `queue_dependencies` edges are spelled identically at `host_side =
/// 0`, so no dependent or admission needs rewriting.
async fn migrate_queue_host_side(db: &DurableDb) -> Result<(), QueueError> {
    tracing::warn!("migrating scheduler queue: adding host_side to the task identity");
    db.query("ALTER TABLE queue RENAME TO queue_migrated")
        .execute()
        .await
        .map_err(|error| format!("rename queue for host_side migration: {error}"))?;
    db.query(include_str!("schema.sql"))
        .execute()
        .await
        .map_err(|error| format!("recreate queue with host_side: {error}"))?;
    db.query(
        "INSERT INTO queue \
         (task_id, crate_name, version, features_json, target, rustc_version, \
          host_side, downloads, miss_count, request_count, priority, status, \
          error_msg, preserve_lockfile, lane, dispatch_attempts, attempt, \
          not_before, first_requested_at, created_at, updated_at, \
          github_run_id, shape_requeue) \
         SELECT task_id, crate_name, version, features_json, target, rustc_version, \
                0, downloads, miss_count, request_count, priority, status, \
                error_msg, preserve_lockfile, lane, dispatch_attempts, attempt, \
                not_before, first_requested_at, created_at, updated_at, \
                github_run_id, shape_requeue \
         FROM queue_migrated",
    )
    .execute()
    .await
    .map_err(|error| format!("copy queue rows for host_side migration: {error}"))?;
    db.query("DROP TABLE queue_migrated")
        .execute()
        .await
        .map_err(|error| format!("drop migrated queue copy: {error}"))?;
    // The RENAME moved the old table's named indexes and triggers onto
    // `queue_migrated`, so the include above could not create them (the
    // `IF NOT EXISTS` names were still taken) — and the drop just freed
    // those names. One more include builds them on the rebuilt queue;
    // every statement is idempotent, so the second run only adds what is
    // missing. `queue_status_counts` still reads empty afterwards —
    // `migrate_dispatch_gate` rebuilds it from the queue at the end of
    // the pass.
    db.query(include_str!("schema.sql"))
        .execute()
        .await
        .map_err(|error| format!("rebuild queue indexes and triggers: {error}"))?;
    Ok(())
}

/// `unit_side`/`unit_invocation`/`unit_linked` key each row's unit
/// shape — a crate legitimately serves one row per shape its consumers
/// compile — so the table is rebuilt the same way `host_side` rebuilt
/// the queue. Rows copy back with `-1` legs — shapeless: a row reported
/// before the columns existed covers nothing under the gate, so a
/// dependent behind one waits for the slice's next publish rather than
/// releasing on membership alone.
async fn migrate_published_slice_row_shape(db: &DurableDb) -> Result<(), QueueError> {
    let columns = db
        .query("PRAGMA table_info(published_slice_rows)")
        .fetch_all::<QueueTableInfoRow>()
        .await
        .map_err(|error| format!("load published_slice_rows table_info: {error}"))?
        .into_iter()
        .map(|row| row.name)
        .collect::<BTreeSet<_>>();
    if columns.is_empty() || columns.contains("unit_side") {
        return Ok(());
    }
    tracing::warn!("migrating scheduler published_slice_rows: adding the unit-shape key");
    db.query("ALTER TABLE published_slice_rows RENAME TO published_slice_rows_migrated")
        .execute()
        .await
        .map_err(|error| format!("rename published_slice_rows for shape migration: {error}"))?;
    db.query(include_str!("schema.sql"))
        .execute()
        .await
        .map_err(|error| format!("recreate published_slice_rows with shape key: {error}"))?;
    db.query(
        "INSERT INTO published_slice_rows \
         (target, rustc_version, generation, crate_name, version, features_json) \
         SELECT target, rustc_version, generation, crate_name, version, features_json \
         FROM published_slice_rows_migrated",
    )
    .execute()
    .await
    .map_err(|error| format!("copy slice rows for shape migration: {error}"))?;
    db.query("DROP TABLE published_slice_rows_migrated")
        .execute()
        .await
        .map_err(|error| format!("drop migrated slice-row copy: {error}"))?;
    Ok(())
}

/// Add `published_slices.applied_generation` — the optimistic token a
/// delta slice report's `base_generation` checks against. Rows that
/// predate it start at 0: the first report for an existing slice comes
/// through the full path (`base_generation = None` on a stale or absent
/// base — the reporter cannot have produced a delta for a generation it
/// never saw), which applies and stamps the counter for the next delta.
async fn migrate_published_slice_columns(db: &DurableDb) -> Result<(), QueueError> {
    let columns = db
        .query("PRAGMA table_info(published_slices)")
        .fetch_all::<QueueTableInfoRow>()
        .await
        .map_err(|error| format!("load published_slices table_info: {error}"))?
        .into_iter()
        .map(|row| row.name)
        .collect::<BTreeSet<_>>();
    if columns.is_empty() || columns.contains("applied_generation") {
        return Ok(());
    }
    db.query(
        "ALTER TABLE published_slices ADD COLUMN applied_generation INTEGER NOT NULL DEFAULT 0",
    )
    .execute()
    .await
    .map_err(|error| format!("add published_slices.applied_generation column: {error}"))?;
    Ok(())
}

async fn migrate_queue_schema(db: &DurableDb) -> Result<(), QueueError> {
    // Legacy rows lack features_json and rustc_version — these are essential
    // identity fields. Instead of backfilling with bogus data ('[]' / ''),
    // drop the table and recreate it from the canonical schema. Dropped
    // tasks are re-enqueued with correct identity on the next cache miss.
    tracing::warn!(
        "migrating scheduler queue schema — legacy rows without identity fields will be dropped"
    );
    db.query("DROP TABLE queue")
        .execute()
        .await
        .map_err(|error| format!("drop legacy scheduler queue: {error}"))?;
    db.query(include_str!("schema.sql"))
        .execute()
        .await
        .map_err(|error| format!("recreate scheduler schema after migration: {error}"))?;
    Ok(())
}

async fn recover_stale_active_tasks(
    db: &DurableDb,
    settings: &SchedulerSettings,
) -> Result<(), QueueError> {
    db.query(
        "DELETE FROM pending_run_completions WHERE task_id IN ( \
             SELECT task_id FROM queue \
             WHERE status IN ('dispatched', 'running') \
               AND updated_at <= datetime('now', ?) \
         )",
    )
    .bind(format!("-{} minutes", settings.stale_dispatch_minutes))
    .execute()
    .await
    .map_err(|error| format!("discard stale pending completions: {error}"))?;
    // Rows re-enter `pending`: `deps_met` re-derives from the live
    // counter, and `blocked` — maintained for pending rows only — may
    // be stale on a stale in-flight row; both recompute in the same
    // statement. `not_before` is untouched, so `wake_at` re-derives
    // from the live columns.
    let recovered = db
        .query(&format!(
            "UPDATE queue \
             SET status = 'pending', error_msg = '', deps_met = {deps_met}, \
                 blocked = {blocked}, wake_at = {wake}, \
                 updated_at = datetime('now') \
             WHERE status IN ('dispatched', 'running') \
               AND updated_at <= datetime('now', ?) \
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
        .bind(format!("-{} minutes", settings.stale_dispatch_minutes))
        .fetch_scalars::<String>()
        .await
        .map_err(|error| format!("recover stale active tasks: {error}"))?;
    if !recovered.is_empty() {
        // Re-entered `pending` rows carry the rank written before the
        // last cost move; re-price exactly the transitioned ids.
        refresh_dispatch_keys(db, &recovered).await?;
    }
    Ok(())
}

/// A `completed` dependency is not done until its published slice rows
/// cover every unit shape a dependent's edge requires — and rows
/// registered before the unit-shape columns existed carry `-1` legs that
/// satisfy no clause, so a dep published pre-upgrade would gate its
/// dependents forever. `completed` here means "reported done without
/// covering": re-queue the row once, behind the same backoff the
/// failed-dependency requeue applies, and let the rebuild republish real
/// shapes; `shape_requeue` latches the repair so it runs at most once.
/// Edges whose dep identity never resolved (`dep_crate_name = ''`) name
/// no node a republish could satisfy, and an edge whose required side
/// was never established (`dep_host_side = -1`) asks for a side the dep
/// can never publish — both leave nothing to re-queue: the first has no
/// dep, the second is the resolver's rewrite, not the dep's rebuild.
async fn requeue_incomplete_shape_deps(
    db: &DurableDb,
    settings: &SchedulerSettings,
) -> Result<(), QueueError> {
    // Driven from the completed rows not yet repaired — a set the
    // `idx_queue_shape_requeue` partial index makes ~0 entries — with
    // the per-candidate dependent probe answered through
    // `idx_queue_dependencies_dep`. The reverse direction the old
    // statement took (every edge's slice check per claim) read the
    // whole edge table. The candidate set is an `IN` subquery pinned
    // `INDEXED BY` the partial index: left as a flat `status =
    // 'completed'` predicate, the planner prefers the plain status index
    // and walks every completed row each pass.
    // Rows re-enter `pending`: `deps_met` re-derives from the live
    // counter, and `blocked` — maintained for pending rows only — is
    // stale on a completed row; both recompute in the same statement,
    // alongside the `not_before` bump's `wake_at`.
    let next_not_before = "MAX(not_before, datetime('now', '+' || MIN(1 << MIN(dispatch_attempts, 6), 60) || ' minutes'))";
    let requeued = db
        .query(&format!(
            "UPDATE queue \
             SET status = 'pending', \
                 attempt = attempt + 1, \
             error_msg = '', \
             request_count = request_count + 1, \
             deps_met = {deps_met}, \
             blocked = {blocked}, \
             not_before = {next_not_before}, \
             wake_at = {wake}, \
             updated_at = datetime('now'), \
             shape_requeue = 1 \
         WHERE task_id IN ( \
             SELECT c.task_id FROM queue c INDEXED BY idx_queue_shape_requeue \
             WHERE c.status = 'completed' AND c.shape_requeue = 0) \
           AND EXISTS ( \
               SELECT 1 FROM queue_dependencies d \
               WHERE d.depends_on_task_id = queue.task_id \
                 AND d.dep_crate_name != '' AND d.dep_host_side >= 0 \
                 AND d.dep_met = 0 \
           ) \
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

/// Active (dispatched/running) queue rows counted by runner family: one
/// `GROUP BY target` pass, with the target→family mapping applied in Rust
/// because the map lives in `stow_types::api::runner_family`, not SQL.
struct ActiveByFamily {
    total: u32,
    by_family: std::collections::HashMap<RunnerFamily, u32>,
}

impl ActiveByFamily {
    /// Active rows building on `family`'s runner pool.
    fn of(&self, family: RunnerFamily) -> u32 {
        self.by_family.get(&family).copied().unwrap_or(0)
    }
}

async fn count_active_by_family(db: &DurableDb) -> Result<ActiveByFamily, QueueError> {
    let rows = db
        .query(
            "SELECT target, count(*) AS count FROM queue \
             WHERE status IN ('dispatched', 'running') GROUP BY target",
        )
        .fetch_all::<TargetCountRow>()
        .await
        .map_err(|error| format!("count active tasks by target: {error}"))?;
    let mut by_family = std::collections::HashMap::new();
    let mut total = 0_u32;
    for row in rows {
        // Enqueue only admits CI targets, so an active row whose target
        // maps to no runner family means the queue state is corrupt.
        let family = runner_family(&row.target).ok_or_else(|| {
            QueueError::Invariant(format!(
                "active task targets `{}`, which maps to no runner family",
                row.target
            ))
        })?;
        let count = u64_to_u32(row.count, "active task count")?;
        *by_family.entry(family).or_insert(0) += count;
        total += count;
    }
    Ok(ActiveByFamily { total, by_family })
}

fn dispatch_cutoff_modifier(dispatch_min_age_minutes: u32) -> String {
    format!("-{dispatch_min_age_minutes} minutes")
}

fn u64_to_i64(value: u64, field: &'static str) -> Result<i64, QueueError> {
    i64::try_from(value).map_err(|_| QueueError::Overflow { field, value })
}

fn u64_to_u32(value: u64, field: &'static str) -> Result<u32, QueueError> {
    u32::try_from(value).map_err(|_| QueueError::Overflow { field, value })
}

#[derive(Debug, skyzen::FromRow)]
struct TaskIdRow {
    task_id: String,
    status: String,
}

/// One `queue_dependencies` row reduced to a [`QueuedTask`]'s dep pin.
#[derive(Debug, skyzen::FromRow)]
struct DepPinRow {
    task_id: String,
    dep_crate_name: String,
    dep_version: String,
    dep_features_json: String,
    dep_host_side: i64,
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
    preserve_lockfile: i64,
    dispatch_key: String,
}

#[derive(Debug, skyzen::FromRow)]
struct ClaimGenerationRow {
    generation_id: String,
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

#[derive(Debug, skyzen::FromRow)]
struct PendingCompletionRow {
    github_run_id: String,
    task_id: String,
    success: i64,
    error: Option<String>,
    received_at: String,
}

#[derive(Debug, skyzen::FromRow)]
struct BoundPendingCompletionRow {
    #[row(rename = "task_id")]
    task: String,
    #[row(rename = "generation_id")]
    generation: String,
    #[row(rename = "github_run_id")]
    run: String,
}

/// One `PRAGMA table_info` row — only the column name matters.
#[derive(Debug, skyzen::FromRow)]
struct QueueTableInfoRow {
    name: String,
}

/// One `GROUP BY target` count over active rows.
#[derive(Debug, skyzen::FromRow)]
struct TargetCountRow {
    target: String,
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
        normalize_gate_rows, normalized_gate_json, plan_alarm, seconds_until_utc_midnight,
    };
    const NOW_MS: i64 = 1_000_000;

    fn inputs() -> AlarmInputs {
        AlarmInputs {
            now_ms: NOW_MS,
            capacity: DispatchCapacity::Available,
            earliest_pending_eligible_ms: None,
            earliest_active_lease_expiry_ms: None,
        }
    }

    #[test]
    fn normalizes_gate_shapes_by_identity_direction_and_eligibility() {
        let row = |unit_side, unit_invocation, unit_linked| SliceRowJson {
            rowid: 0,
            crate_name: "crate".to_owned(),
            version: "1.0.0".to_owned(),
            features_json: "[]".to_owned(),
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
            (row(-1, 0, 1), Some(SliceChangeKind::Added)),
            (row(0, -1, 1), Some(SliceChangeKind::Added)),
        ];
        let normalized = normalize_gate_rows(added);
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

        let retired = normalize_gate_rows([(row(0, 0, 1), Some(SliceChangeKind::Retired))]);
        assert_eq!(
            retired
                .iter()
                .map(|row| (row.unit_side, row.invocations, row.kind))
                .collect::<Vec<_>>(),
            vec![(0, 1, Some(SliceChangeKind::Retired))]
        );

        let full = normalize_gate_rows([(row(0, 0, 0), None), (row(0, 1, 1), None)]);
        assert_eq!(
            full.iter()
                .map(|row| (row.unit_side, row.invocations, row.kind))
                .collect::<Vec<_>>(),
            vec![(0, 3, None)]
        );
        assert_eq!(
            normalized_gate_json([(row(-1, -1, -1), None)]).expect("normalize legacy rows"),
            None
        );
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
            earliest_active_lease_expiry_ms: Some(NOW_MS + 300_000),
            ..inputs()
        };
        assert_eq!(plan_alarm(&inputs), AlarmPlan::At(NOW_MS + 300_000));
    }

    #[test]
    fn clamps_past_lease_expiry_to_now_when_capacity_exhausted() {
        let inputs = AlarmInputs {
            capacity: DispatchCapacity::Exhausted,
            earliest_pending_eligible_ms: Some(NOW_MS - 60_000),
            earliest_active_lease_expiry_ms: Some(NOW_MS - 1),
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
            earliest_active_lease_expiry_ms: Some(NOW_MS + 300_000),
            ..inputs()
        };
        assert_eq!(plan_alarm(&inputs), AlarmPlan::At(NOW_MS + 300_000));
    }

    #[test]
    fn paused_clamps_past_lease_expiry_to_now() {
        let inputs = AlarmInputs {
            capacity: DispatchCapacity::Paused,
            earliest_active_lease_expiry_ms: Some(NOW_MS - 1),
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
            earliest_active_lease_expiry_ms: Some(NOW_MS + 120_000),
            ..inputs()
        };
        assert_eq!(plan_alarm(&inputs), AlarmPlan::At(NOW_MS + 120_000));
    }

    #[test]
    fn clamps_past_lease_expiry_to_now_without_pending_rows() {
        let inputs = AlarmInputs {
            earliest_active_lease_expiry_ms: Some(NOW_MS - 1),
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
            earliest_active_lease_expiry_ms: None,
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
mod sqlite_tests {
    use std::collections::BTreeSet;
    use std::future::Future;

    use stow_types::api::{EnqueueDependency, EnqueueRequest, EnqueueSource};
    use stow_types::identity::FeaturesJson;

    use super::{
        AlarmPlan, CoverageOracle, Dispatch, SchedulerSettings, SemanticTaskIdentity, next_alarm,
        task_id,
    };
    use crate::errors::QueueError;
    use crate::scheduler::test_db::{StatementLog, counting_memory_db, memory_db, memory_db_raw};
    use skyzen_services::durable::DurableDb;
    use stow_types::public_cache::{UnitInvocation, UnitKind, UnitShape, UnitSide};

    const fn shape(side: UnitSide, invocation: UnitInvocation, kind: UnitKind) -> UnitShape {
        UnitShape {
            side,
            invocation,
            kind,
        }
    }

    /// Fixed column timestamp used for exact lease/eligibility assertions:
    /// `2026-01-01 00:00:00` UTC in both the text form the `datetime()`
    /// columns store and the epoch-ms form `now_ms`/`AlarmPlan::At` use.
    const ROW_TS: &str = "2026-01-01 00:00:00";
    const ROW_TS_MS: i64 = 1_767_225_600_000;
    /// `2025-12-31 23:00:00` — strictly before `ROW_TS`, for an eligibility
    /// that is already in the past.
    const PAST_TS: &str = "2025-12-31 23:00:00";

    const VERSION: &str = "1.0.0";
    const FEATURES: &str = "[]";
    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const MACOS_TARGET: &str = "aarch64-apple-darwin";
    const WINDOWS_TARGET: &str = "x86_64-pc-windows-msvc";
    const RUSTC: &str = "1.85.0";

    /// The freeze window tests complete outcomes under — matches the
    /// `STOW_FREEZE_WINDOW_MINUTES` default.
    const TEST_WINDOW_MINUTES: u32 = 60;

    const STALE_DISPATCH_MINUTES: u32 = 60;

    async fn assert_parent_status(db: &DurableDb, expected: stow_types::api::QueueTaskStatus) {
        assert_eq!(
            super::task_status(db, &task_id_on("parent", TARGET))
                .await
                .expect("read parent status")
                .expect("parent row")
                .status,
            expected
        );
    }

    fn stale_ms() -> i64 {
        i64::from(STALE_DISPATCH_MINUTES) * 60_000
    }

    const fn settings() -> SchedulerSettings {
        SchedulerSettings {
            dispatch: Dispatch::from_max_concurrent_jobs(10),
            max_concurrent_macos_jobs: 16,
            dispatch_min_age_minutes: 5,
            stale_dispatch_minutes: STALE_DISPATCH_MINUTES,
            max_queue_pending: 2_000,
            human_daily_task_budget: 2_000,
            min_dispatch_value: 0,
        }
    }

    const fn paused_settings() -> SchedulerSettings {
        SchedulerSettings {
            dispatch: Dispatch::Paused,
            ..settings()
        }
    }

    /// `super::enqueue` with the test settings, so existing call sites keep
    /// their `(db, requests)` shape; cap tests call `super::enqueue` and
    /// `super::enqueue_trusted` directly.
    async fn enqueue(db: &DurableDb, requests: &[EnqueueRequest]) -> Result<u32, QueueError> {
        super::enqueue(db, requests, &settings()).await
    }

    #[derive(skyzen::FromRow)]
    struct PairEdgeFlag {
        dep_crate_name: String,
        dep_met: i64,
    }

    async fn assert_pair_flags_after_publication(db: &DurableDb) {
        let pair_flags = db
            .query(
                "SELECT dep_crate_name, dep_met FROM queue_dependencies \
                 WHERE task_id = ? ORDER BY dep_crate_name",
            )
            .bind(task_id_on("pair", TARGET))
            .fetch_all::<PairEdgeFlag>()
            .await
            .expect("read pair edge flags after publication")
            .into_iter()
            .map(|edge| (edge.dep_crate_name, edge.dep_met))
            .collect::<Vec<_>>();
        assert_eq!(
            pair_flags,
            vec![("dep-fpub".to_owned(), 1), ("dep-short".to_owned(), 0)],
            "real publication initializes the fabricated pair edges"
        );
    }

    /// An artifact catalog that covers nothing: every claim goes to a
    /// build, as before claim-time retirement existed.
    struct NoCoverage;

    impl CoverageOracle for NoCoverage {
        fn covered(
            &self,
            _identities: &[SemanticTaskIdentity],
        ) -> impl Future<Output = Result<BTreeSet<SemanticTaskIdentity>, QueueError>> + Send
        {
            std::future::ready(Ok(BTreeSet::new()))
        }
    }

    /// An artifact catalog that covers exactly the identities it was
    /// built with, and records what it was asked about.
    struct FixedCoverage {
        covered: BTreeSet<SemanticTaskIdentity>,
        asked: std::sync::Mutex<Vec<SemanticTaskIdentity>>,
    }

    impl CoverageOracle for FixedCoverage {
        fn covered(
            &self,
            identities: &[SemanticTaskIdentity],
        ) -> impl Future<Output = Result<BTreeSet<SemanticTaskIdentity>, QueueError>> + Send
        {
            self.asked
                .lock()
                .expect("oracle log")
                .extend_from_slice(identities);
            std::future::ready(Ok(identities
                .iter()
                .filter(|identity| self.covered.contains(identity))
                .cloned()
                .collect()))
        }
    }

    fn semantic_identity(crate_name: &str) -> SemanticTaskIdentity {
        SemanticTaskIdentity {
            crate_name: crate_name.to_owned(),
            version: VERSION.to_owned(),
            features_json: FEATURES.to_owned(),
            target: TARGET.to_owned(),
            rustc_version: RUSTC.to_owned(),
            host_side: false,
        }
    }

    fn request(crate_name: &str, depends_on: Vec<EnqueueDependency>) -> EnqueueRequest {
        request_on(crate_name, TARGET, depends_on)
    }

    fn request_on(
        crate_name: &str,
        target: &str,
        depends_on: Vec<EnqueueDependency>,
    ) -> EnqueueRequest {
        EnqueueRequest {
            crate_name: crate_name.parse().expect("valid crate name"),
            version: VERSION.parse().expect("valid semver"),
            features_json: FeaturesJson::default(),
            target: target.parse().expect("valid target triple"),
            rustc_version: RUSTC.parse().expect("valid rustc version"),
            downloads: 0,
            source: EnqueueSource::CacheMiss,
            depends_on,
            preserve_lockfile: false,
            host_side: false,
        }
    }

    fn task_id_on(crate_name: &str, target: &str) -> String {
        task_id(crate_name, VERSION, FEATURES, target, RUSTC, false)
    }

    fn dependency(crate_name: &str) -> EnqueueDependency {
        EnqueueDependency {
            crate_name: crate_name.parse().expect("valid crate name"),
            version: VERSION.parse().expect("valid semver"),
            features_json: FeaturesJson::default(),
            target: TARGET.parse().expect("valid target triple"),
            rustc_version: RUSTC.parse().expect("valid rustc version"),
            host_side: false,
        }
    }

    /// Force a row into an in-flight status with a deterministic `updated_at`
    /// — a state no public queue function produces (claim always stamps
    /// `datetime('now')`), so one raw UPDATE is required.
    async fn mark_active(db: &DurableDb, crate_name: &str, target: &str, status: &str) {
        db.query("UPDATE queue SET status = ?, updated_at = ? WHERE task_id = ?")
            .bind(status.to_owned())
            .bind(ROW_TS.to_owned())
            .bind(task_id_on(crate_name, target))
            .execute()
            .await
            .expect("mark task active");
    }

    /// `enqueue` always stamps `first_requested_at = datetime('now')`; tests
    /// that assert exact eligibility timestamps need a deterministic value.
    async fn set_first_requested_at(db: &DurableDb, crate_name: &str, timestamp: &str) {
        set_first_requested_at_on(
            db,
            crate_name,
            TARGET,
            timestamp,
            settings().dispatch_min_age_minutes,
        )
        .await;
    }

    async fn set_first_requested_at_on(
        db: &DurableDb,
        crate_name: &str,
        target: &str,
        timestamp: &str,
        min_age_minutes: u32,
    ) {
        // `first_requested_at` is part of the persisted claim-order
        // tuple and of `wake_at`, so a direct column rewrite refreshes
        // both through the same row expressions production updates use.
        // Two statements: SET expressions read the pre-update row, so
        // the recomputes must run after the column write lands.
        db.query("UPDATE queue SET first_requested_at = ? WHERE task_id = ?")
            .bind(timestamp.to_owned())
            .bind(task_id_on(crate_name, target))
            .execute()
            .await
            .expect("set first_requested_at");
        db.query(&format!(
            "UPDATE queue SET wake_at = {} WHERE task_id = ?",
            super::wake_at_sql("lane", "first_requested_at", "not_before", min_age_minutes),
        ))
        .bind(task_id_on(crate_name, target))
        .execute()
        .await
        .expect("recompute wake_at");
        super::refresh_dispatch_keys(db, &[task_id_on(crate_name, target)])
            .await
            .expect("refresh dispatch_key");
    }

    #[tokio::test]
    async fn active_only_wakes_at_lease_expiry() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("alpha", Vec::new())])
            .await
            .expect("enqueue");
        mark_active(&db, "alpha", TARGET, "running").await;

        let plan = next_alarm(&db, ROW_TS_MS, &settings())
            .await
            .expect("next_alarm");
        // Lease = updated_at (2026-01-01 00:00:00) + stale_dispatch_minutes
        // (60) = 01:00:00. A `+`/`-` flip in the lease query's datetime
        // modifier moves this off the asserted value.
        assert_eq!(plan, AlarmPlan::At(ROW_TS_MS + stale_ms()));
    }

    #[tokio::test]
    async fn pending_blocked_by_active_dependency_wakes_at_lease_expiry() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("dep", Vec::new())])
            .await
            .expect("enqueue dep");
        enqueue(&db, &[request("parent", vec![dependency("dep")])])
            .await
            .expect("enqueue parent");
        mark_active(&db, "dep", TARGET, "dispatched").await;

        let plan = next_alarm(&db, ROW_TS_MS, &settings())
            .await
            .expect("next_alarm");
        // The pending row must be filtered out by the dependency gate:
        // "dep" is dispatched, never published, so it is absent from the
        // slice the gate checks and the parent stays ineligible.
        assert_eq!(plan, AlarmPlan::At(ROW_TS_MS + stale_ms()));
    }

    #[tokio::test]
    async fn exhausted_capacity_with_eligible_pending_wakes_at_lease_expiry() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[request("busy", Vec::new()), request("waiting", Vec::new())],
        )
        .await
        .expect("enqueue");
        mark_active(&db, "busy", TARGET, "dispatched").await;
        set_first_requested_at(&db, "waiting", PAST_TS).await;

        let settings = SchedulerSettings {
            dispatch: Dispatch::from_max_concurrent_jobs(1),
            dispatch_min_age_minutes: 0,
            ..settings()
        };
        let plan = next_alarm(&db, ROW_TS_MS, &settings)
            .await
            .expect("next_alarm");
        // The pending row is already eligible, but the only slot is taken:
        // waking at `now` would spin the object in a zero-delay alarm loop.
        assert_eq!(plan, AlarmPlan::At(ROW_TS_MS + stale_ms()));
    }

    /// stow#444: a submit whose every row sits behind an unmet edge —
    /// here a single task gated on a dep nobody has built — must leave
    /// `schedule_alarm` with nothing to arm: `next_alarm` answers
    /// `Delete`, so the request pays no wake for work it cannot run.
    #[tokio::test]
    async fn fully_gated_submit_arms_no_alarm() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("parent", vec![dependency("dep-missing")])])
            .await
            .expect("enqueue gated submit");

        let plan = next_alarm(&db, ROW_TS_MS, &settings())
            .await
            .expect("next_alarm");
        assert_eq!(plan, AlarmPlan::Delete);
    }

    /// stow#444: a submit that does leave dispatchable work arms the
    /// pass immediately — `next_alarm` answers `At(now)` for a row
    /// already past its wake instant, exactly the wake `setAlarm(now)`
    /// used to issue unconditionally.
    #[tokio::test]
    async fn dispatchable_submit_arms_at_now() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("ready", Vec::new())])
            .await
            .expect("enqueue ready");
        set_first_requested_at(&db, "ready", PAST_TS).await;

        let plan = next_alarm(&db, ROW_TS_MS, &settings())
            .await
            .expect("next_alarm");
        assert_eq!(plan, AlarmPlan::At(ROW_TS_MS));
    }

    /// A paused scheduler keeps accepting submits but never plans a wake
    /// for them: with nothing in flight the alarm is deleted, so the
    /// queue waits out the pause instead of spinning on eligibility.
    #[tokio::test]
    async fn paused_with_nothing_in_flight_deletes_alarm() {
        let db = memory_db().await.expect("memory db");
        super::enqueue(&db, &[request("waiting", Vec::new())], &paused_settings())
            .await
            .expect("enqueue");
        set_first_requested_at(&db, "waiting", PAST_TS).await;

        let plan = next_alarm(&db, ROW_TS_MS, &paused_settings())
            .await
            .expect("next_alarm");
        // The pending row is already eligible — under a live limit this
        // is `At(now)` — but paused means nothing to wake for.
        assert_eq!(plan, AlarmPlan::Delete);
    }

    /// With a build already in flight when dispatch pauses, the alarm
    /// still wakes at its lease expiry so stale recovery can reclaim it.
    #[tokio::test]
    async fn paused_with_in_flight_row_wakes_at_lease_expiry() {
        let db = memory_db().await.expect("memory db");
        super::enqueue(
            &db,
            &[request("busy", Vec::new()), request("waiting", Vec::new())],
            &paused_settings(),
        )
        .await
        .expect("enqueue");
        mark_active(&db, "busy", TARGET, "dispatched").await;
        set_first_requested_at(&db, "waiting", PAST_TS).await;

        let plan = next_alarm(&db, ROW_TS_MS, &paused_settings())
            .await
            .expect("next_alarm");
        assert_eq!(plan, AlarmPlan::At(ROW_TS_MS + stale_ms()));
    }

    /// Submits enqueue normally while paused, and the claim pass returns
    /// nothing — the queue fills until the unpause deploy.
    #[tokio::test]
    async fn submit_while_paused_enqueues_but_claims_nothing() {
        let db = memory_db().await.expect("memory db");
        let inserted = super::enqueue(&db, &[request("waiting", Vec::new())], &paused_settings())
            .await
            .expect("enqueue while paused");
        assert_eq!(inserted, 1);

        let claimed = super::claim_dispatchable_tasks(&db, &paused_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert!(claimed.is_empty());
        assert_eq!(super::status(&db).await.expect("status").pending, 1);
    }

    /// An in-flight row past its lease is still reclaimed to `pending`
    /// while paused: the claim pass recovers stale work before the pause
    /// check turns it away.
    #[tokio::test]
    async fn paused_claim_still_recovers_stale_in_flight_row() {
        let db = memory_db().await.expect("memory db");
        super::enqueue(&db, &[request("busy", Vec::new())], &paused_settings())
            .await
            .expect("enqueue");
        mark_active(&db, "busy", TARGET, "dispatched").await;

        let claimed = super::claim_dispatchable_tasks(&db, &paused_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert!(claimed.is_empty());
        let status = db
            .query("SELECT status FROM queue WHERE task_id = ?")
            .bind(task_id_on("busy", TARGET))
            .fetch_scalar::<String>()
            .await
            .expect("status");
        assert_eq!(status, "pending");
    }

    #[tokio::test]
    async fn eligible_pending_with_capacity_wakes_at_eligibility() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("ready", Vec::new())])
            .await
            .expect("enqueue");
        set_first_requested_at_on(&db, "ready", TARGET, ROW_TS, 30).await;

        let settings = SchedulerSettings {
            dispatch_min_age_minutes: 30,
            ..settings()
        };
        let plan = next_alarm(&db, ROW_TS_MS, &settings)
            .await
            .expect("next_alarm");
        // Eligibility = first_requested_at + dispatch_min_age = 00:30:00.
        assert_eq!(plan, AlarmPlan::At(ROW_TS_MS + 30 * 60_000));
    }

    #[tokio::test]
    async fn overdue_pending_with_capacity_wakes_now() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("ready", Vec::new())])
            .await
            .expect("enqueue");
        set_first_requested_at(&db, "ready", PAST_TS).await;

        let settings = SchedulerSettings {
            dispatch_min_age_minutes: 0,
            ..settings()
        };
        let plan = next_alarm(&db, ROW_TS_MS, &settings)
            .await
            .expect("next_alarm");
        assert_eq!(plan, AlarmPlan::At(ROW_TS_MS));
    }

    fn request_with_downloads(crate_name: &str, downloads: u64) -> EnqueueRequest {
        EnqueueRequest {
            downloads,
            ..request(crate_name, Vec::new())
        }
    }

    const fn claim_settings() -> SchedulerSettings {
        SchedulerSettings {
            dispatch: Dispatch::from_max_concurrent_jobs(1),
            dispatch_min_age_minutes: 0,
            ..settings()
        }
    }

    /// Overwrite the cached token's `expires_at` with a `datetime()`
    /// modifier evaluated by `SQLite` itself — the value under test is
    /// stored in the RFC 3339 shape GitHub's API returns.
    async fn set_cached_expiry(db: &DurableDb, modifier: &str) {
        db.query("UPDATE github_app_token SET expires_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?) WHERE id = 1")
            .bind(modifier.to_owned())
            .execute()
            .await
            .expect("set cached token expiry");
    }

    fn token() -> crate::github_app::InstallationToken {
        crate::github_app::InstallationToken {
            token: "ghs_test".to_owned(),
            expires_at: "2099-01-01T00:00:00Z".to_owned(),
        }
    }

    #[tokio::test]
    async fn repeated_requests_do_not_overtake_older_pending_tasks() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("old", Vec::new())])
            .await
            .expect("enqueue old");
        enqueue(&db, &[request("spam", Vec::new())])
            .await
            .expect("enqueue spam");
        set_first_requested_at(&db, "old", PAST_TS).await;
        // Hammer the newer task: under the removed request_count ordering it
        // would outrank the older row; under first-seen FIFO it cannot.
        for _ in 0..20 {
            enqueue(&db, &[request("spam", Vec::new())])
                .await
                .expect("re-request spam");
        }

        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "old");
    }

    /// stow#442 I6: `value` orders before FIFO, and the baseline value
    /// carries the download/miss priority — a popular newer row now
    /// outranks a less popular older one at equal lane and family.
    #[tokio::test]
    async fn higher_priority_value_claims_before_older_first_seen() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("old", Vec::new())])
            .await
            .expect("enqueue old");
        enqueue(&db, &[request_with_downloads("popular", 10_000)])
            .await
            .expect("enqueue popular");
        set_first_requested_at(&db, "old", PAST_TS).await;

        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "popular");
    }

    /// FIFO is the tie-breaker at equal value: two same-lane,
    /// same-priority rows dispatch oldest-first (stow#442 I6).
    #[tokio::test]
    async fn equal_value_claims_in_first_seen_order() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("young", Vec::new())])
            .await
            .expect("enqueue young");
        enqueue(&db, &[request("old", Vec::new())])
            .await
            .expect("enqueue old");
        set_first_requested_at(&db, "old", PAST_TS).await;

        let settings = SchedulerSettings {
            dispatch_min_age_minutes: 0,
            ..settings()
        };
        let claimed = super::claim_dispatchable_tasks(&db, &settings, &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 2);
        assert_eq!(claimed[0].crate_name, "old");
        assert_eq!(claimed[1].crate_name, "young");
    }

    /// The bands cover every lane/family combination: human rows always
    /// outrank miss rows, and inside a lane a Windows row outranks a
    /// non-Windows row — the same precedence today's CASE-encoded key
    /// produced, arrived at regardless of request order or priority
    /// (stow#442 I6).
    #[tokio::test]
    async fn value_bands_preserve_lane_then_family_precedence() {
        let db = memory_db().await.expect("memory db");
        // Worst case for the bands: the miss/Windows row is the oldest
        // and carries the largest admissible downloads; band order must
        // still dominate.
        let mut miss_win = request_on("miss-win", WINDOWS_TARGET, Vec::new());
        miss_win.downloads = i64::MAX as u64;
        enqueue(&db, &[miss_win]).await.expect("enqueue miss-win");
        enqueue(&db, &[request("miss-lin", Vec::new())])
            .await
            .expect("enqueue miss-lin");
        enqueue(
            &db,
            &[
                EnqueueRequest {
                    source: EnqueueSource::HumanRequest,
                    ..request_on("human-lin", TARGET, Vec::new())
                },
                EnqueueRequest {
                    source: EnqueueSource::HumanRequest,
                    ..request_on("human-win", WINDOWS_TARGET, Vec::new())
                },
            ],
        )
        .await
        .expect("enqueue human");
        set_first_requested_at_on(
            &db,
            "miss-win",
            WINDOWS_TARGET,
            PAST_TS,
            settings().dispatch_min_age_minutes,
        )
        .await;

        let settings = SchedulerSettings {
            dispatch_min_age_minutes: 0,
            ..settings()
        };
        let claimed = super::claim_dispatchable_tasks(&db, &settings, &NoCoverage)
            .await
            .expect("claim");
        let order = claimed
            .iter()
            .map(|task| task.crate_name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(order, ["human-win", "human-lin", "miss-win", "miss-lin"]);
    }

    /// The band arithmetic never overflows: a human Windows row at
    /// `PRIORITY_MAX` takes the largest possible value,
    /// `3 * VALUE_BAND + PRIORITY_MAX` — still inside `i64` — and
    /// still dispatches first (stow#442 I6).
    #[tokio::test]
    async fn value_extremes_stay_within_i64_and_order() {
        #[derive(skyzen::FromRow)]
        struct ValueRow {
            value: String,
            key: String,
            first_requested_at: String,
            created_at: String,
        }
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                EnqueueRequest {
                    source: EnqueueSource::HumanRequest,
                    ..request_on("max", WINDOWS_TARGET, Vec::new())
                },
                request("min", Vec::new()),
            ],
        )
        .await
        .expect("enqueue");
        db.query("UPDATE queue SET priority = CAST(? AS INTEGER) WHERE task_id = ?")
            .bind(super::PRIORITY_MAX.to_string())
            .bind(task_id_on("max", WINDOWS_TARGET))
            .execute()
            .await
            .expect("set priority bound");
        super::refresh_dispatch_keys(&db, &[task_id_on("max", WINDOWS_TARGET)])
            .await
            .expect("refresh claim order");
        let row = db
            .query(
                "SELECT CAST(value AS TEXT) AS value, dispatch_key AS key, \
                        first_requested_at, created_at \
                 FROM queue WHERE task_id = ?",
            )
            .bind(task_id_on("max", WINDOWS_TARGET))
            .fetch_one::<ValueRow>()
            .await
            .expect("value row");
        assert_eq!(
            row.value.parse::<i64>().expect("integer value"),
            3 * super::VALUE_BAND + super::PRIORITY_MAX,
            "human + windows + PRIORITY_MAX is the largest legal value"
        );
        // The stored key is byte-exact the shared abstraction's output
        // for the same operands — human lane prefix first.
        assert_eq!(
            row.key,
            crate::scheduler::rank::dispatch_key(&crate::scheduler::rank::KeyOperands {
                lane: "human",
                family: "windows",
                priority: super::PRIORITY_MAX,
                demand: 0,
                cost_ms: crate::scheduler::rank::UNMEASURED_COST,
                first_requested_at: &row.first_requested_at,
                created_at: &row.created_at,
                task_id: &task_id_on("max", WINDOWS_TARGET),
            },)
        );
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed[0].crate_name, "max");
    }

    #[derive(skyzen::FromRow)]
    struct KeyOrder {
        crate_name: String,
    }

    /// The claimed rows' crate names, sorted — floor tests compare
    /// sets where the persisted order is separately covered.
    async fn claimed_names(db: &DurableDb, settings: &SchedulerSettings) -> Vec<String> {
        let mut names: Vec<String> = super::claim_dispatchable_tasks(db, settings, &NoCoverage)
            .await
            .expect("claim")
            .iter()
            .map(|task| task.crate_name.as_str().to_owned())
            .collect();
        names.sort();
        names
    }

    /// Write the authoritative floor the writers' eligibility
    /// expression reads — the `settings` row the operator migrate
    /// stamps (stow#525 I10).
    async fn set_floor(db: &DurableDb, floor: i64) {
        db.query(
            "INSERT INTO settings (key, value) VALUES ('min_dispatch_value', ?) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(floor.to_string())
        .execute()
        .await
        .expect("set dispatch floor");
    }

    /// The persisted admission answer on one row.
    async fn flag_of(db: &DurableDb, crate_name: &str) -> i64 {
        db.query("SELECT dispatch_eligible FROM queue WHERE crate_name = ?")
            .bind(crate_name.to_owned())
            .fetch_scalar::<i64>()
            .await
            .expect("dispatch_eligible")
    }

    /// The claim admits only rows whose persisted eligibility the floor
    /// passed: at `floor = VALUE_BAND` a Windows miss (one band) claims
    /// while a zero-value Linux miss stays under, and a floor one over
    /// the band writes `dispatch_eligible = 0` onto every miss row
    /// (stow#525 I10).
    #[tokio::test]
    async fn floor_admits_only_scored_rows() {
        let db = memory_db().await.expect("memory db");
        set_floor(&db, super::VALUE_BAND).await;
        enqueue(
            &db,
            &[
                request("lin", Vec::new()),
                request_on("win", WINDOWS_TARGET, Vec::new()),
            ],
        )
        .await
        .expect("enqueue");
        set_first_requested_at(&db, "lin", PAST_TS).await;
        set_first_requested_at_on(
            &db,
            "win",
            WINDOWS_TARGET,
            PAST_TS,
            settings().dispatch_min_age_minutes,
        )
        .await;
        assert_eq!(claimed_names(&db, &claim_settings()).await, ["win"]);
        assert_eq!(flag_of(&db, "lin").await, 0);
        // `win` is dispatched now; with only the value-0 `lin` left,
        // even a fresh claim page admits nothing.
        assert_eq!(
            claimed_names(&db, &claim_settings()).await,
            Vec::<String>::new()
        );

        // One band over the floor: a second queue floors every
        // miss-lane row, including the Windows band.
        let db = memory_db().await.expect("memory db");
        set_floor(&db, super::VALUE_BAND + 1).await;
        enqueue(
            &db,
            &[
                request("lin", Vec::new()),
                request_on("win", WINDOWS_TARGET, Vec::new()),
            ],
        )
        .await
        .expect("enqueue");
        set_first_requested_at(&db, "lin", PAST_TS).await;
        set_first_requested_at_on(
            &db,
            "win",
            WINDOWS_TARGET,
            PAST_TS,
            settings().dispatch_min_age_minutes,
        )
        .await;
        assert_eq!(flag_of(&db, "win").await, 0);
        assert_eq!(
            claimed_names(&db, &claim_settings()).await,
            Vec::<String>::new()
        );
    }

    /// A human-lane row is exempt from any floor — even `i64::MAX` —
    /// because the flag's lane clause wins before the score compares,
    /// while the miss lane is held entirely below it (stow#525 I10).
    #[tokio::test]
    async fn floor_never_blocks_the_human_lane() {
        let db = memory_db().await.expect("memory db");
        set_floor(&db, i64::MAX).await;
        enqueue(
            &db,
            &[
                EnqueueRequest {
                    source: EnqueueSource::HumanRequest,
                    ..request("human", Vec::new())
                },
                request("miss", Vec::new()),
            ],
        )
        .await
        .expect("enqueue");

        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        let names = claimed
            .iter()
            .map(|task| task.crate_name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["human"], "only the exempt lane clears i64::MAX");
        assert_eq!(flag_of(&db, "miss").await, 0);
    }

    /// Equal scores tie on the persisted tuple exactly as before the
    /// floor existed: admitted rows claim in stored `dispatch_key`
    /// order, and an under-floor row does not stretch or reorder them
    /// (stow#525 I10).
    #[tokio::test]
    async fn floor_preserves_the_tie_order() {
        let db = memory_db().await.expect("memory db");
        // Three Windows misses share one band — the three-way value
        // tie — beside one Linux miss the floor excludes.
        set_floor(&db, super::VALUE_BAND).await;
        enqueue(
            &db,
            &[
                request_on("cee", WINDOWS_TARGET, Vec::new()),
                request_on("aye", WINDOWS_TARGET, Vec::new()),
                request_on("bee", WINDOWS_TARGET, Vec::new()),
                request("lin", Vec::new()),
            ],
        )
        .await
        .expect("enqueue");
        for name in ["cee", "aye", "bee"] {
            set_first_requested_at_on(
                &db,
                name,
                WINDOWS_TARGET,
                PAST_TS,
                settings().dispatch_min_age_minutes,
            )
            .await;
        }

        let expected = db
            .query(
                "SELECT crate_name FROM queue WHERE status = 'pending' \
                 ORDER BY dispatch_key LIMIT 3",
            )
            .fetch_all::<KeyOrder>()
            .await
            .expect("stored key order")
            .into_iter()
            .map(|row| row.crate_name)
            .collect::<Vec<_>>();

        let page = SchedulerSettings {
            dispatch_min_age_minutes: 0,
            ..settings()
        };
        let claimed = super::claim_dispatchable_tasks(&db, &page, &NoCoverage)
            .await
            .expect("claim");
        let names = claimed
            .iter()
            .map(|task| task.crate_name.as_str().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(names, expected, "claims arrive in the stored key order");
        assert_eq!(names.len(), 3, "the Linux miss stays under the floor");
    }

    /// An under-floor row is no wake's reason to arm: the ready probe
    /// and the deferred `MIN(wake_at)` probe both exclude it, so a
    /// queue of only under-floor rows leaves the alarm disarmed instead
    /// of spinning an empty dispatch loop (stow#525 I10).
    #[tokio::test]
    async fn under_floor_rows_never_arm_the_alarm() {
        // Without a floor the row is eligible now — the alarm arms at
        // `now`.
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("low", Vec::new())])
            .await
            .expect("enqueue");
        set_first_requested_at(&db, "low", PAST_TS).await;
        let armed = next_alarm(&db, ROW_TS_MS, &claim_settings())
            .await
            .expect("next_alarm unfloored");
        assert_eq!(armed, AlarmPlan::At(ROW_TS_MS));

        // Under a floor the same row admits nothing and defers
        // nothing: both wake probes exclude it, and no stale lease or
        // requeue arm exists either.
        let db = memory_db().await.expect("memory db");
        set_floor(&db, 1).await;
        enqueue(&db, &[request("low", Vec::new())])
            .await
            .expect("enqueue");
        set_first_requested_at(&db, "low", PAST_TS).await;
        let plan = next_alarm(&db, ROW_TS_MS, &claim_settings())
            .await
            .expect("next_alarm floored");
        assert_eq!(plan, AlarmPlan::Delete);
        assert!(
            super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
                .await
                .expect("claim")
                .is_empty()
        );
    }

    /// A bulk of under-floor rows — immediate and deferred wakes
    /// alike — contributes no candidate to the claim page and arms no
    /// alarm, and the one eligible row that lands among them still
    /// claims: the equality predicate excludes the bulk inside the
    /// index span, never as page entries the walk visits and rejects
    /// (stow#525 I10).
    #[tokio::test]
    async fn under_floor_bulk_arms_no_wake_and_starves_no_page() {
        let db = memory_db().await.expect("memory db");
        set_floor(&db, 1).await;
        let bulk = (0..300)
            .map(|n| request(&format!("under{n}"), Vec::new()))
            .collect::<Vec<_>>();
        enqueue(&db, &bulk).await.expect("enqueue under-floor bulk");
        // Half the bulk parks behind a future wake — immediate and
        // deferred under-floor rows alike must leave the probes' span.
        db.query(
            "UPDATE queue SET wake_at = datetime('now', '+30 minutes') \
             WHERE crate_name >= 'under2'",
        )
        .execute()
        .await
        .expect("defer part of the bulk");
        assert_eq!(
            next_alarm(&db, ROW_TS_MS, &claim_settings())
                .await
                .expect("next_alarm over the bulk"),
            AlarmPlan::Delete,
            "300 under-floor rows arm nothing"
        );
        assert_eq!(
            claimed_names(&db, &claim_settings()).await,
            Vec::<String>::new()
        );
        // The one row over the floor claims on the first page —
        // the floor is an index equality, not a scan the bulk can starve.
        enqueue(&db, &[request_on("win", WINDOWS_TARGET, Vec::new())])
            .await
            .expect("enqueue the eligible row");
        set_first_requested_at_on(
            &db,
            "win",
            WINDOWS_TARGET,
            PAST_TS,
            settings().dispatch_min_age_minutes,
        )
        .await;
        assert_eq!(claimed_names(&db, &claim_settings()).await, ["win"]);
    }

    /// Demand that raises a row's score across the floor flips the
    /// persisted flag with it: the batched update's `priority`
    /// recomputation flows through the claim-order refresh, which
    /// rewrites `value`, `dispatch_key` and `dispatch_eligible`
    /// together (stow#525 I10).
    #[tokio::test]
    async fn demand_can_cross_the_floor() {
        let db = memory_db().await.expect("memory db");
        set_floor(&db, 1).await;
        enqueue(&db, &[request("rise", Vec::new())])
            .await
            .expect("enqueue");
        set_first_requested_at(&db, "rise", PAST_TS).await;
        assert_eq!(flag_of(&db, "rise").await, 0);

        super::apply_batched_updates(
            &db,
            &settings(),
            &[super::BatchedUpdate {
                task_id: task_id_on("rise", TARGET),
                occurrences: 1,
                // `priority = downloads / 1000` reaches 1 — exactly the
                // floor, the boundary the flag must take.
                downloads: 1_000,
                redispatch: 0,
                human: 0,
            }],
        )
        .await
        .expect("demand update");
        assert_eq!(flag_of(&db, "rise").await, 1);
        assert_eq!(claimed_names(&db, &claim_settings()).await, ["rise"]);
    }

    /// A promoted row gains the human lane's exemption in the same
    /// statement that moves its lane — an under-floor miss claims the
    /// moment it is human (stow#525 I10).
    #[tokio::test]
    async fn promotion_grants_the_human_exemption() {
        let db = memory_db().await.expect("memory db");
        set_floor(&db, 1).await;
        enqueue(&db, &[request("prom", Vec::new())])
            .await
            .expect("enqueue");
        assert_eq!(flag_of(&db, "prom").await, 0);

        let mutated = super::apply_mutation(
            &db,
            &settings(),
            super::QueueMutation::Promote,
            &super::QueueSelector {
                task_ids: vec![task_id_on("prom", TARGET)],
                ..Default::default()
            },
        )
        .await
        .expect("promote");
        assert_eq!(mutated, 1);
        assert_eq!(flag_of(&db, "prom").await, 1);
        set_first_requested_at(&db, "prom", PAST_TS).await;
        assert_eq!(claimed_names(&db, &claim_settings()).await, ["prom"]);
    }

    /// A retried row keeps its persisted answer — retry rewrites
    /// status, `not_before` and `wake_at`, never the flag (stow#525
    /// I10).
    #[tokio::test]
    async fn retry_preserves_the_eligibility_flag() {
        let db = memory_db().await.expect("memory db");
        set_floor(&db, 1).await;
        enqueue(
            &db,
            &[
                request("low", Vec::new()),
                request_on("win", WINDOWS_TARGET, Vec::new()),
            ],
        )
        .await
        .expect("enqueue");
        for name in ["low", "win"] {
            db.query("UPDATE queue SET status = 'failed' WHERE crate_name = ?")
                .bind(name.to_owned())
                .execute()
                .await
                .expect("park the row failed");
        }
        let selector = super::QueueSelector {
            task_ids: vec![task_id_on("low", TARGET), task_id_on("win", WINDOWS_TARGET)],
            ..Default::default()
        };
        assert_eq!(
            super::apply_mutation(&db, &settings(), super::QueueMutation::Retry, &selector)
                .await
                .expect("retry"),
            2
        );
        assert_eq!(flag_of(&db, "low").await, 0);
        assert_eq!(flag_of(&db, "win").await, 1);
        set_first_requested_at_on(
            &db,
            "win",
            WINDOWS_TARGET,
            PAST_TS,
            settings().dispatch_min_age_minutes,
        )
        .await;
        assert_eq!(claimed_names(&db, &claim_settings()).await, ["win"]);
    }

    /// The operator floor move: `migrate` stamps the configured value
    /// into `settings` and backfills `dispatch_eligible` — under-floor
    /// rows lose the flag, the boundary and the exempt lane keep it,
    /// and the stamped row is the value every writer reads from then
    /// on (stow#525 I10).
    #[tokio::test]
    async fn operator_floor_change_backfills_eligibility() {
        let db = memory_db_raw().await.expect("raw memory db");
        super::migrate(&db, &settings()).await.expect("migrate");
        enqueue(
            &db,
            &[
                request("lin", Vec::new()),
                request_on("win", WINDOWS_TARGET, Vec::new()),
                EnqueueRequest {
                    source: EnqueueSource::HumanRequest,
                    ..request("human", Vec::new())
                },
            ],
        )
        .await
        .expect("enqueue");
        assert_eq!(flag_of(&db, "lin").await, 1, "no floor admits all");

        let floor = |min_dispatch_value| SchedulerSettings {
            min_dispatch_value,
            ..settings()
        };
        // Raise the floor to one band: the Linux miss drops out, the
        // band row sits exactly at the floor, the human row is exempt.
        super::migrate_dispatch_eligible(&db, &floor(super::VALUE_BAND))
            .await
            .expect("apply floor");
        assert_eq!(flag_of(&db, "lin").await, 0);
        assert_eq!(flag_of(&db, "win").await, 1);
        assert_eq!(flag_of(&db, "human").await, 1);
        // A second pass with the same floor is a no-op — and a higher
        // floor floors the band too while the human stays.
        super::migrate_dispatch_eligible(&db, &floor(super::VALUE_BAND))
            .await
            .expect("idempotent pass");
        super::migrate_dispatch_eligible(&db, &floor(super::VALUE_BAND + 1))
            .await
            .expect("raise floor");
        assert_eq!(flag_of(&db, "win").await, 0);
        assert_eq!(flag_of(&db, "human").await, 1);
    }

    /// A caught mid-pass failure leaves no stamp, so a retried
    /// operator migrate at the same floor still repairs: the backfill
    /// must not have committed flags against a floor the settings row
    /// was allowed to skip (stow#525 I10).
    #[tokio::test]
    async fn failed_backfill_retries_under_the_same_floor() {
        let db = memory_db_raw().await.expect("raw memory db");
        super::migrate(&db, &settings()).await.expect("migrate");
        enqueue(
            &db,
            &[
                request("lin", Vec::new()),
                request_on("win", WINDOWS_TARGET, Vec::new()),
            ],
        )
        .await
        .expect("enqueue");
        // Kill every queue UPDATE — the backfill's statement fails
        // before the stamp it was supposed to earn.
        db.query(
            "CREATE TRIGGER fail_backfill BEFORE UPDATE ON queue \
             BEGIN SELECT RAISE(ABORT, 'injected backfill failure'); END",
        )
        .execute()
        .await
        .expect("install failure trigger");
        let floored = SchedulerSettings {
            min_dispatch_value: 1,
            ..settings()
        };
        super::migrate_dispatch_eligible(&db, &floored)
            .await
            .expect_err("injected failure must abort the pass");
        // The pass recorded no stamp for the floor it was applying —
        // the last-applied floor ("0", from the schema-building
        // migrate) survives, so a retry still sees floor 1 as
        // unapplied rather than skipping the backfill over stale flags.
        let stamped: Option<String> = db
            .query("SELECT value FROM settings WHERE key = 'min_dispatch_value'")
            .fetch_scalar_optional::<String>()
            .await
            .expect("read stamped floor");
        assert_eq!(
            stamped.as_deref(),
            Some("0"),
            "a failed pass must not stamp"
        );
        db.query("DROP TRIGGER fail_backfill")
            .execute()
            .await
            .expect("remove failure trigger");
        // Same-floor retry converges: backfill repairs flags, then the
        // stamp lands.
        super::migrate_dispatch_eligible(&db, &floored)
            .await
            .expect("retried migrate");
        assert_eq!(flag_of(&db, "lin").await, 0);
        assert_eq!(flag_of(&db, "win").await, 1);
        let stamped: Option<String> = db
            .query("SELECT value FROM settings WHERE key = 'min_dispatch_value'")
            .fetch_scalar_optional::<String>()
            .await
            .expect("read stamped floor");
        assert_eq!(stamped.as_deref(), Some("1"));
    }

    /// A queue at the prior schema version — `dispatch_eligible`
    /// missing and the floor-blind index names live — gains the
    /// column, the eligible-aware indexes and the stamped floor in one
    /// operator pass (stow#525 I10).
    #[tokio::test]
    async fn migrate_recovers_the_prior_schema() {
        let db = memory_db_raw().await.expect("raw memory db");
        super::migrate(&db, &settings()).await.expect("migrate");
        enqueue(
            &db,
            &[
                request("lin", Vec::new()),
                request_on("win", WINDOWS_TARGET, Vec::new()),
            ],
        )
        .await
        .expect("enqueue");
        // Roll the database back to the pre-12 shape: no column, the
        // old index names on their old column lists, the old stamp.
        for statement in [
            "DROP INDEX idx_queue_claim",
            "DROP INDEX idx_queue_wake",
            // The pre-13 trigger carried no eligibility write — drop
            // it rather than leave a definition that references the
            // column being removed.
            "DROP TRIGGER demand_fold",
            "ALTER TABLE queue DROP COLUMN dispatch_eligible",
            "CREATE INDEX idx_queue_dispatch ON queue \
             (status, deps_met, dispatch_key, dispatch_family, lane, first_requested_at, not_before)",
            "CREATE INDEX idx_queue_wake_eligible ON queue \
             (status, deps_met, dispatch_family, wake_at)",
            "UPDATE scheduler_schema_version SET version = 11",
        ] {
            db.query(statement)
                .execute()
                .await
                .expect("stage the prior schema");
        }
        let floored = SchedulerSettings {
            min_dispatch_value: 1,
            ..settings()
        };
        let report = super::migrate(&db, &floored).await.expect("migrate");
        assert_eq!((report.before, report.after), (11, super::SCHEMA_VERSION));
        assert_eq!(flag_of(&db, "lin").await, 0);
        assert_eq!(flag_of(&db, "win").await, 1);
        let names = db
            .query(
                "SELECT name FROM sqlite_master WHERE type = 'index' \
                 AND name LIKE 'idx_queue_%'",
            )
            .fetch_scalars::<String>()
            .await
            .expect("index names");
        assert!(names.iter().any(|name| name == "idx_queue_claim"));
        assert!(names.iter().any(|name| name == "idx_queue_wake"));
        assert!(!names.iter().any(|name| name == "idx_queue_dispatch"));
        assert!(!names.iter().any(|name| name == "idx_queue_wake_eligible"));
    }

    /// `QueueTask.value` is the column's exact decimal text — adjacent
    /// scores above the JS-safe integer range round-trip through the
    /// row projection and out over the JSON wire without rounding,
    /// clamping, or a trailing `.0` (stow#525 I10).
    #[tokio::test]
    async fn list_tasks_reports_value_as_exact_decimal() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[request("wide-a", Vec::new()), request("wide-b", Vec::new())],
        )
        .await
        .expect("enqueue");
        // Literals inside the statement text parse as i64 in SQLite —
        // the only wide-integer channel, since a bound parameter would
        // cross the lossy numeric transport.
        for (name, literal) in [
            ("wide-a", "36893574046765006"),
            ("wide-b", "36893574046765007"),
        ] {
            db.query(&format!(
                "UPDATE queue SET value = {literal} WHERE task_id = ?"
            ))
            .bind(task_id_on(name, TARGET))
            .execute()
            .await
            .expect("set wide value");
        }

        let tasks = super::list_tasks(&db, &super::QueueSelector::default())
            .await
            .expect("list tasks");
        let mut values = tasks
            .iter()
            .map(|task| (task.crate_name.as_str(), task.value.as_str()))
            .collect::<Vec<_>>();
        values.sort_unstable();
        assert_eq!(
            values,
            [
                ("wide-a", "36893574046765006"),
                ("wide-b", "36893574046765007")
            ],
            "adjacent >2^53 scores arrive digit-for-digit"
        );
        // The wire shape is a JSON string, not a number an f64 decoder
        // could truncate.
        let wide_b = tasks
            .iter()
            .find(|task| task.crate_name.as_str() == "wide-b")
            .expect("wide-b listed");
        let serialized = serde_json::to_string(wide_b).expect("serialize task");
        assert!(
            serialized.contains("\"value\":\"36893574046765007\""),
            "the score serializes as decimal text: {serialized}"
        );
    }

    /// A row migrated from a pre-`value` queue (the column still at its
    /// ALTER default, the key in any older form) backfills to exactly
    /// the formula a fresh insert writes — migrated and fresh rows
    /// agree (stow#442 I6).
    #[tokio::test]
    async fn migrate_backfills_value_to_match_fresh_rows() {
        let db = memory_db_raw().await.expect("raw memory db");
        super::migrate(&db, &settings())
            .await
            .expect("first migrate");
        enqueue(
            &db,
            &[
                EnqueueRequest {
                    source: EnqueueSource::HumanRequest,
                    ..request("human", Vec::new())
                },
                request_on("win", WINDOWS_TARGET, Vec::new()),
                request("lin", Vec::new()),
            ],
        )
        .await
        .expect("enqueue");
        // Simulate the ALTER's untouched state: `value` at its 0
        // default and the key in an obsolete form.
        db.query("UPDATE queue SET value = 0, dispatch_key = '0|0|1970|x|1970|0'")
            .execute()
            .await
            .expect("simulate migrated rows");

        super::migrate(&db, &settings()).await.expect("migrate");

        let drifted = db
            .query(super::RANK_SOURCE_SELECT)
            .fetch_all::<super::RankSourceRow>()
            .await
            .expect("load migrated rows")
            .iter()
            .map(|row| row.checked().expect("checked rank row"))
            .filter(|row| {
                let family = crate::scheduler::rank::dispatch_family(&row.target);
                family != row.dispatch_family
                    || crate::scheduler::rank::raw_value(
                        &row.lane,
                        family,
                        row.priority,
                        row.demand,
                    ) != row.value
                    || crate::scheduler::rank::dispatch_key(&crate::scheduler::rank::KeyOperands {
                        lane: &row.lane,
                        family,
                        priority: row.priority,
                        demand: row.demand,
                        cost_ms: row.cost_ms,
                        first_requested_at: &row.first_requested_at,
                        created_at: &row.created_at,
                        task_id: &row.task_id,
                    }) != row.dispatch_key
            })
            .count();
        assert_eq!(
            drifted, 0,
            "every row carries the shared abstraction's pair"
        );
    }

    // stow#522 I7 — keyed demand application.

    fn demand_entry_on(
        crate_name: &str,
        target: &str,
        delta: u64,
    ) -> stow_types::api::SchedulerDemandEntry {
        stow_types::api::SchedulerDemandEntry {
            crate_name: crate_name.parse().expect("demand crate"),
            version: VERSION.parse().expect("demand version"),
            features_json: FeaturesJson::default(),
            target: target.parse().expect("demand target"),
            rustc_version: RUSTC.parse().expect("demand rustc"),
            demand: delta,
        }
    }

    fn demand_entry(crate_name: &str, delta: u64) -> stow_types::api::SchedulerDemandEntry {
        demand_entry_on(crate_name, TARGET, delta)
    }

    fn demand_batch(
        batch_id: &str,
        entries: Vec<stow_types::api::SchedulerDemandEntry>,
    ) -> stow_types::api::SchedulerDemandRequest {
        stow_types::api::SchedulerDemandRequest {
            batch_id: batch_id.to_owned(),
            entries,
        }
    }

    async fn apply(
        db: &DurableDb,
        batch_id: &str,
        entries: Vec<stow_types::api::SchedulerDemandEntry>,
    ) -> Result<stow_types::api::SchedulerDemandReport, QueueError> {
        super::apply_demand(db, &demand_batch(batch_id, entries)).await
    }

    async fn demand_of(db: &DurableDb, task_id: &str) -> i64 {
        db.query("SELECT demand FROM queue WHERE task_id = ?")
            .bind(task_id.to_owned())
            .fetch_scalar::<i64>()
            .await
            .expect("demand read")
    }

    async fn contribution_rows(db: &DurableDb, batch_id: &str) -> u64 {
        db.query("SELECT count(*) FROM demand_contributions WHERE batch_id = ?")
            .bind(batch_id.to_owned())
            .fetch_scalar::<u64>()
            .await
            .expect("contribution count")
    }

    /// Demand lands on the named node and walks its whole unbuilt
    /// dependency closure; unrelated rows stay at zero (stow#522).
    #[tokio::test]
    async fn demand_walks_the_unbuilt_dependency_closure() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                request("leaf", Vec::new()),
                request("mid", vec![dependency("leaf")]),
                request("root", vec![dependency("mid")]),
                request("other", Vec::new()),
            ],
        )
        .await
        .expect("enqueue");

        let report = apply(&db, "h0", vec![demand_entry("root", 5)])
            .await
            .expect("demand");
        assert!(report.applied);
        assert_eq!(report.touched_tasks, 3);
        for name in ["root", "mid", "leaf"] {
            assert_eq!(demand_of(&db, &task_id_on(name, TARGET)).await, 5, "{name}");
        }
        assert_eq!(demand_of(&db, &task_id_on("other", TARGET)).await, 0);
        // The closure's value rows carry the delta — the ordering
        // operand, not a side column.
        let value = db
            .query("SELECT value FROM queue WHERE task_id = ?")
            .bind(task_id_on("leaf", TARGET))
            .fetch_scalar::<i64>()
            .await
            .expect("value read");
        assert_eq!(value, 5, "miss row: bands and priority are 0");
    }

    /// A diamond — root reaches `c` through both `a` and `b` — applies
    /// the delta once per task, and the walk dedup is visible in the
    /// contribution rows too (stow#522).
    #[tokio::test]
    async fn demand_dedupes_diamond_paths() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                request("c", Vec::new()),
                request("a", vec![dependency("c")]),
                request("b", vec![dependency("c")]),
                request("root", vec![dependency("a"), dependency("b")]),
            ],
        )
        .await
        .expect("enqueue");

        let report = apply(&db, "h0", vec![demand_entry("root", 7)])
            .await
            .expect("demand");
        assert_eq!(report.touched_tasks, 4);
        assert_eq!(demand_of(&db, &task_id_on("c", TARGET)).await, 7);
        assert_eq!(contribution_rows(&db, "h0").await, 4);
    }

    /// One entry names a node identity without its side: both the
    /// target-side and the host-side queue rows of that identity are
    /// touched (stow#522).
    #[tokio::test]
    async fn demand_touches_both_compile_sides_of_one_identity() {
        let db = memory_db().await.expect("memory db");
        let host = EnqueueRequest {
            host_side: true,
            ..request("dual", Vec::new())
        };
        enqueue(&db, &[request("dual", Vec::new()), host])
            .await
            .expect("enqueue");

        let report = apply(&db, "h0", vec![demand_entry("dual", 3)])
            .await
            .expect("demand");
        assert_eq!(report.touched_tasks, 2);
        for host_side in [false, true] {
            let id = task_id("dual", VERSION, FEATURES, TARGET, RUSTC, host_side);
            assert_eq!(demand_of(&db, &id).await, 3, "host_side={host_side}");
        }
    }

    /// The walk stops at nodes that are done or in flight — completed
    /// and running deps are not touched — and at edges whose slice
    /// answer is already `dep_met = 1` (stow#522).
    #[tokio::test]
    async fn demand_stops_at_built_in_flight_and_met_edges() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                request("done", Vec::new()),
                request("live", Vec::new()),
                request("leaf", Vec::new()),
                request("met-dep", Vec::new()),
                request(
                    "root",
                    vec![
                        dependency("done"),
                        dependency("live"),
                        dependency("met-dep"),
                    ],
                ),
            ],
        )
        .await
        .expect("enqueue");
        mark_active(&db, "done", TARGET, "completed").await;
        mark_active(&db, "live", TARGET, "running").await;
        // An edge whose dep the index already answered: met edges are
        // not part of the unbuilt closure even when the row behind
        // them is still pending.
        db.query(
            "UPDATE queue_dependencies SET dep_met = 1 \
                  WHERE task_id = ? AND dep_crate_name = 'met-dep'",
        )
        .bind(task_id_on("root", TARGET))
        .execute()
        .await
        .expect("met edge");
        // A failed dep is unbuilt — demand still flows to it.
        mark_active(&db, "leaf", TARGET, "failed").await;
        db.query("INSERT INTO queue_dependencies (task_id, depends_on_task_id, dep_crate_name, dep_version, dep_features_json, dep_target, dep_rustc_version, dep_host_side, dep_invocations, dep_shapes, dep_met, dep_side_known) \
                  VALUES (?, ?, 'leaf', ?, '[]', ?, ?, 0, 1, 2, 0, 1)")
            .bind(task_id_on("root", TARGET))
            .bind(task_id_on("leaf", TARGET))
            .bind(VERSION)
            .bind(TARGET)
            .bind(RUSTC)
            .execute()
            .await
            .expect("leaf edge");

        let report = apply(&db, "h0", vec![demand_entry("root", 4)])
            .await
            .expect("demand");
        assert_eq!(report.touched_tasks, 2, "root and the failed dep only");
        assert_eq!(demand_of(&db, &task_id_on("root", TARGET)).await, 4);
        assert_eq!(demand_of(&db, &task_id_on("leaf", TARGET)).await, 4);
        for name in ["done", "live", "met-dep"] {
            assert_eq!(demand_of(&db, &task_id_on(name, TARGET)).await, 0, "{name}");
        }
    }

    /// Distinct input identities contribute their own deltas to a
    /// shared dependency — and a cycle terminates with each node
    /// touched once (stow#522).
    #[tokio::test]
    async fn demand_sums_distinct_identities_and_survives_cycles() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                request("shared", Vec::new()),
                request("r1", vec![dependency("shared")]),
                request("r2", vec![dependency("shared")]),
            ],
        )
        .await
        .expect("enqueue shared");
        let report = apply(
            &db,
            "h0",
            vec![demand_entry("r1", 3), demand_entry("r2", 4)],
        )
        .await
        .expect("demand");
        assert_eq!(report.touched_tasks, 3);
        assert_eq!(demand_of(&db, &task_id_on("shared", TARGET)).await, 7);

        // a ↔ b: the UNION dedup closes the cycle; each side gets the
        // delta once.
        enqueue(
            &db,
            &[
                request("cyc-a", vec![dependency("cyc-b")]),
                request("cyc-b", vec![dependency("cyc-a")]),
            ],
        )
        .await
        .expect("enqueue cycle");
        let report = apply(&db, "h1", vec![demand_entry("cyc-a", 2)])
            .await
            .expect("cycle demand");
        assert_eq!(report.touched_tasks, 2);
        for name in ["cyc-a", "cyc-b"] {
            assert_eq!(demand_of(&db, &task_id_on(name, TARGET)).await, 2, "{name}");
        }
    }

    /// The replay contract: re-delivering the same `batch_id` applies
    /// nothing and reports `applied = false`; a distinct batch is a
    /// distinct hour and adds on top (stow#522).
    #[tokio::test]
    async fn demand_replay_is_idempotent_and_batches_accumulate() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("root", Vec::new())])
            .await
            .expect("enqueue");

        let first = apply(&db, "hour-1", vec![demand_entry("root", 5)])
            .await
            .expect("first");
        assert!(first.applied);
        let replay = apply(&db, "hour-1", vec![demand_entry("root", 5)])
            .await
            .expect("replay");
        assert!(!replay.applied);
        assert_eq!(demand_of(&db, &task_id_on("root", TARGET)).await, 5);
        assert_eq!(contribution_rows(&db, "hour-1").await, 1);

        let next = apply(&db, "hour-2", vec![demand_entry("root", 5)])
            .await
            .expect("next hour");
        assert!(next.applied);
        assert_eq!(demand_of(&db, &task_id_on("root", TARGET)).await, 10);
    }

    /// A delivery's cost is proportional to its own rows, not the
    /// stored ledger: the same batch run against 3 vs 300 recorded
    /// contribution batches issues identical statements with identical
    /// counted rows, the batch predicate plans as an index search, and
    /// a crashed earlier delivery converges by folding only its own
    /// unmarked rows (stow#522).
    #[tokio::test]
    async fn demand_cost_stays_proportional_with_preexisting_history() {
        async fn seeded(history: u64) -> (DurableDb, StatementLog) {
            let (db, log) = counting_memory_db().await.expect("counting db");
            enqueue(&db, &[request("root", Vec::new())])
                .await
                .expect("enqueue");
            // A long ledger built by real deliveries — every row
            // already folded through the same path under test.
            for hour in 0..history {
                apply(&db, &format!("old-{hour}"), vec![demand_entry("root", 2)])
                    .await
                    .expect("history batch");
            }
            (db, log)
        }

        async fn issued_new_batch(db: &DurableDb, log: &StatementLog) -> Vec<String> {
            let base = log.lock().expect("log").len();
            let report = apply(db, "new-hour", vec![demand_entry("root", 3)])
                .await
                .expect("new batch");
            assert!(report.applied);
            let issued = log.lock().expect("log")[base..].to_vec();
            // (sql, rows_read, rows_written) — the observable cost.
            issued
                .iter()
                .map(|s| format!("{}|{}|{}", s.sql, s.rows_read, s.rows_written))
                .collect()
        }

        let (small, small_log) = seeded(3).await;
        let (large, large_log) = seeded(300).await;
        let root = task_id_on("root", TARGET);
        assert_eq!(demand_of(&small, &root).await, 6);
        assert_eq!(demand_of(&large, &root).await, 600);

        let small_issued = issued_new_batch(&small, &small_log).await;
        let large_issued = issued_new_batch(&large, &large_log).await;
        assert_eq!(
            small_issued, large_issued,
            "history never enters the request"
        );
        assert_eq!(demand_of(&small, &root).await, 9);
        assert_eq!(demand_of(&large, &root).await, 603);

        // Every batch-keyed predicate is an index probe, not a ledger
        // scan — on reprepare's staging clear and on the acceptance
        // guard's staged count.
        for sql in [
            "DELETE FROM demand_contributions WHERE batch_id = ?",
            "SELECT count(*) FROM demand_contributions c WHERE c.batch_id = ?",
        ] {
            let details = db_plan(&small, sql, &["new-hour"]).await;
            assert!(
                details
                    .iter()
                    .any(|d| d.contains("SEARCH") && d.contains("demand_contributions")),
                "keyed predicate expected for `{sql}`: {details:?}"
            );
            assert!(
                !details
                    .iter()
                    .any(|d| d.contains("SCAN") && d.contains("demand_contributions")),
                "ledger scan on the demand path: {details:?}"
            );
        }

        // A delivery that failed after preparing — a `prepared` record
        // with staged rows — reserves nothing and folds nothing: the
        // same-input retry recomputes and accepts, and a different
        // batch never sees the draft's rows.
        let crashed = vec![demand_entry("root", 7)];
        db_insert_batch_record(
            &small,
            "crashed",
            &planted_input_hash(&crashed),
            1,
            "prepared",
        )
        .await;
        db_insert_contribution(&small, &root, "crashed", 7).await;
        let report = apply(&small, "crashed", crashed)
            .await
            .expect("re-deliver crashed batch");
        assert!(report.applied, "the reprepare accepts");
        assert_eq!(demand_of(&small, &root).await, 16, "6 + 3 + 7");
        assert_eq!(batch_state(&small, "crashed").await, "accepted");
    }

    /// One staged row under a planted `prepared` draft — prepared the
    /// same way the route prepares it, so the crashed delivery the
    /// row models carried real post-fold fields when it died.
    async fn db_insert_contribution(db: &DurableDb, task_id: &str, batch_id: &str, delta: i64) {
        let staged = super::prepare_demand_rows(db, &[(task_id.to_owned(), delta)], 0)
            .await
            .expect("prepare draft row")
            .remove(0);
        db.query(
            "INSERT INTO demand_contributions \
             (task_id, batch_id, delta, value, dispatch_key, dispatch_eligible) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(task_id.to_owned())
        .bind(batch_id.to_owned())
        .bind(delta)
        .bind(staged.value)
        .bind(staged.key)
        .bind(i64::from(staged.eligible))
        .execute()
        .await
        .expect("stage contribution");
    }

    /// One `demand_batches` row with an explicit state — how a test
    /// plants the unaccepted `prepared` state a failed delivery leaves.
    async fn db_insert_batch_record(
        db: &DurableDb,
        batch_id: &str,
        input_hash: &str,
        touched_count: i64,
        state: &str,
    ) {
        db.query(
            "INSERT INTO demand_batches (batch_id, input_hash, touched_count, state) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(batch_id.to_owned())
        .bind(input_hash.to_owned())
        .bind(touched_count)
        .bind(state.to_owned())
        .execute()
        .await
        .expect("record batch");
    }

    /// The real canonical-input fingerprint for a batch id — how a
    /// test's planted `prepared` record carries the input the retry
    /// will compute, so the retry is a genuine same-input reprepare.
    fn planted_input_hash(entries: &[stow_types::api::SchedulerDemandEntry]) -> String {
        super::demand_input_fingerprint(&super::demand_deltas(entries).expect("deltas"))
            .expect("fingerprint")
    }

    /// A batch record's current state string, for lifecycle assertions.
    async fn batch_state(db: &DurableDb, batch_id: &str) -> String {
        db.query("SELECT state FROM demand_batches WHERE batch_id = ?")
            .bind(batch_id.to_owned())
            .fetch_scalar::<String>()
            .await
            .expect("batch state")
    }

    async fn batch_rows(db: &DurableDb, batch_id: &str) -> u64 {
        db.query("SELECT count(*) FROM demand_batches WHERE batch_id = ?")
            .bind(batch_id.to_owned())
            .fetch_scalar::<u64>()
            .await
            .expect("batch count")
    }

    async fn db_plan(db: &DurableDb, sql: &str, binds: &[&str]) -> Vec<String> {
        #[derive(skyzen::FromRow)]
        struct PlanRow {
            detail: String,
        }
        let explained = format!("EXPLAIN QUERY PLAN {sql}");
        let mut query = db.query(&explained);
        for bind in binds {
            query = query.bind((*bind).to_owned());
        }
        query
            .fetch_all::<PlanRow>()
            .await
            .expect("explain")
            .into_iter()
            .map(|row| row.detail)
            .collect()
    }

    /// Demand is a queue operand, not a side channel: an ordinary
    /// re-request and a lane promotion recompute `value`/`dispatch_key`
    /// through the same formula and keep the contribution (stow#522).
    #[tokio::test]
    async fn demand_survives_resubmit_and_promotion() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("root", Vec::new())])
            .await
            .expect("enqueue");
        apply(&db, "h0", vec![demand_entry("root", 9)])
            .await
            .expect("demand");

        // Re-request: the enqueue path's key refresh recomputes value
        // with the demand operand.
        enqueue(&db, &[request("root", Vec::new())])
            .await
            .expect("resubmit");
        assert_eq!(demand_of(&db, &task_id_on("root", TARGET)).await, 9);
        let value = db
            .query("SELECT value FROM queue WHERE task_id = ?")
            .bind(task_id_on("root", TARGET))
            .fetch_scalar::<i64>()
            .await
            .expect("value read");
        assert_eq!(value, 9);

        // Promote recomputes lane/family bands and keeps demand.
        super::apply_mutation(
            &db,
            &settings(),
            super::QueueMutation::Promote,
            &filter_selector(stow_types::api::QueueSelector {
                crate_name: Some("root".parse().expect("crate name")),
                ..Default::default()
            }),
        )
        .await
        .expect("promote");
        assert_eq!(demand_of(&db, &task_id_on("root", TARGET)).await, 9);
        let value = db
            .query("SELECT value FROM queue WHERE task_id = ?")
            .bind(task_id_on("root", TARGET))
            .fetch_scalar::<i64>()
            .await
            .expect("value read");
        assert_eq!(value, 2 * super::VALUE_BAND + 9, "human band + demand");
    }

    /// A delta that would push `priority + demand` past `PRIORITY_MAX`
    /// is an error before any write — no clamp, no REAL promotion, and
    /// the queue plus the contribution ledger are untouched
    /// (stow#522).
    #[tokio::test]
    async fn demand_over_band_bound_fails_without_writes() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("root", Vec::new())])
            .await
            .expect("enqueue");

        let over = (super::PRIORITY_MAX as u64) + 1;
        let error = apply(&db, "h0", vec![demand_entry("root", over)])
            .await
            .expect_err("over-bound demand must fail");
        assert!(error.to_string().contains("priority band"), "{error}");
        assert_eq!(demand_of(&db, &task_id_on("root", TARGET)).await, 0);
        assert_eq!(contribution_rows(&db, "h0").await, 0);

        // Exactly at the bound is admissible.
        apply(
            &db,
            "h1",
            vec![demand_entry("root", super::PRIORITY_MAX as u64)],
        )
        .await
        .expect("at-bound demand");
        assert_eq!(
            demand_of(&db, &task_id_on("root", TARGET)).await,
            super::PRIORITY_MAX
        );
    }

    /// The stored batch record pins the accepted canonical input: a
    /// redelivery naming the same id with ANY different payload — a
    /// changed delta or a different identity set — fails before a
    /// single write, so a mistaken retry can never reshape the frozen
    /// contribution set (stow#522).
    #[tokio::test]
    async fn demand_conflicting_same_id_payload_fails_before_writes() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                request("root", vec![dependency("mid")]),
                request("mid", Vec::new()),
            ],
        )
        .await
        .expect("enqueue");
        apply(&db, "h0", vec![demand_entry("root", 5)])
            .await
            .expect("first delivery");

        // Same id, changed delta — refused.
        let error = apply(&db, "h0", vec![demand_entry("root", 7)])
            .await
            .expect_err("conflicting delta must fail");
        assert!(
            error.to_string().contains("different payload"),
            "conflict error: {error}"
        );
        // Same id, different identity — refused.
        apply(&db, "h0", vec![demand_entry("mid", 5)])
            .await
            .expect_err("conflicting identity must fail");

        // Nothing moved: demands, contribution rows and the batch
        // record are exactly what the first delivery established.
        assert_eq!(demand_of(&db, &task_id_on("root", TARGET)).await, 5);
        assert_eq!(demand_of(&db, &task_id_on("mid", TARGET)).await, 5);
        assert_eq!(contribution_rows(&db, "h0").await, 2);
        assert_eq!(batch_rows(&db, "h0").await, 1);
    }

    /// An exact replay folds the frozen set, not the live closure:
    /// after the graph moves on — the root completes, a new task and
    /// edge arrive that a fresh walk would reach — the replay applies
    /// nothing the first delivery did not record (stow#522).
    #[tokio::test]
    async fn demand_replay_uses_the_frozen_set_not_the_live_closure() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                request("leaf", Vec::new()),
                request("root", vec![dependency("leaf")]),
            ],
        )
        .await
        .expect("enqueue");
        let first = apply(&db, "h0", vec![demand_entry("root", 4)])
            .await
            .expect("first delivery");
        assert_eq!(first.touched_tasks, 2);

        // The graph moves on: the root completes (a fresh walk would
        // find no roots), and a new unbuilt task enters the closure —
        // `extra` is now a live `dep_met = 0` dep of `leaf`.
        mark_active(&db, "root", TARGET, "completed").await;
        enqueue(&db, &[request("extra", Vec::new())])
            .await
            .expect("enqueue extra");
        db.query(
            "INSERT INTO queue_dependencies \
             (task_id, depends_on_task_id, dep_met) VALUES (?, ?, 0)",
        )
        .bind(task_id_on("leaf", TARGET))
        .bind(task_id_on("extra", TARGET))
        .execute()
        .await
        .expect("new edge");

        let replay = apply(&db, "h0", vec![demand_entry("root", 4)])
            .await
            .expect("replay");
        assert!(!replay.applied);
        assert_eq!(replay.touched_tasks, 2);
        assert_eq!(demand_of(&db, &task_id_on("extra", TARGET)).await, 0);
        assert_eq!(contribution_rows(&db, "h0").await, 2);
    }

    /// An accepted batch that froze an empty contribution set keeps
    /// its id claimed: replays still apply nothing, and a conflicting
    /// payload on the same id is still a conflict — an unknown root at
    /// first delivery does not make the id reusable (stow#522).
    #[tokio::test]
    async fn demand_empty_accepted_batch_stays_empty() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("other", Vec::new())])
            .await
            .expect("enqueue");

        let first = apply(&db, "h0", vec![demand_entry("absent", 9)])
            .await
            .expect("first delivery");
        assert!(first.applied, "an empty accepted set still accepts");
        assert_eq!(first.touched_tasks, 0);
        assert_eq!(batch_rows(&db, "h0").await, 1);

        // The root becoming eligible later does not retro-apply: the
        // frozen empty set is what replays.
        enqueue(&db, &[request("absent", Vec::new())])
            .await
            .expect("enqueue late root");
        let replay = apply(&db, "h0", vec![demand_entry("absent", 9)])
            .await
            .expect("replay");
        assert!(!replay.applied);
        assert_eq!(replay.touched_tasks, 0);
        assert_eq!(demand_of(&db, &task_id_on("absent", TARGET)).await, 0);
        assert_eq!(contribution_rows(&db, "h0").await, 0);

        apply(&db, "h0", vec![demand_entry("absent", 8)])
            .await
            .expect_err("conflicting payload must fail");
    }

    /// An unaccepted draft is not a frozen set: a same-input retry on
    /// a `prepared` record recomputes the CURRENT closure — staging
    /// from the failed attempt is cleared, tasks the graph no longer
    /// shows (a completed dep) contribute nothing, and a task that
    /// entered the closure meanwhile joins the accepted set. The
    /// draft's own staged rows never fold before acceptance and never
    /// reserve band (stow#522).
    #[tokio::test]
    async fn demand_unaccepted_draft_retry_recomputes_the_live_closure() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                request("leaf", Vec::new()),
                request("root", vec![dependency("leaf")]),
            ],
        )
        .await
        .expect("enqueue");

        // A delivery that failed after preparing: the record and one
        // staged row exist, nothing accepted, nothing folded.
        let entries = vec![demand_entry("root", 9)];
        db_insert_batch_record(&db, "h0", &planted_input_hash(&entries), 2, "prepared").await;
        db_insert_contribution(&db, &task_id_on("root", TARGET), "h0", 9).await;
        db_insert_contribution(&db, &task_id_on("leaf", TARGET), "h0", 9).await;
        assert_eq!(demand_of(&db, &task_id_on("root", TARGET)).await, 0);
        assert_eq!(demand_of(&db, &task_id_on("leaf", TARGET)).await, 0);

        // The graph moves before the retry: `leaf` completes (out of
        // the live closure) and `extra` joins it — while another
        // legitimate batch accepts against the same nodes, proof the
        // draft's staging reserved no demand.
        mark_active(&db, "leaf", TARGET, "completed").await;
        enqueue(&db, &[request("extra", Vec::new())])
            .await
            .expect("enqueue extra");
        db.query(
            "INSERT INTO queue_dependencies \
             (task_id, depends_on_task_id, dep_met) VALUES (?, ?, 0)",
        )
        .bind(task_id_on("root", TARGET))
        .bind(task_id_on("extra", TARGET))
        .execute()
        .await
        .expect("new edge");
        apply(&db, "h1", vec![demand_entry("root", 3)])
            .await
            .expect("another batch");

        let retry = apply(&db, "h0", entries).await.expect("retry");
        assert!(retry.applied);
        assert_eq!(retry.touched_tasks, 2, "root + extra, not leaf");
        let root = task_id_on("root", TARGET);
        assert_eq!(demand_of(&db, &root).await, 12, "9 + 3 from h1");
        assert_eq!(demand_of(&db, &task_id_on("extra", TARGET)).await, 12);
        // `leaf` completed before either acceptance: h1's live closure
        // skipped it, and the draft's staged row for it was cleared —
        // its demand is 0, not the staged 9.
        assert_eq!(demand_of(&db, &task_id_on("leaf", TARGET)).await, 0);
        assert_eq!(contribution_rows(&db, "h0").await, 2, "restaged set");
        assert_eq!(batch_state(&db, "h0").await, "accepted");
    }

    /// A failed staging statement leaves only unaccepted material: the
    /// `prepared` record and its partial rows fold nothing and block
    /// nothing — the same-input retry clears them and accepts the
    /// recomputed set exactly once (stow#522).
    #[tokio::test]
    async fn demand_failed_staging_leaves_no_fold_and_retries_cleanly() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                request("leaf", Vec::new()),
                request("root", vec![dependency("leaf")]),
            ],
        )
        .await
        .expect("enqueue");

        // The stage INSERT failed mid-chunk: the record is prepared
        // and only part of the event's rows landed.
        let entries = vec![demand_entry("root", 5)];
        db_insert_batch_record(&db, "h0", &planted_input_hash(&entries), 2, "prepared").await;
        db_insert_contribution(&db, &task_id_on("root", TARGET), "h0", 5).await;

        // No acceptance happened, so no queue row moved and no demand
        // was reserved — a whole different batch accepts freely.
        assert_eq!(demand_of(&db, &task_id_on("root", TARGET)).await, 0);
        apply(&db, "h1", vec![demand_entry("root", 2)])
            .await
            .expect("independent batch");

        let retry = apply(&db, "h0", entries).await.expect("retry");
        assert!(retry.applied);
        assert_eq!(retry.touched_tasks, 2);
        let root = task_id_on("root", TARGET);
        assert_eq!(demand_of(&db, &root).await, 7, "5 recomputed + 2 from h1");
        assert_eq!(demand_of(&db, &task_id_on("leaf", TARGET)).await, 7);
        assert_eq!(contribution_rows(&db, "h0").await, 2);
    }

    /// An accepted batch's replay is a pure header read: after the
    /// response is lost and the graph changes — a completed root, a
    /// new task and side — the redelivery reports the stored count and
    /// issues zero writes (stow#522).
    #[tokio::test]
    async fn demand_accepted_replay_writes_nothing_after_graph_changes() {
        let (db, log) = counting_memory_db().await.expect("counting db");
        enqueue(
            &db,
            &[
                request("leaf", Vec::new()),
                request("root", vec![dependency("leaf")]),
            ],
        )
        .await
        .expect("enqueue");
        let first = apply(&db, "h0", vec![demand_entry("root", 4)])
            .await
            .expect("first delivery");
        assert_eq!(first.touched_tasks, 2);

        mark_active(&db, "root", TARGET, "completed").await;
        enqueue(&db, &[request("extra", Vec::new())])
            .await
            .expect("enqueue extra");

        let base = log.lock().expect("log").len();
        let replay = apply(&db, "h0", vec![demand_entry("root", 4)])
            .await
            .expect("replay");
        assert!(!replay.applied);
        assert_eq!(replay.touched_tasks, 2, "the stored count answers");
        let issued = log.lock().expect("log")[base..].to_vec();
        assert!(
            issued.iter().all(|s| s.rows_written == 0),
            "an accepted replay must not write: {issued:?}"
        );
        assert_eq!(demand_of(&db, &task_id_on("extra", TARGET)).await, 0);
        assert_eq!(demand_of(&db, &task_id_on("root", TARGET)).await, 4);
    }

    /// The acceptance statement is statement-atomic: force the
    /// trigger's staged-count verification to fail after the fold has
    /// already written a queue row (the raw UPDATE bypasses the
    /// caller's own count guard), and the abort rolls back the queue
    /// fold, the staged rows, and the accepted transition alike —
    /// the batch stays `prepared` and the queue untouched (stow#522).
    #[tokio::test]
    async fn demand_acceptance_trigger_failure_rolls_back_everything() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("root", Vec::new())])
            .await
            .expect("enqueue");
        let root = task_id_on("root", TARGET);

        // Record says two staged rows; only one landed — the partial
        // prepared set the guard exists to refuse. A direct state
        // flip reaches the trigger: the fold writes root's demand,
        // then the count check aborts the whole statement.
        let entries = vec![demand_entry("root", 9)];
        db_insert_batch_record(&db, "h0", &planted_input_hash(&entries), 2, "prepared").await;
        db_insert_contribution(&db, &root, "h0", 9).await;
        let error = db
            .query("UPDATE demand_batches SET state = 'accepted' WHERE batch_id = ?")
            .bind("h0".to_owned())
            .execute()
            .await
            .expect_err("short staged set must abort acceptance");
        assert!(
            error.to_string().contains("staged set short"),
            "abort reason: {error}"
        );

        assert_eq!(batch_state(&db, "h0").await, "prepared");
        assert_eq!(demand_of(&db, &root).await, 0, "the fold rolled back");
        assert_eq!(contribution_rows(&db, "h0").await, 1);

        // And the retry path still works on the rolled-back draft.
        let report = apply(&db, "h0", entries).await.expect("retry");
        assert!(report.applied);
        assert_eq!(demand_of(&db, &root).await, 9);
    }

    /// A closure whose serialized set would exceed the workerd 2 MiB
    /// bound lands whole: staging splits into chunks each under
    /// `DEMAND_STAGE_CHUNK_BYTES`, every row survives, and acceptance
    /// folds the complete set — no truncation, no giant bound string
    /// or ledger row (stow#522).
    #[tokio::test]
    async fn demand_stages_large_closures_in_bounded_chunks() {
        // 60k rows of realistic 64-char task ids serialize to ~6 MiB —
        // far past the 2 MiB bound a single snapshot would hit.
        let rows: Vec<super::ContributionRow> = (0..60_000)
            .map(|i| super::ContributionRow {
                tid: format!("{i:064x}"),
                delta: 1,
                value: "0".to_owned(),
                key: format!("0{i:064x}|now|now|{i:064x}"),
                eligible: 1,
            })
            .collect();
        let chunks = super::contribution_chunks(&rows).expect("chunks");
        assert!(chunks.len() > 1, "the set must split");
        let mut seen = 0_usize;
        for chunk in &chunks {
            assert!(
                chunk.len() < super::DEMAND_STAGE_CHUNK_BYTES,
                "chunk over bound: {} bytes",
                chunk.len()
            );
            let parsed: Vec<super::ContributionRow> =
                serde_json::from_str(chunk).expect("chunk parses");
            seen += parsed.len();
        }
        assert_eq!(seen, rows.len(), "no row truncated or lost");
    }

    /// The end-to-end bound the serialized-snapshot path could never
    /// cross: a real closure whose staged set exceeds the platform's
    /// 2 MiB row/binding bound folds through multiple staging chunks
    /// and still accepts atomically — full touched/ledger counts and
    /// the last task's demand included. A delivery that dies after an
    /// earlier staging chunk leaves only unaccepted draft material —
    /// no header acceptance, no queue fold — and the same-input retry
    /// recomputes, restages and converges exactly once (stow#522).
    #[tokio::test]
    async fn demand_multi_chunk_closure_is_atomic_end_to_end() {
        // 30k real queue tasks, one dependency chain — the closure
        // from the root touches all of them through the unmet-edge
        // walk, with the queue's own 64-hex task ids.
        const CHAIN: usize = 30_000;
        let db = memory_db().await.expect("memory db");
        let mut requests: Vec<EnqueueRequest> = Vec::with_capacity(CHAIN);
        for i in 0..CHAIN {
            let deps = if i + 1 < CHAIN {
                vec![dependency(&format!("chain-{}", i + 1))]
            } else {
                Vec::new()
            };
            requests.push(request(&format!("chain-{i}"), deps));
        }
        enqueue(&db, &requests).await.expect("enqueue chain");

        // The staged set this event would produce: one serialized
        // snapshot of it measures past the 2 MiB bound the old
        // blob-column path bound as a single string, while the real
        // staging splits it into several bounded chunks.
        let contributions = super::demand_event_rows(
            &db,
            &super::demand_deltas(&[demand_entry("chain-0", 2)]).expect("deltas"),
        )
        .await
        .expect("closure rows");
        assert_eq!(contributions.len(), CHAIN, "the closure is the chain");
        let staged = super::prepare_demand_rows(&db, &contributions, 0)
            .await
            .expect("prepared rows");
        let snapshot = serde_json::to_string(&staged).expect("snapshot encodes");
        assert!(
            snapshot.len() > 2 * 1024 * 1024,
            "serialized staged set must cross the old 2 MiB bound: {} bytes",
            snapshot.len()
        );
        let chunks = super::contribution_chunks(&staged).expect("chunks");
        assert!(
            chunks.len() > 1,
            "the staged set must land as multiple chunks, got {}",
            chunks.len()
        );

        // A delivery interrupted after an earlier staging chunk: the
        // `prepared` header plus all-but-the-last chunks — exactly the
        // material a failed stage INSERT leaves behind. Nothing is
        // accepted, so nothing folded.
        let entries = vec![demand_entry("chain-0", 2)];
        db_insert_batch_record(
            &db,
            "big",
            &planted_input_hash(&entries),
            i64::try_from(CHAIN).expect("chain count"),
            "prepared",
        )
        .await;
        for chunk in &chunks[..chunks.len() - 1] {
            db.query(
                "INSERT INTO demand_contributions \
                 (task_id, batch_id, delta, value, dispatch_key, dispatch_eligible) \
                 SELECT j.value ->> 'tid', ?, \
                        CAST(j.value ->> 'delta' AS INTEGER), \
                        j.value ->> 'value', j.value ->> 'key', \
                        j.value ->> 'eligible' \
                 FROM json_each(?) j",
            )
            .bind("big".to_owned())
            .bind(chunk.clone())
            .execute()
            .await
            .expect("stage partial chunk");
        }
        let staged_so_far = contribution_rows(&db, "big").await;
        assert!(staged_so_far > 0 && staged_so_far < CHAIN as u64);
        assert_eq!(batch_state(&db, "big").await, "prepared");
        assert_eq!(demand_of(&db, &task_id_on("chain-0", TARGET)).await, 0);
        assert_eq!(
            demand_of(&db, &task_id_on(&format!("chain-{}", CHAIN - 1), TARGET)).await,
            0,
            "no queue fold without acceptance"
        );

        // The same-input retry recomputes the live closure, replaces
        // the partial staging and accepts once — every task touched,
        // full ledger count, the last task's demand folded.
        let report = apply(&db, "big", entries).await.expect("retry converges");
        assert!(report.applied);
        assert_eq!(report.touched_tasks, CHAIN as u64);
        assert_eq!(contribution_rows(&db, "big").await, CHAIN as u64);
        assert_eq!(batch_state(&db, "big").await, "accepted");
        assert_eq!(demand_of(&db, &task_id_on("chain-0", TARGET)).await, 2);
        assert_eq!(
            demand_of(&db, &task_id_on(&format!("chain-{}", CHAIN - 1), TARGET)).await,
            2
        );

        // And an exact replay of the accepted batch writes nothing:
        // the stored header answers, the demand stays folded once.
        let replay = apply(&db, "big", vec![demand_entry("chain-0", 2)])
            .await
            .expect("accepted replay");
        assert!(!replay.applied);
        assert_eq!(replay.touched_tasks, CHAIN as u64);
        assert_eq!(demand_of(&db, &task_id_on("chain-0", TARGET)).await, 2);
    }

    /// Persisted demand counts against the resubmit writer's band:
    /// demand exactly at `PRIORITY_MAX` is legal while priority stays
    /// 0, but a resubmit that would raise priority must be refused
    /// before any write — queue, edges and demand untouched — while a
    /// sibling below the bound still resubmits normally (stow#522).
    #[tokio::test]
    async fn demand_at_bound_then_rising_resubmit_is_refused() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[request("bound", Vec::new()), request("fine", Vec::new())],
        )
        .await
        .expect("enqueue");
        apply(
            &db,
            "h0",
            vec![demand_entry("bound", super::PRIORITY_MAX as u64)],
        )
        .await
        .expect("at-bound demand");

        // downloads 1000 → new priority 1 > PRIORITY_MAX - demand = 0.
        let mut resubmit = request("bound", Vec::new());
        resubmit.downloads = 1000;
        let error = enqueue(&db, &[resubmit])
            .await
            .expect_err("resubmit past the band must fail");
        assert!(
            error.to_string().contains("priority band"),
            "band error: {error}"
        );

        // Nothing changed: demand, downloads and request count are the
        // pre-resubmit values.
        assert_eq!(
            demand_of(&db, &task_id_on("bound", TARGET)).await,
            super::PRIORITY_MAX
        );
        let downloads: i64 = db
            .query("SELECT downloads FROM queue WHERE task_id = ?")
            .bind(task_id_on("bound", TARGET))
            .fetch_scalar::<i64>()
            .await
            .expect("downloads");
        let request_count: i64 = db
            .query("SELECT request_count FROM queue WHERE task_id = ?")
            .bind(task_id_on("bound", TARGET))
            .fetch_scalar::<i64>()
            .await
            .expect("request_count");
        assert_eq!((downloads, request_count), (0, 1));

        // Below the bound the same resubmit is ordinary: the sibling
        // takes downloads 5000 → priority 5, demand still folded.
        let mut ok = request("fine", Vec::new());
        ok.downloads = 5000;
        enqueue(&db, &[ok]).await.expect("below-bound resubmit");
        let priority: i64 = db
            .query("SELECT priority FROM queue WHERE task_id = ?")
            .bind(task_id_on("fine", TARGET))
            .fetch_scalar::<i64>()
            .await
            .expect("priority");
        assert_eq!(priority, 5);
    }

    /// The same refusal precedes the human-lane budget charge: a human
    /// resubmit that would overflow the band is rejected before any
    /// mutation, so `human_daily_task_budget` stays byte-identical —
    /// on both the untrusted and the trusted entry path (stow#522).
    #[tokio::test]
    async fn demand_at_bound_human_resubmit_spends_no_budget() {
        async fn spent(db: &DurableDb) -> i64 {
            db.query(
                "SELECT task_count FROM human_daily_task_budget \
                 WHERE day = date('now')",
            )
            .fetch_scalar::<i64>()
            .await
            .expect("budget spend")
        }

        let db = memory_db().await.expect("memory db");
        let mut human = request("bound", Vec::new());
        human.source = EnqueueSource::HumanRequest;
        enqueue(&db, &[human.clone()]).await.expect("human enqueue");
        assert_eq!(spent(&db).await, 1, "the first submit charged once");
        apply(
            &db,
            "h0",
            vec![demand_entry("bound", super::PRIORITY_MAX as u64)],
        )
        .await
        .expect("at-bound demand");

        // downloads 1000 → new priority 1 > PRIORITY_MAX - demand = 0:
        // refused before the budget charge, through both entries.
        let mut resubmit = human;
        resubmit.downloads = 1000;
        enqueue(&db, &[resubmit.clone()])
            .await
            .expect_err("untrusted resubmit past the band must fail");
        assert_eq!(spent(&db).await, 1, "a refused resubmit spends nothing");
        super::enqueue_trusted(&db, &[resubmit], &settings())
            .await
            .expect_err("trusted resubmit past the band must fail");
        assert_eq!(spent(&db).await, 1, "trusted path spends nothing either");

        // Queue state is the pre-resubmit truth.
        assert_eq!(
            demand_of(&db, &task_id_on("bound", TARGET)).await,
            super::PRIORITY_MAX
        );
        let downloads: i64 = db
            .query("SELECT downloads FROM queue WHERE task_id = ?")
            .bind(task_id_on("bound", TARGET))
            .fetch_scalar::<i64>()
            .await
            .expect("downloads");
        assert_eq!(downloads, 0);
        let edges: i64 = db
            .query("SELECT count(*) FROM queue_dependencies")
            .fetch_scalar::<i64>()
            .await
            .expect("edges");
        assert_eq!(edges, 0);
    }

    /// Demand magnitudes above the JS safe-integer bound stay exact:
    /// the persisted `value` differs by exactly one for adjacent deltas
    /// above 2^53 and the claim order follows it — the JSON-decimal
    /// transport never became a float (stow#522).
    #[tokio::test]
    async fn demand_orders_exactly_above_the_js_safe_integer() {
        #[derive(skyzen::FromRow)]
        struct ValuePair {
            task_id: String,
            value: i64,
        }
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[request("less", Vec::new()), request("more", Vec::new())],
        )
        .await
        .expect("enqueue");
        let js_safe = 9_007_199_254_740_992_u64; // 2^53
        assert!(js_safe + 2 <= super::PRIORITY_MAX as u64);
        apply(
            &db,
            "h0",
            vec![
                demand_entry("less", js_safe + 1),
                demand_entry("more", js_safe + 2),
            ],
        )
        .await
        .expect("demand");

        let values = db
            .query("SELECT task_id, value FROM queue ORDER BY task_id")
            .fetch_all::<ValuePair>()
            .await
            .expect("values");
        let less = values
            .iter()
            .find(|row| row.task_id == task_id_on("less", TARGET))
            .expect("less row")
            .value;
        let more = values
            .iter()
            .find(|row| row.task_id == task_id_on("more", TARGET))
            .expect("more row")
            .value;
        assert_eq!(more - less, 1, "adjacent deltas stay adjacent");
        assert!(less > js_safe.cast_signed(), "values are above 2^53");

        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed[0].crate_name, "more");
    }

    /// An entry whose identity names no queue row is an accepted
    /// zero-count batch — the id is claimed, the queue untouched
    /// (stow#522).
    #[tokio::test]
    async fn demand_on_an_unknown_identity_is_a_noop() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("root", Vec::new())])
            .await
            .expect("enqueue");
        let report = apply(&db, "h0", vec![demand_entry("absent", 5)])
            .await
            .expect("demand");
        assert!(report.applied, "an empty closure still accepts");
        assert_eq!(report.touched_tasks, 0);
        assert_eq!(contribution_rows(&db, "h0").await, 0);
        assert_eq!(batch_state(&db, "h0").await, "accepted");
        assert_eq!(demand_of(&db, &task_id_on("root", TARGET)).await, 0);
    }

    /// Malformed batches fail at validation, before any queue read or
    /// write: an empty or oversized `batch_id`, an empty entry list,
    /// and a delta that cannot fit `i64` (stow#522).
    #[tokio::test]
    async fn demand_rejects_malformed_batches() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("root", Vec::new())])
            .await
            .expect("enqueue");

        for bad in ["", &"x".repeat(129)] {
            apply(&db, bad, vec![demand_entry("root", 1)])
                .await
                .expect_err("bad batch_id must fail");
        }
        apply(&db, "h0", Vec::new())
            .await
            .expect_err("empty entries must fail");
        let entries = (0..=256)
            .map(|i| demand_entry(&format!("e{i}"), 1))
            .collect();
        apply(&db, "h0", entries)
            .await
            .expect_err("over-cap entries must fail");
        apply(&db, "h0", vec![demand_entry("root", u64::MAX)])
            .await
            .expect_err("u64 delta must fail");
        assert_eq!(demand_of(&db, &task_id_on("root", TARGET)).await, 0);
    }

    /// With the macOS slot count spent mid-pass, the pass skips the
    /// remaining macOS rows but still claims other families' work; the
    /// skipped row stays pending for the next pass.
    #[tokio::test]
    async fn macos_cap_skips_macos_rows_but_claims_other_families() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                request_on("mac-one", MACOS_TARGET, Vec::new()),
                request_on("mac-two", MACOS_TARGET, Vec::new()),
                request_on("lin", TARGET, Vec::new()),
            ],
        )
        .await
        .expect("enqueue");

        let settings = SchedulerSettings {
            max_concurrent_macos_jobs: 1,
            dispatch_min_age_minutes: 0,
            ..settings()
        };
        let claimed = super::claim_dispatchable_tasks(&db, &settings, &NoCoverage)
            .await
            .expect("claim");

        assert_eq!(claimed.len(), 2);
        assert_eq!(
            claimed
                .iter()
                .filter(|task| task.target == MACOS_TARGET)
                .count(),
            1,
            "the macOS cap admits exactly one macOS row"
        );
        assert!(
            claimed.iter().any(|task| task.crate_name == "lin"),
            "the Linux row is not held back by the macOS cap"
        );
        assert_eq!(super::status(&db).await.expect("status").pending, 1);
    }

    /// Within a lane, Windows-family rows claim before other targets even
    /// when the other row was requested first — the Windows legs are the
    /// slowest in a wave, so they start first.
    #[tokio::test]
    async fn windows_tasks_claim_before_linux_within_a_lane() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request_on("lin", TARGET, Vec::new())])
            .await
            .expect("enqueue linux");
        enqueue(&db, &[request_on("win", WINDOWS_TARGET, Vec::new())])
            .await
            .expect("enqueue windows");
        set_first_requested_at(&db, "lin", PAST_TS).await;

        let settings = SchedulerSettings {
            dispatch_min_age_minutes: 0,
            ..settings()
        };
        let claimed = super::claim_dispatchable_tasks(&db, &settings, &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 2);
        assert_eq!(claimed[0].crate_name, "win");
        assert_eq!(claimed[1].crate_name, "lin");
    }

    /// With every macOS slot taken and only macOS rows pending, the alarm
    /// must target the active row's lease expiry — never `now`, which
    /// would spin the object in a zero-delay alarm loop.
    #[tokio::test]
    async fn saturated_macos_family_wakes_at_lease_expiry() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                request_on("mac-busy", MACOS_TARGET, Vec::new()),
                request_on("mac-waiting", MACOS_TARGET, Vec::new()),
            ],
        )
        .await
        .expect("enqueue");
        mark_active(&db, "mac-busy", MACOS_TARGET, "dispatched").await;
        set_first_requested_at_on(
            &db,
            "mac-waiting",
            MACOS_TARGET,
            PAST_TS,
            settings().dispatch_min_age_minutes,
        )
        .await;

        let settings = SchedulerSettings {
            max_concurrent_macos_jobs: 1,
            dispatch_min_age_minutes: 0,
            ..settings()
        };
        let plan = next_alarm(&db, ROW_TS_MS, &settings)
            .await
            .expect("next_alarm");
        assert_eq!(plan, AlarmPlan::At(ROW_TS_MS + stale_ms()));
    }

    /// The lane ordering still dominates the family ordering: a
    /// human-lane Linux row claims ahead of a miss-lane Windows row.
    #[tokio::test]
    async fn human_lane_still_claims_first_regardless_of_family() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request_on("win", WINDOWS_TARGET, Vec::new())])
            .await
            .expect("enqueue windows");
        enqueue(
            &db,
            &[EnqueueRequest {
                source: EnqueueSource::HumanRequest,
                ..request_on("lin", TARGET, Vec::new())
            }],
        )
        .await
        .expect("enqueue human");

        let settings = SchedulerSettings {
            dispatch_min_age_minutes: 0,
            ..settings()
        };
        let claimed = super::claim_dispatchable_tasks(&db, &settings, &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 2);
        assert_eq!(claimed[0].crate_name, "lin");
        assert_eq!(claimed[1].crate_name, "win");
    }

    #[tokio::test]
    async fn a_target_no_runner_builds_never_enters_the_queue() {
        // `build-crate.yml` resolves an unknown target to an empty
        // `runs-on`, so such a row could only ever become a dispatch that
        // dies before any job starts — no job, no log, no completion
        // report, and the slot held until the stale sweep reclaims it.
        let db = memory_db().await.expect("memory db");
        let mut unrunnable = request("serde", Vec::new());
        unrunnable.target = "aarch64-unknown-linux-musl"
            .parse()
            .expect("valid target triple");

        let inserted = enqueue(&db, &[unrunnable]).await.expect("enqueue");

        assert_eq!(
            inserted, 0,
            "nothing is queued for a target CI cannot build"
        );
        assert_eq!(
            super::status(&db).await.expect("status").pending,
            0,
            "and the queue stays empty"
        );
    }

    #[tokio::test]
    async fn a_ci_target_still_enters_the_queue() {
        let db = memory_db().await.expect("memory db");

        let inserted = enqueue(&db, &[request("serde", Vec::new())])
            .await
            .expect("enqueue");

        assert_eq!(inserted, 1);
        assert_eq!(super::status(&db).await.expect("status").pending, 1);
    }

    /// `inserted` counts the records the submit landed — never the
    /// backend's billed write rows, which include index maintenance:
    /// a resync reports 0 and a mixed batch reports only its
    /// newcomers.
    #[tokio::test]
    async fn a_submit_reports_only_the_records_it_inserted() {
        let db = memory_db().await.expect("memory db");

        let inserted = enqueue(
            &db,
            &[request("alpha", Vec::new()), request("beta", Vec::new())],
        )
        .await
        .expect("enqueue pair");
        assert_eq!(inserted, 2);

        let resync = enqueue(&db, &[request("alpha", Vec::new())])
            .await
            .expect("resync");
        assert_eq!(resync, 0, "a resync lands no new row");

        let mixed = enqueue(
            &db,
            &[request("beta", Vec::new()), request("gamma", Vec::new())],
        )
        .await
        .expect("mixed submit");
        assert_eq!(mixed, 1, "only the newcomer counts");
    }

    /// The gate regression's slice membership: `dep-met` and
    /// `dep-fpub` at both shapes a native target dep requires —
    /// (Target, Native, Linked) and (…, Unlinked) — and `dep-short`
    /// at only the linked one.
    fn gate_pub_rows() -> Vec<stow_types::api::PublishedSliceRow> {
        let full = || {
            [
                shape(UnitSide::Target, UnitInvocation::Native, UnitKind::Linked),
                shape(UnitSide::Target, UnitInvocation::Native, UnitKind::Unlinked),
            ]
        };
        ["dep-met", "dep-fpub"]
            .iter()
            .flat_map(|name| full().iter().map(|s| (name, *s)).collect::<Vec<_>>())
            .map(|(name, s)| stow_types::api::PublishedSliceRow {
                crate_name: name.parse().expect("valid crate name"),
                version: VERSION.parse().expect("valid semver"),
                features_json: FeaturesJson::default(),
                unit_shape: Some(s),
            })
            .chain(std::iter::once(stow_types::api::PublishedSliceRow {
                crate_name: "dep-short".parse().expect("valid crate name"),
                version: VERSION.parse().expect("valid semver"),
                features_json: FeaturesJson::default(),
                unit_shape: Some(shape(
                    UnitSide::Target,
                    UnitInvocation::Native,
                    UnitKind::Linked,
                )),
            }))
            .collect()
    }

    /// One submit derives every newcomer's `deps_met`/`blocked` from a
    /// single readiness pass over the batch's edges: a row with no
    /// edges lands met, a dep published at both of the shapes its
    /// target requires releases its parent, a half-published dep only
    /// waits, a dep retrying a transient failure waits unblocked,
    /// and an unresolved-side edge blocks. Multi-dep owners fold per
    /// edge: a met edge beside an unmet one still gates, and a blocker
    /// flag on an already-published dep never blocks on its own.
    #[tokio::test]
    async fn a_submit_gates_each_new_task_on_its_published_deps() {
        let db = memory_db().await.expect("memory db");

        // A transient failure leaves the unpublished dependency pending
        // behind its retry backoff, so its parent waits unblocked.
        enqueue(&db, &[request("dep-failed", Vec::new())])
            .await
            .expect("enqueue dep");
        fail_dependency_at_attempt(&db, "dep-failed", 1).await;
        enqueue(&db, &[request("dep-fpub", Vec::new())])
            .await
            .expect("enqueue published dep");
        db.query("UPDATE queue SET status = 'failed' WHERE task_id = ?")
            .bind(task_id_on("dep-fpub", TARGET))
            .execute()
            .await
            .expect("fail published dep");
        // The migration's spelling for an edge whose required side it
        // could not derive — seeded directly so the owner below is
        // born carrying it (its empty `depends_on` means the resync
        // never deletes the row).
        db.query(
            "INSERT INTO queue_dependencies \
             (task_id, depends_on_task_id, dep_crate_name, dep_version, \
              dep_features_json, dep_target, dep_rustc_version, \
              dep_host_side, dep_invocations, dep_shapes, dep_side_known) \
             VALUES (?, 'unresolved', '', '', '', '', '', -1, 0, 0, 0)",
        )
        .bind(task_id_on("mystery", TARGET))
        .execute()
        .await
        .expect("seed unknown-side edge");
        // `pair` holds two stored edges, so the fold must sum across
        // them — and only an edge that is unmet *and* blocking may
        // raise `blocked`: dep-fpub publishes both shapes but its row
        // sits 'failed' (nothing in this submit names it, so no
        // requeue revives it), contributing unpub=0/blocker=1, while
        // dep-short is unmet but pending-free, unpub=1/blocker=0.
        let (invocations, shapes) = super::dep_edge_requirements(TARGET, false, TARGET, false);
        for (dep, side_known) in [("dep-fpub", 1), ("dep-short", 1)] {
            db.query(
                "INSERT INTO queue_dependencies \
                 (task_id, depends_on_task_id, dep_crate_name, dep_version, \
                  dep_features_json, dep_target, dep_rustc_version, \
                  dep_host_side, dep_invocations, dep_shapes, dep_side_known) \
                 VALUES (?, ?, ?, '1.0.0', '[]', ?, ?, 0, ?, ?, ?)",
            )
            .bind(task_id_on("pair", TARGET))
            .bind(task_id_on(dep, TARGET))
            .bind(dep.to_owned())
            .bind(TARGET.to_owned())
            .bind(RUSTC.to_owned())
            .bind(invocations)
            .bind(shapes)
            .bind(side_known)
            .execute()
            .await
            .expect("seed known-side edge");
        }

        // One slice report serves `dep-met` and `dep-fpub` at both shapes
        // a native target dep requires, and `dep-short` at only the linked
        // shape. Publish it after the fabricated edges exist so the real
        // slice-delta path initializes the persisted `dep_met` flags.
        super::record_published_slice(&db, TARGET, RUSTC, None, None, &gate_pub_rows(), &[])
            .await
            .expect("record shared published slice");
        assert_pair_flags_after_publication(&db).await;

        let inserted = enqueue(
            &db,
            &[
                request("free", Vec::new()),
                request("met", vec![dependency("dep-met")]),
                request("short", vec![dependency("dep-short")]),
                request("stalled", vec![dependency("dep-failed")]),
                request("mystery", Vec::new()),
                request("twin", vec![dependency("dep-met"), dependency("dep-short")]),
                request("pair", Vec::new()),
            ],
        )
        .await
        .expect("enqueue gate cases");
        assert_eq!(inserted, 7, "every newcomer landed");

        for (name, deps_met, blocked) in [
            ("free", 1, 0),
            ("met", 1, 0),
            ("short", 0, 0),
            ("stalled", 0, 0),
            ("mystery", 0, 1),
            // A met edge beside an unmet one: the fold still reports
            // the owner unmet, and a pending dep never blocks.
            ("twin", 0, 0),
            // A blocker flag on a met edge (published but failed dep)
            // cannot block, while the unmet edge still gates the owner.
            ("pair", 0, 0),
        ] {
            for (column, expected) in [("deps_met", deps_met), ("blocked", blocked)] {
                let stored = db
                    .query(&format!("SELECT {column} FROM queue WHERE task_id = ?"))
                    .bind(task_id_on(name, TARGET))
                    .fetch_scalar::<i64>()
                    .await
                    .expect("stored gate flag");
                assert_eq!(stored, expected, "{name}: {column}");
            }
        }
    }

    /// A failed build under the attempt cap re-queues itself: the
    /// failure report writes `pending` with the exponential
    /// `not_before` backoff and the attempt bumped — the next dispatch
    /// it earns is a retry of attempt 2, gated by the backoff.
    #[tokio::test]
    async fn failed_build_retries_behind_its_backoff() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("flaky", Vec::new())])
            .await
            .expect("enqueue");
        set_first_requested_at(&db, "flaky", PAST_TS).await;

        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        super::complete(
            &db,
            &claim_settings(),
            &super::BuildCompleteReport {
                task_id: claimed[0].task_id.clone(),
                generation_id: claimed[0].generation_id.clone(),
                attempt: claimed[0].attempt,
                success: false,
                error: Some("boom".to_owned()),
                finished_at: None,
                github_run_id: None,
            },
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete");

        assert_eq!(row_column(&db, "flaky", "status").await, "pending");
        assert_eq!(row_column(&db, "flaky", "CAST(attempt AS TEXT)").await, "2");
        // attempt 1 fails → 2^1 minutes of `not_before` backoff, and the
        // alarm's `wake_at` follows it.
        let gated = db
            .query(
                "SELECT CASE WHEN not_before > datetime('now') \
                 AND wake_at >= not_before THEN 1 ELSE 0 END AS gated \
                 FROM queue WHERE task_id = ?",
            )
            .bind(claimed[0].task_id.clone())
            .fetch_scalar::<i64>()
            .await
            .expect("read not_before gate");
        assert_eq!(gated, 1);

        // The backoff gates the retry — nothing claims it now — and a
        // re-request neither resurrects nor clears the gate.
        enqueue(&db, &[request("flaky", Vec::new())])
            .await
            .expect("re-request");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert!(claimed.is_empty());
        assert_eq!(row_column(&db, "flaky", "status").await, "pending");
        assert_eq!(row_column(&db, "flaky", "CAST(attempt AS TEXT)").await, "2");
    }

    /// A failure at the attempt cap parks the row `failed` — no
    /// resurrection, no backoff, no claim; only the operator's
    /// `retry` returns it to `pending`.
    #[tokio::test]
    async fn failed_build_at_the_attempt_cap_parks_failed() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("flaky", Vec::new())])
            .await
            .expect("enqueue");
        set_first_requested_at(&db, "flaky", PAST_TS).await;

        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        db.query("UPDATE queue SET attempt = ? WHERE task_id = ?")
            .bind(i64::from(super::MAX_BUILD_ATTEMPTS))
            .bind(claimed[0].task_id.clone())
            .execute()
            .await
            .expect("set attempt to the cap");
        super::complete(
            &db,
            &claim_settings(),
            &report(
                &claimed[0].task_id,
                &claimed[0].generation_id,
                super::MAX_BUILD_ATTEMPTS,
                false,
            ),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete");
        assert_eq!(row_column(&db, "flaky", "status").await, "failed");
        assert_eq!(
            row_column(&db, "flaky", "CAST(attempt AS TEXT)").await,
            super::MAX_BUILD_ATTEMPTS.to_string()
        );

        // A re-request is a no-op: `failed` never resurrects.
        enqueue(&db, &[request("flaky", Vec::new())])
            .await
            .expect("re-request");
        assert_eq!(row_column(&db, "flaky", "status").await, "failed");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert!(claimed.is_empty());
    }

    /// The lane an operator's rebuild submit takes: a completed
    /// row ignores a miss-lane re-request (its artifacts sit in the
    /// catalog), but the human lane — the lane an operator's re-request
    /// rides — resurrects it. With the catalog's coverage oracle no
    /// longer covering the over-floor row, the resurrected rebuild
    /// claims rather than retiring.
    #[tokio::test]
    async fn human_rerequest_resurrects_completed_and_claims() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("stale-glibc", Vec::new())])
            .await
            .expect("enqueue");
        set_first_requested_at(&db, "stale-glibc", PAST_TS).await;

        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        super::complete(
            &db,
            &claim_settings(),
            &super::BuildCompleteReport {
                task_id: claimed[0].task_id.clone(),
                generation_id: claimed[0].generation_id.clone(),
                attempt: claimed[0].attempt,
                success: true,
                error: None,
                finished_at: None,
                github_run_id: None,
            },
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete");

        // A miss-lane re-request is a no-op against a completed row.
        enqueue(&db, &[request("stale-glibc", Vec::new())])
            .await
            .expect("miss re-request");
        assert!(
            super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
                .await
                .expect("claim")
                .is_empty()
        );

        // The human lane resurrects it, and the oracle that no longer
        // covers the over-floor catalog row offers nothing to retire
        // against — the rebuild claims.
        let human = EnqueueRequest {
            source: EnqueueSource::HumanRequest,
            ..request("stale-glibc", Vec::new())
        };
        super::enqueue_trusted(&db, &[human], &claim_settings())
            .await
            .expect("human re-request");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "stale-glibc");
    }

    #[tokio::test]
    async fn github_app_token_cache_reuses_fresh_token() {
        let db = memory_db().await.expect("memory db");
        assert!(
            super::github_app_token(&db).await.expect("read").is_none(),
            "empty cache yields no token"
        );

        let stored = token();
        super::store_github_app_token(&db, &stored)
            .await
            .expect("store");
        let cached = super::github_app_token(&db)
            .await
            .expect("read")
            .expect("fresh token is cached");
        assert_eq!(cached.token, stored.token);
        assert_eq!(cached.expires_at, stored.expires_at);
    }

    #[tokio::test]
    async fn github_app_token_cache_drops_token_inside_refresh_margin() {
        let db = memory_db().await.expect("memory db");
        super::store_github_app_token(&db, &token())
            .await
            .expect("store");
        // Four minutes out is inside the five-minute reuse floor: the
        // cached token must not be served.
        set_cached_expiry(&db, "+4 minutes").await;
        assert!(
            super::github_app_token(&db).await.expect("read").is_none(),
            "token inside the refresh margin must not be reused"
        );
    }

    #[tokio::test]
    async fn github_app_token_cache_drops_expired_token() {
        let db = memory_db().await.expect("memory db");
        super::store_github_app_token(&db, &token())
            .await
            .expect("store");
        set_cached_expiry(&db, "-1 minutes").await;
        assert!(
            super::github_app_token(&db).await.expect("read").is_none(),
            "expired token must not be reused"
        );
    }

    #[tokio::test]
    async fn github_app_token_store_overwrites_singleton_row() {
        let db = memory_db().await.expect("memory db");
        super::store_github_app_token(&db, &token())
            .await
            .expect("store first");
        let replacement = crate::github_app::InstallationToken {
            token: "ghs_replacement".to_owned(),
            expires_at: "2099-06-01T00:00:00Z".to_owned(),
        };
        super::store_github_app_token(&db, &replacement)
            .await
            .expect("store second");
        let cached = super::github_app_token(&db)
            .await
            .expect("read")
            .expect("token is cached");
        assert_eq!(cached.token, "ghs_replacement");
        assert_eq!(cached.expires_at, "2099-06-01T00:00:00Z");
    }

    fn human_request(crate_name: &str) -> EnqueueRequest {
        EnqueueRequest {
            source: EnqueueSource::HumanRequest,
            ..request(crate_name, Vec::new())
        }
    }

    /// The unattended preheat wave re-submits the whole top-N list on
    /// every tick. A completed row's artifacts are already in the
    /// catalog, so a miss-lane re-request leaves it completed instead of
    /// rebuilding the pool on a timer.
    #[tokio::test]
    async fn a_preheat_re_request_does_not_rebuild_a_completed_task() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("alpha", Vec::new())])
            .await
            .expect("enqueue");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        let id = claimed[0].task_id.clone();
        super::complete(
            &db,
            &claim_settings(),
            &report(&id, &claimed[0].generation_id, 1, true),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete");

        enqueue(
            &db,
            &[EnqueueRequest {
                source: EnqueueSource::CrateUpdate,
                ..request("alpha", Vec::new())
            }],
        )
        .await
        .expect("preheat re-request");

        let row = db
            .query("SELECT status, attempt FROM queue WHERE task_id = ?")
            .bind(id)
            .fetch_optional::<super::AttemptStatusRow>()
            .await
            .expect("row")
            .expect("row exists");
        assert_eq!(row.status, "completed");
        assert_eq!(row.attempt, 1);
        assert!(
            super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
                .await
                .expect("claim")
                .is_empty(),
            "a completed preheat task must not dispatch again"
        );
    }

    /// Convergence is the other half: an identity whose build failed
    /// stays in the queue — the failure report re-queues it behind its
    /// backoff — so the coverage the preheat lane asked for is
    /// eventually reached without anyone dispatching by hand. The
    /// wave's re-submit leaves the retry untouched.
    #[tokio::test]
    async fn a_preheat_re_request_retries_a_failed_task() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("alpha", Vec::new())])
            .await
            .expect("enqueue");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        let id = claimed[0].task_id.clone();
        super::complete(
            &db,
            &claim_settings(),
            &report(&id, &claimed[0].generation_id, 1, false),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("fail the build");

        enqueue(
            &db,
            &[EnqueueRequest {
                source: EnqueueSource::CrateUpdate,
                ..request("alpha", Vec::new())
            }],
        )
        .await
        .expect("preheat re-request");

        let row = db
            .query("SELECT status, attempt FROM queue WHERE task_id = ?")
            .bind(id)
            .fetch_optional::<super::AttemptStatusRow>()
            .await
            .expect("row")
            .expect("row exists");
        assert_eq!(row.status, "pending");
        assert_eq!(row.attempt, 2);
    }

    /// A task whose exact identity an artifact publish already covered is
    /// retired at claim time — `completed`, never dispatched — and the
    /// oracle is asked only about plain crates.io rows.
    #[tokio::test]
    async fn claim_retires_tasks_the_catalog_already_covers() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                request("covered", Vec::new()),
                request("uncovered", Vec::new()),
                EnqueueRequest {
                    preserve_lockfile: true,
                    ..request("lockfile", Vec::new())
                },
            ],
        )
        .await
        .expect("enqueue");
        let oracle = FixedCoverage {
            covered: BTreeSet::from([semantic_identity("covered")]),
            asked: std::sync::Mutex::new(Vec::new()),
        };
        let settings = SchedulerSettings {
            dispatch: Dispatch::from_max_concurrent_jobs(10),
            dispatch_min_age_minutes: 0,
            ..settings()
        };

        let claimed = super::claim_dispatchable_tasks(&db, &settings, &oracle)
            .await
            .expect("claim");
        let mut claimed_names = claimed
            .iter()
            .map(|task| task.crate_name.as_str())
            .collect::<Vec<_>>();
        claimed_names.sort_unstable();
        assert_eq!(claimed_names, ["lockfile", "uncovered"]);
        assert_eq!(
            oracle.asked.lock().expect("oracle log").as_slice(),
            [semantic_identity("covered"), semantic_identity("uncovered")]
        );
        let status = db
            .query("SELECT status FROM queue WHERE task_id = ?")
            .bind(crate_task_id("covered"))
            .fetch_scalar::<String>()
            .await
            .expect("status");
        assert_eq!(status, "completed");
    }

    fn crate_task_id(crate_name: &str) -> String {
        task_id(crate_name, VERSION, FEATURES, TARGET, RUSTC, false)
    }

    /// Both rows are eligible to claim here: the miss row is aged past the
    /// dispatch minimum, the human row is exempt from it — so the only
    /// thing deciding order is the lane.
    #[tokio::test]
    async fn human_task_dispatches_before_older_miss_task() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("missed", Vec::new())])
            .await
            .expect("enqueue miss");
        enqueue(&db, &[human_request("asked")])
            .await
            .expect("enqueue human");
        set_first_requested_at(&db, "missed", PAST_TS).await;

        let claimed = super::claim_dispatchable_tasks(&db, &settings(), &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 2);
        assert_eq!(claimed[0].crate_name, "asked");
        assert_eq!(claimed[1].crate_name, "missed");
    }

    /// A miss-lane task enqueued a second ago would sit out the whole
    /// minimum-age window; the same-age human task must be claimable now.
    #[tokio::test]
    async fn human_task_bypasses_dispatch_min_age() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("missed", Vec::new())])
            .await
            .expect("enqueue miss");
        enqueue(&db, &[human_request("asked")])
            .await
            .expect("enqueue human");

        let settings = SchedulerSettings {
            dispatch_min_age_minutes: 60,
            ..settings()
        };
        let claimed = super::claim_dispatchable_tasks(&db, &settings, &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "asked");
    }

    #[tokio::test]
    async fn human_rerequest_promotes_miss_task() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("asked", Vec::new())])
            .await
            .expect("enqueue miss");
        let status = super::task_status(&db, &crate_task_id("asked"))
            .await
            .expect("task status")
            .expect("row exists");
        assert_eq!(status.lane, stow_types::api::TaskLane::Miss);

        enqueue(&db, &[human_request("asked")])
            .await
            .expect("re-request through human path");
        let status = super::task_status(&db, &crate_task_id("asked"))
            .await
            .expect("task status")
            .expect("row exists");
        assert_eq!(status.lane, stow_types::api::TaskLane::Human);
    }

    #[tokio::test]
    async fn miss_rerequest_never_demotes_human_task() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[human_request("asked")])
            .await
            .expect("enqueue human");
        enqueue(&db, &[request("asked", Vec::new())])
            .await
            .expect("re-request through miss path");

        let status = super::task_status(&db, &crate_task_id("asked"))
            .await
            .expect("task status")
            .expect("row exists");
        assert_eq!(status.lane, stow_types::api::TaskLane::Human);
    }

    /// A pending human task is eligible now, so with capacity free the
    /// alarm must fire immediately instead of at `first_requested_at +
    /// min_age` like a miss task would.
    #[tokio::test]
    async fn pending_human_task_makes_alarm_eligible_now() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[human_request("asked")])
            .await
            .expect("enqueue human");

        let settings = SchedulerSettings {
            dispatch_min_age_minutes: 60,
            ..settings()
        };
        let now_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock before epoch")
                .as_millis(),
        )
        .expect("epoch millis fits in i64");
        let plan = next_alarm(&db, now_ms, &settings)
            .await
            .expect("next_alarm");
        // Eligible-at-now resolves to `max(eligible, now)`; a miss task
        // this young would instead schedule ~an hour out. Allow a couple of
        // seconds of clock drift between the test capture and SQLite's
        // `datetime('now')`.
        match plan {
            AlarmPlan::At(ms) => {
                assert!(ms <= now_ms + 2_000, "alarm {ms} is not ~now ({now_ms})");
            }
            AlarmPlan::Delete => panic!("pending human task must wake the alarm now"),
        }
    }

    #[tokio::test]
    async fn status_reports_human_pending_separately() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[request("missed", Vec::new()), human_request("asked")],
        )
        .await
        .expect("enqueue");

        let status = super::status(&db).await.expect("status");
        assert_eq!(status.pending, 2);
        assert_eq!(status.human_pending, 1);
    }

    /// Position is 1-based in human-lane dispatch order: the older human
    /// task is first, the younger one second.
    #[tokio::test]
    async fn task_status_reports_human_lane_position() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[human_request("first"), human_request("second")])
            .await
            .expect("enqueue");
        set_first_requested_at(&db, "first", PAST_TS).await;

        let first = super::task_status(&db, &crate_task_id("first"))
            .await
            .expect("task status")
            .expect("row exists");
        let second = super::task_status(&db, &crate_task_id("second"))
            .await
            .expect("task status")
            .expect("row exists");
        assert_eq!(first.human_lane_position, Some(1));
        assert_eq!(second.human_lane_position, Some(2));
    }

    /// Two human tasks in one submit batch share `first_requested_at`,
    /// `priority`, and `created_at`, so only the `task_id` tiebreaker can
    /// order them — positions must follow ascending task id and match the
    /// order `claim_dispatchable_tasks` dispatches in.
    #[tokio::test]
    async fn human_lane_position_ties_break_on_task_id() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[human_request("zed"), human_request("alpha")])
            .await
            .expect("enqueue");
        // `task_id("alpha") < task_id("zed")` on the crate-name segment —
        // pin every ordering column above it to identical values so
        // task_id is the only key that can decide.
        for name in ["alpha", "zed"] {
            set_first_requested_at(&db, name, PAST_TS).await;
        }
        db.query("UPDATE queue SET created_at = ?")
            .bind(ROW_TS.to_owned())
            .execute()
            .await
            .expect("pin created_at");

        let alpha = super::task_status(&db, &crate_task_id("alpha"))
            .await
            .expect("task status")
            .expect("row exists");
        let zed = super::task_status(&db, &crate_task_id("zed"))
            .await
            .expect("task status")
            .expect("row exists");
        assert_eq!(alpha.human_lane_position, Some(1));
        assert_eq!(zed.human_lane_position, Some(2));

        // The position must equal true dispatch order.
        let claimed = super::claim_dispatchable_tasks(&db, &settings(), &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 2);
        assert_eq!(claimed[0].crate_name, "alpha");
        assert_eq!(claimed[1].crate_name, "zed");
    }

    /// Positions order exactly when `value` sits above the workerd
    /// cursor's JS-safe integer range: two human rows whose values
    /// differ by 1 — far past 2^53, where a JS-number decode would
    /// collapse them to one float — still rank correctly through the
    /// persisted TEXT `dispatch_key` (stow#442 I6).
    #[tokio::test]
    async fn human_lane_position_orders_values_above_js_safe_integer() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[human_request("below"), human_request("above")])
            .await
            .expect("enqueue");
        for (name, priority) in [("below", 1_000_005_i64), ("above", 1_000_006_i64)] {
            db.query("UPDATE queue SET priority = ? WHERE task_id = ?")
                .bind(priority)
                .bind(crate_task_id(name))
                .execute()
                .await
                .expect("set priority");
        }
        super::refresh_dispatch_keys(&db, &[crate_task_id("below"), crate_task_id("above")])
            .await
            .expect("refresh claim order");
        // Guard the premise: the human band puts both rows' stored
        // values above 2^53, the range the JS cursor cannot represent.
        let stored = db
            .query("SELECT value FROM queue WHERE task_id = ?")
            .bind(crate_task_id("below"))
            .fetch_scalar::<i64>()
            .await
            .expect("stored value");
        assert!(stored > (1_i64 << 53));

        let below = super::task_status(&db, &crate_task_id("below"))
            .await
            .expect("task status")
            .expect("row exists");
        let above = super::task_status(&db, &crate_task_id("above"))
            .await
            .expect("task status")
            .expect("row exists");
        assert_eq!(above.human_lane_position, Some(1));
        assert_eq!(below.human_lane_position, Some(2));
    }

    #[tokio::test]
    async fn task_status_omits_position_outside_pending_human_lane() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("missed", Vec::new())])
            .await
            .expect("enqueue");

        let status = super::task_status(&db, &crate_task_id("missed"))
            .await
            .expect("task status")
            .expect("row exists");
        assert_eq!(status.lane, stow_types::api::TaskLane::Miss);
        assert_eq!(status.human_lane_position, None);
        assert!(
            super::task_status(&db, "no-such-task")
                .await
                .expect("task status")
                .is_none(),
            "unknown task id yields None"
        );
    }

    /// A report for a task the queue holds only applies while the row is
    /// in flight under the reported attempt; the completion path can no
    /// longer be exercised without a claim.
    #[tokio::test]
    async fn complete_marks_a_held_task_and_rejects_an_unknown_one() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("alpha", Vec::new())])
            .await
            .expect("enqueue");
        let id = task_id("alpha", VERSION, FEATURES, TARGET, RUSTC, false);
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].attempt, 1);

        super::complete(
            &db,
            &claim_settings(),
            &super::BuildCompleteReport {
                task_id: id.clone(),
                generation_id: claimed[0].generation_id.clone(),
                attempt: claimed[0].attempt,
                success: true,
                error: None,
                finished_at: None,
                github_run_id: None,
            },
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete a held task");
        let status = db
            .query("SELECT status FROM queue WHERE task_id = ?")
            .bind(id)
            .fetch_scalar::<String>()
            .await
            .expect("status");
        assert_eq!(status, "completed");

        // The DO maps this variant to 404: a report naming a task the
        // queue never held is a client error, not a server failure.
        let error = super::complete(
            &db,
            &claim_settings(),
            &super::BuildCompleteReport {
                task_id: "never-enqueued".to_owned(),
                generation_id: "unknown-generation".to_owned(),
                attempt: 1,
                success: true,
                error: None,
                finished_at: None,
                github_run_id: None,
            },
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect_err("an unknown task must be rejected");
        assert!(matches!(
            error,
            crate::errors::QueueError::UnknownTask(ref task_id)
                if task_id == "never-enqueued"
        ));
    }

    /// The regression this field exists for: attempt 1's report arriving
    /// after the row was resurrected to attempt 2 must not overwrite the
    /// new attempt's state — a report that matches no in-flight row is a
    /// `StaleCompletion` (409 at the handler), never a silent success.
    #[tokio::test]
    async fn stale_report_for_a_superseded_attempt_leaves_the_live_row_untouched() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("alpha", Vec::new())])
            .await
            .expect("enqueue");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        let id = claimed[0].task_id.clone();

        super::complete(
            &db,
            &claim_settings(),
            &report(&id, &claimed[0].generation_id, 1, true),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete attempt 1");
        // A human re-request resurrects the completed row as attempt 2,
        // and the resurrected row dispatches again.
        enqueue(&db, &[human_request("alpha")])
            .await
            .expect("re-request");
        let reclaimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("re-claim");
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].attempt, 2);

        let error = super::complete(
            &db,
            &claim_settings(),
            &report(&id, &claimed[0].generation_id, 1, true),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect_err("a report for attempt 1 must not apply to attempt 2");
        assert!(matches!(
            error,
            crate::errors::QueueError::StaleCompletion { .. }
        ));

        let row = db
            .query("SELECT status, attempt FROM queue WHERE task_id = ?")
            .bind(id.clone())
            .fetch_optional::<super::AttemptStatusRow>()
            .await
            .expect("row")
            .expect("row exists");
        assert_eq!(row.attempt, 2);
        assert_eq!(row.status, "dispatched");

        // And the report for the live attempt still completes normally.
        super::complete(
            &db,
            &claim_settings(),
            &report(&id, &reclaimed[0].generation_id, 2, true),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete attempt 2");
        let status = db
            .query("SELECT status FROM queue WHERE task_id = ?")
            .bind(id)
            .fetch_scalar::<String>()
            .await
            .expect("status");
        assert_eq!(status, "completed");
    }

    /// A second report for the attempt that already applied is a
    /// duplicate, not a success: the row is already terminal, so the same
    /// stale-completion rejection answers it.
    #[tokio::test]
    async fn duplicate_report_for_the_current_attempt_conflicts() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("alpha", Vec::new())])
            .await
            .expect("enqueue");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        let id = claimed[0].task_id.clone();

        super::complete(
            &db,
            &claim_settings(),
            &report(&id, &claimed[0].generation_id, 1, true),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete");
        let error = super::complete(
            &db,
            &claim_settings(),
            &report(&id, &claimed[0].generation_id, 1, true),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect_err("a duplicate report must conflict");
        assert!(matches!(
            error,
            crate::errors::QueueError::StaleCompletion { .. }
        ));

        let status = db
            .query("SELECT status FROM queue WHERE task_id = ?")
            .bind(id)
            .fetch_scalar::<String>()
            .await
            .expect("status");
        assert_eq!(status, "completed");
    }

    /// Mark one crate's semantic identity served by the `(TARGET, RUSTC)`
    /// slice — the state `stow-admin index report` produces through
    /// `record_published_slice` after `index publish` lands. The rows
    /// cover the shapes a native `(TARGET)` consumer's target-side dep
    /// edge requires: its own invocation, both kinds.
    async fn publish(db: &DurableDb, crate_name: &str) {
        let rows = [UnitKind::Linked, UnitKind::Unlinked]
            .iter()
            .map(|kind| stow_types::api::PublishedSliceRow {
                crate_name: crate_name.parse().expect("valid crate name"),
                version: VERSION.parse().expect("valid semver"),
                features_json: FeaturesJson::default(),
                unit_shape: Some(shape(UnitSide::Target, UnitInvocation::Native, *kind)),
            })
            .collect::<Vec<_>>();
        super::record_published_slice(db, TARGET, RUSTC, None, None, &rows, &[])
            .await
            .expect("record published slice");
    }

    /// The same, carrying the row's unit shape — what `index report`
    /// sends once the publish path registers the builder-recorded shape
    /// (`None` is the legacy shapeless row that covers nothing).
    async fn publish_shapes(db: &DurableDb, crate_name: &str, target: &str, shapes: &[UnitShape]) {
        let rows = shapes
            .iter()
            .map(|shape| stow_types::api::PublishedSliceRow {
                crate_name: crate_name.parse().expect("valid crate name"),
                version: VERSION.parse().expect("valid semver"),
                features_json: FeaturesJson::default(),
                unit_shape: Some(*shape),
            })
            .collect::<Vec<_>>();
        super::record_published_slice(db, target, RUSTC, None, None, &rows, &[])
            .await
            .expect("record shaped published slice");
    }

    /// Completed is not servable: a dependency whose build landed but
    /// whose slice has not been republished yet must not release its
    /// dependent — the dependent's build resolves the dependency from
    /// the signed index, and only a publish makes it appear there.
    #[tokio::test]
    async fn dependent_waits_for_a_completed_dependency_until_it_is_published() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("dep", Vec::new())])
            .await
            .expect("enqueue dep");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim dep");
        assert_eq!(claimed.len(), 1);
        super::complete(
            &db,
            &claim_settings(),
            &report(
                &claimed[0].task_id,
                &claimed[0].generation_id,
                claimed[0].attempt,
                true,
            ),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete dep");

        enqueue(&db, &[request("parent", vec![dependency("dep")])])
            .await
            .expect("enqueue parent");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim parent");
        assert!(
            claimed.is_empty(),
            "a completed-but-unpublished dependency must not release its dependent"
        );
        assert_eq!(row_column(&db, "parent", "status").await, "pending");

        publish(&db, "dep").await;
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim parent after publish");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "parent");
    }

    /// A failed dependency on its retry backoff keeps its dependents
    /// waiting: the failure report re-queues it `pending`, not
    /// published, so the gate holds the parent until a build and a
    /// publish land.
    #[tokio::test]
    async fn dependent_waits_while_a_failed_dependency_retries() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("dep", Vec::new())])
            .await
            .expect("enqueue dep");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim dep");
        super::complete(
            &db,
            &claim_settings(),
            &report(
                &claimed[0].task_id,
                &claimed[0].generation_id,
                claimed[0].attempt,
                false,
            ),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("fail dep");

        // The dep is already `pending` behind its retry backoff —
        // retrying, not terminal — and the parent's submit is a no-op
        // against it.
        enqueue(&db, &[request("parent", vec![dependency("dep")])])
            .await
            .expect("enqueue parent");
        assert_eq!(row_column(&db, "dep", "status").await, "pending");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert!(
            claimed.is_empty(),
            "neither the backoff-gated retry nor its unpublished dependent may claim"
        );
    }

    /// A dependency that fails for good leaves its dependents settled
    /// behind it: reporting `blocked`, naming the failed dependency,
    /// and never dispatched — no dispatching the dependent to compile
    /// the dependency itself. Retrying the dependency returns the
    /// dependent to `pending`, since the dependent's `blocked` is a
    /// flag the dep's status flips maintain, not its own verdict.
    #[tokio::test]
    async fn dependent_settles_blocked_behind_a_terminally_failed_dependency() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("dep", Vec::new())])
            .await
            .expect("enqueue dep");
        enqueue(&db, &[request("parent", vec![dependency("dep")])])
            .await
            .expect("enqueue parent");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim dep");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "dep");
        // The terminal failure: the last permitted attempt fails and
        // the row parks `failed`.
        db.query("UPDATE queue SET attempt = ? WHERE task_id = ?")
            .bind(i64::from(super::MAX_BUILD_ATTEMPTS))
            .bind(claimed[0].task_id.clone())
            .execute()
            .await
            .expect("set attempt to the cap");
        super::complete(
            &db,
            &claim_settings(),
            &report(
                &claimed[0].task_id,
                &claimed[0].generation_id,
                super::MAX_BUILD_ATTEMPTS,
                false,
            ),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("fail dep");
        assert_eq!(row_column(&db, "dep", "status").await, "failed");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim after terminal failure");
        assert!(
            claimed.is_empty(),
            "a terminally failed dependency must leave its dependent undispatched"
        );
        // Stored status stays `pending`; the read paths surface `blocked`
        // with the failed dependency's task id.
        assert_eq!(row_column(&db, "parent", "status").await, "pending");
        let parent = super::task_status(&db, &task_id_on("parent", TARGET))
            .await
            .expect("read parent status")
            .expect("parent row");
        assert_eq!(parent.status, stow_types::api::QueueTaskStatus::Blocked);
        assert_eq!(
            parent.blocked_by.as_deref(),
            Some(task_id_on("dep", TARGET).as_str()),
            "the blocked report must name the failed dependency's task id"
        );
        let listed = super::list_tasks(
            &db,
            &filter_selector(stow_types::api::QueueSelector {
                status: Some(stow_types::api::QueueTaskStatus::Blocked),
                ..Default::default()
            }),
        )
        .await
        .expect("list blocked tasks");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].crate_name, "parent");
        assert_eq!(
            listed[0].blocked_by.as_deref(),
            Some(task_id_on("dep", TARGET).as_str())
        );
        assert_eq!(super::status(&db).await.expect("status").blocked, 1);

        // Retrying the dependency returns the dependent to `pending`
        // — nothing to reconcile, the flag refresh just stops firing.
        let affected = super::apply_mutation(
            &db,
            &settings(),
            super::QueueMutation::Retry,
            &filter_selector(stow_types::api::QueueSelector {
                status: Some(stow_types::api::QueueTaskStatus::Failed),
                ..Default::default()
            }),
        )
        .await
        .expect("retry dep");
        assert_eq!(affected, 1, "only the failed dep moves");
        assert_eq!(row_column(&db, "dep", "status").await, "pending");
        assert_eq!(row_column(&db, "dep", "CAST(attempt AS TEXT)").await, "1");
        let parent = super::task_status(&db, &task_id_on("parent", TARGET))
            .await
            .expect("read parent status after retry")
            .expect("parent row");
        assert_eq!(parent.status, stow_types::api::QueueTaskStatus::Pending);
        assert_eq!(parent.blocked_by, None);
    }

    /// The owner's persisted gate counters — `(unpublished_deps,
    /// deps_met)` as stored, not the status derivation.
    async fn gate_counters(db: &DurableDb, crate_name: &str) -> (i64, i64) {
        #[derive(skyzen::FromRow)]
        struct GateCounters {
            unpublished_deps: i64,
            deps_met: i64,
        }
        let counters = db
            .query("SELECT unpublished_deps, deps_met FROM queue WHERE task_id = ?")
            .bind(task_id_on(crate_name, TARGET))
            .fetch_one::<GateCounters>()
            .await
            .expect("read gate counters");
        (counters.unpublished_deps, counters.deps_met)
    }

    /// Each edge's stored `dep_met` flag, keyed by dep crate.
    async fn edge_flags(db: &DurableDb) -> Vec<(String, i64)> {
        #[derive(skyzen::FromRow)]
        struct EdgeFlag {
            dep_crate_name: String,
            dep_met: i64,
        }
        let mut flags: Vec<(String, i64)> = db
            .query(
                "SELECT dep_crate_name, dep_met FROM queue_dependencies \
                 ORDER BY dep_crate_name",
            )
            .fetch_all::<EdgeFlag>()
            .await
            .expect("edge flags")
            .into_iter()
            .map(|edge| (edge.dep_crate_name, edge.dep_met))
            .collect();
        flags.sort();
        flags
    }

    /// The `PublishedSliceRow` set `publish` registers for a crate —
    /// both kinds under the target side's native invocation — so a
    /// delta report can add or retire exactly those rows.
    fn dep_slice_rows(crate_name: &str) -> Vec<stow_types::api::PublishedSliceRow> {
        [UnitKind::Linked, UnitKind::Unlinked]
            .iter()
            .map(|kind| stow_types::api::PublishedSliceRow {
                crate_name: crate_name.parse().expect("valid crate name"),
                version: VERSION.parse().expect("valid semver"),
                features_json: FeaturesJson::default(),
                unit_shape: Some(shape(UnitSide::Target, UnitInvocation::Native, *kind)),
            })
            .collect()
    }

    /// A mixed dep set lands the slice answer per edge — the same
    /// EXISTS the gate used to replay per evaluation, run once at
    /// insert — and the owner counts its unmet edges, so `deps_met` is
    /// the counter's zero (stow#521).
    #[tokio::test]
    async fn enqueue_writes_each_edge_s_answer_and_counts_unpublished_deps() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                request("served-dep", Vec::new()),
                request("absent-dep", Vec::new()),
            ],
        )
        .await
        .expect("enqueue deps");
        publish(&db, "served-dep").await;

        enqueue(
            &db,
            &[request(
                "parent",
                vec![dependency("served-dep"), dependency("absent-dep")],
            )],
        )
        .await
        .expect("enqueue parent");

        assert_eq!(
            edge_flags(&db).await,
            vec![("absent-dep".to_owned(), 0), ("served-dep".to_owned(), 1),],
            "dep_met is the slice answer at edge-write time"
        );
        assert_eq!(gate_counters(&db, "parent").await, (1, 0));
        assert_eq!(gate_counters(&db, "absent-dep").await, (0, 1));
    }

    /// A publish delta flips exactly the edges its rows match — the
    /// already-met edge does not move — and each owner's counter tracks
    /// the flips, so reaching zero releases the pending row to claim.
    #[tokio::test]
    async fn a_slice_delta_flips_the_matched_edges_and_moves_the_counter() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                request("first-dep", Vec::new()),
                request("second-dep", Vec::new()),
            ],
        )
        .await
        .expect("enqueue deps");
        publish(&db, "first-dep").await;
        enqueue(
            &db,
            &[request(
                "parent",
                vec![dependency("first-dep"), dependency("second-dep")],
            )],
        )
        .await
        .expect("enqueue parent");
        assert_eq!(gate_counters(&db, "parent").await, (1, 0));

        // A delta report on the live generation adds only second-dep's
        // rows: the first-dep edge is already met and must not flip.
        super::record_published_slice(
            &db,
            TARGET,
            RUSTC,
            Some(1),
            None,
            &dep_slice_rows("second-dep"),
            &[],
        )
        .await
        .expect("delta publish second-dep");

        assert_eq!(
            edge_flags(&db).await,
            vec![("first-dep".to_owned(), 1), ("second-dep".to_owned(), 1),]
        );
        assert_eq!(gate_counters(&db, "parent").await, (0, 1));
        let claimed = super::claim_dispatchable_tasks(
            &db,
            &SchedulerSettings {
                dispatch: Dispatch::from_max_concurrent_jobs(8),
                ..claim_settings()
            },
            &NoCoverage,
        )
        .await
        .expect("claim after delta");
        assert!(
            claimed.iter().any(|task| task.crate_name == "parent"),
            "an owner whose counter reaches 0 dispatches"
        );
    }

    /// Membership removal is a delta like any other: retiring a dep's
    /// rows flips its matched edges back to unmet and the owner's
    /// counter increments — the publish path stays symmetric.
    #[tokio::test]
    async fn a_slice_delta_retire_flips_the_edges_back_and_increments_the_counter() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("dep", Vec::new())])
            .await
            .expect("enqueue dep");
        enqueue(&db, &[request("parent", vec![dependency("dep")])])
            .await
            .expect("enqueue parent");
        publish(&db, "dep").await;
        assert_eq!(gate_counters(&db, "parent").await, (0, 1));

        // applied_generation is 1 after the first publish; the retire
        // delta reports against it.
        super::record_published_slice(
            &db,
            TARGET,
            RUSTC,
            Some(1),
            None,
            &[],
            &dep_slice_rows("dep"),
        )
        .await
        .expect("delta retire dep");

        assert_eq!(
            edge_flags(&db).await,
            vec![("dep".to_owned(), 0)],
            "a retire flips the matched edge back to unmet"
        );
        assert_eq!(gate_counters(&db, "parent").await, (1, 0));
        let claimed = super::claim_dispatchable_tasks(
            &db,
            &SchedulerSettings {
                dispatch: Dispatch::from_max_concurrent_jobs(8),
                ..claim_settings()
            },
            &NoCoverage,
        )
        .await
        .expect("claim after retire");
        assert!(
            claimed.iter().all(|task| task.crate_name != "parent"),
            "an owner whose counter returns above 0 stops dispatching"
        );
    }

    async fn fail_dependency_at_attempt(db: &DurableDb, name: &str, attempt: u32) {
        let id = task_id_on(name, TARGET);
        mark_active(db, name, TARGET, "dispatched").await;
        let generation = db
            .query("UPDATE queue SET attempt = ? WHERE task_id = ? RETURNING generation_id")
            .bind(i64::from(attempt))
            .bind(id.clone())
            .fetch_scalar::<String>()
            .await
            .expect("seed dependency failure attempt");
        super::complete(
            db,
            &claim_settings(),
            &report(&id, &generation, attempt, false),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete dependency failure");
    }

    #[tokio::test]
    async fn net_zero_slice_flips_refresh_blocked_and_replays_preserve_counters() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                request("failed-dep", Vec::new()),
                request("other-dep", Vec::new()),
            ],
        )
        .await
        .expect("enqueue deps");
        publish(&db, "other-dep").await;
        enqueue(
            &db,
            &[request(
                "parent",
                vec![dependency("failed-dep"), dependency("other-dep")],
            )],
        )
        .await
        .expect("enqueue parent");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim failed dependency");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "failed-dep");
        fail_dependency_at_attempt(&db, "failed-dep", super::MAX_BUILD_ATTEMPTS).await;
        assert_eq!(gate_counters(&db, "parent").await, (1, 0));
        assert_eq!(row_column(&db, "failed-dep", "status").await, "failed");
        assert_eq!(
            edge_flags(&db).await,
            vec![("failed-dep".to_owned(), 0), ("other-dep".to_owned(), 1),]
        );
        let parent = super::task_status(&db, &task_id_on("parent", TARGET))
            .await
            .expect("read parent status")
            .expect("parent row");
        assert_eq!(parent.status, stow_types::api::QueueTaskStatus::Blocked);
        assert_eq!(super::status(&db).await.expect("status").blocked, 1);

        // Several changed shapes match each edge, but each edge flips
        // only once. The owner's counter is unchanged while blocked
        // clears: the remaining unmet edge names a non-failed dep.
        for base in [1, 2] {
            super::record_published_slice(
                &db,
                TARGET,
                RUSTC,
                Some(base),
                None,
                &dep_slice_rows("failed-dep"),
                &dep_slice_rows("other-dep"),
            )
            .await
            .expect("swap or replay slice membership");
            assert_eq!(gate_counters(&db, "parent").await, (1, 0));
            assert_eq!(super::status(&db).await.expect("status").blocked, 0);
        }
        publish(&db, "other-dep").await;
        assert_eq!(gate_counters(&db, "parent").await, (1, 0));
        assert_eq!(super::status(&db).await.expect("status").blocked, 1);
    }

    #[tokio::test]
    async fn fatal_blocker_clears_and_reappears_across_net_counter_flips() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                request("fatal-dep", Vec::new()),
                request("dep-a", Vec::new()),
                request("dep-b", Vec::new()),
            ],
        )
        .await
        .expect("enqueue dependencies");
        let mut initial_rows = dep_slice_rows("dep-a");
        initial_rows.extend(dep_slice_rows("dep-b"));
        super::record_published_slice(&db, TARGET, RUSTC, None, None, &initial_rows, &[])
            .await
            .expect("publish nonfatal dependencies");
        enqueue(
            &db,
            &[request(
                "parent",
                vec![
                    dependency("fatal-dep"),
                    dependency("dep-a"),
                    dependency("dep-b"),
                ],
            )],
        )
        .await
        .expect("enqueue parent");
        mark_active(&db, "dep-a", TARGET, "completed").await;
        mark_active(&db, "dep-b", TARGET, "completed").await;
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim fatal dependency");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "fatal-dep");
        fail_dependency_at_attempt(&db, "fatal-dep", super::MAX_BUILD_ATTEMPTS).await;
        assert_eq!(gate_counters(&db, "parent").await, (1, 0));
        assert_parent_status(&db, stow_types::api::QueueTaskStatus::Blocked).await;

        let mut retired = dep_slice_rows("dep-a");
        retired.extend(dep_slice_rows("dep-b"));
        super::record_published_slice(
            &db,
            TARGET,
            RUSTC,
            Some(1),
            None,
            &dep_slice_rows("fatal-dep"),
            &retired,
        )
        .await
        .expect("clear fatal and retire two nonfatal deps");
        assert_eq!(gate_counters(&db, "parent").await, (2, 0));
        assert_parent_status(&db, stow_types::api::QueueTaskStatus::Pending).await;

        super::record_published_slice(
            &db,
            TARGET,
            RUSTC,
            Some(2),
            None,
            &retired,
            &dep_slice_rows("fatal-dep"),
        )
        .await
        .expect("reintroduce fatal blocker and serve nonfatal deps");
        assert_eq!(gate_counters(&db, "parent").await, (1, 0));
        assert_parent_status(&db, stow_types::api::QueueTaskStatus::Blocked).await;

        super::record_published_slice(
            &db,
            TARGET,
            RUSTC,
            Some(3),
            None,
            &[],
            &dep_slice_rows("dep-a"),
        )
        .await
        .expect("retire a nonfatal dependency while fatal remains unmet");
        assert_eq!(gate_counters(&db, "parent").await, (2, 0));
        assert_parent_status(&db, stow_types::api::QueueTaskStatus::Blocked).await;
    }

    /// The counter stays live on non-pending rows: an edge flip against
    /// a claimed owner still moves `unpublished_deps`, so the pending
    /// transition's cheap re-derivation can never disagree with the
    /// stored count.
    #[tokio::test]
    async fn the_counter_tracks_flips_on_a_claimed_owner_too() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("dep", Vec::new())])
            .await
            .expect("enqueue dep");
        enqueue(&db, &[request("parent", vec![dependency("dep")])])
            .await
            .expect("enqueue parent");
        mark_active(&db, "parent", TARGET, "dispatched").await;
        assert_eq!(gate_counters(&db, "parent").await, (1, 0));

        publish(&db, "dep").await;

        assert_eq!(
            gate_counters(&db, "parent").await,
            (0, 1),
            "a dispatched owner's counter still moves with the delta"
        );
    }

    /// A failed dependency whose identity the published slice already
    /// serves holds nothing back: the dependent still claims, so it
    /// reports `pending`, never `blocked`. Only an unmet edge blocks.
    #[tokio::test]
    async fn dependent_is_not_blocked_by_a_failed_dependency_the_slice_already_serves() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("dep", Vec::new())])
            .await
            .expect("enqueue dep");
        enqueue(&db, &[request("parent", vec![dependency("dep")])])
            .await
            .expect("enqueue parent");
        publish(&db, "dep").await;

        // The dependency's row is failed and republished — an operator
        // re-ran it after the slice went live and it failed again.
        mark_active(&db, "dep", TARGET, "failed").await;
        let parent = super::task_status(&db, &task_id_on("parent", TARGET))
            .await
            .expect("read parent status")
            .expect("parent row");
        assert_eq!(parent.status, stow_types::api::QueueTaskStatus::Pending);
        assert_eq!(parent.blocked_by, None);
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim parent");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "parent");
    }

    /// The gate releases when the dependency is later built and its
    /// slice republished — a terminal failure is a settlement, not a
    /// deadlock.
    #[tokio::test]
    async fn dependent_releases_when_the_dependency_later_succeeds_and_is_published() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("dep", Vec::new())])
            .await
            .expect("enqueue dep");
        enqueue(&db, &[request("parent", vec![dependency("dep")])])
            .await
            .expect("enqueue parent");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim dep");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "dep");
        fail_dependency_at_attempt(&db, "dep", super::MAX_BUILD_ATTEMPTS).await;
        assert_eq!(gate_counters(&db, "parent").await, (1, 0));
        assert_eq!(super::status(&db).await.expect("status").blocked, 1);

        // An operator starts a fresh retry cycle; even after success,
        // the dependent still waits for the slice that serves it.
        super::apply_mutation(
            &db,
            &claim_settings(),
            super::QueueMutation::Retry,
            &stow_types::api::QueueSelector {
                task_ids: vec![claimed[0].task_id.clone()],
                ..Default::default()
            },
        )
        .await
        .expect("retry terminal dependency");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim dep retry");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "dep");
        super::complete(
            &db,
            &claim_settings(),
            &report(
                &claimed[0].task_id,
                &claimed[0].generation_id,
                claimed[0].attempt,
                true,
            ),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete dep retry");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim before publish");
        assert!(claimed.is_empty(), "completed is still not servable");

        publish(&db, "dep").await;
        assert_eq!(
            gate_counters(&db, "parent").await,
            (0, 1),
            "publishing the only unmet edge reaches the counter-zero fast path"
        );
        assert_eq!(super::status(&db).await.expect("status").blocked, 0);
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim parent after publish");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "parent");
    }

    /// A republished slice replaces membership wholesale: an identity
    /// the new report no longer carries must not keep the gate open.
    #[tokio::test]
    async fn republishing_a_slice_replaces_its_membership() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("parent", vec![dependency("dep")])])
            .await
            .expect("enqueue parent");
        enqueue(&db, &[request("later", vec![dependency("other")])])
            .await
            .expect("enqueue later");
        publish(&db, "dep").await;

        // A later report without "dep" shrinks the slice: the edge's
        // record must track the latest publish, never the union.
        publish(&db, "other").await;
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim after shrink");
        assert_eq!(claimed.len(), 1);
        assert_eq!(
            claimed[0].crate_name, "later",
            "an identity absent from the latest report must hold its dependents, \
             and one it still serves must release"
        );
    }

    /// A `--target` dependent's host-side dep edge is served by the
    /// `--target` host shape alone: the slice's linked `debuginfo = 2`
    /// row releases it, while a slice holding only the native shape
    /// (`debuginfo = 1`) — what a host node's native-spelling run
    /// publishes — does not (stow#349).
    #[tokio::test]
    async fn cross_dependent_releases_on_the_target_shape_of_a_host_dep() {
        let db = memory_db().await.expect("memory db");
        let host_dep = EnqueueDependency {
            crate_name: "heck".parse().expect("valid crate name"),
            version: VERSION.parse().expect("valid semver"),
            features_json: FeaturesJson::default(),
            target: TARGET.parse().expect("valid target triple"),
            rustc_version: RUSTC.parse().expect("valid rustc version"),
            host_side: true,
        };
        enqueue(
            &db,
            &[request_on(
                "consumer",
                "wasm32-unknown-unknown",
                vec![host_dep],
            )],
        )
        .await
        .expect("enqueue consumer");

        publish_shapes(
            &db,
            "heck",
            TARGET,
            &[
                shape(UnitSide::Host, UnitInvocation::Native, UnitKind::Linked),
                shape(UnitSide::Host, UnitInvocation::Native, UnitKind::Unlinked),
            ],
        )
        .await;
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim with only the native shape");
        assert!(
            claimed.is_empty(),
            "the native host shape alone must not serve a `--target` consumer's host dep"
        );

        publish_shapes(
            &db,
            "heck",
            TARGET,
            &[
                shape(UnitSide::Host, UnitInvocation::Target, UnitKind::Linked),
                shape(UnitSide::Host, UnitInvocation::Target, UnitKind::Unlinked),
            ],
        )
        .await;
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim with the target shape");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "consumer");
    }

    /// A native dependent's host-side dep edge needs the native host
    /// shape (`debuginfo = 1`): the `--target` host shape it also
    /// carries does not release it — the exact mis-service the snafu-
    /// derive failure reported (stow#349).
    #[tokio::test]
    async fn native_dependent_needs_the_native_shape_of_a_host_dep() {
        let db = memory_db().await.expect("memory db");
        let host_dep = EnqueueDependency {
            crate_name: "heck".parse().expect("valid crate name"),
            version: VERSION.parse().expect("valid semver"),
            features_json: FeaturesJson::default(),
            target: TARGET.parse().expect("valid target triple"),
            rustc_version: RUSTC.parse().expect("valid rustc version"),
            host_side: true,
        };
        enqueue(&db, &[request("consumer", vec![host_dep])])
            .await
            .expect("enqueue consumer");

        publish_shapes(
            &db,
            "heck",
            TARGET,
            &[
                shape(UnitSide::Host, UnitInvocation::Target, UnitKind::Linked),
                shape(UnitSide::Host, UnitInvocation::Target, UnitKind::Unlinked),
            ],
        )
        .await;
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim with only the target shape");
        assert!(
            claimed.is_empty(),
            "the `--target` host shape must not serve a native consumer's host dep"
        );

        publish_shapes(
            &db,
            "heck",
            TARGET,
            &[
                shape(UnitSide::Host, UnitInvocation::Native, UnitKind::Linked),
                shape(UnitSide::Host, UnitInvocation::Native, UnitKind::Unlinked),
            ],
        )
        .await;
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim with the native shape");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "consumer");
    }

    /// A host-side dependent's own build runs both invocation spellings,
    /// so its host-side dep edge needs both host shapes: a slice
    /// missing either leaves the dependent held.
    #[tokio::test]
    async fn a_host_side_dependent_needs_both_shapes_of_a_host_dep() {
        let db = memory_db().await.expect("memory db");
        let host_dep = EnqueueDependency {
            crate_name: "heck".parse().expect("valid crate name"),
            version: VERSION.parse().expect("valid semver"),
            features_json: FeaturesJson::default(),
            target: TARGET.parse().expect("valid target triple"),
            rustc_version: RUSTC.parse().expect("valid rustc version"),
            host_side: true,
        };
        let mut owner = request("proc-macro-crate", vec![host_dep]);
        owner.host_side = true;
        enqueue(&db, &[owner])
            .await
            .expect("enqueue host-side owner");

        publish_shapes(
            &db,
            "heck",
            TARGET,
            &[
                shape(UnitSide::Host, UnitInvocation::Target, UnitKind::Linked),
                shape(UnitSide::Host, UnitInvocation::Target, UnitKind::Unlinked),
            ],
        )
        .await;
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim with one shape");
        assert!(
            claimed.is_empty(),
            "one host shape must not serve a dependent that builds under both invocations"
        );

        publish_shapes(
            &db,
            "heck",
            TARGET,
            &[
                shape(UnitSide::Host, UnitInvocation::Native, UnitKind::Linked),
                shape(UnitSide::Host, UnitInvocation::Native, UnitKind::Unlinked),
                shape(UnitSide::Host, UnitInvocation::Target, UnitKind::Linked),
                shape(UnitSide::Host, UnitInvocation::Target, UnitKind::Unlinked),
            ],
        )
        .await;
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim with both shapes");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "proc-macro-crate");
    }

    /// A real slice is every built node of a `(target, rustc)` pair —
    /// production reports run into the thousands — so a large report
    /// must record whole, partial tail included.
    #[tokio::test]
    async fn a_larger_slice_reports_whole() {
        const REPORT_ROWS: usize = 3_500;
        let db = memory_db().await.expect("memory db");
        let rows = (0..REPORT_ROWS)
            .flat_map(|index| {
                [UnitKind::Linked, UnitKind::Unlinked].map(|kind| {
                    stow_types::api::PublishedSliceRow {
                        crate_name: format!("crate-{index}").parse().expect("valid crate name"),
                        version: VERSION.parse().expect("valid semver"),
                        features_json: FeaturesJson::default(),
                        unit_shape: Some(shape(UnitSide::Target, UnitInvocation::Native, kind)),
                    }
                })
            })
            .collect::<Vec<_>>();
        super::record_published_slice(&db, TARGET, RUSTC, None, None, &rows, &[])
            .await
            .expect("record wide slice");

        let last = format!("crate-{}", REPORT_ROWS - 1);
        enqueue(&db, &[request("parent", vec![dependency(&last)])])
            .await
            .expect("enqueue parent");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim parent");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "parent");
    }

    /// A report that dies after inserting its rows but before flipping
    /// `published_slices.generation` leaves orphans at a generation no
    /// live pointer references. The next report must not inherit them:
    /// `ON CONFLICT DO NOTHING` would otherwise keep the leftover rows
    /// inside the generation it reuses, and the live set would silently
    /// include a crate the report never named.
    #[tokio::test]
    async fn a_crashed_reports_orphans_cannot_leak_into_the_next_report() {
        let db = memory_db().await.expect("memory db");
        publish(&db, "dep").await;

        // Simulate a crashed second report: rows land at a generation
        // above the committed one, then the writer dies before the flip.
        db.query(
            "INSERT INTO published_slice_rows \
             (target, rustc_version, generation, crate_name, version, features_json) \
             VALUES (?, ?, 2, 'stale', '1.0.0', '[]')",
        )
        .bind(TARGET.to_owned())
        .bind(RUSTC.to_owned())
        .execute()
        .await
        .expect("orphan crashed-report rows");

        // The real report publishes only "dep" — the orphaned "stale"
        // row must not survive into the live set.
        publish(&db, "dep").await;
        let live = db
            .query(
                "SELECT count(*) AS count FROM published_slice_rows p \
                 JOIN published_slices s \
                   ON s.target = p.target AND s.rustc_version = p.rustc_version \
                  AND s.generation = p.generation \
                 WHERE p.target = ? AND p.rustc_version = ?",
            )
            .bind(TARGET.to_owned())
            .bind(RUSTC.to_owned())
            .fetch_scalar::<i64>()
            .await
            .expect("count live slice rows");
        assert_eq!(
            live, 2,
            "the live set is exactly the second report's rows, both shapes"
        );

        enqueue(&db, &[request("stale-dep", vec![dependency("stale")])])
            .await
            .expect("enqueue stale dependent");
        enqueue(&db, &[request("fresh-dep", vec![dependency("dep")])])
            .await
            .expect("enqueue fresh dependent");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim after republish");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "fresh-dep");
    }

    /// An edge the migration could not backfill keeps `''` for the
    /// dependency's semantic identity — it can never resolve to a
    /// published row, so the dependent is blocked rather than pending
    /// forever, and the report says why.
    #[tokio::test]
    async fn an_unresolvable_dependency_edge_reports_blocked_with_unknown_identity() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("parent", vec![dependency("dep")])])
            .await
            .expect("enqueue parent");
        db.query("UPDATE queue_dependencies SET dep_crate_name = '' WHERE task_id = ?")
            .bind(task_id_on("parent", TARGET))
            .execute()
            .await
            .expect("erase dep identity");
        // The persisted `blocked` flag answers at write time: the only
        // production writer of an unresolved identity is the dev-era
        // migration backfill, which recomputes the flag itself — replay
        // that owner refresh here.
        super::refresh_deps_met_tasks(&db, &[task_id_on("parent", TARGET)])
            .await
            .expect("recompute blocked after identity erase");

        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim with unknown edge");
        assert!(claimed.is_empty());
        let parent = super::task_status(&db, &task_id_on("parent", TARGET))
            .await
            .expect("read parent status")
            .expect("parent row");
        assert_eq!(parent.status, stow_types::api::QueueTaskStatus::Blocked);
        assert_eq!(
            parent.blocked_by.as_deref(),
            Some("unknown dependency identity")
        );
        assert_eq!(super::status(&db).await.expect("status").blocked, 1);
    }

    fn report(
        task_id: &str,
        generation_id: &str,
        attempt: u32,
        success: bool,
    ) -> super::BuildCompleteReport {
        super::BuildCompleteReport {
            task_id: task_id.to_owned(),
            generation_id: generation_id.to_owned(),
            attempt,
            success,
            error: None,
            finished_at: None,
            github_run_id: None,
        }
    }

    fn report_with_run(
        task_id: &str,
        success: bool,
        github_run_id: &str,
    ) -> stow_types::api::WorkflowRunComplete {
        stow_types::api::WorkflowRunComplete {
            task_id: task_id.to_owned(),
            success,
            error: (!success).then(|| "build failed".to_owned()),
            github_run_id: Some(github_run_id.to_owned()),
        }
    }

    #[derive(skyzen::FromRow)]
    struct AttemptEvidenceRow {
        generation_id: String,
        attempt: i64,
        github_run_id: Option<String>,
    }

    async fn seed_failed_retry_cycle(db: &DurableDb, id: &str, cycle: &str) {
        for attempt in 1..=4 {
            mark_active(db, "flaky", TARGET, "dispatched").await;
            db.query(
                "UPDATE queue SET attempt = ?, generation_id = lower(hex(randomblob(16))) \
                 WHERE task_id = ?",
            )
            .bind(i64::from(attempt))
            .bind(id.to_owned())
            .execute()
            .await
            .expect("seed retry-cycle attempt");
            super::complete(
                db,
                &settings(),
                &super::BuildCompleteReport {
                    task_id: id.to_owned(),
                    generation_id: db
                        .query("SELECT generation_id FROM queue WHERE task_id = ?")
                        .bind(id.to_owned())
                        .fetch_scalar::<String>()
                        .await
                        .expect("retry-cycle generation"),
                    attempt,
                    success: false,
                    error: Some(format!("cycle-{cycle}-{attempt}")),
                    github_run_id: Some(format!("run-{cycle}-{attempt}")),
                    finished_at: None,
                },
                TEST_WINDOW_MINUTES,
            )
            .await
            .expect("record retry-cycle failure");
            if attempt == 1 {
                let short_backoff = db
                    .query(
                        "SELECT CASE WHEN not_before <= datetime('now', '+3 minutes') \
                         THEN 1 ELSE 0 END FROM queue WHERE task_id = ?",
                    )
                    .bind(id.to_owned())
                    .fetch_scalar::<i64>()
                    .await
                    .expect("read second-cycle backoff");
                assert_eq!(
                    short_backoff, 1,
                    "retry cycle backoff must restart at 2 minutes"
                );
            }
            db.query("UPDATE queue SET not_before = '1970-01-01 00:00:00', wake_at = '1970-01-01 00:00:00' WHERE task_id = ?")
                .bind(id.to_owned())
                .execute()
                .await
                .expect("open next retry-cycle attempt");
        }
    }

    #[tokio::test]
    async fn two_retry_cycles_keep_distinct_failure_evidence() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("flaky", Vec::new())])
            .await
            .expect("enqueue");
        let id = task_id_on("flaky", TARGET);

        seed_failed_retry_cycle(&db, &id, "a").await;

        super::apply_mutation(
            &db,
            &settings(),
            super::QueueMutation::Retry,
            &ids_selector(std::slice::from_ref(&id)),
        )
        .await
        .expect("operator retry");
        assert_eq!(
            row_column(&db, "flaky", "CAST(attempt AS TEXT)").await,
            "1",
            "operator retry resets the visible failure cycle to attempt 1"
        );
        seed_failed_retry_cycle(&db, &id, "b").await;

        let evidence = db
            .query(
                "SELECT generation_id, attempt, github_run_id FROM attempt_outcomes_v2 \
                 WHERE task_id = ? ORDER BY github_run_id",
            )
            .bind(id)
            .fetch_all::<AttemptEvidenceRow>()
            .await
            .expect("read failure evidence");
        assert_eq!(evidence.len(), 8);
        assert_eq!(evidence[0].attempt, 1);
        assert_eq!(evidence[3].attempt, 4);
        assert_eq!(evidence[4].attempt, 1);
        assert_eq!(evidence[7].attempt, 4);
        assert_eq!(evidence[0].github_run_id.as_deref(), Some("run-a-1"));
        assert_eq!(evidence[4].github_run_id.as_deref(), Some("run-b-1"));
        let mut generation_ids = evidence
            .iter()
            .map(|row| row.generation_id.clone())
            .collect::<Vec<_>>();
        generation_ids.sort();
        generation_ids.dedup();
        assert_eq!(
            generation_ids.len(),
            8,
            "each failure has a distinct generation"
        );
    }

    #[tokio::test]
    async fn delayed_old_run_cannot_complete_new_bound_generation() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("flaky", Vec::new())])
            .await
            .expect("enqueue");
        let id = task_id_on("flaky", TARGET);
        let first = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim A")[0]
            .clone();
        super::bind_dispatch_run(&db, &id, &first.generation_id, "run-a")
            .await
            .expect("bind A");
        super::complete_run(
            &db,
            &settings(),
            &report_with_run(&id, false, "run-a"),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete A");
        db.query("UPDATE queue SET not_before = '1970-01-01 00:00:00', wake_at = '1970-01-01 00:00:00' WHERE task_id = ?")
            .bind(id.clone())
            .execute()
            .await
            .expect("open retry");
        let second = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim B")[0]
            .clone();
        super::bind_dispatch_run(&db, &id, &second.generation_id, "run-b")
            .await
            .expect("bind B");
        let stale = super::complete_run(
            &db,
            &settings(),
            &report_with_run(&id, false, "run-a"),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect_err("old A must conflict with B");
        assert!(matches!(stale, QueueError::StaleCompletion { .. }));
        super::complete_run(
            &db,
            &settings(),
            &report_with_run(&id, true, "run-b"),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete B");
        assert_eq!(row_column(&db, "flaky", "status").await, "completed");
    }

    #[tokio::test]
    async fn early_completion_is_acknowledged_then_applied_after_exact_binding() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("early", Vec::new())])
            .await
            .expect("enqueue");
        let id = task_id_on("early", TARGET);
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim")[0]
            .clone();
        super::complete_run(
            &db,
            &settings(),
            &report_with_run(&id, false, "run-early"),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("early report is durably acknowledged");
        assert_eq!(row_column(&db, "early", "status").await, "dispatched");
        assert_eq!(pending_completion_count(&db).await, 1);
        super::bind_dispatch_run(&db, &id, &claimed.generation_id, "run-early")
            .await
            .expect("bind exact run");
        super::reconcile_pending_completions(&db, &settings(), TEST_WINDOW_MINUTES)
            .await
            .expect("apply pending exact run");
        assert_eq!(row_column(&db, "early", "status").await, "pending");
        assert_eq!(pending_completion_count(&db).await, 0);
    }

    #[tokio::test]
    async fn duplicate_early_delivery_is_idempotent_and_replay_conflicts_after_apply() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("replay", Vec::new())])
            .await
            .expect("enqueue");
        let id = task_id_on("replay", TARGET);
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim")[0]
            .clone();
        let event = report_with_run(&id, true, "run-replay");
        super::complete_run(&db, &settings(), &event, TEST_WINDOW_MINUTES)
            .await
            .expect("first early delivery");
        super::complete_run(&db, &settings(), &event, TEST_WINDOW_MINUTES)
            .await
            .expect("duplicate early delivery");
        assert_eq!(pending_completion_count(&db).await, 1);
        super::bind_dispatch_run(&db, &id, &claimed.generation_id, "run-replay")
            .await
            .expect("bind replay run");
        super::reconcile_pending_completions(&db, &settings(), TEST_WINDOW_MINUTES)
            .await
            .expect("apply replay run");
        let replay = super::complete_run(&db, &settings(), &event, TEST_WINDOW_MINUTES)
            .await
            .expect_err("replayed applied delivery conflicts");
        assert!(matches!(replay, QueueError::StaleCompletion { .. }));
        assert_eq!(pending_completion_count(&db).await, 0);
    }

    #[tokio::test]
    async fn response_loss_reclaim_drops_unbound_event_before_new_claim() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("lost", Vec::new())])
            .await
            .expect("enqueue");
        let id = task_id_on("lost", TARGET);
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim")[0]
            .clone();
        super::complete_run(
            &db,
            &settings(),
            &report_with_run(&id, false, "run-lost"),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("store response-loss event");
        super::mark_dispatch_failed(
            &db,
            &settings(),
            &id,
            &claimed.generation_id,
            "response lost",
        )
        .await
        .expect("reclaim response-loss generation");
        assert_eq!(pending_completion_count(&db).await, 0);
        db.query("UPDATE queue SET not_before = '1970-01-01 00:00:00', wake_at = '1970-01-01 00:00:00' WHERE task_id = ?")
            .bind(id.clone())
            .execute()
            .await
            .expect("open replacement dispatch");
        let replacement = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim replacement")[0]
            .clone();
        assert_eq!(replacement.attempt, claimed.attempt);
        super::bind_dispatch_run(&db, &id, &replacement.generation_id, "run-new")
            .await
            .expect("bind replacement");
        let stale = super::complete_run(
            &db,
            &settings(),
            &report_with_run(&id, false, "run-lost"),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect_err("orphaned response-loss run is stale");
        assert!(matches!(stale, QueueError::StaleCompletion { .. }));
    }

    #[tokio::test]
    async fn late_dispatch_failure_cannot_overwrite_cancelled_or_retried_generation() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("fenced", Vec::new())])
            .await
            .expect("enqueue");
        let id = task_id_on("fenced", TARGET);
        let first = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim A")[0]
            .clone();
        super::apply_mutation(
            &db,
            &settings(),
            super::QueueMutation::Cancel,
            &ids_selector(std::slice::from_ref(&id)),
        )
        .await
        .expect("cancel A");
        super::mark_dispatch_failed(
            &db,
            &settings(),
            &id,
            &first.generation_id,
            "late A failure",
        )
        .await
        .expect("fence late A failure after cancel");
        assert_eq!(row_column(&db, "fenced", "status").await, "failed");

        super::apply_mutation(
            &db,
            &settings(),
            super::QueueMutation::Retry,
            &ids_selector(std::slice::from_ref(&id)),
        )
        .await
        .expect("retry for B");
        let second = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim B")[0]
            .clone();
        assert_eq!(second.attempt, 1);
        assert_ne!(second.generation_id, first.generation_id);

        super::complete_run(
            &db,
            &settings(),
            &report_with_run(&id, true, "run-b"),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("persist early B completion");
        assert_eq!(pending_completion_count(&db).await, 1);
        super::bind_dispatch_run(&db, &id, &second.generation_id, "run-b")
            .await
            .expect("bind B");

        super::mark_dispatch_failed(
            &db,
            &settings(),
            &id,
            &first.generation_id,
            "late A failure",
        )
        .await
        .expect("fence late A failure after retry");
        assert_eq!(row_column(&db, "fenced", "status").await, "dispatched");
        assert_eq!(row_column(&db, "fenced", "github_run_id").await, "run-b");
        assert_eq!(pending_completion_count(&db).await, 1);

        super::reconcile_pending_completions(&db, &settings(), TEST_WINDOW_MINUTES)
            .await
            .expect("apply B completion");
        assert_eq!(row_column(&db, "fenced", "status").await, "completed");
        assert_eq!(pending_completion_count(&db).await, 0);
    }

    #[tokio::test]
    async fn purge_recreate_keeps_failure_evidence_under_new_generation() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("purged", Vec::new())])
            .await
            .expect("enqueue A");
        let id = task_id_on("purged", TARGET);
        let first = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim A")[0]
            .clone();
        db.query("UPDATE queue SET attempt = 4 WHERE task_id = ?")
            .bind(id.clone())
            .execute()
            .await
            .expect("seed terminal attempt");
        super::complete(
            &db,
            &settings(),
            &super::BuildCompleteReport {
                task_id: id.clone(),
                generation_id: first.generation_id.clone(),
                attempt: 4,
                success: false,
                error: Some("cycle A".to_owned()),
                finished_at: None,
                github_run_id: Some("run-a".to_owned()),
            },
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("record terminal A");

        super::apply_mutation(
            &db,
            &settings(),
            super::QueueMutation::Purge,
            &ids_selector(std::slice::from_ref(&id)),
        )
        .await
        .expect("purge A");
        enqueue(&db, &[request("purged", Vec::new())])
            .await
            .expect("enqueue B");
        let second = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim B")[0]
            .clone();
        super::complete(
            &db,
            &settings(),
            &super::BuildCompleteReport {
                task_id: id.clone(),
                generation_id: second.generation_id.clone(),
                attempt: second.attempt,
                success: false,
                error: Some("cycle B".to_owned()),
                finished_at: None,
                github_run_id: Some("run-b".to_owned()),
            },
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("record B");

        let rows = db
            .query(
                "SELECT generation_id, attempt, github_run_id FROM attempt_outcomes_v2 \
                 WHERE task_id = ? ORDER BY finished_at, rowid",
            )
            .bind(id)
            .fetch_all::<AttemptEvidenceRow>()
            .await
            .expect("read preserved evidence");
        assert_eq!(rows.len(), 2);
        assert_ne!(rows[0].generation_id, rows[1].generation_id);
        assert_eq!(rows[0].attempt, 4);
        assert_eq!(rows[1].attempt, 1);
    }

    #[tokio::test]
    async fn late_failure_cannot_match_purged_recreated_generation() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("recreated", Vec::new())])
            .await
            .expect("enqueue A");
        let id = task_id_on("recreated", TARGET);
        let first = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim A")[0]
            .clone();
        assert_eq!(
            row_column(&db, "recreated", "generation_id").await,
            first.generation_id
        );

        super::apply_mutation(
            &db,
            &settings(),
            super::QueueMutation::Cancel,
            &ids_selector(std::slice::from_ref(&id)),
        )
        .await
        .expect("cancel A");
        super::apply_mutation(
            &db,
            &settings(),
            super::QueueMutation::Purge,
            &ids_selector(std::slice::from_ref(&id)),
        )
        .await
        .expect("purge A");
        enqueue(&db, &[request("recreated", Vec::new())])
            .await
            .expect("enqueue B");
        let second = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim B")[0]
            .clone();
        assert_ne!(first.generation_id, second.generation_id);
        assert_eq!(
            row_column(&db, "recreated", "generation_id").await,
            second.generation_id
        );

        super::mark_dispatch_failed(&db, &settings(), &id, &first.generation_id, "late A")
            .await
            .expect("fence old failure");
        assert_eq!(row_column(&db, "recreated", "status").await, "dispatched");
        assert_eq!(
            row_column(&db, "recreated", "generation_id").await,
            second.generation_id
        );
    }

    #[tokio::test]
    async fn binding_clears_orphan_pending_run_before_normal_completion() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("orphan", Vec::new())])
            .await
            .expect("enqueue");
        let id = task_id_on("orphan", TARGET);
        let first = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim A")[0]
            .clone();
        super::mark_dispatch_failed(&db, &settings(), &id, &first.generation_id, "response lost")
            .await
            .expect("reclaim A");
        db.query("UPDATE queue SET not_before = '1970-01-01 00:00:00', wake_at = '1970-01-01 00:00:00' WHERE task_id = ?")
            .bind(id.clone())
            .execute()
            .await
            .expect("open B");
        let second = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim B")[0]
            .clone();
        assert_eq!(second.attempt, first.attempt);
        super::complete_run(
            &db,
            &settings(),
            &report_with_run(&id, false, "run-x"),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("persist orphan X");
        assert_eq!(pending_completion_count(&db).await, 1);
        super::bind_dispatch_run(&db, &id, &second.generation_id, "run-y")
            .await
            .expect("bind Y");
        assert_eq!(pending_completion_count(&db).await, 0);
        super::complete_run(
            &db,
            &settings(),
            &report_with_run(&id, true, "run-y"),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete Y");
        assert_eq!(row_column(&db, "orphan", "status").await, "completed");
    }

    #[tokio::test]
    async fn persisted_bound_pending_event_recovers_after_restart() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("restart", Vec::new())])
            .await
            .expect("enqueue");
        let id = task_id_on("restart", TARGET);
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim")[0]
            .clone();
        super::complete_run(
            &db,
            &settings(),
            &report_with_run(&id, false, "run-restart"),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("persist pending event");
        super::bind_dispatch_run(&db, &id, &claimed.generation_id, "run-restart")
            .await
            .expect("persist binding");
        super::reconcile_pending_completions(&db, &settings(), TEST_WINDOW_MINUTES)
            .await
            .expect("restart recovery");
        assert_eq!(row_column(&db, "restart", "status").await, "pending");
        assert_eq!(pending_completion_count(&db).await, 0);
    }

    async fn pending_completion_count(db: &DurableDb) -> i64 {
        db.query("SELECT count(*) FROM pending_run_completions")
            .fetch_scalar::<i64>()
            .await
            .expect("pending completion count")
    }

    /// A `pending` count at or above `max_queue_pending` turns miss-lane
    /// submits away; human-lane and trusted submits still get in.
    #[tokio::test]
    async fn full_queue_refuses_miss_lane_but_not_human_or_trusted() {
        let db = memory_db().await.expect("memory db");
        let cap_settings = SchedulerSettings {
            max_queue_pending: 2,
            ..settings()
        };
        super::enqueue(
            &db,
            &[request("one", Vec::new()), request("two", Vec::new())],
            &cap_settings,
        )
        .await
        .expect("enqueue up to the cap");

        let error = super::enqueue(&db, &[request("three", Vec::new())], &cap_settings)
            .await
            .expect_err("a miss-lane submit over a full queue must be refused");
        assert!(matches!(
            error,
            QueueError::QueueFull { pending: 2, cap: 2 }
        ));

        // Human-lane work is exempt from the depth cap.
        super::enqueue(&db, &[human_request("asked")], &cap_settings)
            .await
            .expect("human-lane enqueue bypasses the pending cap");
        // And so is a trusted (repo-writer) submit of miss-lane work.
        super::enqueue_trusted(&db, &[request("four", Vec::new())], &cap_settings)
            .await
            .expect("trusted submit bypasses the pending cap");
        assert_eq!(super::status(&db).await.expect("status").pending, 4);
    }

    #[tokio::test]
    async fn human_daily_budget_refuses_the_submit_that_would_exceed_it() {
        let db = memory_db().await.expect("memory db");
        let budget_settings = SchedulerSettings {
            human_daily_task_budget: 3,
            ..settings()
        };
        super::enqueue(
            &db,
            &[human_request("one"), human_request("two")],
            &budget_settings,
        )
        .await
        .expect("first two human tasks fit the budget");

        // Two more would take the day to 4 > 3: refused, and the charge
        // is not recorded — a retry of a one-task submit still fits.
        let error = super::enqueue(
            &db,
            &[human_request("three"), human_request("four")],
            &budget_settings,
        )
        .await
        .expect_err("the submit crossing the budget must be refused");
        assert!(matches!(
            error,
            QueueError::HumanDailyBudgetExhausted {
                attempted: 2,
                budget: 3
            }
        ));
        super::enqueue(&db, &[human_request("three")], &budget_settings)
            .await
            .expect("a smaller submit still fits the remaining budget");

        // Miss-lane work never spends the human budget.
        super::enqueue(&db, &[request("missed", Vec::new())], &budget_settings)
            .await
            .expect("miss-lane enqueue is not budget-gated");
        // …and a submit bigger than the whole budget fails without
        // touching the counter.
        let error = super::enqueue(
            &db,
            &[
                human_request("x"),
                human_request("y"),
                human_request("z"),
                human_request("w"),
            ],
            &budget_settings,
        )
        .await
        .expect_err("a submit over the whole budget can never fit");
        assert!(matches!(
            error,
            QueueError::HumanDailyBudgetExhausted { .. }
        ));
    }

    /// `tasks_status` must surface `preserve_lockfile`: it is the flag
    /// that says whether the task's dependency closure is reproducible
    /// from crates.io, and every status consumer reads it off this row.
    #[tokio::test]
    async fn tasks_status_surfaces_lockfile() {
        let db = memory_db().await.expect("memory db");
        let mut locked = request("locked", Vec::new());
        locked.preserve_lockfile = true;
        enqueue(&db, &[request("plain", Vec::new()), locked])
            .await
            .expect("enqueue");

        let statuses = super::tasks_status(
            &db,
            &[
                task_id("plain", VERSION, FEATURES, TARGET, RUSTC, false),
                task_id("locked", VERSION, FEATURES, TARGET, RUSTC, false),
            ],
        )
        .await
        .expect("tasks status");

        assert_eq!(statuses.len(), 2);
        let (plain, locked) = (&statuses[0], &statuses[1]);
        assert!(!plain.preserve_lockfile);
        assert!(!plain.preserve_lockfile);
        assert!(locked.preserve_lockfile);
        assert!(locked.preserve_lockfile);
    }

    // ===== Admin operations: list, mutation domains, status =====

    /// A `QueueSelector` of explicit task ids.
    fn ids_selector(ids: &[String]) -> stow_types::api::QueueSelector {
        stow_types::api::QueueSelector {
            task_ids: ids.to_vec(),
            ..Default::default()
        }
    }

    /// A `QueueSelector` of pure predicates, with no explicit ids.
    fn filter_selector(selector: stow_types::api::QueueSelector) -> stow_types::api::QueueSelector {
        stow_types::api::QueueSelector {
            task_ids: Vec::new(),
            ..selector
        }
    }

    /// One column of one queue row, for post-mutation assertions.
    async fn row_column(db: &DurableDb, crate_name: &str, column: &str) -> String {
        db.query(&format!("SELECT {column} FROM queue WHERE task_id = ?"))
            .bind(task_id_on(crate_name, TARGET))
            .fetch_scalar::<String>()
            .await
            .expect("row column")
    }

    /// Whether a queue row exists at all — purge assertions.
    async fn row_exists(db: &DurableDb, crate_name: &str) -> bool {
        db.query("SELECT count(*) FROM queue WHERE task_id = ?")
            .bind(task_id_on(crate_name, TARGET))
            .fetch_scalar::<i64>()
            .await
            .expect("row count")
            > 0
    }

    #[tokio::test]
    async fn list_tasks_filters_by_status_crate_and_ids() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[request("alpha", Vec::new()), request("beta", Vec::new())],
        )
        .await
        .expect("enqueue");
        mark_active(&db, "beta", TARGET, "failed").await;

        let failed = super::list_tasks(
            &db,
            &filter_selector(stow_types::api::QueueSelector {
                status: Some(stow_types::api::QueueTaskStatus::Failed),
                ..Default::default()
            }),
        )
        .await
        .expect("list failed");
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].crate_name.as_str(), "beta");

        let named = super::list_tasks(
            &db,
            &filter_selector(stow_types::api::QueueSelector {
                crate_name: Some("alpha".parse().expect("crate name")),
                ..Default::default()
            }),
        )
        .await
        .expect("list by crate");
        assert_eq!(named.len(), 1);
        assert_eq!(named[0].task_id, task_id_on("alpha", TARGET));

        let by_id = super::list_tasks(&db, &ids_selector(&[task_id_on("beta", TARGET)]))
            .await
            .expect("list by id");
        assert_eq!(by_id.len(), 1);
        assert_eq!(by_id[0].status, stow_types::api::QueueTaskStatus::Failed);
    }

    #[tokio::test]
    async fn retry_returns_failed_rows_to_pending() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[request("alpha", Vec::new()), request("beta", Vec::new())],
        )
        .await
        .expect("enqueue");
        mark_active(&db, "alpha", TARGET, "failed").await;
        db.query("UPDATE queue SET error_msg = 'boom' WHERE task_id = ?")
            .bind(task_id_on("alpha", TARGET))
            .execute()
            .await
            .expect("set error");

        let affected = super::apply_mutation(
            &db,
            &settings(),
            super::QueueMutation::Retry,
            &filter_selector(stow_types::api::QueueSelector {
                status: Some(stow_types::api::QueueTaskStatus::Failed),
                ..Default::default()
            }),
        )
        .await
        .expect("retry");
        assert_eq!(affected, 1);
        assert_eq!(row_column(&db, "alpha", "status").await, "pending");
        assert_eq!(row_column(&db, "alpha", "error_msg").await, "");
        // The pending sibling is untouched — retry's domain is failed rows.
        assert_eq!(row_column(&db, "beta", "status").await, "pending");
    }

    /// A retried row re-enters `pending` with a fresh retry budget while
    /// its dispatch generation remains monotone for evidence fencing.
    #[tokio::test]
    async fn retry_returns_failed_rows_to_pending_with_a_fresh_attempt() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                request("alpha", Vec::new()),
                request("beta", Vec::new()),
                request("gamma", Vec::new()),
            ],
        )
        .await
        .expect("enqueue");
        mark_active(&db, "alpha", TARGET, "failed").await;
        mark_active(&db, "beta", TARGET, "failed").await;
        db.query(
            "UPDATE queue SET attempt = 4, error_msg = 'boom', \
                  not_before = '2999-01-01 00:00:00' WHERE task_id = ?",
        )
        .bind(task_id_on("alpha", TARGET))
        .execute()
        .await
        .expect("seed terminal state");

        let affected = super::apply_mutation(
            &db,
            &settings(),
            super::QueueMutation::Retry,
            &ids_selector(&[task_id_on("alpha", TARGET), task_id_on("gamma", TARGET)]),
        )
        .await
        .expect("retry");
        // `gamma` is pending, not failed — outside retry's domain.
        assert_eq!(affected, 1);
        assert_eq!(row_column(&db, "alpha", "status").await, "pending");
        assert_eq!(row_column(&db, "alpha", "CAST(attempt AS TEXT)").await, "1");
        assert_eq!(row_column(&db, "alpha", "error_msg").await, "");
        assert_eq!(
            row_column(&db, "alpha", "not_before").await,
            "1970-01-01 00:00:00"
        );
        assert_eq!(row_column(&db, "beta", "status").await, "failed");
        assert_eq!(row_column(&db, "gamma", "status").await, "pending");
    }

    /// `retry` carries the same selector predicates as the other verbs:
    /// `status` plus `rustc`/`target` scope the release to one build
    /// line.
    #[tokio::test]
    async fn retry_selects_by_rustc_and_target() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[request("alpha", Vec::new()), request("beta", Vec::new())],
        )
        .await
        .expect("enqueue");
        mark_active(&db, "alpha", TARGET, "failed").await;
        mark_active(&db, "beta", TARGET, "failed").await;
        // A failed row at a different rustc — the selector must not
        // reach it.
        let other_rustc = task_id("other-rustc", VERSION, FEATURES, TARGET, "1.86.0", false);
        enqueue(
            &db,
            &[EnqueueRequest {
                rustc_version: "1.86.0".parse().expect("rustc"),
                ..request("other-rustc", Vec::new())
            }],
        )
        .await
        .expect("enqueue other-rustc");
        db.query("UPDATE queue SET status = 'failed' WHERE task_id = ?")
            .bind(other_rustc.clone())
            .execute()
            .await
            .expect("fail other-rustc");

        let affected = super::apply_mutation(
            &db,
            &settings(),
            super::QueueMutation::Retry,
            &filter_selector(stow_types::api::QueueSelector {
                status: Some(stow_types::api::QueueTaskStatus::Failed),
                rustc_version: Some(RUSTC.parse().expect("rustc")),
                target: Some(TARGET.parse().expect("target")),
                ..Default::default()
            }),
        )
        .await
        .expect("retry by rustc + target");
        assert_eq!(affected, 2);
        assert_eq!(row_column(&db, "alpha", "status").await, "pending");
        assert_eq!(row_column(&db, "beta", "status").await, "pending");
        assert_eq!(row_column(&db, "alpha", "CAST(attempt AS TEXT)").await, "1");
        let other_status = db
            .query("SELECT status FROM queue WHERE task_id = ?")
            .bind(other_rustc)
            .fetch_scalar::<String>()
            .await
            .expect("other-rustc status");
        assert_eq!(other_status, "failed");
    }

    #[tokio::test]
    async fn cancel_fails_pending_and_dispatched_rows() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                request("alpha", Vec::new()),
                request("beta", Vec::new()),
                request("gamma", Vec::new()),
            ],
        )
        .await
        .expect("enqueue");
        mark_active(&db, "beta", TARGET, "dispatched").await;
        mark_active(&db, "gamma", TARGET, "completed").await;

        // A completed row is outside cancel's domain regardless of the
        // selector.
        let affected = super::apply_mutation(
            &db,
            &settings(),
            super::QueueMutation::Cancel,
            &filter_selector(stow_types::api::QueueSelector {
                crate_name: Some("gamma".parse().expect("crate name")),
                ..Default::default()
            }),
        )
        .await
        .expect("cancel by crate");
        assert_eq!(affected, 0);
        assert_eq!(row_column(&db, "gamma", "status").await, "completed");

        let affected = super::apply_mutation(
            &db,
            &settings(),
            super::QueueMutation::Cancel,
            &ids_selector(&[task_id_on("alpha", TARGET), task_id_on("beta", TARGET)]),
        )
        .await
        .expect("cancel");
        assert_eq!(affected, 2);
        assert_eq!(row_column(&db, "alpha", "status").await, "failed");
        assert_eq!(row_column(&db, "beta", "status").await, "failed");
        assert_eq!(
            row_column(&db, "alpha", "error_msg").await,
            "cancelled by operator"
        );
    }

    #[tokio::test]
    async fn promote_moves_miss_lane_pending_to_human() {
        let db = memory_db().await.expect("memory db");
        let mut human = request("human", Vec::new());
        human.source = EnqueueSource::HumanRequest;
        enqueue(
            &db,
            &[
                request("alpha", Vec::new()),
                request("beta", Vec::new()),
                human,
            ],
        )
        .await
        .expect("enqueue");
        mark_active(&db, "beta", TARGET, "dispatched").await;

        let affected = super::apply_mutation(
            &db,
            &settings(),
            super::QueueMutation::Promote,
            &filter_selector(stow_types::api::QueueSelector {
                crate_name: Some("alpha".parse().expect("crate name")),
                ..Default::default()
            }),
        )
        .await
        .expect("promote");
        assert_eq!(affected, 1);
        assert_eq!(row_column(&db, "alpha", "lane").await, "human");
        // Dispatched and already-human rows are outside promote's domain.
        assert_eq!(row_column(&db, "beta", "lane").await, "miss");
        assert_eq!(row_column(&db, "human", "lane").await, "human");
    }

    #[tokio::test]
    async fn purge_deletes_only_old_terminal_rows() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                request("old-done", Vec::new()),
                request("old-failed", Vec::new()),
                request("fresh-failed", Vec::new()),
                request("live", Vec::new()),
            ],
        )
        .await
        .expect("enqueue");
        mark_active(&db, "old-done", TARGET, "completed").await;
        mark_active(&db, "old-failed", TARGET, "failed").await;
        db.query("UPDATE queue SET status = 'failed' WHERE task_id = ?")
            .bind(task_id_on("fresh-failed", TARGET))
            .execute()
            .await
            .expect("fail fresh row");

        // An age-free filter selector cannot purge — the age floor is the
        // operator's contract that only settled rows are swept.
        let denied = super::apply_mutation(
            &db,
            &settings(),
            super::QueueMutation::Purge,
            &filter_selector(stow_types::api::QueueSelector {
                status: Some(stow_types::api::QueueTaskStatus::Failed),
                ..Default::default()
            }),
        )
        .await;
        assert!(matches!(denied, Err(QueueError::PurgeRequiresAge)));

        let affected = super::apply_mutation(
            &db,
            &settings(),
            super::QueueMutation::Purge,
            &filter_selector(stow_types::api::QueueSelector {
                older_than_secs: Some(3_600),
                ..Default::default()
            }),
        )
        .await
        .expect("purge");
        assert_eq!(affected, 2);
        assert!(!row_exists(&db, "old-done").await);
        assert!(!row_exists(&db, "old-failed").await);
        // Too young for the floor, and pending rows are never purgeable.
        assert!(row_exists(&db, "fresh-failed").await);
        assert!(row_exists(&db, "live").await);
    }

    #[tokio::test]
    async fn mutations_reject_an_empty_selector() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("alpha", Vec::new())])
            .await
            .expect("enqueue");
        let denied = super::apply_mutation(
            &db,
            &settings(),
            super::QueueMutation::Cancel,
            &stow_types::api::QueueSelector::default(),
        )
        .await;
        assert!(matches!(denied, Err(QueueError::EmptySelector)));
        assert_eq!(row_column(&db, "alpha", "status").await, "pending");
    }

    #[tokio::test]
    async fn admin_status_reports_lanes_in_flight_and_targets() {
        let db = memory_db().await.expect("memory db");
        let mut human = request("human", Vec::new());
        human.source = EnqueueSource::HumanRequest;
        enqueue(
            &db,
            &[
                request("miss-a", Vec::new()),
                request("miss-b", Vec::new()),
                human,
            ],
        )
        .await
        .expect("enqueue");
        mark_active(&db, "miss-b", TARGET, "dispatched").await;
        db.query("UPDATE queue SET github_run_id = ? WHERE task_id = ?")
            .bind("777")
            .bind(task_id_on("miss-b", TARGET))
            .execute()
            .await
            .expect("stamp run id");
        // Terminal rows inside the 24 h window feed the per-target tally.
        db.query("UPDATE queue SET status = 'completed' WHERE task_id = ?")
            .bind(task_id_on("human", TARGET))
            .execute()
            .await
            .expect("complete human row");

        let status = super::admin_status(&db).await.expect("admin status");
        assert_eq!(status.pending_miss, 1);
        assert_eq!(status.pending_human, 0);
        assert!(status.oldest_pending_seconds.is_some());
        assert_eq!(status.in_flight.len(), 1);
        let in_flight = &status.in_flight[0];
        assert_eq!(in_flight.task_id, task_id_on("miss-b", TARGET));
        assert_eq!(in_flight.github_run_id.as_deref(), Some("777"));
        let target = status
            .targets
            .iter()
            .find(|entry| entry.target.as_str() == TARGET)
            .expect("target stats");
        assert_eq!(target.completed_24h, 1);
        assert_eq!(target.failed_24h, 0);
    }

    /// The dev-era DDL — `queue` without `host_side`/`shape_requeue`,
    /// `queue_dependencies` carrying the dep_* identity columns but none
    /// of the shape-gate columns — is what production ran before
    /// host-side nodes.
    const DEV_ERA_QUEUE: &str = "CREATE TABLE queue (
        task_id TEXT PRIMARY KEY,
        crate_name TEXT NOT NULL,
        version TEXT NOT NULL,
        features_json TEXT NOT NULL,
        target TEXT NOT NULL,
        rustc_version TEXT NOT NULL,
        downloads INTEGER NOT NULL DEFAULT 0,
        miss_count INTEGER NOT NULL DEFAULT 0,
        request_count INTEGER NOT NULL DEFAULT 1,
        priority INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending',
        error_msg TEXT,
        preserve_lockfile INTEGER NOT NULL DEFAULT 0,
        lane TEXT NOT NULL DEFAULT 'miss' CHECK (lane IN ('miss', 'human')),
        dispatch_attempts INTEGER NOT NULL DEFAULT 0,
        attempt INTEGER NOT NULL DEFAULT 1,
        not_before TEXT NOT NULL DEFAULT '1970-01-01 00:00:00',
        first_requested_at TEXT NOT NULL DEFAULT (datetime('now')),
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        github_run_id TEXT,
        UNIQUE(crate_name, version, features_json, target, rustc_version)
    )";
    const DEV_ERA_DEPENDENCIES: &str = "CREATE TABLE queue_dependencies (
        task_id TEXT NOT NULL,
        depends_on_task_id TEXT NOT NULL,
        dep_crate_name TEXT NOT NULL DEFAULT '',
        dep_version TEXT NOT NULL DEFAULT '',
        dep_features_json TEXT NOT NULL DEFAULT '',
        dep_target TEXT NOT NULL DEFAULT '',
        dep_rustc_version TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        PRIMARY KEY (task_id, depends_on_task_id)
    )";

    /// The objects a pre-`host_side` queue carried on top of
    /// `DEV_ERA_QUEUE`: the counter triggers and the status index. On
    /// `ALTER TABLE queue RENAME TO queue_migrated` `SQLite` moves them
    /// with the table, so a rebuild that recreates the table and drops
    /// the copy without re-running the include afterwards loses them
    /// all — the regression `migrate_rebuilds_queue_triggers_and_indexes`
    /// covers (stow#433).
    const DEV_ERA_QUEUE_OBJECTS: &[&str] = &[
        "CREATE TABLE queue_status_counts (
            status TEXT NOT NULL,
            lane TEXT NOT NULL,
            n INTEGER NOT NULL,
            PRIMARY KEY (status, lane)
        )",
        "CREATE TRIGGER queue_counts_on_insert AFTER INSERT ON queue
         BEGIN
             INSERT INTO queue_status_counts (status, lane, n)
                 VALUES (NEW.status, NEW.lane, 1)
             ON CONFLICT (status, lane) DO UPDATE SET n = n + 1;
         END",
        "CREATE TRIGGER queue_counts_on_delete AFTER DELETE ON queue
         BEGIN
             INSERT INTO queue_status_counts (status, lane, n)
                 VALUES (OLD.status, OLD.lane, -1)
             ON CONFLICT (status, lane) DO UPDATE SET n = n - 1;
         END",
        "CREATE TRIGGER queue_counts_on_move
             AFTER UPDATE OF status, lane ON queue
             WHEN OLD.status != NEW.status OR OLD.lane != NEW.lane
         BEGIN
             INSERT INTO queue_status_counts (status, lane, n)
                 VALUES (OLD.status, OLD.lane, -1)
             ON CONFLICT (status, lane) DO UPDATE SET n = n - 1;
             INSERT INTO queue_status_counts (status, lane, n)
                 VALUES (NEW.status, NEW.lane, 1)
             ON CONFLICT (status, lane) DO UPDATE SET n = n + 1;
         END",
        "CREATE INDEX idx_queue_status_updated ON queue (status, updated_at)",
    ];

    /// `migrate` must migrate a dev-era schema in any column order
    /// and still backfill every pre-existing edge's mask: the backfill
    /// joins `queue.host_side`, so it must run after the host-side
    /// rebuild and must not depend on whether the ALTER columns it fills
    /// were just added (stow#367).
    #[derive(skyzen::FromRow)]
    struct MigratedClaimRow {
        task_id: String,
        status: String,
        host_side: i64,
        shape_requeue: i64,
        attempt: i64,
        dispatch_attempts: i64,
        generation_id: String,
        github_run_id: Option<String>,
        not_before: String,
        wake_at: String,
    }

    async fn seed_legacy_inflight_claims(db: &DurableDb, owner: &str, dep: &str) {
        for statement in [DEV_ERA_QUEUE, DEV_ERA_DEPENDENCIES] {
            db.query(statement).execute().await.expect("dev-era ddl");
        }
        db.query(
            "CREATE TABLE attempt_outcomes (
                task_id TEXT NOT NULL,
                attempt INTEGER NOT NULL,
                target TEXT NOT NULL,
                failure_step TEXT,
                failure_class TEXT,
                github_run_id TEXT,
                finished_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (task_id, attempt)
            )",
        )
        .execute()
        .await
        .expect("legacy outcome ddl");
        db.query(
            "INSERT INTO attempt_outcomes \
             (task_id, attempt, target, failure_class, github_run_id) \
             VALUES ('legacy-before-migrate', 1, ?, 'legacy', 'run-legacy')",
        )
        .bind(TARGET)
        .execute()
        .await
        .expect("legacy outcome row");
        db.query(
            "INSERT INTO queue (task_id, crate_name, version, features_json, target, rustc_version)
             VALUES (?, 'dep', '1.0.0', '[]', ?, '1.85.0'),
                    (?, 'parent', '1.0.0', '[]', ?, '1.85.0')",
        )
        .bind(dep.to_owned())
        .bind(TARGET)
        .bind(owner.to_owned())
        .bind(TARGET)
        .execute()
        .await
        .expect("dev-era queue rows");
        db.query(
            "INSERT INTO queue_dependencies
             (task_id, depends_on_task_id, dep_crate_name, dep_version, dep_features_json, dep_target, dep_rustc_version)
             VALUES (?, ?, 'dep', '1.0.0', '[]', ?, '1.85.0')",
        )
        .bind(owner.to_owned())
        .bind(dep.to_owned())
        .bind(TARGET)
        .execute()
        .await
        .expect("dev-era edge row");
        db.query("UPDATE queue SET dispatch_attempts = 2, attempt = 3")
            .execute()
            .await
            .expect("seed legacy attempt counters");
        db.query("UPDATE queue SET status = 'dispatched' WHERE task_id = ?")
            .bind(dep.to_owned())
            .execute()
            .await
            .expect("seed unbound legacy dispatch");
        db.query("UPDATE queue SET status = 'running', github_run_id = ? WHERE task_id = ?")
            .bind("legacy-run")
            .bind(owner.to_owned())
            .execute()
            .await
            .expect("seed bound legacy dispatch");
    }

    async fn assert_migrated_edge_masks(db: &DurableDb) {
        #[derive(skyzen::FromRow)]
        struct EdgeRow {
            side: i64,
            invocations: i64,
            shapes: i64,
        }
        let edge = db
            .query(
                "SELECT dep_host_side AS side, dep_invocations AS invocations, dep_shapes AS shapes \
                 FROM queue_dependencies",
            )
            .fetch_one::<EdgeRow>()
            .await
            .expect("edge row");
        // Owner and dep both mint on the family host triple, so the
        // dev-era edge's required side is ambiguous — the derivation
        // marks it -1 (unestablished) rather than trusting a target-side
        // 0 it cannot prove; `p.unit_side = -1` matches no published row
        // so the gate holds the dependent until a resync rewrites it.
        assert_eq!(edge.side, -1);
        // The mask is moot on a -1 edge — `p.unit_side = -1` matches no
        // published row — but it is written non-zero so the edge stays
        // out of the unbackfilled-0 marker class.
        assert_eq!(edge.invocations, 1);
        assert_eq!(edge.shapes, 2);
    }

    async fn assert_migrated_claims(
        db: &DurableDb,
        owner: &str,
        dep: &str,
        before_retry: MigratedClaimRow,
    ) {
        let rows = db
            .query(
                "SELECT task_id, status, host_side, shape_requeue, attempt, dispatch_attempts, \
                    generation_id, github_run_id, not_before, wake_at \
                 FROM queue",
            )
            .fetch_all::<MigratedClaimRow>()
            .await
            .expect("queue rows");
        assert_eq!(rows.len(), 2, "the rebuild keeps every queue row");
        assert!(
            rows.iter()
                .all(|row| row.host_side == 0 && row.shape_requeue == 0)
        );
        let abandoned = rows
            .iter()
            .find(|row| row.task_id == dep)
            .expect("abandoned row");
        assert_eq!(abandoned.status, "pending");
        assert_eq!(abandoned.attempt, 3);
        assert_eq!(abandoned.dispatch_attempts, 2);
        assert_ne!(abandoned.not_before, "1970-01-01 00:00:00");
        assert_ne!(abandoned.wake_at, "1970-01-01 00:00:00");
        assert_ne!(abandoned.generation_id, "");
        assert_eq!(abandoned.github_run_id, None);
        assert_eq!(
            (
                abandoned.status.clone(),
                abandoned.attempt,
                abandoned.dispatch_attempts,
                abandoned.generation_id.clone(),
                abandoned.not_before.clone(),
                abandoned.wake_at.clone(),
            ),
            (
                before_retry.status,
                before_retry.attempt,
                before_retry.dispatch_attempts,
                before_retry.generation_id,
                before_retry.not_before,
                before_retry.wake_at,
            ),
            "rerunning migration leaves the requeued claim unchanged"
        );
        let preserved = rows
            .iter()
            .find(|row| row.task_id == owner)
            .expect("bound row");
        assert_eq!(preserved.status, "running");
        assert_ne!(preserved.generation_id, "");
        assert_eq!(preserved.github_run_id.as_deref(), Some("legacy-run"));
    }

    async fn assert_migrated_outcome_history(db: &DurableDb) {
        assert_eq!(
            db.query(
                "SELECT count(*) FROM attempt_outcomes \
                 WHERE task_id = 'legacy-before-migrate'",
            )
            .fetch_scalar::<i64>()
            .await
            .expect("read preserved legacy outcome history"),
            1,
            "migration keeps legacy outcome evidence"
        );

        assert_eq!(
            super::stored_schema_version(db)
                .await
                .expect("schema version"),
            super::SCHEMA_VERSION,
            "a migrated queue is stamped at the current schema version"
        );
        db.query(
            "INSERT INTO attempt_outcomes \
             (task_id, attempt, target, failure_class, github_run_id) \
             VALUES ('legacy-after-migrate', 1, ?, 'legacy', 'run-legacy-2')",
        )
        .bind(TARGET)
        .execute()
        .await
        .expect("old writer remains compatible");
        let generation_columns = db
            .query("PRAGMA table_info(attempt_outcomes_v2)")
            .fetch_all::<super::QueueTableInfoRow>()
            .await
            .expect("generation outcome table");
        assert!(
            generation_columns
                .iter()
                .any(|column| column.name == "generation_id")
        );
    }

    #[tokio::test]
    async fn migrate_migrates_a_dev_era_queue_and_backfills_edge_masks() {
        let db = memory_db_raw().await.expect("raw memory db");
        let owner = task_id_on("parent", TARGET);
        let dep = task_id_on("dep", TARGET);
        seed_legacy_inflight_claims(&db, &owner, &dep).await;

        let report = super::migrate(&db, &settings()).await.expect("migrate");
        assert_eq!(
            (report.before, report.after),
            (0, super::SCHEMA_VERSION),
            "a pre-versioned queue reports 0 → SCHEMA_VERSION"
        );
        let before_retry = db
            .query(
                "SELECT task_id, status, host_side, shape_requeue, attempt, dispatch_attempts, \
                    generation_id, github_run_id, not_before, wake_at \
                 FROM queue WHERE task_id = ?",
            )
            .bind(dep.clone())
            .fetch_one::<MigratedClaimRow>()
            .await
            .expect("read requeued row before migration retry");
        let stale = super::complete_run(
            &db,
            &settings(),
            &report_with_run(&dep, false, "legacy-run"),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect_err("legacy unbound completion cannot settle requeued work");
        assert!(matches!(stale, QueueError::StaleCompletion { .. }));

        // A second pass must be a no-op, not a failure — deploy retries.
        let retry = super::migrate(&db, &settings())
            .await
            .expect("migrate retry");
        assert_eq!(
            (retry.before, retry.after),
            (super::SCHEMA_VERSION, super::SCHEMA_VERSION)
        );

        assert_migrated_edge_masks(&db).await;

        assert_migrated_claims(&db, &owner, &dep, before_retry).await;
        let stale_bound = super::complete_run(
            &db,
            &settings(),
            &report_with_run(&owner, false, "older-run"),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect_err("an old run cannot settle a preserved bound claim");
        assert!(matches!(stale_bound, QueueError::StaleCompletion { .. }));
        assert_migrated_outcome_history(&db).await;
    }

    /// A queue carrying the retired `rust_stable_channel` cache table
    /// loses it in the same pass that stamps the version — `IF EXISTS`
    /// makes the step idempotent, so the version bump's retry test is
    /// also the cover for the table never having existed.
    #[tokio::test]
    async fn migration_drops_the_retired_channel_cache_table() {
        let db = memory_db_raw().await.expect("raw memory db");
        db.query(
            "CREATE TABLE rust_stable_channel (\
             id INTEGER PRIMARY KEY CHECK (id = 1),\
             version TEXT NOT NULL,\
             fetched_at TEXT NOT NULL DEFAULT (datetime('now')))",
        )
        .execute()
        .await
        .expect("create retired table");

        super::migrate(&db, &settings()).await.expect("migrate");

        let columns = db
            .query("PRAGMA table_info(rust_stable_channel)")
            .fetch_all::<super::QueueTableInfoRow>()
            .await
            .expect("table_info");
        assert!(columns.is_empty(), "the retired table is gone");
    }

    /// A fresh database runs the migration pass and ends stamped at
    /// `SCHEMA_VERSION` — production's pre-versioned queues take the
    /// same path exactly once, through the operator route.
    #[tokio::test]
    async fn a_fresh_database_migrates_and_is_stamped() {
        let db = memory_db_raw().await.expect("raw memory db");
        let report = super::migrate(&db, &settings()).await.expect("migrate");
        assert_eq!((report.before, report.after), (0, super::SCHEMA_VERSION));
        assert_eq!(
            super::stored_schema_version(&db)
                .await
                .expect("schema version"),
            super::SCHEMA_VERSION
        );
    }

    /// The ops rule's cost bound (stow#432): request code runs no
    /// schema work at all — no version read, no `PRAGMA`, no DDL — so
    /// the cheapest request path issues exactly its own statement. The
    /// backend's migration permit already refuses anything else; this
    /// names what the permit is for.
    #[tokio::test]
    async fn a_request_path_issues_no_schema_statements() {
        let (db, log) = counting_memory_db().await.expect("counting db");
        let base = log.lock().expect("log").len();
        super::pending_count(&db).await.expect("pending_count");
        let issued = log.lock().expect("log")[base..].to_vec();
        assert_eq!(
            issued.len(),
            1,
            "the pending-count read is one statement and nothing else: {issued:?}"
        );
        assert!(
            issued[0].sql.starts_with("SELECT"),
            "the one statement is the pending count: {}",
            issued[0].sql
        );
    }

    /// A queue stamped newer than this build's `SCHEMA_VERSION` was
    /// migrated by newer code — `migrate` fails fast rather than letting
    /// old code read a schema it does not understand.
    #[tokio::test]
    async fn migrate_refuses_a_newer_schema() {
        // The migrate path's fixture: `migrate` runs only behind the
        // operator route, where schema probes are permitted.
        let db = memory_db_raw().await.expect("raw memory db");
        super::migrate(&db, &settings())
            .await
            .expect("first migrate");
        db.query(&format!(
            "UPDATE scheduler_schema_version SET version = {}",
            super::SCHEMA_VERSION + 1
        ))
        .execute()
        .await
        .expect("stamp newer version");
        let error = super::migrate(&db, &settings())
            .await
            .expect_err("a newer schema version must fail fast");
        assert!(
            error.to_string().contains("newer"),
            "the error names the version skew, got: {error}"
        );
    }

    /// The host backend enforces both halves of the ops rule (stow#432):
    /// a request-path database refuses every `PRAGMA` — including the
    /// documented ones, since request code must never probe the schema —
    /// and every DDL head, while the migrate path's fixture still applies
    /// the Durable Object authorizer's pragma allowlist (`user_version`
    /// refused, `table_info` allowed) on top of permitting the DDL.
    #[tokio::test]
    async fn the_test_backend_refuses_schema_work_outside_migrate() {
        let db = memory_db().await.expect("memory db");
        for sql in [
            "PRAGMA user_version",
            "PRAGMA table_info(queue)",
            "CREATE TABLE extra (id INTEGER)",
            "ALTER TABLE queue ADD COLUMN extra INTEGER",
            "DROP TABLE queue",
        ] {
            assert!(
                db.query(sql).execute().await.is_err(),
                "{sql} must fail on a request-path database"
            );
        }
        let db = memory_db_raw().await.expect("raw memory db");
        db.query("PRAGMA table_info(queue)")
            .fetch_all::<super::QueueTableInfoRow>()
            .await
            .expect("the documented pragma the migrations rely on");
        db.query("CREATE TABLE tmp_marker (id INTEGER)")
            .execute()
            .await
            .expect("DDL on the migrate path's database");
        let error = db
            .query("PRAGMA user_version")
            .execute()
            .await
            .expect_err("the DO authorizer refuses it even under migrate");
        assert!(
            error.to_string().contains("user_version"),
            "the rejection names the pragma, got: {error}"
        );
    }

    /// The side derivation each dev-era edge takes: a dep on the family
    /// host triple under a cross owner is provably host, a dep on the
    /// owner's own target off the host triple is provably target, and a
    /// dep on the host triple under an owner on the same triple — or on
    /// neither — stays unestablished (-1).
    #[tokio::test]
    async fn migrate_derives_dev_era_edge_sides_from_triples() {
        #[derive(skyzen::FromRow)]
        struct EdgeRow {
            side: i64,
        }
        const CROSS: &str = "aarch64-unknown-linux-gnu";
        const WASM: &str = "wasm32-unknown-unknown";
        let db = memory_db_raw().await.expect("raw memory db");
        for statement in [DEV_ERA_QUEUE, DEV_ERA_DEPENDENCIES] {
            db.query(statement).execute().await.expect("dev-era ddl");
        }
        // (owner target, dep target, expected side)
        let cases: [(&str, &str); 4] = [
            (CROSS, TARGET),
            (CROSS, CROSS),
            (TARGET, TARGET),
            (WASM, WASM),
        ];
        for (index, (owner_target, dep_target)) in cases.iter().enumerate() {
            let owner = format!("owner{index}");
            let dep = format!("dep{index}");
            let owner_id = task_id(&owner, VERSION, FEATURES, owner_target, RUSTC, false);
            let dep_id = task_id(&dep, VERSION, FEATURES, dep_target, RUSTC, false);
            db.query(
                "INSERT INTO queue (task_id, crate_name, version, features_json, target, rustc_version) \
                 VALUES (?, ?, '1.0.0', '[]', ?, '1.85.0'), (?, ?, '1.0.0', '[]', ?, '1.85.0')",
            )
            .bind(owner_id.clone())
            .bind(owner)
            .bind(*owner_target)
            .bind(dep_id.clone())
            .bind(dep)
            .bind(*dep_target)
            .execute()
            .await
            .expect("dev-era queue rows");
            db.query(
                "INSERT INTO queue_dependencies \
                 (task_id, depends_on_task_id, dep_crate_name, dep_version, dep_features_json, dep_target, dep_rustc_version) \
                 VALUES (?, ?, ?, '1.0.0', '[]', ?, '1.85.0')",
            )
            .bind(owner_id)
            .bind(dep_id)
            .bind(format!("dep{index}"))
            .bind(*dep_target)
            .execute()
            .await
            .expect("dev-era edge row");
        }

        super::migrate(&db, &settings()).await.expect("migrate");
        super::migrate(&db, &settings())
            .await
            .expect("migrate retry is a no-op");

        let rows = db
            .query(
                "SELECT dep_host_side AS side FROM queue_dependencies \
                 ORDER BY task_id",
            )
            .fetch_all::<EdgeRow>()
            .await
            .expect("edge rows");
        assert_eq!(rows.len(), 4);
        // task_ids hash, so order is not the insert order — compare the
        // side multiset: one unestablished, two provably target, one
        // provably host.
        let mut sides: Vec<i64> = rows.iter().map(|row| row.side).collect();
        sides.sort_unstable();
        assert_eq!(sides, vec![-1, 0, 0, 1]);
    }

    /// The human-lane position count must drive from the covering
    /// `(status, lane, dispatch_key)` index — a plain status scan would
    /// walk every pending miss row to reach a human lane's prefix.
    async fn assert_human_position_plan(db: &DurableDb) {
        #[derive(Debug, skyzen::FromRow)]
        struct PlanRow {
            detail: String,
        }
        let plan = db
            .query(
                "EXPLAIN QUERY PLAN \
                 SELECT count(*) FROM queue \
                 WHERE status = 'pending' AND lane = 'human' AND dispatch_key < ?",
            )
            .bind("9999999999999999999")
            .fetch_all::<PlanRow>()
            .await
            .expect("human position query plan");
        assert!(
            plan.iter().any(|row| row
                .detail
                .contains("USING COVERING INDEX idx_queue_human_position")),
            "human position must use the covering lane/key index: {plan:?}"
        );
    }

    /// The `host_side` rebuild renames `queue` aside, recreates it, copies
    /// the rows and drops the copy — and `SQLite` moves the old table's
    /// named indexes and triggers onto `queue_migrated` with the rename,
    /// so the include that recreates them must run after the drop or the
    /// rebuilt queue keeps neither. Start from a pre-`host_side` queue
    /// carrying the era's counter triggers and one index, migrate, and
    /// assert every `queue` index and trigger `schema.sql` declares
    /// exists afterwards — and that the counters still track a write.
    #[tokio::test]
    async fn migrate_rebuilds_queue_triggers_and_indexes() {
        #[derive(skyzen::FromRow)]
        struct ObjectRow {
            name: String,
        }
        let db = memory_db_raw().await.expect("raw memory db");
        // The era's objects on the dev-era queue: counter triggers and
        // the status index. Without the post-drop include the rename
        // moves them to `queue_migrated` and the drop deletes them.
        for statement in [DEV_ERA_QUEUE, DEV_ERA_DEPENDENCIES]
            .into_iter()
            .chain(DEV_ERA_QUEUE_OBJECTS.iter().copied())
        {
            db.query(statement).execute().await.expect("dev-era ddl");
        }
        db.query(
            "INSERT INTO queue (task_id, crate_name, version, features_json, target, rustc_version)
             VALUES (?, 'dep', '1.0.0', '[]', ?, '1.85.0')",
        )
        .bind(task_id_on("dep", TARGET))
        .bind(TARGET)
        .execute()
        .await
        .expect("dev-era queue row");

        super::migrate(&db, &settings()).await.expect("migrate");

        // Every index and trigger schema.sql declares on `queue` must
        // exist on the rebuilt table.
        let mut expected = Vec::new();
        for statement in include_str!("schema.sql").split(';') {
            let normalized = statement.replace('\n', " ");
            let is_queue_object = normalized.contains("ON queue ")
                && (normalized.contains("INDEX") || normalized.contains("TRIGGER"));
            if !is_queue_object {
                continue;
            }
            let name = normalized
                .split_whitespace()
                .skip_while(|token| *token != "EXISTS")
                .nth(1)
                .expect("object name after IF NOT EXISTS");
            expected.push(name.to_owned());
        }
        assert!(!expected.is_empty(), "schema.sql declares queue objects");
        let present: BTreeSet<String> = db
            .query(
                "SELECT name FROM sqlite_master \
                 WHERE tbl_name = 'queue' AND type IN ('index', 'trigger')",
            )
            .fetch_all::<ObjectRow>()
            .await
            .expect("sqlite_master")
            .into_iter()
            .map(|row| row.name)
            .collect();
        let missing: Vec<String> = expected
            .iter()
            .filter(|name| !present.contains(*name))
            .cloned()
            .collect();
        assert!(
            missing.is_empty(),
            "the rebuild dropped queue objects: {missing:?}"
        );

        assert_human_position_plan(&db).await;

        // And the counters must track a write made after the migration —
        // the defect's other half is triggers that exist but never fire.
        let before: Option<i64> = db
            .query(
                "SELECT n FROM queue_status_counts \
                 WHERE status = 'pending' AND lane = 'miss'",
            )
            .fetch_scalar_optional::<i64>()
            .await
            .expect("counter row");
        db.query(
            "INSERT INTO queue (task_id, crate_name, version, features_json, target, rustc_version)
             VALUES (?, 'post', '1.0.0', '[]', ?, '1.85.0')",
        )
        .bind(task_id_on("post", TARGET))
        .bind(TARGET)
        .execute()
        .await
        .expect("post-migration insert");
        let after: Option<i64> = db
            .query(
                "SELECT n FROM queue_status_counts \
                 WHERE status = 'pending' AND lane = 'miss'",
            )
            .fetch_scalar_optional::<i64>()
            .await
            .expect("counter row after insert");
        assert_eq!(
            after,
            Some(before.unwrap_or(0) + 1),
            "the counter trigger tracks a write made after the migration"
        );
    }

    /// The claim-frontier regression (stow#433): with every macOS slot
    /// taken and more than `CLAIM_MAX_PAGES × CLAIM_PAGE_ROWS` eligible
    /// macOS rows ordered ahead, a Rust-side skip spent the whole page
    /// budget on rows it could not claim, so the claimable rows past the
    /// frontier starved while `next_alarm` kept re-arming `At(now)` for
    /// them. The saturated family's exclusion lives in the claim query's
    /// WHERE now, so a pass must reach the Linux row.
    #[tokio::test]
    async fn a_saturated_macos_backlog_does_not_starve_other_families() {
        let db = memory_db().await.expect("memory db");
        // One more macOS row than the pass's page budget — enough to
        // fill every page if the exclusion were still Rust-side.
        let overflow = super::CLAIM_MAX_PAGES
            * usize::try_from(super::CLAIM_PAGE_ROWS).expect("claim page rows")
            + 1;
        let mut requests = Vec::with_capacity(overflow);
        for index in 0..overflow {
            requests.push(request_on(
                &format!("mac{index:05}"),
                MACOS_TARGET,
                Vec::new(),
            ));
        }
        // The backlog exceeds `max_queue_pending` — the trusted route
        // skips the cap, which is also how production's backlog got
        // that deep.
        super::enqueue_trusted(&db, &requests, &settings())
            .await
            .expect("enqueue macos backlog");
        super::enqueue_trusted(&db, &[request_on("lin", TARGET, Vec::new())], &settings())
            .await
            .expect("enqueue linux");
        // Order the macOS backlog strictly ahead of the Linux row in
        // claim order — persisted `dispatch_key` bakes the row's
        // `first_requested_at`, so recompute it in the same update.
        db.query("UPDATE queue SET first_requested_at = ? WHERE target = ?")
            .bind(PAST_TS)
            .bind(MACOS_TARGET)
            .execute()
            .await
            .expect("backdate macos backlog");
        let mac_ids = db
            .query("SELECT task_id FROM queue WHERE target = ?")
            .bind(MACOS_TARGET)
            .fetch_scalars::<String>()
            .await
            .expect("macos ids");
        super::refresh_dispatch_keys(&db, &mac_ids)
            .await
            .expect("recompute backdated keys");

        let settings = SchedulerSettings {
            max_concurrent_macos_jobs: 0,
            dispatch_min_age_minutes: 0,
            ..settings()
        };
        let claimed = super::claim_dispatchable_tasks(&db, &settings, &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "lin");
        assert_eq!(claimed[0].target, TARGET);
    }

    /// The claim pass reads in proportion to the slots it fills
    /// (stow#433): three open slots over a 2,000-row eligible frontier
    /// must issue exactly one page read — `LIMIT min(CLAIM_PAGE_ROWS,
    /// 2 × slots)` — and hand the coverage oracle a lookup sized to
    /// that page, never to the frontier.
    #[tokio::test]
    async fn a_small_slot_pass_reads_one_page_not_the_frontier() {
        let (db, log) = counting_memory_db().await.expect("counting db");
        let requests: Vec<EnqueueRequest> = (0..2_000)
            .map(|i| request(&format!("frontier-{i:04}"), Vec::new()))
            .collect();
        // The backlog sits at `max_queue_pending`; the trusted route
        // admits it regardless.
        super::enqueue_trusted(&db, &requests, &settings())
            .await
            .expect("enqueue frontier");

        let oracle = FixedCoverage {
            covered: BTreeSet::new(),
            asked: std::sync::Mutex::new(Vec::new()),
        };
        let settings = SchedulerSettings {
            dispatch: Dispatch::from_max_concurrent_jobs(3),
            dispatch_min_age_minutes: 0,
            ..settings()
        };
        let base = log.lock().expect("log").len();
        let claimed = super::claim_dispatchable_tasks(&db, &settings, &oracle)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 3);

        let page_reads = log
            .lock()
            .expect("log")
            .iter()
            .skip(base)
            .filter(|stmt| stmt.sql.starts_with("SELECT q.task_id, q.attempt"))
            .count();
        assert_eq!(
            page_reads, 1,
            "a 3-slot pass over a 2000-row frontier must read one page"
        );
        let asked = oracle.asked.lock().expect("oracle log").len();
        assert_eq!(
            asked, 6,
            "the coverage lookup is sized to the page (2 × slots), not the frontier"
        );
    }

    /// A dependent behind an unestablished edge (`dep_host_side = -1`)
    /// stays held even when its dep publishes every shape it owns:
    /// `p.unit_side = -1` matches no row, so nothing published can
    /// satisfy it — only the resolver's resync rewrites the edge with a
    /// real side, which is what a re-request carrying `depends_on` does.
    #[tokio::test]
    async fn dependent_behind_an_unestablished_edge_waits_for_resync() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("dep", Vec::new())])
            .await
            .expect("enqueue dep");
        enqueue(&db, &[request("parent", vec![dependency("dep")])])
            .await
            .expect("enqueue parent");
        // The spelling the migration writes on an edge whose required
        // side it could not derive.
        db.query("UPDATE queue_dependencies SET dep_host_side = -1")
            .execute()
            .await
            .expect("stamp unestablished edge");

        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim dep");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "dep");
        super::complete(
            &db,
            &claim_settings(),
            &report(
                &claimed[0].task_id,
                &claimed[0].generation_id,
                claimed[0].attempt,
                true,
            ),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete dep");
        publish(&db, "dep").await;
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim with unestablished edge");
        assert!(claimed.is_empty(), "a -1 edge satisfies no published row");

        enqueue(&db, &[request("parent", vec![dependency("dep")])])
            .await
            .expect("re-request parent resyncs the edge");
        let side = db
            .query("SELECT dep_host_side FROM queue_dependencies")
            .fetch_scalar::<i64>()
            .await
            .expect("edge side");
        assert_eq!(side, 0);

        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim after resync");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "parent");
    }

    /// A dependency reported `completed` whose published rows never
    /// covered a dependent's required shapes is not done: the claim pass
    /// re-queues it once — behind the existing backoff — so the rebuild
    /// republishes real shapes (stow#367). The latch holds, so a still-
    /// uncovered second completion does not loop the rebuild.
    #[tokio::test]
    async fn completed_dependency_with_uncovered_shapes_is_requeued_once() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("dep", Vec::new())])
            .await
            .expect("enqueue dep");
        enqueue(&db, &[request("parent", vec![dependency("dep")])])
            .await
            .expect("enqueue parent");
        mark_active(&db, "dep", TARGET, "completed").await;

        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert!(
            claimed.is_empty(),
            "the requeued dep sits behind its backoff and the parent stays gated"
        );
        assert_eq!(row_column(&db, "dep", "status").await, "pending");
        let latch = db
            .query("SELECT shape_requeue FROM queue WHERE task_id = ?")
            .bind(task_id_on("dep", TARGET))
            .fetch_scalar::<i64>()
            .await
            .expect("shape_requeue");
        assert_eq!(latch, 1);

        db.query("UPDATE queue SET not_before = '1970-01-01 00:00:00' WHERE task_id = ?")
            .bind(task_id_on("dep", TARGET))
            .execute()
            .await
            .expect("clear dep backoff");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim requeued dep");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "dep");
        super::complete(
            &db,
            &claim_settings(),
            &report(
                &claimed[0].task_id,
                &claimed[0].generation_id,
                claimed[0].attempt,
                true,
            ),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete dep");

        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim after second completion");
        assert!(
            claimed.is_empty(),
            "the latch blocks a second re-queue; the parent waits for the publish"
        );
        assert_eq!(row_column(&db, "dep", "status").await, "completed");

        publish(&db, "dep").await;
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim parent");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "parent");
    }

    /// The columns the requeue-ordering tests assert on.
    #[derive(Debug, skyzen::FromRow)]
    struct QueueCounters {
        status: String,
        attempt: i64,
        request_count: i64,
    }

    async fn queue_counters(db: &DurableDb, crate_name: &str) -> QueueCounters {
        db.query("SELECT status, attempt, request_count FROM queue WHERE task_id = ?")
            .bind(task_id_on(crate_name, TARGET))
            .fetch_one::<QueueCounters>()
            .await
            .expect("read queue counters")
    }

    /// Seed a row as failed with known counters so the assertions about
    /// what one chunk did to it are exact.
    async fn seed_failed(db: &DurableDb, crate_name: &str, attempt: i64, request_count: i64) {
        enqueue(db, &[request(crate_name, Vec::new())])
            .await
            .expect("seed enqueue");
        db.query(
            "UPDATE queue SET status = 'failed', attempt = ?, request_count = ?, \
             error_msg = 'boom' WHERE task_id = ?",
        )
        .bind(attempt)
        .bind(request_count)
        .bind(task_id_on(crate_name, TARGET))
        .execute()
        .await
        .expect("seed failed row");
    }

    /// Several parents in one chunk all name the same failed dep.
    /// Requesting a task no longer revives a terminal row from any
    /// lane: the dep's status, attempt and counters are untouched
    /// however many parents name it, and every parent parks `blocked`
    /// behind it.
    #[tokio::test]
    async fn a_chunk_never_revives_a_failed_dependency() {
        let db = memory_db().await.expect("memory db");
        seed_failed(&db, "dep", 7, 5).await;

        enqueue(
            &db,
            &[
                request("p1", vec![dependency("dep")]),
                request("p2", vec![dependency("dep")]),
                request("p3", vec![dependency("dep")]),
            ],
        )
        .await
        .expect("enqueue parents");

        let row = queue_counters(&db, "dep").await;
        assert_eq!(
            (row.status.as_str(), row.attempt, row.request_count),
            ("failed", 7, 5),
            "a request never revives a terminal row"
        );
        for parent in ["p1", "p2", "p3"] {
            assert_eq!(row_column(&db, parent, "CAST(blocked AS TEXT)").await, "1");
        }
    }

    /// The dep's own request is no different from its dependents':
    /// re-requesting a `failed` row counts the request —
    /// `request_count` +1 — and changes nothing else. `blocked` rows
    /// behave identically (`resurrects` names neither).
    #[tokio::test]
    async fn dep_request_never_revives_a_failed_dep_in_one_chunk() {
        let db = memory_db().await.expect("memory db");
        seed_failed(&db, "dep", 7, 5).await;

        enqueue(
            &db,
            &[
                request("dep", Vec::new()),
                request("parent", vec![dependency("dep")]),
            ],
        )
        .await
        .expect("enqueue dep then parent");

        let dep = queue_counters(&db, "dep").await;
        assert_eq!(
            (dep.status.as_str(), dep.attempt, dep.request_count),
            ("failed", 7, 6),
            "request counted, status untouched"
        );
        assert_eq!(
            row_column(&db, "parent", "CAST(blocked AS TEXT)").await,
            "1"
        );
    }

    /// Order inside the chunk is irrelevant — parent first lands the
    /// same as dep first: the failed row counts one request and keeps
    /// its terminal status.
    #[tokio::test]
    async fn parent_request_before_its_failed_dep_in_one_chunk() {
        let db = memory_db().await.expect("memory db");
        seed_failed(&db, "dep", 7, 5).await;

        enqueue(
            &db,
            &[
                request("parent", vec![dependency("dep")]),
                request("dep", Vec::new()),
            ],
        )
        .await
        .expect("enqueue parent then dep");

        let dep = queue_counters(&db, "dep").await;
        assert_eq!(
            (dep.status.as_str(), dep.attempt, dep.request_count),
            ("failed", 7, 6),
            "same outcome either order: no resurrection"
        );
    }

    /// Issue #418 regression guard: a submit chunk must not issue one
    /// statement per request or per edge. A 1000-request chunk with
    /// three deps each — 1000 fresh rows, 3000 edges, 4000 probe ids —
    /// runs 6 statements on the host backend: the chunked existence
    /// probes (2), the batched task insert (1), the edge-set delete (1),
    /// and the batched edge inserts (2). The schema check that topped
    /// them up is gone entirely (stow#432): request code runs none. A
    /// return to per-row statements issues thousands.
    #[tokio::test]
    async fn a_submit_chunk_issues_a_constant_statement_count() {
        let (db, log) = counting_memory_db().await.expect("counting db");
        let requests: Vec<EnqueueRequest> = (0..1000)
            .map(|i| {
                request(
                    &format!("req-{i}"),
                    (0..3)
                        .map(|k| dependency(&format!("dep-{i}-{k}")))
                        .collect(),
                )
            })
            .collect();
        let base = log.lock().expect("log").len();

        super::enqueue_trusted(&db, &requests, &settings())
            .await
            .expect("enqueue chunk");

        let issued = log.lock().expect("log").len() - base;
        // Eight: edge delete + edge insert + edge-flag probe + task
        // insert + task update + dep-requeue + `deps_met` refresh +
        // `dispatch_key` refresh, each a single statement over the
        // whole chunk regardless of request count.
        assert!(
            issued <= 8,
            "a 1000-request chunk must stay a constant statement count \
             (measured 8), got {issued}"
        );
    }

    // ===== Dispatch freeze (issue #279) =====

    /// Claim capacity large enough to seed whole windows of outcomes in
    /// one pass.
    const fn wide_claim_settings() -> SchedulerSettings {
        SchedulerSettings {
            dispatch: Dispatch::from_max_concurrent_jobs(500),
            dispatch_min_age_minutes: 0,
            ..settings()
        }
    }

    /// Enqueue then claim `count` tasks on `target`, then complete each
    /// one — `Some((error, run_id))` fails it, `None` succeeds —
    /// leaving `count` outcomes counted in `attempt_outcome_buckets`
    /// (and `count` raw rows in `attempt_outcomes` when all fail).
    async fn seed_outcomes(
        db: &DurableDb,
        batch: u32,
        count: usize,
        target: &str,
        failure: Option<(&str, &str)>,
    ) {
        // Names carry the batch: a repeat name re-requests a task whose
        // own retry backoff already hides it from the claim this
        // seeding is about to run.
        let requests: Vec<EnqueueRequest> = (0..count)
            .map(|i| request_on(&format!("outcome-{batch}-{i}"), target, Vec::new()))
            .collect();
        super::enqueue_trusted(db, &requests, &wide_claim_settings())
            .await
            .expect("seed enqueue");
        let claimed = super::claim_dispatchable_tasks(db, &wide_claim_settings(), &NoCoverage)
            .await
            .expect("seed claim");
        assert_eq!(claimed.len(), count);
        for task in claimed {
            let mut report = report(
                &task.task_id,
                &task.generation_id,
                task.attempt,
                failure.is_none(),
            );
            if let Some((error, run_id)) = failure {
                report.error = Some(error.to_owned());
                report.github_run_id = Some(run_id.to_owned());
            }
            super::complete(db, &wide_claim_settings(), &report, TEST_WINDOW_MINUTES)
                .await
                .expect("seed complete");
        }
    }

    fn freeze_record_fixture() -> stow_types::api::DispatchFreezeRecord {
        stow_types::api::DispatchFreezeRecord {
            frozen_at: "2026-09-22T03:51:00Z".to_owned(),
            trigger: stow_types::api::DispatchFreezeTrigger::Manual,
            notify: stow_types::api::ChannelOutcome::Disabled {
                reason: "test".to_owned(),
            },
        }
    }

    /// The record's presence is the flag: set reads back, enabled
    /// reports true, delete clears both.
    #[tokio::test]
    async fn freeze_record_roundtrips_and_deletes() {
        let db = memory_db().await.expect("memory db");
        assert!(super::freeze_record(&db).await.expect("read").is_none());
        assert!(!super::freeze_enabled(&db).await.expect("enabled"));

        let record = freeze_record_fixture();
        super::set_freeze(&db, &record).await.expect("set");
        assert!(super::freeze_enabled(&db).await.expect("enabled"));
        let stored = super::freeze_record(&db)
            .await
            .expect("read")
            .expect("stored");
        assert_eq!(stored, record);

        super::delete_freeze(&db).await.expect("delete");
        assert!(!super::freeze_enabled(&db).await.expect("enabled"));
        assert!(super::freeze_record(&db).await.expect("read").is_none());
    }

    /// While frozen, claim returns nothing and enqueue keeps accepting —
    /// and `next_alarm` plans `Delete` so no dispatch pass even wakes.
    /// Clearing restores dispatch.
    #[tokio::test]
    async fn freeze_gates_dispatch_but_not_enqueue_and_clear_resumes() {
        let db = memory_db().await.expect("memory db");
        super::set_freeze(&db, &freeze_record_fixture())
            .await
            .expect("set freeze");

        // Enqueue is unaffected — misses keep arriving.
        enqueue(&db, &[request("frozen-miss", Vec::new())])
            .await
            .expect("enqueue while frozen");
        // Dispatch is not: the claim gate answers empty no matter what
        // is pending.
        assert!(
            super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
                .await
                .expect("claim while frozen")
                .is_empty()
        );
        let plan = super::next_alarm(&db, ROW_TS_MS, &settings())
            .await
            .expect("next alarm while frozen");
        assert_eq!(plan, AlarmPlan::Delete);

        super::delete_freeze(&db).await.expect("clear");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim after clear");
        assert_eq!(claimed.len(), 1, "the freeze-queued miss dispatches");
    }

    /// The trip decision reads `attempt_outcomes`, not live queue rows —
    /// a retried task keeps every failed attempt inside the window.
    #[tokio::test]
    async fn evaluate_freeze_trip_reads_attempt_outcomes() {
        let db = memory_db().await.expect("memory db");
        let freeze = crate::freeze::FreezeSettings {
            window_minutes: 60,
            min_outcomes: 10,
            fail_percent: 50,
        };

        // Below the floor the ratio never trips, whatever it reads.
        seed_outcomes(&db, 0, 9, TARGET, Some(("build-crate 500", "run-1"))).await;
        assert!(
            super::evaluate_freeze_trip(&db, &freeze)
                .await
                .expect("evaluate")
                .is_none(),
            "9/9 failures under a floor of 10 must not trip"
        );

        // Crossing the floor *and* the ratio trips; the draft carries
        // the class tally and example run ids the alert prints.
        seed_outcomes(&db, 1, 1, TARGET, None).await;
        seed_outcomes(&db, 2, 1, TARGET, Some(("build-crate 500", "run-2"))).await;
        let draft = super::evaluate_freeze_trip(&db, &freeze)
            .await
            .expect("evaluate")
            .expect("10 failures of 11 outcomes trips (>= 10 sample, 91% >= 50%)");
        assert!(draft.eval.fleet_tripped);
        assert_eq!(draft.eval.outcomes, 11);
        assert_eq!(draft.eval.failures, 10);
        assert_eq!(
            draft.classes.first().map(|class| class.class.as_str()),
            Some("build-crate 500"),
            "the dominant class names the error's first line"
        );
        assert_eq!(draft.classes.first().map(|class| class.count), Some(10));
        assert_eq!(
            draft.example_run_ids,
            vec!["run-2".to_owned(), "run-1".to_owned()],
            "freshest failing run ids first"
        );
    }

    /// A failure wave concentrated on one target trips that target's
    /// stream even when the fleet aggregate stays under the ratio.
    #[tokio::test]
    async fn evaluate_freeze_trip_trips_a_single_target_stream() {
        let db = memory_db().await.expect("memory db");
        let freeze = crate::freeze::FreezeSettings {
            window_minutes: 60,
            min_outcomes: 10,
            fail_percent: 50,
        };
        // 10/10 on the Windows leg, all green on Linux: fleet 10/30 =
        // 33% stays quiet; the target trips alone.
        seed_outcomes(&db, 0, 20, TARGET, None).await;
        seed_outcomes(
            &db,
            1,
            10,
            WINDOWS_TARGET,
            Some(("linker exploded", "run-9")),
        )
        .await;
        let draft = super::evaluate_freeze_trip(&db, &freeze)
            .await
            .expect("evaluate")
            .expect("the concentrated stream trips");
        assert!(!draft.eval.fleet_tripped);
        let tripped: Vec<&str> = draft
            .eval
            .targets
            .iter()
            .filter(|target| target.tripped)
            .map(|target| target.target.as_str())
            .collect();
        assert_eq!(tripped, [WINDOWS_TARGET]);
    }

    /// The exact boundary is inclusive: `failures*100 >=
    /// outcomes*fail_percent` at the sample floor.
    #[tokio::test]
    async fn freeze_trip_boundary_is_inclusive() {
        let db = memory_db().await.expect("memory db");
        let freeze = crate::freeze::FreezeSettings {
            window_minutes: 60,
            min_outcomes: 10,
            fail_percent: 50,
        };
        seed_outcomes(&db, 0, 5, TARGET, None).await;
        seed_outcomes(&db, 1, 5, TARGET, Some(("boom", "run-1"))).await;
        assert!(
            super::evaluate_freeze_trip(&db, &freeze)
                .await
                .expect("evaluate")
                .is_some(),
            "5/10 failures at a 50% threshold trips"
        );
    }

    /// A completion's read set must stay constant as the outcome window
    /// fills — a wave of N completions cannot cost N rows per
    /// completion (the raw-row design read the whole in-window log:
    /// a wave of N completions read about N²/2 rows). Seed the window
    /// with 10, then 10,000 outcomes and measure the rows a failing
    /// completion plus its trip evaluation read: identical at both
    /// volumes.
    #[tokio::test]
    async fn a_completion_reads_a_constant_row_count_as_the_window_fills() {
        let freeze = crate::freeze::FreezeSettings {
            window_minutes: TEST_WINDOW_MINUTES,
            min_outcomes: 10,
            fail_percent: 50,
        };
        let mut reads = Vec::new();
        for volume in [10usize, 10_000] {
            let (db, log) = counting_memory_db().await.expect("counting db");
            // Fill the window the way a failure wave leaves it: twelve
            // in-window buckets totaling `volume` outcomes (all
            // failures), plus `volume` raw failure rows — the evidence
            // the trip alert reads.
            let per_bucket = i64::try_from(volume.div_ceil(12)).expect("fits");
            db.query(
                "WITH RECURSIVE seq(x) AS (                     SELECT 0 UNION ALL SELECT x + 1 FROM seq WHERE x < 11                 )                  INSERT INTO attempt_outcome_buckets (target, bucket, outcomes, failures)                  SELECT ?, (unixepoch('now') / 300) * 300 - x * 300, ?, ? FROM seq",
            )
            .bind(TARGET)
            .bind(per_bucket)
            .bind(per_bucket)
            .execute()
            .await
            .expect("seed buckets");
            db.query(
                "WITH RECURSIVE seq(x) AS (                     SELECT 1 UNION ALL SELECT x + 1 FROM seq WHERE x <= ?                 )                  INSERT INTO attempt_outcomes_v2                      (task_id, generation_id, attempt, target, failure_class,                       github_run_id, finished_at)                  SELECT 'seed-' || x, 'seed-generation-' || x, 1, ?, 'boom',                         'run-' || x, datetime('now', '-' || (x % 50) || ' minutes')                  FROM seq",
            )
            .bind(i64::try_from(volume).expect("fits"))
            .bind(TARGET)
            .execute()
            .await
            .expect("seed failure rows");

            // The measured completion: a live task reports a failure,
            // then the trip evaluation runs — the production handler's
            // exact read path.
            enqueue(&db, &[request("measured", Vec::new())])
                .await
                .expect("enqueue");
            let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
                .await
                .expect("claim");
            let base = log.lock().expect("log").len();
            super::complete(
                &db,
                &claim_settings(),
                &super::BuildCompleteReport {
                    task_id: claimed[0].task_id.clone(),
                    generation_id: claimed[0].generation_id.clone(),
                    attempt: claimed[0].attempt,
                    success: false,
                    error: Some("boom".to_owned()),
                    finished_at: None,
                    github_run_id: Some("run-live".to_owned()),
                },
                TEST_WINDOW_MINUTES,
            )
            .await
            .expect("complete");
            super::evaluate_freeze_trip(&db, &freeze)
                .await
                .expect("evaluate");
            let read: u64 = log.lock().expect("log")[base..]
                .iter()
                .map(|entry| entry.rows_read)
                .sum();
            reads.push(read);
        }
        assert_eq!(
            reads[0], reads[1],
            "a completion over 10 stored outcomes read {} rows; over 10,000 \
             it read {} — the read set must be window-bounded, not volume-\
             bounded",
            reads[0], reads[1]
        );
    }
    /// `POST /requests` input for `crate_name` — mirrors the edge's
    /// admission after version/rustc resolution.
    fn admission(crate_name: &str) -> stow_types::api::RequestAdmission {
        stow_types::api::RequestAdmission {
            request_id: stow_types::api::request_id(crate_name, VERSION, FEATURES, RUSTC),
            crate_name: crate_name.parse().expect("request crate"),
            version: VERSION.parse().expect("request version"),
            features_json: FeaturesJson::default(),
            rustc_version: RUSTC.parse().expect("request rustc"),
            max_closure: 500,
        }
    }

    fn resolved_report(attempt: u32, crate_name: &str) -> stow_types::api::RequestOutcomeReport {
        use stow_types::api::{RequestOutcome, RequestOutcomeReport, RequestRootOutcome};
        let task = EnqueueRequest {
            source: EnqueueSource::HumanRequest,
            ..request(crate_name, vec![dependency("dep")])
        };
        RequestOutcomeReport {
            attempt,
            outcome: RequestOutcome::Resolved {
                tasks: vec![task],
                roots: vec![RequestRootOutcome {
                    target: TARGET.parse().expect("target"),
                    task_id: Some(task_id_on(crate_name, TARGET)),
                    cached: false,
                }],
            },
        }
    }

    #[tokio::test]
    async fn request_admission_dedups_and_re_attempts_a_failed_record() {
        let db = memory_db().await.expect("memory db");
        let admission = admission("req-crate");

        let step = super::admit_request(&db, &admission, 1_000, &settings())
            .await
            .expect("first admit");
        assert!(matches!(
            step,
            super::RequestAdmissionStep::Dispatch { attempt: 1 }
        ));
        let status = super::crate_request_status(&db, &admission.request_id)
            .await
            .expect("status")
            .expect("record");
        assert_eq!(status.status, stow_types::api::CrateRequestPhase::Accepted);

        // Same request id again — the live record answers, no re-dispatch.
        let step = super::admit_request(&db, &admission, 2_000, &settings())
            .await
            .expect("second admit");
        assert!(matches!(step, super::RequestAdmissionStep::Existing));

        // A `failed` record re-attempts at `attempt + 1` in one write.
        super::fail_request_dispatch(&db, &admission.request_id, 1, "dispatch refused")
            .await
            .expect("fail");
        let step = super::admit_request(&db, &admission, 3_000, &settings())
            .await
            .expect("re-attempt admit");
        assert!(matches!(
            step,
            super::RequestAdmissionStep::Dispatch { attempt: 2 }
        ));
        let status = super::crate_request_status(&db, &admission.request_id)
            .await
            .expect("status")
            .expect("record");
        assert_eq!(status.status, stow_types::api::CrateRequestPhase::Accepted);
        assert_eq!(status.error, None);
    }

    #[tokio::test]
    async fn request_admission_refuses_when_the_day_is_spent() {
        let db = memory_db().await.expect("memory db");
        db.query(
            "INSERT INTO human_daily_task_budget (day, task_count) \
             VALUES (date('now'), ?)",
        )
        .bind(i64::from(settings().human_daily_task_budget))
        .execute()
        .await
        .expect("seed spent day");
        let error = super::admit_request(&db, &admission("req-crate"), 1_000, &settings())
            .await
            .expect_err("spent day refuses admission");
        assert!(matches!(
            error,
            QueueError::HumanDailyBudgetExhausted { .. }
        ));
    }

    #[tokio::test]
    async fn request_run_updates_drive_the_lifecycle() {
        let db = memory_db().await.expect("memory db");
        let admission = admission("req-crate");
        super::admit_request(&db, &admission, 1_000, &settings())
            .await
            .expect("admit");

        super::record_request_run_update(
            &db,
            &admission.request_id,
            &stow_types::api::RequestRunUpdate {
                attempt: 1,
                action: stow_types::api::RequestRunAction::InProgress,
                conclusion: None,
                run_id: Some("9".to_owned()),
                run_url: Some("https://example/run/9".to_owned()),
            },
        )
        .await
        .expect("in_progress");
        let status = super::crate_request_status(&db, &admission.request_id)
            .await
            .expect("status")
            .expect("record");
        assert_eq!(status.status, stow_types::api::CrateRequestPhase::Resolving);
        assert_eq!(status.github_run_id.as_deref(), Some("9"));

        // A `completed` delivery on a live record is the failure
        // backstop: the resolve reported no outcome.
        super::record_request_run_update(
            &db,
            &admission.request_id,
            &stow_types::api::RequestRunUpdate {
                attempt: 1,
                action: stow_types::api::RequestRunAction::Completed,
                conclusion: Some("success".to_owned()),
                run_id: Some("9".to_owned()),
                run_url: Some("https://example/run/9".to_owned()),
            },
        )
        .await
        .expect("completed");
        let status = super::crate_request_status(&db, &admission.request_id)
            .await
            .expect("status")
            .expect("record");
        assert_eq!(status.status, stow_types::api::CrateRequestPhase::Failed);
        assert!(
            status
                .error
                .as_deref()
                .is_some_and(|error| error.contains("outcome report")),
            "the backstop names why the record failed: {:?}",
            status.error
        );
    }

    #[tokio::test]
    async fn request_run_update_refuses_a_stale_attempt() {
        let db = memory_db().await.expect("memory db");
        let admission = admission("req-crate");
        super::admit_request(&db, &admission, 1_000, &settings())
            .await
            .expect("admit");
        let error = super::record_request_run_update(
            &db,
            &admission.request_id,
            &stow_types::api::RequestRunUpdate {
                attempt: 9,
                action: stow_types::api::RequestRunAction::InProgress,
                conclusion: None,
                run_id: None,
                run_url: None,
            },
        )
        .await
        .expect_err("attempt 9 is stale");
        assert!(matches!(error, QueueError::RequestAttemptSuperseded { .. }));
    }

    #[tokio::test]
    async fn request_outcome_enqueues_and_settles_the_record() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("dep", Vec::new())])
            .await
            .expect("enqueue dep");
        let admission = admission("req-crate");
        super::admit_request(&db, &admission, 1_000, &settings())
            .await
            .expect("admit");

        let status = super::apply_request_outcome(
            &db,
            &settings(),
            &admission.request_id,
            &resolved_report(1, "req-crate"),
        )
        .await
        .expect("outcome");
        assert_eq!(status.status, stow_types::api::CrateRequestPhase::Enqueued);
        assert_eq!(status.targets.len(), 1);
        assert_eq!(
            status.targets[0].state,
            stow_types::api::CrateRequestState::Queued
        );

        // The root task landed as a pending human-lane row.
        let lane: String = db
            .query("SELECT lane FROM queue WHERE task_id = ?")
            .bind(task_id_on("req-crate", TARGET))
            .fetch_scalar::<String>()
            .await
            .expect("read task lane");
        let status_row: String = db
            .query("SELECT status FROM queue WHERE task_id = ?")
            .bind(task_id_on("req-crate", TARGET))
            .fetch_scalar::<String>()
            .await
            .expect("read task status");
        assert_eq!((lane.as_str(), status_row.as_str()), ("human", "pending"));

        // A second identical report is a no-op read of the settled
        // record — not a re-enqueue.
        let again = super::apply_request_outcome(
            &db,
            &settings(),
            &admission.request_id,
            &resolved_report(1, "req-crate"),
        )
        .await
        .expect("replay");
        assert_eq!(again.status, stow_types::api::CrateRequestPhase::Enqueued);

        // And a `completed` webhook delivery afterward must not claw the
        // settled record back to `failed` — the conditional write's
        // whole point (stow#428 review).
        super::record_request_run_update(
            &db,
            &admission.request_id,
            &stow_types::api::RequestRunUpdate {
                attempt: 1,
                action: stow_types::api::RequestRunAction::Completed,
                conclusion: Some("failure".to_owned()),
                run_id: None,
                run_url: None,
            },
        )
        .await
        .expect("completed after settle");
        let status = super::crate_request_status(&db, &admission.request_id)
            .await
            .expect("status")
            .expect("record");
        assert_eq!(status.status, stow_types::api::CrateRequestPhase::Enqueued);
    }

    #[tokio::test]
    async fn request_outcome_failed_marks_the_record() {
        let db = memory_db().await.expect("memory db");
        let admission = admission("req-crate");
        super::admit_request(&db, &admission, 1_000, &settings())
            .await
            .expect("admit");
        let status = super::apply_request_outcome(
            &db,
            &settings(),
            &admission.request_id,
            &stow_types::api::RequestOutcomeReport {
                attempt: 1,
                outcome: stow_types::api::RequestOutcome::Failed {
                    error: "resolve: no semver-compatible version".to_owned(),
                },
            },
        )
        .await
        .expect("failed outcome");
        assert_eq!(status.status, stow_types::api::CrateRequestPhase::Failed);
        assert_eq!(
            status.error.as_deref(),
            Some("resolve: no semver-compatible version")
        );
    }

    #[tokio::test]
    async fn request_outcome_refuses_a_stale_attempt() {
        let db = memory_db().await.expect("memory db");
        let admission = admission("req-crate");
        super::admit_request(&db, &admission, 1_000, &settings())
            .await
            .expect("admit");
        let error = super::apply_request_outcome(
            &db,
            &settings(),
            &admission.request_id,
            &resolved_report(2, "req-crate"),
        )
        .await
        .expect_err("attempt 2 is stale");
        assert!(matches!(error, QueueError::RequestAttemptSuperseded { .. }));
    }

    // ---- stow#524: expected build cost ----

    /// Claim, pin the claim instant `minutes_ago` back, bind a run and
    /// complete it successfully — one honest sample of the path a real
    /// build takes. `claimed_at` is pinned by raw UPDATE for the same
    /// reason `mark_active` writes `updated_at` directly: no public
    /// function produces a past claim stamp, and the pin must be exact
    /// for a deterministic duration assertion.
    async fn complete_success_at_minutes(
        db: &DurableDb,
        task_id: &str,
        run: &str,
        minutes_ago: u32,
    ) {
        let claimed = super::claim_dispatchable_tasks(db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim")[0]
            .clone();
        db.query("UPDATE queue SET claimed_at = datetime('now', ?) WHERE task_id = ?")
            .bind(format!("-{minutes_ago} minutes"))
            .bind(task_id.to_owned())
            .execute()
            .await
            .expect("pin claim instant");
        super::bind_dispatch_run(db, task_id, &claimed.generation_id, run)
            .await
            .expect("bind run");
        super::complete_run(
            db,
            &settings(),
            &report_with_run(task_id, true, run),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete");
    }

    #[derive(skyzen::FromRow)]
    struct BuildStatRow {
        builds: i64,
        median_ms: i64,
    }

    /// `EXPLAIN QUERY PLAN` detail rows — only the plan text matters.
    #[derive(skyzen::FromRow)]
    struct PlanRow {
        detail: String,
    }

    async fn build_stats(db: &DurableDb, crate_name: &str) -> Option<BuildStatRow> {
        db.query(
            "SELECT builds, median_ms FROM crate_build_stats \
             WHERE crate_name = ? AND target = ?",
        )
        .bind(crate_name.to_owned())
        .bind(TARGET)
        .fetch_optional::<BuildStatRow>()
        .await
        .expect("build stats")
    }

    async fn sample_count(db: &DurableDb, crate_name: &str) -> i64 {
        db.query("SELECT count(*) FROM crate_build_samples WHERE crate_name = ?")
            .bind(crate_name.to_owned())
            .fetch_scalar::<i64>()
            .await
            .expect("sample count")
    }

    /// The in-flight re-request writer rewrites `updated_at` even on an
    /// active task — a resubmitted build's duration must still measure
    /// from the claim's immutable `claimed_at`, not the mutable stamp.
    #[tokio::test]
    async fn build_duration_samples_the_immutable_claim_instant() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("durable", Vec::new())])
            .await
            .expect("enqueue");
        let id = task_id_on("durable", TARGET);
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim")[0]
            .clone();
        super::bind_dispatch_run(&db, &id, &claimed.generation_id, "run-1")
            .await
            .expect("bind");
        // Pin the claim instant BEFORE the resubmission so a writer
        // that clobbered `claimed_at` would be caught rather than
        // masked: the pin must survive the in-flight writer verbatim.
        db.query("UPDATE queue SET claimed_at = datetime('now', '-1 hour') WHERE task_id = ?")
            .bind(id.clone())
            .execute()
            .await
            .expect("pin claim instant");
        let pinned = row_column(&db, "durable", "claimed_at").await;
        // The resubmission: `apply_batched_updates` rewrites
        // `updated_at` on the in-flight row.
        enqueue(&db, &[request("durable", Vec::new())])
            .await
            .expect("in-flight resubmission");
        let claimed_at = row_column(&db, "durable", "claimed_at").await;
        let updated_at = row_column(&db, "durable", "updated_at").await;
        assert_eq!(claimed_at, pinned, "the resubmit rewrote claimed_at");
        assert_ne!(claimed_at, updated_at, "the resubmit moved updated_at");

        super::complete_run(
            &db,
            &settings(),
            &report_with_run(&id, true, "run-1"),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete");

        let duration = db
            .query("SELECT duration_ms FROM crate_build_samples WHERE crate_name = 'durable'")
            .fetch_scalar::<i64>()
            .await
            .expect("duration sample");
        assert!(
            (3_500_000..=3_700_000).contains(&duration),
            "claim-to-completion ~1h, not resubmit-to-completion ~0: {duration}"
        );
        let stats = build_stats(&db, "durable").await.expect("stats row exists");
        assert_eq!(stats.builds, 1);
        assert_eq!(stats.median_ms, duration);
    }

    /// A deferred completion — the webhook landed while the row's
    /// `github_run_id` was still `NULL`, so it parked in
    /// `pending_run_completions` — measures claim-to-`received_at`, the
    /// instant the run actually finished, not the later binding moment.
    #[tokio::test]
    async fn deferred_completion_measures_duration_at_received_at() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("deferred", Vec::new())])
            .await
            .expect("enqueue");
        let id = task_id_on("deferred", TARGET);
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim")[0]
            .clone();
        db.query("UPDATE queue SET claimed_at = datetime('now', '-1 hour') WHERE task_id = ?")
            .bind(id.clone())
            .execute()
            .await
            .expect("pin claim instant");
        // The report arrives with no run bound yet — it parks, stamping
        // `received_at` at arrival.
        assert!(
            super::persist_pending_completion(&db, &report_with_run(&id, true, "run-def"))
                .await
                .expect("park completion")
        );
        super::bind_dispatch_run(&db, &id, &claimed.generation_id, "run-def")
            .await
            .expect("bind run");
        super::apply_pending_completion_for_binding(
            &db,
            &settings(),
            &id,
            &claimed.generation_id,
            "run-def",
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("apply bound completion");

        let duration = db
            .query("SELECT duration_ms FROM crate_build_samples WHERE crate_name = 'deferred'")
            .fetch_scalar::<i64>()
            .await
            .expect("duration sample");
        assert!(
            (3_500_000..=3_700_000).contains(&duration),
            "claim-to-received_at ~1h: {duration}"
        );
    }

    /// A measured claim-to-completion span is nonnegative by
    /// construction; a report whose finish precedes its claim (skewed
    /// `finished_at`, a future `claimed_at`) must fail the sample
    /// insert through the column's `CHECK (duration_ms >= 0)` — the
    /// span is never clamped into a bogus zero. The failed statement
    /// must leave no trace: no sample, no stats row, no median and no
    /// key refresh off it. A legitimately zero-length span (sub-ms
    /// build) still records and floors its median to the 1ms unit.
    #[tokio::test]
    async fn backward_completion_span_fails_without_polluting_stats() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("skewed", Vec::new())])
            .await
            .expect("enqueue");
        let id = task_id_on("skewed", TARGET);
        let report = super::BuildCompleteReport {
            task_id: id,
            generation_id: "gen-skew".to_owned(),
            attempt: 1,
            success: true,
            error: None,
            github_run_id: Some("run-skew".to_owned()),
            finished_at: Some(ROW_TS.to_owned()),
        };
        // Claim stamped after the reported finish — a negative span.
        let error =
            super::record_build_sample(&db, &report, "skewed", TARGET, Some("2099-01-01 00:00:00"))
                .await
                .expect_err("negative measured span fails");
        assert!(
            error.to_string().contains("record build sample"),
            "statement error, not a silent write: {error}"
        );
        let count = db
            .query(
                "SELECT (SELECT count(*) FROM crate_build_samples) + \
                 (SELECT count(*) FROM crate_build_stats) AS n",
            )
            .fetch_scalar::<i64>()
            .await
            .expect("cost state count");
        assert_eq!(count, 0, "no sample/stats/window pollution");

        // The legitimate zero-length span records and floors to the
        // 1ms unit at the stats write.
        let same = super::BuildCompleteReport {
            finished_at: Some(ROW_TS.to_owned()),
            ..report
        };
        super::record_build_sample(&db, &same, "skewed", TARGET, Some(ROW_TS))
            .await
            .expect("zero-length span records");
        let median = db
            .query("SELECT median_ms FROM crate_build_stats WHERE crate_name = 'skewed'")
            .fetch_scalar::<i64>()
            .await
            .expect("median");
        assert_eq!(median, 1, "0ms span floors to the 1ms unit");
    }

    /// One task's stored key prefix — the 65-char lane+score field the
    /// rank assertions compare.
    async fn prefix_of(db: &DurableDb, name: &str) -> String {
        db.query("SELECT substr(dispatch_key, 1, 65) AS p FROM queue WHERE crate_name = ?")
            .bind(name.to_owned())
            .fetch_scalar::<String>()
            .await
            .expect("prefix")
    }

    async fn status_of(db: &DurableDb, name: &str) -> String {
        db.query("SELECT status FROM queue WHERE crate_name = ?")
            .bind(name.to_owned())
            .fetch_scalar::<String>()
            .await
            .expect("status")
    }

    /// The key prefix the same operands derive at the moved cost —
    /// what every repriced row must carry.
    fn repriced_prefix() -> String {
        crate::scheduler::rank::rank_prefix("miss", 100, std::num::NonZero::new(1000).unwrap())
    }

    /// The shared fixture: five fresh-keyed rows whose stored keys go
    /// stale the moment a cost lands underneath them — each named for
    /// the re-entry path it exercises, `waiter` the non-transitioned
    /// control.
    async fn reentry_fixture() -> (DurableDb, String) {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[
                request("retried", Vec::new()),
                request("failed-dispatch", Vec::new()),
                request("stale", Vec::new()),
                request("shaped", Vec::new()),
                request("waiter", vec![dependency("shaped")]),
            ],
        )
        .await
        .expect("enqueue");
        // Fresh keys at cost 1 (no stats yet); then the cost moves
        // underneath them — each row's stored key is now stale.
        for name in ["retried", "failed-dispatch", "stale", "shaped", "waiter"] {
            db.query(
                "INSERT INTO crate_build_stats \
                 (crate_name, target, builds, median_ms) \
                 VALUES (?, ?, 3, 1000)",
            )
            .bind(name.to_owned())
            .bind(TARGET)
            .execute()
            .await
            .expect("move cost");
            db.query("UPDATE queue SET priority = 100 WHERE crate_name = ?")
                .bind(name.to_owned())
                .execute()
                .await
                .expect("set priority");
        }
        let stale_prefix = prefix_of(&db, "retried").await;
        for name in ["failed-dispatch", "stale", "shaped", "waiter"] {
            assert_eq!(
                prefix_of(&db, name).await,
                stale_prefix,
                "{name} starts on the cost-1 key"
            );
        }
        (db, stale_prefix)
    }

    /// Every nonpending→pending re-entry reprices through the shared
    /// refresh: a row whose key was written before a cost move must
    /// leave the transition carrying the new cost's rank — on the
    /// operator `Retry` and on `mark_dispatch_failed` here, on the
    /// stale-lease recovery and the incomplete-shape requeue in the
    /// sibling test — while rows that did not transition keep their
    /// keys byte-for-byte.
    #[tokio::test]
    async fn retry_and_dispatch_failure_reprice_against_moved_cost() {
        let (db, _stale) = reentry_fixture().await;
        let priced = repriced_prefix;

        // Operator Retry: failed → pending.
        db.query("UPDATE queue SET status = 'failed' WHERE crate_name = 'retried'")
            .execute()
            .await
            .expect("park failed");
        let selector = super::QueueSelector {
            task_ids: vec![task_id_on("retried", TARGET)],
            ..Default::default()
        };
        super::apply_mutation(&db, &settings(), super::QueueMutation::Retry, &selector)
            .await
            .expect("retry");
        assert_eq!(status_of(&db, "retried").await, "pending");
        assert_eq!(prefix_of(&db, "retried").await, priced());

        // mark_dispatch_failed: dispatched (run unbound) → pending.
        db.query(
            "UPDATE queue SET status = 'dispatched', generation_id = 'gen-fd' \
             WHERE crate_name = 'failed-dispatch'",
        )
        .execute()
        .await
        .expect("mark dispatched");
        super::mark_dispatch_failed(
            &db,
            &settings(),
            &task_id_on("failed-dispatch", TARGET),
            "gen-fd",
            "workflow_dispatch failed",
        )
        .await
        .expect("dispatch failure");
        assert_eq!(status_of(&db, "failed-dispatch").await, "pending");
        assert_eq!(prefix_of(&db, "failed-dispatch").await, priced());
    }

    /// The other two nonpending→pending paths — see
    /// [`retry_and_dispatch_failure_reprice_against_moved_cost`].
    #[tokio::test]
    async fn stale_recovery_and_shape_requeue_reprice_against_moved_cost() {
        let (db, stale_prefix) = reentry_fixture().await;
        let priced = repriced_prefix;

        // Stale-lease recovery: running, past the stale window → pending.
        db.query(
            "UPDATE queue SET status = 'running', updated_at = datetime('now', '-2 days') \
             WHERE crate_name = 'stale'",
        )
        .execute()
        .await
        .expect("mark stale");
        super::recover_stale_active_tasks(&db, &settings())
            .await
            .expect("recover stale");
        assert_eq!(status_of(&db, "stale").await, "pending");
        assert_eq!(prefix_of(&db, "stale").await, priced());

        // Incomplete-shape requeue: completed dep → pending once.
        db.query("UPDATE queue SET status = 'completed' WHERE crate_name = 'shaped'")
            .execute()
            .await
            .expect("mark completed");
        db.query(
            "UPDATE queue_dependencies SET dep_crate_name = 'shaped', \
                 dep_host_side = 0, dep_met = 0 \
             WHERE task_id = ? AND depends_on_task_id = ?",
        )
        .bind(task_id_on("waiter", TARGET))
        .bind(task_id_on("shaped", TARGET))
        .execute()
        .await
        .expect("resolve edge identity");
        super::requeue_incomplete_shape_deps(&db, &settings())
            .await
            .expect("shape requeue");
        assert_eq!(status_of(&db, "shaped").await, "pending");
        assert_eq!(prefix_of(&db, "shaped").await, priced());

        // The non-transitioned row keeps its stale key byte-for-byte:
        // only the refresh's own cost-move path may reprice it.
        assert_eq!(prefix_of(&db, "waiter").await, stale_prefix);
    }

    /// The statistic is the window's lower median — durations 1, 2,
    /// and 100 minutes report 2 minutes, where a moving mean would
    /// report ~34 — and the window never grows past
    /// `BUILD_SAMPLE_WINDOW` however many samples land.
    #[tokio::test]
    async fn build_stats_median_is_a_real_median_over_a_bounded_window() {
        let db = memory_db().await.expect("memory db");
        let versions = ["1.0.0", "1.1.0", "1.2.0"];
        let minutes = [1, 2, 100];
        for (version, minutes_ago) in versions.iter().zip(minutes) {
            let mut request = request_on("median", TARGET, Vec::new());
            request.version = version.parse().expect("semver");
            enqueue(&db, &[request]).await.expect("enqueue");
            let id = stow_types::api::task_id("median", version, FEATURES, TARGET, RUSTC, false);
            complete_success_at_minutes(&db, &id, &format!("run-{version}"), minutes_ago).await;
        }
        let stats = build_stats(&db, "median").await.expect("stats row");
        assert_eq!(stats.builds, 3);
        assert!(
            (110_000..=130_000).contains(&stats.median_ms),
            "lower median of 1/2/100 min is 2 min, not the ~34-min mean: {}",
            stats.median_ms
        );

        // The window caps at BUILD_SAMPLE_WINDOW: enough further
        // completions to overflow it leave exactly the bound.
        for round in 0..(super::BUILD_SAMPLE_WINDOW + 3) {
            let version = format!("2.0.{round}");
            let mut request = request_on("median", TARGET, Vec::new());
            request.version = version.parse().expect("semver");
            enqueue(&db, &[request]).await.expect("enqueue");
            let id = stow_types::api::task_id("median", &version, FEATURES, TARGET, RUSTC, false);
            complete_success_at_minutes(&db, &id, &format!("run-b{round}"), 3).await;
        }
        assert_eq!(
            sample_count(&db, "median").await,
            super::BUILD_SAMPLE_WINDOW
        );
        assert_eq!(
            build_stats(&db, "median").await.expect("stats row").builds,
            3 + super::BUILD_SAMPLE_WINDOW + 3
        );
    }

    /// The generation fence reaches the sample path: a replayed report
    /// for a consumed generation and a report naming a generation that
    /// was never live are both rejected before they can record a
    /// duration, and a failure never samples at all.
    #[tokio::test]
    async fn stale_duplicate_and_failed_reports_never_sample() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("fenced", Vec::new())])
            .await
            .expect("enqueue");
        let id = task_id_on("fenced", TARGET);
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim")[0]
            .clone();
        super::bind_dispatch_run(&db, &id, &claimed.generation_id, "run-f")
            .await
            .expect("bind");
        super::complete_run(
            &db,
            &settings(),
            &report_with_run(&id, true, "run-f"),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete");
        assert_eq!(sample_count(&db, "fenced").await, 1);

        let replay = super::complete_run(
            &db,
            &settings(),
            &report_with_run(&id, true, "run-f"),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect_err("replayed completion conflicts");
        assert!(matches!(replay, QueueError::StaleCompletion { .. }));
        let ghost = super::complete(
            &db,
            &settings(),
            &report(&id, "never-live-generation", 1, true),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect_err("old-generation report conflicts");
        assert!(matches!(ghost, QueueError::StaleCompletion { .. }));
        assert_eq!(
            sample_count(&db, "fenced").await,
            1,
            "rejected reports added no samples"
        );

        enqueue(&db, &[request("failonly", Vec::new())])
            .await
            .expect("enqueue");
        let fail_id = task_id_on("failonly", TARGET);
        let failed_claim = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim")[0]
            .clone();
        super::bind_dispatch_run(&db, &fail_id, &failed_claim.generation_id, "run-x")
            .await
            .expect("bind");
        super::complete_run(
            &db,
            &settings(),
            &report_with_run(&fail_id, false, "run-x"),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("failure completes");
        assert_eq!(
            sample_count(&db, "failonly").await,
            0,
            "a truncated failure run prices no build"
        );
    }

    /// Cost divides the demand operand inside a band: at equal
    /// priority the crate the stats call cheaper claims first, while
    /// the bands stay absolute — an unmeasured cheap miss can never
    /// outrank a measured expensive human task.
    #[tokio::test]
    async fn cheaper_expected_build_claims_first_inside_a_band() {
        let db = memory_db().await.expect("memory db");
        db.query(
            "INSERT INTO crate_build_stats (crate_name, target, builds, median_ms) \
             VALUES ('pricey', ?, 5, 3600000)",
        )
        .bind(TARGET)
        .execute()
        .await
        .expect("seed pricey stats");
        let expensive = stow_types::api::EnqueueRequest {
            downloads: 5_000_000,
            ..request("pricey", Vec::new())
        };
        let cheap = stow_types::api::EnqueueRequest {
            downloads: 5_000_000,
            ..request("cheap", Vec::new())
        };
        enqueue(&db, &[expensive, cheap]).await.expect("enqueue");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed[0].crate_name, "cheap", "cost-divided rank");

        // Bands still win: a pricey human-lane task claims ahead of an
        // unmeasured miss however cheap the miss looks.
        let db = memory_db().await.expect("memory db");
        db.query(
            "INSERT INTO crate_build_stats (crate_name, target, builds, median_ms) \
             VALUES ('hpricey', ?, 5, 3600000)",
        )
        .bind(TARGET)
        .execute()
        .await
        .expect("seed pricey stats");
        let human = stow_types::api::EnqueueRequest {
            downloads: 5_000_000,
            source: EnqueueSource::HumanRequest,
            ..request("hpricey", Vec::new())
        };
        let miss = stow_types::api::EnqueueRequest {
            downloads: 5_000_000,
            ..request("mcheap", Vec::new())
        };
        super::enqueue_trusted(&db, &[human, miss], &settings())
            .await
            .expect("enqueue");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(
            claimed[0].crate_name, "hpricey",
            "band precedence is undivided"
        );
    }

    /// Equal score operands keep `value`'s FIFO: same band, same
    /// priority, same cost answer → `first_requested_at` decides.
    #[tokio::test]
    async fn equal_scores_keep_fifo_order() {
        let db = memory_db().await.expect("memory db");
        let first = stow_types::api::EnqueueRequest {
            downloads: 5_000_000,
            ..request("fifo-first", Vec::new())
        };
        let second = stow_types::api::EnqueueRequest {
            downloads: 5_000_000,
            ..request("fifo-second", Vec::new())
        };
        enqueue(&db, &[first, second]).await.expect("enqueue");
        db.query(
            "UPDATE queue SET first_requested_at = '2025-01-01 00:00:00' \
             WHERE crate_name = 'fifo-first'",
        )
        .execute()
        .await
        .expect("age the first request");
        // The instant is baked into the key — the same keyed refresh
        // every operand move takes rewrites it.
        super::refresh_dispatch_keys(&db, &[task_id_on("fifo-first", TARGET)])
            .await
            .expect("refresh aged key");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed[0].crate_name, "fifo-first");
    }

    /// The stats probe correlates to the outer row on every recompute
    /// path: two crates with different medians must each price by
    /// their own (`crate_name`, `target`) row through a resubmit's key
    /// refresh, a promote and a median move — not whatever stats row
    /// the table yields first (stow#524 review: an unqualified probe
    /// collapses to `s.crate_name = s.crate_name` and answers one
    /// median for every row).
    #[tokio::test]
    async fn refreshed_scores_price_their_own_crate_target() {
        let db = memory_db().await.expect("memory db");
        // 'dear' lands in the table first, so a broken probe hands its
        // median to every row and makes 'cheap' indistinguishable.
        db.query(
            "INSERT INTO crate_build_stats (crate_name, target, builds, median_ms) \
             VALUES ('dear', ?, 5, 3600000), ('cheap', ?, 5, 36000), ('cheap', ?, 5, 999999)",
        )
        .bind(TARGET)
        .bind(TARGET)
        .bind(MACOS_TARGET)
        .execute()
        .await
        .expect("seed stats");
        let dear = stow_types::api::EnqueueRequest {
            downloads: 5_000_000,
            ..request("dear", Vec::new())
        };
        let cheap = stow_types::api::EnqueueRequest {
            downloads: 5_000_000,
            ..request("cheap", Vec::new())
        };
        let mac = stow_types::api::EnqueueRequest {
            downloads: 5_000_000,
            ..request_on("cheap", MACOS_TARGET, Vec::new())
        };
        enqueue(&db, &[dear, cheap, mac]).await.expect("enqueue");

        let prefix = async |db: &DurableDb, name: &str, target: &str| -> String {
            db.query(
                "SELECT substr(dispatch_key, 1, 65) AS p FROM queue \
                 WHERE crate_name = ? AND target = ?",
            )
            .bind(name.to_owned())
            .bind(target.to_owned())
            .fetch_scalar::<String>()
            .await
            .expect("score prefix")
        };
        // A resubmit recomputes each touched row's key: a broken probe
        // leaves every row at 'dear''s cost and the prefixes tie.
        enqueue(
            &db,
            &[request("dear", Vec::new()), request("cheap", Vec::new())],
        )
        .await
        .expect("resubmit");
        assert!(
            prefix(&db, "cheap", TARGET).await < prefix(&db, "dear", TARGET).await,
            "refreshed keys price each row's own cost"
        );
        // Target discriminates too: 'cheap' on macOS has its own
        // (crate, target) median, not the Linux row's.
        assert!(
            prefix(&db, "cheap", MACOS_TARGET).await > prefix(&db, "cheap", TARGET).await,
            "same crate on a pricier target scores lower"
        );

        // Promote recomputes the key under the 'human' operand: the
        // cost probe still has to bind to the outer row.
        for name in ["dear", "cheap"] {
            super::apply_mutation(
                &db,
                &settings(),
                super::QueueMutation::Promote,
                &filter_selector(stow_types::api::QueueSelector {
                    crate_name: Some(name.parse().expect("crate name")),
                    ..Default::default()
                }),
            )
            .await
            .expect("promote");
        }
        assert!(
            prefix(&db, "cheap", TARGET).await < prefix(&db, "dear", TARGET).await,
            "promoted keys price each row's own cost"
        );

        // A median move refreshes only that key's pending set: 'cheap'
        // reprices, 'dear' keeps its key byte-for-byte.
        let dear_key = prefix(&db, "dear", TARGET).await;
        super::record_build_sample(
            &db,
            &super::BuildCompleteReport {
                task_id: task_id_on("cheap", TARGET),
                generation_id: "gen-cost-move".to_owned(),
                attempt: 1,
                success: true,
                error: None,
                github_run_id: None,
                finished_at: None,
            },
            "cheap",
            TARGET,
            Some("2025-01-01 00:00:00"),
        )
        .await
        .expect("cost move sample");
        assert_ne!(
            prefix(&db, "cheap", TARGET).await,
            prefix(&db, "dear", TARGET).await,
            "median move repriced the moved key"
        );
        assert_eq!(
            prefix(&db, "dear", TARGET).await,
            dear_key,
            "an unrelated key is untouched"
        );
    }

    /// The keyed refresh's probe is served by its partial index, not
    /// a crate-wide walk — it reads the same-(crate, target) pending
    /// set, never the crate's terminal or other-target history.
    #[tokio::test]
    async fn cost_move_refresh_uses_the_pending_crate_target_index() {
        let db = memory_db().await.expect("memory db");
        let plan = db
            .query(
                "EXPLAIN QUERY PLAN \
                 SELECT q.task_id FROM queue q \
                 WHERE q.status = 'pending' AND q.crate_name = ? AND q.target = ?",
            )
            .bind("crate0".to_owned())
            .bind(TARGET.to_owned())
            .fetch_all::<PlanRow>()
            .await
            .expect("explain refresh");
        let detail = plan
            .iter()
            .map(|row| row.detail.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        assert!(
            detail.contains("idx_queue_pending_crate_target"),
            "refresh probe should seek the partial index: {detail}"
        );
    }

    /// The insert cost probe starts from the event's distinct
    /// `(crate_name, target)` keys and seeks `crate_build_stats` by
    /// its primary key — stored build history of any size stays out
    /// of an enqueue's read set (stow#524 review).
    #[tokio::test]
    async fn insert_cost_probe_seeks_stats_by_pk_only() {
        let db = memory_db().await.expect("memory db");
        // Seed stored history far larger than the batch's distinct
        // keys — a stats-first probe would read all of it.
        db.query(
            "WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 \
                                     FROM seq WHERE n < 10000) \
             INSERT INTO crate_build_stats (crate_name, target, builds, median_ms) \
             SELECT 'old' || n, 'x86_64-unknown-linux-gnu', n, n FROM seq",
        )
        .execute()
        .await
        .expect("seed stats history");
        let plan = db
            .query(&format!("EXPLAIN QUERY PLAN {}", super::INSERT_COST_PROBE))
            .bind(super::enqueue_json(&[request("probe", Vec::new())]).expect("json"))
            .fetch_all::<PlanRow>()
            .await
            .expect("explain cost probe");
        let detail = plan
            .iter()
            .map(|row| row.detail.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        assert!(
            detail.contains("SEARCH s") && !detail.contains("SCAN s"),
            "cost probe should PK-seek stats per event key: {detail}"
        );
    }

    /// The refresh writer itself — not only the pure helper —
    /// preserves exactness past `2^53`: adjacent priorities that
    /// collapsed under REAL keep distinct exact keys, and an extreme
    /// stored median prices through the same writer byte-for-byte as
    /// the shared abstraction derives it (stow#524 review).
    #[tokio::test]
    async fn refresh_writer_preserves_exactness_beyond_f64() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[request("priced", Vec::new()), request("plain", Vec::new())],
        )
        .await
        .expect("enqueue");
        let near = 9_007_199_254_740_992_i64;
        // Wide operands bind as TEXT with a CAST — an i64 bind would
        // itself cross the JSON number boundary and truncate.
        for (name, priority) in [("priced", near), ("plain", near + 1)] {
            db.query("UPDATE queue SET priority = CAST(? AS INTEGER) WHERE task_id = ?")
                .bind(priority.to_string())
                .bind(task_id_on(name, TARGET))
                .execute()
                .await
                .expect("set priority");
        }
        db.query(
            "INSERT INTO crate_build_stats \
             (crate_name, target, builds, median_ms) \
             VALUES ('priced', ?, 3, CAST(? AS INTEGER))",
        )
        .bind(TARGET)
        .bind(i64::MAX.to_string())
        .execute()
        .await
        .expect("seed extreme cost");

        super::refresh_dispatch_keys(
            &db,
            &[task_id_on("priced", TARGET), task_id_on("plain", TARGET)],
        )
        .await
        .expect("refresh keys");

        let prefix = async |db: &DurableDb, name: &str| -> String {
            db.query(
                "SELECT substr(dispatch_key, 1, 65) AS p FROM queue \
                 WHERE crate_name = ? AND target = ?",
            )
            .bind(name.to_owned())
            .bind(TARGET.to_owned())
            .fetch_scalar::<String>()
            .await
            .expect("prefix")
        };
        let priced = prefix(&db, "priced").await;
        let plain = prefix(&db, "plain").await;
        // 'priced' ranks near/(2^63-1) ≈ 1 against 'plain''s near+1 —
        // distinct keys, and each byte-exact the abstraction's output
        // for the row's own operands.
        assert_eq!(
            priced,
            crate::scheduler::rank::rank_prefix(
                "miss",
                near,
                std::num::NonZero::new(i64::MAX).unwrap()
            ),
            "extreme stored median prices exactly through the writer"
        );
        assert_eq!(
            plain,
            crate::scheduler::rank::rank_prefix(
                "miss",
                near + 1,
                crate::scheduler::rank::UNMEASURED_COST
            ),
            "adjacent >2^53 priority keeps its exact key"
        );
        assert!(plain < priced, "the larger exact ratio claims first");
    }

    /// The additive migration grows `claimed_at` and the build-cost
    /// tables on a dev-era queue — the operator route's only schema
    /// work — while rows migrated before the column carry no claim
    /// stamp and sample nothing.
    #[tokio::test]
    async fn migration_adds_claim_stamp_and_cost_tables() {
        let db = memory_db_raw().await.expect("raw memory db");
        for statement in [DEV_ERA_QUEUE, DEV_ERA_DEPENDENCIES] {
            db.query(statement).execute().await.expect("dev-era schema");
        }
        super::migrate(&db, &settings()).await.expect("migrate");
        let queue_columns = db
            .query("PRAGMA table_info(queue)")
            .fetch_all::<super::QueueTableInfoRow>()
            .await
            .expect("queue columns")
            .into_iter()
            .map(|column| column.name)
            .collect::<Vec<_>>();
        assert!(queue_columns.iter().any(|name| name == "claimed_at"));
        for table in ["crate_build_samples", "crate_build_stats"] {
            let columns = db
                .query(&format!("PRAGMA table_info({table})"))
                .fetch_all::<super::QueueTableInfoRow>()
                .await
                .expect("cost table columns");
            assert!(!columns.is_empty(), "{table} exists");
        }
    }
}
