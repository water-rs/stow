use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::num::NonZeroU32;

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
/// `STOW_HUMAN_DAILY_TASK_BUDGET`).
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
        }
    }
}

/// Priority breaks ties between tasks first requested in the same second —
/// dispatch order is FIFO by `first_requested_at`, so `request_count` is
/// deliberately absent: hammering one pending task must never let it
/// overtake older work.
fn compute_priority(downloads: u64, miss_count: u32) -> Result<i64, QueueError> {
    let downloads_bucket = downloads / 1000;
    let downloads_bucket = i64::try_from(downloads_bucket)
        .map_err(|_| format!("downloads bucket exceeds i64: {downloads_bucket}"))?;
    Ok(downloads_bucket + i64::from(miss_count) * 10)
}

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
/// A failed row always goes back: that is how a wave converges on the
/// coverage it asked for, and the exponential backoff in the batched
/// `UPDATE queue` keeps the retry rate sane. A completed row is
/// different — its artifacts are in the catalog, and the unattended
/// preheat lane re-submits the whole top-N list on every wave, so
/// resurrecting completions would rebuild the entire pool on a timer.
/// Only the human lane, where someone asked for this exact crate again,
/// rebuilds something already served.
const fn resurrects(status: &str, lane: TaskLane) -> bool {
    match status.as_bytes() {
        b"failed" => true,
        b"completed" => matches!(lane, TaskLane::Human),
        _ => false,
    }
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

/// The failed-dependency requeue applied to one dep task id: the
/// in-memory replay of the old per-edge `UPDATE … WHERE status =
/// 'failed'` emits at most one entry per dep (a 'failed' row flips to
/// 'pending' in the status map, so later parents in the chunk no-op
/// exactly as the sequential statements did). The deltas and `revived`
/// flag travel per row so the statement is a keyed UPDATE, not a
/// count(*) fold.
#[derive(serde::Serialize)]
struct BatchedRequeue {
    task_id: String,
    attempt_delta: u32,
    request_count_delta: u32,
    revived: u8,
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

/// `UPDATE queue` for every re-requested row in the chunk, one statement
/// per slice. Semantics of the old per-request `update_existing_task`,
/// carried per JSON entry: downloads keep the max, `request_count`
/// grows by the occurrence count, priority recomputes from downloads and
/// `miss_count` (`first_requested_at` untouched — re-requesting never
/// jumps the queue), resurrection bumps `attempt` so a completion report
/// in flight for the superseded attempt cannot land on the new one, a
/// failed row's resurrection re-arms the same exponential backoff a
/// dispatch failure would apply, and the lane only ever moves toward
/// 'human'.
async fn apply_batched_updates(
    db: &DurableDb,
    settings: &SchedulerSettings,
    updates: &[BatchedUpdate],
) -> Result<(), QueueError> {
    // `wake_at` recomputes on a redispatch (status/backoff move) or a
    // lane move to `human` — both change the wake expression's
    // operands. The CASE'd `not_before`/`lane` the same statement
    // assigns must re-appear inside it: SET terms see the old row.
    let next_not_before = "CASE WHEN e ->> 'redispatch' = 1 AND status = 'failed' \
         THEN MAX(not_before, datetime('now', '+' || MIN(1 << MIN(dispatch_attempts, 6), 60) || ' minutes')) \
         ELSE not_before END";
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
                 not_before = {next_not_before}, \
                 wake_at = CASE WHEN (e ->> 'redispatch' = 1 OR e ->> 'human' = 1) \
                     THEN {wake} ELSE wake_at END, \
                 updated_at = datetime('now'), \
                 lane = {next_lane} \
             FROM (SELECT value AS e FROM json_each(?)) AS j \
             WHERE queue.task_id = j.e ->> 'task_id'",
            deps_met = deps_met_sql("queue.task_id"),
            blocked = blocked_sql("queue.task_id"),
            wake = wake_at_sql(
                next_lane,
                "first_requested_at",
                next_not_before,
                settings.dispatch_min_age_minutes,
            ),
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
    let mut inserted = 0u64;
    for chunk in inserts.chunks(ENQUEUE_JSON_BATCH_ROWS) {
        let inserted_rows = db
            .query(&format!(
                "INSERT INTO queue \
                 (task_id, crate_name, version, features_json, target, rustc_version, host_side, downloads, miss_count, request_count, priority, status, preserve_lockfile, lane, attempt, first_requested_at, deps_met, blocked, wake_at, dispatch_family, dispatch_key) \
                 SELECT e ->> 'task_id', e ->> 'crate_name', e ->> 'version', e ->> 'features_json', \
                        e ->> 'target', e ->> 'rustc_version', e ->> 'host_side', e ->> 'downloads', \
                        0, 1, e ->> 'priority', 'pending', e ->> 'preserve_lockfile', e ->> 'lane', \
                        1, datetime('now'), {deps_met}, {blocked}, {wake}, {family}, {key} \
                 FROM (SELECT value AS e FROM json_each(?)) \
                 WHERE TRUE \
                 ON CONFLICT DO NOTHING \
                 RETURNING task_id",
                deps_met = deps_met_sql("e ->> 'task_id'"),
                blocked = blocked_sql("e ->> 'task_id'"),
                // `not_before` takes its epoch default, so the wake is
                // the age gate alone for a miss row, epoch for human.
                wake = wake_at_sql(
                    "e ->> 'lane'",
                    "datetime('now')",
                    "'1970-01-01 00:00:00'",
                    settings.dispatch_min_age_minutes,
                ),
                family = dispatch_family_sql("e ->> 'target'"),
                key = dispatch_key_sql(
                    "e ->> 'lane'",
                    "e ->> 'target'",
                    "datetime('now')",
                    "e ->> 'priority'",
                    "datetime('now')",
                    "e ->> 'task_id'",
                ),
            ))
            .bind(enqueue_json(chunk)?)
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
/// reinserted as known rather than left failing closed. The requeue of
/// failed deps applies the per-dep deltas the in-memory replay computed
/// — one keyed UPDATE, same columns as the old per-edge statement.
async fn apply_batched_dependency_sync(
    db: &DurableDb,
    settings: &SchedulerSettings,
    resync_ids: &[String],
    edges: &[BatchedDepEdge],
    requeues: &[BatchedRequeue],
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
    for chunk in edges.chunks(ENQUEUE_JSON_BATCH_ROWS) {
        db.query(
            "INSERT INTO queue_dependencies \
             (task_id, depends_on_task_id, dep_crate_name, dep_version, dep_features_json, dep_target, dep_rustc_version, dep_host_side, dep_invocations, dep_shapes, dep_side_known) \
             SELECT e ->> 'task_id', e ->> 'depends_on_task_id', e ->> 'dep_crate_name', \
                    e ->> 'dep_version', e ->> 'dep_features_json', e ->> 'dep_target', \
                    e ->> 'dep_rustc_version', e ->> 'dep_host_side', e ->> 'dep_invocations', \
                    e ->> 'dep_shapes', 1 \
             FROM (SELECT value AS e FROM json_each(?)) \
             WHERE TRUE \
             ON CONFLICT(task_id, depends_on_task_id) DO NOTHING",
        )
        .bind(enqueue_json(chunk)?)
        .execute()
        .await
        .map_err(|error| format!("insert task dependencies: {error}"))?;
    }
    // Requeueing a failed dependency for a waiting parent revives the
    // row only behind the same backoff a fresh enqueue applies, with
    // `attempt` bumped for the same reason resurrection bumps it. The
    // replay already resolved which deps revive and by how much, so the
    // statement only applies the per-row deltas. Revived rows re-enter
    // `pending`, where `deps_met` must be current — it is recomputed in
    // the same statement for exactly the rows that revive.
    let next_not_before = "CASE WHEN e ->> 'revived' = 1 \
         THEN MAX(not_before, datetime('now', '+' || MIN(1 << MIN(dispatch_attempts, 6), 60) || ' minutes')) \
         ELSE not_before END";
    for chunk in requeues.chunks(ENQUEUE_JSON_BATCH_ROWS) {
        db.query(&format!(
            "UPDATE queue \
             SET status = CASE WHEN e ->> 'revived' = 1 THEN 'pending' ELSE status END, \
                 attempt = attempt + (e ->> 'attempt_delta'), \
                 error_msg = CASE WHEN e ->> 'revived' = 1 THEN '' ELSE error_msg END, \
                 deps_met = CASE WHEN e ->> 'revived' = 1 \
                     THEN {deps_met} ELSE deps_met END, \
                 blocked = CASE WHEN e ->> 'revived' = 1 \
                     THEN {blocked} ELSE blocked END, \
                 request_count = request_count + (e ->> 'request_count_delta'), \
                 not_before = {next_not_before}, \
                 wake_at = CASE WHEN e ->> 'revived' = 1 \
                     THEN {wake} ELSE wake_at END, \
                 updated_at = datetime('now') \
             FROM (SELECT value AS e FROM json_each(?)) AS j \
             WHERE queue.task_id = j.e ->> 'task_id' AND queue.status = 'failed'",
            deps_met = deps_met_sql("queue.task_id"),
            blocked = blocked_sql("queue.task_id"),
            wake = wake_at_sql(
                "lane",
                "first_requested_at",
                next_not_before,
                settings.dispatch_min_age_minutes,
            ),
        ))
        .bind(enqueue_json(chunk)?)
        .execute()
        .await
        .map_err(|error| format!("requeue failed dependencies: {error}"))?;
    }
    // A revived dep leaves `failed` — the transition that can unblock a
    // dependent still parked on it. Refresh exactly their gate answers.
    if requeues.iter().any(|requeue| requeue.revived != 0) {
        refresh_dependents(
            db,
            "SELECT value ->> 'task_id' AS task_id FROM json_each(?) \
             WHERE value ->> 'revived' = 1",
            &[DbValue::Text(enqueue_json(requeues)?)],
        )
        .await?;
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
        // Each named dep's task id is resolved here too: the failed-dep
        // requeue must see the deps' live statuses, so they join the
        // chunk's existence probe.
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
    let resync_ids: Vec<String> = plan.resync.keys().cloned().collect();
    let edges: Vec<BatchedDepEdge> = plan.resync.into_values().flatten().collect();
    apply_batched_dependency_sync(db, settings, &resync_ids, &edges, &plan.requeues).await?;
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
    /// Failed deps the chunk revived, one entry per dep task id.
    requeues: Vec<BatchedRequeue>,
}

/// One existence probe for the chunk, over every task id it can
/// touch — the requests' own plus every dep they name. `task_id` is
/// the queue's primary key, so this answers every existence check the
/// row-at-a-time loop ran, including each `WHERE status = 'failed'`
/// the per-edge requeue issued.
async fn probe_task_statuses(
    db: &DurableDb,
    prepared: &[Prepared<'_>],
) -> Result<BTreeMap<String, String>, QueueError> {
    let probe_ids: BTreeSet<&str> = prepared
        .iter()
        .flat_map(|entry| {
            std::iter::once(entry.task_id.as_str())
                .chain(entry.dep_task_ids.iter().map(String::as_str))
        })
        .collect();
    let probe_ids: Vec<&str> = probe_ids.into_iter().collect();
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
/// order: each request's own insert/update, then its dep sync, then the
/// requeue of every dep that is 'failed' at that point — the same
/// interleaving the row-at-a-time loop ran, so a failed dep is revived
/// by the first parent to name it (+1 `attempt` / +1 `request_count`,
/// the old per-edge `UPDATE … WHERE status = 'failed'`), flips to
/// 'pending' in the map, and every later occurrence is a no-op. A task
/// appearing twice in one chunk likewise sees what its earlier
/// occurrence left (a fresh insert reads as 'pending', a resurrected
/// row as 'pending'), so duplicates land identically to the
/// row-at-a-time loop. `resync` keeps the last occurrence's dependency
/// list per task — the old loop's per-occurrence DELETE+INSERT made
/// the last sync the surviving one. `statuses` carries the existence
/// probe in and is advanced to the row each occurrence leaves.
fn plan_enqueue(
    prepared: &[Prepared<'_>],
    statuses: &mut BTreeMap<String, String>,
) -> Result<EnqueuePlan, QueueError> {
    let mut updates: BTreeMap<String, BatchedUpdate> = BTreeMap::new();
    let mut requeues: BTreeMap<String, BatchedRequeue> = BTreeMap::new();
    let mut plan = EnqueuePlan {
        updates: Vec::new(),
        inserts: Vec::new(),
        resync: BTreeMap::new(),
        requeues: Vec::new(),
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
        // The old loop ran the revival `UPDATE … WHERE status =
        // 'failed'` per edge in request order; replayed in memory,
        // the first parent to name a still-'failed' dep flips it
        // 'pending' so its revival happens exactly once, and any
        // later request for that dep in the chunk meets the
        // 'pending' row — the same reads the sequential
        // statements produced.
        for dep_task_id in &entry.dep_task_ids {
            if statuses
                .get(dep_task_id.as_str())
                .is_some_and(|status| status == "failed")
            {
                statuses.insert(dep_task_id.clone(), "pending".to_owned());
                requeues
                    .entry(dep_task_id.clone())
                    .or_insert_with(|| BatchedRequeue {
                        task_id: dep_task_id.clone(),
                        attempt_delta: 1,
                        request_count_delta: 1,
                        revived: 1,
                    });
            }
        }
        plan.resync.insert(entry.task_id.clone(), edges);
    }
    plan.updates = updates.into_values().collect();
    plan.requeues = requeues.into_values().collect();
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
    attempt: u32,
    success: bool,
    error: Option<String>,
    github_run_id: Option<String>,
}

/// `window_minutes` bounds the outcome evidence the record keeps: the
/// freeze breaker's window, so the expiry deletes carried inside the
/// insert drop exactly what the trip check can no longer read.
async fn complete(
    db: &DurableDb,
    report: &BuildCompleteReport,
    window_minutes: u32,
) -> Result<(), QueueError> {
    // `RETURNING target` hands the outcome counter the row's target —
    // the breaker files outcomes under it without a second read.
    #[derive(skyzen::FromRow)]
    struct UpdatedTarget {
        target: String,
    }
    let status = if report.success {
        "completed"
    } else {
        "failed"
    };

    // The report must name the row's live attempt in an in-flight status:
    // without that predicate a late or duplicate report for a superseded
    // attempt would overwrite the state of the attempt the row has since
    // been resurrected into (enqueue bumps `attempt` on resurrection).
    let updated = db
        .query(
            "UPDATE queue \
             SET status = ?, error_msg = ?, github_run_id = COALESCE(?, github_run_id), \
                 updated_at = datetime('now') \
             WHERE task_id = ? AND attempt = ? AND status IN ('dispatched', 'running') \
             RETURNING target",
        )
        .bind(status)
        .bind(report.error.clone().unwrap_or_default())
        .bind(report.github_run_id.clone())
        .bind(report.task_id.clone())
        .bind(i64::from(report.attempt))
        .fetch_optional::<UpdatedTarget>()
        .await
        .map_err(|error| format!("complete task: {error}"))?;
    // A report that applied to no row is never a silent success: an
    // unknown task id is a 404 at the handler, and a known row whose live
    // attempt/status no longer matches is a stale or duplicate report —
    // logged and answered 409 so the reporter sees the conflict rather
    // than believing it completed the current attempt.
    if updated.is_none() {
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
        return Err(QueueError::StaleCompletion {
            task_id: report.task_id.clone(),
            attempt: report.attempt,
            row_attempt: row.attempt,
            row_status: row.status,
        });
    }
    // A dep that just entered `failed` is the one outside-the-row event
    // that flips a pending dependent's `blocked` flag — refresh exactly
    // its dependents.
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
    let target = updated.expect("checked above").target;
    record_attempt_outcome(db, report, &target, window_minutes).await?;

    Ok(())
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
            "INSERT INTO attempt_outcomes \
                 (task_id, attempt, target, failure_class, \
                  github_run_id, finished_at) \
             VALUES (?, ?, ?, ?, ?, datetime('now')) \
             ON CONFLICT(task_id, attempt) DO NOTHING",
        )
        .bind(report.task_id.clone())
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
/// which names the task and its outcome but no attempt number.
///
/// The webhook cannot carry `attempt` (GitHub invented the event), so the
/// row's live attempt is resolved here and the same in-flight predicate
/// applies — a stale event can only fail the attempt it names when the
/// records check upstream already refused the success.
///
/// # Errors
///
/// [`QueueError::UnknownTask`] when no queue row carries the task id;
/// [`QueueError::StaleCompletion`] when the live row's attempt or status
/// has moved past what the event describes.
pub async fn complete_run(
    db: &DurableDb,
    report: &stow_types::api::WorkflowRunComplete,
    window_minutes: u32,
) -> Result<(), QueueError> {
    let row = db
        .query("SELECT attempt, status FROM queue WHERE task_id = ?")
        .bind(report.task_id.clone())
        .fetch_optional::<AttemptStatusRow>()
        .await
        .map_err(|error| format!("load task {} for run completion: {error}", report.task_id))?;
    let Some(row) = row else {
        return Err(QueueError::UnknownTask(report.task_id.clone()));
    };
    complete(
        db,
        &BuildCompleteReport {
            task_id: report.task_id.clone(),
            attempt: row.attempt,
            success: report.success,
            error: report.error.clone(),
            github_run_id: report.github_run_id.clone(),
        },
        window_minutes,
    )
    .await
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
             ({}) AS status, preserve_lockfile, first_requested_at, priority, created_at, \
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
             ({}) AS status, preserve_lockfile, first_requested_at, priority, created_at, \
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
    // The position must equal `claim_dispatchable_tasks` dispatch order:
    // Windows-family rows sort first within the lane, then the FIFO
    // tie-breakers. The subject row's own Windows rank is computed in
    // Rust from the same target list the SQL `IN` clause binds.
    let windows_targets = RunnerFamily::Windows.targets();
    let windows_rank = i64::from(!windows_targets.contains(&row.target.as_str()));
    let sql = format!(
        "SELECT count(*) AS count FROM queue q \
         WHERE q.lane = 'human' AND q.status = 'pending' \
           AND (CASE WHEN q.target IN ({0}) THEN 0 ELSE 1 END < ? \
                OR (CASE WHEN q.target IN ({0}) THEN 0 ELSE 1 END = ? \
                    AND (q.first_requested_at < ? \
                        OR (q.first_requested_at = ? AND (q.priority > ? \
                            OR (q.priority = ? AND (q.created_at < ? \
                                OR (q.created_at = ? AND q.task_id < ?))))))))",
        crate::sql_batch::placeholders(windows_targets.len())
    );
    let mut query = db.query(&sql);
    for _ in 0..2 {
        for target in windows_targets {
            query = query.bind((*target).to_owned());
        }
        query = query.bind(windows_rank);
    }
    let ahead = query
        .bind(row.first_requested_at.clone())
        .bind(row.first_requested_at.clone())
        .bind(row.priority)
        .bind(row.priority)
        .bind(row.created_at.clone())
        .bind(row.created_at.clone())
        .bind(row.task_id.clone())
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
fn dep_edge_unpublished_sql(dep: &str) -> String {
    format!(
        "({dep}.dep_shapes = 0 \
         OR (SELECT count(DISTINCT p.unit_invocation * 2 + p.unit_linked) \
             FROM published_slice_rows p \
             JOIN published_slices s \
               ON s.target = p.target AND s.rustc_version = p.rustc_version \
              AND s.generation = p.generation \
             WHERE p.target = {dep}.dep_target \
               AND p.rustc_version = {dep}.dep_rustc_version \
               AND p.crate_name = {dep}.dep_crate_name \
               AND p.version = {dep}.dep_version \
               AND p.features_json = {dep}.dep_features_json \
               AND p.unit_side = {dep}.dep_host_side \
               AND ({dep}.dep_host_side = 0 OR p.unit_linked = 1) \
               AND ({dep}.dep_invocations & (p.unit_invocation + 1)) != 0 \
            ) < {dep}.dep_shapes)"
    )
}

/// The dependency gate's EXISTS half — one task's unmet-edge check,
/// aliased for reuse: `deps_met` stores its negation, so the persisted
/// flag can never drift from the predicate it replaces.
///
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
/// A dependency that fails keeps its dependents waiting while it retries
/// with the existing backoff; a dependency that fails for good leaves
/// them settled behind it undispatched, released only when it is later
/// built and published.
fn unmet_dep_edge_exists_sql(dep: &str, owner_task: &str) -> String {
    format!(
        "EXISTS ( \
            SELECT 1 FROM queue_dependencies {dep} \
            WHERE {dep}.task_id = {owner_task} \
              AND {} \
        )",
        dep_edge_unpublished_sql(dep)
    )
}

/// `deps_met` as a SQL expression over the owner's row: `1` while every
/// edge resolves to units the live published slice serves. Written at
/// edge sync, refreshed by slice publish and the schema migration — the
/// three places an edge's answer can change — so the claim walk and the
/// alarm's wake probes read the flag instead of re-evaluating the gate
/// per pending row.
pub(super) fn deps_met_sql(owner_task: &str) -> String {
    format!(
        "CASE WHEN {} THEN 0 ELSE 1 END",
        unmet_dep_edge_exists_sql("d", owner_task)
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
              AND {} \
        ) THEN 1 ELSE 0 END",
        dep_edge_unpublished_sql("bd")
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

/// The claim `ORDER BY` tuple encoded as one sortable string over row
/// columns: human lane first, then Windows targets (the slowest legs of
/// a wave start earliest), then FIFO by `first_requested_at` with
/// priority, creation and id as the tie breakers — the same ordering the
/// pre-index CASE expressions produced. Priority is inverted into a
/// full-`i64`-width field (`i64::MAX - priority`), so the text sort is
/// the numeric `DESC` at every magnitude — no clamp, no tie horizon.
pub(super) fn dispatch_key_sql(
    lane: &str,
    target: &str,
    first: &str,
    priority: &str,
    created: &str,
    task_id: &str,
) -> String {
    let windows = RunnerFamily::Windows
        .targets()
        .iter()
        .map(|triple| format!("'{triple}'"))
        .collect::<Vec<_>>()
        .join(", ");
    // Every operand is parenthesized: `->>` and `||` share one
    // precedence level and associate left, so a bare `x || e ->> 'col'`
    // would evaluate `(x || e) ->> 'col'` — a JSON operator on the
    // concatenated string — instead of `x || (e ->> 'col')`.
    format!(
        "(CASE WHEN {lane} = 'human' THEN '0' ELSE '1' END) || '|' || \
         (CASE WHEN {target} IN ({windows}) THEN '0' ELSE '1' END) || '|' || \
         ({first}) || '|' || \
         printf('%019d', 9223372036854775807 - MAX(0, ({priority}))) || '|' || \
         ({created}) || '|' || ({task_id})"
    )
}

/// `dispatch_key_sql` over the queue's own columns — the in-row form the
/// backfill, the re-request update and the promote refresh share.
pub(super) fn dispatch_key_row_sql() -> String {
    dispatch_key_sql(
        "lane",
        "target",
        "first_requested_at",
        "priority",
        "created_at",
        "task_id",
    )
}

/// Recompute `deps_met` for a task-id set — the only places an edge's
/// answer changes are edge writes (here, after the batch's resync) and
/// slice writes ([`record_published_slice`]). `deps_met` is maintained
/// only for `pending` rows — the claim reads it there alone, and every
/// transition into `pending` recomputes it in the same statement — so
/// the refresh touches nothing else: a stale value on a non-pending row
/// is never observed. The `deps_met !=` guard keeps `changes()` honest:
/// an unchanged row does not count as written.
///
/// The `task_id IN` drives the update — the `status = 'pending'`
/// restriction is folded inside the subquery, so the planner cannot
/// prefer a status-index scan over the id list: the statement visits
/// exactly the named pending rows, never the pending group.
async fn refresh_deps_met_tasks(db: &DurableDb, task_ids: &[String]) -> Result<(), QueueError> {
    for chunk in task_ids.chunks(ENQUEUE_JSON_BATCH_ROWS) {
        db.query(&format!(
            "UPDATE queue SET deps_met = {dexpr}, blocked = {bexpr} \
             WHERE task_id IN ( \
                 SELECT q.task_id FROM json_each(?) AS j \
                 CROSS JOIN queue q ON q.task_id = j.value \
                   AND q.status = 'pending') \
               AND (deps_met != {dexpr} OR blocked != {bexpr})",
            dexpr = deps_met_sql("queue.task_id"),
            bexpr = blocked_sql("queue.task_id"),
        ))
        .bind(enqueue_json(chunk)?)
        .execute()
        .await
        .map_err(|error| format!("refresh deps_met for enqueued tasks: {error}"))?;
    }
    Ok(())
}

/// Recompute `deps_met`/`blocked` on the pending dependents of a set of
/// dep tasks — the refresh a dep's own status change owes them. `dep_set`
/// is a SELECT yielding the dep task ids (a `json_each` arm, a queue
/// subquery re-running a mutation's selector, or a single `SELECT ?`):
/// it drives `idx_queue_dependencies_dep` in pinned `CROSS JOIN` order,
/// then the owners' id list drives the UPDATE, so the pass reads in
/// proportion to the dep set's dependents — never the queue.
async fn refresh_dependents(
    db: &DurableDb,
    dep_set_sql: &str,
    binds: &[DbValue],
) -> Result<(), QueueError> {
    let sql = format!(
        "UPDATE queue SET deps_met = {dexpr}, blocked = {bexpr} \
         WHERE task_id IN ( \
             SELECT o.task_id FROM ({dep_set_sql}) AS s \
             CROSS JOIN queue_dependencies d ON d.depends_on_task_id = s.task_id \
             CROSS JOIN queue o ON o.task_id = d.task_id AND o.status = 'pending') \
           AND (deps_met != {dexpr} OR blocked != {bexpr})",
        dexpr = deps_met_sql("queue.task_id"),
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

/// Recompute `dispatch_key` for a task-id set after a mutation that may
/// have moved a row's lane or priority (re-request humanization, revive
/// priority bump). Rows already carrying the right key write nothing.
async fn refresh_dispatch_keys(db: &DurableDb, task_ids: &[String]) -> Result<(), QueueError> {
    for chunk in task_ids.chunks(ENQUEUE_JSON_BATCH_ROWS) {
        db.query(&format!(
            "UPDATE queue SET dispatch_key = {expr} \
             WHERE task_id IN (SELECT value FROM json_each(?)) \
               AND dispatch_key != {expr}",
            expr = dispatch_key_row_sql()
        ))
        .bind(enqueue_json(chunk)?)
        .execute()
        .await
        .map_err(|error| format!("refresh dispatch keys: {error}"))?;
    }
    Ok(())
}

/// Status projection read paths use so a dependent parked behind a
/// terminally failed dependency surfaces as `blocked` instead of
/// `pending`: a `failed` dependency is done until an operator
/// retries it or a fresh request requeues it, and "waiting for that" is
/// a different thing to see than "waiting for a publish". The answer is
/// the persisted `blocked` flag — `blocked_sql` is its definition —
/// written alongside `deps_met` and on the dependents of a dep whose
/// status flips, so reads are a column lookup rather than an EXISTS per
/// row. The stored status stays `pending`, so retrying the dependency
/// returns the dependent to `pending` with nothing to reconcile.
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
    format!(
        "CASE WHEN queue.status = 'pending' AND queue.blocked != 0 THEN ( \
            SELECT CASE WHEN bd.dep_crate_name = '' THEN 'unknown dependency identity' \
                        ELSE bd.depends_on_task_id END \
                FROM queue_dependencies bd \
                LEFT JOIN queue bdep ON bdep.task_id = bd.depends_on_task_id \
                WHERE bd.task_id = queue.task_id \
                  AND (bdep.status = 'failed' OR bd.dep_crate_name = '' OR bd.dep_host_side < 0) \
                  AND {} \
                ORDER BY bd.depends_on_task_id LIMIT 1 \
        ) END",
        dep_edge_unpublished_sql("bd")
    )
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
            let result = db
                .query(
                    "UPDATE queue \
                     SET status = 'dispatched', dispatch_attempts = dispatch_attempts + 1, \
                         updated_at = datetime('now') \
                     WHERE task_id = ? AND status = 'pending'",
                )
                .bind(row.task_id.clone())
                .execute()
                .await
                .map_err(|error| format!("claim task {}: {error}", row.task_id))?;

            if result.rows_written == 0 {
                tracing::warn!(
                    task_id = %row.task_id,
                    "skipping task claim — already claimed by concurrent dispatch"
                );
                continue;
            }
            total_slots -= 1;
            if family == RunnerFamily::MacOs {
                macos_slots -= 1;
            }

            claimed.push(QueuedTask {
                task_id: row.task_id,
                attempt: row.attempt,
                crate_name: row.crate_name,
                version: row.version,
                features_json: row.features_json,
                target: row.target,
                rustc_version: row.rustc_version,
                host_side: row.host_side != 0,
                preserve_lockfile: row.preserve_lockfile != 0,
                dep_pins: Vec::new(),
            });
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
/// tuple (human lane first, then Windows targets — the slowest legs of
/// a wave start earliest — then FIFO by `first_requested_at` with the
/// priority, creation and id tie breakers), so neither is evaluated per
/// row.
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
           AND (q.lane = 'human' OR q.first_requested_at <= datetime('now', ?)) \
           AND q.not_before <= datetime('now') \
           AND q.dispatch_key > ? \
           {family_filter} \
         ORDER BY q.dispatch_key \
         LIMIT ?"
    );
    let cutoff = dispatch_cutoff_modifier(settings.dispatch_min_age_minutes);
    // The keyset cursor: every real key starts with a lane rank digit,
    // so '' orders before all of them.
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
    error: &str,
) -> Result<(), QueueError> {
    // Exponential backoff keyed on dispatch_attempts (incremented at claim
    // time): a persistent dispatch failure (GitHub outage, bad token) must
    // not spin the alarm in a zero-delay retry loop.
    let dispatch_attempts = db
        .query("SELECT dispatch_attempts FROM queue WHERE task_id = ?")
        .bind(task_id.to_owned())
        .fetch_scalar_optional::<u32>()
        .await
        .map_err(|db_error| format!("load dispatch attempts for {task_id}: {db_error}"))?
        .ok_or_else(|| QueueError::UnknownTask(task_id.to_owned()))?;
    let backoff_minutes = dispatch_backoff_minutes(dispatch_attempts);
    // The row re-enters `pending`: `deps_met`/`blocked` are maintained
    // only for pending rows, so their answers may have gone stale while it
    // was in-flight — recompute both in the same statement. `wake_at`
    // is the later of the age gate and the backoff this statement writes
    // (the SET operand is spelled out again — SET terms see the old row);
    // the human lane ignores the age gate.
    let next_not_before = "datetime('now', ?)";
    db.query(&format!(
        "UPDATE queue \
         SET status = 'pending', error_msg = ?, \
             not_before = {next_not_before}, \
             deps_met = {deps_met}, blocked = {blocked}, \
             wake_at = {wake}, \
             updated_at = datetime('now') \
         WHERE task_id = ?",
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
    .bind(task_id.to_owned())
    .execute()
    .await
    .map_err(|db_error| format!("mark dispatch failed: {db_error}"))?;

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
            "SELECT failure_class, count(*) AS count FROM attempt_outcomes \
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
            "SELECT github_run_id FROM attempt_outcomes \
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
}

const ADMIN_TASK_COLUMNS: &str = "task_id, crate_name, version, features_json, target, \
     rustc_version, lane, attempt, error_msg, downloads, miss_count, \
     request_count, dispatch_attempts, preserve_lockfile, \
     github_run_id, first_requested_at, created_at, updated_at, host_side";

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
        })
    }
}

/// The `WHERE` clause and bound values a [`QueueSelector`] describes. With
/// a non-empty `task_ids` the ids select the rows; otherwise the filter
/// predicates apply.
fn selector_predicate(selector: &QueueSelector) -> Result<(String, Vec<DbValue>), QueueError> {
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
                    predicates.push("status = 'pending'".to_owned());
                    predicates.push("blocked = ?".to_owned());
                    values.push(i64::from(matches!(status, QueueTaskStatus::Blocked)).into());
                }
                _ => {
                    predicates.push("status = ?".to_owned());
                    values.push(status.as_str().into());
                }
            }
        }
        if let Some(target) = &selector.target {
            predicates.push("target = ?".to_owned());
            values.push(target.as_str().into());
        }
        if let Some(crate_name) = &selector.crate_name {
            predicates.push("crate_name = ?".to_owned());
            values.push(crate_name.as_str().into());
        }
        if let Some(older_than_secs) = selector.older_than_secs {
            predicates.push("updated_at <= datetime('now', ?)".to_owned());
            values.push(format!("-{older_than_secs} seconds").into());
        }
        if predicates.is_empty() {
            return Err(QueueError::EmptySelector);
        }
    } else {
        predicates.push(format!(
            "task_id IN ({})",
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
    let (predicate, values) = match selector_predicate(selector) {
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
    let (predicate, values) = selector_predicate(selector)?;
    // Retry, Cancel and Purge move a dep into or out of `failed` (or out
    // of the queue entirely) — the only outside-the-row events that move
    // a pending dependent's `blocked` flag. The dep set is the selector
    // applied to the statuses the arm can touch, captured before the
    // mutation runs (the selector itself may carry a status that no
    // longer matches after the UPDATE).
    let dep_side = match mutation {
        QueueMutation::Retry => Some("status = 'failed'"),
        QueueMutation::Cancel => Some("status IN ('pending', 'dispatched')"),
        QueueMutation::Promote => None,
        QueueMutation::Purge => Some("status IN ('completed', 'failed')"),
    };
    let dep_ids = match dep_side {
        Some(statuses) => {
            let dep_sql = format!("SELECT task_id FROM queue WHERE {statuses} AND {predicate}");
            let mut query = db.query(&dep_sql);
            for value in values.iter().cloned() {
                query = query.bind(value);
            }
            query
                .fetch_scalars::<String>()
                .await
                .map_err(|error| format!("list dep ids before mutation: {error}"))?
        }
        None => Vec::new(),
    };
    let sql = match mutation {
        QueueMutation::Retry => format!(
            // Rows re-enter `pending`: `deps_met`/`blocked` are
            // maintained only for pending rows, so a failed row's
            // answers may be stale — recompute them in the same
            // statement. `not_before` resets to epoch, so `wake_at` is
            // the age gate (miss lane) or epoch (human).
            "UPDATE queue SET status = 'pending', error_msg = '', \
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
        QueueMutation::Promote => format!(
            // `dispatch_key` re-derives from the row — but a SET
            // expression reads the pre-update row, so the key's lane
            // operand is the value this statement assigns, 'human',
            // not the `lane` column it is about to overwrite. The same
            // goes for `wake_at`: the human lane pays no age gate, so
            // the promote's wake is the row's `not_before` as-is.
            "UPDATE queue SET lane = 'human', updated_at = datetime('now'), \
                 wake_at = not_before, \
                 dispatch_key = {} \
             WHERE status = 'pending' AND lane = 'miss' AND {predicate}",
            dispatch_key_sql(
                "'human'",
                "target",
                "first_requested_at",
                "priority",
                "created_at",
                "task_id",
            )
        ),
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
    if !dep_ids.is_empty() {
        refresh_dependents(
            db,
            "SELECT value AS task_id FROM json_each(?)",
            &[DbValue::Text(enqueue_json(&dep_ids)?)],
        )
        .await?;
    }
    u64_to_u32(
        u64::try_from(mutated.len()).unwrap_or(u64::MAX),
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
    // Two probes over `idx_queue_wake_eligible (status, deps_met,
    // dispatch_family, wake_at)`: `wake_at` is the persisted earliest
    // dispatch instant (the lane-aware later of age gate and backoff),
    // so eligibility collapses to one ordering — no per-lane arms, no
    // MIN over a CASE. The claim re-checks the live columns, so a stale
    // wake_at costs at most one wasted pass, never a wrong dispatch.
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
    let (changed, run_stale_cleanup) = match (base_generation, live_applied) {
        (Some(base), Some(applied)) if applied == base => {
            // Delta report on a live base: apply `added`/`retired`
            // directly — no live-slice read — and the stale-generation
            // sweep stays on the full path (it reads in proportion to
            // the slice, which a per-wave delta must not pay).
            let changed = apply_slice_delta(
                db,
                target,
                rustc_version,
                live_generation,
                &to_slice_rows(added),
                &to_slice_rows(retired),
            )
            .await?;
            (changed, false)
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
            (changed, true)
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
    let changed_json = if changed.is_empty() {
        None
    } else {
        Some(
            serde_json::to_string(&changed)
                .map_err(|error| QueueError::Sql(format!("encode slice delta json: {error}")))?,
        )
    };
    let marker_generation = live.as_ref().map_or(1, |row| row.generation);
    commit_published_slice(
        db,
        target,
        rustc_version,
        marker_generation,
        changed_json,
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
/// PK in one statement: the `json_each` join produces each stale row's
/// rowid with a PK probe per report row, so reads stay proportional to
/// the delta. Returns the changed row set for the dependent refresh.
async fn apply_slice_delta(
    db: &DurableDb,
    target: &str,
    rustc_version: &str,
    live_generation: i64,
    added: &[SliceRowJson],
    retired: &[SliceRowJson],
) -> Result<Vec<SliceRowJson>, QueueError> {
    if !retired.is_empty() {
        let retired_json = serde_json::to_string(retired)
            .map_err(|error| QueueError::Sql(format!("encode slice retire json: {error}")))?;
        db.query(
            "DELETE FROM published_slice_rows \
             WHERE rowid IN ( \
                 SELECT p.rowid \
                 FROM (SELECT value AS e FROM json_each(?)) AS j \
                 CROSS JOIN published_slice_rows p \
                   ON p.target = ? AND p.rustc_version = ? AND p.generation = ? \
                  AND p.crate_name = j.e ->> 'crate_name' \
                  AND p.version = j.e ->> 'version' \
                  AND p.features_json = j.e ->> 'features_json' \
                  AND p.unit_side = j.e ->> 'unit_side' \
                  AND p.unit_invocation = j.e ->> 'unit_invocation' \
                  AND p.unit_linked = j.e ->> 'unit_linked')",
        )
        .bind(retired_json)
        .bind(target.to_owned())
        .bind(rustc_version.to_owned())
        .bind(live_generation)
        .execute()
        .await
        .map_err(|error| format!("drop retired slice rows {target}/{rustc_version}: {error}"))?;
    }
    let mut changed: Vec<SliceRowJson> = retired.to_vec();
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
        changed.extend(added.iter().cloned());
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
/// delta report never writes outside the live generation — then refresh
/// `deps_met` — but only on the dependents whose answer can have
/// changed. `changed_json` is the exact set of slice rows this report
/// added or retired, so the refresh probes the dependents of those rows
/// through `idx_queue_dependencies_dep_match` rather than re-evaluating
/// every task with any edge on the slice. `deps_met` is maintained only
/// for `pending` rows — every transition into `pending` recomputes it —
/// so the refresh touches nothing else.
async fn commit_published_slice(
    db: &DurableDb,
    target: &str,
    rustc_version: &str,
    live_generation: i64,
    changed_json: Option<String>,
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
        // merge into the answer the gate reads. O(slice) — the full
        // path pays it; the per-wave delta path skips it.
        db.query(
            "DELETE FROM published_slice_rows \
             WHERE target = ? AND rustc_version = ? AND generation != ?",
        )
        .bind(target.to_owned())
        .bind(rustc_version.to_owned())
        .bind(live_generation)
        .execute()
        .await
        .map_err(|error| format!("retire stale slice rows {target}/{rustc_version}: {error}"))?;
    }
    let Some(changed_json) = changed_json else {
        return Ok(());
    };
    // Membership changed for exactly the `changed_json` rows: refresh
    // the persisted gate answers on the pending dependents of those rows
    // alone. `json_each` drives the probe — one `dep_match` index walk
    // per changed row, then a PK seek into each dependent — so the pass
    // reads in proportion to the delta's dependents, not the slice's
    // edge graph. The `status = 'pending'` restriction lives inside the
    // subquery join: as an outer literal it makes the planner prefer the
    // status index and walk the whole pending group (measured 60k
    // reads on the 100k fixture).
    db.query(&format!(
        "UPDATE queue SET deps_met = {deps_met}, blocked = {blocked} \
         WHERE task_id IN ( \
               SELECT DISTINCT o.task_id \
               FROM (SELECT value AS c FROM json_each(?)) AS j \
               CROSS JOIN queue_dependencies d \
                 ON d.dep_target = ? AND d.dep_rustc_version = ? \
                AND d.dep_crate_name = j.c ->> 'crate_name' \
                AND d.dep_version = j.c ->> 'version' \
                AND d.dep_features_json = j.c ->> 'features_json' \
                AND d.dep_host_side = j.c ->> 'unit_side' \
                AND (d.dep_host_side = 0 OR (j.c ->> 'unit_linked') = 1) \
                AND (d.dep_invocations & ((j.c ->> 'unit_invocation') + 1)) != 0 \
               CROSS JOIN queue o \
                 ON o.task_id = d.task_id AND o.status = 'pending') \
           AND (deps_met != {deps_met} OR blocked != {blocked})",
        deps_met = deps_met_sql("queue.task_id"),
        blocked = blocked_sql("queue.task_id"),
    ))
    .bind(changed_json)
    .bind(target.to_owned())
    .bind(rustc_version.to_owned())
    .execute()
    .await
    .map_err(|error| format!("refresh deps_met for slice {target}/{rustc_version}: {error}"))?;
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
const SCHEMA_VERSION: i64 = 5;

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
    // The claim-order tuple is derived from columns every row carries;
    // `deps_met`/`blocked` replay the gate's EXISTS per row and
    // `wake_at` the lane-aware wake expression. Queue-wide passes are
    // legal here and only here — this is operations code. The `!=`
    // guards recompute any row whose persisted form drifted — a key
    // written under an older format rebuilds under the current one.
    db.query(&format!(
        "UPDATE queue \
         SET dispatch_family = {family}, dispatch_key = {key} \
         WHERE dispatch_family != {family} OR dispatch_key != {key}",
        family = dispatch_family_sql("target"),
        key = dispatch_key_row_sql(),
    ))
    .execute()
    .await
    .map_err(|error| format!("backfill dispatch keys: {error}"))?;
    let deps_met = deps_met_sql("queue.task_id");
    let blocked = blocked_sql("queue.task_id");
    let wake = wake_at_sql(
        "lane",
        "first_requested_at",
        "not_before",
        settings.dispatch_min_age_minutes,
    );
    db.query(&format!(
        "UPDATE queue SET deps_met = {deps_met}, blocked = {blocked}, wake_at = {wake} \
         WHERE deps_met != {deps_met} OR blocked != {blocked} OR wake_at != {wake}",
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
            "dispatch_key",
            "ALTER TABLE queue ADD COLUMN dispatch_key TEXT NOT NULL DEFAULT ''",
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
    // Rows re-enter `pending`: `deps_met`/`blocked` are maintained only
    // for pending rows, so a stale in-flight row's answers may be stale —
    // recompute them in the same statement. `not_before` is untouched, so
    // `wake_at` re-derives from the live columns.
    db.query(&format!(
        "UPDATE queue \
         SET status = 'pending', error_msg = '', deps_met = {deps_met}, \
             blocked = {blocked}, wake_at = {wake}, \
             updated_at = datetime('now') \
         WHERE status IN ('dispatched', 'running') \
           AND updated_at <= datetime('now', ?)",
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
    .execute()
    .await
    .map_err(|error| format!("recover stale active tasks: {error}"))?;
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
    // Rows re-enter `pending`: `deps_met`/`blocked` are maintained only
    // for pending rows, so a completed row's answers are stale —
    // recompute them in the same statement, alongside the `not_before`
    // bump's `wake_at`.
    let next_not_before = "MAX(not_before, datetime('now', '+' || MIN(1 << MIN(dispatch_attempts, 6), 60) || ' minutes'))";
    db.query(&format!(
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
                 AND {unpublished} \
           )",
        deps_met = deps_met_sql("queue.task_id"),
        blocked = blocked_sql("queue.task_id"),
        wake = wake_at_sql(
            "lane",
            "first_requested_at",
            next_not_before,
            settings.dispatch_min_age_minutes,
        ),
        unpublished = dep_edge_unpublished_sql("d")
    ))
    .execute()
    .await
    .map_err(|error| format!("requeue shape-incomplete dependencies: {error}"))?;
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
    first_requested_at: String,
    priority: i64,
    created_at: String,
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
    use super::{AlarmInputs, AlarmPlan, DispatchCapacity, plan_alarm, seconds_until_utc_midnight};

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
    use crate::scheduler::test_db::{counting_memory_db, memory_db, memory_db_raw};
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

    #[tokio::test]
    async fn newer_high_downloads_task_still_loses_to_older_first_seen() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("old", Vec::new())])
            .await
            .expect("enqueue old");
        enqueue(&db, &[request_with_downloads("popular", 10_000)])
            .await
            .expect("enqueue popular");
        set_first_requested_at(&db, "old", PAST_TS).await;

        // Downloads still feed the tie-break priority, but first-seen order
        // dominates: the older, less popular task claims the single slot.
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "old");
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

    #[tokio::test]
    async fn failed_task_re_request_respects_backoff_window() {
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
            &super::BuildCompleteReport {
                task_id: claimed[0].task_id.clone(),
                attempt: claimed[0].attempt,
                success: false,
                error: Some("boom".to_owned()),
                github_run_id: None,
            },
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete");

        // The re-request resurrects the row to pending, but gated by the
        // same exponential backoff a dispatch failure applies — it must not
        // be claimable immediately.
        enqueue(&db, &[request("flaky", Vec::new())])
            .await
            .expect("re-request");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert!(claimed.is_empty());

        let gated = db
            .query(
                "SELECT CASE WHEN not_before > datetime('now') THEN 1 ELSE 0 END AS gated \
                 FROM queue WHERE task_id = ?",
            )
            .bind(super::task_id(
                "flaky", VERSION, FEATURES, TARGET, RUSTC, false,
            ))
            .fetch_scalar::<i64>()
            .await
            .expect("read not_before gate");
        assert_eq!(gated, 1);
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
            &super::BuildCompleteReport {
                task_id: claimed[0].task_id.clone(),
                attempt: claimed[0].attempt,
                success: true,
                error: None,
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
        super::complete(&db, &report(&id, 1, true), TEST_WINDOW_MINUTES)
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

    /// Convergence is the other half: a wave that re-submits an identity
    /// whose build failed puts it back in the queue, so the coverage the
    /// preheat lane asked for is eventually reached without anyone
    /// dispatching by hand.
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
        super::complete(&db, &report(&id, 1, false), TEST_WINDOW_MINUTES)
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
            &super::BuildCompleteReport {
                task_id: id.clone(),
                attempt: claimed[0].attempt,
                success: true,
                error: None,
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
            &super::BuildCompleteReport {
                task_id: "never-enqueued".to_owned(),
                attempt: 1,
                success: true,
                error: None,
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

        super::complete(&db, &report(&id, 1, true), TEST_WINDOW_MINUTES)
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

        let error = super::complete(&db, &report(&id, 1, true), TEST_WINDOW_MINUTES)
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
        super::complete(&db, &report(&id, 2, true), TEST_WINDOW_MINUTES)
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

        super::complete(&db, &report(&id, 1, true), TEST_WINDOW_MINUTES)
            .await
            .expect("complete");
        let error = super::complete(&db, &report(&id, 1, true), TEST_WINDOW_MINUTES)
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
            &report(&claimed[0].task_id, claimed[0].attempt, true),
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
    /// waiting: the requeue revival puts it pending, not published, so
    /// the gate holds the parent until a build and a publish land.
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
            &report(&claimed[0].task_id, claimed[0].attempt, false),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("fail dep");

        // The parent's submit requeues the failed dependency behind the
        // existing backoff — retrying, not terminal.
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
    /// behind it: reporting `blocked`, naming the failed dependency, and
    /// never dispatched — no dispatching the dependent to compile the
    /// dependency itself. Retrying the dependency returns the dependent
    /// to `pending`, since `blocked` is derived, never stored.
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
        super::complete(
            &db,
            &report(&claimed[0].task_id, claimed[0].attempt, false),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("fail dep");

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

        // Retrying the dependency returns the dependent to `pending` —
        // nothing to reconcile, the derivation just stops firing.
        super::apply_mutation(
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
        let parent = super::task_status(&db, &task_id_on("parent", TARGET))
            .await
            .expect("read parent status after retry")
            .expect("parent row");
        assert_eq!(parent.status, stow_types::api::QueueTaskStatus::Pending);
        assert_eq!(parent.blocked_by, None);
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
        super::complete(
            &db,
            &report(&claimed[0].task_id, claimed[0].attempt, false),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("fail dep");

        // The dependency is retried and this time succeeds — but the
        // dependent still waits for the slice that serves it.
        super::apply_mutation(
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
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim dep retry");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "dep");
        super::complete(
            &db,
            &report(&claimed[0].task_id, claimed[0].attempt, true),
            TEST_WINDOW_MINUTES,
        )
        .await
        .expect("complete dep retry");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim before publish");
        assert!(claimed.is_empty(), "completed is still not servable");

        publish(&db, "dep").await;
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

    fn report(task_id: &str, attempt: u32, success: bool) -> super::BuildCompleteReport {
        super::BuildCompleteReport {
            task_id: task_id.to_owned(),
            attempt,
            success,
            error: None,
            github_run_id: None,
        }
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
    #[tokio::test]
    async fn migrate_migrates_a_dev_era_queue_and_backfills_edge_masks() {
        #[derive(skyzen::FromRow)]
        struct EdgeRow {
            side: i64,
            invocations: i64,
            shapes: i64,
        }
        #[derive(skyzen::FromRow)]
        struct QueueRow {
            status: String,
            host_side: i64,
            shape_requeue: i64,
        }
        let db = memory_db_raw().await.expect("raw memory db");
        for statement in [DEV_ERA_QUEUE, DEV_ERA_DEPENDENCIES] {
            db.query(statement).execute().await.expect("dev-era ddl");
        }
        let owner = task_id_on("parent", TARGET);
        let dep = task_id_on("dep", TARGET);
        db.query(
            "INSERT INTO queue (task_id, crate_name, version, features_json, target, rustc_version)
             VALUES (?, 'dep', '1.0.0', '[]', ?, '1.85.0'),
                    (?, 'parent', '1.0.0', '[]', ?, '1.85.0')",
        )
        .bind(dep.clone())
        .bind(TARGET)
        .bind(owner.clone())
        .bind(TARGET)
        .execute()
        .await
        .expect("dev-era queue rows");
        db.query(
            "INSERT INTO queue_dependencies
             (task_id, depends_on_task_id, dep_crate_name, dep_version, dep_features_json, dep_target, dep_rustc_version)
             VALUES (?, ?, 'dep', '1.0.0', '[]', ?, '1.85.0')",
        )
        .bind(owner)
        .bind(dep)
        .bind(TARGET)
        .execute()
        .await
        .expect("dev-era edge row");

        let report = super::migrate(&db, &settings()).await.expect("migrate");
        assert_eq!(
            (report.before, report.after),
            (0, super::SCHEMA_VERSION),
            "a pre-versioned queue reports 0 → SCHEMA_VERSION"
        );
        // A second pass must be a no-op, not a failure — deploy retries.
        let retry = super::migrate(&db, &settings())
            .await
            .expect("migrate retry");
        assert_eq!(
            (retry.before, retry.after),
            (super::SCHEMA_VERSION, super::SCHEMA_VERSION)
        );

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

        let rows = db
            .query("SELECT status, host_side, shape_requeue FROM queue")
            .fetch_all::<QueueRow>()
            .await
            .expect("queue rows");
        assert_eq!(rows.len(), 2, "the rebuild keeps every queue row");
        assert!(
            rows.iter()
                .all(|row| row.status == "pending" && row.host_side == 0 && row.shape_requeue == 0)
        );

        assert_eq!(
            super::stored_schema_version(&db)
                .await
                .expect("schema version"),
            super::SCHEMA_VERSION,
            "a migrated queue is stamped at the current schema version"
        );
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
        db.query(&format!(
            "UPDATE queue SET first_requested_at = ?, dispatch_key = {} \
             WHERE target = ?",
            super::dispatch_key_row_sql()
        ))
        .bind(PAST_TS)
        .bind(MACOS_TARGET)
        .execute()
        .await
        .expect("backdate macos backlog");

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
            &report(&claimed[0].task_id, claimed[0].attempt, true),
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
            &report(&claimed[0].task_id, claimed[0].attempt, true),
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

    /// Several parents in one chunk all name the same failed dep. The
    /// pre-batch loop issued the revival `UPDATE … WHERE status =
    /// 'failed'` once per edge: the first parent's statement flipped the
    /// row to 'pending' and every later parent's matched nothing, so the
    /// net was +1 `attempt` / +1 `request_count` however many parents
    /// named it. The batched requeue must land the same.
    #[tokio::test]
    async fn a_chunk_revives_a_failed_dependency_once_for_many_parents() {
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
            ("pending", 8, 6),
            "exactly one revival: +1 attempt, +1 request_count"
        );
    }

    /// Order matters inside a chunk. Dep first: its own request runs
    /// the old loop's `update_existing_task` resurrection (+1 `attempt`,
    /// +1 `request_count`, status 'pending', error cleared) and the
    /// parent's later per-edge `WHERE status = 'failed'` then matches
    /// nothing — net +1/+1, the row pending.
    #[tokio::test]
    async fn dep_request_before_its_parent_in_one_chunk() {
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
            ("pending", 8, 6),
            "dep resurrected by its own request; the parent's requeue is a no-op"
        );
        assert_eq!(row_column(&db, "parent", "status").await, "pending");
    }

    /// Parent first: its dep-sync revival flips the failed row pending
    /// with +1 `attempt` / +1 `request_count`, and the dep's own request
    /// afterwards meets a 'pending' row — `update_existing_task` runs
    /// the non-resurrection update, `request_count` +1 and no `attempt`
    /// bump. Net +1 `attempt` / +2 `request_count` (the reverse order
    /// differs — see `dep_request_before_its_parent_in_one_chunk`).
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
            ("pending", 8, 7),
            "the requeue's +1/+1 then the dep's own non-resurrection request_count +1"
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
        // Seven: edge delete + edge insert + task insert + task update
        // + dep-requeue + `deps_met` refresh + `dispatch_key` refresh,
        // each a single statement over the whole chunk regardless of
        // request count.
        assert!(
            issued <= 7,
            "a 1000-request chunk must stay a constant statement count \
             (measured 7), got {issued}"
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
        // Names carry the batch: a repeat name re-requests the failed
        // task, which re-arms the not_before backoff and hides the row
        // from the claim this seeding is about to run.
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
            let mut report = report(&task.task_id, task.attempt, failure.is_none());
            if let Some((error, run_id)) = failure {
                report.error = Some(error.to_owned());
                report.github_run_id = Some(run_id.to_owned());
            }
            super::complete(db, &report, TEST_WINDOW_MINUTES)
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
                "WITH RECURSIVE seq(x) AS (                     SELECT 1 UNION ALL SELECT x + 1 FROM seq WHERE x <= ?                 )                  INSERT INTO attempt_outcomes                      (task_id, attempt, target, failure_class,                       github_run_id, finished_at)                  SELECT 'seed-' || x, 1, ?, 'boom',                         'run-' || x, datetime('now', '-' || (x % 50) || ' minutes')                  FROM seq",
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
                &super::BuildCompleteReport {
                    task_id: claimed[0].task_id.clone(),
                    attempt: claimed[0].attempt,
                    success: false,
                    error: Some("boom".to_owned()),
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
}
