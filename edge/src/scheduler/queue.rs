use std::collections::BTreeSet;
use std::future::Future;

use skyzen_services::durable::{DbValue, DurableDb};
use stow_types::api::{
    AdminInFlight, AdminStatus, AdminTargetStats, BuildCompleteReport, EnqueueDependency,
    EnqueueRequest, EnqueueSource, PublishedSliceRow, QueueSelector, QueueTask, QueueTaskStatus,
    RequestStatus, RunnerFamily, SchedulerStatus, TaskLane, runner_family,
};
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};

use crate::errors::QueueError;

/// The semantic identity of a crates.io task, as the artifact catalog
/// keys it: the identity a published closure member registers under.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemanticTaskIdentity {
    pub crate_name: String,
    pub version: String,
    pub features_json: String,
    pub target: String,
    pub rustc_version: String,
}

/// Answers, for a batch of pending crates.io tasks, which of them the
/// artifact catalog already covers. A dominator's publish registers every
/// member of its closure, so the dominated tasks it held back are retired
/// at claim time instead of rebuilding what is already served. Production
/// asks D1; tests answer from a fixed set.
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
    /// The row's enqueue epoch at claim time. Dispatch carries it in
    /// `BuildTaskPayload` and the completion report echoes it back, so a
    /// late report for a superseded attempt cannot overwrite the live one.
    pub attempt: u32,
    pub crate_name: String,
    pub version: String,
    pub features_json: String,
    pub target: String,
    pub rustc_version: String,
    pub preserve_lockfile: bool,
}

// Dispatch ceilings, sized against the org's 60 GitHub-hosted runners (20
// of them macOS): 45 total leaves 15 runners for the repo's own CI, and
// the macOS cap keeps a full wave from queueing on the smallest pool
// while leaving 4 macOS runners free.
const DEFAULT_MAX_CONCURRENT_JOBS: u32 = 45;
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

/// Runtime-tunable scheduler knobs, read from Worker env bindings by the
/// Durable Object glue (`STOW_MAX_CONCURRENT_JOBS`,
/// `STOW_MAX_CONCURRENT_MACOS_JOBS`, `STOW_DISPATCH_MIN_AGE_MINUTES`,
/// `STOW_STALE_DISPATCH_MINUTES`, `STOW_MAX_QUEUE_PENDING`,
/// `STOW_HUMAN_DAILY_TASK_BUDGET`).
///
/// Defaults match production; the local mock lowers `max_concurrent_jobs`
/// via `vars` because miniflare's workerd OOMs under parallel register/
/// complete bursts.
#[derive(Debug, Clone, Copy)]
pub struct SchedulerSettings {
    /// Cap on tasks in flight (`dispatched`/`running`) across all runner
    /// families.
    pub max_concurrent_jobs: u32,
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
            max_concurrent_jobs: DEFAULT_MAX_CONCURRENT_JOBS,
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

async fn find_existing_task(
    db: &DurableDb,
    identity: &TaskIdentity,
) -> Result<Option<TaskIdRow>, QueueError> {
    db.query(
        "SELECT task_id, status FROM queue \
         WHERE crate_name = ? AND version = ? AND features_json = ? AND target = ? AND rustc_version = ? \
         LIMIT 1",
    )
    .bind(identity.crate_name.clone())
    .bind(identity.version.clone())
    .bind(identity.features_json.clone())
    .bind(identity.target.clone())
    .bind(identity.rustc_version.clone())
    .fetch_optional::<TaskIdRow>()
    .await
    .map_err(|error| format!("select existing task: {error}").into())
}

/// Whether a re-request puts a terminal row back in the queue.
///
/// A failed row always goes back: that is how a wave converges on the
/// coverage it asked for, and the exponential backoff in
/// `update_existing_task` keeps the retry rate sane. A completed row is
/// different — its artifacts are in the catalog, and the unattended
/// preheat lane re-submits the whole top-N list on every wave, so
/// resurrecting completions would rebuild the entire pool on a timer.
/// Only the human lane, where someone asked for this exact crate again,
/// rebuilds something already served.
const fn resurrects(status: &str, lane: TaskLane) -> bool {
    match status.as_bytes() {
        // A partial row's own artifact is still missing — a re-request
        // needs the build to run again exactly like a plain failure does.
        b"failed" | b"partial" => true,
        b"completed" => matches!(lane, TaskLane::Human),
        _ => false,
    }
}

/// Apply a re-request to an existing row. `redispatch` (see
/// `resurrects`) puts a terminal row back to pending — a failed task's
/// resurrection carries the same exponential backoff a dispatch failure
/// would have applied, so spamming a miss cannot resurrect it early.
async fn update_existing_task(
    db: &DurableDb,
    identity: &TaskIdentity,
    redispatch: bool,
    downloads: i64,
    lane: TaskLane,
) -> Result<(), QueueError> {
    // Re-requesting a task never lets it jump the queue: priority is
    // recomputed from downloads/misses only and `first_requested_at` is
    // untouched. Resurrection bumps `attempt` so a completion report still
    // in flight for the superseded attempt cannot apply to the new one.
    let update = if redispatch {
        db.query(
            "UPDATE queue \
             SET downloads = CASE WHEN downloads > ? THEN downloads ELSE ? END, \
                 request_count = request_count + 1, \
                 priority = ((CASE WHEN downloads > ? THEN downloads ELSE ? END) / 1000) + \
                            (miss_count * 10), \
                 status = 'pending', \
                 attempt = attempt + 1, \
                 error_msg = '', \
                 not_before = CASE WHEN status IN ('failed', 'partial') \
                     THEN MAX(not_before, datetime('now', '+' || MIN(1 << MIN(dispatch_attempts, 6), 60) || ' minutes')) \
                     ELSE not_before END, \
                 updated_at = datetime('now'), \
                 lane = CASE ? WHEN 'human' THEN 'human' ELSE lane END \
             WHERE crate_name = ? AND version = ? AND features_json = ? AND target = ? AND rustc_version = ?",
        )
    } else {
        db.query(
            "UPDATE queue \
             SET downloads = CASE WHEN downloads > ? THEN downloads ELSE ? END, \
                 request_count = request_count + 1, \
                 priority = ((CASE WHEN downloads > ? THEN downloads ELSE ? END) / 1000) + \
                            (miss_count * 10), \
                 updated_at = datetime('now'), \
                 lane = CASE ? WHEN 'human' THEN 'human' ELSE lane END \
             WHERE crate_name = ? AND version = ? AND features_json = ? AND target = ? AND rustc_version = ?",
        )
    };
    update
        .bind(downloads)
        .bind(downloads)
        .bind(downloads)
        .bind(downloads)
        .bind(lane.as_str())
        .bind(identity.crate_name.clone())
        .bind(identity.version.clone())
        .bind(identity.features_json.clone())
        .bind(identity.target.clone())
        .bind(identity.rustc_version.clone())
        .execute()
        .await
        .map_err(|error| format!("update existing task: {error}").into())
        .map(|_| ())
}

async fn insert_task(
    db: &DurableDb,
    task_id: &str,
    identity: TaskIdentity,
    downloads: i64,
    priority: i64,
    preserve_lockfile: bool,
    lane: TaskLane,
) -> Result<(), QueueError> {
    db.query(
        "INSERT INTO queue \
         (task_id, crate_name, version, features_json, target, rustc_version, downloads, miss_count, request_count, priority, status, preserve_lockfile, lane, attempt, first_requested_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, 0, 1, ?, 'pending', ?, ?, 1, datetime('now'))",
    )
    .bind(task_id.to_owned())
    .bind(identity.crate_name)
    .bind(identity.version)
    .bind(identity.features_json)
    .bind(identity.target)
    .bind(identity.rustc_version)
    .bind(downloads)
    .bind(priority)
    .bind(i64::from(preserve_lockfile))
    .bind(lane.as_str())
    .execute()
    .await
    .map_err(|error| format!("insert task: {error}").into())
    .map(|_| ())
}

/// Pending rows in the queue — the count the `STOW_MAX_QUEUE_PENDING`
/// gate compares against.
async fn pending_count(db: &DurableDb) -> Result<u32, QueueError> {
    let pending = db
        .query("SELECT count(*) AS count FROM queue WHERE status = 'pending'")
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

/// Enqueue submissions from a RepoWriter-trusted caller: the
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
    ensure_schema(db).await?;
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
    let mut inserted = 0u32;

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
        let task_id = task_id(
            &identity.crate_name,
            &identity.version,
            identity.features_json.as_str(),
            &identity.target,
            &identity.rustc_version,
        );
        let downloads = u64_to_i64(request.downloads, "downloads")?;
        let priority = compute_priority(request.downloads, 0)?;
        let lane = request_lane(request.source);

        if let Some(existing) = find_existing_task(db, &identity).await? {
            let redispatch = resurrects(existing.status.as_str(), lane);
            update_existing_task(db, &identity, redispatch, downloads, lane).await?;
            // A re-request without dependency info (exact/semantic miss paths
            // always send an empty list) must not erase ordering edges that a
            // graph-analysis enqueue already established.
            if !request.depends_on.is_empty() {
                sync_task_dependencies(db, &existing.task_id, &request.depends_on).await?;
            }
        } else {
            insert_task(
                db,
                &task_id,
                identity,
                downloads,
                priority,
                request.preserve_lockfile,
                lane,
            )
            .await?;
            inserted += 1;
            sync_task_dependencies(db, &task_id, &request.depends_on).await?;
        }
    }

    Ok(inserted)
}

pub async fn complete(db: &DurableDb, report: &BuildCompleteReport) -> Result<(), QueueError> {
    ensure_schema(db).await?;
    // Three terminal outcomes, not two: a stopped-early build that
    // published the prefix it captured is neither a completion (its own
    // artifact is still missing) nor a plain failure (the run did not
    // land empty-handed).
    let status = if report.success {
        "completed"
    } else if report.partial {
        "partial"
    } else {
        "failed"
    };

    // The report must name the row's live attempt in an in-flight status:
    // without that predicate a late or duplicate report for a superseded
    // attempt would overwrite the state of the attempt the row has since
    // been resurrected into (enqueue bumps `attempt` on resurrection).
    let result = db
        .query(
            "UPDATE queue \
             SET status = ?, error_msg = ?, github_run_id = COALESCE(?, github_run_id), \
                 updated_at = datetime('now') \
             WHERE task_id = ? AND attempt = ? AND status IN ('dispatched', 'running')",
        )
        .bind(status)
        .bind(report.error.clone().unwrap_or_default())
        .bind(report.github_run_id.clone())
        .bind(report.task_id.clone())
        .bind(i64::from(report.attempt))
        .execute()
        .await
        .map_err(|error| format!("complete task: {error}"))?;
    // A report that applied to no row is never a silent success: an
    // unknown task id is a 404 at the handler, and a known row whose live
    // attempt/status no longer matches is a stale or duplicate report —
    // logged and answered 409 so the reporter sees the conflict rather
    // than believing it completed the current attempt.
    if result.rows_written == 0 {
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

    Ok(())
}

pub async fn status(db: &DurableDb) -> Result<SchedulerStatus, QueueError> {
    ensure_schema(db).await?;
    // One pass over the queue's (status, lane) groups — six sequential
    // count(*) scans would read ~6x the rows for the same answer, and every
    // graph analysis and enqueue redemption calls this.
    let rows = db
        .query(
            "SELECT status, lane, count(*) AS count \
             FROM queue GROUP BY status, lane",
        )
        .fetch_all::<StatusLaneCountRow>()
        .await
        .map_err(|error| format!("count queue by status and lane: {error}"))?;
    let mut pending = 0_u64;
    let mut human_pending = 0_u64;
    let mut dispatched = 0_u64;
    let mut running = 0_u64;
    let mut completed = 0_u64;
    let mut failed = 0_u64;
    let mut partial = 0_u64;
    for row in rows {
        match row.status.as_str() {
            "pending" => {
                pending += row.count;
                if row.lane == TaskLane::Human.as_str() {
                    human_pending += row.count;
                }
            }
            "dispatched" => dispatched += row.count,
            "running" => running += row.count,
            "completed" => completed += row.count,
            "failed" => failed += row.count,
            "partial" => partial += row.count,
            _ => {}
        }
    }
    let blocked = db
        .query(&format!(
            "SELECT count(*) AS count FROM queue WHERE ({}) = 'blocked'",
            effective_status_sql()
        ))
        .fetch_scalar::<u64>()
        .await
        .map_err(|error| format!("count blocked tasks: {error}"))?;
    Ok(SchedulerStatus {
        pending: u64_to_u32(pending, "pending task count")?,
        human_pending: u64_to_u32(human_pending, "human pending task count")?,
        dispatched: u64_to_u32(dispatched, "dispatched task count")?,
        running: u64_to_u32(running, "running task count")?,
        completed: u64_to_u32(completed, "completed task count")?,
        failed: u64_to_u32(failed, "failed task count")?,
        partial: u64_to_u32(partial, "partial task count")?,
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
    ensure_schema(db).await?;
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
    ensure_schema(db).await?;
    if task_ids.is_empty() {
        return Ok(Vec::new());
    }
    // One IN-clause select per batch: the per-id loop re-ran ensure_schema
    // and a point select for every id — an N+1 on a hot request path.
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

/// The dependency edge's unsatisfied half: no row of the live published
/// generation for the dependency's own `(target, rustc_version)` slice
/// carries the semantic identity the edge names. Built per call site
/// since the edge table's alias differs between the gate (`d`) and the
/// status derivation (`bd`).
fn dep_edge_unpublished_sql(alias: &str) -> String {
    format!(
        "NOT EXISTS ( \
            SELECT 1 FROM published_slice_rows p \
            JOIN published_slices s \
              ON s.target = p.target AND s.rustc_version = p.rustc_version \
             AND s.generation = p.generation \
            WHERE p.target = {alias}.dep_target \
              AND p.rustc_version = {alias}.dep_rustc_version \
              AND p.crate_name = {alias}.dep_crate_name \
              AND p.version = {alias}.dep_version \
              AND p.features_json = {alias}.dep_features_json \
        )"
    )
}

/// Dependency-gate predicate shared by dispatch selection and alarm
/// computation: a task is dispatchable only when every dependency edge
/// resolves to a row the latest published index slice serves for the
/// dependency's own `(target, rustc_version)` — the host slice for a
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
fn dependency_not_blocked_sql() -> String {
    format!(
        "NOT EXISTS ( \
            SELECT 1 FROM queue_dependencies d \
            WHERE d.task_id = q.task_id \
              AND {} \
        )",
        dep_edge_unpublished_sql("d")
    )
}

/// Status projection read paths use so a dependent parked behind a
/// terminally failed dependency surfaces as `blocked` instead of
/// `pending`: a `failed`/`partial` dependency is done until an operator
/// retries it or a fresh request requeues it, and "waiting for that" is
/// a different thing to see than "waiting for a publish". Only an edge
/// the gate still counts as unmet blocks — a failed dependency whose
/// identity is already served by the published slice holds nothing back.
/// Read-time only — the stored status stays `pending`, so retrying the
/// dependency returns the dependent to `pending` with nothing to
/// reconcile.
fn effective_status_sql() -> String {
    format!(
        "CASE WHEN queue.status = 'pending' AND EXISTS ( \
            SELECT 1 FROM queue_dependencies bd \
            JOIN queue bdep ON bdep.task_id = bd.depends_on_task_id \
            WHERE bd.task_id = queue.task_id AND bdep.status IN ('failed', 'partial') \
              AND {} \
        ) THEN 'blocked' ELSE queue.status END",
        dep_edge_unpublished_sql("bd")
    )
}

/// Task id of the first terminally failed dependency edge a pending row
/// names — the `blocked_by` companion to [`effective_status_sql`].
fn blocked_by_sql() -> String {
    format!(
        "SELECT bd.depends_on_task_id \
            FROM queue_dependencies bd \
            JOIN queue bdep ON bdep.task_id = bd.depends_on_task_id \
            WHERE bd.task_id = queue.task_id AND bdep.status IN ('failed', 'partial') \
              AND {} \
            ORDER BY bd.depends_on_task_id LIMIT 1",
        dep_edge_unpublished_sql("bd")
    )
}

pub async fn claim_dispatchable_tasks(
    db: &DurableDb,
    settings: &SchedulerSettings,
    coverage: &impl CoverageOracle,
) -> Result<Vec<QueuedTask>, QueueError> {
    ensure_schema(db).await?;
    recover_stale_active_tasks(db, settings).await?;
    let active = count_active_by_family(db).await?;
    let mut total_slots = settings.max_concurrent_jobs.saturating_sub(active.total);
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

    let rows = select_dispatchable_rows(db, settings).await?;
    tracing::info!(
        selected = rows.len(),
        "scheduler claim_dispatchable_tasks selected rows"
    );

    let rows = retire_covered_rows(db, rows, coverage).await?;
    let mut claimed = Vec::with_capacity(rows.len());
    for row in rows {
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
            preserve_lockfile: row.preserve_lockfile != 0,
        });
    }

    Ok(claimed)
}

/// Retire every candidate row whose semantic identity the artifact
/// catalog already covers — a dominator's publish landed while the row
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

/// Every dispatchable pending row in claim order: human lane first
/// (exempt from the dispatch minimum age), then Windows-family targets —
/// the Windows legs are the slowest in a wave, so starting them first
/// shortens the wave's wall clock — then FIFO by `first_requested_at`
/// with the existing tie breakers.
///
/// Deliberately no `LIMIT`: a row's family is decided in Rust, so a
/// family-capped row must be skippable without hiding the rows behind
/// it; the claim walk stops once the total slot count is spent.
async fn select_dispatchable_rows(
    db: &DurableDb,
    settings: &SchedulerSettings,
) -> Result<Vec<TaskRow>, QueueError> {
    let windows_targets = RunnerFamily::Windows.targets();
    let sql = format!(
        "SELECT q.task_id, q.attempt, q.crate_name, q.version, q.features_json, q.target, q.rustc_version, q.preserve_lockfile, q.dispatch_attempts \
         FROM queue q \
         WHERE q.status = 'pending' \
           AND (q.lane = 'human' OR q.first_requested_at <= datetime('now', ?)) \
           AND q.not_before <= datetime('now') \
           AND {} \
         ORDER BY CASE q.lane WHEN 'human' THEN 0 ELSE 1 END, \
                  CASE WHEN q.target IN ({}) THEN 0 ELSE 1 END, \
                  q.first_requested_at ASC, q.priority DESC, q.created_at ASC, q.task_id ASC",
        dependency_not_blocked_sql(),
        crate::sql_batch::placeholders(windows_targets.len())
    );
    let mut query = db
        .query(&sql)
        .bind(dispatch_cutoff_modifier(settings.dispatch_min_age_minutes));
    for target in windows_targets {
        query = query.bind((*target).to_owned());
    }
    query
        .fetch_all::<TaskRow>()
        .await
        .map_err(|error| format!("select dispatchable tasks: {error}").into())
}

pub async fn mark_dispatch_failed(
    db: &DurableDb,
    task_id: &str,
    error: &str,
) -> Result<(), QueueError> {
    ensure_schema(db).await?;
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
    db.query(
        "UPDATE queue \
         SET status = 'pending', error_msg = ?, \
             not_before = datetime('now', ?), \
             updated_at = datetime('now') \
         WHERE task_id = ?",
    )
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
    ensure_schema(db).await?;
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
    ensure_schema(db).await?;
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

/// Read the anonymous-traffic circuit breaker from the `settings` table.
/// An absent row means off; any stored value other than 'true'/'false'
/// violates the schema's contract and is an invariant error rather than a
/// guess.
pub async fn panic_enabled(db: &DurableDb) -> Result<bool, QueueError> {
    ensure_schema(db).await?;
    let value = db
        .query("SELECT value FROM settings WHERE key = 'panic'")
        .fetch_scalar_optional::<String>()
        .await
        .map_err(|error| format!("read panic setting: {error}"))?;
    match value.as_deref() {
        Some("true") => Ok(true),
        // An absent row, like a stored 'false', means off.
        None | Some("false") => Ok(false),
        Some(other) => Err(QueueError::Invariant(format!(
            "settings row `panic` holds unexpected value `{other}`"
        ))),
    }
}

/// Write the anonymous-traffic circuit breaker into the `settings` table.
pub async fn set_panic(db: &DurableDb, enabled: bool) -> Result<(), QueueError> {
    ensure_schema(db).await?;
    db.query(
        "INSERT INTO settings (key, value) VALUES ('panic', ?) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(if enabled { "true" } else { "false" })
    .execute()
    .await
    .map_err(|error| format!("write panic setting: {error}"))?;
    Ok(())
}

// ===== Admin operations (`stow-admin` through the DO's `/tasks*` routes) =====

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
}

const ADMIN_TASK_COLUMNS: &str = "task_id, crate_name, version, features_json, target, \
     rustc_version, lane, attempt, error_msg, downloads, miss_count, \
     request_count, dispatch_attempts, preserve_lockfile, \
     github_run_id, first_requested_at, created_at, updated_at";

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
            // The predicate compares the derived status, so a `blocked`
            // selector finds parked dependents and a `pending` one does
            // not conflate them with rows merely waiting on a publish.
            predicates.push(format!("({}) = ?", effective_status_sql()));
            values.push(status.as_str().into());
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
    ensure_schema(db).await?;
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
    mutation: QueueMutation,
    selector: &QueueSelector,
) -> Result<u32, QueueError> {
    ensure_schema(db).await?;
    let (predicate, values) = selector_predicate(selector)?;
    let sql = match mutation {
        QueueMutation::Retry => format!(
            "UPDATE queue SET status = 'pending', error_msg = '', \
             not_before = '1970-01-01 00:00:00', updated_at = datetime('now') \
             WHERE status IN ('failed', 'partial') AND {predicate}"
        ),
        QueueMutation::Cancel => format!(
            "UPDATE queue SET status = 'failed', error_msg = 'cancelled by operator', \
             updated_at = datetime('now') \
             WHERE status IN ('pending', 'dispatched') AND {predicate}"
        ),
        QueueMutation::Promote => format!(
            "UPDATE queue SET lane = 'human', updated_at = datetime('now') \
             WHERE status = 'pending' AND lane = 'miss' AND {predicate}"
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
            format!(
                "DELETE FROM queue WHERE status IN ('completed', 'failed', 'partial') AND {predicate}"
            )
        }
    };
    let mut query = db.query(&sql);
    for value in values {
        query = query.bind(value);
    }
    let result = query
        .execute()
        .await
        .map_err(|error| format!("apply queue mutation: {error}"))?;
    u64_to_u32(result.rows_written, "mutated row count")
}

/// Operator view of the whole queue for `GET /admin/status`: lane depths,
/// the oldest pending row's age, the in-flight set, per-target outcome
/// tallies over the trailing 24 hours, and the panic flag.
pub async fn admin_status(db: &DurableDb) -> Result<AdminStatus, QueueError> {
    ensure_schema(db).await?;
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
             WHERE status IN ('completed', 'failed', 'partial') \
               AND updated_at >= datetime('now', '-24 hours') \
             GROUP BY target, status",
        )
        .fetch_all::<TargetOutcomeRow>()
        .await
        .map_err(|error| format!("count 24h outcomes by target: {error}"))?;
    let mut by_target: std::collections::BTreeMap<String, (u32, u32, u32)> =
        std::collections::BTreeMap::new();
    for row in outcome_rows {
        let entry = by_target.entry(row.target).or_default();
        match row.status.as_str() {
            "completed" => entry.0 = u64_to_u32(row.count, "completed count")?,
            "failed" => entry.1 = u64_to_u32(row.count, "failed count")?,
            "partial" => entry.2 = u64_to_u32(row.count, "partial count")?,
            _ => {}
        }
    }
    let targets = by_target
        .into_iter()
        .map(|(target, (completed_24h, failed_24h, partial_24h))| {
            Ok(AdminTargetStats {
                target: TargetTriple::parse(target)?,
                completed_24h,
                failed_24h,
                partial_24h,
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
        panic_enabled: panic_enabled(db).await?,
    })
}

/// Stamp the GitHub Actions run id a dispatched build reported back
/// through its OIDC-claimed register/complete calls onto the queue row.
///
/// The stamp deliberately does not touch `updated_at`: that column is the
/// stale-dispatch lease clock and must only move on real state
/// transitions. Rows that already left the in-flight set (resurrected by
/// a re-request or completed) are not stamped — their `github_run_id`
/// still names the run that acted on the live attempt.
pub async fn observe_run(
    db: &DurableDb,
    task_id: &str,
    github_run_id: &str,
) -> Result<(), QueueError> {
    ensure_schema(db).await?;
    db.query(
        "UPDATE queue SET github_run_id = ? \
         WHERE task_id = ? AND status IN ('dispatched', 'running')",
    )
    .bind(github_run_id.to_owned())
    .bind(task_id.to_owned())
    .execute()
    .await
    .map_err(|error| format!("observe run id for {task_id}: {error}"))?;
    Ok(())
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

/// Everything [`plan_alarm`] needs, pre-fetched from the queue so the
/// decision itself is a pure function unit tests can drive on the host.
#[derive(Debug, Clone, Copy)]
pub struct AlarmInputs {
    /// Current time in epoch milliseconds.
    pub now_ms: i64,
    /// `active_total < max_concurrent_jobs` — a dispatch slot is free.
    /// Family saturation is already folded into
    /// `earliest_pending_eligible_ms`, whose query only covers rows whose
    /// family has a free slot, so `Some(..)` here plus `capacity_available`
    /// always means a claim can proceed.
    pub capacity_available: bool,
    /// Earliest moment any unblocked pending row in a family with a free
    /// dispatch slot becomes dispatchable.
    pub earliest_pending_eligible_ms: Option<i64>,
    /// Earliest `updated_at + stale_dispatch_minutes` over dispatched/running
    /// rows — when the oldest in-flight build becomes recoverable. Must be
    /// `Some` whenever `capacity_available` is false; `next_alarm` enforces
    /// this before delegating.
    pub earliest_active_lease_expiry_ms: Option<i64>,
}

/// Pure alarm decision; see [`AlarmInputs`] for the meaning of each field.
///
/// A wake-up is needed not only for pending rows becoming eligible but also
/// for stale recovery: `recover_stale_active_tasks` only runs inside
/// `claim_dispatchable_tasks`, so an in-flight build whose `/complete`
/// callback never arrives would never be reclaimed unless the alarm fires at
/// its lease expiry.
pub fn plan_alarm(inputs: &AlarmInputs) -> AlarmPlan {
    match inputs.earliest_pending_eligible_ms {
        Some(eligible_ms) if inputs.capacity_available => {
            AlarmPlan::At(eligible_ms.max(inputs.now_ms))
        }
        // Capacity is exhausted, so the earliest wake-up that can make
        // progress is the oldest lease expiring — never `now`, which would
        // spin the Durable Object in a zero-delay alarm loop.
        Some(_) => inputs.earliest_active_lease_expiry_ms.map_or_else(
            || unreachable!("exhausted dispatch capacity implies an active queue row"),
            |lease_ms| AlarmPlan::At(lease_ms.max(inputs.now_ms)),
        ),
        // No unblocked pending row: wake at lease expiry if anything is in
        // flight (covers pending rows blocked on an active dependency too —
        // they unblock when it completes or goes stale), otherwise delete.
        None => inputs
            .earliest_active_lease_expiry_ms
            .map_or(AlarmPlan::Delete, |lease_ms| {
                AlarmPlan::At(lease_ms.max(inputs.now_ms))
            }),
    }
}

/// Decide the next scheduler alarm from live queue state.
pub async fn next_alarm(
    db: &DurableDb,
    now_ms: i64,
    settings: &SchedulerSettings,
) -> Result<AlarmPlan, QueueError> {
    ensure_schema(db).await?;
    let active = count_active_by_family(db).await?;
    // A capped family whose slots are all taken must not feed the
    // eligibility query: a queue whose only eligible pending rows belong
    // to it would otherwise re-arm the alarm at `now` forever.
    let macos_saturated = active.of(RunnerFamily::MacOs) >= settings.max_concurrent_macos_jobs;
    let inputs = AlarmInputs {
        now_ms,
        capacity_available: active.total < settings.max_concurrent_jobs,
        earliest_pending_eligible_ms: earliest_pending_eligible_ms(
            db,
            settings,
            macos_saturated.then_some(RunnerFamily::MacOs),
        )
        .await?,
        earliest_active_lease_expiry_ms: earliest_active_lease_expiry_ms(db, settings).await?,
    };
    // Exhausted capacity means at least one dispatched/running row exists, so
    // a missing lease expiry contradicts the count just read — fail loudly
    // rather than letting plan_alarm pick a wake-up.
    if !inputs.capacity_available && inputs.earliest_active_lease_expiry_ms.is_none() {
        return Err(QueueError::Invariant(
            "dispatch capacity exhausted but no dispatched/running rows".to_owned(),
        ));
    }
    Ok(plan_alarm(&inputs))
}

/// Earliest epoch-ms at which an unblocked pending row in a family with a
/// free dispatch slot becomes dispatchable. Per-row eligibility is the
/// later of `first_requested_at + min age` and the failure-backoff gate;
/// the result is the earliest such moment among unblocked pending tasks.
/// May be in the past (already eligible).
///
/// `full_family` names a capped runner family whose slots are all taken;
/// its pending rows are excluded so an eligibility the scheduler could
/// not act on cannot wake the alarm at `now`.
async fn earliest_pending_eligible_ms(
    db: &DurableDb,
    settings: &SchedulerSettings,
    full_family: Option<RunnerFamily>,
) -> Result<Option<i64>, QueueError> {
    // A pending human task is eligible now: the minimum-age gate applies
    // only to the miss lane, while `not_before` (dispatch-failure backoff)
    // still applies to both lanes.
    let (family_filter, excluded_targets) = full_family.map_or_else(
        || (String::new(), &[][..]),
        |family| {
            (
                format!(
                    "AND q.target NOT IN ({})",
                    crate::sql_batch::placeholders(family.targets().len())
                ),
                family.targets(),
            )
        },
    );
    let sql = format!(
        "SELECT CAST(strftime('%s', MIN(CASE WHEN q.lane = 'human' \
             THEN MAX(q.not_before, datetime('now')) \
             ELSE MAX(datetime(q.first_requested_at, ?), q.not_before) END)) AS INTEGER) AS eligible_epoch \
         FROM queue q \
         WHERE q.status = 'pending' \
           AND {} \
           {family_filter}",
        dependency_not_blocked_sql()
    );
    let mut query = db
        .query(&sql)
        .bind(format!("+{} minutes", settings.dispatch_min_age_minutes));
    for target in excluded_targets {
        query = query.bind((*target).to_owned());
    }
    let eligible_epoch = query
        .fetch_scalar::<Option<i64>>()
        .await
        .map_err(|error| format!("load earliest pending eligibility: {error}"))?;
    let Some(eligible_epoch) = eligible_epoch else {
        return Ok(None);
    };

    eligible_epoch
        .checked_mul(1000)
        .map(Some)
        .ok_or_else(|| format!("eligible epoch overflow: {eligible_epoch}").into())
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

async fn sync_task_dependencies(
    db: &DurableDb,
    parent_task_id: &str,
    depends_on: &[EnqueueDependency],
) -> Result<(), QueueError> {
    db.query("DELETE FROM queue_dependencies WHERE task_id = ?")
        .bind(parent_task_id.to_owned())
        .execute()
        .await
        .map_err(|error| format!("clear task dependencies for {parent_task_id}: {error}"))?;

    for dependency in depends_on {
        let dep_features = dependency.features_json.raw();
        let dep_version = dependency.version.to_string();
        let dependency_task_id = task_id(
            dependency.crate_name.as_str(),
            dep_version.as_str(),
            dep_features.as_str(),
            dependency.target.as_str(),
            dependency.rustc_version.as_str(),
        );
        if dependency_task_id == parent_task_id {
            return Err(QueueError::Sql(format!(
                "task {parent_task_id} cannot depend on itself"
            )));
        }
        db.query(
            "INSERT INTO queue_dependencies \
             (task_id, depends_on_task_id, dep_crate_name, dep_version, dep_features_json, dep_target, dep_rustc_version) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(task_id, depends_on_task_id) DO NOTHING",
        )
        .bind(parent_task_id.to_owned())
        .bind(dependency_task_id.clone())
        .bind(dependency.crate_name.as_str().to_owned())
        .bind(dep_version.clone())
        .bind(dep_features.clone())
        .bind(dependency.target.as_str().to_owned())
        .bind(dependency.rustc_version.as_str().to_owned())
        .execute()
        .await
        .map_err(|error| format!("insert task dependency for {parent_task_id}: {error}"))?;
        // Requeueing a failed dependency for a waiting parent is a
        // re-request like any other: it revives the row only behind the
        // same backoff window a fresh enqueue would apply, and bumps
        // `attempt` for the same reason resurrection does — a completion
        // report in flight for the failed attempt must not land on the
        // revived one.
        db.query(
            "UPDATE queue \
             SET status = 'pending', \
                 attempt = attempt + 1, \
                 error_msg = '', \
                 request_count = request_count + 1, \
                 not_before = MAX(not_before, datetime('now', '+' || MIN(1 << MIN(dispatch_attempts, 6), 60) || ' minutes')), \
                 updated_at = datetime('now') \
             WHERE task_id = ? AND status IN ('failed', 'partial')",
        )
        .bind(dependency_task_id)
        .execute()
        .await
        .map_err(|error| format!("requeue failed dependency for {parent_task_id}: {error}"))?;
    }

    Ok(())
}

/// Bound params per `published_slice_rows` VALUES row: `target`,
/// `rustc_version`, `generation`, `crate_name`, `version`,
/// `features_json`.
const PUBLISHED_SLICE_ROW_PARAMS: usize = 6;

/// Rows per multi-row insert into `published_slice_rows`: chunked under
/// the bound-parameter ceiling, since a report carries every built node
/// of a `(target, rustc_version)` pair.
const PUBLISHED_SLICE_INSERT_BATCH_SIZE: usize =
    crate::sql_batch::D1_MAX_BOUND_PARAMS / PUBLISHED_SLICE_ROW_PARAMS;

/// Record what one published index slice serves — the semantic identities
/// the index-publish path reports after the slice goes live. The report
/// covers the whole slice, so membership is replaced wholesale: a row an
/// earlier report served that the new slice no longer does must not keep
/// a dependent's gate open. Queue status never enters here — a
/// dependency's presence in the slice is the only release signal the
/// gate knows.
///
/// `DurableDb` exposes no transaction, so the rewrite happens under a
/// fresh generation instead: rows insert alongside the live set, then the
/// single `published_slices` upsert flips `generation` — the commit
/// point, since the gate only reads the live generation. A failed report
/// leaves superseded rows a later report's cleanup pass removes, and
/// never shows a half-written slice.
pub async fn record_published_slice(
    db: &DurableDb,
    target: &str,
    rustc_version: &str,
    rows: &[PublishedSliceRow],
) -> Result<(), QueueError> {
    ensure_schema(db).await?;
    let generation = db
        .query("SELECT generation FROM published_slices WHERE target = ? AND rustc_version = ?")
        .bind(target.to_owned())
        .bind(rustc_version.to_owned())
        .fetch_optional::<GenerationRow>()
        .await
        .map_err(|error| format!("read published slice {target}/{rustc_version}: {error}"))?
        .map_or(1, |row| row.generation + 1);
    for chunk in rows.chunks(PUBLISHED_SLICE_INSERT_BATCH_SIZE) {
        let sql = format!(
            "INSERT INTO published_slice_rows \
             (target, rustc_version, generation, crate_name, version, features_json) \
             VALUES {} ON CONFLICT DO NOTHING",
            crate::sql_batch::values_rows("(?, ?, ?, ?, ?, ?)", chunk.len())
        );
        let mut query = db.query(&sql);
        for row in chunk {
            query = query
                .bind(target.to_owned())
                .bind(rustc_version.to_owned())
                .bind(generation)
                .bind(row.crate_name.as_str().to_owned())
                .bind(row.version.to_string())
                .bind(row.features_json.raw());
        }
        query.execute().await.map_err(|error| {
            format!("record published slice rows {target}/{rustc_version}: {error}")
        })?;
    }
    // The one-statement commit point: the gate joins
    // `published_slice_rows` to the live generation, so before this
    // statement it saw the previous report in full, and after it the new
    // one in full.
    db.query(
        "INSERT INTO published_slices (target, rustc_version, generation) \
         VALUES (?, ?, ?) \
         ON CONFLICT(target, rustc_version) DO UPDATE \
         SET generation = excluded.generation, published_at = datetime('now')",
    )
    .bind(target.to_owned())
    .bind(rustc_version.to_owned())
    .bind(generation)
    .execute()
    .await
    .map_err(|error| format!("publish slice {target}/{rustc_version} generation: {error}"))?;
    // Retire every superseded generation — including one a crashed report
    // left half-inserted before it ever went live.
    db.query(
        "DELETE FROM published_slice_rows \
         WHERE target = ? AND rustc_version = ? AND generation != ?",
    )
    .bind(target.to_owned())
    .bind(rustc_version.to_owned())
    .bind(generation)
    .execute()
    .await
    .map_err(|error| format!("retire stale slice rows {target}/{rustc_version}: {error}"))?;
    Ok(())
}

pub async fn ensure_schema(db: &DurableDb) -> Result<(), QueueError> {
    let columns = db
        .query("PRAGMA table_info(queue)")
        .fetch_all::<QueueTableInfoRow>()
        .await
        .map_err(|error| format!("load queue table_info: {error}"))?
        .into_iter()
        .map(|row| row.name)
        .collect::<BTreeSet<_>>();

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
        if !columns.contains("preserve_lockfile") {
            db.query("ALTER TABLE queue ADD COLUMN preserve_lockfile INTEGER NOT NULL DEFAULT 0")
                .execute()
                .await
                .map_err(|error| format!("add preserve_lockfile column: {error}"))?;
        }
        if !columns.contains("dispatch_attempts") {
            db.query("ALTER TABLE queue ADD COLUMN dispatch_attempts INTEGER NOT NULL DEFAULT 0")
                .execute()
                .await
                .map_err(|error| format!("add dispatch_attempts column: {error}"))?;
        }
        if !columns.contains("attempt") {
            db.query("ALTER TABLE queue ADD COLUMN attempt INTEGER NOT NULL DEFAULT 1")
                .execute()
                .await
                .map_err(|error| format!("add attempt column: {error}"))?;
        }
        if !columns.contains("not_before") {
            db.query(
                "ALTER TABLE queue ADD COLUMN not_before TEXT NOT NULL DEFAULT '1970-01-01 00:00:00'",
            )
            .execute()
            .await
            .map_err(|error| format!("add not_before column: {error}"))?;
        }
        if !columns.contains("lane") {
            db.query(
                "ALTER TABLE queue ADD COLUMN lane TEXT NOT NULL DEFAULT 'miss' \
                 CHECK (lane IN ('miss', 'human'))",
            )
            .execute()
            .await
            .map_err(|error| format!("add lane column: {error}"))?;
        }
        if !columns.contains("github_run_id") {
            db.query("ALTER TABLE queue ADD COLUMN github_run_id TEXT")
                .execute()
                .await
                .map_err(|error| format!("add github_run_id column: {error}"))?;
        }
        // Tables added after the queue schema (github_app_token) land
        // here rather than through the drop-and-recreate path: every
        // statement in schema.sql is IF NOT EXISTS, so re-running it on
        // an existing modern queue only creates what is missing.
        db.query(include_str!("schema.sql"))
            .execute()
            .await
            .map_err(|error| format!("ensure scheduler schema additions: {error}"))?;
        migrate_queue_dependencies_columns(db).await?;
        return Ok(());
    }

    migrate_queue_schema(db).await
}

/// Columns added to `queue_dependencies` after the table first shipped:
/// the dependency's semantic identity, denormalized so the published-slice
/// gate reads it without the dependency's queue row. Rows written before
/// the columns existed backfill from the queue row their
/// `depends_on_task_id` still points at; an edge whose dependency left
/// the queue keeps '' and never satisfies the gate.
async fn migrate_queue_dependencies_columns(db: &DurableDb) -> Result<(), QueueError> {
    let columns = db
        .query("PRAGMA table_info(queue_dependencies)")
        .fetch_all::<QueueTableInfoRow>()
        .await
        .map_err(|error| format!("load queue_dependencies table_info: {error}"))?
        .into_iter()
        .map(|row| row.name)
        .collect::<BTreeSet<_>>();
    if columns.is_empty() || columns.contains("dep_crate_name") {
        return Ok(());
    }
    for column in [
        "dep_crate_name",
        "dep_version",
        "dep_features_json",
        "dep_target",
        "dep_rustc_version",
    ] {
        db.query(&format!(
            "ALTER TABLE queue_dependencies ADD COLUMN {column} TEXT NOT NULL DEFAULT ''"
        ))
        .execute()
        .await
        .map_err(|error| format!("add queue_dependencies.{column} column: {error}"))?;
    }
    db.query(
        "UPDATE queue_dependencies SET \
            dep_crate_name = (SELECT crate_name FROM queue WHERE task_id = queue_dependencies.depends_on_task_id), \
            dep_version = (SELECT version FROM queue WHERE task_id = queue_dependencies.depends_on_task_id), \
            dep_features_json = (SELECT features_json FROM queue WHERE task_id = queue_dependencies.depends_on_task_id), \
            dep_target = (SELECT target FROM queue WHERE task_id = queue_dependencies.depends_on_task_id), \
            dep_rustc_version = (SELECT rustc_version FROM queue WHERE task_id = queue_dependencies.depends_on_task_id) \
         WHERE EXISTS (SELECT 1 FROM queue WHERE task_id = queue_dependencies.depends_on_task_id)",
    )
    .execute()
    .await
    .map_err(|error| format!("backfill queue_dependencies identity columns: {error}"))?;
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
    migrate_queue_dependencies_columns(db).await
}

async fn recover_stale_active_tasks(
    db: &DurableDb,
    settings: &SchedulerSettings,
) -> Result<(), QueueError> {
    db.query(
        "UPDATE queue \
         SET status = 'pending', error_msg = '', updated_at = datetime('now') \
         WHERE status IN ('dispatched', 'running') \
           AND updated_at <= datetime('now', ?)",
    )
    .bind(format!("-{} minutes", settings.stale_dispatch_minutes))
    .execute()
    .await
    .map_err(|error| format!("recover stale active tasks: {error}"))?;
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

/// Canonical scheduler task identity — the same id `enqueue` deduplicates
/// on. Miss responses mint admissions against this id and
/// `POST /api/v1/enqueue` redeems them, so the derivation must stay exactly
/// in step with the queue's own.
pub fn task_id(
    crate_name: &str,
    version: &str,
    features_json: &str,
    target: &str,
    rustc_version: &str,
) -> String {
    let features_hash = blake3::hash(features_json.as_bytes()).to_hex().to_string();
    format!(
        "{}-{}-{}-{}-{}",
        crate_name,
        version,
        features_hash,
        target.replace('-', "_"),
        rustc_version.replace('-', "_")
    )
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

#[derive(Debug, skyzen::FromRow)]
struct GenerationRow {
    generation: i64,
}

/// One `GROUP BY status, lane` aggregate row from [`status`].
#[derive(Debug, skyzen::FromRow)]
struct StatusLaneCountRow {
    status: String,
    lane: String,
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
    preserve_lockfile: i64,
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
    use super::{AlarmInputs, AlarmPlan, plan_alarm, seconds_until_utc_midnight};

    const NOW_MS: i64 = 1_000_000;

    fn inputs() -> AlarmInputs {
        AlarmInputs {
            now_ms: NOW_MS,
            capacity_available: true,
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
            capacity_available: false,
            earliest_pending_eligible_ms: Some(NOW_MS - 60_000),
            earliest_active_lease_expiry_ms: Some(NOW_MS + 300_000),
            ..inputs()
        };
        assert_eq!(plan_alarm(&inputs), AlarmPlan::At(NOW_MS + 300_000));
    }

    #[test]
    fn clamps_past_lease_expiry_to_now_when_capacity_exhausted() {
        let inputs = AlarmInputs {
            capacity_available: false,
            earliest_pending_eligible_ms: Some(NOW_MS - 60_000),
            earliest_active_lease_expiry_ms: Some(NOW_MS - 1),
            ..inputs()
        };
        assert_eq!(plan_alarm(&inputs), AlarmPlan::At(NOW_MS));
    }

    #[test]
    fn wakes_at_lease_expiry_when_only_active_rows_remain() {
        // No pending rows (or all blocked on active dependencies): the alarm
        // still has to fire so a build whose `/complete` callback was lost
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
            capacity_available: false,
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

    use skyzen_services::durable::DurableDb;
    use stow_types::api::{EnqueueDependency, EnqueueRequest, EnqueueSource};
    use stow_types::identity::FeaturesJson;

    use super::{
        AlarmPlan, CoverageOracle, SchedulerSettings, SemanticTaskIdentity, next_alarm, task_id,
    };
    use crate::errors::QueueError;
    use crate::scheduler::test_db::memory_db;

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

    const STALE_DISPATCH_MINUTES: u32 = 60;

    fn stale_ms() -> i64 {
        i64::from(STALE_DISPATCH_MINUTES) * 60_000
    }

    const fn settings() -> SchedulerSettings {
        SchedulerSettings {
            max_concurrent_jobs: 10,
            max_concurrent_macos_jobs: 16,
            dispatch_min_age_minutes: 5,
            stale_dispatch_minutes: STALE_DISPATCH_MINUTES,
            max_queue_pending: 2_000,
            human_daily_task_budget: 2_000,
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
        }
    }

    fn task_id_on(crate_name: &str, target: &str) -> String {
        task_id(crate_name, VERSION, FEATURES, target, RUSTC)
    }

    fn dependency(crate_name: &str) -> EnqueueDependency {
        EnqueueDependency {
            crate_name: crate_name.parse().expect("valid crate name"),
            version: VERSION.parse().expect("valid semver"),
            features_json: FeaturesJson::default(),
            target: TARGET.parse().expect("valid target triple"),
            rustc_version: RUSTC.parse().expect("valid rustc version"),
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
        set_first_requested_at_on(db, crate_name, TARGET, timestamp).await;
    }

    async fn set_first_requested_at_on(
        db: &DurableDb,
        crate_name: &str,
        target: &str,
        timestamp: &str,
    ) {
        db.query("UPDATE queue SET first_requested_at = ? WHERE task_id = ?")
            .bind(timestamp.to_owned())
            .bind(task_id_on(crate_name, target))
            .execute()
            .await
            .expect("set first_requested_at");
    }

    #[tokio::test]
    async fn empty_queue_deletes_alarm() {
        let db = memory_db().await.expect("memory db");
        let plan = next_alarm(&db, ROW_TS_MS, &settings())
            .await
            .expect("next_alarm");
        assert_eq!(plan, AlarmPlan::Delete);
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
            max_concurrent_jobs: 1,
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

    #[tokio::test]
    async fn eligible_pending_with_capacity_wakes_at_eligibility() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("ready", Vec::new())])
            .await
            .expect("enqueue");
        set_first_requested_at(&db, "ready", ROW_TS).await;

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
            max_concurrent_jobs: 1,
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
        set_first_requested_at_on(&db, "mac-waiting", MACOS_TARGET, PAST_TS).await;

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
    async fn panic_flag_round_trips_and_defaults_off() {
        let db = memory_db().await.expect("memory db");
        assert!(
            !super::panic_enabled(&db).await.expect("panic_enabled"),
            "panic flag defaults to off"
        );
        super::set_panic(&db, true).await.expect("set panic on");
        assert!(super::panic_enabled(&db).await.expect("panic_enabled"));
        super::set_panic(&db, false).await.expect("set panic off");
        assert!(!super::panic_enabled(&db).await.expect("panic_enabled"));
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
            &stow_types::api::BuildCompleteReport {
                task_id: claimed[0].task_id.clone(),
                attempt: claimed[0].attempt,
                success: false,
                partial: false,
                error: Some("boom".to_owned()),
                artifacts_uploaded: 0,
                github_run_id: None,
            },
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
            .bind(super::task_id("flaky", VERSION, FEATURES, TARGET, RUSTC))
            .fetch_scalar::<i64>()
            .await
            .expect("read not_before gate");
        assert_eq!(gated, 1);
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
        super::complete(&db, &report(&id, 1, true))
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
        super::complete(&db, &report(&id, 1, false))
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

    /// A dominated task whose dominator already published its closure is
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
            max_concurrent_jobs: 10,
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
        task_id(crate_name, VERSION, FEATURES, TARGET, RUSTC)
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
        let id = task_id("alpha", VERSION, FEATURES, TARGET, RUSTC);
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].attempt, 1);

        super::complete(
            &db,
            &stow_types::api::BuildCompleteReport {
                task_id: id.clone(),
                attempt: claimed[0].attempt,
                success: true,
                partial: false,
                error: None,
                artifacts_uploaded: 3,
                github_run_id: None,
            },
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
            &stow_types::api::BuildCompleteReport {
                task_id: "never-enqueued".to_owned(),
                attempt: 1,
                success: true,
                partial: false,
                error: None,
                artifacts_uploaded: 0,
                github_run_id: None,
            },
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

        super::complete(&db, &report(&id, 1, true))
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

        let error = super::complete(&db, &report(&id, 1, true))
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
        super::complete(&db, &report(&id, 2, true))
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

        super::complete(&db, &report(&id, 1, true))
            .await
            .expect("complete");
        let error = super::complete(&db, &report(&id, 1, true))
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

    /// The third terminal state the `partial` outcome exists for: a
    /// stopped-early build that published the prefix it captured is not a
    /// completion (its own artifact is still missing) and not a plain
    /// failure (the run did not land empty-handed).
    #[tokio::test]
    async fn a_partial_build_is_not_reported_as_a_completed_task() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("alpha", Vec::new())])
            .await
            .expect("enqueue");
        set_first_requested_at(&db, "alpha", PAST_TS).await;
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        let id = claimed[0].task_id.clone();

        let mut partial = report(&id, claimed[0].attempt, false);
        partial.partial = true;
        partial.error = Some("cargo build failed for alpha 1.0.0".to_owned());
        partial.artifacts_uploaded = 2;
        super::complete(&db, &partial).await.expect("complete");

        let status = db
            .query("SELECT status FROM queue WHERE task_id = ?")
            .bind(id)
            .fetch_scalar::<String>()
            .await
            .expect("status");
        assert_eq!(
            status, "partial",
            "a stopped-early build must not land as completed or failed"
        );
        let status = super::status(&db).await.expect("status");
        assert_eq!(status.completed, 0);
        assert_eq!(status.failed, 0);
        assert_eq!(status.partial, 1);
    }

    /// A partial row's own artifact is still missing, so a re-request
    /// resurrects it to pending behind the same backoff a plain failure
    /// applies — it must not be claimable immediately.
    #[tokio::test]
    async fn a_partial_task_resurrects_behind_backoff() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("flaky", Vec::new())])
            .await
            .expect("enqueue");
        set_first_requested_at(&db, "flaky", PAST_TS).await;
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        let mut partial = report(&claimed[0].task_id, claimed[0].attempt, false);
        partial.partial = true;
        super::complete(&db, &partial)
            .await
            .expect("partial complete");

        enqueue(&db, &[request("flaky", Vec::new())])
            .await
            .expect("re-request");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim");
        assert!(claimed.is_empty(), "resurrection is backoff-gated");
        assert_eq!(row_column(&db, "flaky", "status").await, "pending");
    }

    /// `retry`'s domain covers partial rows: the crate's own artifacts
    /// still need a build.
    #[tokio::test]
    async fn retry_returns_partial_rows_to_pending() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("alpha", Vec::new())])
            .await
            .expect("enqueue");
        mark_active(&db, "alpha", TARGET, "partial").await;

        let affected = super::apply_mutation(
            &db,
            super::QueueMutation::Retry,
            &filter_selector(stow_types::api::QueueSelector {
                status: Some(stow_types::api::QueueTaskStatus::Partial),
                ..Default::default()
            }),
        )
        .await
        .expect("retry");
        assert_eq!(affected, 1);
        assert_eq!(row_column(&db, "alpha", "status").await, "pending");
    }

    /// A partial dependency is a dependency whose own artifacts never
    /// landed: requeueing a waiting parent's dep covers it like a
    /// failure.
    #[tokio::test]
    async fn a_partial_dependency_requeues_for_a_waiting_parent() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("dep", Vec::new())])
            .await
            .expect("enqueue dep");
        mark_active(&db, "dep", TARGET, "partial").await;

        enqueue(&db, &[request("parent", vec![dependency("dep")])])
            .await
            .expect("enqueue parent");

        assert_eq!(row_column(&db, "dep", "status").await, "pending");
        let attempt = db
            .query("SELECT attempt FROM queue WHERE task_id = ?")
            .bind(task_id_on("dep", TARGET))
            .fetch_scalar::<i64>()
            .await
            .expect("dep attempt");
        assert_eq!(attempt, 2, "the requeue bumps the dep's live attempt");
    }

    /// Mark one crate's semantic identity served by the `(TARGET, RUSTC)`
    /// slice — the state `stow-admin index report` produces through
    /// `record_published_slice` after `index publish` lands.
    async fn publish(db: &DurableDb, crate_name: &str) {
        super::record_published_slice(
            db,
            TARGET,
            RUSTC,
            &[stow_types::api::PublishedSliceRow {
                crate_name: crate_name.parse().expect("valid crate name"),
                version: VERSION.parse().expect("valid semver"),
                features_json: FeaturesJson::default(),
            }],
        )
        .await
        .expect("record published slice");
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
        super::complete(&db, &report(&claimed[0].task_id, claimed[0].attempt, true))
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
        super::complete(&db, &report(&claimed[0].task_id, claimed[0].attempt, false))
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
        super::complete(&db, &report(&claimed[0].task_id, claimed[0].attempt, false))
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
        super::complete(&db, &report(&claimed[0].task_id, claimed[0].attempt, false))
            .await
            .expect("fail dep");

        // The dependency is retried and this time succeeds — but the
        // dependent still waits for the slice that serves it.
        super::apply_mutation(
            &db,
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
        super::complete(&db, &report(&claimed[0].task_id, claimed[0].attempt, true))
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
        super::record_published_slice(
            &db,
            TARGET,
            RUSTC,
            &[stow_types::api::PublishedSliceRow {
                crate_name: "other".parse().expect("valid crate name"),
                version: VERSION.parse().expect("valid semver"),
                features_json: FeaturesJson::default(),
            }],
        )
        .await
        .expect("republish slice");
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

    /// A real slice is every built node of a `(target, rustc)` pair, so
    /// the report inserts in `VALUES`-row chunks — a slice larger than
    /// one chunk must still record whole, including the partial tail.
    #[tokio::test]
    async fn a_larger_slice_reports_through_every_insert_chunk() {
        let db = memory_db().await.expect("memory db");
        let rows = (0..(super::PUBLISHED_SLICE_INSERT_BATCH_SIZE + 3))
            .map(|index| stow_types::api::PublishedSliceRow {
                crate_name: format!("crate-{index}").parse().expect("valid crate name"),
                version: VERSION.parse().expect("valid semver"),
                features_json: FeaturesJson::default(),
            })
            .collect::<Vec<_>>();
        super::record_published_slice(&db, TARGET, RUSTC, &rows)
            .await
            .expect("record wide slice");

        let last = format!("crate-{}", super::PUBLISHED_SLICE_INSERT_BATCH_SIZE + 2);
        enqueue(&db, &[request("parent", vec![dependency(&last)])])
            .await
            .expect("enqueue parent");
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings(), &NoCoverage)
            .await
            .expect("claim parent");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "parent");
    }

    fn report(task_id: &str, attempt: u32, success: bool) -> stow_types::api::BuildCompleteReport {
        stow_types::api::BuildCompleteReport {
            task_id: task_id.to_owned(),
            attempt,
            success,
            partial: false,
            error: None,
            artifacts_uploaded: 0,
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
        // And so is a trusted (RepoWriter) submit of miss-lane work.
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

    /// The register binding reads `preserve_lockfile` off the status row
    /// to decide whether the task's dependency closure is reproducible from
    /// crates.io — `tasks_status` must surface it, or every record write
    /// against a lockfile task is either blindly accepted or wrongly
    /// rejected.
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
                task_id("plain", VERSION, FEATURES, TARGET, RUSTC),
                task_id("locked", VERSION, FEATURES, TARGET, RUSTC),
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
            super::QueueMutation::Cancel,
            &stow_types::api::QueueSelector::default(),
        )
        .await;
        assert!(matches!(denied, Err(QueueError::EmptySelector)));
        assert_eq!(row_column(&db, "alpha", "status").await, "pending");
    }

    #[tokio::test]
    async fn observe_run_stamps_only_in_flight_rows() {
        let db = memory_db().await.expect("memory db");
        enqueue(
            &db,
            &[request("alpha", Vec::new()), request("beta", Vec::new())],
        )
        .await
        .expect("enqueue");
        mark_active(&db, "alpha", TARGET, "dispatched").await;

        super::observe_run(&db, &task_id_on("alpha", TARGET), "12345")
            .await
            .expect("observe run");
        assert_eq!(row_column(&db, "alpha", "github_run_id").await, "12345");

        // A pending row is not a run — the stamp must not reach it.
        super::observe_run(&db, &task_id_on("beta", TARGET), "99999")
            .await
            .expect("observe pending");
        let status = super::admin_status(&db).await.expect("admin status");
        let beta = status
            .in_flight
            .iter()
            .find(|task| task.crate_name.as_str() == "beta");
        assert!(beta.is_none(), "pending row must not appear in-flight");
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
        super::observe_run(&db, &task_id_on("miss-b", TARGET), "777")
            .await
            .expect("observe run");
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
        assert!(!status.panic_enabled);
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
}
