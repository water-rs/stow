use std::collections::BTreeSet;

use skyzen_services::durable::DurableDb;
use stow_types::api::{
    BuildCompleteReport, EnqueueDependency, EnqueueRequest, EnqueueSource, ProjectSource,
    QueueTaskStatus, RequestStatus, SchedulerStatus, TaskLane,
};
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};

use crate::errors::QueueError;

/// One claimed queue row, ready to dispatch to a build runner.
#[derive(Debug, Clone)]
pub struct QueuedTask {
    pub task_id: String,
    pub crate_name: String,
    pub version: String,
    pub features_json: String,
    pub target: String,
    pub rustc_version: String,
    pub preserve_lockfile: bool,
    /// Deserialized `ProjectSource` for project-source tasks; `None` for
    /// crates.io tarball tasks.
    pub project_source: Option<ProjectSource>,
}

const DEFAULT_MAX_CONCURRENT_JOBS: u32 = 10;
const DEFAULT_DISPATCH_MIN_AGE_MINUTES: u32 = 5;
// A single crate build on GitHub-hosted runners (toolchain install + compile
// + sign + push) can legitimately take tens of minutes and nothing updates
// the row while CI runs, so the stale-recovery cutoff must comfortably
// exceed the slowest expected build or long builds get double-dispatched.
const DEFAULT_STALE_DISPATCH_MINUTES: u32 = 60;
// Exponential dispatch-failure backoff cap.
const MAX_DISPATCH_BACKOFF_MINUTES: u32 = 60;

/// Runtime-tunable scheduler knobs, read from Worker env bindings by the
/// Durable Object glue (`STOW_MAX_CONCURRENT_JOBS`,
/// `STOW_DISPATCH_MIN_AGE_MINUTES`, `STOW_STALE_DISPATCH_MINUTES`).
///
/// Defaults match production; the local mock lowers `max_concurrent_jobs`
/// via `vars` because miniflare's workerd OOMs under parallel register/
/// complete bursts.
#[derive(Debug, Clone, Copy)]
pub struct SchedulerSettings {
    pub max_concurrent_jobs: u32,
    pub dispatch_min_age_minutes: u32,
    pub stale_dispatch_minutes: u32,
}

impl Default for SchedulerSettings {
    fn default() -> Self {
        Self {
            max_concurrent_jobs: DEFAULT_MAX_CONCURRENT_JOBS,
            dispatch_min_age_minutes: DEFAULT_DISPATCH_MIN_AGE_MINUTES,
            stale_dispatch_minutes: DEFAULT_STALE_DISPATCH_MINUTES,
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

/// The queue-identity columns of one enqueue request. `source_json` is the
/// serialized `ProjectSource` — a project-source task never deduplicates
/// against a crates.io tarball task for the same crate, because they build
/// different trees.
struct TaskIdentity {
    crate_name: String,
    version: String,
    features_json: String,
    target: String,
    rustc_version: String,
    source_json: String,
}

/// The canonical storage form of `EnqueueRequest::source`: the serialized
/// struct for a project task, empty string for a crates.io tarball task.
/// Serializing the typed value (rather than echoing request JSON) keeps the
/// column and the `task_id` hash input byte-stable across clients.
pub fn source_json(source: Option<&ProjectSource>) -> Result<String, QueueError> {
    source.map_or_else(
        || Ok(String::new()),
        |source| {
            serde_json::to_string(source)
                .map_err(|error| format!("serialize project source: {error}").into())
        },
    )
}

impl TaskIdentity {
    fn from_request(request: &EnqueueRequest) -> Result<Self, QueueError> {
        // FeaturesJson is already validated + canonicalized at deserialize
        // time; raw() emits the same JSON-encoded string the column expects.
        Ok(Self {
            crate_name: request.crate_name.as_str().to_owned(),
            version: request.version.to_string(),
            features_json: request.features_json.raw(),
            target: request.target.as_str().to_owned(),
            rustc_version: request.rustc_version.as_str().to_owned(),
            source_json: source_json(request.project_source.as_ref())?,
        })
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
         WHERE crate_name = ? AND version = ? AND features_json = ? AND target = ? AND rustc_version = ? AND source_json = ? \
         LIMIT 1",
    )
    .bind(identity.crate_name.clone())
    .bind(identity.version.clone())
    .bind(identity.features_json.clone())
    .bind(identity.target.clone())
    .bind(identity.rustc_version.clone())
    .bind(identity.source_json.clone())
    .fetch_optional::<TaskIdRow>()
    .await
    .map_err(|error| format!("select existing task: {error}").into())
}

/// Apply a re-request to an existing row. `redispatch` resurrects a
/// failed/completed row back to pending — a failed task's resurrection
/// carries the same exponential backoff a dispatch failure would have
/// applied, so spamming a miss cannot resurrect it early.
async fn update_existing_task(
    db: &DurableDb,
    identity: &TaskIdentity,
    redispatch: bool,
    downloads: i64,
    lane: TaskLane,
) -> Result<(), QueueError> {
    // Re-requesting a task never lets it jump the queue: priority is
    // recomputed from downloads/misses only and `first_requested_at` is
    // untouched.
    let update = if redispatch {
        db.query(
            "UPDATE queue \
             SET downloads = CASE WHEN downloads > ? THEN downloads ELSE ? END, \
                 request_count = request_count + 1, \
                 priority = ((CASE WHEN downloads > ? THEN downloads ELSE ? END) / 1000) + \
                            (miss_count * 10), \
                 status = 'pending', \
                 error_msg = '', \
                 not_before = CASE WHEN status = 'failed' \
                     THEN MAX(not_before, datetime('now', '+' || MIN(1 << MIN(dispatch_attempts, 6), 60) || ' minutes')) \
                     ELSE not_before END, \
                 updated_at = datetime('now'), \
                 lane = CASE ? WHEN 'human' THEN 'human' ELSE lane END \
             WHERE crate_name = ? AND version = ? AND features_json = ? AND target = ? AND rustc_version = ? AND source_json = ?",
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
             WHERE crate_name = ? AND version = ? AND features_json = ? AND target = ? AND rustc_version = ? AND source_json = ?",
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
        .bind(identity.source_json.clone())
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
         (task_id, crate_name, version, features_json, target, rustc_version, source_json, downloads, miss_count, request_count, priority, status, preserve_lockfile, lane, first_requested_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 1, ?, 'pending', ?, ?, datetime('now'))",
    )
    .bind(task_id.to_owned())
    .bind(identity.crate_name)
    .bind(identity.version)
    .bind(identity.features_json)
    .bind(identity.target)
    .bind(identity.rustc_version)
    .bind(identity.source_json)
    .bind(downloads)
    .bind(priority)
    .bind(i64::from(preserve_lockfile))
    .bind(lane.as_str())
    .execute()
    .await
    .map_err(|error| format!("insert task: {error}").into())
    .map(|_| ())
}

pub async fn enqueue(db: &DurableDb, requests: &[EnqueueRequest]) -> Result<u32, QueueError> {
    ensure_schema(db).await?;
    let mut inserted = 0u32;

    for request in requests {
        let identity = TaskIdentity::from_request(request)?;
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
            &identity.source_json,
        );
        let downloads = u64_to_i64(request.downloads, "downloads")?;
        let priority = compute_priority(request.downloads, 0)?;
        let lane = request_lane(request.source);

        if let Some(existing) = find_existing_task(db, &identity).await? {
            let redispatch = matches!(existing.status.as_str(), "failed" | "completed");
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
    let status = if report.success {
        "completed"
    } else {
        "failed"
    };

    let result = db
        .query(
            "UPDATE queue \
             SET status = ?, error_msg = ?, updated_at = datetime('now') \
             WHERE task_id = ?",
        )
        .bind(status)
        .bind(report.error.clone().unwrap_or_default())
        .bind(report.task_id.clone())
        .execute()
        .await
        .map_err(|error| format!("complete task: {error}"))?;
    // Swallowing a completion for an unknown task would leave the real work
    // item (if any) stuck in 'dispatched' while CI believes it reported
    // success — fail loudly so the mismatch is visible at the reporter.
    if result.rows_written == 0 {
        return Err(QueueError::UnknownTask(report.task_id.clone()));
    }

    Ok(())
}

pub async fn status(db: &DurableDb) -> Result<SchedulerStatus, QueueError> {
    ensure_schema(db).await?;
    Ok(SchedulerStatus {
        pending: count_by_status(db, "pending").await?,
        human_pending: count_pending_by_lane(db, TaskLane::Human).await?,
        dispatched: count_by_status(db, "dispatched").await?,
        running: count_by_status(db, "running").await?,
        completed: count_by_status(db, "completed").await?,
        failed: count_by_status(db, "failed").await?,
    })
}

/// Point-in-time view of one queue row, for the public
/// `GET /api/v1/requests/{task_id}` endpoint. `None` when the task id is
/// not in the queue.
pub async fn task_status(
    db: &DurableDb,
    task_id: &str,
) -> Result<Option<RequestStatus>, QueueError> {
    ensure_schema(db).await?;
    let row = db
        .query(
            "SELECT task_id, crate_name, version, features_json, target, rustc_version, lane, status, first_requested_at, priority, created_at \
             FROM queue WHERE task_id = ?",
        )
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
/// lookups; skips ids with no queue row.
pub async fn tasks_status(
    db: &DurableDb,
    task_ids: &[String],
) -> Result<Vec<RequestStatus>, QueueError> {
    let mut statuses = Vec::with_capacity(task_ids.len());
    for task_id in task_ids {
        if let Some(status) = task_status(db, task_id).await? {
            statuses.push(status);
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
    })
}

/// 1-based position of a pending human task in dispatch order: the number
/// of pending human rows that sort ahead of it (matching the
/// `claim_dispatchable_tasks` ordering) plus one.
async fn human_lane_position(db: &DurableDb, row: &RequestStatusRow) -> Result<u32, QueueError> {
    let ahead = db
        .query(
            "SELECT count(*) AS count FROM queue \
             WHERE lane = 'human' AND status = 'pending' \
               AND (first_requested_at < ? \
                    OR (first_requested_at = ? AND (priority > ? \
                        OR (priority = ? AND (created_at < ? \
                            OR (created_at = ? AND task_id < ?))))))",
        )
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

/// Dependency-gate predicate shared by dispatch selection and alarm
/// computation: a task is blocked only while a dependency row exists and is
/// still in flight. Failed or missing dependencies do NOT block — the
/// dependency ordering is a cache-locality optimization (dependents reuse
/// freshly-registered dependency artifacts), and a permanently-failed or
/// vanished dependency must never deadlock its dependents, whose own CI
/// build compiles every dependency from source anyway.
const DEPENDENCY_NOT_BLOCKED_SQL: &str = "NOT EXISTS ( \
    SELECT 1 FROM queue_dependencies d \
    JOIN queue dep ON dep.task_id = d.depends_on_task_id \
    WHERE d.task_id = q.task_id \
      AND dep.status IN ('pending', 'dispatched', 'running') \
)";

pub async fn claim_dispatchable_tasks(
    db: &DurableDb,
    settings: &SchedulerSettings,
) -> Result<Vec<QueuedTask>, QueueError> {
    ensure_schema(db).await?;
    recover_stale_active_tasks(db, settings).await?;
    let running = count_active(db).await?;
    let available = settings.max_concurrent_jobs.saturating_sub(running);
    tracing::info!(
        running,
        available,
        ?settings,
        "scheduler claim_dispatchable_tasks capacity"
    );
    if available == 0 {
        return Ok(Vec::new());
    }

    // Human-lane rows jump ahead of everything the miss path queued and are
    // exempt from the dispatch minimum age; within a lane the order stays
    // FIFO by first_requested_at with the existing tie breakers.
    let sql = format!(
        "SELECT q.task_id, q.crate_name, q.version, q.features_json, q.target, q.rustc_version, q.preserve_lockfile, q.source_json, q.dispatch_attempts \
         FROM queue q \
         WHERE q.status = 'pending' \
           AND (q.lane = 'human' OR q.first_requested_at <= datetime('now', ?)) \
           AND q.not_before <= datetime('now') \
           AND {DEPENDENCY_NOT_BLOCKED_SQL} \
         ORDER BY CASE q.lane WHEN 'human' THEN 0 ELSE 1 END, \
                  q.first_requested_at ASC, q.priority DESC, q.created_at ASC, q.task_id ASC \
         LIMIT ?"
    );
    let rows = db
        .query(&sql)
        .bind(dispatch_cutoff_modifier(settings.dispatch_min_age_minutes))
        .bind(i64::from(available))
        .fetch_all::<TaskRow>()
        .await
        .map_err(|error| format!("select dispatchable tasks: {error}"))?;
    tracing::info!(
        selected = rows.len(),
        "scheduler claim_dispatchable_tasks selected rows"
    );

    let mut claimed = Vec::with_capacity(rows.len());
    for row in rows {
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

        let project_source = if row.source_json.is_empty() {
            None
        } else {
            Some(
                serde_json::from_str::<ProjectSource>(&row.source_json).map_err(|error| {
                    QueueError::Invariant(format!("stored source_json: {error}"))
                })?,
            )
        };
        claimed.push(QueuedTask {
            task_id: row.task_id,
            crate_name: row.crate_name,
            version: row.version,
            features_json: row.features_json,
            target: row.target,
            rustc_version: row.rustc_version,
            preserve_lockfile: row.preserve_lockfile != 0,
            project_source,
        });
    }

    Ok(claimed)
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
/// GitHub `expires_at` RFC 3339 format and SQLite datetime strings
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

/// What the Durable Object should do with its alarm after a dispatch pass.
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
    /// `count_active < max_concurrent_jobs` — a dispatch slot is free.
    pub capacity_available: bool,
    /// Earliest moment any unblocked pending row becomes dispatchable.
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
    let inputs = AlarmInputs {
        now_ms,
        capacity_available: count_active(db).await? < settings.max_concurrent_jobs,
        earliest_pending_eligible_ms: earliest_pending_eligible_ms(db, settings).await?,
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

/// Earliest epoch-ms at which any unblocked pending row becomes dispatchable.
/// Per-row eligibility is the later of `first_requested_at + min age` and the
/// failure-backoff gate; the result is the earliest such moment among
/// unblocked pending tasks. May be in the past (already eligible).
async fn earliest_pending_eligible_ms(
    db: &DurableDb,
    settings: &SchedulerSettings,
) -> Result<Option<i64>, QueueError> {
    // A pending human task is eligible now: the minimum-age gate applies
    // only to the miss lane, while `not_before` (dispatch-failure backoff)
    // still applies to both lanes.
    let sql = format!(
        "SELECT CAST(strftime('%s', MIN(CASE WHEN q.lane = 'human' \
             THEN MAX(q.not_before, datetime('now')) \
             ELSE MAX(datetime(q.first_requested_at, ?), q.not_before) END)) AS INTEGER) AS eligible_epoch \
         FROM queue q \
         WHERE q.status = 'pending' \
           AND {DEPENDENCY_NOT_BLOCKED_SQL}"
    );
    let eligible_epoch = db
        .query(&sql)
        .bind(format!("+{} minutes", settings.dispatch_min_age_minutes))
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
            // Dependency edges always name crates.io tarball tasks; a
            // project source never appears in `depends_on`.
            "",
        );
        if dependency_task_id == parent_task_id {
            return Err(QueueError::Sql(format!(
                "task {parent_task_id} cannot depend on itself"
            )));
        }
        db.query(
            "INSERT INTO queue_dependencies (task_id, depends_on_task_id) VALUES (?, ?) \
             ON CONFLICT(task_id, depends_on_task_id) DO NOTHING",
        )
        .bind(parent_task_id.to_owned())
        .bind(dependency_task_id.clone())
        .execute()
        .await
        .map_err(|error| format!("insert task dependency for {parent_task_id}: {error}"))?;
        // Requeueing a failed dependency for a waiting parent is a
        // re-request like any other: it revives the row only behind the
        // same backoff window a fresh enqueue would apply.
        db.query(
            "UPDATE queue \
             SET status = 'pending', \
                 error_msg = '', \
                 request_count = request_count + 1, \
                 not_before = MAX(not_before, datetime('now', '+' || MIN(1 << MIN(dispatch_attempts, 6), 60) || ' minutes')), \
                 updated_at = datetime('now') \
             WHERE task_id = ? AND status = 'failed'",
        )
        .bind(dependency_task_id)
        .execute()
        .await
        .map_err(|error| format!("requeue failed dependency for {parent_task_id}: {error}"))?;
    }

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
        && columns.contains("source_json")
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
        // Tables added after the queue schema (github_app_token) land
        // here rather than through the drop-and-recreate path: every
        // statement in schema.sql is IF NOT EXISTS, so re-running it on
        // an existing modern queue only creates what is missing.
        db.query(include_str!("schema.sql"))
            .execute()
            .await
            .map_err(|error| format!("ensure scheduler schema additions: {error}"))?;
        return Ok(());
    }

    migrate_queue_schema(db).await
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

async fn count_active(db: &DurableDb) -> Result<u32, QueueError> {
    let count = db
        .query("SELECT count(*) AS count FROM queue WHERE status IN ('dispatched', 'running')")
        .fetch_scalar::<u64>()
        .await
        .map_err(|error| format!("count active tasks: {error}"))?;
    u64_to_u32(count, "active task count")
}

async fn count_by_status(db: &DurableDb, status: &str) -> Result<u32, QueueError> {
    let count = db
        .query("SELECT count(*) AS count FROM queue WHERE status = ?")
        .bind(status.to_owned())
        .fetch_scalar::<u64>()
        .await
        .map_err(|error| format!("count tasks by status '{status}': {error}"))?;
    u64_to_u32(count, "task count")
}

async fn count_pending_by_lane(db: &DurableDb, lane: TaskLane) -> Result<u32, QueueError> {
    let count = db
        .query("SELECT count(*) AS count FROM queue WHERE status = 'pending' AND lane = ?")
        .bind(lane.as_str().to_owned())
        .fetch_scalar::<u64>()
        .await
        .map_err(|error| format!("count pending tasks in lane '{}': {error}", lane.as_str()))?;
    u64_to_u32(count, "pending task count")
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
    source_json: &str,
) -> String {
    // The project source is part of task identity: a tarball task and a
    // checkout task for the same crate/version/features build different
    // trees and must never share a task row. Appending it keeps crate-task
    // ids byte-identical to what they were before the field existed.
    let features_hash = blake3::hash(format!("{features_json}{source_json}").as_bytes())
        .to_hex()
        .to_string();
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
struct TaskRow {
    task_id: String,
    crate_name: String,
    version: String,
    features_json: String,
    target: String,
    rustc_version: String,
    preserve_lockfile: i64,
    source_json: String,
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
    first_requested_at: String,
    priority: i64,
    created_at: String,
}

/// One `PRAGMA table_info` row — only the column name matters.
#[derive(Debug, skyzen::FromRow)]
struct QueueTableInfoRow {
    name: String,
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
    use super::{AlarmInputs, AlarmPlan, plan_alarm};

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

/// SQL-level tests: drive `next_alarm` against a real in-memory SQLite so a
/// wrong column, `status IN` list, or datetime-modifier sign in the queue
/// queries fails the test instead of compiling past the pure `plan_alarm`
/// suite.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod sqlite_tests {
    use skyzen_services::durable::DurableDb;
    use stow_types::api::{EnqueueDependency, EnqueueRequest, EnqueueSource};
    use stow_types::identity::FeaturesJson;

    use super::{AlarmPlan, SchedulerSettings, enqueue, next_alarm, task_id};
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
    const RUSTC: &str = "1.85.0";

    const STALE_DISPATCH_MINUTES: u32 = 60;

    fn stale_ms() -> i64 {
        i64::from(STALE_DISPATCH_MINUTES) * 60_000
    }

    const fn settings() -> SchedulerSettings {
        SchedulerSettings {
            max_concurrent_jobs: 10,
            dispatch_min_age_minutes: 5,
            stale_dispatch_minutes: STALE_DISPATCH_MINUTES,
        }
    }

    fn request(crate_name: &str, depends_on: Vec<EnqueueDependency>) -> EnqueueRequest {
        EnqueueRequest {
            crate_name: crate_name.parse().expect("valid crate name"),
            version: VERSION.parse().expect("valid semver"),
            features_json: FeaturesJson::default(),
            target: TARGET.parse().expect("valid target triple"),
            rustc_version: RUSTC.parse().expect("valid rustc version"),
            downloads: 0,
            source: EnqueueSource::CacheMiss,
            depends_on,
            preserve_lockfile: false,
            project_source: None,
        }
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
    async fn mark_active(db: &DurableDb, crate_name: &str, status: &str) {
        db.query("UPDATE queue SET status = ?, updated_at = ? WHERE task_id = ?")
            .bind(status.to_owned())
            .bind(ROW_TS.to_owned())
            .bind(task_id(crate_name, VERSION, FEATURES, TARGET, RUSTC, ""))
            .execute()
            .await
            .expect("mark task active");
    }

    /// `enqueue` always stamps `first_requested_at = datetime('now')`; tests
    /// that assert exact eligibility timestamps need a deterministic value.
    async fn set_first_requested_at(db: &DurableDb, crate_name: &str, timestamp: &str) {
        db.query("UPDATE queue SET first_requested_at = ? WHERE task_id = ?")
            .bind(timestamp.to_owned())
            .bind(task_id(crate_name, VERSION, FEATURES, TARGET, RUSTC, ""))
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
        mark_active(&db, "alpha", "running").await;

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
        mark_active(&db, "dep", "dispatched").await;

        let plan = next_alarm(&db, ROW_TS_MS, &settings())
            .await
            .expect("next_alarm");
        // The pending row must be filtered out by the dependency-block
        // predicate; a wrong `dep.status IN (...)` list would surface it as
        // eligible and produce a real-time (not `ROW_TS`-derived) alarm.
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
        mark_active(&db, "busy", "dispatched").await;
        set_first_requested_at(&db, "waiting", PAST_TS).await;

        let settings = SchedulerSettings {
            max_concurrent_jobs: 1,
            dispatch_min_age_minutes: 0,
            stale_dispatch_minutes: STALE_DISPATCH_MINUTES,
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
            stale_dispatch_minutes: STALE_DISPATCH_MINUTES,
        }
    }

    /// Overwrite the cached token's `expires_at` with a `datetime()`
    /// modifier evaluated by SQLite itself — the value under test is
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

        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings())
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
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings())
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].crate_name, "old");
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

    #[tokio::test]
    async fn failed_task_re_request_respects_backoff_window() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("flaky", Vec::new())])
            .await
            .expect("enqueue");
        set_first_requested_at(&db, "flaky", PAST_TS).await;

        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings())
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1);
        super::complete(
            &db,
            &stow_types::api::BuildCompleteReport {
                task_id: claimed[0].task_id.clone(),
                success: false,
                error: Some("boom".to_owned()),
                artifacts_uploaded: 0,
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
        let claimed = super::claim_dispatchable_tasks(&db, &claim_settings())
            .await
            .expect("claim");
        assert!(claimed.is_empty());

        let gated = db
            .query(
                "SELECT CASE WHEN not_before > datetime('now') THEN 1 ELSE 0 END AS gated \
                 FROM queue WHERE task_id = ?",
            )
            .bind(super::task_id(
                "flaky", VERSION, FEATURES, TARGET, RUSTC, "",
            ))
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

    fn crate_task_id(crate_name: &str) -> String {
        task_id(crate_name, VERSION, FEATURES, TARGET, RUSTC, "")
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

        let claimed = super::claim_dispatchable_tasks(&db, &settings())
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
        let claimed = super::claim_dispatchable_tasks(&db, &settings)
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
        let claimed = super::claim_dispatchable_tasks(&db, &settings())
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

    #[tokio::test]
    async fn complete_marks_a_held_task_and_rejects_an_unknown_one() {
        let db = memory_db().await.expect("memory db");
        enqueue(&db, &[request("alpha", Vec::new())])
            .await
            .expect("enqueue");
        let id = task_id("alpha", VERSION, FEATURES, TARGET, RUSTC, "");

        super::complete(
            &db,
            &stow_types::api::BuildCompleteReport {
                task_id: id.clone(),
                success: true,
                error: None,
                artifacts_uploaded: 3,
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
                success: true,
                error: None,
                artifacts_uploaded: 0,
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
}
