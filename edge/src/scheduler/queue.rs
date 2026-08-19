use std::collections::BTreeSet;

use serde::Deserialize;
use skyzen_services::durable::DurableDb;
use stow_types::api::{BuildCompleteReport, EnqueueDependency, EnqueueRequest, SchedulerStatus};

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

fn compute_priority(downloads: u64, miss_count: u32, request_count: u32) -> Result<i64, QueueError> {
    let downloads_bucket = downloads / 1000;
    let downloads_bucket = i64::try_from(downloads_bucket)
        .map_err(|_| format!("downloads bucket exceeds i64: {downloads_bucket}"))?;
    Ok(i64::from(request_count) * 1000 + downloads_bucket + i64::from(miss_count) * 10)
}

pub async fn enqueue(db: &DurableDb, requests: &[EnqueueRequest]) -> Result<u32, QueueError> {
    ensure_schema(db).await?;
    let mut inserted = 0u32;

    for request in requests {
        // FeaturesJson is already validated + canonicalized at deserialize time;
        // raw() emits the same JSON-encoded string the column expects.
        let features_json = request.features_json.raw();
        let crate_name = request.crate_name.as_str().to_owned();
        let version_string = request.version.to_string();
        let target = request.target.as_str().to_owned();
        let rustc_version = request.rustc_version.as_str().to_owned();
        let task_id = task_id(
            &crate_name,
            &version_string,
            features_json.as_str(),
            &target,
            &rustc_version,
        );
        let downloads = u64_to_i64(request.downloads, "downloads")?;
        let priority = compute_priority(request.downloads, 0, 1)?;

        let existing = db
            .query(
                "SELECT task_id, status FROM queue \
                 WHERE crate_name = ? AND version = ? AND features_json = ? AND target = ? AND rustc_version = ? \
                 LIMIT 1",
            )
            .bind(crate_name.clone())
            .bind(version_string.clone())
            .bind(features_json.clone())
            .bind(target.clone())
            .bind(rustc_version.clone())
            .fetch_optional::<TaskIdRow>()
            .await
            .map_err(|error| format!("select existing task: {error}"))?;

        if let Some(existing) = existing {
            let redispatch = matches!(existing.status.as_str(), "failed" | "completed");
            let update = if redispatch {
                db.query(
                    "UPDATE queue \
                     SET downloads = CASE WHEN downloads > ? THEN downloads ELSE ? END, \
                         request_count = request_count + 1, \
                         priority = ((request_count + 1) * 1000) + \
                                    ((CASE WHEN downloads > ? THEN downloads ELSE ? END) / 1000) + \
                                    (miss_count * 10), \
                         status = 'pending', \
                         error_msg = '', \
                         updated_at = datetime('now') \
                     WHERE crate_name = ? AND version = ? AND features_json = ? AND target = ? AND rustc_version = ?",
                )
            } else {
                db.query(
                    "UPDATE queue \
                     SET downloads = CASE WHEN downloads > ? THEN downloads ELSE ? END, \
                         request_count = request_count + 1, \
                         priority = ((request_count + 1) * 1000) + \
                                    ((CASE WHEN downloads > ? THEN downloads ELSE ? END) / 1000) + \
                                    (miss_count * 10), \
                         updated_at = datetime('now') \
                     WHERE crate_name = ? AND version = ? AND features_json = ? AND target = ? AND rustc_version = ?",
                )
            };
            update
                .bind(downloads)
                .bind(downloads)
                .bind(downloads)
                .bind(downloads)
                .bind(crate_name.clone())
                .bind(version_string.clone())
                .bind(features_json)
                .bind(target.clone())
                .bind(rustc_version.clone())
                .execute()
                .await
                .map_err(|error| format!("update existing task: {error}"))?;
            // A re-request without dependency info (exact/semantic miss paths
            // always send an empty list) must not erase ordering edges that a
            // graph-analysis enqueue already established.
            if !request.depends_on.is_empty() {
                sync_task_dependencies(db, &existing.task_id, &request.depends_on).await?;
            }
        } else {
            db.query(
                "INSERT INTO queue \
                 (task_id, crate_name, version, features_json, target, rustc_version, downloads, miss_count, request_count, priority, status, preserve_lockfile, first_requested_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, 0, 1, ?, 'pending', ?, datetime('now'))",
            )
            .bind(task_id.clone())
            .bind(crate_name)
            .bind(version_string)
            .bind(features_json)
            .bind(target)
            .bind(rustc_version)
            .bind(downloads)
            .bind(priority)
            .bind(i64::from(request.preserve_lockfile))
            .execute()
            .await
            .map_err(|error| format!("insert task: {error}"))?;

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
        dispatched: count_by_status(db, "dispatched").await?,
        running: count_by_status(db, "running").await?,
        completed: count_by_status(db, "completed").await?,
        failed: count_by_status(db, "failed").await?,
    })
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

    let sql = format!(
        "SELECT q.task_id, q.crate_name, q.version, q.features_json, q.target, q.rustc_version, q.preserve_lockfile, q.dispatch_attempts \
         FROM queue q \
         WHERE q.status = 'pending' AND q.first_requested_at <= datetime('now', ?) \
           AND q.not_before <= datetime('now') \
           AND {DEPENDENCY_NOT_BLOCKED_SQL} \
         ORDER BY q.request_count DESC, q.priority DESC, q.first_requested_at ASC, q.updated_at ASC, q.created_at ASC \
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

        claimed.push(QueuedTask {
            task_id: row.task_id,
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

pub async fn mark_dispatch_failed(
    db: &DurableDb,
    task_id: &str,
    error: &str,
) -> Result<(), QueueError> {
    ensure_schema(db).await?;
    // Exponential backoff keyed on dispatch_attempts (incremented at claim
    // time): a persistent dispatch failure (GitHub outage, bad token) must
    // not spin the alarm in a zero-delay retry loop.
    let row = db
        .query("SELECT dispatch_attempts FROM queue WHERE task_id = ?")
        .bind(task_id.to_owned())
        .fetch_optional::<DispatchAttemptsRow>()
        .await
        .map_err(|db_error| format!("load dispatch attempts for {task_id}: {db_error}"))?
        .ok_or_else(|| QueueError::UnknownTask(task_id.to_owned()))?;
    let backoff_minutes = dispatch_backoff_minutes(row.dispatch_attempts);
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

pub async fn has_pending_work(db: &DurableDb) -> Result<bool, QueueError> {
    ensure_schema(db).await?;
    Ok(count_by_status(db, "pending").await? > 0)
}

pub async fn next_dispatch_eligible_alarm_ms(
    db: &DurableDb,
    now_ms: i64,
    settings: &SchedulerSettings,
) -> Result<Option<i64>, QueueError> {
    ensure_schema(db).await?;
    // Per-row eligibility is the later of (first_requested + min age) and the
    // failure-backoff gate; the next alarm is the earliest such moment among
    // unblocked pending tasks.
    let sql = format!(
        "SELECT CAST(strftime('%s', MIN(MAX(datetime(q.first_requested_at, ?), q.not_before))) AS INTEGER) AS eligible_epoch \
         FROM queue q \
         WHERE q.status = 'pending' \
           AND {DEPENDENCY_NOT_BLOCKED_SQL}"
    );
    let row = db
        .query(&sql)
        .bind(format!("+{} minutes", settings.dispatch_min_age_minutes))
        .fetch_one::<PendingEligibleRow>()
        .await
        .map_err(|error| format!("load earliest pending eligibility: {error}"))?;
    let Some(eligible_epoch) = row.eligible_epoch else {
        return Ok(None);
    };

    let eligible_ms = eligible_epoch
        .checked_mul(1000)
        .ok_or_else(|| format!("eligible epoch overflow: {eligible_epoch}"))?;
    Ok(Some(eligible_ms.max(now_ms)))
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
            "INSERT INTO queue_dependencies (task_id, depends_on_task_id) VALUES (?, ?) \
             ON CONFLICT(task_id, depends_on_task_id) DO NOTHING",
        )
        .bind(parent_task_id.to_owned())
        .bind(dependency_task_id.clone())
        .execute()
        .await
        .map_err(|error| format!("insert task dependency for {parent_task_id}: {error}"))?;
        db.query(
            "UPDATE queue \
             SET status = 'pending', \
                 error_msg = '', \
                 request_count = request_count + 1, \
                 priority = ((request_count + 1) * 1000) + (downloads / 1000) + (miss_count * 10), \
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

async fn ensure_schema(db: &DurableDb) -> Result<(), QueueError> {
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
    let row = db
        .query("SELECT count(*) AS count FROM queue WHERE status IN ('dispatched', 'running')")
        .fetch_one::<CountRow>()
        .await
        .map_err(|error| format!("count active tasks: {error}"))?;
    u64_to_u32(row.count, "active task count")
}

async fn count_by_status(db: &DurableDb, status: &str) -> Result<u32, QueueError> {
    let row = db
        .query("SELECT count(*) AS count FROM queue WHERE status = ?")
        .bind(status.to_owned())
        .fetch_one::<CountRow>()
        .await
        .map_err(|error| format!("count tasks by status '{status}': {error}"))?;
    u64_to_u32(row.count, "task count")
}

fn task_id(
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

#[derive(Debug, Deserialize)]
struct TaskIdRow {
    task_id: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct TaskRow {
    task_id: String,
    crate_name: String,
    version: String,
    features_json: String,
    target: String,
    rustc_version: String,
    #[serde(default)]
    preserve_lockfile: i64,
}

#[derive(Debug, Deserialize)]
struct DispatchAttemptsRow {
    dispatch_attempts: u32,
}

#[derive(Debug, Deserialize)]
struct CountRow {
    count: u64,
}

#[derive(Debug, Deserialize)]
struct QueueTableInfoRow {
    name: String,
}

#[derive(Debug, Deserialize)]
struct PendingEligibleRow {
    eligible_epoch: Option<i64>,
}
