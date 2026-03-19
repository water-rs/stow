use std::collections::BTreeSet;

use serde::Deserialize;
use skyzen_services::durable::DurableDb;
use stow_types::api::{BuildCompleteReport, EnqueueDependency, EnqueueRequest, SchedulerStatus};

use crate::scheduler::dispatch::QueuedTask;

const MAX_CONCURRENT_JOBS: u32 = 10;
const DISPATCH_MIN_AGE_MINUTES: u32 = 5;

fn compute_priority(downloads: u64, miss_count: u32, request_count: u32) -> Result<i64, String> {
    let downloads_bucket = downloads / 1000;
    let downloads_bucket = i64::try_from(downloads_bucket)
        .map_err(|_| format!("downloads bucket exceeds i64: {downloads_bucket}"))?;
    Ok(i64::from(request_count) * 1000 + downloads_bucket + i64::from(miss_count) * 10)
}

pub async fn enqueue(db: &DurableDb, requests: &[EnqueueRequest]) -> Result<u32, String> {
    ensure_schema(db).await?;
    let mut inserted = 0u32;

    for request in requests {
        let features_json = normalize_features_json(&request.features_json)?;
        let task_id = task_id(
            request.crate_name.as_str(),
            request.version.as_str(),
            features_json.as_str(),
            request.target.as_str(),
        );
        let downloads = u64_to_i64(request.downloads, "downloads")?;
        let priority = compute_priority(request.downloads, 0, 1)?;

        let existing = db
            .query(
                "SELECT task_id FROM queue \
                 WHERE crate_name = ? AND version = ? AND features_json = ? AND target = ? \
                 LIMIT 1",
            )
            .bind(request.crate_name.clone())
            .bind(request.version.clone())
            .bind(features_json.clone())
            .bind(request.target.clone())
            .fetch_optional::<TaskIdRow>()
            .await
            .map_err(|error| format!("select existing task: {error}"))?;

        if existing.is_some() {
            db.query(
                "UPDATE queue \
                 SET downloads = CASE WHEN downloads > ? THEN downloads ELSE ? END, \
                     request_count = request_count + 1, \
                     priority = ((request_count + 1) * 1000) + \
                                ((CASE WHEN downloads > ? THEN downloads ELSE ? END) / 1000) + \
                                (miss_count * 10), \
                     updated_at = datetime('now') \
                 WHERE crate_name = ? AND version = ? AND features_json = ? AND target = ?",
            )
            .bind(downloads)
            .bind(downloads)
            .bind(downloads)
            .bind(downloads)
            .bind(request.crate_name.clone())
            .bind(request.version.clone())
            .bind(features_json)
            .bind(request.target.clone())
            .execute()
            .await
            .map_err(|error| format!("update existing task: {error}"))?;
        } else {
            db.query(
                "INSERT INTO queue \
                 (task_id, crate_name, version, features_json, target, downloads, miss_count, request_count, priority, status, first_requested_at) \
                 VALUES (?, ?, ?, ?, ?, ?, 0, 1, ?, 'pending', datetime('now'))",
            )
            .bind(task_id.clone())
            .bind(request.crate_name.clone())
            .bind(request.version.clone())
            .bind(features_json)
            .bind(request.target.clone())
            .bind(downloads)
            .bind(priority)
            .execute()
            .await
            .map_err(|error| format!("insert task: {error}"))?;

            inserted += 1;
        }
        sync_task_dependencies(db, &task_id, &request.depends_on).await?;
    }

    Ok(inserted)
}

pub async fn boost(db: &DurableDb, boost: &stow_types::api::MissBoost) -> Result<(), String> {
    ensure_schema(db).await?;
    db.query(
        "UPDATE queue \
         SET miss_count = miss_count + 1, \
             priority = (request_count * 1000) + (downloads / 1000) + ((miss_count + 1) * 10), \
             updated_at = datetime('now') \
         WHERE crate_name = ? AND target = ? AND status IN ('pending', 'dispatched', 'running')",
    )
    .bind(boost.crate_name.clone())
    .bind(boost.target.clone())
    .execute()
    .await
    .map_err(|error| format!("boost task: {error}"))?;

    Ok(())
}

pub async fn complete(db: &DurableDb, report: &BuildCompleteReport) -> Result<(), String> {
    ensure_schema(db).await?;
    let status = if report.success {
        "completed"
    } else {
        "failed"
    };

    db.query(
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

    Ok(())
}

pub async fn status(db: &DurableDb) -> Result<SchedulerStatus, String> {
    ensure_schema(db).await?;
    Ok(SchedulerStatus {
        pending: count_by_status(db, "pending").await?,
        dispatched: count_by_status(db, "dispatched").await?,
        running: count_by_status(db, "running").await?,
        completed: count_by_status(db, "completed").await?,
        failed: count_by_status(db, "failed").await?,
    })
}

pub async fn claim_dispatchable_tasks(db: &DurableDb) -> Result<Vec<QueuedTask>, String> {
    ensure_schema(db).await?;
    let running = count_active(db).await?;
    let available = MAX_CONCURRENT_JOBS.saturating_sub(running);
    if available == 0 {
        return Ok(Vec::new());
    }

    let rows = db
        .query(
            "SELECT q.task_id, q.crate_name, q.version, q.features_json, q.target \
             FROM queue q \
             WHERE q.status = 'pending' AND q.first_requested_at <= datetime('now', ?) \
               AND NOT EXISTS ( \
                   SELECT 1 FROM queue_dependencies d \
                   LEFT JOIN queue dep ON dep.task_id = d.depends_on_task_id \
                   WHERE d.task_id = q.task_id \
                     AND (dep.task_id IS NULL OR dep.status != 'completed') \
               ) \
             ORDER BY q.request_count DESC, q.priority DESC, q.first_requested_at ASC, q.updated_at ASC, q.created_at ASC \
             LIMIT ?",
        )
        .bind(dispatch_cutoff_modifier())
        .bind(i64::from(available))
        .fetch_all::<TaskRow>()
        .await
        .map_err(|error| format!("select dispatchable tasks: {error}"))?;

    let mut claimed = Vec::with_capacity(rows.len());
    for row in rows {
        db.query(
            "UPDATE queue \
             SET status = 'dispatched', updated_at = datetime('now') \
             WHERE task_id = ? AND status = 'pending'",
        )
        .bind(row.task_id.clone())
        .execute()
        .await
        .map_err(|error| format!("claim task {}: {error}", row.task_id))?;

        claimed.push(QueuedTask {
            task_id: row.task_id,
            crate_name: row.crate_name,
            version: row.version,
            features_json: row.features_json,
            target: row.target,
        });
    }

    Ok(claimed)
}

pub async fn mark_dispatch_failed(
    db: &DurableDb,
    task_id: &str,
    error: &str,
) -> Result<(), String> {
    ensure_schema(db).await?;
    db.query(
        "UPDATE queue \
         SET status = 'pending', error_msg = ?, updated_at = datetime('now') \
         WHERE task_id = ?",
    )
    .bind(error.to_owned())
    .bind(task_id.to_owned())
    .execute()
    .await
    .map_err(|db_error| format!("mark dispatch failed: {db_error}"))?;

    Ok(())
}

pub async fn has_pending_work(db: &DurableDb) -> Result<bool, String> {
    ensure_schema(db).await?;
    Ok(count_by_status(db, "pending").await? > 0)
}

pub async fn next_dispatch_eligible_alarm_ms(
    db: &DurableDb,
    now_ms: i64,
) -> Result<Option<i64>, String> {
    ensure_schema(db).await?;
    let row = db
        .query(
            "SELECT CAST(strftime('%s', min(q.first_requested_at)) AS INTEGER) AS first_requested_epoch \
             FROM queue q \
             WHERE q.status = 'pending' \
               AND NOT EXISTS ( \
                   SELECT 1 FROM queue_dependencies d \
                   LEFT JOIN queue dep ON dep.task_id = d.depends_on_task_id \
                   WHERE d.task_id = q.task_id \
                     AND (dep.task_id IS NULL OR dep.status != 'completed') \
               )",
        )
        .fetch_one::<PendingFirstSeenRow>()
        .await
        .map_err(|error| format!("load earliest pending first_requested_at: {error}"))?;
    let Some(first_requested_epoch) = row.first_requested_epoch else {
        return Ok(None);
    };

    let min_age_ms = i64::from(DISPATCH_MIN_AGE_MINUTES) * 60 * 1000;
    let first_requested_ms = first_requested_epoch
        .checked_mul(1000)
        .ok_or_else(|| format!("first requested epoch overflow: {first_requested_epoch}"))?;
    let eligible_ms = first_requested_ms.checked_add(min_age_ms).ok_or_else(|| {
        format!("dispatch age overflow for first requested epoch: {first_requested_epoch}")
    })?;
    Ok(Some(eligible_ms.max(now_ms)))
}

async fn sync_task_dependencies(
    db: &DurableDb,
    parent_task_id: &str,
    depends_on: &[EnqueueDependency],
) -> Result<(), String> {
    db.query("DELETE FROM queue_dependencies WHERE task_id = ?")
        .bind(parent_task_id.to_owned())
        .execute()
        .await
        .map_err(|error| format!("clear task dependencies for {parent_task_id}: {error}"))?;

    for dependency in depends_on {
        let dep_features = normalize_features_json(&dependency.features_json)?;
        let dependency_task_id = task_id(
            dependency.crate_name.as_str(),
            dependency.version.as_str(),
            dep_features.as_str(),
            dependency.target.as_str(),
        );
        if dependency_task_id == parent_task_id {
            return Err(format!("task {parent_task_id} cannot depend on itself"));
        }
        db.query(
            "INSERT INTO queue_dependencies (task_id, depends_on_task_id) VALUES (?, ?) \
             ON CONFLICT(task_id, depends_on_task_id) DO NOTHING",
        )
        .bind(parent_task_id.to_owned())
        .bind(dependency_task_id)
        .execute()
        .await
        .map_err(|error| format!("insert task dependency for {parent_task_id}: {error}"))?;
    }

    Ok(())
}

async fn ensure_schema(db: &DurableDb) -> Result<(), String> {
    db.query(include_str!("schema.sql"))
        .execute()
        .await
        .map_err(|error| format!("ensure scheduler schema: {error}"))?;
    migrate_queue_schema(db).await?;
    Ok(())
}

async fn migrate_queue_schema(db: &DurableDb) -> Result<(), String> {
    let columns = db
        .query("PRAGMA table_info(queue)")
        .fetch_all::<QueueTableInfoRow>()
        .await
        .map_err(|error| format!("load queue table_info: {error}"))?
        .into_iter()
        .map(|row| row.name)
        .collect::<BTreeSet<_>>();
    if columns.contains("features_json")
        && columns.contains("request_count")
        && columns.contains("first_requested_at")
    {
        return Ok(());
    }

    db.query(
        "CREATE TABLE IF NOT EXISTS queue_v2 ( \
             task_id TEXT PRIMARY KEY, \
             crate_name TEXT NOT NULL, \
             version TEXT NOT NULL, \
             features_json TEXT NOT NULL, \
             target TEXT NOT NULL, \
             downloads INTEGER NOT NULL DEFAULT 0, \
             miss_count INTEGER NOT NULL DEFAULT 0, \
             request_count INTEGER NOT NULL DEFAULT 1, \
             priority INTEGER NOT NULL DEFAULT 0, \
             status TEXT NOT NULL DEFAULT 'pending', \
             gh_run_id TEXT, \
             error_msg TEXT, \
             first_requested_at TEXT NOT NULL DEFAULT (datetime('now')), \
             created_at TEXT NOT NULL DEFAULT (datetime('now')), \
             updated_at TEXT NOT NULL DEFAULT (datetime('now')), \
             UNIQUE(crate_name, version, features_json, target) \
         )",
    )
    .execute()
    .await
    .map_err(|error| format!("create scheduler queue_v2: {error}"))?;

    db.query(
        "INSERT INTO queue_v2 (task_id, crate_name, version, features_json, target, downloads, miss_count, request_count, priority, status, gh_run_id, error_msg, first_requested_at, created_at, updated_at) \
         SELECT task_id, crate_name, version, '[]', target, downloads, miss_count, 1, priority, status, gh_run_id, error_msg, coalesce(created_at, datetime('now')), created_at, updated_at \
         FROM queue",
    )
    .execute()
    .await
    .map_err(|error| format!("copy scheduler queue to queue_v2: {error}"))?;
    db.query("DROP TABLE queue")
        .execute()
        .await
        .map_err(|error| format!("drop legacy scheduler queue: {error}"))?;
    db.query("ALTER TABLE queue_v2 RENAME TO queue")
        .execute()
        .await
        .map_err(|error| format!("rename scheduler queue_v2: {error}"))?;
    Ok(())
}

async fn count_active(db: &DurableDb) -> Result<u32, String> {
    let row = db
        .query("SELECT count(*) AS count FROM queue WHERE status IN ('dispatched', 'running')")
        .fetch_one::<CountRow>()
        .await
        .map_err(|error| format!("count active tasks: {error}"))?;
    u64_to_u32(row.count, "active task count")
}

async fn count_by_status(db: &DurableDb, status: &str) -> Result<u32, String> {
    let row = db
        .query("SELECT count(*) AS count FROM queue WHERE status = ?")
        .bind(status.to_owned())
        .fetch_one::<CountRow>()
        .await
        .map_err(|error| format!("count tasks by status '{status}': {error}"))?;
    u64_to_u32(row.count, "task count")
}

fn task_id(crate_name: &str, version: &str, features_json: &str, target: &str) -> String {
    let features_hash = blake3::hash(features_json.as_bytes()).to_hex().to_string();
    format!(
        "{}-{}-{}-{}",
        crate_name,
        version,
        features_hash,
        target.replace('-', "_")
    )
}

fn normalize_features_json(raw: &str) -> Result<String, String> {
    let features = serde_json::from_str::<Vec<String>>(raw)
        .map_err(|error| format!("parse features_json: {error}"))?;
    for feature in &features {
        if feature.is_empty()
            || feature.len() > 128
            || !feature
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        {
            return Err(format!("invalid feature name: {feature}"));
        }
    }
    if features.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("features_json must be sorted and deduplicated".to_owned());
    }
    serde_json::to_string(&features).map_err(|error| format!("serialize features_json: {error}"))
}

fn dispatch_cutoff_modifier() -> String {
    format!("-{} minutes", DISPATCH_MIN_AGE_MINUTES)
}

fn u64_to_i64(value: u64, field: &str) -> Result<i64, String> {
    i64::try_from(value).map_err(|_| format!("{field} exceeds i64: {value}"))
}

fn u64_to_u32(value: u64, field: &str) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| format!("{field} exceeds u32: {value}"))
}

#[derive(Debug, Deserialize)]
struct TaskIdRow {
    task_id: String,
}

#[derive(Debug, Deserialize)]
struct TaskRow {
    task_id: String,
    crate_name: String,
    version: String,
    features_json: String,
    target: String,
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
struct PendingFirstSeenRow {
    first_requested_epoch: Option<i64>,
}
