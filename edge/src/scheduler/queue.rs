use serde::Deserialize;
use skyzen_services::durable::DurableDb;
use stow_types::api::{BuildCompleteReport, EnqueueRequest, SchedulerStatus};

use crate::scheduler::dispatch::QueuedTask;

/// Maximum concurrent GitHub Actions jobs.
const MAX_CONCURRENT_JOBS: u32 = 10;

/// Priority calculation: `(downloads / 1000) + (miss_count * 10)`.
fn compute_priority(downloads: u64, miss_count: u32) -> Result<i64, String> {
    let downloads_bucket = downloads / 1000;
    let downloads_bucket = i64::try_from(downloads_bucket)
        .map_err(|_| format!("downloads bucket exceeds i64: {downloads_bucket}"))?;
    Ok(downloads_bucket + i64::from(miss_count) * 10)
}

pub async fn enqueue(db: &DurableDb, requests: &[EnqueueRequest]) -> Result<u32, String> {
    ensure_schema(db).await?;
    let mut inserted = 0u32;

    for request in requests {
        let task_id = task_id(request);
        let downloads = u64_to_i64(request.downloads, "downloads")?;
        let priority = compute_priority(request.downloads, 0)?;

        let existing = db
            .query(
                "SELECT task_id FROM queue WHERE crate_name = ? AND version = ? AND target = ? LIMIT 1",
            )
            .bind(request.crate_name.clone())
            .bind(request.version.clone())
            .bind(request.target.clone())
            .fetch_optional::<TaskIdRow>()
            .await
            .map_err(|error| format!("select existing task: {error}"))?;

        if existing.is_some() {
            db.query(
                "UPDATE queue \
                 SET downloads = ?, priority = ?, updated_at = datetime('now') \
                 WHERE crate_name = ? AND version = ? AND target = ?",
            )
            .bind(downloads)
            .bind(priority)
            .bind(request.crate_name.clone())
            .bind(request.version.clone())
            .bind(request.target.clone())
            .execute()
            .await
            .map_err(|error| format!("update existing task: {error}"))?;
            continue;
        }

        db.query(
            "INSERT INTO queue \
             (task_id, crate_name, version, target, downloads, miss_count, priority, status) \
             VALUES (?, ?, ?, ?, ?, 0, ?, 'pending')",
        )
        .bind(task_id)
        .bind(request.crate_name.clone())
        .bind(request.version.clone())
        .bind(request.target.clone())
        .bind(downloads)
        .bind(priority)
        .execute()
        .await
        .map_err(|error| format!("insert task: {error}"))?;

        inserted += 1;
    }

    Ok(inserted)
}

pub async fn boost(db: &DurableDb, boost: &stow_types::api::MissBoost) -> Result<(), String> {
    ensure_schema(db).await?;
    db.query(
        "UPDATE queue \
         SET miss_count = miss_count + 1, \
             priority = (downloads / 1000) + ((miss_count + 1) * 10), \
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
            "SELECT task_id, crate_name, version, target \
             FROM queue \
             WHERE status = 'pending' \
             ORDER BY priority DESC, updated_at ASC, created_at ASC \
             LIMIT ?",
        )
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

async fn ensure_schema(db: &DurableDb) -> Result<(), String> {
    db.query(include_str!("schema.sql"))
        .execute()
        .await
        .map_err(|error| format!("ensure scheduler schema: {error}"))?;
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

fn task_id(request: &EnqueueRequest) -> String {
    format!(
        "{}-{}-{}",
        request.crate_name,
        request.version,
        request.target.replace('-', "_")
    )
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
    target: String,
}

#[derive(Debug, Deserialize)]
struct CountRow {
    count: u64,
}
