use skyzen_cloudflare::CfDurableSqlite;
use stow_types::api::{BuildCompleteReport, EnqueueRequest, MissBoost, SchedulerStatus};

/// Maximum concurrent GitHub Actions jobs.
const MAX_CONCURRENT_JOBS: u32 = 10;

/// Priority calculation: `(downloads / 1000) + (miss_count * 10)`.
fn compute_priority(downloads: u64, miss_count: u32) -> i64 {
    (downloads / 1000) as i64 + (miss_count as i64 * 10)
}

/// Initialize the queue table in DO SQLite.
pub fn init_schema(sql: &CfDurableSqlite) -> Result<(), String> {
    sql.exec(include_str!("schema.sql"))
        .map_err(|e| format!("schema init: {e}"))?;
    Ok(())
}

/// Enqueue build requests. Deduplicates by (crate_name, version, target).
pub fn enqueue(sql: &CfDurableSqlite, requests: &[EnqueueRequest]) -> Result<u32, String> {
    let mut inserted = 0u32;
    for req in requests {
        let task_id = format!(
            "{}-{}-{}",
            req.crate_name,
            req.version,
            req.target.replace('-', "_")
        );
        let priority = compute_priority(req.downloads, 0);

        let insert_sql = format!(
            "INSERT OR IGNORE INTO queue (task_id, crate_name, version, target, downloads, priority) \
             VALUES ('{}', '{}', '{}', '{}', {}, {})",
            task_id, req.crate_name, req.version, req.target, req.downloads, priority
        );

        sql.exec(&insert_sql).map_err(|e| format!("enqueue: {e}"))?;
        inserted += 1;
    }
    Ok(inserted)
}

/// Bump priority for pending tasks matching the missed crate.
pub fn boost(sql: &CfDurableSqlite, boost: &MissBoost) -> Result<(), String> {
    let update_sql = format!(
        "UPDATE queue SET miss_count = miss_count + 1, \
         priority = (downloads / 1000) + ((miss_count + 1) * 10), \
         updated_at = datetime('now') \
         WHERE crate_name = '{}' AND target = '{}' AND status IN ('pending', 'dispatched')",
        boost.crate_name, boost.target
    );

    sql.exec(&update_sql).map_err(|e| format!("boost: {e}"))?;
    Ok(())
}

/// Mark a task as completed or failed.
pub fn complete(sql: &CfDurableSqlite, report: &BuildCompleteReport) -> Result<(), String> {
    let status = if report.success { "completed" } else { "failed" };
    let error_msg = report.error.as_deref().unwrap_or("");

    let update_sql = format!(
        "UPDATE queue SET status = '{}', error_msg = '{}', updated_at = datetime('now') \
         WHERE task_id = '{}'",
        status, error_msg, report.task_id
    );

    sql.exec(&update_sql)
        .map_err(|e| format!("complete: {e}"))?;
    Ok(())
}

/// Get queue status for monitoring.
pub fn status(sql: &CfDurableSqlite) -> Result<SchedulerStatus, String> {
    // DO SQLite exec returns raw results, so we count each status
    let count_sql = |status: &str| -> Result<u32, String> {
        let sql_str = format!(
            "SELECT count(*) as cnt FROM queue WHERE status = '{}'",
            status
        );
        // Note: CfDurableSqlite::exec returns JsValue, parsing is limited.
        // For now, return 0 as placeholder - proper parsing needs serde_wasm_bindgen.
        let _result = sql.exec(&sql_str).map_err(|e| format!("status: {e}"))?;
        Ok(0) // Placeholder - actual parsing would deserialize the JsValue
    };

    Ok(SchedulerStatus {
        pending: count_sql("pending")?,
        dispatched: count_sql("dispatched")?,
        running: count_sql("running")?,
        completed: count_sql("completed")?,
        failed: count_sql("failed")?,
    })
}

/// Pop highest-priority pending tasks and return them for dispatch.
/// Returns task IDs and their details.
pub fn pop_highest_priority(
    sql: &CfDurableSqlite,
    limit: u32,
) -> Result<Vec<(String, String, String, String)>, String> {
    // Get count of currently running/dispatched tasks
    let _running = sql
        .exec("SELECT count(*) FROM queue WHERE status IN ('dispatched', 'running')")
        .map_err(|e| format!("count running: {e}"))?;

    // For now, return empty - proper implementation needs JsValue parsing
    // In production: query top N by priority where status = 'pending',
    // up to MAX_CONCURRENT_JOBS minus currently running
    let _select_sql = format!(
        "SELECT task_id, crate_name, version, target FROM queue \
         WHERE status = 'pending' ORDER BY priority DESC LIMIT {}",
        limit
    );

    Ok(Vec::new())
}
