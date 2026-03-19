use crate::config::StowConfig;
use crate::state_db::{connect, duration_millis, now_millis};

pub async fn is_tripped(config: &StowConfig) -> eyre::Result<bool> {
    let connection = connect(&config.cache_dir).await?;
    let row = sqlx::query_as::<_, (i64, Option<i64>)>(
        "SELECT consecutive_failures, tripped_at_ms \
         FROM circuit_state \
         WHERE singleton = 1",
    )
    .fetch_optional(&connection)
    .await?;
    let Some((_, Some(tripped_at_ms))) = row else {
        return Ok(false);
    };

    let elapsed = now_millis().saturating_sub(tripped_at_ms as u64);
    if elapsed < duration_millis(config.circuit_reset_after) {
        return Ok(true);
    }

    sqlx::query(
        "INSERT INTO circuit_state (singleton, consecutive_failures, tripped_at_ms) \
         VALUES (1, 0, NULL) \
         ON CONFLICT(singleton) DO UPDATE SET consecutive_failures = 0, tripped_at_ms = NULL",
    )
    .execute(&connection)
    .await?;
    Ok(false)
}

pub async fn record_success(config: &StowConfig) -> eyre::Result<()> {
    let connection = connect(&config.cache_dir).await?;
    sqlx::query(
        "INSERT INTO circuit_state (singleton, consecutive_failures, tripped_at_ms) \
         VALUES (1, 0, NULL) \
         ON CONFLICT(singleton) DO UPDATE SET consecutive_failures = 0, tripped_at_ms = NULL",
    )
    .execute(&connection)
    .await?;
    Ok(())
}

pub async fn record_failure(config: &StowConfig) -> eyre::Result<()> {
    let connection = connect(&config.cache_dir).await?;
    let consecutive_failures = sqlx::query_scalar::<_, i64>(
        "SELECT consecutive_failures \
         FROM circuit_state \
         WHERE singleton = 1",
    )
    .fetch_optional(&connection)
    .await?
    .unwrap_or(0)
    .saturating_add(1);
    let tripped_at_ms = if consecutive_failures >= i64::from(config.circuit_trip_threshold) {
        Some(now_millis() as i64)
    } else {
        None
    };
    sqlx::query(
        "INSERT INTO circuit_state (singleton, consecutive_failures, tripped_at_ms) \
         VALUES (1, ?, ?) \
         ON CONFLICT(singleton) DO UPDATE SET \
             consecutive_failures = excluded.consecutive_failures, \
             tripped_at_ms = excluded.tripped_at_ms",
    )
    .bind(consecutive_failures)
    .bind(tripped_at_ms)
    .execute(&connection)
    .await?;
    Ok(())
}

pub async fn negative_cache_contains(config: &StowConfig, key: &str) -> eyre::Result<bool> {
    let connection = connect(&config.cache_dir).await?;
    let now_ms = now_millis() as i64;
    let ttl_ms = duration_millis(config.negative_cache_ttl) as i64;
    sqlx::query(
        "DELETE FROM negative_cache_entries \
         WHERE ? - inserted_at_ms >= ?",
    )
    .bind(now_ms)
    .bind(ttl_ms)
    .execute(&connection)
    .await?;
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM negative_cache_entries WHERE cache_key = ?",
    )
    .bind(key)
    .fetch_optional(&connection)
    .await?
    .is_some();
    Ok(exists)
}

pub async fn record_negative_cache(config: &StowConfig, key: &str) -> eyre::Result<()> {
    let connection = connect(&config.cache_dir).await?;
    let now_ms = now_millis() as i64;
    let ttl_ms = duration_millis(config.negative_cache_ttl) as i64;
    sqlx::query(
        "DELETE FROM negative_cache_entries \
         WHERE ? - inserted_at_ms >= ?",
    )
    .bind(now_ms)
    .bind(ttl_ms)
    .execute(&connection)
    .await?;
    sqlx::query(
        "INSERT INTO negative_cache_entries (cache_key, inserted_at_ms) \
         VALUES (?, ?) \
         ON CONFLICT(cache_key) DO UPDATE SET inserted_at_ms = excluded.inserted_at_ms",
    )
    .bind(key)
    .bind(now_ms)
    .execute(&connection)
    .await?;
    Ok(())
}
