use crate::config::StowConfig;
use crate::state_db::{db_int, duration_millis, now_millis};

/// A build's shared circuit handle: the state-db row behind the breaker,
/// the tripped answer this build memoizes for its plan path, and the
/// open broadcast an in-flight edge download abandons on (stow#977).
/// The supervisor and the build's enrichment write through the same
/// handle.
#[derive(Debug, Clone)]
pub struct BuildCircuit {
    tripped: std::sync::Arc<tokio::sync::OnceCell<tokio::sync::watch::Sender<bool>>>,
}

impl BuildCircuit {
    pub fn new() -> Self {
        Self {
            tripped: std::sync::Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    /// The lazily-read tripped cell: the first answer asks the state db,
    /// and this build's own recordings keep the broadcast in step.
    async fn cell(
        &self,
        config: &StowConfig,
    ) -> stow_types::error::Result<&tokio::sync::watch::Sender<bool>> {
        self.tripped
            .get_or_try_init(|| async {
                Ok::<_, stow_types::error::Error>(
                    tokio::sync::watch::channel(is_tripped(config).await?).0,
                )
            })
            .await
    }

    /// The circuit's tripped state for this build, read once — the
    /// per-invocation state-db query was the supervisor's busiest query
    /// (stow#347).
    pub async fn tripped(&self, config: &StowConfig) -> stow_types::error::Result<bool> {
        Ok(*self.cell(config).await?.borrow())
    }

    /// Resolve when the circuit opens — the wait an in-flight download
    /// races its request against (stow#977). A state-db read that fails
    /// leaves the signal silent: the request's own outcome then decides
    /// the unit.
    pub async fn opened(&self, config: &StowConfig) {
        let Ok(cell) = self.cell(config).await else {
            return std::future::pending().await;
        };
        let mut receiver = cell.subscribe();
        let _ = receiver.wait_for(|tripped| *tripped).await;
    }

    /// Count a remote-cache failure against the breaker, then refresh
    /// the memo so the rest of the build sees its own recording.
    pub async fn record_failure(&self, config: &StowConfig) {
        crate::log_nonfatal_result(
            "failed to record stow circuit failure",
            record_failure(config).await,
        );
        if let Some(cell) = self.tripped.get()
            && let Ok(tripped) = is_tripped(config).await
        {
            cell.send_replace(tripped);
        }
    }

    /// Count a remote-cache success toward resetting the breaker; a
    /// success resets it outright, so the memo just clears.
    pub async fn record_success(&self, config: &StowConfig) {
        crate::log_nonfatal_result(
            "failed to record stow circuit success",
            record_success(config).await,
        );
        if let Some(cell) = self.tripped.get() {
            cell.send_replace(false);
        }
    }

    /// Trip the breaker outright — one definitive answer (the build's
    /// own index fetch found the registry unreachable) rather than the
    /// failure count reaching the threshold (stow#977). The broadcast
    /// releases in-flight downloads with the waiters.
    pub async fn trip(&self, config: &StowConfig) {
        crate::log_nonfatal_result("failed to trip the stow circuit", trip(config).await);
        if let Some(cell) = self.tripped.get() {
            cell.send_replace(true);
        }
    }
}

pub async fn is_tripped(config: &StowConfig) -> stow_types::error::Result<bool> {
    let connection = config.state_db_pool().await?;
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

    let tripped_at_ms: u64 = db_int(tripped_at_ms, "circuit tripped_at_ms")?;
    let elapsed = now_millis().saturating_sub(tripped_at_ms);
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

pub async fn record_success(config: &StowConfig) -> stow_types::error::Result<()> {
    let connection = config.state_db_pool().await?;
    sqlx::query(
        "INSERT INTO circuit_state (singleton, consecutive_failures, tripped_at_ms) \
         VALUES (1, 0, NULL) \
         ON CONFLICT(singleton) DO UPDATE SET consecutive_failures = 0, tripped_at_ms = NULL",
    )
    .execute(&connection)
    .await?;
    Ok(())
}

/// Trip the breaker outright — the row's failure count set at the
/// threshold and `tripped_at_ms` stamped now, so every reader of the
/// row, this build's memo included, sees it open (stow#977).
pub async fn trip(config: &StowConfig) -> stow_types::error::Result<()> {
    let connection = config.state_db_pool().await?;
    let tripped_at_ms: i64 = db_int(now_millis(), "circuit trip timestamp")?;
    sqlx::query(
        "INSERT INTO circuit_state (singleton, consecutive_failures, tripped_at_ms) \
         VALUES (1, ?, ?) \
         ON CONFLICT(singleton) DO UPDATE SET \
             consecutive_failures = excluded.consecutive_failures, \
             tripped_at_ms = excluded.tripped_at_ms",
    )
    .bind(i64::from(config.circuit_trip_threshold))
    .bind(tripped_at_ms)
    .execute(&connection)
    .await?;
    Ok(())
}

pub async fn record_failure(config: &StowConfig) -> stow_types::error::Result<()> {
    let connection = config.state_db_pool().await?;
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
        Some(db_int::<_, i64>(now_millis(), "circuit trip timestamp")?)
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

pub async fn negative_cache_contains(
    config: &StowConfig,
    key: &str,
) -> stow_types::error::Result<bool> {
    let connection = config.state_db_pool().await?;
    let now_ms: i64 = db_int(now_millis(), "negative cache current time")?;
    let ttl_ms: i64 = db_int(
        duration_millis(config.negative_cache_ttl),
        "negative cache TTL",
    )?;
    sqlx::query(
        "DELETE FROM negative_cache_entries \
         WHERE ? - inserted_at_ms >= ?",
    )
    .bind(now_ms)
    .bind(ttl_ms)
    .execute(&connection)
    .await?;
    let exists =
        sqlx::query_scalar::<_, i64>("SELECT 1 FROM negative_cache_entries WHERE cache_key = ?")
            .bind(key)
            .fetch_optional(&connection)
            .await?
            .is_some();
    Ok(exists)
}

pub async fn record_negative_cache(
    config: &StowConfig,
    key: &str,
) -> stow_types::error::Result<()> {
    let connection = config.state_db_pool().await?;
    let now_ms: i64 = db_int(now_millis(), "negative cache current time")?;
    let ttl_ms: i64 = db_int(
        duration_millis(config.negative_cache_ttl),
        "negative cache TTL",
    )?;
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
