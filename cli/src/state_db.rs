use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eyre::Context;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous};
use sqlx::SqlitePool;

const STATE_DB_FILE_NAME: &str = "state-v3.sqlite3";

pub fn state_db_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join(STATE_DB_FILE_NAME)
}

pub async fn connect(cache_dir: &Path) -> eyre::Result<SqlitePool> {
    let path = state_db_path(cache_dir);
    if let Some(parent) = path.parent() {
        async_fs::create_dir_all(parent)
            .await
            .wrap_err_with(|| format!("create state db parent {}", parent.display()))?;
    }

    let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
        .wrap_err_with(|| format!("build sqlite connect options for {}", path.display()))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true);

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .wrap_err_with(|| format!("open state db {}", path.display()))?;
    sqlx::raw_sql(include_str!("state-db-schema.sql"))
        .execute(&pool)
        .await
        .wrap_err_with(|| format!("initialize state db schema {}", path.display()))?;
    Ok(pool)
}

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as u64
}

pub fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis() as u64
}
