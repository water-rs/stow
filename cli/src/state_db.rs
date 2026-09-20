use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous};
use stow_types::error::Context;

const STATE_DB_FILE_NAME: &str = "state-v3.sqlite3";

struct RequiredSqlColumn {
    name: &'static str,
    add_sql: &'static str,
}

const REQUIRED_ARTIFACT_CACHE_ENTRY_COLUMNS: &[RequiredSqlColumn] = &[
    RequiredSqlColumn {
        name: "compile_key",
        add_sql: "ALTER TABLE artifact_cache_entries ADD COLUMN compile_key TEXT NOT NULL DEFAULT ''",
    },
    RequiredSqlColumn {
        name: "crate_name",
        add_sql: "ALTER TABLE artifact_cache_entries ADD COLUMN crate_name TEXT NOT NULL DEFAULT ''",
    },
    RequiredSqlColumn {
        name: "crate_version",
        add_sql: "ALTER TABLE artifact_cache_entries ADD COLUMN crate_version TEXT NOT NULL DEFAULT ''",
    },
    RequiredSqlColumn {
        name: "c_metadata",
        add_sql: "ALTER TABLE artifact_cache_entries ADD COLUMN c_metadata TEXT NOT NULL DEFAULT ''",
    },
    RequiredSqlColumn {
        name: "features_json",
        add_sql: "ALTER TABLE artifact_cache_entries ADD COLUMN features_json TEXT NOT NULL DEFAULT '[]'",
    },
    RequiredSqlColumn {
        name: "target",
        add_sql: "ALTER TABLE artifact_cache_entries ADD COLUMN target TEXT NOT NULL DEFAULT ''",
    },
    RequiredSqlColumn {
        name: "profile_json",
        add_sql: "ALTER TABLE artifact_cache_entries ADD COLUMN profile_json TEXT NOT NULL DEFAULT '{}'",
    },
    RequiredSqlColumn {
        name: "emit_json",
        add_sql: "ALTER TABLE artifact_cache_entries ADD COLUMN emit_json TEXT NOT NULL DEFAULT '[]'",
    },
    RequiredSqlColumn {
        name: "kind_json",
        add_sql: "ALTER TABLE artifact_cache_entries ADD COLUMN kind_json TEXT NOT NULL DEFAULT '\"Rlib\"'",
    },
    RequiredSqlColumn {
        name: "crate_types_json",
        add_sql: "ALTER TABLE artifact_cache_entries ADD COLUMN crate_types_json TEXT NOT NULL DEFAULT '[]'",
    },
    RequiredSqlColumn {
        name: "dependency_c_metadata_json",
        add_sql: "ALTER TABLE artifact_cache_entries ADD COLUMN dependency_c_metadata_json TEXT NOT NULL DEFAULT '[]'",
    },
    RequiredSqlColumn {
        name: "dependency_compile_keys_json",
        add_sql: "ALTER TABLE artifact_cache_entries ADD COLUMN dependency_compile_keys_json TEXT NOT NULL DEFAULT '[]'",
    },
    RequiredSqlColumn {
        name: "provenance",
        add_sql: "ALTER TABLE artifact_cache_entries ADD COLUMN provenance TEXT NOT NULL DEFAULT 'remote'",
    },
    RequiredSqlColumn {
        name: "compile_millis",
        add_sql: "ALTER TABLE artifact_cache_entries ADD COLUMN compile_millis INTEGER NOT NULL DEFAULT 0",
    },
];

pub fn state_db_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join(STATE_DB_FILE_NAME)
}

/// Lazy-init builder for the state `SQLite` pool. Prefer
/// [`crate::config::StowConfig::state_db_pool`] in callers — it caches the
/// pool for the lifetime of the process so the hot path doesn't pay schema
/// migration costs per invocation.
#[tracing::instrument(name = "stow.sqlite.connect", skip_all)]
pub async fn connect_pool(cache_dir: &Path) -> stow_types::error::Result<SqlitePool> {
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
    ensure_required_artifact_cache_entry_columns(&pool, &path).await?;
    Ok(pool)
}

async fn ensure_required_artifact_cache_entry_columns(
    pool: &SqlitePool,
    db_path: &Path,
) -> stow_types::error::Result<()> {
    let existing_columns = sqlx::query_scalar::<_, String>(
        "SELECT name FROM pragma_table_info('artifact_cache_entries')",
    )
    .fetch_all(pool)
    .await
    .wrap_err_with(|| {
        format!(
            "inspect artifact_cache_entries columns in {}",
            db_path.display()
        )
    })?;
    for required in REQUIRED_ARTIFACT_CACHE_ENTRY_COLUMNS {
        if existing_columns
            .iter()
            .any(|column| column == required.name)
        {
            continue;
        }
        sqlx::query(required.add_sql)
            .execute(pool)
            .await
            .wrap_err_with(|| {
                format!(
                    "add missing artifact_cache_entries column {} in {}",
                    required.name,
                    db_path.display()
                )
            })?;
    }
    Ok(())
}

/// Thin test-only shim that calls [`connect_pool`] without the process-wide
/// cache. Hot paths must go through `StowConfig::state_db_pool`.
#[cfg(test)]
pub async fn connect(cache_dir: &Path) -> stow_types::error::Result<SqlitePool> {
    connect_pool(cache_dir).await
}

pub fn now_millis() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis();
    u64::try_from(millis).expect("current time in milliseconds exceeds u64 range")
}

// `as_millis` of configured durations fits u64: overflow would require a
// duration of ~584 million years. `const fn` cannot use `u128::try_from`.
#[allow(clippy::cast_possible_truncation)]
pub const fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis() as u64
}

/// Fast-fail integer conversion for values crossing the `SQLite` boundary.
///
/// `SQLite` stores integers as `i64`, so every unsigned or wider value must be
/// range-checked on the way in, and every stored value must be range-checked
/// on the way back out. `what` names the value for the error message.
pub fn db_int<Source, Target>(value: Source, what: &str) -> stow_types::error::Result<Target>
where
    Target: TryFrom<Source>,
    Source: Copy + std::fmt::Display,
{
    TryFrom::try_from(value).map_err(|_| {
        stow_types::stow_error!(
            "{what} value {value} is out of range for its database representation"
        )
    })
}
