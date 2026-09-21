use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous};
use stow_types::error::Context;

const STATE_DB_FILE_NAME: &str = "state-v3.sqlite3";

/// One column as `state-db-schema.sql` declares it.
///
/// `CREATE TABLE IF NOT EXISTS` does nothing to a table that already
/// exists, so a column added to the schema file never reaches a database
/// created before it. The columns are therefore read back out of the
/// schema file and added to whatever is on disk — which means adding a
/// column to the schema file is the whole of adding a column, with no
/// second list to keep in step. `artifact_cache_native_out_dir_files.sha256`
/// was added to the schema and to no migration, so every database older
/// than it answered `no such column: sha256` for the rest of its life and
/// every bundle whose artifact had native out-dir files was downloaded,
/// verified, and then thrown away.
#[derive(Debug, PartialEq, Eq)]
struct SchemaColumn<'a> {
    table: &'a str,
    name: &'a str,
    /// The column's declaration, verbatim, for `ALTER TABLE … ADD COLUMN`.
    definition: &'a str,
}

/// Table-level constraints, which sit among the column declarations and
/// are not columns.
const CONSTRAINT_KEYWORDS: &[&str] = &["PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"];

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
    ensure_declared_columns(&pool, &path).await?;
    Ok(pool)
}

/// Add every column `state-db-schema.sql` declares that the database on
/// disk does not have.
async fn ensure_declared_columns(
    pool: &SqlitePool,
    db_path: &Path,
) -> stow_types::error::Result<()> {
    let schema = include_str!("state-db-schema.sql");
    let declared = declared_columns(schema);
    let mut current_table = "";
    let mut existing: Vec<String> = Vec::new();
    for column in declared {
        if column.table != current_table {
            current_table = column.table;
            existing = sqlx::query_scalar::<_, String>(&format!(
                "SELECT name FROM pragma_table_info('{current_table}')"
            ))
            .fetch_all(pool)
            .await
            .wrap_err_with(|| {
                format!("inspect {current_table} columns in {}", db_path.display())
            })?;
        }
        // An empty listing means the table itself is absent, which the
        // schema file above was supposed to create: there is nothing to
        // alter, and altering a missing table would only mask that.
        if existing.is_empty() || existing.iter().any(|name| name == column.name) {
            continue;
        }
        let statement = format!(
            "ALTER TABLE {} ADD COLUMN {}",
            column.table, column.definition
        );
        sqlx::query(&statement)
            .execute(pool)
            .await
            .wrap_err_with(|| {
                format!(
                    "add missing column {}.{} in {}",
                    column.table,
                    column.name,
                    db_path.display()
                )
            })?;
        tracing::debug!(
            table = column.table,
            column = column.name,
            "added a column the state database was missing"
        );
    }
    Ok(())
}

/// Every column declared by every `CREATE TABLE` in `schema`, in file
/// order, so the tables come out grouped.
fn declared_columns(schema: &str) -> Vec<SchemaColumn<'_>> {
    let mut columns = Vec::new();
    let mut rest = schema;
    while let Some(start) = rest.find("CREATE TABLE") {
        let after = &rest[start..];
        let Some(open) = after.find('(') else {
            break;
        };
        let table = table_name(&after[..open]);
        let body = balanced_body(&after[open..]);
        rest = &after[open + body.len()..];
        let Some(table) = table else {
            continue;
        };
        for declaration in split_top_level(body) {
            let declaration = declaration.trim();
            let Some(name) = declaration.split_whitespace().next() else {
                continue;
            };
            if CONSTRAINT_KEYWORDS
                .iter()
                .any(|keyword| name.eq_ignore_ascii_case(keyword))
            {
                continue;
            }
            columns.push(SchemaColumn {
                table,
                name,
                definition: declaration,
            });
        }
    }
    columns
}

/// The table name out of `CREATE TABLE [IF NOT EXISTS] <name>`.
fn table_name(header: &str) -> Option<&str> {
    header
        .split_whitespace()
        .last()
        .filter(|name| !name.eq_ignore_ascii_case("TABLE") && !name.eq_ignore_ascii_case("EXISTS"))
}

/// The text between the opening parenthesis of `input` and its match.
fn balanced_body(input: &str) -> &str {
    let mut depth = 0usize;
    for (index, character) in input.char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &input[1..index];
                }
            }
            _ => {}
        }
    }
    ""
}

/// Split on the commas that separate declarations, ignoring the ones
/// inside a nested parenthesis.
fn split_top_level(body: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (index, character) in body.char_indices() {
        match character {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&body[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&body[start..]);
    parts
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

#[cfg(test)]
mod schema_tests {
    use super::{connect_pool, declared_columns};

    /// The schema file is the source of truth for the migration, so it has
    /// to parse into the columns it declares — including the one whose
    /// absence broke every pre-existing database.
    #[test]
    fn the_schema_file_declares_its_columns() {
        let schema = include_str!("state-db-schema.sql");
        let columns = declared_columns(schema);
        assert!(
            columns.iter().any(
                |column| column.table == "artifact_cache_native_out_dir_files"
                    && column.name == "sha256"
            ),
            "the parser must see artifact_cache_native_out_dir_files.sha256"
        );
        assert!(
            columns
                .iter()
                .any(|column| column.table == "artifact_cache_entries"
                    && column.name == "compile_key"),
            "the parser must see artifact_cache_entries.compile_key"
        );
        assert!(
            !columns
                .iter()
                .any(|column| column.name.eq_ignore_ascii_case("PRIMARY")
                    || column.name.eq_ignore_ascii_case("FOREIGN")),
            "table constraints are not columns"
        );
    }

    /// The regression itself: a database created before a column was added
    /// to the schema file gets the column on the next open, instead of
    /// answering `no such column` forever.
    #[tokio::test]
    async fn an_older_database_gains_the_columns_it_is_missing() {
        let cache_dir = tempfile::tempdir().expect("temp dir");
        let path = super::state_db_path(cache_dir.path());
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create parent");

        // A database from before `sha256` existed on that table.
        let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .expect("open the old database");
        sqlx::query(
            "CREATE TABLE artifact_cache_native_out_dir_files (\
                 rustc_version TEXT NOT NULL, \
                 cache_key TEXT NOT NULL, \
                 ordinal INTEGER NOT NULL, \
                 relative_path TEXT NOT NULL, \
                 PRIMARY KEY (rustc_version, cache_key, ordinal))",
        )
        .execute(&pool)
        .await
        .expect("create the old table");
        pool.close().await;

        let pool = connect_pool(cache_dir.path())
            .await
            .expect("open the database through the migration");
        let columns = sqlx::query_scalar::<_, String>(
            "SELECT name FROM pragma_table_info('artifact_cache_native_out_dir_files')",
        )
        .fetch_all(&pool)
        .await
        .expect("read the migrated columns");
        assert!(
            columns.iter().any(|column| column == "sha256"),
            "the missing column must be added: {columns:?}"
        );
        sqlx::query_scalar::<_, String>(
            "SELECT relative_path FROM artifact_cache_native_out_dir_files LIMIT 1",
        )
        .fetch_optional(&pool)
        .await
        .expect("the table stays usable after the migration");
    }
}
