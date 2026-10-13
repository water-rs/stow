use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous};
use stow_types::error::Context;
use tokio::sync::OnceCell;

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
/// verified, and then thrown away. (The table has since been removed — the
/// consumer no longer stores build-script products — but the mechanism it
/// motivated remains the way columns reach existing databases.)
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

/// The process's one handle on the state database.
///
/// The command entry point creates it, every config the process loads
/// carries a clone, and the entry point closes it once the command's
/// future has finished. One handle, because a process that opened a pool
/// per loaded config held connections nothing could enumerate, and a
/// connection still open when the process exits breaks the next one on
/// Windows: the next opener of a WAL database truncates its `-shm` file
/// while the dying process still has it mapped, and `SQLite` answers
/// `SQLITE_IOERR_TRUNCATE` — "disk I/O error" — where a process that
/// closed its connection first never causes it (stow#682).
///
/// The cell holds `Some` once the pool is open and `None` once the handle
/// is closed. Closing is final: a later [`Self::pool`] fails rather than
/// reopen a database nothing is left to close.
#[derive(Debug, Clone, Default)]
pub struct StateDb(Arc<OnceCell<Option<SqlitePool>>>);

impl StateDb {
    /// A handle closed from the start, for a process that has no state
    /// database: `stow-build` loads a config through
    /// [`crate::build_consume`] to read the index and verify bundles,
    /// never opens the database, and has no entry point here to close
    /// one. A use fails the way a use after [`Self::close`] does, rather
    /// than open a connection nothing would close (stow#682).
    pub fn closed() -> Self {
        Self(Arc::new(OnceCell::from(None)))
    }

    /// The pool, opened for `cache_dir` on the first call and shared by
    /// every later one, so the hot path pays the connect and the schema
    /// pass once per process.
    ///
    /// # Errors
    ///
    /// Whatever opening the database fails with, and any use after
    /// [`Self::close`].
    pub async fn pool(&self, cache_dir: &Path) -> stow_types::error::Result<SqlitePool> {
        self.0
            .get_or_try_init(|| async { connect_pool(cache_dir).await.map(Some) })
            .await?
            .clone()
            .ok_or_else(|| stow_types::stow_error!("the state database was closed before this use"))
    }

    /// Close the pool and refuse every later [`Self::pool`].
    ///
    /// Claiming the cell waits for an open that is in flight, so a
    /// connect racing the close is closed too; a handle that was never
    /// opened becomes closed without opening anything.
    pub async fn close(&self) {
        if let Some(pool) = self.0.get_or_init(|| async { None }).await {
            pool.close().await;
        }
    }
}

/// Open the state `SQLite` pool. Callers go through [`StateDb::pool`] —
/// it opens once per process, so the hot path doesn't pay schema
/// migration costs per invocation, and it is the handle the process
/// closes.
#[tracing::instrument(name = "stow.sqlite.connect", skip_all)]
async fn connect_pool(cache_dir: &Path) -> stow_types::error::Result<SqlitePool> {
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
        .after_connect(|connection, _| Box::pin(keep_wal_on_close(connection)))
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

/// Tell `SQLite` not to checkpoint the WAL when this connection is the
/// last one to close.
///
/// A process closes its connection before it exits (see [`StateDb`]),
/// and the last connection's close otherwise checkpoints the WAL and
/// syncs the database file — about 20 ms on macOS and Windows for a
/// process that is the database's only connection, which a standalone
/// wrapper is once per compiled unit. The close this leaves still
/// unmaps `-shm` before it releases the file's locks, which is all the
/// next opener needs (stow#682); the WAL is checkpointed where it
/// always was, by the automatic checkpoint inside a commit.
async fn keep_wal_on_close(connection: &mut sqlx::SqliteConnection) -> Result<(), sqlx::Error> {
    let mut handle = connection.lock_handle().await?;
    // SAFETY: `handle` is this live connection's `sqlite3*`, locked for
    // the duration of the call, and `SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE`
    // takes an `int` and a nullable `int*`.
    let code = unsafe {
        libsqlite3_sys::sqlite3_db_config(
            handle.as_raw_handle().as_ptr(),
            libsqlite3_sys::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            1_i32,
            std::ptr::null_mut::<i32>(),
        )
    };
    if code == libsqlite3_sys::SQLITE_OK {
        Ok(())
    } else {
        Err(sqlx::Error::Protocol(format!(
            "sqlite3_db_config(SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE) returned {code}"
        )))
    }
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
            existing = sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(format!(
                "SELECT name FROM pragma_table_info('{current_table}')"
            )))
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
        sqlx::query(sqlx::AssertSqlSafe(statement))
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

/// Thin test-only shim that calls [`connect_pool`] without the process's
/// handle. Hot paths must go through [`StateDb::pool`].
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
mod handle_tests {
    use super::{StateDb, state_db_path};

    /// A handle that is born closed opens nothing either.
    #[tokio::test]
    async fn a_handle_born_closed_refuses_to_open() {
        let cache_dir = tempfile::tempdir().expect("temp dir");
        let state_db = StateDb::closed();

        let error = state_db
            .pool(cache_dir.path())
            .await
            .expect_err("a handle born closed must not open the database");
        assert!(
            error.to_string().contains("closed before this use"),
            "unexpected error: {error}"
        );
        assert!(
            !state_db_path(cache_dir.path()).exists(),
            "a handle born closed must not create the database file"
        );
        // Closing it again is the no-op the entry point's close would be.
        state_db.close().await;
    }

    /// Closing is final even for a handle that never opened: the process
    /// is past the point where anything would close what a late caller
    /// opened, so the late caller gets an error and no database.
    #[tokio::test]
    async fn a_closed_handle_refuses_to_open() {
        let cache_dir = tempfile::tempdir().expect("temp dir");
        let state_db = StateDb::default();
        state_db.close().await;

        let error = state_db
            .pool(cache_dir.path())
            .await
            .expect_err("a closed handle must not open the database");
        assert!(
            error.to_string().contains("closed before this use"),
            "unexpected error: {error}"
        );
        assert!(
            !state_db_path(cache_dir.path()).exists(),
            "a closed handle must not create the database file"
        );
    }

    /// Every clone of the pool the handle gave out is the pool it closes.
    #[tokio::test]
    async fn closing_closes_the_pool() {
        let cache_dir = tempfile::tempdir().expect("temp dir");
        let state_db = StateDb::default();
        let pool = state_db
            .pool(cache_dir.path())
            .await
            .expect("open the state database");
        assert!(!pool.is_closed());

        state_db.close().await;
        assert!(pool.is_closed(), "the close must reach the pool's clones");
    }

    /// The close leaves the WAL where it is: the last connection's
    /// default close would checkpoint it, sync the database and delete
    /// it, which is the cost `keep_wal_on_close` exists to avoid.
    #[tokio::test]
    async fn closing_does_not_checkpoint_the_wal() {
        let cache_dir = tempfile::tempdir().expect("temp dir");
        let state_db = StateDb::default();
        // Opening ran the schema, so the WAL already holds frames.
        state_db
            .pool(cache_dir.path())
            .await
            .expect("open the state database");

        state_db.close().await;
        let mut wal = state_db_path(cache_dir.path()).into_os_string();
        wal.push("-wal");
        let wal_len = std::fs::metadata(&wal)
            .expect("the close must leave the WAL file in place")
            .len();
        assert!(wal_len > 0, "the close checkpointed the WAL");
    }

    /// The regression the early connect makes possible (stow#682): an
    /// open still in flight when the command ends is waited for and
    /// closed, never left to finish after the close has returned.
    #[tokio::test]
    async fn a_close_waits_for_a_connect_in_flight() {
        let cache_dir = tempfile::tempdir().expect("temp dir");
        let state_db = StateDb::default();
        let opening = tokio::spawn({
            let state_db = state_db.clone();
            let cache_dir = cache_dir.path().to_path_buf();
            async move { state_db.pool(&cache_dir).await }
        });
        // Let the spawned open claim the cell before the close asks for it.
        tokio::task::yield_now().await;
        let (opened, ()) = tokio::join!(opening, state_db.close());

        let pool = opened
            .expect("join the opening task")
            .expect("the open that claimed the cell first completes");
        assert!(
            pool.is_closed(),
            "the close must wait for the open in flight and close its pool"
        );
        // Whatever the cell holds now, it is nothing a caller can use.
        match state_db.pool(cache_dir.path()).await {
            Ok(pool) => assert!(pool.is_closed(), "a closed handle handed out a live pool"),
            Err(error) => assert!(
                error.to_string().contains("closed before this use"),
                "unexpected error: {error}"
            ),
        }
    }
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
            columns
                .iter()
                .any(|column| column.table == "artifact_cache_entries"
                    && column.name == "provenance"),
            "the parser must see artifact_cache_entries.provenance"
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

        // A database from before `provenance` existed on that table.
        let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .expect("open the old database");
        sqlx::query(
            "CREATE TABLE artifact_cache_entries (\
                 rustc_version TEXT NOT NULL, \
                 cache_key TEXT NOT NULL, \
                 relative_dir TEXT NOT NULL, \
                 size_bytes INTEGER NOT NULL, \
                 last_accessed_ms INTEGER NOT NULL, \
                 oci_reference TEXT NOT NULL, \
                 oci_digest TEXT NOT NULL, \
                 compile_key TEXT NOT NULL DEFAULT '', \
                 crate_name TEXT NOT NULL DEFAULT '', \
                 crate_version TEXT NOT NULL DEFAULT '', \
                 c_metadata TEXT NOT NULL DEFAULT '', \
                 features_json TEXT NOT NULL DEFAULT '', \
                 dependency_c_metadata_json TEXT NOT NULL DEFAULT '[]', \
                 dependency_compile_keys_json TEXT NOT NULL DEFAULT '[]', \
                 compile_millis INTEGER NOT NULL DEFAULT 0, \
                 target TEXT NOT NULL DEFAULT '', \
                 profile_json TEXT NOT NULL DEFAULT '{}', \
                 emit_json TEXT NOT NULL DEFAULT '[]', \
                 kind_json TEXT NOT NULL DEFAULT '\"Rlib\"', \
                 crate_types_json TEXT NOT NULL DEFAULT '[]', \
                 verified_marker_version INTEGER, \
                 verified_marker_policy TEXT, \
                 PRIMARY KEY (rustc_version, cache_key))",
        )
        .execute(&pool)
        .await
        .expect("create the old table");
        pool.close().await;

        let pool = connect_pool(cache_dir.path())
            .await
            .expect("open the database through the migration");
        let columns = sqlx::query_scalar::<_, String>(
            "SELECT name FROM pragma_table_info('artifact_cache_entries')",
        )
        .fetch_all(&pool)
        .await
        .expect("read the migrated columns");
        assert!(
            columns.iter().any(|column| column == "provenance"),
            "the missing column must be added: {columns:?}"
        );
        sqlx::query_scalar::<_, String>("SELECT relative_dir FROM artifact_cache_entries LIMIT 1")
            .fetch_optional(&pool)
            .await
            .expect("the table stays usable after the migration");
    }

    /// The four `artifact_cache_native_*` tables are gone from the schema
    /// (stow#640) — a database carrying them sheds them on open.
    #[tokio::test]
    async fn opening_a_database_drops_the_native_tables() {
        let cache_dir = tempfile::tempdir().expect("temp dir");
        let path = super::state_db_path(cache_dir.path());
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create parent");

        let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .expect("open the old database");
        for table in [
            "artifact_cache_native_static_libs",
            "artifact_cache_native_directives",
            "artifact_cache_native_dep_env_vars",
            "artifact_cache_native_out_dir_files",
        ] {
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "CREATE TABLE {table} (marker TEXT)"
            )))
            .execute(&pool)
            .await
            .expect("create an old native table");
        }
        pool.close().await;

        let pool = connect_pool(cache_dir.path())
            .await
            .expect("open the database through the schema");
        let tables =
            sqlx::query_scalar::<_, String>("SELECT name FROM sqlite_master WHERE type = 'table'")
                .fetch_all(&pool)
                .await
                .expect("list tables");
        for table in [
            "artifact_cache_native_static_libs",
            "artifact_cache_native_directives",
            "artifact_cache_native_dep_env_vars",
            "artifact_cache_native_out_dir_files",
        ] {
            assert!(
                !tables.iter().any(|name| name == table),
                "{table} must be dropped: {tables:?}"
            );
        }
    }
}
