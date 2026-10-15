use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous};
use stow_types::error::Context;
use tokio::sync::OnceCell;

const STATE_DB_FILE_NAME: &str = "state-v3.sqlite3";

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
    /// opened becomes closed without opening anything. Before the pool
    /// lets go, a WAL grown past [`WAL_RESET_BYTES`] is truncated — the
    /// close is the one place a database whose processes are each its
    /// only connection ever sheds it (stow#687).
    pub async fn close(&self) {
        if let Some(pool) = self.0.get_or_init(|| async { None }).await {
            // Logged and not returned: the close runs after the
            // command's result is decided, that result is the
            // caller's, and the next close meets the same WAL and
            // tries again.
            if let Err(error) = reset_grown_wal(pool).await {
                tracing::warn!(error = %error, "the state database's WAL was not reset");
            }
            pool.close().await;
        }
    }
}

/// The state database's one schema — the shape every database at
/// `state_db_path` was created with. A schema change is a new database,
/// never a repair of the old one.
const SCHEMA_SQL: &str = include_str!("state-db-schema.sql");

/// The schema's identity — the first four bytes of the file's blake3
/// digest as a nonzero `i32`, stamped into `PRAGMA user_version` when a
/// database is created and compared on every open. `| 1` keeps the value
/// off `0`, which is what an unstamped database reads.
fn schema_identity() -> i32 {
    let digest = blake3::hash(SCHEMA_SQL.as_bytes());
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&digest.as_bytes()[..4]);
    i32::from_le_bytes(bytes) | 1
}

/// Open the state `SQLite` pool. Callers go through [`StateDb::pool`] —
/// it opens once per process, so the hot path doesn't pay schema
/// work per invocation, and it is the handle the process closes.
///
/// The database carries the schema's identity in `user_version`, stamped
/// at creation. An open whose stamp differs — including a database an
/// older stow created before the stamp existed — fails fast and names
/// the remedy (`stow clean` removes the directory whole): the state is
/// a cache, so a shape the build does not recognize is discarded
/// whole, never repaired in place. Only a provably fresh database — no
/// user tables and an unstamped `user_version` — gets the schema and
/// the stamp.
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
    let stamped: i32 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&pool)
        .await
        .wrap_err_with(|| format!("read schema identity of {}", path.display()))?;
    if stamped == schema_identity() {
        return Ok(pool);
    }
    // Wrappers of one cold build open a fresh database at once: the
    // check and the creation share one write transaction, so a second
    // opener waits for the first and then reads its stamp.
    let mut transaction = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .wrap_err_with(|| format!("lock state db {} for creation", path.display()))?;
    let stamped: i32 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut *transaction)
        .await
        .wrap_err_with(|| format!("read schema identity of {}", path.display()))?;
    if stamped == schema_identity() {
        transaction
            .commit()
            .await
            .wrap_err_with(|| format!("release state db {}", path.display()))?;
        return Ok(pool);
    }
    let user_tables: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_master \
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    )
    .fetch_one(&mut *transaction)
    .await
    .wrap_err_with(|| format!("list tables in {}", path.display()))?;
    if stamped != 0 || user_tables != 0 {
        return Err(stow_types::stow_error!(
            "the state database {} was created by a stow whose schema \
             does not match this build — remove it with `stow clean`",
            path.display()
        ));
    }
    sqlx::raw_sql(SCHEMA_SQL)
        .execute(&mut *transaction)
        .await
        .wrap_err_with(|| format!("initialize state db schema {}", path.display()))?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "PRAGMA user_version = {}",
        schema_identity()
    )))
    .execute(&mut *transaction)
    .await
    .wrap_err_with(|| format!("stamp state db schema identity {}", path.display()))?;
    transaction
        .commit()
        .await
        .wrap_err_with(|| format!("commit state db schema {}", path.display()))?;
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
/// next opener needs (stow#682); the WAL it leaves is bounded by
/// [`StateDb::close`], which truncates it once it reaches
/// [`WAL_RESET_BYTES`].
async fn keep_wal_on_close(connection: &mut sqlx::SqliteConnection) -> Result<(), sqlx::Error> {
    let mut handle = connection.lock_handle().await?;
    // SAFETY: `handle` is this live connection's `sqlite3*`, locked for
    // the duration of the call, and `SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE`
    // takes an `int` and a nullable `int*`.
    let code = unsafe {
        sqlite3_db_config(
            handle.as_raw_handle().as_ptr().cast(),
            SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            1 as std::ffi::c_int,
            std::ptr::null_mut::<std::ffi::c_int>(),
        )
    };
    if code == 0 {
        Ok(())
    } else {
        Err(sqlx::Error::Protocol(format!(
            "sqlite3_db_config(SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE) returned {code}"
        )))
    }
}

/// `SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE`, from `sqlite3.h`.
const SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE: std::ffi::c_int = 1006;

// The one `SQLite` entry point sqlx does not expose, from the library
// sqlx links. Declared here rather than taken from `libsqlite3-sys`: only
// one crate may link `sqlite3`, the workspace builds against a pinned sqlx
// revision that allows `libsqlite3-sys` 0.38 while the released sqlx this
// crate is packaged against stops below it, and a direct dependency is
// locked to the workspace's version — so `cargo package` cannot resolve
// the two together. It moves to the crate's binding when that pin goes.
unsafe extern "C" {
    fn sqlite3_db_config(db: *mut std::ffi::c_void, op: std::ffi::c_int, ...) -> std::ffi::c_int;
}

/// The WAL size at which a close truncates it.
///
/// A WAL that outlives every connection grows forever: since stow#682
/// the last close leaves it in place, and across processes that are
/// each the database's only connection nothing ever restarts it. The
/// first connection to a WAL database takes `-shm` exclusively, wipes
/// it and rebuilds the index by reading the whole WAL — and the count
/// of frames already copied into the database lives in `-shm` and is
/// lost with it, so the next writer appends instead of starting the
/// file over. The automatic checkpoint inside a commit only copies
/// frames; it never restarts the file either. And once the WAL is past
/// that checkpoint's 1000 pages, every commit of every process runs it
/// over the whole file again.
///
/// Measured over 1500 processes in a row on one database — open,
/// schema, one transaction, close; run 38403129194 — the WAL reaches
/// 22 MiB and each process slows with it, Windows from 14 ms to
/// 42–46 ms and Linux from 2.7 ms to 9.1 ms (stow#687). The bound has
/// to stay below the automatic checkpoint's 1000 pages, about 4 MiB,
/// so that checkpoint is never the one that runs; truncating at 1 MiB
/// keeps Windows at 13.9–14.6 ms and Linux at 2.8 ms with 21
/// truncations in 1500 processes. A 4 MiB bound is slower
/// (15.9–16.6 ms, 3.1 ms) because the automatic checkpoint is reached
/// first, and 256 KiB costs the same as 1 MiB with four times the
/// truncations.
const WAL_RESET_BYTES: u64 = 1 << 20;

/// The database's path with `-wal` appended — the file `SQLite` keeps
/// the write-ahead log in.
fn wal_path(database: &Path) -> PathBuf {
    let mut wal = database.as_os_str().to_os_string();
    wal.push("-wal");
    PathBuf::from(wal)
}

/// Truncate the WAL if it has reached [`WAL_RESET_BYTES`], through a
/// truncating checkpoint on one of the pool's connections.
async fn reset_grown_wal(pool: &SqlitePool) -> stow_types::error::Result<()> {
    // The database's path is the pool's own: the close has no cache
    // directory to rebuild it from.
    let wal = wal_path(pool.connect_options().get_filename());
    let metadata = match async_fs::metadata(&wal).await {
        Ok(metadata) => metadata,
        // No WAL is nothing to reset.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).wrap_err_with(|| format!("stat {}", wal.display())),
    };
    if metadata.len() < WAL_RESET_BYTES {
        return Ok(());
    }

    let mut connection = pool
        .acquire()
        .await
        .wrap_err_with(|| format!("acquire a connection to reset {}", wal.display()))?;
    // A truncating checkpoint waits for other connections' readers and
    // writer through the busy handler; a process on its way out must
    // not wait behind another one, and with no handler the checkpoint
    // copies what it can and reports busy instead.
    sqlx::query("PRAGMA busy_timeout = 0")
        .execute(&mut *connection)
        .await
        .wrap_err_with(|| format!("disarm the busy timeout on {}", wal.display()))?;
    let (busy, _log, _checkpointed): (i64, i64, i64) =
        sqlx::query_as("PRAGMA wal_checkpoint(TRUNCATE)")
            .fetch_one(&mut *connection)
            .await
            .wrap_err_with(|| format!("checkpoint {}", wal.display()))?;
    if busy != 0 {
        // Another connection held the WAL; it stays grown, and the
        // next close meets it and tries again.
        tracing::debug!(
            wal_bytes = metadata.len(),
            "the state database's WAL stayed grown"
        );
    }
    Ok(())
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
    use std::str::FromStr;
    use std::time::Duration;

    use sqlx::sqlite::SqliteConnectOptions;
    use sqlx::{ConnectOptions, Connection, SqlitePool};

    use super::{StateDb, WAL_RESET_BYTES, state_db_path, wal_path};

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
        let wal = wal_path(&state_db_path(cache_dir.path()));
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

    /// Write at least `bytes` of WAL in one transaction — `wal_filler`
    /// rows of a 64 KiB `randomblob` apiece — and return the row count.
    async fn grow_wal(pool: &SqlitePool, bytes: u64) -> u64 {
        let mut transaction = pool.begin().await.expect("begin the filler transaction");
        sqlx::query("CREATE TABLE IF NOT EXISTS wal_filler (v BLOB NOT NULL)")
            .execute(&mut *transaction)
            .await
            .expect("create the filler table");
        let (mut written, mut rows) = (0, 0);
        while written < bytes {
            sqlx::query("INSERT INTO wal_filler (v) VALUES (randomblob(65536))")
                .execute(&mut *transaction)
                .await
                .expect("insert a filler row");
            written += 65536;
            rows += 1;
        }
        transaction.commit().await.expect("commit the filler rows");
        rows
    }

    /// A WAL past [`WAL_RESET_BYTES`] is truncated as the close lets go
    /// of the database — and its frames reach the database first
    /// (stow#687).
    #[tokio::test]
    async fn a_wal_past_the_bound_is_truncated_at_close() {
        let cache_dir = tempfile::tempdir().expect("temp dir");
        let wal = wal_path(&state_db_path(cache_dir.path()));
        let state_db = StateDb::default();
        let pool = state_db
            .pool(cache_dir.path())
            .await
            .expect("open the state database");
        let rows = grow_wal(&pool, 2 * WAL_RESET_BYTES).await;
        assert!(
            std::fs::metadata(&wal).expect("the WAL exists").len() >= WAL_RESET_BYTES,
            "the filler must grow the WAL past the bound"
        );

        state_db.close().await;
        assert_eq!(
            std::fs::metadata(&wal)
                .expect("the truncated WAL exists")
                .len(),
            0,
            "the close must truncate a grown WAL"
        );

        let reopened = StateDb::default();
        let pool = reopened
            .pool(cache_dir.path())
            .await
            .expect("reopen the state database");
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM wal_filler")
            .fetch_one(&pool)
            .await
            .expect("count the filler rows");
        assert_eq!(
            u64::try_from(count).expect("a row count is nonnegative"),
            rows,
            "the checkpoint must land the filler rows in the database"
        );
    }

    /// Back-to-back sole connections keep the WAL under the bound plus
    /// one round's writes (stow#687).
    #[tokio::test]
    async fn the_wal_stays_bounded_across_sole_connections() {
        let cache_dir = tempfile::tempdir().expect("temp dir");
        let wal = wal_path(&state_db_path(cache_dir.path()));
        for round in 0..40 {
            let state_db = StateDb::default();
            let pool = state_db
                .pool(cache_dir.path())
                .await
                .expect("open the state database");
            grow_wal(&pool, 128 * 1024).await;
            state_db.close().await;

            let len = std::fs::metadata(&wal).expect("the WAL exists").len();
            assert!(
                len < WAL_RESET_BYTES + 512 * 1024,
                "round {round}: the WAL grew to {len} bytes"
            );
        }
    }

    /// A truncating checkpoint that meets another connection's read
    /// reports busy instead of waiting on it: the close is a process on
    /// its way out, and a read snapshot may outlive it (stow#687).
    ///
    /// The reader's snapshot predates the filler and reads the database
    /// file alone. A checkpoint copies every frame up to the oldest
    /// snapshot into the database and syncs it before it reports busy,
    /// and a hosted Windows runner's disk stalls for seconds at a time:
    /// with the snapshot at the WAL's end the close copied 2 MiB and took
    /// past 10 s, and a snapshot past only the schema's frames still left
    /// syncs that took 6.5 s (stow#728). With the WAL backfilled before
    /// the snapshot, the checkpoint meets the reader's lock before it
    /// copies or syncs anything, so the bound times the wait alone — 2 s,
    /// below sqlx's default 5 s busy timeout.
    #[tokio::test]
    async fn a_close_beside_another_connections_read_does_not_wait() {
        let cache_dir = tempfile::tempdir().expect("temp dir");
        let state_db = StateDb::default();
        let pool = state_db
            .pool(cache_dir.path())
            .await
            .expect("open the state database");
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&pool)
            .await
            .expect("backfill the schema's frames");

        let path = state_db_path(cache_dir.path());
        let mut reader = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
            .expect("connect options for the same database")
            .connect()
            .await
            .expect("a second connection to the same database");
        sqlx::query("BEGIN")
            .execute(&mut reader)
            .await
            .expect("begin the reader's transaction");
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sqlite_master")
            .fetch_one(&mut reader)
            .await
            .expect("hold a read snapshot that predates the filler");
        grow_wal(&pool, 2 * WAL_RESET_BYTES).await;

        tokio::time::timeout(Duration::from_secs(2), state_db.close())
            .await
            .expect("the close must not wait behind another connection's read");
        let wal_len = std::fs::metadata(wal_path(&path))
            .expect("the WAL exists")
            .len();
        assert!(
            wal_len >= WAL_RESET_BYTES,
            "the close truncated a WAL another connection was reading: {wal_len} bytes"
        );

        sqlx::query("ROLLBACK")
            .execute(&mut reader)
            .await
            .expect("end the reader's transaction");
        reader.close().await.expect("close the second connection");
    }
}

#[cfg(test)]
mod schema_tests {
    use sqlx::sqlite::SqliteConnectOptions;
    use sqlx::{ConnectOptions, Connection};
    use std::str::FromStr;

    use super::{connect_pool, schema_identity, state_db_path};

    /// A raw second connection to the same file, for stamping a
    /// `user_version` the schema did not write.
    async fn raw_connection(path: &std::path::Path) -> sqlx::SqliteConnection {
        SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
            .expect("connect options")
            .create_if_missing(true)
            .connect()
            .await
            .expect("a raw connection to the database")
    }

    /// A fresh database gets the schema and the identity stamp, and a
    /// later open takes the stamped path straight through.
    #[tokio::test]
    async fn a_fresh_database_is_created_and_stamped_and_reopens() {
        let cache_dir = tempfile::tempdir().expect("temp dir");
        let pool = connect_pool(cache_dir.path())
            .await
            .expect("create the database");
        let stamped: i32 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&pool)
            .await
            .expect("read the stamp");
        assert_eq!(stamped, schema_identity(), "creation stamps the schema");
        let tables: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM sqlite_master \
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        )
        .fetch_one(&pool)
        .await
        .expect("count tables");
        assert!(tables > 0, "the schema's tables were created");
        pool.close().await;

        connect_pool(cache_dir.path())
            .await
            .expect("reopen the stamped database");
    }

    /// Openers racing on an empty database: every open succeeds, one of
    /// them creates the schema, the rest read its stamp. The file is
    /// switched to WAL first — the journal-mode switch is the file's
    /// own first write and is not what this covers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_opens_of_an_empty_database_create_it_once() {
        let cache_dir = tempfile::tempdir().expect("temp dir");
        let path = state_db_path(cache_dir.path());
        let empty = sqlx::SqlitePool::connect(&format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .expect("create the empty file");
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&empty)
            .await
            .expect("switch the empty file to WAL");
        empty.close().await;
        let opens = (0..8).map(|_| connect_pool(cache_dir.path()));
        for pool in futures_util::future::join_all(opens).await {
            let pool = pool.expect("every concurrent open succeeds");
            let stamped: i32 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&pool)
                .await
                .expect("read the stamp");
            assert_eq!(stamped, schema_identity());
            pool.close().await;
        }
    }

    /// A database whose stamp is not this schema's — one an older stow
    /// wrote before the stamp existed, or any other shape — fails fast
    /// naming the file and the remedy; nothing repairs it in place.
    #[tokio::test]
    async fn a_differently_stamped_database_fails_to_clean() {
        let cache_dir = tempfile::tempdir().expect("temp dir");
        let path = state_db_path(cache_dir.path());
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create parent");

        // The old shape: tables on disk, no identity stamp — exactly what
        // a pre-`user_version` stow leaves.
        let mut conn = raw_connection(&path).await;
        sqlx::query("CREATE TABLE old_shape (v TEXT)")
            .execute(&mut conn)
            .await
            .expect("create an old-shaped table");
        conn.close().await.expect("close the raw connection");

        let error = connect_pool(cache_dir.path())
            .await
            .expect_err("an unstamped database with tables must fail");
        assert!(
            error
                .to_string()
                .contains(path.to_str().expect("utf8 path")),
            "the error names the database: {error}"
        );
        assert!(
            error.to_string().contains("stow clean"),
            "the error names the remedy: {error}"
        );

        // `stow clean` removes the cache directory whole — it never opens
        // the database — so the same path is what recovers this state.
        std::fs::remove_dir_all(cache_dir.path())
            .expect("remove the cache dir, as stow clean does");
        connect_pool(cache_dir.path())
            .await
            .expect("after the clean, a fresh database is created");
        assert!(state_db_path(cache_dir.path()).exists());
    }
}
