use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous};
use stow_types::error::Context;
use stow_types::public_cache::Reach;

const STATE_DB_FILE_NAME: &str = "state-v3.sqlite3";
pub const TIER_CATALOG_FILE_NAME: &str = "catalog-v1.sqlite3";

/// One of the three self-contained artifact cache directories under
/// `~/.stow` (`$STOW_CACHE_DIR`), ordered in eviction priority from first
/// evicted (`CratesIo`) to last evicted (`Local`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CacheTier {
    /// Downloaded bundles from the signed public cache (`~/.stow/crates-io/`).
    CratesIo,
    /// Locally compiled `Reach::Public` `crates.io` misses awaiting public
    /// publication (`~/.stow/local-crates-io/`).
    LocalCratesIo,
    /// Locally compiled `Reach::LocalOnly` units and `cc/` objects that
    /// never enter the public cache (`~/.stow/local/`).
    Local,
}

impl CacheTier {
    /// Every tier in eviction order (`CratesIo`, `LocalCratesIo`, `Local`).
    pub const ALL: [Self; 3] = [Self::CratesIo, Self::LocalCratesIo, Self::Local];

    /// Subdirectory name under `$STOW_CACHE_DIR`.
    #[must_use]
    pub const fn dir_name(self) -> &'static str {
        match self {
            Self::CratesIo => "crates-io",
            Self::LocalCratesIo => "local-crates-io",
            Self::Local => "local",
        }
    }

    /// Dense array slot (`0..3`) matching [`Self::ALL`].
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::CratesIo => 0,
            Self::LocalCratesIo => 1,
            Self::Local => 2,
        }
    }

    /// Which local tier a locally compiled rustc unit belongs to.
    #[must_use]
    pub const fn for_local_reach(reach: Reach) -> Self {
        match reach {
            Reach::Public => Self::LocalCratesIo,
            Reach::LocalOnly => Self::Local,
        }
    }
}

pub fn state_db_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join(STATE_DB_FILE_NAME)
}

#[must_use]
pub fn tier_dir(cache_dir: &Path, tier: CacheTier) -> PathBuf {
    cache_dir.join(tier.dir_name())
}

#[must_use]
pub fn tier_db_path(cache_dir: &Path, tier: CacheTier) -> PathBuf {
    tier_dir(cache_dir, tier).join(TIER_CATALOG_FILE_NAME)
}

/// Whether a top-level file name in `cache_dir` belongs to the SQLite state
/// database (`state-v3.sqlite3` and its WAL / shared-memory sidecars).
#[must_use]
pub fn is_state_db_file(name: &str) -> bool {
    matches!(
        name,
        "state-v3.sqlite3" | "state-v3.sqlite3-wal" | "state-v3.sqlite3-shm"
    )
}

/// Delete `state-v3.sqlite3` and its WAL/SHM sidecars without opening SQLite,
/// used when `stow clean` recovers a state database created under a different
/// schema version.
pub async fn remove_state_db_files(cache_dir: &Path) -> stow_types::error::Result<()> {
    for suffix in ["", "-wal", "-shm"] {
        let path = cache_dir.join(format!("{STATE_DB_FILE_NAME}{suffix}"));
        remove_state_db_file(&path).await?;
    }
    Ok(())
}

async fn remove_state_db_file(path: &Path) -> stow_types::error::Result<()> {
    #[cfg(windows)]
    {
        // `sqlx-sqlite`'s `SqliteConnectOptions::connect` runs connect-time
        // pragmas with `?` without awaiting `conn.close()`, so when a corrupt
        // database fails `connect_with`, its background `ConnectionWorker`
        // thread may still be calling `sqlite3_close()` for a few
        // milliseconds. Windows rejects `DeleteFile` with
        // `ERROR_SHARING_VIOLATION` (32) until that handle closes.
        const ERROR_SHARING_VIOLATION: i32 = 32;
        const MAX_RETRIES: usize = 20;
        const RETRY_DELAY: Duration = Duration::from_millis(25);
        let mut attempt = 0;
        loop {
            match async_fs::remove_file(path).await {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error)
                    if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION)
                        && attempt < MAX_RETRIES =>
                {
                    attempt += 1;
                    tokio::time::sleep(RETRY_DELAY).await;
                }
                Err(error) => {
                    return Err(error).wrap_err_with(|| format!("remove {}", path.display()));
                }
            }
        }
    }
    #[cfg(not(windows))]
    {
        match async_fs::remove_file(path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).wrap_err_with(|| format!("remove {}", path.display())),
        }
    }
}

/// Clear every ephemeral host-state row (`build_directories`,
/// `materialized_outputs`, `negative_cache_entries` and
/// `lockfile_graph_cache`) while keeping `crate_stats`, `metadata_values`,
/// `circuit_state` and `link_resolution_cache` intact.
pub async fn clear_cached_entries(pool: &SqlitePool) -> stow_types::error::Result<()> {
    let mut tx = pool
        .begin()
        .await
        .wrap_err("begin state database clean transaction")?;
    for statement in [
        "DELETE FROM build_directories",
        "DELETE FROM materialized_outputs",
        "DELETE FROM negative_cache_entries",
        "DELETE FROM lockfile_graph_cache",
    ] {
        sqlx::query(statement)
            .execute(&mut *tx)
            .await
            .wrap_err_with(|| format!("execute `{statement}`"))?;
    }
    tx.commit()
        .await
        .wrap_err("commit state database clean transaction")
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
}

#[cfg(unix)]
async fn file_identity(path: &Path) -> std::io::Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = async_fs::metadata(path).await?;
    Ok(FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}

#[cfg(windows)]
type FileIdentity = Arc<same_file::Handle>;

#[cfg(windows)]
async fn file_identity(path: &Path) -> std::io::Result<FileIdentity> {
    let owned = path.to_path_buf();
    tokio::task::spawn_blocking(move || same_file::Handle::from_path(owned).map(Arc::new))
        .await
        .map_err(std::io::Error::other)?
}

#[derive(Debug, Default)]
enum PoolSlot {
    #[default]
    Unopened,
    Open {
        pool: SqlitePool,
        identity: FileIdentity,
    },
    Closed,
}

#[derive(Debug, Default)]
struct StateDbInner {
    host: tokio::sync::Mutex<PoolSlot>,
    tiers: [tokio::sync::Mutex<PoolSlot>; 3],
}

/// The process's one handle on the host state database and the three
/// self-contained tier catalogs (`crates-io/`, `local-crates-io/`, `local/`).
///
/// The command entry point creates it, every config the process loads
/// carries a clone, and the entry point closes it once the command's
/// future has finished. One handle, because a process that opened a pool
/// per loaded config held connections nothing could enumerate, and a
/// connection still open when the process exits breaks the next one on
/// Windows (stow#682).
#[derive(Debug, Clone, Default)]
pub struct StateDb(Arc<StateDbInner>);

impl StateDb {
    /// A handle closed from the start, for a process that has no state
    /// database (`stow-build`, stow#682).
    pub fn closed() -> Self {
        Self(Arc::new(StateDbInner {
            host: tokio::sync::Mutex::new(PoolSlot::Closed),
            tiers: std::array::from_fn(|_| tokio::sync::Mutex::new(PoolSlot::Closed)),
        }))
    }

    /// The host runtime pool (`state-v3.sqlite3`), opened on first call and
    /// shared by every later one while the underlying file on disk stays the
    /// same inode/handle.
    ///
    /// # Errors
    ///
    /// Whatever opening the database fails with, and any use after
    /// [`Self::close`].
    pub async fn pool(&self, cache_dir: &Path) -> stow_types::error::Result<SqlitePool> {
        let mut slot = self.0.host.lock().await;
        let path = state_db_path(cache_dir);
        match &*slot {
            PoolSlot::Closed => {
                return Err(stow_types::stow_error!(
                    "the state database was closed before this use"
                ));
            }
            PoolSlot::Open { pool, identity } => {
                if let Ok(current) = file_identity(&path).await
                    && current == *identity
                {
                    return Ok(pool.clone());
                }
                pool.close().await;
                *slot = PoolSlot::Unopened;
            }
            PoolSlot::Unopened => {}
        }
        let pool = connect_pool(cache_dir).await?;
        let identity = file_identity(&path)
            .await
            .wrap_err_with(|| format!("identify {}", path.display()))?;
        *slot = PoolSlot::Open {
            pool: pool.clone(),
            identity,
        };
        drop(slot);
        Ok(pool)
    }

    /// The `SQLite` pool of `tier`'s self-contained catalog
    /// (`<cache_dir>/<tier>/catalog-v1.sqlite3`), creating it on first write
    /// and reopening if the file on disk was removed or replaced.
    ///
    /// # Errors
    ///
    /// Whatever opening the catalog fails with, and any use after
    /// [`Self::close`].
    pub async fn tier_pool(
        &self,
        cache_dir: &Path,
        tier: CacheTier,
    ) -> stow_types::error::Result<SqlitePool> {
        let mut slot = self.0.tiers[tier.index()].lock().await;
        let path = tier_db_path(cache_dir, tier);
        match &*slot {
            PoolSlot::Closed => {
                return Err(stow_types::stow_error!(
                    "the state database was closed before this use"
                ));
            }
            PoolSlot::Open { pool, identity } => {
                if let Ok(current) = file_identity(&path).await
                    && current == *identity
                {
                    return Ok(pool.clone());
                }
                pool.close().await;
                *slot = PoolSlot::Unopened;
            }
            PoolSlot::Unopened => {}
        }
        let pool = connect_tier_pool(cache_dir, tier).await?;
        let identity = file_identity(&path)
            .await
            .wrap_err_with(|| format!("identify {}", path.display()))?;
        *slot = PoolSlot::Open {
            pool: pool.clone(),
            identity,
        };
        drop(slot);
        Ok(pool)
    }

    /// Open `tier`'s catalog only when `<cache_dir>/<tier>/catalog-v1.sqlite3`
    /// already exists on disk, leaving the slot unopened when absent so
    /// read-only probes never create empty tier directories and a later store
    /// can still create the catalog.
    ///
    /// # Errors
    ///
    /// Stat/open failures, schema mismatches, and any use after [`Self::close`].
    pub async fn existing_tier_pool(
        &self,
        cache_dir: &Path,
        tier: CacheTier,
    ) -> stow_types::error::Result<Option<SqlitePool>> {
        let mut slot = self.0.tiers[tier.index()].lock().await;
        let path = tier_db_path(cache_dir, tier);
        match &*slot {
            PoolSlot::Closed => {
                return Err(stow_types::stow_error!(
                    "the state database was closed before this use"
                ));
            }
            PoolSlot::Open { pool, identity } => match file_identity(&path).await {
                Ok(current) if current == *identity => return Ok(Some(pool.clone())),
                Ok(_) => {
                    pool.close().await;
                    *slot = PoolSlot::Unopened;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    pool.close().await;
                    *slot = PoolSlot::Unopened;
                    return Ok(None);
                }
                Err(error) => {
                    return Err(error).wrap_err_with(|| format!("stat {}", path.display()));
                }
            },
            PoolSlot::Unopened => match file_identity(&path).await {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => {
                    return Err(error).wrap_err_with(|| format!("stat {}", path.display()));
                }
            },
        }
        let pool = connect_tier_pool(cache_dir, tier).await?;
        let identity = file_identity(&path)
            .await
            .wrap_err_with(|| format!("identify {}", path.display()))?;
        *slot = PoolSlot::Open {
            pool: pool.clone(),
            identity,
        };
        drop(slot);
        Ok(Some(pool))
    }

    /// Close every opened pool and refuse every later open, truncating any
    /// WAL grown past [`WAL_RESET_BYTES`] (stow#687).
    pub async fn close(&self) {
        self.close_inner(false).await;
    }

    /// Checkpoint and truncate the WAL of every opened pool regardless of
    /// size, then close every pool — used when draining the daemon before
    /// archiving tier directories.
    pub async fn checkpoint_and_close(&self) {
        self.close_inner(true).await;
    }

    /// Close only the per-tier pools (`crates-io/`, `local-crates-io/`,
    /// `local/`) and leave them reopenable so `stow clean` can remove tier
    /// directories on Windows while leaving the host `state-v3.sqlite3`
    /// handle usable.
    pub async fn close_tiers(&self) {
        let [t0, t1, t2] = &self.0.tiers;
        tokio::join!(
            reset_pool_slot(t0),
            reset_pool_slot(t1),
            reset_pool_slot(t2),
        );
    }

    async fn close_inner(&self, force_truncate: bool) {
        let [t0, t1, t2] = &self.0.tiers;
        tokio::join!(
            close_pool_slot(&self.0.host, force_truncate),
            close_pool_slot(t0, force_truncate),
            close_pool_slot(t1, force_truncate),
            close_pool_slot(t2, force_truncate),
        );
    }
}

async fn reset_pool_slot(mutex: &tokio::sync::Mutex<PoolSlot>) {
    let mut slot = mutex.lock().await;
    if let PoolSlot::Open { pool, .. } = std::mem::replace(&mut *slot, PoolSlot::Unopened) {
        pool.close().await;
    }
}

async fn close_pool_slot(mutex: &tokio::sync::Mutex<PoolSlot>, force_truncate: bool) {
    let mut slot = mutex.lock().await;
    if let PoolSlot::Open { pool, .. } = std::mem::replace(&mut *slot, PoolSlot::Closed) {
        let outcome = if force_truncate {
            truncate_wal(&pool).await
        } else {
            reset_grown_wal(&pool).await
        };
        if let Err(error) = outcome {
            tracing::warn!(error = %error, "the state database's WAL was not reset");
        }
        pool.close().await;
    }
}

/// Checkpoint and truncate every existing catalog in `cache_dir` so on-disk
/// `catalog-v1.sqlite3` files hold every committed frame with zero-length
/// `-wal` sidecars before archiving.
pub async fn checkpoint_existing_databases(cache_dir: &Path) -> stow_types::error::Result<()> {
    let state_db = StateDb::default();
    if state_db_path(cache_dir).exists() {
        let _ = state_db.pool(cache_dir).await?;
    }
    for tier in CacheTier::ALL {
        let _ = state_db.existing_tier_pool(cache_dir, tier).await?;
    }
    state_db.checkpoint_and_close().await;
    Ok(())
}

/// The host state database's one schema.
const SCHEMA_SQL: &str = include_str!("state-db-schema.sql");
/// Each tier catalog's self-contained schema.
const TIER_SCHEMA_SQL: &str = include_str!("tier-catalog-schema.sql");

/// The schema's identity — the first four bytes of the file's blake3
/// digest as a nonzero `i32`, stamped into `PRAGMA user_version` when a
/// database is created and compared on every open. `| 1` keeps the value
/// off `0`, which is what an unstamped database reads.
fn schema_identity_of(sql: &str) -> i32 {
    let digest = blake3::hash(sql.as_bytes());
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&digest.as_bytes()[..4]);
    i32::from_le_bytes(bytes) | 1
}

#[cfg(test)]
fn schema_identity() -> i32 {
    schema_identity_of(SCHEMA_SQL)
}

#[tracing::instrument(name = "stow.sqlite.connect", skip_all)]
async fn connect_pool(cache_dir: &Path) -> stow_types::error::Result<SqlitePool> {
    connect_db_at(&state_db_path(cache_dir), SCHEMA_SQL).await
}

#[tracing::instrument(name = "stow.sqlite.connect_tier", skip_all)]
async fn connect_tier_pool(
    cache_dir: &Path,
    tier: CacheTier,
) -> stow_types::error::Result<SqlitePool> {
    connect_db_at(&tier_db_path(cache_dir, tier), TIER_SCHEMA_SQL).await
}

/// Wait out concurrent writers when multiple daemons share one `cache_dir`
/// (e.g. containerized sessions sharing a host cache mount); sqlx's 5 s
/// default is too short under heavy parallel cold-cache writes.
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(30);

async fn connect_db_at(
    path: &Path,
    schema_sql: &'static str,
) -> stow_types::error::Result<SqlitePool> {
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
        .busy_timeout(SQLITE_BUSY_TIMEOUT)
        .foreign_keys(true);

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _| Box::pin(keep_wal_on_close(connection)))
        .connect_with(options)
        .await
        .wrap_err_with(|| format!("open state db {}", path.display()))?;
    match ensure_schema(&pool, path, schema_sql).await {
        Ok(()) => Ok(pool),
        Err(error) => {
            // A dropped pool closes its connection in the background, and
            // until it does Windows refuses to delete the file `stow clean`
            // is about to remove.
            pool.close().await;
            Err(error)
        }
    }
}

/// Accepts a database stamped with `schema_sql`'s identity, creates the
/// schema in an empty one, and refuses anything else.
async fn ensure_schema(
    pool: &SqlitePool,
    path: &Path,
    schema_sql: &'static str,
) -> stow_types::error::Result<()> {
    let expected = schema_identity_of(schema_sql);
    let stamped: i32 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(pool)
        .await
        .wrap_err_with(|| format!("read schema identity of {}", path.display()))?;
    if stamped == expected {
        return Ok(());
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
    if stamped == expected {
        transaction
            .commit()
            .await
            .wrap_err_with(|| format!("release state db {}", path.display()))?;
        return Ok(());
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
    sqlx::raw_sql(schema_sql)
        .execute(&mut *transaction)
        .await
        .wrap_err_with(|| format!("initialize state db schema {}", path.display()))?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "PRAGMA user_version = {expected}"
    )))
    .execute(&mut *transaction)
    .await
    .wrap_err_with(|| format!("stamp state db schema identity {}", path.display()))?;
    transaction
        .commit()
        .await
        .wrap_err_with(|| format!("commit state db schema {}", path.display()))?;
    Ok(())
}

/// Tell `SQLite` not to checkpoint the WAL when this connection is the
/// last one to close.
///
/// A process closes its connection before it exits (see [`StateDb`]),
/// and the last connection's close otherwise checkpoints the WAL and
/// syncs the database file — about 20 ms on macOS and Windows for a
/// process that is the database's only connection, which a short-lived
/// command is on every run. The close this leaves still
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
    truncate_wal(pool).await
}

/// Unconditionally run a non-blocking `PRAGMA wal_checkpoint(TRUNCATE)` on
/// `pool` when its `-wal` file exists.
async fn truncate_wal(pool: &SqlitePool) -> stow_types::error::Result<()> {
    let wal = wal_path(pool.connect_options().get_filename());
    let metadata = match async_fs::metadata(&wal).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).wrap_err_with(|| format!("stat {}", wal.display())),
    };

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

/// Test-only shim opening `tier`'s catalog directly without a [`StateDb`].
#[cfg(test)]
pub async fn connect_tier(
    cache_dir: &Path,
    tier: CacheTier,
) -> stow_types::error::Result<SqlitePool> {
    connect_tier_pool(cache_dir, tier).await
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

    /// Child-process helper for [`reusing_open_pool_preserves_sqlite_locks_across_external_reader_close`]:
    /// opens and closes `STOW_TEST_EXTERNAL_DB_PATH` in a separate OS process
    /// without `SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE` so `SQLite` queries the real
    /// kernel lock table rather than the parent process's in-memory `inodeList`.
    #[tokio::test]
    async fn external_reader_closes_database_in_subprocess() {
        let Some(path) = std::env::var_os("STOW_TEST_EXTERNAL_DB_PATH") else {
            return;
        };
        let mut reader = raw_connection(std::path::Path::new(&path)).await;
        let first_hits: i64 =
            sqlx::query_scalar("SELECT hits FROM crate_stats WHERE crate_name = 'itoa'")
                .fetch_one(&mut reader)
                .await
                .expect("external subprocess read");
        assert_eq!(first_hits, 1);
        reader
            .close()
            .await
            .expect("close external subprocess reader");
    }

    /// Reusing an open `StateDb` pool must never open and close a descriptor
    /// on the live `SQLite` file: on Unix, closing any descriptor to an inode
    /// cancels the process's POSIX `fcntl` advisory locks on that file, so an
    /// external process's close thinks it is the last holder, checkpoints, and
    /// unlinks `-wal` and `-shm` out from under the still-open pool.
    #[tokio::test]
    async fn reusing_open_pool_preserves_sqlite_locks_across_external_reader_close() {
        let cache_dir = tempfile::tempdir().expect("temp dir");
        let state_db = super::StateDb::default();
        let db_path = state_db_path(cache_dir.path());

        let pool = state_db.pool(cache_dir.path()).await.expect("first open");
        sqlx::query(
            "INSERT INTO crate_stats (crate_name, hits, misses, errors) VALUES ('itoa', 1, 0, 0)",
        )
        .execute(&pool)
        .await
        .expect("insert first row");

        let reused = state_db.pool(cache_dir.path()).await.expect("second open");

        let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "state_db::schema_tests::external_reader_closes_database_in_subprocess",
                "--nocapture",
            ])
            .env("STOW_TEST_EXTERNAL_DB_PATH", &db_path)
            .status()
            .expect("spawn external subprocess reader");
        assert!(status.success(), "external subprocess reader failed");

        sqlx::query(
            "INSERT INTO crate_stats (crate_name, hits, misses, errors) \
             VALUES ('once_cell', 1, 0, 0)",
        )
        .execute(&reused)
        .await
        .expect("insert second row");

        let mut verify = raw_connection(&db_path).await;
        let second_hits: Option<i64> =
            sqlx::query_scalar("SELECT hits FROM crate_stats WHERE crate_name = 'once_cell'")
                .fetch_optional(&mut verify)
                .await
                .expect("verify second row");
        verify.close().await.expect("close verify reader");
        state_db.close().await;

        assert_eq!(
            second_hits,
            Some(1),
            "writes on the kept pool must remain visible after an external process closes"
        );
    }
}
