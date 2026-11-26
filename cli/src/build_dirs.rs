//! Collecting the build directories stow placed (stow#1540).
//!
//! `stow setup` places each workspace's build directory under
//! `<cache>/build-dir/` (`{workspace-path-hash}`), where the files a serve
//! clones from the artifact cache live. A directory stow can attribute to
//! a workspace is removed once that workspace's manifest is gone or the
//! directory has not been built for the operator's idle age; deleting its
//! clones turns the cache entries they shared into reclaimable bytes
//! (stow#1539). A directory stow never recorded — one placed before the
//! records existed, or by a build with no driver — is attributed to
//! nothing, so only the idle rule applies to it, judged by the newest
//! modification time near its top.
//!
//! A directory is removed only while cargo's own build-directory lock is
//! held: cargo takes `.cargo-build-lock` exclusively in each
//! `<build-dir>[/<triple>]/<profile>` directory for the length of a build
//! (shared under `-Zfine-grain-locking`, which an exclusive try-lock also
//! finds held), so a lock that cannot be taken without blocking is a
//! running build, and its directory is skipped.

use std::collections::{BTreeSet, HashMap};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sqlx::SqlitePool;
use stow_types::error::{Context, Result};

use crate::file_lock::FileLock;
use crate::state_db::{db_int, duration_millis, now_millis};

/// The directory of the cache root that holds the per-workspace build
/// directories `stow setup` places.
pub const BUILD_DIR_PARENT: &str = "build-dir";

/// The file cargo locks a build directory's profile directory with.
const CARGO_BUILD_LOCK: &str = ".cargo-build-lock";

/// The prefix of a directory being deleted after it was moved aside.
const COLLECTING_PREFIX: &str = ".collecting-";

/// How often a daemon sweeps. A sweep reads the recorded rows and lists
/// `<cache>/build-dir/`, so its cost follows the number of workspaces,
/// never the number of compiles; one sweep an hour keeps that cost to a
/// few directory listings an hour and is far finer than the idle age,
/// which is days.
const SWEEP_INTERVAL: Duration = Duration::from_hours(1);

/// The `metadata_values` key holding when the last sweep started.
const LAST_SWEEP_KEY: &str = "build_dirs_collected_ms";

/// How deep below a build directory a modification time still shows
/// builds: `<profile>/deps`, `<profile>/.fingerprint`, and with a target
/// triple one level less than `<triple>/<profile>`'s own entries.
const ACTIVITY_DEPTH: usize = 2;

/// Why a directory is collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The workspace manifest it was recorded for no longer exists.
    WorkspaceGone,
    /// Not built, by the record or by its modification times, for longer
    /// than the idle age.
    Idle,
}

/// What a sweep did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Collected {
    /// The directories removed.
    pub removed: Vec<(PathBuf, Reason)>,
    /// The directories due for removal whose cargo lock is held: a build
    /// is running in them.
    pub locked: Vec<PathBuf>,
}

/// Record that `build_dir` was last built at `built_ms` for a workspace
/// of which `manifests` are member manifests. The set is added to what
/// earlier builds of the directory recorded, so builds of different
/// members, each seeing only its own, together name the workspace; an
/// empty `manifests` only refreshes the build time. One transaction per
/// call, which a session makes at its open and its end, never per compile.
///
/// # Errors
///
/// A path is not UTF-8, or the state database refuses the write.
pub async fn record(
    pool: &SqlitePool,
    build_dir: &Path,
    manifests: &[PathBuf],
    built_ms: u64,
) -> Result<()> {
    let build_dir = utf8(build_dir)?;
    let mut transaction = pool.begin().await?;
    let recorded: Option<String> =
        sqlx::query_scalar("SELECT manifests_json FROM build_directories WHERE build_dir = ?")
            .bind(build_dir)
            .fetch_optional(&mut *transaction)
            .await?;
    let mut set: BTreeSet<String> = match recorded {
        Some(json) => serde_json::from_str(&json).wrap_err("parse the recorded manifests")?,
        None => BTreeSet::new(),
    };
    for manifest in manifests {
        set.insert(utf8(manifest)?.to_owned());
    }
    sqlx::query(
        "INSERT INTO build_directories (build_dir, manifests_json, last_built_ms) \
         VALUES (?, ?, ?) \
         ON CONFLICT (build_dir) DO UPDATE SET \
             manifests_json = excluded.manifests_json, \
             last_built_ms = excluded.last_built_ms",
    )
    .bind(build_dir)
    .bind(serde_json::to_string(&set).wrap_err("encode the manifests")?)
    .bind(db_int::<_, i64>(built_ms, "build directory last built")?)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

/// Sweep when the last one is older than [`SWEEP_INTERVAL`]; `None` when
/// another sweep claimed the interval. The claim is one conditional write,
/// so concurrent sessions sweep once.
///
/// # Errors
///
/// As [`collect`].
pub async fn collect_if_due(
    pool: &SqlitePool,
    cache_dir: &Path,
    idle: Duration,
) -> Result<Option<Collected>> {
    let now = now_millis();
    let due_before = now.saturating_sub(duration_millis(SWEEP_INTERVAL));
    let claimed = sqlx::query(
        "INSERT INTO metadata_values (key, value) VALUES (?1, ?2) \
         ON CONFLICT (key) DO UPDATE SET value = excluded.value \
         WHERE CAST(metadata_values.value AS INTEGER) <= ?3",
    )
    .bind(LAST_SWEEP_KEY)
    .bind(now.to_string())
    .bind(db_int::<_, i64>(
        due_before,
        "build directory sweep cutoff",
    )?)
    .execute(pool)
    .await?
    .rows_affected();
    if claimed == 0 {
        return Ok(None);
    }
    collect(pool, cache_dir, idle, now).await.map(Some)
}

/// Remove the build directories under `<cache_dir>/build-dir/` that are
/// collectable at `now_ms`, and forget the records of directories that no
/// longer exist.
///
/// # Errors
///
/// The state database or a directory cannot be read, or a removal fails
/// for a reason other than the directory being in use.
pub async fn collect(
    pool: &SqlitePool,
    cache_dir: &Path,
    idle: Duration,
    now_ms: u64,
) -> Result<Collected> {
    let rows: Vec<(String, String, i64)> =
        sqlx::query_as("SELECT build_dir, manifests_json, last_built_ms FROM build_directories")
            .fetch_all(pool)
            .await?;
    let mut records = HashMap::with_capacity(rows.len());
    for (build_dir, manifests_json, last_built_ms) in rows {
        let manifests: Vec<PathBuf> =
            serde_json::from_str(&manifests_json).wrap_err("parse the recorded manifests")?;
        let record = Record {
            manifests,
            last_built_ms: db_int(last_built_ms, "build directory last built")?,
        };
        records.insert(build_dir, record);
    }
    let root = cache_dir.join(BUILD_DIR_PARENT);
    let cache_dir_owned = cache_dir.to_path_buf();
    let idle_ms = duration_millis(idle);
    let swept = tokio::task::spawn_blocking(move || {
        let swept = sweep(&root, &records, idle_ms, now_ms)?;
        if let Err(error) = crate::fuse_cow::gc_unreferenced_blobs(&cache_dir_owned) {
            tracing::debug!(%error, "failed to GC unreferenced FUSE CoW blobs");
        }
        Ok::<_, stow_types::error::Error>(swept)
    })
    .await
    .wrap_err("join the build directory sweep")??;
    let mut transaction = pool.begin().await?;
    for forgotten in swept.forgotten.iter().chain(&swept.removed_keys) {
        sqlx::query("DELETE FROM build_directories WHERE build_dir = ?")
            .bind(forgotten)
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    Ok(swept.collected)
}

/// What stow recorded of one build directory.
struct Record {
    /// The member manifests builds of the directory were seen compiling;
    /// empty when none was seen.
    manifests: Vec<PathBuf>,
    last_built_ms: u64,
}

struct Swept {
    collected: Collected,
    /// The recorded keys of the removed directories.
    removed_keys: Vec<String>,
    /// Recorded keys whose directory no longer exists.
    forgotten: Vec<String>,
}

fn sweep(
    root: &Path,
    records: &HashMap<String, Record>,
    idle_ms: u64,
    now_ms: u64,
) -> Result<Swept> {
    let mut swept = Swept {
        collected: Collected::default(),
        removed_keys: Vec::new(),
        forgotten: Vec::new(),
    };
    let mut present = std::collections::HashSet::new();
    let listing = match std::fs::read_dir(root) {
        Ok(listing) => listing,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            swept.forgotten.extend(records.keys().cloned());
            return Ok(swept);
        }
        Err(error) => return Err(error).wrap_err_with(|| format!("list {}", root.display())),
    };
    let ctx = Sweep {
        records,
        idle_ms,
        now_ms,
    };
    for entry in listing {
        let entry = entry.wrap_err_with(|| format!("list {}", root.display()))?;
        let path = entry.path();
        let name = entry.file_name();
        // Left by a sweep a crash ended between its rename and its
        // removal: no build can be in it, since no lock was free to be
        // taken for it after the rename.
        if name.to_string_lossy().starts_with(COLLECTING_PREFIX) {
            remove_path(&path)?;
            continue;
        }
        if !entry
            .file_type()
            .wrap_err_with(|| format!("stat {}", path.display()))?
            .is_dir()
        {
            continue;
        }
        // Cargo's `{workspace-path-hash}` shards workspaces into
        // `<2-hex>/<14-hex>`, and that is the directory `record` keys.
        if is_hash_shard_name(&name.to_string_lossy()) {
            sweep_shard(&path, &ctx, &mut swept, &mut present)?;
        } else {
            sweep_dir(path, &ctx, &mut swept, &mut present)?;
        }
    }
    swept.forgotten.extend(
        records
            .keys()
            .filter(|key| !present.contains(*key))
            .cloned(),
    );
    Ok(swept)
}

/// What a sweep judges a build directory by.
struct Sweep<'a> {
    records: &'a HashMap<String, Record>,
    idle_ms: u64,
    now_ms: u64,
}

/// Sweep the workspace directories of one hash shard. The shard itself is
/// left in place, empty or not: a build creating a directory in it must
/// not find it removed.
fn sweep_shard(
    shard: &Path,
    ctx: &Sweep<'_>,
    swept: &mut Swept,
    present: &mut std::collections::HashSet<String>,
) -> Result<()> {
    let listing = match std::fs::read_dir(shard) {
        Ok(listing) => listing,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).wrap_err_with(|| format!("list {}", shard.display())),
    };
    for entry in listing {
        let entry = entry.wrap_err_with(|| format!("list {}", shard.display()))?;
        let path = entry.path();
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(COLLECTING_PREFIX)
        {
            remove_path(&path)?;
            continue;
        }
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).wrap_err_with(|| format!("stat {}", path.display())),
        };
        if kind.is_dir() {
            sweep_dir(path, ctx, swept, present)?;
        }
    }
    Ok(())
}

/// Judge one workspace build directory and remove it when it is due.
fn sweep_dir(
    dir: PathBuf,
    ctx: &Sweep<'_>,
    swept: &mut Swept,
    present: &mut std::collections::HashSet<String>,
) -> Result<()> {
    let key = dir.to_str().map(str::to_owned);
    present.extend(key.clone());
    let record = key.as_ref().and_then(|key| ctx.records.get(key));
    let Some(reason) = verdict(&dir, record, ctx.idle_ms, ctx.now_ms)? else {
        return Ok(());
    };
    if remove_unlocked(&dir)? {
        swept.collected.removed.push((dir, reason));
        swept.removed_keys.extend(key);
    } else {
        tracing::debug!(
            build_dir = %dir.display(),
            "a build holds the build directory's cargo lock; not collecting it"
        );
        swept.collected.locked.push(dir);
    }
    Ok(())
}

/// Whether `dir` is due for collection, and why.
fn verdict(
    dir: &Path,
    record: Option<&Record>,
    idle_ms: u64,
    now_ms: u64,
) -> Result<Option<Reason>> {
    let last_built_ms = match record {
        Some(record) => {
            // The workspace is gone when none of its recorded members
            // exists; a directory no member was recorded for is judged
            // by its build time alone.
            let mut any_exists = record.manifests.is_empty();
            for manifest in &record.manifests {
                any_exists |= manifest
                    .try_exists()
                    .wrap_err_with(|| format!("stat {}", manifest.display()))?;
            }
            if !any_exists {
                return Ok(Some(Reason::WorkspaceGone));
            }
            record.last_built_ms
        }
        None => newest_modification_ms(dir)?,
    };
    Ok((now_ms.saturating_sub(last_built_ms) > idle_ms).then_some(Reason::Idle))
}

/// The newest modification time, in milliseconds, of `dir` and its
/// entries down to [`ACTIVITY_DEPTH`]: the directories a build adds and
/// removes files in.
fn newest_modification_ms(dir: &Path) -> Result<u64> {
    let mut newest = 0;
    for entry in walkdir::WalkDir::new(dir).max_depth(ACTIVITY_DEPTH) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error)
                if error
                    .io_error()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                continue;
            }
            Err(error) => return Err(error).wrap_err_with(|| format!("walk {}", dir.display())),
        };
        // Read through the path, not the walk's entry: on Windows the
        // entry carries the timestamps the directory listing cached, which
        // lag a directory a build just added files to.
        let modified = match std::fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata.modified().wrap_err_with(|| {
                format!("read the modification time of {}", entry.path().display())
            })?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).wrap_err_with(|| format!("stat {}", entry.path().display()));
            }
        };
        let since_epoch = modified
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        newest = newest.max(duration_millis(since_epoch));
    }
    Ok(newest)
}

/// Remove every idle workspace build directory under `root`, skipping any
/// whose `.cargo-build-lock` is held by a running `cargo` build. Returns
/// the number of active build directories skipped.
///
/// Cargo's `{workspace-path-hash}` template shards workspaces into two-hex
/// subdirectories (`<root>/<2-hex>/<14-hex>/...`), while direct workspace
/// directories (`<root>/<name>/...`) can also exist. Shards are descended
/// into so an active build in one workspace does not block cleaning idle
/// siblings under the same shard.
///
/// # Errors
///
/// Listing `root` or removing an unlocked entry failed.
pub fn clean_all(root: &Path) -> Result<usize> {
    let listing = match std::fs::read_dir(root) {
        Ok(listing) => listing,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error).wrap_err_with(|| format!("list {}", root.display())),
    };
    let mut skipped = 0usize;
    for entry in listing {
        let entry = entry.wrap_err_with(|| format!("list {}", root.display()))?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with(COLLECTING_PREFIX) {
            remove_path(&path)?;
            continue;
        }
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).wrap_err_with(|| format!("stat {}", path.display())),
        };
        if !kind.is_dir() {
            remove_path(&path)?;
            continue;
        }
        if is_hash_shard_name(&name_str) {
            skipped += clean_shard(&path)?;
            remove_empty_dir(&path)?;
        } else if !remove_unlocked(&path)? {
            tracing::info!(
                build_dir = %path.display(),
                "skipping active build directory held by a running cargo build"
            );
            skipped += 1;
        }
    }
    remove_empty_dir(root)?;
    Ok(skipped)
}

fn clean_shard(shard: &Path) -> Result<usize> {
    let listing = match std::fs::read_dir(shard) {
        Ok(listing) => listing,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error).wrap_err_with(|| format!("list {}", shard.display())),
    };
    let mut skipped = 0usize;
    for entry in listing {
        let entry = entry.wrap_err_with(|| format!("list {}", shard.display()))?;
        let path = entry.path();
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(COLLECTING_PREFIX)
        {
            remove_path(&path)?;
            continue;
        }
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).wrap_err_with(|| format!("stat {}", path.display())),
        };
        if !kind.is_dir() {
            remove_path(&path)?;
            continue;
        }
        if !remove_unlocked(&path)? {
            tracing::info!(
                build_dir = %path.display(),
                "skipping active build directory held by a running cargo build"
            );
            skipped += 1;
        }
    }
    Ok(skipped)
}

fn is_hash_shard_name(name: &str) -> bool {
    name.len() == 2 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn remove_empty_dir(dir: &Path) -> Result<()> {
    match std::fs::remove_dir(dir) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::DirectoryNotEmpty
                    | std::io::ErrorKind::ResourceBusy
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error).wrap_err_with(|| format!("remove {}", dir.display())),
    }
}

/// Whether any build directory under `root` currently has its
/// `.cargo-build-lock` held by a running `cargo` build.
///
/// # Errors
///
/// Walking `root` or opening a lock file failed.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn has_active_cargo_lock(root: &Path) -> Result<bool> {
    if !root.exists() {
        return Ok(false);
    }
    for entry in walkdir::WalkDir::new(root).max_depth(5) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error)
                if error
                    .io_error()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                continue;
            }
            Err(error) => return Err(error).wrap_err_with(|| format!("walk {}", root.display())),
        };
        if entry.file_name() != OsStr::new(CARGO_BUILD_LOCK) || !entry.file_type().is_file() {
            continue;
        }
        let file = match std::fs::File::open(entry.path()) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).wrap_err_with(|| format!("open {}", entry.path().display()));
            }
        };
        if FileLock::try_exclusive(file)
            .wrap_err_with(|| format!("lock {}", entry.path().display()))?
            .is_none()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Remove `dir` with every cargo build lock inside it held; `false`, with
/// nothing removed, when a lock is held by a build.
fn remove_unlocked(dir: &Path) -> Result<bool> {
    let mut locks = Vec::new();
    // Depth 4 covers both `<ws>/<triple>/<profile>/.cargo-build-lock` and a
    // two-level `<shard>/<hash>/<triple>/<profile>/.cargo-build-lock` tree.
    for entry in walkdir::WalkDir::new(dir).max_depth(4) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error)
                if error
                    .io_error()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                continue;
            }
            Err(error) => return Err(error).wrap_err_with(|| format!("walk {}", dir.display())),
        };
        if entry.file_name() != OsStr::new(CARGO_BUILD_LOCK) || !entry.file_type().is_file() {
            continue;
        }
        let file = match std::fs::File::open(entry.path()) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).wrap_err_with(|| format!("open {}", entry.path().display()));
            }
        };
        let Some(lock) = FileLock::try_exclusive(file)
            .wrap_err_with(|| format!("lock {}", entry.path().display()))?
        else {
            return Ok(false);
        };
        locks.push((entry.into_path(), lock));
    }
    // Unix renames the directory away while the locks are held — one
    // atomic step on the cache's filesystem — then releases them and
    // deletes the renamed tree: a build that starts afterwards finds no
    // directory and creates a fresh one.
    #[cfg(unix)]
    {
        let hidden = hidden_sibling(dir);
        match std::fs::rename(dir, &hidden) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(error) => {
                return Err(error).wrap_err_with(|| format!("move {} aside", dir.display()));
            }
        }
        drop(locks);
        remove_path(&hidden)?;
        Ok(true)
    }
    // Windows cannot rename a directory with open handles inside it, and
    // cannot delete a locked file. Everything but the held lock files
    // goes while the locks are held, so a build that starts meanwhile
    // waits on cargo's lock; the empty shell, lock files included, goes
    // after they are released. A build starting between the release and
    // the last removal is not excluded.
    #[cfg(not(unix))]
    {
        remove_all_but_locks(&locks)?;
        drop(locks);
        remove_path(dir)?;
        Ok(true)
    }
}

/// The name a build directory is moved to for deletion: hidden, beside
/// it, on the same filesystem, so the move is atomic. [`sweep`] deletes
/// the ones a crash left behind.
#[cfg(unix)]
fn hidden_sibling(dir: &Path) -> PathBuf {
    let name = dir.file_name().unwrap_or_default().to_string_lossy();
    dir.with_file_name(format!("{COLLECTING_PREFIX}{}-{name}", std::process::id()))
}

#[cfg(not(unix))]
fn remove_all_but_locks(locks: &[(PathBuf, FileLock)]) -> Result<()> {
    for (lock_path, _) in locks {
        let profile_dir = lock_path.parent().expect("a lock file has a directory");
        for entry in std::fs::read_dir(profile_dir)
            .wrap_err_with(|| format!("list {}", profile_dir.display()))?
        {
            let entry = entry.wrap_err_with(|| format!("list {}", profile_dir.display()))?;
            if entry.file_name() != OsStr::new(CARGO_BUILD_LOCK) {
                remove_path(&entry.path())?;
            }
        }
    }
    Ok(())
}

fn remove_path(path: &Path) -> Result<()> {
    let is_dir = std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir());
    let mut removed = remove_once(path, is_dir);
    // A build script or test fixture can leave a read-only directory,
    // whose entries cannot be unlinked until it is writable again.
    if is_dir
        && removed
            .as_ref()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
    {
        make_writable(path)?;
        removed = remove_once(path, is_dir);
    }
    match removed {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(error).wrap_err_with(|| format!("remove {}", path.display()))
        }
        _ => Ok(()),
    }
}

fn remove_once(path: &Path, is_dir: bool) -> std::io::Result<()> {
    if is_dir {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

/// Give every directory under `root`, `root` included, its owner's write
/// and search permission, so its entries can be removed. Only Unix has
/// directories whose permissions keep their entries from being removed.
#[cfg(unix)]
fn make_writable(root: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error)
                if error
                    .io_error()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                continue;
            }
            Err(error) => return Err(error).wrap_err_with(|| format!("walk {}", root.display())),
        };
        if !entry.file_type().is_dir() {
            continue;
        }
        let mut permissions = entry
            .metadata()
            .wrap_err_with(|| format!("stat {}", entry.path().display()))?
            .permissions();
        permissions.set_mode(permissions.mode() | 0o700);
        std::fs::set_permissions(entry.path(), permissions)
            .wrap_err_with(|| format!("make {} writable", entry.path().display()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn make_writable(_root: &Path) -> Result<()> {
    Ok(())
}

fn utf8(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| stow_types::stow_error!("{} is not UTF-8", path.display()))
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    use super::{CARGO_BUILD_LOCK, Reason, collect, collect_if_due, record};
    use crate::state_db::{connect, now_millis};

    const IDLE: Duration = Duration::from_hours(24 * 30);
    const DAY_MS: u64 = 24 * 60 * 60 * 1000;

    struct Fixture {
        cache: tempfile::TempDir,
        workspaces: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                cache: tempfile::tempdir().expect("cache dir"),
                workspaces: tempfile::tempdir().expect("workspaces"),
            }
        }

        /// A build directory holding one profile directory with cargo's
        /// lock file and some outputs.
        fn build_dir(&self, name: &str) -> PathBuf {
            let dir = self.cache.path().join(super::BUILD_DIR_PARENT).join(name);
            let deps = dir.join("debug/deps");
            std::fs::create_dir_all(&deps).expect("create build dir");
            std::fs::write(dir.join("debug").join(CARGO_BUILD_LOCK), b"").expect("lock file");
            std::fs::write(deps.join("libdemo.rlib"), b"rlib").expect("output");
            dir
        }

        /// A workspace manifest that exists.
        fn workspace(&self, name: &str) -> PathBuf {
            let manifest = self.workspaces.path().join(name).join("Cargo.toml");
            std::fs::create_dir_all(manifest.parent().expect("parent")).expect("workspace dir");
            std::fs::write(&manifest, b"[workspace]\n").expect("manifest");
            manifest
        }
    }

    /// Age every file and directory of `dir` down to the activity depth.
    fn age(dir: &Path, days: u64) {
        let old = filetime::FileTime::from_system_time(
            SystemTime::now() - Duration::from_secs(days * 24 * 60 * 60),
        );
        for entry in walkdir::WalkDir::new(dir).max_depth(super::ACTIVITY_DEPTH) {
            let entry = entry.expect("walk");
            filetime::set_file_mtime(entry.path(), old).expect("age");
        }
    }

    async fn remaining_rows(pool: &sqlx::SqlitePool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM build_directories")
            .fetch_one(pool)
            .await
            .expect("count rows")
    }

    #[tokio::test]
    async fn a_deleted_workspaces_build_directory_is_collected() {
        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        let dir = fixture.build_dir("gone");
        let manifest = fixture.workspace("gone");
        record(&pool, &dir, std::slice::from_ref(&manifest), now_millis())
            .await
            .expect("record");
        std::fs::remove_file(&manifest).expect("delete the workspace");

        let collected = collect(&pool, fixture.cache.path(), IDLE, now_millis())
            .await
            .expect("collect");
        assert_eq!(collected.removed, [(dir.clone(), Reason::WorkspaceGone)]);
        assert!(!dir.exists());
        assert_eq!(remaining_rows(&pool).await, 0, "its record goes with it");
    }

    #[tokio::test]
    async fn a_deleted_workspaces_sharded_build_directory_is_collected() {
        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        let gone = fixture.build_dir("79/201e3c3f383709");
        let kept = fixture.build_dir("79/aaaaaaaaaaaaaa");
        let gone_manifest = fixture.workspace("gone");
        let kept_manifest = fixture.workspace("kept");
        let now = now_millis();
        record(&pool, &gone, std::slice::from_ref(&gone_manifest), now)
            .await
            .expect("record gone");
        record(&pool, &kept, std::slice::from_ref(&kept_manifest), now)
            .await
            .expect("record kept");
        std::fs::remove_file(&gone_manifest).expect("delete the workspace");

        let collected = collect(&pool, fixture.cache.path(), IDLE, now)
            .await
            .expect("collect");
        assert_eq!(collected.removed, [(gone.clone(), Reason::WorkspaceGone)]);
        assert!(!gone.exists());
        assert!(kept.join("debug/deps/libdemo.rlib").exists());
        assert_eq!(
            remaining_rows(&pool).await,
            1,
            "the live workspace keeps its record"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_read_only_directory_inside_a_build_directory_does_not_stop_its_removal() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        let dir = fixture.build_dir("79/201e3c3f383709");
        let manifest = fixture.workspace("gone");
        record(&pool, &dir, std::slice::from_ref(&manifest), now_millis())
            .await
            .expect("record");
        let readonly = dir.join("debug/deps/fixture");
        std::fs::create_dir_all(&readonly).expect("fixture dir");
        std::fs::write(readonly.join("data"), b"x").expect("fixture file");
        std::fs::set_permissions(&readonly, std::fs::Permissions::from_mode(0o555))
            .expect("make read-only");
        std::fs::remove_file(&manifest).expect("delete the workspace");

        let collected = collect(&pool, fixture.cache.path(), IDLE, now_millis())
            .await
            .expect("collect");
        assert_eq!(collected.removed, [(dir.clone(), Reason::WorkspaceGone)]);
        assert!(!dir.exists());
    }

    #[tokio::test]
    async fn a_build_directory_idle_past_the_age_is_collected() {
        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        let dir = fixture.build_dir("idle");
        let manifest = fixture.workspace("idle");
        let now = now_millis();
        record(
            &pool,
            &dir,
            std::slice::from_ref(&manifest),
            now - 31 * DAY_MS,
        )
        .await
        .expect("record");

        let collected = collect(&pool, fixture.cache.path(), IDLE, now)
            .await
            .expect("collect");
        assert_eq!(collected.removed, [(dir.clone(), Reason::Idle)]);
        assert!(!dir.exists());
    }

    #[tokio::test]
    async fn a_recently_built_directory_is_kept() {
        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        let dir = fixture.build_dir("live");
        let manifest = fixture.workspace("live");
        let now = now_millis();
        record(
            &pool,
            &dir,
            std::slice::from_ref(&manifest),
            now - 29 * DAY_MS,
        )
        .await
        .expect("record");

        let collected = collect(&pool, fixture.cache.path(), IDLE, now)
            .await
            .expect("collect");
        assert_eq!(collected, super::Collected::default());
        assert!(dir.join("debug/deps/libdemo.rlib").exists());
        assert_eq!(remaining_rows(&pool).await, 1);
    }

    #[tokio::test]
    async fn an_unrecorded_directory_is_collected_only_by_its_modification_times() {
        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        let stale = fixture.build_dir("stale");
        let fresh = fixture.build_dir("fresh");
        // A directory whose own top is old but whose `deps` a build just
        // wrote into is in use.
        let building = fixture.build_dir("building");
        age(&stale, 31);
        age(&fresh, 29);
        age(&building, 90);
        std::fs::write(building.join("debug/deps/libnew.rlib"), b"new").expect("a build's output");

        let collected = collect(&pool, fixture.cache.path(), IDLE, now_millis())
            .await
            .expect("collect");
        assert_eq!(collected.removed, [(stale.clone(), Reason::Idle)]);
        assert!(!stale.exists());
        assert!(fresh.exists());
        assert!(building.exists());
    }

    #[tokio::test]
    async fn a_directory_whose_cargo_lock_is_held_is_skipped_until_released() {
        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        let dir = fixture.build_dir("running");
        let manifest = fixture.workspace("running");
        record(&pool, &dir, std::slice::from_ref(&manifest), now_millis())
            .await
            .expect("record");
        std::fs::remove_file(&manifest).expect("delete the workspace");

        // Cargo's own hold: an exclusive lock on the profile's lock file.
        let cargo = File::options()
            .read(true)
            .write(true)
            .open(dir.join("debug").join(CARGO_BUILD_LOCK))
            .expect("open cargo's lock");
        cargo.lock().expect("cargo locks the build directory");

        let collected = collect(&pool, fixture.cache.path(), IDLE, now_millis())
            .await
            .expect("collect");
        assert_eq!(collected.locked, std::slice::from_ref(&dir));
        assert_eq!(collected.removed, []);
        assert!(
            dir.join("debug/deps/libdemo.rlib").exists(),
            "nothing was touched"
        );
        assert_eq!(remaining_rows(&pool).await, 1);

        cargo.unlock().expect("the build ends");
        let collected = collect(&pool, fixture.cache.path(), IDLE, now_millis())
            .await
            .expect("collect again");
        assert_eq!(collected.removed, [(dir.clone(), Reason::WorkspaceGone)]);
        assert!(!dir.exists());
    }

    #[tokio::test]
    async fn a_workspace_is_gone_only_when_none_of_its_members_exists() {
        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        let dir = fixture.build_dir("members");
        let first = fixture.workspace("first");
        let second = fixture.workspace("second");
        // Two builds, each of one member, name the workspace together.
        record(&pool, &dir, std::slice::from_ref(&first), now_millis())
            .await
            .expect("record the first build");
        record(&pool, &dir, std::slice::from_ref(&second), now_millis())
            .await
            .expect("record the second build");
        // A build that saw no member keeps what was recorded.
        record(&pool, &dir, &[], now_millis())
            .await
            .expect("record a build with no member");

        std::fs::remove_file(&first).expect("one member is deleted");
        let collected = collect(&pool, fixture.cache.path(), IDLE, now_millis())
            .await
            .expect("collect");
        assert_eq!(collected, super::Collected::default(), "one member remains");

        std::fs::remove_file(&second).expect("the other member is deleted");
        let collected = collect(&pool, fixture.cache.path(), IDLE, now_millis())
            .await
            .expect("collect again");
        assert_eq!(collected.removed, [(dir.clone(), Reason::WorkspaceGone)]);
    }

    #[tokio::test]
    async fn a_directory_recorded_with_no_member_is_judged_by_its_build_time() {
        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        let dir = fixture.build_dir("memberless");
        record(&pool, &dir, &[], now_millis())
            .await
            .expect("record");
        let collected = collect(&pool, fixture.cache.path(), IDLE, now_millis())
            .await
            .expect("collect");
        assert_eq!(collected, super::Collected::default());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_sweeps_leftover_hidden_directory_is_removed() {
        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        let leftover = fixture
            .cache
            .path()
            .join(super::BUILD_DIR_PARENT)
            .join(".collecting-1-gone");
        std::fs::create_dir_all(leftover.join("debug")).expect("leftover");
        collect(&pool, fixture.cache.path(), IDLE, now_millis())
            .await
            .expect("collect");
        assert!(!leftover.exists());
    }

    #[tokio::test]
    async fn the_record_of_a_directory_removed_by_hand_is_forgotten() {
        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        let dir = fixture.build_dir("cleaned");
        let manifest = fixture.workspace("cleaned");
        record(&pool, &dir, std::slice::from_ref(&manifest), now_millis())
            .await
            .expect("record");
        std::fs::remove_dir_all(&dir).expect("the user cleans it");

        collect(&pool, fixture.cache.path(), IDLE, now_millis())
            .await
            .expect("collect");
        assert_eq!(remaining_rows(&pool).await, 0);
    }

    #[tokio::test]
    async fn a_sweep_runs_once_per_interval() {
        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        assert!(
            collect_if_due(&pool, fixture.cache.path(), IDLE)
                .await
                .expect("first sweep")
                .is_some()
        );
        assert!(
            collect_if_due(&pool, fixture.cache.path(), IDLE)
                .await
                .expect("second sweep")
                .is_none(),
            "a sweep inside the interval is claimed by the first"
        );
    }

    /// Deleting a build directory's clones frees the bytes they shared:
    /// the cache entry's private bytes rise to its whole size, which the
    /// next measurement of the entry records (stow#1539).
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn collecting_a_directory_makes_the_entries_it_cloned_reclaimable() {
        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        let entry = fixture.cache.path().join("entry/libdemo.rlib");
        std::fs::create_dir_all(entry.parent().expect("parent")).expect("entry dir");
        std::fs::write(&entry, vec![7u8; 1 << 20]).expect("entry file");
        let dir = fixture.build_dir("clones");
        reflink_copy::reflink(&entry, dir.join("debug/deps/clone.rlib"))
            .expect("clone on the APFS temp volume");
        let manifest = fixture.workspace("clones");
        record(&pool, &dir, std::slice::from_ref(&manifest), now_millis())
            .await
            .expect("record");
        std::fs::remove_file(&manifest).expect("delete the workspace");

        let shared_before = crate::reclaimable::shared_bytes(&entry).expect("measure");
        assert_eq!(shared_before, 1 << 20, "the clone shares the whole entry");

        collect(&pool, fixture.cache.path(), IDLE, now_millis())
            .await
            .expect("collect");
        assert!(!dir.exists());
        assert_eq!(
            crate::reclaimable::shared_bytes(&entry).expect("measure"),
            0,
            "deleting the entry now frees all of it"
        );
    }
}
