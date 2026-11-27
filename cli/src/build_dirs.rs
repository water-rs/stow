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

/// How often a daemon runs a full shard sweep regardless of session ends.
const SWEEP_INTERVAL: Duration = Duration::from_hours(1);

/// Minimum gap between post-session `WorkspaceGone` checks.
const POST_SESSION_INTERVAL: Duration = Duration::from_secs(15);

/// Minimum gap between post-session size-budget sweeps when disk space is
/// above `min_free_bytes`.
const BUDGET_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// The `metadata_values` key holding when the last full sweep started.
const LAST_SWEEP_KEY: &str = "build_dirs_collected_ms";

/// The `metadata_values` key holding when the last post-session check ran.
const LAST_POST_SESSION_KEY: &str = "build_dirs_post_session_ms";

/// The `metadata_values` key holding when the last budget sweep ran.
const LAST_BUDGET_SWEEP_KEY: &str = "build_dirs_budget_ms";

/// How deep below a build directory a modification time still shows
/// builds: `<profile>/deps`, `<profile>/.fingerprint`, and with a target
/// triple one level less than `<triple>/<profile>`'s own entries.
const ACTIVITY_DEPTH: usize = 2;

/// Operator bounds governing build-directory collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub idle: Duration,
    pub max_bytes: u64,
    pub min_free_bytes: u64,
}

impl Policy {
    /// Time-only collection with no byte cap or free-space floor.
    #[must_use]
    pub const fn unbounded(idle: Duration) -> Self {
        Self {
            idle,
            max_bytes: u64::MAX,
            min_free_bytes: 0,
        }
    }
}

/// Why a directory is collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The workspace manifest it was recorded for no longer exists.
    WorkspaceGone,
    /// Not built, by the record or by its modification times, for longer
    /// than the idle age.
    Idle,
    /// Evicted least-recently-used because private reclaimable bytes under
    /// `build-dir/` exceeded `build_dir_max_bytes`.
    OverBudget,
    /// Evicted least-recently-used because free space on the cache volume
    /// fell below `build_dir_min_free_bytes`.
    LowDisk,
}

/// What a sweep did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Collected {
    /// The directories removed.
    pub removed: Vec<(PathBuf, Reason)>,
    /// The directories due for removal whose cargo lock is held: a build
    /// is running in them.
    pub locked: Vec<PathBuf>,
    /// Private filesystem bytes reclaimed by [`Self::removed`].
    pub reclaimed_bytes: u64,
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

async fn claim_interval(
    pool: &SqlitePool,
    key: &str,
    now_ms: u64,
    interval: Duration,
) -> Result<bool> {
    let due_before = now_ms.saturating_sub(duration_millis(interval));
    let claimed = sqlx::query(
        "INSERT INTO metadata_values (key, value) VALUES (?1, ?2) \
         ON CONFLICT (key) DO UPDATE SET value = excluded.value \
         WHERE CAST(metadata_values.value AS INTEGER) <= ?3",
    )
    .bind(key)
    .bind(now_ms.to_string())
    .bind(db_int::<_, i64>(
        due_before,
        "build directory sweep cutoff",
    )?)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(claimed > 0)
}

/// Sweep when the last one is older than [`SWEEP_INTERVAL`]; `None` when
/// another sweep claimed the interval. The claim is one conditional write,
/// so concurrent sessions sweep once.
///
/// # Errors
///
/// As [`collect_with_policy`].
pub async fn collect_if_due(
    pool: &SqlitePool,
    cache_dir: &Path,
    policy: Policy,
) -> Result<Option<Collected>> {
    let now = now_millis();
    if !claim_interval(pool, LAST_SWEEP_KEY, now, SWEEP_INTERVAL).await? {
        return Ok(None);
    }
    collect_with_policy(pool, cache_dir, policy, now)
        .await
        .map(Some)
}

/// Post-session collection: runs immediately when free space is below
/// `policy.min_free_bytes`, runs a full budget sweep at most once per
/// [`BUDGET_SWEEP_INTERVAL`], and otherwise stats recorded manifests at most
/// once per [`POST_SESSION_INTERVAL`] to reclaim deleted workspaces without
/// walking shards.
pub async fn collect_after_session(
    pool: &SqlitePool,
    cache_dir: &Path,
    policy: Policy,
) -> Result<Option<Collected>> {
    let now = now_millis();
    let root = cache_dir.join(BUILD_DIR_PARENT);
    let low_disk = policy.min_free_bytes > 0
        && available_disk_bytes(&root).is_ok_and(|avail| avail < policy.min_free_bytes);
    if low_disk {
        return collect_with_policy(pool, cache_dir, policy, now)
            .await
            .map(Some);
    }
    if !claim_interval(pool, LAST_POST_SESSION_KEY, now, POST_SESSION_INTERVAL).await? {
        return Ok(None);
    }
    if policy.max_bytes < u64::MAX
        && claim_interval(pool, LAST_BUDGET_SWEEP_KEY, now, BUDGET_SWEEP_INTERVAL).await?
    {
        return collect_with_policy(pool, cache_dir, policy, now)
            .await
            .map(Some);
    }
    collect_gone_recorded(pool, cache_dir).await.map(Some)
}

/// Remove recorded build directories whose workspace manifests are all gone,
/// without scanning `<cache_dir>/build-dir/` shards.
async fn collect_gone_recorded(pool: &SqlitePool, cache_dir: &Path) -> Result<Collected> {
    let rows = load_records(pool).await?;
    if rows.is_empty() {
        return Ok(Collected::default());
    }
    let cache_dir_owned = cache_dir.to_path_buf();
    let swept = tokio::task::spawn_blocking(move || {
        let mut collected = Collected::default();
        let mut removed_keys = Vec::new();
        let mut forgotten = Vec::new();
        for (dir, record) in rows {
            if record.manifests.is_empty() {
                continue;
            }
            if !dir.exists() {
                forgotten.push(record.key);
                continue;
            }
            let mut any_exists = false;
            for manifest in &record.manifests {
                any_exists |= manifest
                    .try_exists()
                    .wrap_err_with(|| format!("stat {}", manifest.display()))?;
            }
            if any_exists {
                continue;
            }
            let bytes = crate::reclaimable::reclaimable_bytes(&dir).unwrap_or(0);
            if remove_unlocked(&dir)? {
                collected.reclaimed_bytes = collected.reclaimed_bytes.saturating_add(bytes);
                collected.removed.push((dir, Reason::WorkspaceGone));
                removed_keys.push(record.key);
            } else {
                collected.locked.push(dir);
            }
        }
        if !collected.removed.is_empty()
            && let Err(error) = crate::fuse_cow::gc_unreferenced_blobs(&cache_dir_owned)
        {
            tracing::debug!(%error, "failed to GC unreferenced FUSE CoW blobs");
        }
        Ok::<_, stow_types::error::Error>((collected, removed_keys, forgotten))
    })
    .await
    .wrap_err("join post-session workspace-gone check")??;
    delete_record_keys(pool, &swept.1, &swept.2).await?;
    Ok(swept.0)
}

/// Remove the build directories under `<cache_dir>/build-dir/` that are
/// collectable by `WorkspaceGone` or `idle` at `now_ms`, and forget the
/// records of directories that no longer exist.
///
/// # Errors
///
/// As [`collect_with_policy`].
#[cfg_attr(not(test), allow(dead_code))]
pub async fn collect(
    pool: &SqlitePool,
    cache_dir: &Path,
    idle: Duration,
    now_ms: u64,
) -> Result<Collected> {
    collect_with_policy(pool, cache_dir, Policy::unbounded(idle), now_ms).await
}

/// Remove build directories under `<cache_dir>/build-dir/` due by
/// `WorkspaceGone`, `policy.idle`, `policy.max_bytes`, or
/// `policy.min_free_bytes`, evicting unlocked idle directories oldest-first
/// (LRU) when over budget or low on disk.
///
/// # Errors
///
/// The state database or a directory cannot be read, or a removal fails
/// for a reason other than the directory being in use.
pub async fn collect_with_policy(
    pool: &SqlitePool,
    cache_dir: &Path,
    policy: Policy,
    now_ms: u64,
) -> Result<Collected> {
    collect_with_avail_override(pool, cache_dir, policy, now_ms, None).await
}

async fn collect_with_avail_override(
    pool: &SqlitePool,
    cache_dir: &Path,
    policy: Policy,
    now_ms: u64,
    avail_override: Option<u64>,
) -> Result<Collected> {
    let records = load_records(pool).await?;
    let root = cache_dir.join(BUILD_DIR_PARENT);
    let cache_dir_owned = cache_dir.to_path_buf();
    let swept = tokio::task::spawn_blocking(move || {
        let swept = sweep(&root, &records, policy, now_ms, avail_override)?;
        if let Err(error) = crate::fuse_cow::gc_unreferenced_blobs(&cache_dir_owned) {
            tracing::debug!(%error, "failed to GC unreferenced FUSE CoW blobs");
        }
        Ok::<_, stow_types::error::Error>(swept)
    })
    .await
    .wrap_err("join the build directory sweep")??;
    delete_record_keys(pool, &swept.forgotten, &swept.removed_keys).await?;
    Ok(swept.collected)
}

/// Reclaim unlocked build directories attributed to `worktrees` (by recorded
/// manifests or, when a manifest still exists on disk, `cargo metadata`'s
/// `build_directory` under `<cache_dir>/build-dir/`).
pub async fn gc_worktrees(
    pool: &SqlitePool,
    cache_dir: &Path,
    worktrees: &[PathBuf],
) -> Result<Collected> {
    let records = load_records(pool).await?;
    let cache_dir_owned = cache_dir.to_path_buf();
    let worktrees_owned = worktrees.to_vec();
    let swept = tokio::task::spawn_blocking(move || {
        let root = cache_dir_owned.join(BUILD_DIR_PARENT);
        let root_abs = std::path::absolute(&root).unwrap_or_else(|_| root.clone());
        let root_canon = std::fs::canonicalize(&root).ok();
        let mut prefixes = Vec::new();
        let mut targets = BTreeSet::new();
        for wt in &worktrees_owned {
            if let Ok(abs) = std::path::absolute(wt) {
                prefixes.push(abs);
            } else {
                prefixes.push(wt.clone());
            }
            if let Ok(canon) = std::fs::canonicalize(wt) {
                prefixes.push(canon);
            }
            if let Some(bdir) = cargo_build_dir_for_worktree(wt, &root_abs, root_canon.as_deref()) {
                targets.insert(bdir);
            }
        }
        for (dir, record) in &records {
            let matched = record.manifests.iter().any(|manifest| {
                prefixes
                    .iter()
                    .any(|prefix| manifest == prefix || manifest.starts_with(prefix))
            });
            if matched {
                targets.insert(dir.clone());
            }
        }
        let mut collected = Collected::default();
        let mut removed_keys = Vec::new();
        for dir in targets {
            let record_key = records
                .get(&dir)
                .map(|record| record.key.clone())
                .or_else(|| {
                    std::fs::canonicalize(&dir).ok().and_then(|canon| {
                        records
                            .iter()
                            .find(|(recorded_dir, _)| {
                                std::fs::canonicalize(recorded_dir)
                                    .is_ok_and(|recorded_canon| recorded_canon == canon)
                            })
                            .map(|(_, record)| record.key.clone())
                    })
                });
            if !dir.exists() {
                removed_keys.extend(record_key);
                continue;
            }
            let bytes = crate::reclaimable::reclaimable_bytes(&dir).unwrap_or(0);
            if remove_unlocked(&dir)? {
                collected.reclaimed_bytes = collected.reclaimed_bytes.saturating_add(bytes);
                collected.removed.push((dir, Reason::WorkspaceGone));
                removed_keys.extend(record_key);
            } else {
                collected.locked.push(dir);
            }
        }
        if !collected.removed.is_empty()
            && let Err(error) = crate::fuse_cow::gc_unreferenced_blobs(&cache_dir_owned)
        {
            tracing::debug!(%error, "failed to GC unreferenced FUSE CoW blobs");
        }
        Ok::<_, stow_types::error::Error>((collected, removed_keys))
    })
    .await
    .wrap_err("join targeted worktree build-dir GC")??;
    delete_record_keys(pool, &swept.1, &[]).await?;
    Ok(swept.0)
}

fn cargo_build_dir_for_worktree(
    wt: &Path,
    build_root_abs: &Path,
    build_root_canon: Option<&Path>,
) -> Option<PathBuf> {
    let manifest = if wt.file_name() == Some(OsStr::new("Cargo.toml")) && wt.is_file() {
        wt.to_path_buf()
    } else {
        let candidate = wt.join("Cargo.toml");
        if !candidate.is_file() {
            return None;
        }
        candidate
    };
    let output = std::process::Command::new("cargo")
        .args([
            "metadata",
            "--no-deps",
            "--offline",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(&manifest)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let bdir = PathBuf::from(parsed.get("build_directory")?.as_str()?);
    let inside = bdir.starts_with(build_root_abs)
        || build_root_canon.is_some_and(|canon| bdir.starts_with(canon));
    (inside && bdir != build_root_abs && build_root_canon != Some(bdir.as_path())).then_some(bdir)
}

async fn load_records(pool: &SqlitePool) -> Result<HashMap<PathBuf, Record>> {
    let rows: Vec<(String, String, i64)> =
        sqlx::query_as("SELECT build_dir, manifests_json, last_built_ms FROM build_directories")
            .fetch_all(pool)
            .await?;
    let mut records = HashMap::with_capacity(rows.len());
    for (build_dir, manifests_json, last_built_ms) in rows {
        let manifests: Vec<PathBuf> =
            serde_json::from_str(&manifests_json).wrap_err("parse the recorded manifests")?;
        // Keyed by path, which compares by component: a key written with
        // `/` on Windows matches the directory the listing names with `\`.
        let record = Record {
            key: build_dir,
            manifests,
            last_built_ms: db_int(last_built_ms, "build directory last built")?,
        };
        records.insert(PathBuf::from(&record.key), record);
    }
    Ok(records)
}

async fn delete_record_keys(pool: &SqlitePool, first: &[String], second: &[String]) -> Result<()> {
    if first.is_empty() && second.is_empty() {
        return Ok(());
    }
    let mut transaction = pool.begin().await?;
    for key in first.iter().chain(second) {
        sqlx::query("DELETE FROM build_directories WHERE build_dir = ?")
            .bind(key)
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    Ok(())
}

/// What stow recorded of one build directory.
struct Record {
    /// The row's key, as `record` wrote it.
    key: String,
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

struct Survivor {
    dir: PathBuf,
    key: Option<String>,
    last_active_ms: u64,
}

fn sweep(
    root: &Path,
    records: &HashMap<PathBuf, Record>,
    policy: Policy,
    now_ms: u64,
    avail_override: Option<u64>,
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
            swept
                .forgotten
                .extend(records.values().map(|record| record.key.clone()));
            return Ok(swept);
        }
        Err(error) => return Err(error).wrap_err_with(|| format!("list {}", root.display())),
    };
    let ctx = Sweep {
        records,
        idle_ms: duration_millis(policy.idle),
        now_ms,
    };
    let mut survivors = Vec::new();
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
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).wrap_err_with(|| format!("stat {}", path.display())),
        };
        if !kind.is_dir() {
            continue;
        }
        // Cargo's `{workspace-path-hash}` shards workspaces into
        // `<2-hex>/<14-hex>`, and that is the directory `record` keys.
        if is_hash_shard_name(&name.to_string_lossy()) {
            sweep_shard(&path, &ctx, &mut swept, &mut present, &mut survivors)?;
        } else {
            sweep_dir(path, &ctx, &mut swept, &mut present, &mut survivors)?;
        }
    }
    evict_survivors_for_bounds(root, policy, avail_override, survivors, &mut swept)?;
    swept.forgotten.extend(
        records
            .iter()
            .filter(|(path, _)| !present.contains(*path))
            .map(|(_, record)| record.key.clone()),
    );
    Ok(swept)
}

fn evict_survivors_for_bounds(
    root: &Path,
    policy: Policy,
    avail_override: Option<u64>,
    survivors: Vec<Survivor>,
    swept: &mut Swept,
) -> Result<()> {
    if survivors.is_empty() {
        return Ok(());
    }
    let mut avail = match avail_override {
        Some(initial) => initial.saturating_add(swept.collected.reclaimed_bytes),
        None if policy.min_free_bytes > 0 => available_disk_bytes(root)?,
        None => u64::MAX,
    };
    let need_budget = policy.max_bytes < u64::MAX;
    let need_free = avail < policy.min_free_bytes;
    if !need_budget && !need_free {
        return Ok(());
    }
    let mut measured = Vec::with_capacity(survivors.len());
    let mut total_bytes = 0u64;
    for survivor in survivors {
        let bytes = crate::reclaimable::reclaimable_bytes(&survivor.dir).unwrap_or(0);
        total_bytes = total_bytes.saturating_add(bytes);
        measured.push((survivor, bytes));
    }
    if total_bytes <= policy.max_bytes && avail >= policy.min_free_bytes {
        return Ok(());
    }
    measured.sort_by(|(left, _), (right, _)| {
        left.last_active_ms
            .cmp(&right.last_active_ms)
            .then_with(|| left.dir.cmp(&right.dir))
    });
    for (survivor, bytes) in measured {
        if total_bytes <= policy.max_bytes && avail >= policy.min_free_bytes {
            break;
        }
        let reason = if avail < policy.min_free_bytes {
            Reason::LowDisk
        } else {
            Reason::OverBudget
        };
        if remove_unlocked(&survivor.dir)? {
            total_bytes = total_bytes.saturating_sub(bytes);
            avail = avail.saturating_add(bytes);
            swept.collected.reclaimed_bytes = swept.collected.reclaimed_bytes.saturating_add(bytes);
            swept.collected.removed.push((survivor.dir, reason));
            swept.removed_keys.extend(survivor.key);
        } else {
            tracing::debug!(
                build_dir = %survivor.dir.display(),
                "a build holds the build directory's cargo lock; skipping LRU eviction"
            );
            swept.collected.locked.push(survivor.dir);
        }
    }
    Ok(())
}

/// Available unprivileged bytes on the filesystem containing `path` (or its
/// nearest existing ancestor).
pub fn available_disk_bytes(path: &Path) -> Result<u64> {
    let Some(existing) = path.ancestors().find(|ancestor| ancestor.exists()) else {
        return Ok(u64::MAX);
    };
    platform_available_disk_bytes(existing)
        .wrap_err_with(|| format!("query available disk space for {}", existing.display()))
}

#[cfg(unix)]
fn platform_available_disk_bytes(path: &Path) -> std::io::Result<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: `cpath` is NUL-terminated and `stat` is a writable `statvfs`.
    if unsafe { libc::statvfs(cpath.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `statvfs` returned 0, initializing `stat`.
    let stat = unsafe { stat.assume_init() };
    #[allow(clippy::useless_conversion)]
    let bavail = u64::from(stat.f_bavail);
    #[allow(clippy::useless_conversion)]
    let frsize = u64::from(stat.f_frsize);
    Ok(bavail.saturating_mul(frsize))
}

#[cfg(windows)]
fn platform_available_disk_bytes(path: &Path) -> std::io::Result<u64> {
    use std::os::windows::ffi::OsStrExt as _;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let mut free_available = 0u64;
    // SAFETY: `wide` is NUL-terminated UTF-16 and `free_available` is writable.
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &raw mut free_available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(free_available)
}

/// What a sweep judges a build directory by.
struct Sweep<'a> {
    records: &'a HashMap<PathBuf, Record>,
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
    present: &mut std::collections::HashSet<PathBuf>,
    survivors: &mut Vec<Survivor>,
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
            sweep_dir(path, ctx, swept, present, survivors)?;
        }
    }
    Ok(())
}

/// Judge one workspace build directory and remove it when it is due, or
/// retain it as a candidate for capacity/disk-pressure LRU eviction.
fn sweep_dir(
    dir: PathBuf,
    ctx: &Sweep<'_>,
    swept: &mut Swept,
    present: &mut std::collections::HashSet<PathBuf>,
    survivors: &mut Vec<Survivor>,
) -> Result<()> {
    present.insert(dir.clone());
    let record = ctx.records.get(&dir);
    let (reason, last_active_ms) = verdict(&dir, record, ctx.idle_ms, ctx.now_ms)?;
    let Some(reason) = reason else {
        survivors.push(Survivor {
            dir,
            key: record.map(|record| record.key.clone()),
            last_active_ms,
        });
        return Ok(());
    };
    let bytes = crate::reclaimable::reclaimable_bytes(&dir).unwrap_or(0);
    if remove_unlocked(&dir)? {
        swept.collected.reclaimed_bytes = swept.collected.reclaimed_bytes.saturating_add(bytes);
        swept
            .removed_keys
            .extend(record.map(|record| record.key.clone()));
        swept.collected.removed.push((dir, reason));
    } else {
        tracing::debug!(
            build_dir = %dir.display(),
            "a build holds the build directory's cargo lock; not collecting it"
        );
        swept.collected.locked.push(dir);
    }
    Ok(())
}

/// Whether `dir` is due for collection, why, and its last activity timestamp.
fn verdict(
    dir: &Path,
    record: Option<&Record>,
    idle_ms: u64,
    now_ms: u64,
) -> Result<(Option<Reason>, u64)> {
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
                return Ok((Some(Reason::WorkspaceGone), record.last_built_ms));
            }
            record.last_built_ms
        }
        None => newest_modification_ms(dir)?,
    };
    Ok((
        (now_ms.saturating_sub(last_built_ms) > idle_ms).then_some(Reason::Idle),
        last_built_ms,
    ))
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
    // Depth 3 covers both `<ws>/<profile>/.cargo-build-lock` and
    // `<ws>/<triple>/<profile>/.cargo-build-lock` on the leaf workspace
    // build directory passed here.
    for entry in walkdir::WalkDir::new(dir).max_depth(3) {
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
    let removed = if std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()) {
        stow_types::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    match removed {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(error).wrap_err_with(|| format!("remove {}", path.display()))
        }
        _ => Ok(()),
    }
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

    use super::{CARGO_BUILD_LOCK, Reason, clean_all, collect, collect_if_due, record};
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
        let policy = super::Policy::unbounded(IDLE);
        assert!(
            collect_if_due(&pool, fixture.cache.path(), policy)
                .await
                .expect("first sweep")
                .is_some()
        );
        assert!(
            collect_if_due(&pool, fixture.cache.path(), policy)
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

    #[tokio::test]
    async fn a_sharded_deleted_workspace_is_collected_while_its_shard_sibling_stays() {
        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        let gone_dir = fixture.build_dir("e5/31c0aabbccddeeff");
        let gone_manifest = fixture.workspace("gone-sharded");
        let live_dir = fixture.build_dir("e5/4444555566667777");
        let live_manifest = fixture.workspace("live-sharded");
        let now = now_millis();
        record(&pool, &gone_dir, std::slice::from_ref(&gone_manifest), now)
            .await
            .expect("record gone");
        record(&pool, &live_dir, std::slice::from_ref(&live_manifest), now)
            .await
            .expect("record live");
        std::fs::remove_file(&gone_manifest).expect("delete gone workspace");

        let collected = collect(&pool, fixture.cache.path(), IDLE, now)
            .await
            .expect("collect");
        assert_eq!(
            collected.removed,
            [(gone_dir.clone(), Reason::WorkspaceGone)]
        );
        assert!(!gone_dir.exists());
        assert!(live_dir.join("debug/deps/libdemo.rlib").exists());
        assert_eq!(remaining_rows(&pool).await, 1);

        // Removing the remaining sibling collects it and removes the empty shard.
        std::fs::remove_file(&live_manifest).expect("delete live workspace");
        let collected = collect(&pool, fixture.cache.path(), IDLE, now)
            .await
            .expect("collect second");
        assert_eq!(
            collected.removed,
            [(live_dir.clone(), Reason::WorkspaceGone)]
        );
        assert!(!live_dir.exists());
        assert_eq!(remaining_rows(&pool).await, 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_sweeps_leftover_hidden_directory_inside_a_shard_is_removed() {
        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        let shard = fixture
            .cache
            .path()
            .join(super::BUILD_DIR_PARENT)
            .join("a1");
        let leftover = shard.join(".collecting-1-bbbbbbbbbbbbbb");
        std::fs::create_dir_all(leftover.join("debug")).expect("leftover");

        collect(&pool, fixture.cache.path(), IDLE, now_millis())
            .await
            .expect("collect");
        assert!(!leftover.exists());
        assert!(
            shard.exists(),
            "shard directory stays in place for concurrent builds"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_read_only_subdirectory_inside_a_build_dir_is_removed() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        let collect_dir = fixture.build_dir("f1/11111111111111");
        let collect_ro = collect_dir.join("debug/build/pkg/out/ro");
        std::fs::create_dir_all(&collect_ro).expect("create ro dir");
        std::fs::write(collect_ro.join("generated.rs"), b"// ro").expect("write ro file");
        std::fs::set_permissions(&collect_ro, std::fs::Permissions::from_mode(0o555))
            .expect("chmod 0555");
        let manifest = fixture.workspace("ro-collect");
        record(
            &pool,
            &collect_dir,
            std::slice::from_ref(&manifest),
            now_millis(),
        )
        .await
        .expect("record");
        std::fs::remove_file(&manifest).expect("delete workspace");

        let collected = collect(&pool, fixture.cache.path(), IDLE, now_millis())
            .await
            .expect("collect with read-only subdir");
        assert_eq!(
            collected.removed,
            [(collect_dir.clone(), Reason::WorkspaceGone)]
        );
        assert!(!collect_dir.exists());

        let clean_dir = fixture.build_dir("f2/22222222222222");
        let clean_ro = clean_dir.join("debug/build/pkg/out/ro_0444");
        std::fs::create_dir_all(&clean_ro).expect("create 0444 dir");
        std::fs::write(clean_ro.join("generated.rs"), b"// ro").expect("write ro file");
        std::fs::set_permissions(&clean_ro, std::fs::Permissions::from_mode(0o444))
            .expect("chmod 0444");

        let skipped =
            clean_all(&fixture.cache.path().join(super::BUILD_DIR_PARENT)).expect("clean_all");
        assert_eq!(skipped, 0);
        assert!(!clean_dir.exists());
    }

    #[tokio::test]
    async fn a_sharded_idle_build_directory_is_collected_without_touching_active_sibling() {
        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        let now = now_millis();

        let idle_recorded = fixture.build_dir("c3/11111111111111");
        let idle_manifest = fixture.workspace("idle-sharded");
        record(
            &pool,
            &idle_recorded,
            std::slice::from_ref(&idle_manifest),
            now - 31 * DAY_MS,
        )
        .await
        .expect("record idle");

        let idle_unrecorded = fixture.build_dir("c3/22222222222222");
        age(&idle_unrecorded, 31);

        let active_recorded = fixture.build_dir("c3/33333333333333");
        let active_manifest = fixture.workspace("active-sharded");
        record(
            &pool,
            &active_recorded,
            std::slice::from_ref(&active_manifest),
            now - 2 * DAY_MS,
        )
        .await
        .expect("record active");

        let mut collected = collect(&pool, fixture.cache.path(), IDLE, now)
            .await
            .expect("collect");
        collected
            .removed
            .sort_by(|(left, _), (right, _)| left.cmp(right));
        assert_eq!(
            collected.removed,
            [
                (idle_recorded.clone(), Reason::Idle),
                (idle_unrecorded.clone(), Reason::Idle),
            ]
        );
        assert!(!idle_recorded.exists());
        assert!(!idle_unrecorded.exists());
        assert!(active_recorded.join("debug/deps/libdemo.rlib").exists());
        assert_eq!(remaining_rows(&pool).await, 1);
    }

    #[tokio::test]
    async fn over_budget_evicts_unlocked_idle_directories_oldest_first_while_skipping_locked() {
        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        let now = now_millis();

        let oldest = fixture.build_dir("a0/11111111111111");
        std::fs::write(oldest.join("debug/deps/big.bin"), vec![1u8; 4096]).expect("oldest payload");
        let oldest_manifest = fixture.workspace("oldest");
        record(
            &pool,
            &oldest,
            std::slice::from_ref(&oldest_manifest),
            now - 3 * DAY_MS,
        )
        .await
        .expect("record oldest");

        let locked_middle = fixture.build_dir("a0/22222222222222");
        std::fs::write(locked_middle.join("debug/deps/big.bin"), vec![2u8; 4096])
            .expect("locked payload");
        let locked_manifest = fixture.workspace("locked");
        record(
            &pool,
            &locked_middle,
            std::slice::from_ref(&locked_manifest),
            now - 2 * DAY_MS,
        )
        .await
        .expect("record locked");
        let cargo_lock = File::options()
            .read(true)
            .write(true)
            .open(locked_middle.join("debug").join(CARGO_BUILD_LOCK))
            .expect("open lock");
        cargo_lock.lock().expect("hold cargo lock");

        let newer = fixture.build_dir("a0/33333333333333");
        std::fs::write(newer.join("debug/deps/big.bin"), vec![3u8; 4096]).expect("newer payload");
        let newer_manifest = fixture.workspace("newer");
        record(
            &pool,
            &newer,
            std::slice::from_ref(&newer_manifest),
            now - DAY_MS,
        )
        .await
        .expect("record newer");

        let newest = fixture.build_dir("a0/44444444444444");
        std::fs::write(newest.join("debug/deps/big.bin"), vec![4u8; 4096]).expect("newest payload");
        let newest_manifest = fixture.workspace("newest");
        record(&pool, &newest, std::slice::from_ref(&newest_manifest), now)
            .await
            .expect("record newest");

        let policy = super::Policy {
            idle: IDLE,
            max_bytes: 9000,
            min_free_bytes: 0,
        };
        let collected = super::collect_with_policy(&pool, fixture.cache.path(), policy, now)
            .await
            .expect("collect over budget");
        assert_eq!(
            collected.removed,
            [
                (oldest.clone(), Reason::OverBudget),
                (newer.clone(), Reason::OverBudget),
            ]
        );
        assert_eq!(collected.locked, std::slice::from_ref(&locked_middle));
        assert!(collected.reclaimed_bytes >= 8192);
        assert!(!oldest.exists());
        assert!(locked_middle.exists());
        assert!(!newer.exists());
        assert!(newest.exists());
        drop(cargo_lock);
    }

    #[tokio::test]
    async fn low_disk_evicts_lru_until_free_space_floor_is_met() {
        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        let now = now_millis();

        let first = fixture.build_dir("b0/11111111111111");
        std::fs::write(first.join("debug/deps/big.bin"), vec![5u8; 4096]).expect("first");
        let first_manifest = fixture.workspace("first-low");
        record(
            &pool,
            &first,
            std::slice::from_ref(&first_manifest),
            now - 2 * DAY_MS,
        )
        .await
        .expect("record first");

        let second = fixture.build_dir("b0/22222222222222");
        std::fs::write(second.join("debug/deps/big.bin"), vec![6u8; 4096]).expect("second");
        let second_manifest = fixture.workspace("second-low");
        record(&pool, &second, std::slice::from_ref(&second_manifest), now)
            .await
            .expect("record second");

        let policy = super::Policy {
            idle: IDLE,
            max_bytes: u64::MAX,
            min_free_bytes: 5000,
        };
        let collected = super::collect_with_avail_override(
            &pool,
            fixture.cache.path(),
            policy,
            now,
            Some(2000),
        )
        .await
        .expect("collect low disk");
        assert_eq!(collected.removed, [(first.clone(), Reason::LowDisk)]);
        assert!(!first.exists());
        assert!(second.exists());
    }

    #[tokio::test]
    async fn gc_worktrees_removes_only_matching_worktree_before_and_after_deletion() {
        let fixture = Fixture::new();
        let pool = connect(fixture.cache.path()).await.expect("state db");
        let now = now_millis();

        let target_dir = fixture.build_dir("d0/11111111111111");
        let target_manifest = fixture.workspace("wt-removed");
        let wt_root = target_manifest.parent().expect("wt dir").to_path_buf();
        record(
            &pool,
            &target_dir,
            std::slice::from_ref(&target_manifest),
            now,
        )
        .await
        .expect("record target");

        let other_dir = fixture.build_dir("d0/22222222222222");
        let other_manifest = fixture.workspace("wt-other");
        record(
            &pool,
            &other_dir,
            std::slice::from_ref(&other_manifest),
            now,
        )
        .await
        .expect("record other");

        std::fs::remove_dir_all(&wt_root).expect("simulate git worktree remove");
        let collected = super::gc_worktrees(&pool, fixture.cache.path(), &[wt_root])
            .await
            .expect("gc_worktrees");
        assert_eq!(
            collected.removed,
            [(target_dir.clone(), Reason::WorkspaceGone)]
        );
        assert!(!target_dir.exists());
        assert!(other_dir.exists());
        assert_eq!(remaining_rows(&pool).await, 1);
    }
}
