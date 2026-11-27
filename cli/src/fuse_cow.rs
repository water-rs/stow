//! Linux FUSE virtual copy-on-write layer for `<cache_dir>/build-dir/` on
//! non-copy-on-write filesystems such as ext4 (stow#1704).
//!
//! Enabled by default on Linux (`fuse = true`; opt out via `fuse = false` in
//! `config.toml` or `STOW_FUSE=0`) whenever `<cache_dir>/build-dir/` is
//! configured or used (skipped under `stow setup --no-build-dir` when no build
//! targets `<cache_dir>/build-dir/`). Automatically skipped on native `CoW`
//! filesystems (`btrfs` / `xfs`) and cleanly falls back to regular byte copies
//! when `/dev/fuse` or `fusermount3`/`fusermount` is unavailable.
//!
//! When mounted at `<cache_dir>/build-dir/` backed by
//! `<cache_dir>/build-dir-backing/`:
//!
//! - Regular files (`.fingerprint/`, compiled outputs, `.cargo-build-lock`,
//!   dep-info) pass straight through to `build-dir-backing/` with kernel
//!   writeback caching (`FUSE_WRITEBACK_CACHE`) and openless I/O
//!   (`FUSE_NO_OPEN_SUPPORT`) so cached reads stay inside the kernel.
//! - Served cache artifacts are materialized directly into `build-dir-backing/`
//!   (with an internal `user.stow.cow.clone` `setxattr` fallback for custom
//!   mountpoints): the immutable cache file is hard-linked into
//!   `<cache_dir>/build-dir-backing/.stow-cow-blobs/<dev>-<ino>` (0 extra
//!   blocks on the same filesystem, keeping the bytes alive even if the cache
//!   entry is later evicted) and a zero-byte stub in `build-dir-backing/` is
//!   tagged with `user.stow.cow = v1:<size>:<blob_name>`.
//! - Each worktree's stub has its own ext4 inode, so `mtime` and `mode` are
//!   independent per worktree (preserving Cargo fingerprint freshness,
//!   stow#634) and persist across daemon restarts.
//! - Any write (`write`, `O_WRONLY`/`O_RDWR`/`O_TRUNC`, `fallocate`) or
//!   size-changing `setattr` copies up the stub into a private backing file
//!   transparently. Unlinked-while-open regular files are parked in
//!   `.stow-cow-unlinked/<ino>` (0 held file descriptors) until kernel `FORGET`.

#[cfg(not(target_os = "linux"))]
use std::io;
#[cfg(not(target_os = "linux"))]
use std::path::Path;
#[cfg(not(target_os = "linux"))]
use std::sync::Arc;

/// Backing directory sibling to `build-dir/` that stores real files,
/// zero-byte copy-on-write stubs, and `.stow-cow-blobs/`.
pub const BUILD_DIR_BACKING: &str = "build-dir-backing";

#[cfg(target_os = "linux")]
pub use linux::{
    FuseMount, ensure_mounted, gc_unreferenced_blobs, is_fuse_mount, try_virtual_clone,
};

/// Handle to an active FUSE mount for one cache directory. Dropping it
/// unmounts `<cache_dir>/build-dir/`.
#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct FuseMount;

/// Mount `<cache_dir>/build-dir/` when `enabled` is true on a Linux
/// non-copy-on-write filesystem. Inert on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub const fn ensure_mounted(_cache_dir: &Path, _enabled: bool) -> Option<Arc<FuseMount>> {
    None
}

/// Whether `path` currently resides on a FUSE filesystem.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub const fn is_fuse_mount(_path: &Path) -> bool {
    false
}

/// Create a virtual copy-on-write clone of `source` at `staged` if `staged`
/// lies on a stow FUSE mount. Always returns `Ok(false)` on non-Linux
/// platforms.
///
/// # Errors
///
/// Never fails on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)]
pub const fn try_virtual_clone(_source: &Path, _staged: &Path) -> io::Result<bool> {
    Ok(false)
}

/// Remove unreferenced immutable blobs from `<cache_dir>/build-dir-backing/.stow-cow-blobs/`.
///
/// # Errors
///
/// Never fails on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)]
pub const fn gc_unreferenced_blobs(_cache_dir: &Path) -> io::Result<usize> {
    Ok(0)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};
    use std::ffi::{CString, OsStr, OsString};
    use std::fs::{File, OpenOptions};
    use std::io::{self, Seek, SeekFrom};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{DirEntryExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Component, Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, OnceLock, RwLock};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use fuser::{
        BackgroundSession, BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem,
        FopenFlags, Generation, INodeNo, InitFlags, KernelConfig, LockOwner, MountOption, Notifier,
        OpenAccMode, OpenFlags, Owner, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
        ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyLseek, ReplyOpen,
        ReplyStatfs, ReplyWrite, ReplyXattr, Request, SessionACL, TimeOrNow, WriteFlags,
    };

    use super::BUILD_DIR_BACKING;
    use crate::build_dirs::BUILD_DIR_PARENT;

    /// Hidden directory inside `build-dir-backing/` holding immutable hard
    /// links to cached artifact files referenced by copy-on-write stubs.
    const COW_BLOBS_DIR: &str = ".stow-cow-blobs";
    /// Hidden directory inside `build-dir-backing/` holding unlinked-while-open
    /// backing files until kernel `FORGET` releases the last lookup reference.
    const COW_UNLINKED_DIR: &str = ".stow-cow-unlinked";
    /// Extended attribute stored on zero-byte copy-on-write stubs in `build-dir-backing/`.
    const COW_XATTR_NAME: &str = "user.stow.cow";
    /// Write-only control extended attribute accepted by the FUSE mount to
    /// convert an empty staged file into a virtual copy-on-write clone of a cache file.
    const COW_CLONE_XATTR_NAME: &str = "user.stow.cow.clone";
    /// Prefix of the serialized `user.stow.cow` payload (`v1:<size>:<blob>`).
    const COW_XATTR_PREFIX: &str = "v1:";
    /// Kernel cache TTL for stable lookups and attributes. Safe to keep long
    /// because all mutations under `build-dir/` flow through this FUSE mount
    /// (and direct backing clones verify kernel visibility before returning).
    const ATTR_TTL: Duration = Duration::from_secs(300);
    /// Grace period before GC removes an unreferenced blob so a concurrent
    /// `setxattr` linking a fresh blob is never raced.
    const BLOB_GC_GRACE: Duration = Duration::from_secs(60);

    /// Linux `FUSE_SUPER_MAGIC` (`0x65735546`, from `<linux/magic.h>`).
    const FUSE_SUPER_MAGIC: libc::c_long = 0x6573_5546;

    /// Handle to a live FUSE mount for one cache directory.
    #[derive(Debug)]
    pub struct FuseMount {
        mountpoint: PathBuf,
        session: Mutex<Option<BackgroundSession>>,
    }

    impl FuseMount {
        /// Mount a FUSE virtual copy-on-write overlay at `mountpoint` backed by
        /// `backing_dir`, allowing virtual clones from files under `cache_dir`.
        ///
        /// # Errors
        ///
        /// Returns an I/O error if directories cannot be prepared or the FUSE
        /// session fails to mount.
        pub fn mount(cache_dir: &Path, mountpoint: &Path, backing_dir: &Path) -> io::Result<Self> {
            std::fs::create_dir_all(mountpoint)?;
            std::fs::create_dir_all(backing_dir.join(COW_BLOBS_DIR))?;

            let canonical_cache = std::fs::canonicalize(cache_dir)?;
            let canonical_backing = std::fs::canonicalize(backing_dir)?;
            let canonical_mount = std::fs::canonicalize(mountpoint)?;

            let notifier = Arc::new(OnceLock::new());
            let fs = StowCowFs::new(
                canonical_cache,
                canonical_mount,
                canonical_backing,
                Arc::clone(&notifier),
            )?;

            let mut config = Config::default();
            config.mount_options = vec![
                MountOption::FSName("stow-cow".to_owned()),
                MountOption::Subtype("stow".to_owned()),
                MountOption::DefaultPermissions,
                MountOption::NoSuid,
                MountOption::NoDev,
                MountOption::RW,
                MountOption::Exec,
                MountOption::NoAtime,
            ];
            config.acl = SessionACL::Owner;
            let threads =
                std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get);
            config.n_threads = Some(threads);
            config.clone_fd = true;

            let session = fuser::spawn_mount(fs, mountpoint, &config)?;
            let _ = notifier.set(session.notifier());
            Ok(Self {
                mountpoint: mountpoint.to_path_buf(),
                session: Mutex::new(Some(session)),
            })
        }

        /// Explicitly unmount this FUSE session, falling back to lazy
        /// `fusermount3 -uz` if the mountpoint is still busy.
        pub fn unmount(&self) {
            let session = self
                .session
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(session) = session {
                drop(session);
            }
            if is_fuse_mount(&self.mountpoint) || is_stale_fuse_mount(&self.mountpoint) {
                let _ = lazy_unmount(&self.mountpoint);
            }
        }
    }

    impl Drop for FuseMount {
        fn drop(&mut self) {
            self.unmount();
        }
    }

    /// Ensure `<cache_dir>/build-dir/` is mounted with FUSE virtual copy-on-write when
    /// `enabled` is true and the underlying filesystem lacks native reflinks.
    ///
    /// Returns `None` when disabled, when the filesystem already supports
    /// native copy-on-write (`btrfs`/`xfs`), when a live `cargo` build already holds a
    /// lock on an unmounted `build-dir/`, or when `/dev/fuse` / `fusermount`
    /// is unavailable (logging a warning once and falling back to byte copies).
    #[must_use]
    pub fn ensure_mounted(cache_dir: &Path, enabled: bool) -> Option<Arc<FuseMount>> {
        if !enabled {
            return None;
        }
        if let Err(error) = std::fs::create_dir_all(cache_dir) {
            tracing::warn!(
                %error,
                cache_dir = %cache_dir.display(),
                "cannot prepare cache dir for FUSE mount; falling back to byte copies"
            );
            return None;
        }
        if is_native_cow_fs(cache_dir) {
            tracing::debug!(
                cache_dir = %cache_dir.display(),
                "cache dir is already on a native CoW filesystem; skipping FUSE mount"
            );
            return None;
        }
        if !fuse_runtime_available() {
            tracing::info!(
                cache_dir = %cache_dir.display(),
                "FUSE virtual CoW unavailable (/dev/fuse or fusermount missing); falling back to byte copies"
            );
            return None;
        }

        let mountpoint = cache_dir.join(BUILD_DIR_PARENT);
        let backing_dir = cache_dir.join(BUILD_DIR_BACKING);

        if is_stale_fuse_mount(&mountpoint) {
            tracing::warn!(
                mountpoint = %mountpoint.display(),
                "detected stale FUSE mount (ENOTCONN); unmounting before remount"
            );
            if let Err(error) = lazy_unmount(&mountpoint) {
                tracing::warn!(
                    %error,
                    mountpoint = %mountpoint.display(),
                    "failed to clear stale FUSE mount; falling back to byte copies"
                );
                return None;
            }
        }

        if is_fuse_mount(&mountpoint) {
            tracing::debug!(
                mountpoint = %mountpoint.display(),
                "build-dir is already FUSE-mounted"
            );
            return None;
        }

        if mountpoint.exists() {
            match crate::build_dirs::has_active_cargo_lock(&mountpoint) {
                Ok(true) => {
                    tracing::debug!(
                        mountpoint = %mountpoint.display(),
                        "a running cargo build holds a lock in unmounted build-dir; deferring FUSE mount"
                    );
                    return None;
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(
                        %error,
                        mountpoint = %mountpoint.display(),
                        "could not inspect build-dir locks before FUSE mount; falling back to byte copies"
                    );
                    return None;
                }
            }
            if let Err(error) = migrate_existing_build_dirs(&mountpoint, &backing_dir) {
                tracing::warn!(
                    %error,
                    mountpoint = %mountpoint.display(),
                    backing_dir = %backing_dir.display(),
                    "failed to migrate existing build-dir entries into backing dir; falling back to byte copies"
                );
                return None;
            }
        }

        match FuseMount::mount(cache_dir, &mountpoint, &backing_dir) {
            Ok(mount) => {
                tracing::info!(
                    mountpoint = %mountpoint.display(),
                    backing_dir = %backing_dir.display(),
                    "mounted Linux FUSE virtual CoW layer for build-dir"
                );
                Some(Arc::new(mount))
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    mountpoint = %mountpoint.display(),
                    "failed to mount Linux FUSE virtual CoW layer; falling back to byte copies"
                );
                None
            }
        }
    }

    /// Move any existing workspace directories out of an unmounted
    /// `build-dir/` into `build-dir-backing/` so mounting over `build-dir/`
    /// preserves every existing workspace on the same filesystem.
    fn migrate_existing_build_dirs(mountpoint: &Path, backing_dir: &Path) -> io::Result<()> {
        std::fs::create_dir_all(backing_dir)?;
        for entry in std::fs::read_dir(mountpoint)? {
            let entry = entry?;
            let src = entry.path();
            let dst = backing_dir.join(entry.file_name());
            if dst.exists() {
                merge_or_replace_dir(&src, &dst)?;
            } else {
                std::fs::rename(&src, &dst)?;
            }
        }
        Ok(())
    }

    fn merge_or_replace_dir(src: &Path, dst: &Path) -> io::Result<()> {
        if src.is_dir() && dst.is_dir() {
            for entry in std::fs::read_dir(src)? {
                let entry = entry?;
                let child_src = entry.path();
                let child_dst = dst.join(entry.file_name());
                if child_dst.exists() {
                    merge_or_replace_dir(&child_src, &child_dst)?;
                } else {
                    std::fs::rename(&child_src, &child_dst)?;
                }
            }
            std::fs::remove_dir(src)?;
        } else {
            if dst.is_dir() {
                stow_types::fs::remove_dir_all(dst)?;
            } else if dst.exists() {
                std::fs::remove_file(dst)?;
            }
            std::fs::rename(src, dst)?;
        }
        Ok(())
    }

    /// Standard system locations searched when the detached stow daemon runs
    /// with a cleared `PATH` environment.
    const FUSERMOUNT_CANDIDATES: [&str; 8] = [
        "/bin/fusermount3",
        "/usr/bin/fusermount3",
        "/sbin/fusermount3",
        "/run/wrappers/bin/fusermount3",
        "/bin/fusermount",
        "/usr/bin/fusermount",
        "/sbin/fusermount",
        "/run/wrappers/bin/fusermount",
    ];

    fn is_executable_file(path: &Path) -> bool {
        std::fs::metadata(path)
            .is_ok_and(|meta| meta.is_file() && (meta.permissions().mode() & 0o111) != 0)
    }

    fn find_fusermount() -> Option<PathBuf> {
        if let Some(explicit) = std::env::var_os("FUSERMOUNT_PATH") {
            let path = PathBuf::from(explicit);
            if is_executable_file(&path) {
                return Some(path);
            }
        }
        if let Ok(path) = which::which("fusermount3").or_else(|_| which::which("fusermount")) {
            return Some(path);
        }
        FUSERMOUNT_CANDIDATES
            .into_iter()
            .map(PathBuf::from)
            .find(|path| is_executable_file(path))
    }

    fn fuse_runtime_available() -> bool {
        if !Path::new("/dev/fuse").exists() {
            return false;
        }
        if OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/fuse")
            .is_err()
        {
            return false;
        }
        find_fusermount().is_some()
    }

    fn is_native_cow_fs(path: &Path) -> bool {
        statfs_type(path).is_some_and(|fs_type| {
            fs_type == libc::BTRFS_SUPER_MAGIC || fs_type == libc::XFS_SUPER_MAGIC
        })
    }

    /// Whether `path` currently resides on a FUSE filesystem.
    #[must_use]
    pub fn is_fuse_mount(path: &Path) -> bool {
        statfs_type(path) == Some(FUSE_SUPER_MAGIC)
    }

    fn is_stale_fuse_mount(path: &Path) -> bool {
        match std::fs::symlink_metadata(path) {
            Ok(_) => false,
            Err(error) => error.raw_os_error() == Some(libc::ENOTCONN),
        }
    }

    fn statfs_type(path: &Path) -> Option<libc::c_long> {
        let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::zeroed();
        // SAFETY: `c_path` is NUL-terminated and `stat` is a writable `statfs`.
        let rc = unsafe { libc::statfs(c_path.as_ptr(), stat.as_mut_ptr()) };
        if rc != 0 {
            return None;
        }
        // SAFETY: `statfs` succeeded and initialized the struct.
        Some(unsafe { stat.assume_init() }.f_type)
    }

    fn lazy_unmount(mountpoint: &Path) -> io::Result<()> {
        let tool = find_fusermount().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "neither fusermount3 nor fusermount found",
            )
        })?;
        let status = Command::new(tool).arg("-uz").arg(mountpoint).status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "fusermount -uz {} exited with {status}",
                mountpoint.display()
            )))
        }
    }

    /// Try to materialize `source` at the not-yet-existing `staged` path as a
    /// virtual copy-on-write clone on a stow FUSE mount. Returns `Ok(true)` if the
    /// virtual clone was registered, or `Ok(false)` if `staged` is not on a
    /// stow FUSE mount (leaving no file behind so the caller can fall back to
    /// byte copying).
    ///
    /// When `staged` lies under `<cache_dir>/build-dir/` with a sibling
    /// `<cache_dir>/build-dir-backing/.stow-cow-blobs/`, creates the immutable
    /// blob hard link and tagged zero-byte stub directly in the backing tree so
    /// staging pays zero FUSE round-trips and the kernel observes the virtual
    /// file size on the very first lookup (compatible with `FUSE_WRITEBACK_CACHE`).
    ///
    /// # Errors
    ///
    /// Propagates unexpected filesystem errors while staging the stub file.
    pub fn try_virtual_clone(source: &Path, staged: &Path) -> io::Result<bool> {
        if let Some(result) = try_direct_virtual_clone(source, staged) {
            return result;
        }
        let parent = staged
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if !is_fuse_mount(parent) {
            return Ok(false);
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(staged)?;
        let attr_name = CString::new(COW_CLONE_XATTR_NAME)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let source_bytes = source.as_os_str().as_bytes();
        // SAFETY: `file` is an open fd, `attr_name` is NUL-terminated, and
        // `source_bytes` is a valid buffer of length `source_bytes.len()`.
        let rc = unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                attr_name.as_ptr(),
                source_bytes.as_ptr().cast(),
                source_bytes.len(),
                0,
            )
        };
        drop(file);
        if rc == 0 {
            return Ok(true);
        }
        let _ = std::fs::remove_file(staged);
        let error = io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(libc::EOPNOTSUPP | libc::ENOSYS | libc::EXDEV | libc::EACCES | libc::EINVAL)
        ) {
            tracing::debug!(
                %error,
                source = %source.display(),
                staged = %staged.display(),
                "FUSE virtual clone declined; falling back to byte copy"
            );
            return Ok(false);
        }
        Err(error)
    }

    /// Resolve `<cache_dir>/build-dir/<rel>` to `(cache_dir, mountpoint, backing_dir, rel)`
    /// when `staged` sits inside a standard stow FUSE mount whose sibling
    /// `build-dir-backing/.stow-cow-blobs` exists.
    ///
    /// Matches the `build-dir` component in memory first so only a single
    /// `statfs` check runs on the mountpoint instead of one per ancestor.
    fn resolve_direct_backing(staged: &Path) -> Option<(PathBuf, PathBuf, PathBuf, PathBuf)> {
        let parent = staged.parent()?;
        let canonical_parent = std::fs::canonicalize(parent).ok()?;
        let file_name = staged.file_name()?;
        let mut cursor = canonical_parent.as_path();
        let mut found = None;
        while let Some(next_parent) = cursor.parent() {
            if cursor.file_name() == Some(OsStr::new(BUILD_DIR_PARENT)) {
                let backing_dir = next_parent.join(BUILD_DIR_BACKING);
                if backing_dir.join(COW_BLOBS_DIR).is_dir() && is_fuse_mount(cursor) {
                    found = Some((next_parent.to_path_buf(), cursor.to_path_buf(), backing_dir));
                    break;
                }
            }
            cursor = next_parent;
        }
        let (cache_dir, mountpoint, backing_dir) = found?;
        let rel_parent = canonical_parent.strip_prefix(&mountpoint).ok()?;
        let rel = rel_parent.join(file_name);
        Some((cache_dir, mountpoint, backing_dir, rel))
    }

    fn try_direct_virtual_clone(source: &Path, staged: &Path) -> Option<io::Result<bool>> {
        let (cache_dir, mountpoint, backing_dir, rel) = resolve_direct_backing(staged)?;
        let backing_staged_out = {
            let Ok(canonical_source) = std::fs::canonicalize(source) else {
                return Some(Ok(false));
            };
            let canonical_cache = match std::fs::canonicalize(&cache_dir) {
                Ok(path) => path,
                Err(err) => return Some(Err(err)),
            };
            let canonical_backing = match std::fs::canonicalize(&backing_dir) {
                Ok(path) => path,
                Err(err) => return Some(Err(err)),
            };
            if !canonical_source.starts_with(&canonical_cache)
                || canonical_source.starts_with(&mountpoint)
                || canonical_source.starts_with(&canonical_backing)
            {
                return Some(Ok(false));
            }
            let src_meta = match std::fs::symlink_metadata(&canonical_source) {
                Ok(meta) => meta,
                Err(err) => return Some(Err(err)),
            };
            if !src_meta.is_file() {
                return Some(Ok(false));
            }
            let blob_name = format!("{}-{}", src_meta.dev(), src_meta.ino());
            let blob_path = canonical_backing.join(COW_BLOBS_DIR).join(&blob_name);
            match std::fs::hard_link(&canonical_source, &blob_path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::EXDEV | libc::EOPNOTSUPP | libc::EACCES | libc::EPERM)
                    ) =>
                {
                    return Some(Ok(false));
                }
                Err(error) => return Some(Err(error)),
            }
            let backing_staged = canonical_backing.join(&rel);
            let file = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&backing_staged)
            {
                Ok(file) => file,
                Err(err) => return Some(Err(err)),
            };
            let target = CowTarget {
                blob_name,
                size: src_meta.len(),
            };
            if let Err(error) = write_cow_xattr_fd(file.as_raw_fd(), &target) {
                drop(file);
                let _ = std::fs::remove_file(&backing_staged);
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EOPNOTSUPP | libc::ENOSYS | libc::EACCES | libc::EINVAL)
                ) {
                    return Some(Ok(false));
                }
                return Some(Err(error));
            }
            drop(file);
            backing_staged
        };
        if std::fs::symlink_metadata(staged).is_err() {
            if reveal_hidden_direct_stub(&backing_staged_out, staged) {
                return Some(Ok(true));
            }
            let _ = std::fs::remove_file(&backing_staged_out);
            return None;
        }
        Some(Ok(true))
    }

    /// When a prior negative dentry on `staged` hides a stub written directly
    /// into `build-dir-backing/`, move the backing stub to a fresh uncached
    /// sibling name and rename it into `staged` through FUSE so the kernel
    /// replaces the negative dentry with the positive `CoW` inode (`size = cow.size`).
    fn reveal_hidden_direct_stub(backing_staged: &Path, staged: &Path) -> bool {
        let Some(backing_parent) = backing_staged.parent() else {
            return false;
        };
        let Some(fuse_parent) = staged.parent() else {
            return false;
        };
        let Ok(tmp) = tempfile::Builder::new()
            .prefix(".stow-cow-vis-")
            .make_in(backing_parent, |tmp_path| {
                std::fs::rename(backing_staged, tmp_path)
            })
        else {
            return false;
        };
        let mut tmp_path = tmp.into_temp_path();
        let Some(tmp_name) = tmp_path.file_name() else {
            return false;
        };
        let fuse_tmp = fuse_parent.join(tmp_name);
        if std::fs::rename(&fuse_tmp, staged).is_ok() {
            tmp_path.disable_cleanup(true);
            return true;
        }
        false
    }

    /// Remove blobs in `<cache_dir>/build-dir-backing/.stow-cow-blobs/` that
    /// no copy-on-write stub in `build-dir-backing/` references anymore and that are
    /// older than [`BLOB_GC_GRACE`].
    ///
    /// # Errors
    ///
    /// Fails if reading the backing or blob directories fails for a reason
    /// other than absence.
    pub fn gc_unreferenced_blobs(cache_dir: &Path) -> io::Result<usize> {
        let backing_dir = cache_dir.join(BUILD_DIR_BACKING);
        let blobs_dir = backing_dir.join(COW_BLOBS_DIR);
        if !blobs_dir.is_dir() {
            return Ok(0);
        }

        let mut referenced = HashSet::new();
        for entry in walkdir::WalkDir::new(&backing_dir)
            .into_iter()
            .filter_entry(|entry| {
                !(entry.depth() == 1 && entry.file_name() == OsStr::new(COW_BLOBS_DIR))
            })
        {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error)
                    if error
                        .io_error()
                        .is_some_and(|io| io.kind() == io::ErrorKind::NotFound) =>
                {
                    continue;
                }
                Err(error) => return Err(io::Error::other(error)),
            };
            if !entry.file_type().is_file() {
                continue;
            }
            if let Ok(meta) = entry.metadata()
                && meta.len() == 0
                && let Ok(Some(target)) = read_cow_xattr(entry.path())
            {
                referenced.insert(target.blob_name);
            }
        }

        let cutoff = SystemTime::now().checked_sub(BLOB_GC_GRACE);
        let mut removed = 0usize;
        for entry in std::fs::read_dir(&blobs_dir)? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if referenced.contains(&name) {
                continue;
            }
            let path = entry.path();
            if let Some(cutoff) = cutoff
                && let Ok(meta) = entry.metadata()
                && let Ok(modified) = meta.modified()
                && modified > cutoff
            {
                continue;
            }
            match std::fs::remove_file(&path) {
                Ok(()) => removed += 1,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(removed)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CowTarget {
        blob_name: String,
        size: u64,
    }

    impl CowTarget {
        fn encode(&self) -> String {
            format!("{COW_XATTR_PREFIX}{}:{}", self.size, self.blob_name)
        }

        fn decode(raw: &[u8]) -> Option<Self> {
            let text = std::str::from_utf8(raw).ok()?;
            let rest = text.strip_prefix(COW_XATTR_PREFIX)?;
            let (size_str, blob_name) = rest.split_once(':')?;
            let size = size_str.parse::<u64>().ok()?;
            if blob_name.is_empty() || blob_name.contains('/') || blob_name.contains('\0') {
                return None;
            }
            Some(Self {
                blob_name: blob_name.to_owned(),
                size,
            })
        }
    }

    #[derive(Debug)]
    struct InodeEntry {
        ino: INodeNo,
        backing_ino: u64,
        /// Live relative paths under `backing_root` pointing at this inode, or
        /// the hidden `.stow-cow-unlinked/<ino>` path when `unlinked` is true.
        /// Usually length 1; holds multiple entries across `link` + `unlink`
        /// (`persist_noclobber`).
        paths: Vec<PathBuf>,
        kind: FileType,
        cow: Option<CowTarget>,
        unlinked: bool,
        nlookup: AtomicU64,
    }

    impl InodeEntry {
        fn primary_path(&self) -> Option<&Path> {
            self.paths.first().map(PathBuf::as_path)
        }
    }

    #[derive(Debug)]
    struct InodeTable {
        entries: HashMap<INodeNo, InodeEntry>,
        backing_map: HashMap<u64, INodeNo>,
        path_to_ino: HashMap<PathBuf, INodeNo>,
        next_id: u64,
    }

    impl InodeTable {
        fn new(root_backing_ino: u64) -> Self {
            let mut entries = HashMap::new();
            let mut backing_map = HashMap::new();
            let mut path_to_ino = HashMap::new();
            entries.insert(
                INodeNo::ROOT,
                InodeEntry {
                    ino: INodeNo::ROOT,
                    backing_ino: root_backing_ino,
                    paths: vec![PathBuf::new()],
                    kind: FileType::Directory,
                    cow: None,
                    unlinked: false,
                    nlookup: AtomicU64::new(1),
                },
            );
            backing_map.insert(root_backing_ino, INodeNo::ROOT);
            path_to_ino.insert(PathBuf::new(), INodeNo::ROOT);
            Self {
                entries,
                backing_map,
                path_to_ino,
                next_id: 2,
            }
        }

        fn resolve_backing_path(&self, backing_root: &Path, ino: INodeNo) -> Option<PathBuf> {
            let entry = self.entries.get(&ino)?;
            let rel = entry.primary_path()?;
            if rel.as_os_str().is_empty() {
                Some(backing_root.to_path_buf())
            } else {
                Some(backing_root.join(rel))
            }
        }

        fn resolve_path_and_cow(
            &self,
            backing_root: &Path,
            ino: INodeNo,
        ) -> Option<(PathBuf, Option<CowTarget>, bool)> {
            let entry = self.entries.get(&ino)?;
            let rel = entry.primary_path()?;
            let path = if rel.as_os_str().is_empty() {
                backing_root.to_path_buf()
            } else {
                backing_root.join(rel)
            };
            Some((path, entry.cow.clone(), entry.unlinked))
        }

        /// Detach `rel_path` from `ino`. Once an inode has no remaining live
        /// paths on disk, immediately release its `backing_map` slot so ext4
        /// inode reuse before kernel `FORGET` cannot collide with the unlinked
        /// FUSE inode.
        fn detach_path_from_ino(&mut self, ino: INodeNo, rel_path: &Path) {
            if let Some(entry) = self.entries.get_mut(&ino) {
                entry.paths.retain(|existing| existing != rel_path);
                if entry.paths.is_empty()
                    && entry.ino != INodeNo::ROOT
                    && self.backing_map.get(&entry.backing_ino) == Some(&ino)
                {
                    self.backing_map.remove(&entry.backing_ino);
                }
            }
        }

        /// Fast-path lookup under a shared read lock: if `rel_path` is already
        /// registered for `backing_ino` with matching `kind` and `cow`, bump
        /// `nlookup` atomically without taking the table write lock.
        fn lookup_hit(
            &self,
            rel_path: &Path,
            backing_ino: u64,
            kind: FileType,
            cow: Option<&CowTarget>,
        ) -> Option<INodeNo> {
            let &ino = self.path_to_ino.get(rel_path)?;
            let entry = self.entries.get(&ino)?;
            if entry.backing_ino == backing_ino && entry.kind == kind && entry.cow.as_ref() == cow {
                entry.nlookup.fetch_add(1, Ordering::Relaxed);
                return Some(ino);
            }
            None
        }

        fn upsert_lookup(
            &mut self,
            rel_path: PathBuf,
            backing_ino: u64,
            kind: FileType,
            cow: Option<CowTarget>,
        ) -> INodeNo {
            if let Some(&prev_ino) = self.path_to_ino.get(&rel_path)
                && self
                    .entries
                    .get(&prev_ino)
                    .is_some_and(|entry| entry.backing_ino != backing_ino)
            {
                self.path_to_ino.remove(&rel_path);
                self.detach_path_from_ino(prev_ino, &rel_path);
            }
            if let Some(&ino) = self.backing_map.get(&backing_ino)
                && let Some(entry) = self.entries.get_mut(&ino)
            {
                if !entry.paths.contains(&rel_path) {
                    entry.paths.push(rel_path.clone());
                }
                self.path_to_ino.insert(rel_path, ino);
                entry.kind = kind;
                entry.cow = cow;
                let prev = *entry.nlookup.get_mut();
                *entry.nlookup.get_mut() = prev.saturating_add(1);
                return ino;
            }
            let ino = INodeNo(self.next_id);
            self.next_id += 1;
            self.backing_map.insert(backing_ino, ino);
            self.path_to_ino.insert(rel_path.clone(), ino);
            self.entries.insert(
                ino,
                InodeEntry {
                    ino,
                    backing_ino,
                    paths: vec![rel_path],
                    kind,
                    cow,
                    unlinked: false,
                    nlookup: AtomicU64::new(1),
                },
            );
            ino
        }

        fn forget(&mut self, ino: INodeNo, nlookup: u64) -> (bool, Option<PathBuf>) {
            if ino == INodeNo::ROOT {
                return (false, None);
            }
            let remove = if let Some(entry) = self.entries.get_mut(&ino) {
                let remaining = entry.nlookup.get_mut().saturating_sub(nlookup);
                *entry.nlookup.get_mut() = remaining;
                remaining == 0
            } else {
                false
            };
            if remove && let Some(entry) = self.entries.remove(&ino) {
                let unlinked_rel = if entry.unlinked {
                    entry.paths.first().cloned()
                } else {
                    for path in &entry.paths {
                        if self.path_to_ino.get(path) == Some(&ino) {
                            self.path_to_ino.remove(path);
                        }
                    }
                    None
                };
                if self.backing_map.get(&entry.backing_ino) == Some(&ino) {
                    self.backing_map.remove(&entry.backing_ino);
                }
                return (true, unlinked_rel);
            }
            (false, None)
        }

        fn unlinked_candidate(
            &self,
            rel_path: &Path,
            skip_ino: Option<INodeNo>,
        ) -> Option<INodeNo> {
            let &ino = self.path_to_ino.get(rel_path)?;
            if Some(ino) == skip_ino {
                return None;
            }
            let entry = self.entries.get(&ino)?;
            if entry.kind != FileType::RegularFile
                || entry.unlinked
                || entry.paths.len() != 1
                || entry.nlookup.load(Ordering::Relaxed) == 0
            {
                return None;
            }
            Some(ino)
        }

        fn mark_unlinked(&mut self, rel_path: &Path, unlinked_rel: PathBuf) {
            if let Some(ino) = self.path_to_ino.remove(rel_path)
                && let Some(entry) = self.entries.get_mut(&ino)
            {
                entry.paths = vec![unlinked_rel];
                entry.unlinked = true;
            }
        }

        fn unlink_path(&mut self, rel_path: &Path) {
            if let Some(ino) = self.path_to_ino.remove(rel_path) {
                self.detach_path_from_ino(ino, rel_path);
            }
        }

        fn rename_path(&mut self, old_rel: &Path, new_rel: &Path, exchange: bool) {
            if old_rel == new_rel {
                return;
            }
            let old_ino = self.path_to_ino.get(old_rel).copied();
            let new_ino = self.path_to_ino.get(new_rel).copied();
            if !exchange && old_ino.is_some() && old_ino == new_ino {
                // POSIX rename between two hard links to the same inode is a no-op.
                return;
            }

            let old_is_dir = old_ino
                .and_then(|ino| self.entries.get(&ino))
                .is_some_and(|entry| entry.kind == FileType::Directory);
            let new_is_dir = exchange
                && new_ino
                    .and_then(|ino| self.entries.get(&ino))
                    .is_some_and(|entry| entry.kind == FileType::Directory);

            if !old_is_dir && !new_is_dir {
                self.rename_non_dir_paths(old_rel, new_rel, old_ino, new_ino, exchange);
                return;
            }

            self.rename_dir_paths(old_rel, new_rel, exchange);
        }

        fn rename_non_dir_paths(
            &mut self,
            old_rel: &Path,
            new_rel: &Path,
            old_ino: Option<INodeNo>,
            new_ino: Option<INodeNo>,
            exchange: bool,
        ) {
            if exchange {
                self.path_to_ino.remove(old_rel);
                self.path_to_ino.remove(new_rel);
                if let Some(ino) = old_ino {
                    if let Some(entry) = self.entries.get_mut(&ino) {
                        for path in &mut entry.paths {
                            if path == old_rel {
                                *path = new_rel.to_path_buf();
                            }
                        }
                    }
                    self.path_to_ino.insert(new_rel.to_path_buf(), ino);
                }
                if let Some(ino) = new_ino {
                    if let Some(entry) = self.entries.get_mut(&ino) {
                        for path in &mut entry.paths {
                            if path == new_rel {
                                *path = old_rel.to_path_buf();
                            }
                        }
                    }
                    self.path_to_ino.insert(old_rel.to_path_buf(), ino);
                }
                return;
            }
            if let Some(victim_ino) = self.path_to_ino.remove(new_rel) {
                self.detach_path_from_ino(victim_ino, new_rel);
            }
            if let Some(src_ino) = self.path_to_ino.remove(old_rel) {
                if let Some(entry) = self.entries.get_mut(&src_ino) {
                    for path in &mut entry.paths {
                        if path == old_rel {
                            *path = new_rel.to_path_buf();
                        }
                    }
                }
                self.path_to_ino.insert(new_rel.to_path_buf(), src_ino);
            }
        }

        fn rename_dir_paths(&mut self, old_rel: &Path, new_rel: &Path, exchange: bool) {
            if !exchange && let Some(victim_ino) = self.path_to_ino.remove(new_rel) {
                self.detach_path_from_ino(victim_ino, new_rel);
            }
            let mut moved_paths: Vec<(PathBuf, PathBuf, INodeNo)> = Vec::new();
            for entry in self.entries.values_mut() {
                for path in &mut entry.paths {
                    let replacement = rewrite_renamed_path(path, old_rel, new_rel, exchange);
                    if let Some(updated) = replacement {
                        let prev = std::mem::replace(path, updated.clone());
                        moved_paths.push((prev, updated, entry.ino));
                    }
                }
            }
            for (prev, _, ino) in &moved_paths {
                if self.path_to_ino.get(prev) == Some(ino) {
                    self.path_to_ino.remove(prev);
                }
            }
            for (_, updated, ino) in moved_paths {
                self.path_to_ino.insert(updated, ino);
            }
        }
    }

    fn rewrite_renamed_path(
        path: &Path,
        old_rel: &Path,
        new_rel: &Path,
        exchange: bool,
    ) -> Option<PathBuf> {
        if let Ok(suffix) = path.strip_prefix(old_rel) {
            return Some(if suffix.as_os_str().is_empty() {
                new_rel.to_path_buf()
            } else {
                new_rel.join(suffix)
            });
        }
        if exchange && let Ok(suffix) = path.strip_prefix(new_rel) {
            return Some(if suffix.as_os_str().is_empty() {
                old_rel.to_path_buf()
            } else {
                old_rel.join(suffix)
            });
        }
        None
    }

    #[derive(Debug)]
    enum OpenFile {
        Regular(File),
        CowRead { blob: File, size: u64 },
    }

    thread_local! {
        /// Per-worker reusable scratch buffer for FUSE `read` replies so hot
        /// artifact reads never allocate or zero a fresh 1 MiB `Vec` per call.
        static READ_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    }

    type DirEntryRecord = (u64, FileType, OsString);

    #[derive(Debug)]
    struct OpenDir {
        ino: INodeNo,
        entries: OnceLock<Arc<Vec<DirEntryRecord>>>,
    }

    /// Number of shards in [`HandleTable`]; must be a power of two.
    const HANDLE_SHARDS: usize = 64;
    /// Sharded cache of open backing file descriptors for `FUSE_NO_OPEN_SUPPORT`
    /// (`16 * 16 = 256` fds max, comfortably within default `RLIMIT_NOFILE`).
    const FD_CACHE_SHARDS: usize = 16;
    const FD_CACHE_SLOTS_PER_SHARD: usize = 16;

    type FileHandleShard = RwLock<HashMap<FileHandle, (INodeNo, Arc<OpenFile>)>>;
    type InoHandleShard = RwLock<HashMap<INodeNo, Vec<FileHandle>>>;
    type DirHandleShard = RwLock<HashMap<FileHandle, Arc<OpenDir>>>;

    #[derive(Debug)]
    struct HandleTable {
        files: [FileHandleShard; HANDLE_SHARDS],
        ino_files: [InoHandleShard; HANDLE_SHARDS],
        dirs: [DirHandleShard; HANDLE_SHARDS],
        next_fh: AtomicU64,
    }

    impl Default for HandleTable {
        fn default() -> Self {
            Self {
                files: std::array::from_fn(|_| RwLock::new(HashMap::new())),
                ino_files: std::array::from_fn(|_| RwLock::new(HashMap::new())),
                dirs: std::array::from_fn(|_| RwLock::new(HashMap::new())),
                next_fh: AtomicU64::new(1),
            }
        }
    }

    impl HandleTable {
        fn shard(id: u64) -> usize {
            usize::try_from(id & ((HANDLE_SHARDS - 1) as u64)).unwrap_or(0)
        }

        fn insert_file(&self, ino: INodeNo, file: OpenFile) -> FileHandle {
            let fh = FileHandle(self.next_fh.fetch_add(1, Ordering::Relaxed));
            self.files[Self::shard(fh.0)]
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(fh, (ino, Arc::new(file)));
            self.ino_files[Self::shard(ino.0)]
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry(ino)
                .or_default()
                .push(fh);
            fh
        }

        fn get_file(&self, fh: FileHandle) -> Option<Arc<OpenFile>> {
            self.files[Self::shard(fh.0)]
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&fh)
                .map(|(_, file)| Arc::clone(file))
        }

        fn any_file_for_ino(&self, ino: INodeNo) -> Option<Arc<OpenFile>> {
            let candidates: Vec<FileHandle> = self.ino_files[Self::shard(ino.0)]
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&ino)
                .cloned()?;
            candidates.into_iter().find_map(|fh| self.get_file(fh))
        }

        fn remove_file(&self, fh: FileHandle) -> Option<Arc<OpenFile>> {
            let (ino, file) = self.files[Self::shard(fh.0)]
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&fh)?;
            let mut ino_shard = self.ino_files[Self::shard(ino.0)]
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(fhs) = ino_shard.get_mut(&ino) {
                fhs.retain(|existing| *existing != fh);
                if fhs.is_empty() {
                    ino_shard.remove(&ino);
                }
            }
            drop(ino_shard);
            Some(file)
        }

        fn insert_dir(&self, ino: INodeNo) -> FileHandle {
            let fh = FileHandle(self.next_fh.fetch_add(1, Ordering::Relaxed));
            self.dirs[Self::shard(fh.0)]
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(
                    fh,
                    Arc::new(OpenDir {
                        ino,
                        entries: OnceLock::new(),
                    }),
                );
            fh
        }

        fn get_dir(&self, fh: FileHandle) -> Option<Arc<OpenDir>> {
            self.dirs[Self::shard(fh.0)]
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&fh)
                .cloned()
        }

        fn remove_dir(&self, fh: FileHandle) -> Option<Arc<OpenDir>> {
            self.dirs[Self::shard(fh.0)]
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&fh)
        }
    }

    #[derive(Debug)]
    enum CachedFd {
        Regular { file: File, writable: bool },
        CowRead { blob: File },
    }

    type FdCacheShard = RwLock<HashMap<INodeNo, Arc<CachedFd>>>;

    #[derive(Debug)]
    struct InodeFdCache {
        shards: [FdCacheShard; FD_CACHE_SHARDS],
    }

    impl Default for InodeFdCache {
        fn default() -> Self {
            Self {
                shards: std::array::from_fn(|_| RwLock::new(HashMap::new())),
            }
        }
    }

    impl InodeFdCache {
        fn shard(ino: INodeNo) -> usize {
            usize::try_from(ino.0 & ((FD_CACHE_SHARDS - 1) as u64)).unwrap_or(0)
        }

        fn get(&self, ino: INodeNo) -> Option<Arc<CachedFd>> {
            self.shards[Self::shard(ino)]
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&ino)
                .cloned()
        }

        fn insert(&self, ino: INodeNo, fd: CachedFd) -> Arc<CachedFd> {
            let arc = Arc::new(fd);
            let mut shard = self.shards[Self::shard(ino)]
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if shard.len() >= FD_CACHE_SLOTS_PER_SHARD
                && !shard.contains_key(&ino)
                && let Some(&victim) = shard.keys().next()
            {
                shard.remove(&victim);
            }
            shard.insert(ino, Arc::clone(&arc));
            drop(shard);
            arc
        }

        fn evict(&self, ino: INodeNo) {
            self.shards[Self::shard(ino)]
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&ino);
        }
    }

    struct RenameGuard<'a>(&'a StowCowFs);

    impl<'a> RenameGuard<'a> {
        fn enter(fs: &'a StowCowFs) -> Self {
            fs.rename_in_flight.fetch_add(1, Ordering::AcqRel);
            Self(fs)
        }
    }

    impl Drop for RenameGuard<'_> {
        fn drop(&mut self) {
            self.0.rename_seq.fetch_add(1, Ordering::Release);
            self.0.rename_in_flight.fetch_sub(1, Ordering::Release);
        }
    }

    const fn negative_entry_attr() -> FileAttr {
        FileAttr {
            ino: INodeNo(0),
            size: 0,
            blocks: 0,
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::RegularFile,
            perm: 0,
            nlink: 0,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 0,
            flags: 0,
        }
    }

    /// Passthrough + virtual copy-on-write FUSE filesystem for `<cache_dir>/build-dir/`.
    struct StowCowFs {
        cache_dir: PathBuf,
        mountpoint: PathBuf,
        backing_root: PathBuf,
        blobs_dir: PathBuf,
        unlinked_dir: PathBuf,
        notifier: Arc<OnceLock<Notifier>>,
        /// Negotiated in `init()` when the kernel supports `FUSE_WRITEBACK_CACHE`.
        writeback_cache: bool,
        /// Negotiated in `init()` when the kernel supports `FUSE_NO_OPEN_SUPPORT`.
        no_open: bool,
        /// Write-locked only for rare directory renames; all regular-file
        /// operations take a shared read lock (uncontended during builds).
        /// Lock order: `copy_up_lock` -> `dir_lock` -> `inodes` -> `handles` -> `fd_cache`.
        dir_lock: RwLock<()>,
        /// Tracks concurrent regular-file renames so inode-by-path lookups
        /// retry cleanly if a rename moves a backing file mid-syscall.
        rename_in_flight: AtomicUsize,
        rename_seq: AtomicU64,
        inodes: RwLock<InodeTable>,
        handles: HandleTable,
        fd_cache: InodeFdCache,
        /// Serializes copy-up operations so concurrent write opens on the same
        /// copy-on-write stub cannot corrupt the transition to a private file.
        copy_up_lock: Mutex<()>,
    }

    impl Drop for StowCowFs {
        fn drop(&mut self) {
            let _ = stow_types::fs::remove_dir_all(&self.unlinked_dir);
        }
    }

    struct SetattrParams {
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
    }

    impl StowCowFs {
        fn new(
            cache_dir: PathBuf,
            mountpoint: PathBuf,
            backing_root: PathBuf,
            notifier: Arc<OnceLock<Notifier>>,
        ) -> io::Result<Self> {
            let root_meta = std::fs::symlink_metadata(&backing_root)?;
            let blobs_dir = backing_root.join(COW_BLOBS_DIR);
            std::fs::create_dir_all(&blobs_dir)?;
            let unlinked_dir = backing_root.join(COW_UNLINKED_DIR);
            let _ = stow_types::fs::remove_dir_all(&unlinked_dir);
            std::fs::create_dir_all(&unlinked_dir)?;
            Ok(Self {
                cache_dir,
                mountpoint,
                backing_root,
                blobs_dir,
                unlinked_dir,
                notifier,
                writeback_cache: false,
                no_open: false,
                dir_lock: RwLock::new(()),
                rename_in_flight: AtomicUsize::new(0),
                rename_seq: AtomicU64::new(0),
                inodes: RwLock::new(InodeTable::new(root_meta.ino())),
                handles: HandleTable::default(),
                fd_cache: InodeFdCache::default(),
                copy_up_lock: Mutex::new(()),
            })
        }

        fn unlinked_rel(ino: INodeNo) -> PathBuf {
            PathBuf::from(COW_UNLINKED_DIR).join(ino.0.to_string())
        }

        fn open_read_fd_cached(&self, ino: INodeNo) -> Result<Arc<CachedFd>, Errno> {
            if let Some(cached) = self.fd_cache.get(ino) {
                return Ok(cached);
            }
            let _dir = self
                .dir_lock
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let opened = self.with_backing_path_retry(ino, |full, cow, _| {
                if let Some(cow) = cow {
                    let blob = File::open(self.blobs_dir.join(&cow.blob_name))
                        .map_err(|err| io_to_errno(&err))?;
                    Ok(CachedFd::CowRead { blob })
                } else {
                    let file = File::open(full).map_err(|err| io_to_errno(&err))?;
                    Ok(CachedFd::Regular {
                        file,
                        writable: false,
                    })
                }
            })?;
            Ok(self.fd_cache.insert(ino, opened))
        }

        fn open_write_fd_cached(&self, ino: INodeNo) -> Result<Arc<CachedFd>, Errno> {
            if let Some(cached) = self.fd_cache.get(ino)
                && matches!(cached.as_ref(), CachedFd::Regular { writable: true, .. })
            {
                return Ok(cached);
            }
            let _dir = self
                .dir_lock
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let file = self.with_backing_path_retry(ino, |full, _, _| {
                open_backing_for_no_open_write(full, self.writeback_cache)
                    .map_err(|err| io_to_errno(&err))
            })?;
            Ok(self.fd_cache.insert(
                ino,
                CachedFd::Regular {
                    file,
                    writable: true,
                },
            ))
        }

        fn reply_read_file(file: &File, offset: u64, size: u32, reply: ReplyData) {
            let want = size as usize;
            READ_BUF.with(|cell| {
                let mut buf = cell.borrow_mut();
                if buf.len() < want {
                    buf.resize(want, 0);
                }
                let mut filled = 0usize;
                while filled < want {
                    match file.read_at(&mut buf[filled..want], offset + filled as u64) {
                        Ok(0) => break,
                        Ok(n) => filled += n,
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                        Err(err) => {
                            reply.error(io_to_errno(&err));
                            return;
                        }
                    }
                }
                reply.data(&buf[..filled]);
            });
        }

        fn reply_write_file(file: &File, offset: u64, data: &[u8], reply: ReplyWrite) {
            let mut written = 0usize;
            while written < data.len() {
                match file.write_at(&data[written..], offset + written as u64) {
                    Ok(0) => break,
                    Ok(n) => written += n,
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(err) => {
                        reply.error(io_to_errno(&err));
                        return;
                    }
                }
            }
            match u32::try_from(written) {
                Ok(n) => reply.written(n),
                Err(_) => reply.error(Errno::EIO),
            }
        }

        fn is_directory_path(&self, rel: &Path) -> bool {
            let table = self
                .inodes
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            table
                .path_to_ino
                .get(rel)
                .and_then(|ino| table.entries.get(ino))
                .is_some_and(|entry| entry.kind == FileType::Directory)
        }

        /// Run `op` against the backing path currently registered for `ino`,
        /// retrying cleanly if a concurrent regular-file `rename` moved `ino`
        /// between reading `inodes` and executing the backing syscall.
        fn with_backing_path_retry<T>(
            &self,
            ino: INodeNo,
            mut op: impl FnMut(&Path, Option<&CowTarget>, bool) -> Result<T, Errno>,
        ) -> Result<T, Errno> {
            for attempt in 0..4u8 {
                let seq0 = self.rename_seq.load(Ordering::Acquire);
                let inflight0 = self.rename_in_flight.load(Ordering::Acquire);
                let (full, cow, unlinked) = self.backing_path_and_cow(ino)?;
                match op(&full, cow.as_ref(), unlinked) {
                    Ok(value) => return Ok(value),
                    Err(Errno::ENOENT)
                        if attempt < 3
                            && (inflight0 > 0
                                || self.rename_in_flight.load(Ordering::Acquire) > 0
                                || self.rename_seq.load(Ordering::Acquire) != seq0) =>
                    {
                        while self.rename_in_flight.load(Ordering::Acquire) > 0 {
                            std::thread::yield_now();
                        }
                    }
                    Err(err) => return Err(err),
                }
            }
            Err(Errno::ENOENT)
        }

        fn is_hidden_root_entry(parent: INodeNo, name: &OsStr) -> bool {
            parent == INodeNo::ROOT
                && (name == OsStr::new(COW_BLOBS_DIR) || name == OsStr::new(COW_UNLINKED_DIR))
        }

        fn child_rel_path(&self, parent: INodeNo, name: &OsStr) -> Result<PathBuf, Errno> {
            if Self::is_hidden_root_entry(parent, name) {
                return Err(Errno::ENOENT);
            }
            let base = self
                .inodes
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entries
                .get(&parent)
                .and_then(InodeEntry::primary_path)
                .map(Path::to_path_buf)
                .ok_or(Errno::ENOENT)?;
            Ok(if base.as_os_str().is_empty() {
                PathBuf::from(name)
            } else {
                base.join(name)
            })
        }

        fn backing_path_and_cow(
            &self,
            ino: INodeNo,
        ) -> Result<(PathBuf, Option<CowTarget>, bool), Errno> {
            let table = self
                .inodes
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            table
                .resolve_path_and_cow(&self.backing_root, ino)
                .ok_or(Errno::ENOENT)
        }

        fn is_cow_inode(&self, ino: INodeNo) -> bool {
            self.inodes
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entries
                .get(&ino)
                .is_some_and(|entry| entry.cow.is_some())
        }

        fn backing_path(&self, ino: INodeNo) -> Result<PathBuf, Errno> {
            let table = self
                .inodes
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            table
                .resolve_backing_path(&self.backing_root, ino)
                .ok_or(Errno::ENOENT)
        }

        fn backing_full(&self, rel: &Path) -> PathBuf {
            if rel.as_os_str().is_empty() {
                self.backing_root.clone()
            } else {
                self.backing_root.join(rel)
            }
        }

        fn file_attr_for(
            ino: INodeNo,
            meta: &std::fs::Metadata,
            cow: Option<&CowTarget>,
        ) -> Result<FileAttr, Errno> {
            let mut attr = FileAttr::try_from(meta).map_err(|_| Errno::EIO)?;
            attr.ino = ino;
            if let Some(cow) = cow {
                attr.size = cow.size;
                attr.blocks = cow.size.div_ceil(512);
            }
            Ok(attr)
        }

        fn open_file_attr(ino: INodeNo, open: &OpenFile) -> Result<FileAttr, Errno> {
            match open {
                OpenFile::Regular(file) => Self::regular_file_attr(ino, file),
                OpenFile::CowRead { blob, size } => {
                    let meta = blob.metadata().map_err(|err| io_to_errno(&err))?;
                    let mut attr = Self::file_attr_for(ino, &meta, None)?;
                    attr.size = *size;
                    attr.blocks = size.div_ceil(512);
                    Ok(attr)
                }
            }
        }

        fn regular_file_attr(ino: INodeNo, file: &File) -> Result<FileAttr, Errno> {
            file.metadata()
                .map_err(|err| io_to_errno(&err))
                .and_then(|meta| Self::file_attr_for(ino, &meta, None))
        }

        fn register_meta(
            &self,
            rel_path: PathBuf,
            meta: &std::fs::Metadata,
            cow: Option<&CowTarget>,
        ) -> Result<FileAttr, Errno> {
            let kind = FileType::from_std(meta.file_type()).ok_or(Errno::EIO)?;
            let hit = self
                .inodes
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .lookup_hit(&rel_path, meta.ino(), kind, cow);
            let ino = hit.unwrap_or_else(|| {
                self.inodes
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .upsert_lookup(rel_path, meta.ino(), kind, cow.cloned())
            });
            Self::file_attr_for(ino, meta, cow)
        }

        fn stat_and_register(&self, rel_path: PathBuf) -> Result<FileAttr, Errno> {
            let full = self.backing_full(&rel_path);
            let meta = std::fs::symlink_metadata(&full).map_err(|err| io_to_errno(&err))?;
            let cow = if meta.is_file() && meta.len() == 0 {
                read_cow_xattr(&full).map_err(|err| io_to_errno(&err))?
            } else {
                None
            };
            self.register_meta(rel_path, &meta, cow.as_ref())
        }

        /// Copy a copy-on-write stub up into a private regular file in `build-dir-backing/`
        /// in place (preserving its backing inode number, mode, and mtime).
        /// When `truncate_to_zero` is true, simply clears the copy-on-write xattr and
        /// truncates the stub without copying any blob bytes.
        fn ensure_copied_up(&self, ino: INodeNo, truncate_to_zero: bool) -> Result<(), Errno> {
            // Fast path: regular non-CoW files skip the global copy-up mutex and
            // all extra stat/xattr syscalls.
            if !self.is_cow_inode(ino) {
                return Ok(());
            }
            let _guard = self
                .copy_up_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (cow, orig_mode, orig_mtime, need_chmod, mut stub_rw) = {
                let _dir = self
                    .dir_lock
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let (full, cow, _) = self.backing_path_and_cow(ino)?;
                let Some(cow) = cow else {
                    return Ok(());
                };
                let orig_meta =
                    std::fs::symlink_metadata(&full).map_err(|err| io_to_errno(&err))?;
                let orig_mode = orig_meta.mode() & 0o7777;
                let orig_mtime =
                    system_time_from_timespec(orig_meta.mtime(), orig_meta.mtime_nsec());
                let need_chmod = (orig_mode & 0o200) == 0;
                if need_chmod {
                    std::fs::set_permissions(
                        &full,
                        std::fs::Permissions::from_mode(orig_mode | 0o600),
                    )
                    .map_err(|err| io_to_errno(&err))?;
                }
                let stub_rw = OpenOptions::new().read(true).write(true).open(&full);
                match stub_rw {
                    Ok(file) => (cow, orig_mode, orig_mtime, need_chmod, file),
                    Err(err) => {
                        if need_chmod {
                            let _ = std::fs::set_permissions(
                                &full,
                                std::fs::Permissions::from_mode(orig_mode),
                            );
                        }
                        return Err(io_to_errno(&err));
                    }
                }
            };

            let copy_result: io::Result<()> = (|| {
                if truncate_to_zero {
                    stub_rw.set_len(0)?;
                } else {
                    let blob_path = self.blobs_dir.join(&cow.blob_name);
                    let mut blob = File::open(&blob_path)?;
                    stub_rw.set_len(0)?;
                    io::copy(&mut blob, &mut stub_rw)?;
                }
                remove_cow_xattr_fd(stub_rw.as_raw_fd())?;
                if !truncate_to_zero {
                    let _ = stub_rw.set_modified(orig_mtime);
                }
                Ok(())
            })();

            if need_chmod {
                // SAFETY: `stub_rw` is an open descriptor to the stub inode.
                let _ = unsafe { libc::fchmod(stub_rw.as_raw_fd(), orig_mode as libc::mode_t) };
            }
            copy_result.map_err(|err| io_to_errno(&err))?;

            if let Some(entry) = self
                .inodes
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entries
                .get_mut(&ino)
            {
                entry.cow = None;
            }
            self.fd_cache.evict(ino);
            Ok(())
        }

        fn register_virtual_clone(&self, ino: INodeNo, source_bytes: &[u8]) -> Result<(), Errno> {
            let source_raw = Path::new(OsStr::from_bytes(source_bytes));
            let canonical_source =
                std::fs::canonicalize(source_raw).map_err(|err| io_to_errno(&err))?;
            if !canonical_source.starts_with(&self.cache_dir)
                || canonical_source.starts_with(&self.mountpoint)
                || canonical_source.starts_with(&self.backing_root)
            {
                return Err(Errno::EACCES);
            }
            let src_meta =
                std::fs::symlink_metadata(&canonical_source).map_err(|err| io_to_errno(&err))?;
            if !src_meta.is_file() {
                return Err(Errno::EINVAL);
            }

            let blob_name = format!("{}-{}", src_meta.dev(), src_meta.ino());
            let blob_path = self.blobs_dir.join(&blob_name);
            match std::fs::hard_link(&canonical_source, &blob_path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(io_to_errno(&error)),
            }

            let target = CowTarget {
                blob_name,
                size: src_meta.len(),
            };

            let _dir = self
                .dir_lock
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let stub_path = self.backing_path(ino)?;
            let stub_meta =
                std::fs::symlink_metadata(&stub_path).map_err(|err| io_to_errno(&err))?;
            if !stub_meta.is_file() || stub_meta.len() != 0 {
                return Err(Errno::EINVAL);
            }
            write_cow_xattr(&stub_path, &target).map_err(|err| io_to_errno(&err))?;

            if let Some(entry) = self
                .inodes
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entries
                .get_mut(&ino)
            {
                entry.cow = Some(target);
            }
            self.fd_cache.evict(ino);
            if let Some(notifier) = self.notifier.get() {
                let _ = notifier.inval_inode(ino, -1, 0);
            }
            Ok(())
        }

        fn apply_setattr_on_fd(fd: libc::c_int, params: &SetattrParams) -> Result<(), Errno> {
            if let Some(mode) = params.mode {
                // SAFETY: `fd` is a valid open file descriptor.
                if unsafe { libc::fchmod(fd, mode as libc::mode_t) } != 0 {
                    return Err(io_to_errno(&io::Error::last_os_error()));
                }
            }
            if params.uid.is_some() || params.gid.is_some() {
                let uid = params.uid.unwrap_or(u32::MAX);
                let gid = params.gid.unwrap_or(u32::MAX);
                // SAFETY: `fd` is a valid open file descriptor.
                if unsafe { libc::fchown(fd, uid, gid) } != 0 {
                    return Err(io_to_errno(&io::Error::last_os_error()));
                }
            }
            if let Some(size) = params.size {
                let off = libc::off_t::try_from(size).map_err(|_| Errno::EINVAL)?;
                // SAFETY: `fd` is a valid open file descriptor.
                if unsafe { libc::ftruncate(fd, off) } != 0 {
                    return Err(io_to_errno(&io::Error::last_os_error()));
                }
            }
            if params.atime.is_some() || params.mtime.is_some() {
                let times = [
                    time_or_now_to_timespec(params.atime),
                    time_or_now_to_timespec(params.mtime),
                ];
                // SAFETY: `fd` is valid and `times` has two initialized `timespec` entries.
                if unsafe { libc::futimens(fd, times.as_ptr()) } != 0 {
                    return Err(io_to_errno(&io::Error::last_os_error()));
                }
            }
            Ok(())
        }

        fn setattr_by_path(&self, ino: INodeNo, params: &SetattrParams) -> Result<FileAttr, Errno> {
            let _dir = self
                .dir_lock
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.with_backing_path_retry(ino, |full, cow, unlinked| {
                let Ok(c_path) = CString::new(full.as_os_str().as_bytes()) else {
                    return Err(Errno::EINVAL);
                };
                if let Some(mode) = params.mode {
                    std::fs::set_permissions(full, std::fs::Permissions::from_mode(mode & 0o7777))
                        .map_err(|err| io_to_errno(&err))?;
                }
                if params.uid.is_some() || params.gid.is_some() {
                    let uid = params.uid.unwrap_or(u32::MAX);
                    let gid = params.gid.unwrap_or(u32::MAX);
                    // SAFETY: `c_path` is NUL-terminated.
                    if unsafe { libc::lchown(c_path.as_ptr(), uid, gid) } != 0 {
                        return Err(io_to_errno(&io::Error::last_os_error()));
                    }
                }
                if let Some(size) = params.size {
                    let off = libc::off_t::try_from(size).map_err(|_| Errno::EINVAL)?;
                    // SAFETY: `c_path` is NUL-terminated.
                    if unsafe { libc::truncate(c_path.as_ptr(), off) } != 0 {
                        return Err(io_to_errno(&io::Error::last_os_error()));
                    }
                }
                if params.atime.is_some() || params.mtime.is_some() {
                    let times = [
                        time_or_now_to_timespec(params.atime),
                        time_or_now_to_timespec(params.mtime),
                    ];
                    // SAFETY: `c_path` is NUL-terminated and `times` has two `timespec` entries.
                    if unsafe {
                        libc::utimensat(
                            libc::AT_FDCWD,
                            c_path.as_ptr(),
                            times.as_ptr(),
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    } != 0
                    {
                        return Err(io_to_errno(&io::Error::last_os_error()));
                    }
                }
                let meta = std::fs::symlink_metadata(full).map_err(|err| io_to_errno(&err))?;
                let cow = if meta.is_file() && meta.len() == 0 {
                    cow
                } else {
                    None
                };
                let mut attr = Self::file_attr_for(ino, &meta, cow)?;
                if unlinked {
                    attr.nlink = 0;
                }
                Ok(attr)
            })
        }

        fn dir_entries(&self, fh: FileHandle) -> Result<Arc<Vec<DirEntryRecord>>, Errno> {
            let dir = self.handles.get_dir(fh).ok_or(Errno::EBADF)?;
            if let Some(entries) = dir.entries.get() {
                return Ok(Arc::clone(entries));
            }
            let listing = {
                let _dir = self
                    .dir_lock
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let full = self.backing_path(dir.ino)?;
                std::fs::read_dir(&full).map_err(|err| io_to_errno(&err))?
            };
            let mut entries = Vec::new();
            entries.push((dir.ino.0, FileType::Directory, OsString::from(".")));
            entries.push((dir.ino.0, FileType::Directory, OsString::from("..")));
            for item in listing {
                let Ok(item) = item else { continue };
                let name = item.file_name();
                if Self::is_hidden_root_entry(dir.ino, &name) {
                    continue;
                }
                let Ok(ft) = item.file_type() else { continue };
                let Some(kind) = FileType::from_std(ft) else {
                    continue;
                };
                entries.push((item.ino(), kind, name));
            }
            Ok(Arc::clone(dir.entries.get_or_init(|| Arc::new(entries))))
        }

        fn rename_backing_files(
            old_full: &Path,
            new_full: &Path,
            flags: RenameFlags,
        ) -> Result<(), Errno> {
            if flags.is_empty() {
                std::fs::rename(old_full, new_full).map_err(|err| io_to_errno(&err))
            } else {
                let Ok(c_old) = CString::new(old_full.as_os_str().as_bytes()) else {
                    return Err(Errno::EINVAL);
                };
                let Ok(c_new) = CString::new(new_full.as_os_str().as_bytes()) else {
                    return Err(Errno::EINVAL);
                };
                // SAFETY: both paths are NUL-terminated and `AT_FDCWD` is valid.
                let rc = unsafe {
                    libc::renameat2(
                        libc::AT_FDCWD,
                        c_old.as_ptr(),
                        libc::AT_FDCWD,
                        c_new.as_ptr(),
                        flags.bits(),
                    )
                };
                if rc != 0 {
                    return Err(io_to_errno(&io::Error::last_os_error()));
                }
                Ok(())
            }
        }
    }

    impl Filesystem for StowCowFs {
        fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
            let offered = config.capabilities();
            let desired = [
                InitFlags::FUSE_ASYNC_READ,
                InitFlags::FUSE_ATOMIC_O_TRUNC,
                InitFlags::FUSE_BIG_WRITES,
                InitFlags::FUSE_MAX_PAGES,
                InitFlags::FUSE_DO_READDIRPLUS,
                InitFlags::FUSE_READDIRPLUS_AUTO,
                InitFlags::FUSE_PARALLEL_DIROPS,
                InitFlags::FUSE_ASYNC_DIO,
                InitFlags::FUSE_CACHE_SYMLINKS,
                InitFlags::FUSE_EXPLICIT_INVAL_DATA,
                InitFlags::FUSE_HANDLE_KILLPRIV_V2,
            ];
            for flag in desired {
                if offered.contains(flag) {
                    let _ = config.add_capabilities(flag);
                }
            }
            if offered.contains(InitFlags::FUSE_WRITEBACK_CACHE)
                && config
                    .add_capabilities(InitFlags::FUSE_WRITEBACK_CACHE)
                    .is_ok()
            {
                self.writeback_cache = true;
            }
            if offered.contains(InitFlags::FUSE_NO_OPEN_SUPPORT)
                && config
                    .add_capabilities(InitFlags::FUSE_NO_OPEN_SUPPORT)
                    .is_ok()
            {
                self.no_open = true;
            }
            // 1 MiB write/readahead buffers and 128 background requests match
            // parallel rustc/ld I/O over large `.rlib`/`.rmeta` artifacts.
            let _ = config.set_max_write(1024 * 1024);
            let _ = config.set_max_readahead(1024 * 1024);
            let _ = config.set_max_background(128);
            let _ = config.set_congestion_threshold(96);
            Ok(())
        }

        fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
            let _dir = self
                .dir_lock
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if Self::is_hidden_root_entry(parent, name) {
                reply.entry_with_ttls(
                    &Duration::ZERO,
                    &ATTR_TTL,
                    &negative_entry_attr(),
                    Generation(0),
                );
                return;
            }
            let rel = match self.child_rel_path(parent, name) {
                Ok(rel) => rel,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };
            match self.stat_and_register(rel) {
                Ok(attr) => reply.entry(&ATTR_TTL, &attr, Generation(0)),
                Err(Errno::ENOENT) => reply.entry_with_ttls(
                    &Duration::ZERO,
                    &ATTR_TTL,
                    &negative_entry_attr(),
                    Generation(0),
                ),
                Err(err) => reply.error(err),
            }
        }

        fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
            let (removed, unlinked_rel) = self
                .inodes
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .forget(ino, nlookup);
            if removed {
                self.fd_cache.evict(ino);
                if let Some(rel) = unlinked_rel {
                    let _ = std::fs::remove_file(self.backing_full(&rel));
                }
            }
        }

        fn getattr(&self, _req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
            let open_handle = fh
                .filter(|fh| fh.0 != 0)
                .and_then(|fh| self.handles.get_file(fh));
            if let Some(open) = open_handle.as_ref()
                && let OpenFile::Regular(file) = open.as_ref()
            {
                match Self::regular_file_attr(ino, file) {
                    Ok(attr) => reply.attr(&ATTR_TTL, &attr),
                    Err(err) => reply.error(err),
                }
                return;
            }
            let _dir = self
                .dir_lock
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let res = self.with_backing_path_retry(ino, |full, cow, unlinked| {
                let meta = std::fs::symlink_metadata(full).map_err(|err| io_to_errno(&err))?;
                let cow = if meta.is_file() && meta.len() == 0 {
                    cow
                } else {
                    None
                };
                let mut attr = Self::file_attr_for(ino, &meta, cow)?;
                if unlinked {
                    attr.nlink = 0;
                }
                Ok(attr)
            });
            match res {
                Ok(attr) => reply.attr(&ATTR_TTL, &attr),
                Err(Errno::ENOENT) => {
                    // Linux `fstat(fd)` passes `fh = None` to `getattr`, so when
                    // `FUSE_NO_OPEN_SUPPORT` is unavailable an unlinked open file
                    // resolves through any live handle for `ino`.
                    let fallback = open_handle.or_else(|| self.handles.any_file_for_ino(ino));
                    if let Some(open) = fallback {
                        match Self::open_file_attr(ino, open.as_ref()) {
                            Ok(attr) => reply.attr(&ATTR_TTL, &attr),
                            Err(attr_err) => reply.error(attr_err),
                        }
                        return;
                    }
                    reply.error(Errno::ENOENT);
                }
                Err(err) => reply.error(err),
            }
        }

        fn setattr(
            &self,
            _req: &Request,
            ino: INodeNo,
            mode: Option<u32>,
            uid: Option<u32>,
            gid: Option<u32>,
            size: Option<u64>,
            atime: Option<TimeOrNow>,
            mtime: Option<TimeOrNow>,
            _ctime: Option<SystemTime>,
            fh: Option<FileHandle>,
            _crtime: Option<SystemTime>,
            _chgtime: Option<SystemTime>,
            _bkuptime: Option<SystemTime>,
            _flags: Option<BsdFileFlags>,
            _kill_suid_gid: bool,
            reply: ReplyAttr,
        ) {
            if let Some(new_size) = size
                && let Err(err) = self.ensure_copied_up(ino, new_size == 0)
            {
                reply.error(err);
                return;
            }

            let params = SetattrParams {
                mode,
                uid,
                gid,
                size,
                atime,
                mtime,
            };

            let open = fh
                .filter(|fh| fh.0 != 0)
                .and_then(|fh| self.handles.get_file(fh));

            if let Some(open) = open.as_ref()
                && let OpenFile::Regular(file) = open.as_ref()
            {
                if let Err(err) = Self::apply_setattr_on_fd(file.as_raw_fd(), &params) {
                    reply.error(err);
                    return;
                }
                match Self::regular_file_attr(ino, file) {
                    Ok(attr) => reply.attr(&ATTR_TTL, &attr),
                    Err(err) => reply.error(err),
                }
                return;
            }

            match self.setattr_by_path(ino, &params) {
                Ok(attr) => reply.attr(&ATTR_TTL, &attr),
                Err(Errno::ENOENT) => {
                    if let Some(open) = self.handles.any_file_for_ino(ino)
                        && let OpenFile::Regular(file) = open.as_ref()
                    {
                        if let Err(err) = Self::apply_setattr_on_fd(file.as_raw_fd(), &params) {
                            reply.error(err);
                            return;
                        }
                        match Self::regular_file_attr(ino, file) {
                            Ok(attr) => reply.attr(&ATTR_TTL, &attr),
                            Err(err) => reply.error(err),
                        }
                        return;
                    }
                    reply.error(Errno::ENOENT);
                }
                Err(err) => reply.error(err),
            }
        }

        fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
            let _dir = self
                .dir_lock
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match self.with_backing_path_retry(ino, |full, _, _| {
                std::fs::read_link(full).map_err(|err| io_to_errno(&err))
            }) {
                Ok(target) => reply.data(target.as_os_str().as_bytes()),
                Err(err) => reply.error(err),
            }
        }

        fn mknod(
            &self,
            _req: &Request,
            parent: INodeNo,
            name: &OsStr,
            mode: u32,
            umask: u32,
            rdev: u32,
            _owner: Owner,
            reply: ReplyEntry,
        ) {
            let _dir = self
                .dir_lock
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let rel = match self.child_rel_path(parent, name) {
                Ok(rel) => rel,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };
            let full = self.backing_full(&rel);
            let Ok(c_path) = CString::new(full.as_os_str().as_bytes()) else {
                reply.error(Errno::EINVAL);
                return;
            };
            let eff_mode = (mode & !umask) as libc::mode_t;
            // SAFETY: `c_path` is NUL-terminated.
            if unsafe { libc::mknod(c_path.as_ptr(), eff_mode, u64::from(rdev)) } != 0 {
                reply.error(io_to_errno(&io::Error::last_os_error()));
                return;
            }
            match self.stat_and_register(rel) {
                Ok(attr) => reply.entry(&ATTR_TTL, &attr, Generation(0)),
                Err(err) => reply.error(err),
            }
        }

        fn mkdir(
            &self,
            _req: &Request,
            parent: INodeNo,
            name: &OsStr,
            mode: u32,
            umask: u32,
            _owner: Owner,
            reply: ReplyEntry,
        ) {
            let _dir = self
                .dir_lock
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let rel = match self.child_rel_path(parent, name) {
                Ok(rel) => rel,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };
            let full = self.backing_full(&rel);
            if let Err(err) = std::fs::create_dir(&full) {
                reply.error(io_to_errno(&err));
                return;
            }
            let _ = std::fs::set_permissions(
                &full,
                std::fs::Permissions::from_mode((mode & !umask) & 0o7777),
            );
            match self.stat_and_register(rel) {
                Ok(attr) => reply.entry(&ATTR_TTL, &attr, Generation(0)),
                Err(err) => reply.error(err),
            }
        }

        fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
            let _dir = self
                .dir_lock
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let rel = match self.child_rel_path(parent, name) {
                Ok(rel) => rel,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };
            let full = self.backing_full(&rel);
            let candidate = if self.no_open {
                self.inodes
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .unlinked_candidate(&rel, None)
            } else {
                None
            };
            if let Some(ino) = candidate {
                let _guard = RenameGuard::enter(self);
                let unlinked_rel = Self::unlinked_rel(ino);
                let unlinked_full = self.backing_full(&unlinked_rel);
                if let Err(err) = std::fs::rename(&full, &unlinked_full) {
                    reply.error(io_to_errno(&err));
                    return;
                }
                self.inodes
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .mark_unlinked(&rel, unlinked_rel);
                reply.ok();
                return;
            }
            if let Err(err) = std::fs::remove_file(&full) {
                reply.error(io_to_errno(&err));
                return;
            }
            self.inodes
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .unlink_path(&rel);
            reply.ok();
        }

        fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
            let _dir = self
                .dir_lock
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let rel = match self.child_rel_path(parent, name) {
                Ok(rel) => rel,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };
            let full = self.backing_full(&rel);
            if let Err(err) = std::fs::remove_dir(&full) {
                reply.error(io_to_errno(&err));
                return;
            }
            self.inodes
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .unlink_path(&rel);
            reply.ok();
        }

        fn symlink(
            &self,
            _req: &Request,
            parent: INodeNo,
            link_name: &OsStr,
            target: &Path,
            _owner: Owner,
            reply: ReplyEntry,
        ) {
            let _dir = self
                .dir_lock
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let rel = match self.child_rel_path(parent, link_name) {
                Ok(rel) => rel,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };
            let full = self.backing_full(&rel);
            if let Err(err) = std::os::unix::fs::symlink(target, &full) {
                reply.error(io_to_errno(&err));
                return;
            }
            match self.stat_and_register(rel) {
                Ok(attr) => reply.entry(&ATTR_TTL, &attr, Generation(0)),
                Err(err) => reply.error(err),
            }
        }

        fn rename(
            &self,
            _req: &Request,
            parent: INodeNo,
            name: &OsStr,
            newparent: INodeNo,
            newname: &OsStr,
            flags: RenameFlags,
            _owner: Option<Owner>,
            reply: ReplyEmpty,
        ) {
            let exchange = flags.contains(RenameFlags::RENAME_EXCHANGE);
            let is_dir_rename = {
                let _dir = self
                    .dir_lock
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let old_is_dir = self
                    .child_rel_path(parent, name)
                    .is_ok_and(|rel| self.is_directory_path(&rel));
                let new_is_dir = exchange
                    && self
                        .child_rel_path(newparent, newname)
                        .is_ok_and(|rel| self.is_directory_path(&rel));
                old_is_dir || new_is_dir
            };
            let (_dir_write, _dir_read, _rename_guard) = if is_dir_rename {
                (
                    Some(
                        self.dir_lock
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner),
                    ),
                    None,
                    None,
                )
            } else {
                (
                    None,
                    Some(
                        self.dir_lock
                            .read()
                            .unwrap_or_else(std::sync::PoisonError::into_inner),
                    ),
                    Some(RenameGuard::enter(self)),
                )
            };
            let old_rel = match self.child_rel_path(parent, name) {
                Ok(rel) => rel,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };
            let new_rel = match self.child_rel_path(newparent, newname) {
                Ok(rel) => rel,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };
            let old_full = self.backing_full(&old_rel);
            let new_full = self.backing_full(&new_rel);
            let preserved = if !exchange && old_rel != new_rel && self.no_open {
                let victim_ino = {
                    let table = self
                        .inodes
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let old_ino = table.path_to_ino.get(&old_rel).copied();
                    table.unlinked_candidate(&new_rel, old_ino)
                };
                victim_ino.and_then(|ino| {
                    let unlinked_rel = Self::unlinked_rel(ino);
                    let unlinked_full = self.backing_full(&unlinked_rel);
                    std::fs::hard_link(&new_full, &unlinked_full)
                        .ok()
                        .map(|()| (unlinked_rel, unlinked_full))
                })
            } else {
                None
            };
            if let Err(err) = Self::rename_backing_files(&old_full, &new_full, flags) {
                if let Some((_, unlinked_full)) = preserved {
                    let _ = std::fs::remove_file(unlinked_full);
                }
                reply.error(err);
                return;
            }
            let mut table = self
                .inodes
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some((unlinked_rel, _)) = preserved {
                table.mark_unlinked(&new_rel, unlinked_rel);
            }
            table.rename_path(&old_rel, &new_rel, exchange);
            drop(table);
            reply.ok();
        }

        fn link(
            &self,
            _req: &Request,
            ino: INodeNo,
            newparent: INodeNo,
            newname: &OsStr,
            reply: ReplyEntry,
        ) {
            let _dir = self
                .dir_lock
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let new_rel = match self.child_rel_path(newparent, newname) {
                Ok(rel) => rel,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };
            let new_full = self.backing_full(&new_rel);
            if let Err(err) = self.with_backing_path_retry(ino, |old_full, _, _| {
                std::fs::hard_link(old_full, &new_full).map_err(|err| io_to_errno(&err))
            }) {
                reply.error(err);
                return;
            }
            match self.stat_and_register(new_rel) {
                Ok(attr) => reply.entry(&ATTR_TTL, &attr, Generation(0)),
                Err(err) => reply.error(err),
            }
        }

        fn open(
            &self,
            _req: &Request,
            ino: INodeNo,
            flags: OpenFlags,
            _kill_suid_gid: bool,
            reply: ReplyOpen,
        ) {
            if self.no_open {
                // Returning ENOSYS with `FUSE_NO_OPEN_SUPPORT` sets
                // `fc->no_open = 1` in the kernel so cached open/read/fstat/close
                // cycles avoid all userspace FUSE round-trips.
                reply.error(Errno::ENOSYS);
                return;
            }
            let acc = flags.acc_mode();
            let wants_write = matches!(acc, OpenAccMode::O_WRONLY | OpenAccMode::O_RDWR)
                || (flags.0 & libc::O_TRUNC) != 0;

            if wants_write {
                if let Err(err) = self.ensure_copied_up(ino, (flags.0 & libc::O_TRUNC) != 0) {
                    reply.error(err);
                    return;
                }
                let opened = {
                    let _dir = self
                        .dir_lock
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    self.with_backing_path_retry(ino, |full, _, _| {
                        open_backing_for_write(full, acc, flags.0, self.writeback_cache)
                            .map_err(|err| io_to_errno(&err))
                    })
                };
                match opened {
                    Ok(file) => {
                        let fh = self.handles.insert_file(ino, OpenFile::Regular(file));
                        let open_flags = if (flags.0 & libc::O_TRUNC) != 0 {
                            FopenFlags::empty()
                        } else {
                            FopenFlags::FOPEN_KEEP_CACHE
                        };
                        reply.opened(fh, open_flags);
                    }
                    Err(err) => reply.error(err),
                }
                return;
            }

            let open_file = {
                let _dir = self
                    .dir_lock
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                self.with_backing_path_retry(ino, |full, cow, _| {
                    if let Some(cow) = cow {
                        let blob_path = self.blobs_dir.join(&cow.blob_name);
                        let blob = File::open(&blob_path).map_err(|err| io_to_errno(&err))?;
                        Ok(OpenFile::CowRead {
                            blob,
                            size: cow.size,
                        })
                    } else {
                        let file = File::open(full).map_err(|err| io_to_errno(&err))?;
                        Ok(OpenFile::Regular(file))
                    }
                })
            };
            match open_file {
                Ok(open_file) => {
                    let fh = self.handles.insert_file(ino, open_file);
                    reply.opened(fh, FopenFlags::FOPEN_KEEP_CACHE | FopenFlags::FOPEN_NOFLUSH);
                }
                Err(err) => reply.error(err),
            }
        }

        fn create(
            &self,
            _req: &Request,
            parent: INodeNo,
            name: &OsStr,
            mode: u32,
            umask: u32,
            flags: i32,
            _kill_suid_gid: bool,
            _owner: Owner,
            reply: ReplyCreate,
        ) {
            let opts = open_options_for_create(mode, umask, flags, self.writeback_cache);
            let exclusive = (flags & libc::O_EXCL) != 0;
            let acc = flags & libc::O_ACCMODE;
            let wants_write =
                matches!(acc, libc::O_WRONLY | libc::O_RDWR) || (flags & libc::O_TRUNC) != 0;
            let (file, mut attr, needs_copy_up) = {
                let _dir = self
                    .dir_lock
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let rel = match self.child_rel_path(parent, name) {
                    Ok(rel) => rel,
                    Err(err) => {
                        reply.error(err);
                        return;
                    }
                };
                let full = self.backing_full(&rel);
                let file = match opts.open(&full) {
                    Ok(file) => file,
                    Err(err) => {
                        reply.error(io_to_errno(&err));
                        return;
                    }
                };
                let meta = match file.metadata() {
                    Ok(meta) => meta,
                    Err(err) => {
                        reply.error(io_to_errno(&err));
                        return;
                    }
                };
                let cow = if !exclusive && meta.is_file() && meta.len() == 0 {
                    match read_cow_xattr_fd(file.as_raw_fd()) {
                        Ok(cow) => cow,
                        Err(err) => {
                            reply.error(io_to_errno(&err));
                            return;
                        }
                    }
                } else {
                    None
                };
                let needs_copy_up = wants_write && cow.is_some();
                let attr = match self.register_meta(rel, &meta, cow.as_ref()) {
                    Ok(attr) => attr,
                    Err(err) => {
                        reply.error(err);
                        return;
                    }
                };
                (file, attr, needs_copy_up)
            };
            if needs_copy_up {
                if let Err(err) = self.ensure_copied_up(attr.ino, (flags & libc::O_TRUNC) != 0) {
                    reply.error(err);
                    return;
                }
                match Self::regular_file_attr(attr.ino, &file) {
                    Ok(updated) => attr = updated,
                    Err(err) => {
                        reply.error(err);
                        return;
                    }
                }
            }
            let fh = if self.no_open {
                // Under `FUSE_NO_OPEN_SUPPORT`, cache the newly created fd in
                // the bounded `fd_cache` and hand `FileHandle(0)` back so
                // `handles` can never accumulate descriptors.
                self.fd_cache.insert(
                    attr.ino,
                    CachedFd::Regular {
                        file,
                        writable: wants_write,
                    },
                );
                FileHandle(0)
            } else {
                self.handles.insert_file(attr.ino, OpenFile::Regular(file))
            };
            reply.created(
                &ATTR_TTL,
                &attr,
                Generation(0),
                fh,
                FopenFlags::FOPEN_KEEP_CACHE,
            );
        }

        fn read(
            &self,
            _req: &Request,
            ino: INodeNo,
            fh: FileHandle,
            offset: u64,
            size: u32,
            _flags: OpenFlags,
            _lock_owner: Option<LockOwner>,
            reply: ReplyData,
        ) {
            if fh.0 != 0 {
                let Some(open) = self.handles.get_file(fh) else {
                    reply.error(Errno::EBADF);
                    return;
                };
                let file = match open.as_ref() {
                    OpenFile::Regular(file) | OpenFile::CowRead { blob: file, .. } => file,
                };
                Self::reply_read_file(file, offset, size, reply);
                return;
            }
            match self.open_read_fd_cached(ino) {
                Ok(cached) => {
                    let file = match cached.as_ref() {
                        CachedFd::Regular { file, .. } | CachedFd::CowRead { blob: file } => file,
                    };
                    Self::reply_read_file(file, offset, size, reply);
                }
                Err(err) => reply.error(err),
            }
        }

        fn write(
            &self,
            _req: &Request,
            ino: INodeNo,
            fh: FileHandle,
            offset: u64,
            data: &[u8],
            _write_flags: WriteFlags,
            _flags: OpenFlags,
            _lock_owner: Option<LockOwner>,
            reply: ReplyWrite,
        ) {
            if fh.0 != 0 {
                let Some(open) = self.handles.get_file(fh) else {
                    reply.error(Errno::EBADF);
                    return;
                };
                let OpenFile::Regular(file) = open.as_ref() else {
                    reply.error(Errno::EBADF);
                    return;
                };
                Self::reply_write_file(file, offset, data, reply);
                return;
            }
            if let Err(err) = self.ensure_copied_up(ino, false) {
                reply.error(err);
                return;
            }
            match self.open_write_fd_cached(ino) {
                Ok(cached) => {
                    let CachedFd::Regular { file, .. } = cached.as_ref() else {
                        reply.error(Errno::EBADF);
                        return;
                    };
                    Self::reply_write_file(file, offset, data, reply);
                }
                Err(err) => reply.error(err),
            }
        }

        fn flush(
            &self,
            _req: &Request,
            _ino: INodeNo,
            _fh: FileHandle,
            _lock_owner: LockOwner,
            reply: ReplyEmpty,
        ) {
            // Returning ENOSYS sets `fc->no_flush = 1` in the Linux kernel so
            // subsequent `close()` calls skip the redundant `FUSE_FLUSH`
            // round-trip (dirty writeback pages are still flushed in-kernel).
            reply.error(Errno::ENOSYS);
        }

        fn release(
            &self,
            _req: &Request,
            _ino: INodeNo,
            fh: FileHandle,
            _flags: OpenFlags,
            _lock_owner: Option<LockOwner>,
            _flush: bool,
            reply: ReplyEmpty,
        ) {
            if fh.0 != 0 {
                self.handles.remove_file(fh);
            }
            reply.ok();
        }

        fn fsync(
            &self,
            _req: &Request,
            ino: INodeNo,
            fh: FileHandle,
            datasync: bool,
            reply: ReplyEmpty,
        ) {
            let sync = |file: &File| {
                if datasync {
                    file.sync_data()
                } else {
                    file.sync_all()
                }
            };
            if fh.0 != 0 {
                let Some(open) = self.handles.get_file(fh) else {
                    reply.error(Errno::EBADF);
                    return;
                };
                let res = match open.as_ref() {
                    OpenFile::Regular(file) => sync(file),
                    OpenFile::CowRead { .. } => Ok(()),
                };
                match res {
                    Ok(()) => reply.ok(),
                    Err(err) => reply.error(io_to_errno(&err)),
                }
                return;
            }
            match self.open_read_fd_cached(ino) {
                Ok(cached) => {
                    let res = match cached.as_ref() {
                        CachedFd::Regular { file, .. } => sync(file),
                        CachedFd::CowRead { .. } => Ok(()),
                    };
                    match res {
                        Ok(()) => reply.ok(),
                        Err(err) => reply.error(io_to_errno(&err)),
                    }
                }
                Err(err) => reply.error(err),
            }
        }

        fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
            let fh = self.handles.insert_dir(ino);
            reply.opened(
                fh,
                FopenFlags::FOPEN_KEEP_CACHE | FopenFlags::FOPEN_CACHE_DIR,
            );
        }

        fn readdir(
            &self,
            _req: &Request,
            _ino: INodeNo,
            fh: FileHandle,
            offset: u64,
            mut reply: ReplyDirectory,
        ) {
            let entries = match self.dir_entries(fh) {
                Ok(entries) => entries,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };
            let Ok(start) = usize::try_from(offset) else {
                reply.ok();
                return;
            };
            if start < entries.len() {
                for (delta, (entry_ino, kind, name)) in entries[start..].iter().enumerate() {
                    if reply.add(INodeNo(*entry_ino), (start + delta + 1) as u64, *kind, name) {
                        break;
                    }
                }
            }
            reply.ok();
        }

        fn readdirplus(
            &self,
            _req: &Request,
            ino: INodeNo,
            fh: FileHandle,
            offset: u64,
            mut reply: ReplyDirectoryPlus,
        ) {
            let entries = match self.dir_entries(fh) {
                Ok(entries) => entries,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };
            let Ok(start) = usize::try_from(offset) else {
                reply.ok();
                return;
            };
            let base_offset = offset;
            if start < entries.len() {
                for (delta, (_raw_ino, _kind, name)) in entries[start..].iter().enumerate() {
                    let next_offset = base_offset + (delta as u64) + 1;
                    if name == "." || name == ".." {
                        let attr = {
                            let _dir = self
                                .dir_lock
                                .read()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            let Ok(full) = self.backing_path(ino) else {
                                continue;
                            };
                            let Ok(meta) = std::fs::symlink_metadata(&full) else {
                                continue;
                            };
                            let Ok(attr) = Self::file_attr_for(ino, &meta, None) else {
                                continue;
                            };
                            attr
                        };
                        if reply.add(ino, next_offset, name, &ATTR_TTL, &attr, Generation(0)) {
                            break;
                        }
                        continue;
                    }
                    let attr = {
                        let _dir = self
                            .dir_lock
                            .read()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let Ok(rel) = self.child_rel_path(ino, name) else {
                            continue;
                        };
                        let Ok(attr) = self.stat_and_register(rel) else {
                            continue;
                        };
                        attr
                    };
                    if reply.add(attr.ino, next_offset, name, &ATTR_TTL, &attr, Generation(0)) {
                        // Kernel buffer was full so it did not take ownership of
                        // the lookup reference added by `stat_and_register`.
                        self.inodes
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .forget(attr.ino, 1);
                        break;
                    }
                }
            }
            reply.ok();
        }

        fn releasedir(
            &self,
            _req: &Request,
            _ino: INodeNo,
            fh: FileHandle,
            _flags: OpenFlags,
            reply: ReplyEmpty,
        ) {
            self.handles.remove_dir(fh);
            reply.ok();
        }

        fn fsyncdir(
            &self,
            _req: &Request,
            _ino: INodeNo,
            _fh: FileHandle,
            _datasync: bool,
            reply: ReplyEmpty,
        ) {
            reply.ok();
        }

        fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
            let Ok(c_path) = CString::new(self.backing_root.as_os_str().as_bytes()) else {
                reply.error(Errno::EINVAL);
                return;
            };
            let mut st = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
            // SAFETY: `c_path` is NUL-terminated and `st` is a writable `statvfs`.
            if unsafe { libc::statvfs(c_path.as_ptr(), st.as_mut_ptr()) } != 0 {
                reply.error(io_to_errno(&io::Error::last_os_error()));
                return;
            }
            // SAFETY: `statvfs` succeeded and initialized `st`.
            let st = unsafe { st.assume_init() };
            reply.statfs(
                st.f_blocks,
                st.f_bfree,
                st.f_bavail,
                st.f_files,
                st.f_ffree,
                u32::try_from(st.f_bsize).unwrap_or(4096),
                u32::try_from(st.f_namemax).unwrap_or(255),
                u32::try_from(st.f_frsize).unwrap_or(4096),
            );
        }

        fn setxattr(
            &self,
            _req: &Request,
            ino: INodeNo,
            name: &OsStr,
            value: &[u8],
            _flags: i32,
            _position: u32,
            reply: ReplyEmpty,
        ) {
            if name == OsStr::new(COW_CLONE_XATTR_NAME) {
                match self.register_virtual_clone(ino, value) {
                    Ok(()) => reply.ok(),
                    Err(err) => reply.error(err),
                }
                return;
            }
            if name == OsStr::new(COW_XATTR_NAME) {
                reply.error(Errno::EACCES);
                return;
            }
            reply.error(Errno::EOPNOTSUPP);
        }

        fn getxattr(
            &self,
            _req: &Request,
            _ino: INodeNo,
            _name: &OsStr,
            _size: u32,
            reply: ReplyXattr,
        ) {
            // Returning ENOSYS permanently disables kernel `FUSE_GETXATTR`
            // probes (such as `security.capability` and `system.posix_acl_*`
            // on every write/open).
            reply.error(Errno::ENOSYS);
        }

        fn listxattr(&self, _req: &Request, _ino: INodeNo, _size: u32, reply: ReplyXattr) {
            reply.error(Errno::ENOSYS);
        }

        fn removexattr(&self, _req: &Request, _ino: INodeNo, _name: &OsStr, reply: ReplyEmpty) {
            reply.error(Errno::ENOSYS);
        }

        fn fallocate(
            &self,
            _req: &Request,
            ino: INodeNo,
            fh: FileHandle,
            offset: u64,
            length: u64,
            mode: i32,
            reply: ReplyEmpty,
        ) {
            let (Ok(off), Ok(len)) = (libc::off_t::try_from(offset), libc::off_t::try_from(length))
            else {
                reply.error(Errno::EINVAL);
                return;
            };
            if let Err(err) = self.ensure_copied_up(ino, false) {
                reply.error(err);
                return;
            }
            if fh.0 != 0 {
                let Some(open) = self.handles.get_file(fh) else {
                    reply.error(Errno::EBADF);
                    return;
                };
                let OpenFile::Regular(file) = open.as_ref() else {
                    reply.error(Errno::EBADF);
                    return;
                };
                // SAFETY: `file` is a valid open descriptor.
                if unsafe { libc::fallocate(file.as_raw_fd(), mode, off, len) } != 0 {
                    reply.error(io_to_errno(&io::Error::last_os_error()));
                    return;
                }
                reply.ok();
                return;
            }
            match self.open_write_fd_cached(ino) {
                Ok(cached) => {
                    let CachedFd::Regular { file, .. } = cached.as_ref() else {
                        reply.error(Errno::EBADF);
                        return;
                    };
                    // SAFETY: `file` is a valid open descriptor.
                    if unsafe { libc::fallocate(file.as_raw_fd(), mode, off, len) } != 0 {
                        reply.error(io_to_errno(&io::Error::last_os_error()));
                        return;
                    }
                    reply.ok();
                }
                Err(err) => reply.error(err),
            }
        }

        fn lseek(
            &self,
            _req: &Request,
            ino: INodeNo,
            fh: FileHandle,
            offset: i64,
            whence: i32,
            reply: ReplyLseek,
        ) {
            let seek_from = match whence {
                libc::SEEK_SET => {
                    if let Ok(pos) = u64::try_from(offset) {
                        SeekFrom::Start(pos)
                    } else {
                        reply.error(Errno::EINVAL);
                        return;
                    }
                }
                libc::SEEK_CUR => SeekFrom::Current(offset),
                libc::SEEK_END => SeekFrom::End(offset),
                _ => {
                    reply.error(Errno::EINVAL);
                    return;
                }
            };
            let reply_seek = |mut file_ref: &File, reply: ReplyLseek| match file_ref.seek(seek_from)
            {
                Ok(pos) => match i64::try_from(pos) {
                    Ok(pos) => reply.offset(pos),
                    Err(_) => reply.error(Errno::EOVERFLOW),
                },
                Err(err) => reply.error(io_to_errno(&err)),
            };
            if fh.0 != 0 {
                let Some(open) = self.handles.get_file(fh) else {
                    reply.error(Errno::EBADF);
                    return;
                };
                let file = match open.as_ref() {
                    OpenFile::Regular(file) | OpenFile::CowRead { blob: file, .. } => file,
                };
                reply_seek(file, reply);
                return;
            }
            match self.open_read_fd_cached(ino) {
                Ok(cached) => {
                    let file = match cached.as_ref() {
                        CachedFd::Regular { file, .. } | CachedFd::CowRead { blob: file } => file,
                    };
                    reply_seek(file, reply);
                }
                Err(err) => reply.error(err),
            }
        }
    }

    fn open_backing_for_no_open_write(full: &Path, writeback_cache: bool) -> io::Result<File> {
        match open_backing_for_write(full, OpenAccMode::O_RDWR, 0, writeback_cache) {
            Ok(file) => Ok(file),
            Err(err) if writeback_cache && err.kind() == io::ErrorKind::PermissionDenied => {
                // Delayed writeback can flush dirty pages after `fchmod(0o444)`
                // cleared the owner-write bit on a file opened for writing
                // (`DefaultPermissions` already authorized the open in-kernel).
                let orig_mode = std::fs::symlink_metadata(full)?.mode() & 0o7777;
                if (orig_mode & 0o200) != 0 {
                    return Err(err);
                }
                std::fs::set_permissions(full, std::fs::Permissions::from_mode(orig_mode | 0o200))?;
                let opened = open_backing_for_write(full, OpenAccMode::O_RDWR, 0, writeback_cache);
                match opened {
                    Ok(file) => {
                        // SAFETY: `file` is a valid open descriptor.
                        let _ =
                            unsafe { libc::fchmod(file.as_raw_fd(), orig_mode as libc::mode_t) };
                        Ok(file)
                    }
                    Err(open_err) => {
                        let _ = std::fs::set_permissions(
                            full,
                            std::fs::Permissions::from_mode(orig_mode),
                        );
                        Err(open_err)
                    }
                }
            }
            Err(err) => Err(err),
        }
    }

    fn open_backing_for_write(
        full: &Path,
        acc: OpenAccMode,
        raw_flags: i32,
        writeback_cache: bool,
    ) -> io::Result<File> {
        let mut opts = OpenOptions::new();
        let upgrade_wronly = writeback_cache && matches!(acc, OpenAccMode::O_WRONLY);
        match acc {
            OpenAccMode::O_RDONLY => {
                opts.read(true);
            }
            OpenAccMode::O_WRONLY => {
                opts.read(upgrade_wronly).write(true);
            }
            OpenAccMode::O_RDWR => {
                opts.read(true).write(true);
            }
        }
        if (raw_flags & libc::O_TRUNC) != 0 {
            opts.truncate(true);
        }
        // Under `FUSE_WRITEBACK_CACHE`, the kernel computes append offsets and
        // issues positioned writes (`pwrite`); keeping `O_APPEND` on the
        // backing fd would make Linux ignore the offset argument.
        if !writeback_cache && (raw_flags & libc::O_APPEND) != 0 {
            opts.append(true);
        }
        match opts.open(full) {
            Ok(file) => Ok(file),
            Err(err) if upgrade_wronly && err.kind() == io::ErrorKind::PermissionDenied => {
                let mut fallback = OpenOptions::new();
                fallback.write(true);
                if (raw_flags & libc::O_TRUNC) != 0 {
                    fallback.truncate(true);
                }
                fallback.open(full)
            }
            Err(err) => Err(err),
        }
    }

    fn open_options_for_create(
        mode: u32,
        umask: u32,
        flags: i32,
        writeback_cache: bool,
    ) -> OpenOptions {
        let mut opts = OpenOptions::new();
        match flags & libc::O_ACCMODE {
            libc::O_RDONLY => {
                opts.read(true);
            }
            libc::O_WRONLY => {
                opts.read(writeback_cache).write(true);
            }
            _ => {
                opts.read(true).write(true);
            }
        }
        if (flags & libc::O_EXCL) != 0 {
            opts.create_new(true);
        } else {
            opts.create(true);
        }
        if (flags & libc::O_TRUNC) != 0 {
            opts.truncate(true);
        }
        if !writeback_cache && (flags & libc::O_APPEND) != 0 {
            opts.append(true);
        }
        opts.mode((mode & !umask) & 0o7777);
        opts
    }

    fn read_cow_xattr(path: &Path) -> io::Result<Option<CowTarget>> {
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let c_name = CString::new(COW_XATTR_NAME)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let mut buf = [0u8; 256];
        // SAFETY: `c_path` and `c_name` are NUL-terminated and `buf` is valid.
        let rc = unsafe {
            libc::lgetxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if matches!(
                err.raw_os_error(),
                Some(libc::ENODATA | libc::EOPNOTSUPP | libc::ENOENT)
            ) {
                return Ok(None);
            }
            return Err(err);
        }
        let len = usize::try_from(rc).unwrap_or(0);
        Ok(CowTarget::decode(&buf[..len]))
    }

    fn read_cow_xattr_fd(fd: libc::c_int) -> io::Result<Option<CowTarget>> {
        let c_name = CString::new(COW_XATTR_NAME)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let mut buf = [0u8; 256];
        // SAFETY: `fd` is an open descriptor, `c_name` is NUL-terminated, and `buf` is valid.
        let rc =
            unsafe { libc::fgetxattr(fd, c_name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(libc::ENODATA | libc::EOPNOTSUPP)) {
                return Ok(None);
            }
            return Err(err);
        }
        let len = usize::try_from(rc).unwrap_or(0);
        Ok(CowTarget::decode(&buf[..len]))
    }

    fn write_cow_xattr(path: &Path, target: &CowTarget) -> io::Result<()> {
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let c_name = CString::new(COW_XATTR_NAME)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let encoded = target.encode();
        // SAFETY: `c_path` and `c_name` are NUL-terminated and `encoded` is valid.
        let rc = unsafe {
            libc::lsetxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                encoded.as_ptr().cast(),
                encoded.len(),
                0,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn write_cow_xattr_fd(fd: libc::c_int, target: &CowTarget) -> io::Result<()> {
        let c_name = CString::new(COW_XATTR_NAME)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let encoded = target.encode();
        // SAFETY: `fd` is open, `c_name` is NUL-terminated, and `encoded` is valid.
        let rc = unsafe {
            libc::fsetxattr(
                fd,
                c_name.as_ptr(),
                encoded.as_ptr().cast(),
                encoded.len(),
                0,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn remove_cow_xattr_fd(fd: libc::c_int) -> io::Result<()> {
        let c_name = CString::new(COW_XATTR_NAME)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        // SAFETY: `fd` is open and `c_name` is NUL-terminated.
        let rc = unsafe { libc::fremovexattr(fd, c_name.as_ptr()) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENODATA) {
                return Err(err);
            }
        }
        Ok(())
    }

    fn io_to_errno(error: &io::Error) -> Errno {
        error.raw_os_error().map_or(Errno::EIO, Errno::from_i32)
    }

    fn system_time_from_timespec(secs: i64, nsecs: i64) -> SystemTime {
        let nanos = u32::try_from(nsecs).unwrap_or(0);
        if secs >= 0 {
            UNIX_EPOCH + Duration::new(secs.cast_unsigned(), nanos)
        } else {
            UNIX_EPOCH
                .checked_sub(Duration::new(secs.unsigned_abs(), 0))
                .unwrap_or(UNIX_EPOCH)
        }
    }

    fn time_or_now_to_timespec(time: Option<TimeOrNow>) -> libc::timespec {
        match time {
            None => libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            Some(TimeOrNow::Now) => libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_NOW,
            },
            Some(TimeOrNow::SpecificTime(st)) => match st.duration_since(UNIX_EPOCH) {
                Ok(dur) => libc::timespec {
                    tv_sec: i64::try_from(dur.as_secs()).unwrap_or(0),
                    tv_nsec: i64::from(dur.subsec_nanos()),
                },
                Err(err) => {
                    let dur = err.duration();
                    libc::timespec {
                        tv_sec: -i64::try_from(dur.as_secs()).unwrap_or(0),
                        tv_nsec: 0,
                    }
                }
            },
        }
    }

    #[allow(dead_code)]
    fn _ensure_rel_path_clean(rel: &Path) -> bool {
        rel.components().all(|c| matches!(c, Component::Normal(_)))
    }

    #[cfg(test)]
    mod tests {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, UNIX_EPOCH};

        use super::*;

        fn assert_independent_metadata(wt1: &Path, wt2: &Path, t1: SystemTime, t2: SystemTime) {
            // Independent per-worktree mtime and mode (stow#634): mutating wt2
            // never changes wt1 or the cache entry.
            File::open(wt1)
                .expect("open wt1")
                .set_modified(t1)
                .expect("set mtime wt1");
            File::open(wt2)
                .expect("open wt2")
                .set_modified(t2)
                .expect("set mtime wt2");
            std::fs::set_permissions(wt2, std::fs::Permissions::from_mode(0o755))
                .expect("chmod wt2");
            assert_eq!(
                std::fs::metadata(wt1)
                    .expect("meta wt1")
                    .modified()
                    .expect("t1"),
                t1
            );
            assert_eq!(
                std::fs::metadata(wt2)
                    .expect("meta wt2")
                    .modified()
                    .expect("t2"),
                t2
            );
            assert_eq!(
                std::fs::metadata(wt2).expect("meta wt2").mode() & 0o777,
                0o755
            );
            assert_ne!(
                std::fs::metadata(wt1).expect("meta wt1").mode() & 0o777,
                0o755
            );
        }

        fn assert_flock_and_escape_guard(mountpoint: &Path) {
            // Local flock on `.cargo-build-lock` works across two handles.
            let lock_path = mountpoint.join("bb/wt2/debug/.cargo-build-lock");
            let lock_a = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(&lock_path)
                .expect("open lock a");
            let guard = crate::file_lock::FileLock::try_exclusive(lock_a)
                .expect("lock a")
                .expect("lock a acquired");
            let lock_b = File::open(&lock_path).expect("open lock b");
            assert!(
                crate::file_lock::FileLock::try_exclusive(lock_b)
                    .expect("lock b")
                    .is_none(),
                "second exclusive flock must observe held lock"
            );
            drop(guard);

            // Security: cloning a path outside `cache_dir` is refused.
            let outside = tempfile::NamedTempFile::new().expect("outside");
            std::fs::write(outside.path(), b"secret").expect("write outside");
            let escape_dst = mountpoint.join("escape.bin");
            assert!(!try_virtual_clone(outside.path(), &escape_dst).expect("refused"));
            assert!(!escape_dst.exists());
        }

        fn assert_no_open_edge_cases(cache_entry: &Path, mountpoint: &Path, expected_len: u64) {
            // Opening a CoW stub read-write, unlinking it, then writing must copy
            // up cleanly into an anonymous backing file under `FUSE_NO_OPEN_SUPPORT`.
            let unlinked_rw_cow = mountpoint.join("cc/wt3/debug/deps/libunlinked_rw.rlib");
            assert!(try_virtual_clone(cache_entry, &unlinked_rw_cow).expect("clone rw unlinked"));
            let rw_cow = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&unlinked_rw_cow)
                .expect("open rw cow");
            std::fs::remove_file(&unlinked_rw_cow).expect("unlink rw cow");
            rw_cow.write_at(b"UNLINKED", 0).expect("write unlinked cow");
            let mut patched_head = [0u8; 8];
            rw_cow
                .read_at(&mut patched_head, 0)
                .expect("read back unlinked cow");
            assert_eq!(&patched_head, b"UNLINKED");
            assert_eq!(
                rw_cow.metadata().expect("fstat unlinked rw cow").len(),
                expected_len
            );
            drop(rw_cow);

            // Opening a file read-only and overwriting its name via `rename` must
            // keep the original descriptor readable and `fstat`-able.
            let old_target = mountpoint.join("cc/wt3/debug/deps/overwrite_old.txt");
            let new_source = mountpoint.join("cc/wt3/debug/deps/overwrite_new.txt");
            std::fs::write(&old_target, b"old-contents-1234").expect("write old");
            std::fs::write(&new_source, b"new-contents").expect("write new");
            let old_fd = File::open(&old_target).expect("open old");
            std::fs::rename(&new_source, &old_target).expect("rename overwrite");
            assert_eq!(old_fd.metadata().expect("fstat overwritten").len(), 17);
            let mut old_buf = [0u8; 17];
            old_fd
                .read_at(&mut old_buf, 0)
                .expect("read overwritten fd");
            assert_eq!(&old_buf, b"old-contents-1234");
            drop(old_fd);
            std::fs::remove_file(&old_target).expect("cleanup overwrite target");

            // Writeback flush after `fchmod(0o444)` on an existing writable file
            // must persist dirty pages cleanly under `FUSE_NO_OPEN_SUPPORT`.
            let chmod_wb = mountpoint.join("cc/wt3/debug/deps/chmod_wb.txt");
            std::fs::write(&chmod_wb, b"initial").expect("seed chmod_wb");
            {
                let f = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&chmod_wb)
                    .expect("open chmod_wb");
                f.write_at(b"flushed!", 0).expect("write chmod_wb");
                f.set_permissions(std::fs::Permissions::from_mode(0o444))
                    .expect("fchmod 0444");
            }
            assert_eq!(
                std::fs::read(&chmod_wb).expect("read chmod_wb"),
                b"flushed!"
            );
            std::fs::set_permissions(&chmod_wb, std::fs::Permissions::from_mode(0o644))
                .expect("restore mode");
            std::fs::remove_file(&chmod_wb).expect("cleanup chmod_wb");

            // Negative dentry cached by an earlier `stat` must not hide a
            // subsequent `try_virtual_clone` at the exact same path.
            let neg_clone = mountpoint.join("cc/wt3/debug/deps/libnegclone.rlib");
            assert!(std::fs::symlink_metadata(&neg_clone).is_err());
            assert!(try_virtual_clone(cache_entry, &neg_clone).expect("clone over neg dentry"));
            assert_eq!(
                std::fs::metadata(&neg_clone)
                    .expect("meta after neg clone")
                    .len(),
                expected_len
            );
            std::fs::remove_file(&neg_clone).expect("cleanup neg clone");

            // Multi-chunk `readdir` over > 300 entries must return every entry
            // cleanly with the lazy zero-copy `OpenDir` cache.
            let big_dir = mountpoint.join("big_dir");
            std::fs::create_dir_all(&big_dir).expect("mkdir big_dir");
            for idx in 0..320usize {
                std::fs::write(big_dir.join(format!("entry-{idx:04}.txt")), b"x")
                    .expect("write big_dir entry");
            }
            let listed: HashSet<_> = std::fs::read_dir(&big_dir)
                .expect("read big_dir")
                .map(|entry| entry.expect("dir entry").file_name())
                .collect();
            assert_eq!(listed.len(), 320);
            std::fs::remove_dir_all(&big_dir).expect("cleanup big_dir");
        }

        fn assert_unlinked_open_cow_and_concurrent_storm(
            cache_entry: &Path,
            mountpoint: &Path,
            expected_len: u64,
        ) {
            // Opening a regular file or CoW stub and unlinking it while open must
            // keep `fstat` working without ENOENT (Linux sends `getattr` with `fh=None`).
            let unlinked_reg = mountpoint.join("cc/wt3/debug/deps/unlinked.tmp");
            std::fs::write(&unlinked_reg, b"temp-payload").expect("write unlinked regular");
            let open_reg = File::open(&unlinked_reg).expect("open regular");
            std::fs::remove_file(&unlinked_reg).expect("unlink open regular");
            assert_eq!(
                open_reg
                    .metadata()
                    .expect("fstat unlinked open regular")
                    .len(),
                12
            );
            drop(open_reg);

            let unlinked_cow = mountpoint.join("cc/wt3/debug/deps/libunlinked.rlib");
            assert!(try_virtual_clone(cache_entry, &unlinked_cow).expect("clone unlinked"));
            let open_cow = File::open(&unlinked_cow).expect("open cow read-only");
            std::fs::remove_file(&unlinked_cow).expect("unlink open cow");
            assert_eq!(
                open_cow.metadata().expect("fstat unlinked open cow").len(),
                expected_len
            );
            let mut head = [0u8; 16];
            open_cow
                .read_at(&mut head, 0)
                .expect("read unlinked open cow");
            assert_eq!(head, std::fs::read(cache_entry).expect("cache")[..16]);
            drop(open_cow);

            assert_no_open_edge_cases(cache_entry, mountpoint, expected_len);

            // Under `FUSE_WRITEBACK_CACHE`, O_APPEND and partial O_WRONLY writes
            // on a CoW stub must copy up cleanly and preserve all untouched bytes.
            let append_cow = mountpoint.join("cc/wt3/debug/deps/libappend.rlib");
            assert!(try_virtual_clone(cache_entry, &append_cow).expect("clone append"));
            {
                use std::io::Write as _;
                let mut f = OpenOptions::new()
                    .append(true)
                    .open(&append_cow)
                    .expect("open cow append");
                f.write_all(b"-tail").expect("append cow");
            }
            let appended = std::fs::read(&append_cow).expect("read appended cow");
            assert_eq!(appended.len() as u64, expected_len + 5);
            assert!(appended.ends_with(b"-tail"));
            {
                let f = OpenOptions::new()
                    .write(true)
                    .open(&append_cow)
                    .expect("open wronly partial");
                f.write_at(b"PATCH", 10).expect("write_at partial page");
            }
            let patched = std::fs::read(&append_cow).expect("read patched");
            assert_eq!(&patched[10..15], b"PATCH");
            assert_eq!(patched.len() as u64, expected_len + 5);
            std::fs::remove_file(&append_cow).expect("cleanup append cow");

            // Concurrent create / atomic rename / unlink / lookup storm on the
            // same directory must never produce spurious ENOENT or stale inode
            // paths.
            let storm_dir = mountpoint.join("storm");
            std::fs::create_dir_all(&storm_dir).expect("mkdir storm");
            std::thread::scope(|scope| {
                for worker in 0..8usize {
                    let dir = storm_dir.clone();
                    scope.spawn(move || {
                        for iter in 0..100usize {
                            let tmp = dir.join(format!("w{worker}-{iter}.tmp"));
                            let dst = dir.join(format!("slot-{}.out", iter % 4));
                            let body = format!("worker-{worker}-iter-{iter}");
                            std::fs::write(&tmp, body.as_bytes()).expect("write tmp");
                            std::fs::rename(&tmp, &dst).expect("rename tmp -> dst");
                            let _ = std::fs::read(&dst);
                            if iter % 3 == 0 {
                                let _ = std::fs::remove_file(&dst);
                            }
                        }
                    });
                }
            });
        }

        /// Exercise the full Linux FUSE virtual copy-on-write contract when `/dev/fuse`
        /// and `fusermount3` are available (e.g. Ubuntu ext4 runners / VMs).
        #[test]
        fn fuse_virtual_cow_isolation_copy_up_persistence_and_eviction() {
            if !fuse_runtime_available() {
                return;
            }
            let root = tempfile::tempdir().expect("tempdir");
            let cache_dir = root.path();
            let cache_entry = cache_dir.join("crates-io/1.99.1/bundles/v3/demo/files/libdemo.rlib");
            std::fs::create_dir_all(cache_entry.parent().expect("parent")).expect("create cache");
            let payload: Vec<u8> = (0..131_072u32).map(|i| (i % 251) as u8).collect();
            std::fs::write(&cache_entry, &payload).expect("write cache entry");

            let mountpoint = cache_dir.join(BUILD_DIR_PARENT);
            let backing_dir = cache_dir.join(BUILD_DIR_BACKING);
            let mount =
                FuseMount::mount(cache_dir, &mountpoint, &backing_dir).expect("mount FUSE CoW");
            assert!(is_fuse_mount(&mountpoint));

            // Materialize the same cached artifact into two separate worktrees.
            let wt1 = mountpoint.join("aa/wt1/debug/deps/libdemo.rlib");
            let wt2 = mountpoint.join("bb/wt2/debug/deps/libdemo.rlib");
            std::fs::create_dir_all(wt1.parent().expect("wt1 parent")).expect("mkdir wt1");
            std::fs::create_dir_all(wt2.parent().expect("wt2 parent")).expect("mkdir wt2");

            assert!(try_virtual_clone(&cache_entry, &wt1).expect("clone wt1"));
            assert!(try_virtual_clone(&cache_entry, &wt2).expect("clone wt2"));

            // Both worktrees read the full cached payload with 0-byte stubs in backing_dir.
            assert_eq!(std::fs::read(&wt1).expect("read wt1"), payload);
            assert_eq!(std::fs::read(&wt2).expect("read wt2"), payload);
            let backing_wt1 = backing_dir.join("aa/wt1/debug/deps/libdemo.rlib");
            assert_eq!(
                std::fs::metadata(&backing_wt1).expect("backing stub").len(),
                0,
                "backing stub must occupy zero private bytes"
            );

            // Cache entry now has nlink >= 2 (shared with .stow-cow-blobs), so
            // reclaimable::shared_bytes recognizes it as shared on ext4.
            assert!(std::fs::metadata(&cache_entry).expect("cache meta").nlink() >= 2);

            let t1 = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
            let t2 = UNIX_EPOCH + Duration::from_secs(1_700_005_000);
            assert_independent_metadata(&wt1, &wt2, t1, t2);

            // `persist_noclobber` (`link` + `unlink`) works seamlessly on CoW stubs.
            let wt3_final = mountpoint.join("cc/wt3/debug/deps/libdemo.rlib");
            std::fs::create_dir_all(wt3_final.parent().expect("wt3 parent")).expect("mkdir wt3");
            let staged =
                crate::inject::stage_clone(&cache_entry, &wt3_final).expect("stage_clone via FUSE");
            staged
                .persist_noclobber(&wt3_final)
                .expect("persist_noclobber");
            assert_eq!(std::fs::read(&wt3_final).expect("read wt3"), payload);

            // Copy-up on write: mutating wt1 must not corrupt wt2 or the cache entry.
            std::fs::write(&wt1, b"overwritten-private").expect("write copy-up");
            assert_eq!(
                std::fs::read(&wt1).expect("read wt1 after write"),
                b"overwritten-private"
            );
            assert_eq!(std::fs::read(&wt2).expect("wt2 unaffected"), payload);
            assert_eq!(
                std::fs::read(&cache_entry).expect("cache unaffected"),
                payload
            );

            assert_unlinked_open_cow_and_concurrent_storm(
                &cache_entry,
                &mountpoint,
                payload.len() as u64,
            );

            // Evicting the original cache entry leaves wt2 intact via `.stow-cow-blobs`.
            std::fs::remove_file(&cache_entry).expect("evict cache entry");
            assert_eq!(std::fs::read(&wt2).expect("wt2 survives eviction"), payload);

            // Daemon restart (unmount + remount) preserves wt2 and its mtime.
            mount.unmount();
            assert!(!is_fuse_mount(&mountpoint));
            let remount =
                FuseMount::mount(cache_dir, &mountpoint, &backing_dir).expect("remount FUSE CoW");
            assert_eq!(std::fs::read(&wt2).expect("wt2 survives restart"), payload);
            assert_eq!(
                std::fs::metadata(&wt2)
                    .expect("meta wt2 after restart")
                    .modified()
                    .expect("t2"),
                t2
            );

            assert_flock_and_escape_guard(&mountpoint);

            remount.unmount();
        }

        #[test]
        fn inode_table_detaches_unlinked_backing_ino_and_handles_renames() {
            let mut table = InodeTable::new(1);
            let root = Path::new("/backing");

            let ino1 =
                table.upsert_lookup(PathBuf::from("a.tmp"), 500, FileType::RegularFile, None);
            assert_eq!(
                table.resolve_backing_path(root, ino1),
                Some(root.join("a.tmp"))
            );

            // Unlinking `a.tmp` detaches backing inode 500 immediately so ext4
            // reusing inode 500 before `forget(ino1)` gets a brand-new FUSE inode.
            table.unlink_path(Path::new("a.tmp"));
            assert_eq!(table.resolve_backing_path(root, ino1), None);
            let ino2 =
                table.upsert_lookup(PathBuf::from("b.tmp"), 500, FileType::RegularFile, None);
            assert_ne!(ino1, ino2);
            assert_eq!(
                table.resolve_backing_path(root, ino2),
                Some(root.join("b.tmp"))
            );

            // Self-rename and same-inode hardlink rename are POSIX no-ops.
            let ino2_link =
                table.upsert_lookup(PathBuf::from("b.link"), 500, FileType::RegularFile, None);
            assert_eq!(ino2_link, ino2);
            table.rename_path(Path::new("b.tmp"), Path::new("b.tmp"), false);
            table.rename_path(Path::new("b.tmp"), Path::new("b.link"), false);
            assert_eq!(table.path_to_ino.get(Path::new("b.tmp")), Some(&ino2));
            assert_eq!(table.path_to_ino.get(Path::new("b.link")), Some(&ino2));

            // Directory rename updates descendants and `path_to_ino`.
            let dir_ino =
                table.upsert_lookup(PathBuf::from("dir1"), 600, FileType::Directory, None);
            let child_ino =
                table.upsert_lookup(PathBuf::from("dir1/f"), 601, FileType::RegularFile, None);
            table.rename_path(Path::new("dir1"), Path::new("dir2"), false);
            assert_eq!(table.path_to_ino.get(Path::new("dir2")), Some(&dir_ino));
            assert_eq!(table.path_to_ino.get(Path::new("dir2/f")), Some(&child_ino));
            assert_eq!(
                table.resolve_backing_path(root, child_ino),
                Some(root.join("dir2/f"))
            );
            assert!(!table.path_to_ino.contains_key(Path::new("dir1/f")));
        }
    }
}
