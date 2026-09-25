//! Virtual filesystem access for the vendored cargo code.
//!
//! The vendored sources call `std::fs`-shaped functions; this module provides
//! the same API surface backed by an ambient [`Vfs`] implementation, so the
//! resolver works both against the real filesystem (the host-side
//! differential harness, via [`OsVfs`]) and against an in-memory tree
//! (wasm/edge, via [`MemoryVfs`]) without any other code changes.
//!
//! The ambient VFS is installed for the duration of a resolve by
//! [`with_vfs`]. Files opened for write are buffered and committed to the
//! backing [`Vfs`] on flush/drop, matching the semantics the vendored code
//! relies on (e.g. the `.cargo-ok` marker written after extraction).

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::future::Future;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use std::time::SystemTime;

/// The filesystem boundary the vendored cargo code sees.
pub trait Vfs {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    /// Write `data` atomically enough for our callers (single writer).
    fn write(&self, path: &Path, data: &[u8]) -> io::Result<()>;
    fn create_dir_all(&self, path: &Path) -> io::Result<()>;
    fn read_dir(&self, path: &Path) -> io::Result<Vec<RawDirEntry>>;
    fn metadata(&self, path: &Path) -> io::Result<RawMetadata>;
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    fn remove_dir_all(&self, path: &Path) -> io::Result<()>;
    /// Equivalent to `std::fs::canonicalize` for this filesystem.
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf>;
    fn exists(&self, path: &Path) -> bool {
        self.metadata(path).is_ok()
    }
    /// Whether `File`s on this backend wrap a real OS handle. Only [`OsVfs`]
    /// does, which lets `flock` take real OS-level locks; memory backends
    /// report locking as unsupported (a single process cannot contend).
    fn is_os(&self) -> bool {
        false
    }
    /// `std::fs::rename` — always available in our two backends.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let data = self.read(from)?;
        self.write(to, &data)?;
        self.remove_file(from)
    }
    /// Last-write time of `path` (for `cargo_util::paths::mtime` callers).
    fn mtime(&self, _path: &Path) -> io::Result<SystemTime> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no mtime available",
        ))
    }
    /// Record a modification time (`filetime::set_file_mtime`).
    fn set_mtime(&self, _path: &Path, _t: SystemTime) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cannot set mtime",
        ))
    }
}

/// Raw metadata returned by a [`Vfs`].
#[derive(Debug, Clone)]
pub struct RawMetadata {
    pub file_type: RawFileType,
    pub len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawFileType {
    File,
    Dir,
    Symlink,
}

#[derive(Debug, Clone)]
pub struct RawDirEntry {
    pub path: PathBuf,
    pub file_type: RawFileType,
}

// ---------------------------------------------------------------------------
// Ambient VFS handle
// ---------------------------------------------------------------------------

thread_local! {
    static CURRENT: RefCell<Option<Rc<dyn Vfs>>> = const { RefCell::new(None) };
}

/// Install `vfs` as the ambient filesystem for `f`'s dynamic extent.
pub fn with_vfs<R>(vfs: Rc<dyn Vfs>, f: impl FnOnce() -> R) -> R {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CURRENT.with(|c| *c.borrow_mut() = None);
        }
    }
    CURRENT.with(|c| *c.borrow_mut() = Some(vfs));
    let _reset = Reset;
    f()
}

/// Install `vfs` as the ambient filesystem until replaced — for hosts that
/// own the thread for the process's lifetime (the differential harness),
/// where the scoped [`with_vfs`] reset cannot span `.await` points.
pub fn set_vfs(vfs: Rc<dyn Vfs>) {
    CURRENT.with(|c| *c.borrow_mut() = Some(vfs));
}

/// Swap the ambient filesystem, returning the previously installed one
/// (`None` when none was installed). Futures that swap a VFS in before
/// polling their inner future — the poll-scoped ambient pattern — restore
/// with `replace_vfs(previous)` after the poll so an interleaved future on
/// the same thread always sees its own ambient.
pub fn replace_vfs(vfs: Option<Rc<dyn Vfs>>) -> Option<Rc<dyn Vfs>> {
    CURRENT.with(|c| std::mem::replace(&mut *c.borrow_mut(), vfs))
}

/// A future that installs `vfs` as the ambient filesystem for each poll of
/// the wrapped future and restores the previous ambient afterwards — the
/// pattern `tracing::Instrument` applies to a tracing span.
///
/// The Workers isolate runs every in-flight request's futures on one
/// thread, and the vendored resolver reads [`current`] only synchronously
/// inside a poll, so resolves interleaved on that thread each see their
/// own ambient VFS. Scoping the ambient to the poll replaces the
/// isolate-wide mutex a single shared slot would otherwise need: a request
/// the runtime abandons mid-resolve can no longer park every later resolve
/// on a permit nobody releases.
pub struct VfsScoped<'a, T> {
    vfs: Rc<dyn Vfs>,
    inner: Pin<Box<dyn Future<Output = T> + 'a>>,
}

/// Wrap `inner` so [`current`] answers `vfs` for each of its polls.
pub fn poll_scoped<'a, T>(
    vfs: Rc<dyn Vfs>,
    inner: impl Future<Output = T> + 'a,
) -> VfsScoped<'a, T> {
    VfsScoped {
        vfs,
        inner: Box::pin(inner),
    }
}

impl<T> Future for VfsScoped<'_, T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let previous = replace_vfs(Some(this.vfs.clone()));
        let result = this.inner.as_mut().poll(cx);
        replace_vfs(previous);
        result
    }
}

/// The ambient filesystem. Panics when no VFS is installed.
pub fn current() -> Rc<dyn Vfs> {
    CURRENT.with(|c| {
        c.borrow()
            .clone()
            .expect("stow-resolve filesystem accessed without an installed VFS")
    })
}

/// `Path::is_absolute` with VFS semantics.
///
/// `is_absolute` is stubbed `false` on `wasm32-unknown-unknown` even though
/// component parsing still yields [`std::path::Component::RootDir`], so the
/// root component is the absoluteness test there — identical to `std`'s unix
/// rule, which every wasm VFS path follows. Hosts keep `std`'s own
/// platform-aware check (Windows drives, UNC prefixes).
pub fn is_absolute(path: &Path) -> bool {
    // `std`'s own rule on hosts (Windows drives come through `Prefix`, not
    // `RootDir`); wasm's VFS paths are unix-shaped, where the root component
    // is the absoluteness test — `is_absolute` is stubbed `false` there.
    #[cfg(target_family = "wasm")]
    return matches!(
        path.components().next(),
        Some(std::path::Component::RootDir)
    );
    #[cfg(not(target_family = "wasm"))]
    path.is_absolute()
}

/// `glob::glob` over the ambient VFS.
///
/// cargo expands `workspace.members` patterns through the `glob` crate's
/// iterator, which reads the real filesystem directly; over our VFS the
/// equivalent is a `read_dir` walk from the pattern's literal prefix with
/// `glob::Pattern` matching on top — the same crate and its default
/// `MatchOptions`, so `*`/`?`/`[...]`/`**` keep upstream semantics.
/// Results are sorted; upstream yields filesystem order.
pub fn glob(pattern: &Path) -> io::Result<Vec<PathBuf>> {
    let pattern_str = pattern.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("non-UTF8 glob pattern `{}`", pattern.display()),
        )
    })?;
    // `.` components are inert filesystem-wise, but `Pattern` keeps them
    // as literal tokens while `Path::components` drops them off
    // candidates — `dir/./crates/*` would match nothing upstream of
    // this normalization. `..` stays: `components` keeps ParentDir, so
    // the pattern and the candidates tokenize the same way.
    let mut normalized = PathBuf::new();
    for component in Path::new(pattern_str).components() {
        if component != Component::CurDir {
            normalized.push(component.as_os_str());
        }
    }
    let pattern_str = normalized.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("non-UTF8 glob pattern `{}`", pattern.display()),
        )
    })?;
    let pattern = glob::Pattern::new(pattern_str)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;

    // The deepest leading directory containing no glob metacharacters is
    // the walk's root — components under it are matched by `Pattern`.
    let mut root = PathBuf::new();
    for component in Path::new(pattern_str).components() {
        match component {
            Component::Normal(name) => {
                let name = name.to_str().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("non-UTF8 glob component in `{}`", pattern_str),
                    )
                })?;
                if name.chars().any(|c| matches!(c, '*' | '?' | '[')) {
                    break;
                }
                root.push(name);
            }
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {
                root.push(component.as_os_str());
            }
            // `..` is left for `Pattern` to match textually.
            Component::ParentDir => break,
        }
    }

    // Upstream's iterator navigates component by component, so a `*`
    // segment never crosses a directory boundary — `require_literal_separator`
    // reproduces that for the whole-path matcher.
    let options = glob::MatchOptions {
        require_literal_separator: true,
        ..Default::default()
    };

    let mut found = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        let entries = match current().read_dir(&dir) {
            Ok(entries) => entries,
            // A pattern whose literal prefix does not exist matches
            // nothing, as upstream's iterator reports on a missing base.
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for entry in entries {
            if pattern.matches_path_with(&entry.path, options) {
                found.push(entry.path.clone());
            }
            if entry.file_type == RawFileType::Dir {
                stack.push(entry.path);
            }
        }
    }
    found.sort();
    Ok(found)
}

// ---------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------

/// Real filesystem — used by the host-side differential harness so that
/// paths in emitted metadata byte-match real `cargo metadata` output.
pub struct OsVfs;

impl Vfs for OsVfs {
    fn is_os(&self) -> bool {
        true
    }
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }
    fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, data)
    }
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        std::fs::create_dir_all(path)
    }
    fn read_dir(&self, path: &Path) -> io::Result<Vec<RawDirEntry>> {
        std::fs::read_dir(path)?
            .map(|e| {
                e.map(|e| RawDirEntry {
                    path: e.path(),
                    file_type: match e.file_type() {
                        Ok(t) if t.is_dir() => RawFileType::Dir,
                        Ok(t) if t.is_symlink() => RawFileType::Symlink,
                        _ => RawFileType::File,
                    },
                })
            })
            .collect()
    }
    fn metadata(&self, path: &Path) -> io::Result<RawMetadata> {
        let m = std::fs::metadata(path)?;
        Ok(RawMetadata {
            file_type: if m.is_dir() {
                RawFileType::Dir
            } else {
                RawFileType::File
            },
            len: m.len(),
        })
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }
    fn remove_dir_all(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_dir_all(path)
    }
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::canonicalize(path)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }
    fn mtime(&self, path: &Path) -> io::Result<SystemTime> {
        std::fs::metadata(path)?.modified()
    }
    #[cfg(not(target_family = "wasm"))]
    fn set_mtime(&self, path: &Path, t: SystemTime) -> io::Result<()> {
        filetime::set_file_mtime(path, filetime::FileTime::from_system_time(t))
    }
    #[cfg(target_family = "wasm")]
    fn set_mtime(&self, _path: &Path, _t: SystemTime) -> io::Result<()> {
        // There is no OS filesystem on wasm; like every other OsVfs method
        // this reports the operation as unimplemented there.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "OsVfs::set_mtime is unavailable on wasm32-unknown-unknown",
        ))
    }
}

/// In-memory tree — the wasm/edge backend. Holds one resolve's worth of
/// inputs (project manifests plus fetched registry files) and the files the
/// resolver writes (unpacked crates, `Cargo.lock`, index caches).
///
/// Git trees carry no directory entries of their own, so `read_dir` and
/// `metadata` on directories are derived from path prefixes — the same way
/// `std::fs` presents a tree whose intermediate dirs are implicit.
#[derive(Default)]
pub struct MemoryVfs {
    files: RefCell<BTreeMap<PathBuf, Vec<u8>>>,
    mtimes: RefCell<BTreeMap<PathBuf, SystemTime>>,
}

impl MemoryVfs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Populate a file (e.g. a fetched manifest or registry index entry).
    pub fn insert(&self, path: impl Into<PathBuf>, data: impl Into<Vec<u8>>) {
        let path = normalize(path.into());
        self.files.borrow_mut().insert(path.clone(), data.into());
        self.mtimes
            .borrow_mut()
            .insert(path, crate::util::time::system_time_now());
    }

    fn is_dir(&self, path: &Path) -> bool {
        let mut prefix = path.to_path_buf();
        prefix.push("");
        self.files.borrow().keys().any(|p| p.starts_with(&prefix))
    }
}

impl Vfs for MemoryVfs {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        let path = normalize(path.to_path_buf());
        self.files
            .borrow()
            .get(&path)
            .cloned()
            .ok_or_else(|| not_found(&path))
    }
    fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        self.insert(path.to_path_buf(), data.to_vec());
        Ok(())
    }
    fn create_dir_all(&self, _path: &Path) -> io::Result<()> {
        Ok(())
    }
    fn read_dir(&self, path: &Path) -> io::Result<Vec<RawDirEntry>> {
        let dir = normalize(path.to_path_buf());
        let mut out = BTreeMap::new();
        for key in self.files.borrow().keys() {
            if let Ok(rest) = key.strip_prefix(&dir) {
                let mut it = rest.iter();
                if let Some(first) = it.next() {
                    let child = dir.join(first);
                    let ft = if it.next().is_some() {
                        RawFileType::Dir
                    } else {
                        RawFileType::File
                    };
                    out.insert(
                        child.clone(),
                        RawDirEntry {
                            path: child,
                            file_type: ft,
                        },
                    );
                }
            }
        }
        if out.is_empty() && !self.is_dir(&dir) {
            return Err(not_found(&dir));
        }
        Ok(out.into_values().collect())
    }
    fn metadata(&self, path: &Path) -> io::Result<RawMetadata> {
        let path = normalize(path.to_path_buf());
        if let Some(data) = self.files.borrow().get(&path) {
            return Ok(RawMetadata {
                file_type: RawFileType::File,
                len: data.len() as u64,
            });
        }
        if self.is_dir(&path) {
            return Ok(RawMetadata {
                file_type: RawFileType::Dir,
                len: 0,
            });
        }
        Err(not_found(&path))
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        let path = normalize(path.to_path_buf());
        if self.files.borrow_mut().remove(&path).is_none() {
            return Err(not_found(&path));
        }
        Ok(())
    }
    fn remove_dir_all(&self, path: &Path) -> io::Result<()> {
        let dir = normalize(path.to_path_buf());
        let mut prefix = dir.clone();
        prefix.push("");
        let keys: Vec<PathBuf> = self
            .files
            .borrow()
            .keys()
            .filter(|p| p.starts_with(&prefix))
            .cloned()
            .collect();
        if keys.is_empty() {
            return Err(not_found(&dir));
        }
        let mut files = self.files.borrow_mut();
        for k in keys {
            files.remove(&k);
        }
        Ok(())
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let from = normalize(from.to_path_buf());
        let to = normalize(to.to_path_buf());
        // A directory moves with every file beneath it — the default
        // file-only `rename` cannot see a dir in this backend.
        if !self.files.borrow().contains_key(&from) && !self.is_dir(&from) {
            return Err(not_found(&from));
        }
        let mut prefix = from.clone();
        prefix.push("");
        let keys: Vec<PathBuf> = self
            .files
            .borrow()
            .keys()
            .filter(|p| **p == from || p.starts_with(&prefix))
            .cloned()
            .collect();
        let mut files = self.files.borrow_mut();
        let mut mtimes = self.mtimes.borrow_mut();
        for key in keys {
            if let Some(data) = files.remove(&key) {
                let rest = key.strip_prefix(&from).unwrap_or_else(|_| Path::new(""));
                files.insert(to.join(rest), data);
            }
            if let Some(t) = mtimes.remove(&key) {
                let rest = key.strip_prefix(&from).unwrap_or_else(|_| Path::new(""));
                mtimes.insert(to.join(rest), t);
            }
        }
        Ok(())
    }
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        // The in-memory tree has no symlinks, so canonical form is the
        // normalized path itself (same rule `std::fs::canonicalize` applies
        // to a symlink-free hierarchy).
        Ok(normalize(path.to_path_buf()))
    }
    fn mtime(&self, path: &Path) -> io::Result<SystemTime> {
        let path = normalize(path.to_path_buf());
        self.mtimes
            .borrow()
            .get(&path)
            .copied()
            .ok_or_else(|| not_found(&path))
    }
    fn set_mtime(&self, path: &Path, t: SystemTime) -> io::Result<()> {
        let path = normalize(path.to_path_buf());
        if !self.files.borrow().contains_key(&path) && !self.is_dir(&path) {
            return Err(not_found(&path));
        }
        self.mtimes.borrow_mut().insert(path, t);
        Ok(())
    }
}

fn normalize(path: PathBuf) -> PathBuf {
    // Lexically normalize `.`/`..`/duplicate separators without touching the
    // filesystem, matching `cargo_util::paths::normalize_path`.
    crate::util::paths::normalize_path(&path)
}

fn not_found(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("{}: no such file or directory", path.display()),
    )
}

// ---------------------------------------------------------------------------
// `std::fs`-shaped API used by the vendored sources
// ---------------------------------------------------------------------------

/// A file over the ambient VFS.
///
/// On [`OsVfs`] this wraps a real `std::fs::File`; on memory backends it is a
/// buffered view committed to the VFS on `flush`/drop. Clones share position
/// and contents, like clones of `std::fs::File` share the OS handle.
impl std::fmt::Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &*self.inner.borrow() {
            FileInner::Os(file) => f.debug_tuple("File::Os").field(file).finish(),
            FileInner::Mem { path, .. } => f.debug_tuple("File::Mem").field(path).finish(),
        }
    }
}

#[derive(Clone)]
pub struct File {
    inner: Rc<RefCell<FileInner>>,
}

enum FileInner {
    /// Real OS file — only ever produced by [`OsVfs`].
    Os(std::fs::File),
    /// Buffered VFS file.
    Mem {
        path: PathBuf,
        data: Vec<u8>,
        pos: u64,
        writable: bool,
        dirty: bool,
    },
}

impl File {
    fn buffered(path: PathBuf, data: Vec<u8>, pos: u64, writable: bool) -> File {
        File {
            inner: Rc::new(RefCell::new(FileInner::Mem {
                path: normalize(path),
                data,
                pos,
                writable,
                dirty: false,
            })),
        }
    }

    /// Whether this file is backed by a real OS handle.
    pub fn is_os(&self) -> bool {
        matches!(&*self.inner.borrow(), FileInner::Os(_))
    }

    /// The raw OS file, when this file is OS-backed (flock's fcntl path).
    pub(crate) fn os_file(&self) -> Option<std::fs::File> {
        match &*self.inner.borrow() {
            FileInner::Os(f) => f.try_clone().ok(),
            FileInner::Mem { .. } => None,
        }
    }

    pub fn metadata(&self) -> io::Result<Metadata> {
        match &*self.inner.borrow() {
            FileInner::Os(f) => f.metadata().map(|m| {
                Metadata(RawMetadata {
                    file_type: if m.is_dir() {
                        RawFileType::Dir
                    } else if m.is_symlink() {
                        RawFileType::Symlink
                    } else {
                        RawFileType::File
                    },
                    len: m.len(),
                })
            }),
            FileInner::Mem { data, .. } => Ok(Metadata(RawMetadata {
                file_type: RawFileType::File,
                len: data.len() as u64,
            })),
        }
    }

    /// Force a commit of buffered writes. No-op for OS files.
    pub fn commit(&mut self) -> io::Result<()> {
        let mut inner = self.inner.borrow_mut();
        if let FileInner::Mem {
            path, data, dirty, ..
        } = &mut *inner
            && *dirty
        {
            current().write(path, data)?;
            *dirty = false;
        }
        Ok(())
    }

    /// `std::fs::File::set_len`.
    pub fn set_len(&self, size: u64) -> io::Result<()> {
        match &mut *self.inner.borrow_mut() {
            FileInner::Os(f) => f.set_len(size),
            FileInner::Mem {
                data,
                dirty,
                writable,
                ..
            } => {
                if !*writable {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "file not opened for writing",
                    ));
                }
                data.resize(size as usize, 0);
                *dirty = true;
                Ok(())
            }
        }
    }

    /// `std::fs::File::try_lock`. Reports [`io::ErrorKind::Unsupported`] on
    /// memory backends, where callers treat locking like cargo treats NFS:
    /// locking is skipped, never faked.
    pub fn try_lock(&self) -> Result<(), std::fs::TryLockError> {
        match &*self.inner.borrow() {
            FileInner::Os(f) => f.try_lock(),
            FileInner::Mem { .. } => Err(std::fs::TryLockError::Error(io::Error::new(
                io::ErrorKind::Unsupported,
                "file locking is unsupported on this filesystem",
            ))),
        }
    }

    /// `std::fs::File::try_lock_shared`. See [`File::try_lock`].
    pub fn try_lock_shared(&self) -> Result<(), std::fs::TryLockError> {
        match &*self.inner.borrow() {
            FileInner::Os(f) => f.try_lock_shared(),
            FileInner::Mem { .. } => Err(std::fs::TryLockError::Error(io::Error::new(
                io::ErrorKind::Unsupported,
                "file locking is unsupported on this filesystem",
            ))),
        }
    }

    /// `std::fs::File::lock`. See [`File::try_lock`].
    pub fn lock(&self) -> io::Result<()> {
        match &*self.inner.borrow() {
            FileInner::Os(f) => f.lock(),
            FileInner::Mem { .. } => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "file locking is unsupported on this filesystem",
            )),
        }
    }

    /// `std::fs::File::lock_shared`. See [`File::try_lock`].
    pub fn lock_shared(&self) -> io::Result<()> {
        match &*self.inner.borrow() {
            FileInner::Os(f) => f.lock_shared(),
            FileInner::Mem { .. } => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "file locking is unsupported on this filesystem",
            )),
        }
    }

    /// `std::fs::File::unlock`.
    pub fn unlock(&self) -> io::Result<()> {
        match &*self.inner.borrow() {
            FileInner::Os(f) => f.unlock(),
            FileInner::Mem { .. } => Ok(()),
        }
    }

    fn open_opts(
        path: &Path,
        read: bool,
        write: bool,
        append: bool,
        truncate: bool,
    ) -> io::Result<File> {
        let mut data = if read || append {
            current().read(path)?
        } else {
            Vec::new()
        };
        if truncate {
            data.clear();
        }
        let pos = if append { data.len() as u64 } else { 0 };
        Ok(File::buffered(path.to_path_buf(), data, pos, write))
    }
}

impl Drop for File {
    fn drop(&mut self) {
        let _ = self.commit();
    }
}

impl Read for File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self).read(buf)
    }
}

impl Read for &File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut *self.inner.borrow_mut() {
            FileInner::Os(f) => f.read(buf),
            FileInner::Mem { data, pos, .. } => {
                let avail = data.len().saturating_sub(*pos as usize);
                let n = avail.min(buf.len());
                buf[..n].copy_from_slice(&data[*pos as usize..*pos as usize + n]);
                *pos += n as u64;
                Ok(n)
            }
        }
    }
}

impl Seek for File {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        (&*self).seek(pos)
    }
}

impl Seek for &File {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match &mut *self.inner.borrow_mut() {
            FileInner::Os(f) => f.seek(pos),
            FileInner::Mem { data, pos: cur, .. } => {
                let new = match pos {
                    SeekFrom::Start(n) => n as i64,
                    SeekFrom::End(n) => data.len() as i64 + n,
                    SeekFrom::Current(n) => *cur as i64 + n,
                };
                if new < 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid seek"));
                }
                *cur = new as u64;
                Ok(*cur)
            }
        }
    }
}

impl Write for File {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        (&*self).flush()
    }
}

impl Write for &File {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut *self.inner.borrow_mut() {
            FileInner::Os(f) => f.write(buf),
            FileInner::Mem {
                data,
                pos,
                writable,
                dirty,
                ..
            } => {
                if !*writable {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "file not opened for writing",
                    ));
                }
                let end = *pos as usize + buf.len();
                if end > data.len() {
                    data.resize(end, 0);
                }
                data[*pos as usize..end].copy_from_slice(buf);
                *pos = end as u64;
                *dirty = true;
                Ok(buf.len())
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut inner = self.inner.borrow_mut();
        if let FileInner::Mem {
            path, data, dirty, ..
        } = &mut *inner
            && *dirty
        {
            current().write(path, data)?;
            *dirty = false;
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
}

impl OpenOptions {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn read(&mut self, v: bool) -> &mut Self {
        self.read = v;
        self
    }
    pub fn write(&mut self, v: bool) -> &mut Self {
        self.write = v;
        self
    }
    pub fn append(&mut self, v: bool) -> &mut Self {
        self.append = v;
        self
    }
    pub fn truncate(&mut self, v: bool) -> &mut Self {
        self.truncate = v;
        self
    }
    pub fn create(&mut self, v: bool) -> &mut Self {
        self.create = v;
        self
    }
    pub fn create_new(&mut self, v: bool) -> &mut Self {
        self.create_new = v;
        self
    }
    pub fn open(&self, path: &Path) -> io::Result<File> {
        if current().is_os() {
            let mut opts = std::fs::OpenOptions::new();
            opts.read(self.read)
                .write(self.write)
                .append(self.append)
                .truncate(self.truncate)
                .create(self.create)
                .create_new(self.create_new);
            return opts.open(path).map(|f| File {
                inner: Rc::new(RefCell::new(FileInner::Os(f))),
            });
        }
        if self.create_new && current().exists(path) {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "file exists"));
        }
        let exists = current().exists(path);
        if !exists && !(self.create || self.write || self.append || self.create_new) {
            return Err(not_found(path));
        }
        if !exists && (self.write || self.append || self.create) {
            current().write(path, &[])?;
        }
        File::open_opts(
            path,
            self.read,
            self.write || self.append,
            self.append,
            self.truncate,
        )
    }
}

pub fn read(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    current().read(path.as_ref())
}

pub fn read_to_string(path: impl AsRef<Path>) -> io::Result<String> {
    let bytes = read(path.as_ref())?;
    String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    current().write(path.as_ref(), contents.as_ref())
}

pub fn create_dir_all(path: impl AsRef<Path>) -> io::Result<()> {
    current().create_dir_all(path.as_ref())
}

pub fn remove_dir_all(path: impl AsRef<Path>) -> io::Result<()> {
    current().remove_dir_all(path.as_ref())
}

pub fn remove_dir(path: impl AsRef<Path>) -> io::Result<()> {
    current().remove_dir_all(path.as_ref())
}

pub fn remove_file(path: impl AsRef<Path>) -> io::Result<()> {
    current().remove_file(path.as_ref())
}

pub fn rename(from: impl AsRef<Path>, to: impl AsRef<Path>) -> io::Result<()> {
    current().rename(from.as_ref(), to.as_ref())
}

pub fn metadata(path: impl AsRef<Path>) -> io::Result<Metadata> {
    current().metadata(path.as_ref()).map(Metadata)
}

pub fn symlink_metadata(path: impl AsRef<Path>) -> io::Result<Metadata> {
    metadata(path)
}

pub fn canonicalize(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    current().canonicalize(path.as_ref())
}

/// `Path::exists` — false on any error, matching `std::path::Path::exists`.
pub fn exists(path: impl AsRef<Path>) -> bool {
    current().exists(path.as_ref())
}

/// `Path::is_file` — false on any error.
pub fn is_file(path: impl AsRef<Path>) -> bool {
    current()
        .metadata(path.as_ref())
        .map(|m| m.file_type == RawFileType::File)
        .unwrap_or(false)
}

/// `Path::is_dir` — false on any error.
pub fn is_dir(path: impl AsRef<Path>) -> bool {
    current()
        .metadata(path.as_ref())
        .map(|m| m.file_type == RawFileType::Dir)
        .unwrap_or(false)
}

/// `Path::is_symlink` — false on any error.
pub fn is_symlink(path: impl AsRef<Path>) -> bool {
    current()
        .metadata(path.as_ref())
        .map(|m| m.file_type == RawFileType::Symlink)
        .unwrap_or(false)
}

#[derive(Debug)]
pub struct Metadata(RawMetadata);

impl Metadata {
    pub fn is_dir(&self) -> bool {
        self.0.file_type == RawFileType::Dir
    }
    pub fn is_file(&self) -> bool {
        self.0.file_type == RawFileType::File
    }
    pub fn is_symlink(&self) -> bool {
        self.0.file_type == RawFileType::Symlink
    }
    pub fn len(&self) -> u64 {
        self.0.len
    }
    pub fn file_type(&self) -> FileType {
        FileType(self.0.file_type)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FileType(RawFileType);

impl FileType {
    pub fn is_dir(&self) -> bool {
        self.0 == RawFileType::Dir
    }
    pub fn is_file(&self) -> bool {
        self.0 == RawFileType::File
    }
    pub fn is_symlink(&self) -> bool {
        self.0 == RawFileType::Symlink
    }
}

#[derive(Debug)]
pub struct DirEntry(RawDirEntry);

impl DirEntry {
    pub fn path(&self) -> PathBuf {
        self.0.path.clone()
    }
    pub fn file_name(&self) -> std::ffi::OsString {
        self.0
            .path
            .file_name()
            .map(|s| s.to_os_string())
            .unwrap_or_default()
    }
    pub fn file_type(&self) -> io::Result<FileType> {
        Ok(FileType(self.0.file_type))
    }
    pub fn metadata(&self) -> io::Result<Metadata> {
        metadata(&self.0.path)
    }
}

pub struct ReadDir {
    entries: std::vec::IntoIter<RawDirEntry>,
}

impl Iterator for ReadDir {
    type Item = io::Result<DirEntry>;
    fn next(&mut self) -> Option<Self::Item> {
        self.entries.next().map(|e| Ok(DirEntry(e)))
    }
}

pub fn read_dir(path: impl AsRef<Path>) -> io::Result<ReadDir> {
    Ok(ReadDir {
        entries: current().read_dir(path.as_ref())?.into_iter(),
    })
}

/// `std::fs::File::create` equivalent.
pub fn create(path: impl AsRef<Path>) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path.as_ref())
}

/// `std::fs::File::open` equivalent.
pub fn open(path: impl AsRef<Path>) -> io::Result<File> {
    OpenOptions::new().read(true).open(path.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `members = ["crates/*"]` resolves inside the fetched tree — the VFS —
    /// never the real FS, and a `*` segment cannot cross `/` (an upstream
    /// `glob` iterator never would).
    #[test]
    fn glob_matches_member_dirs_in_memory_vfs() {
        let vfs = Rc::new(MemoryVfs::new());
        set_vfs(vfs.clone());
        vfs.insert("/ws/Cargo.toml", b"");
        vfs.insert("/ws/crates/alpha/Cargo.toml", b"");
        vfs.insert("/ws/crates/alpha/src/lib.rs", b"");
        vfs.insert("/ws/crates/beta/Cargo.toml", b"");
        vfs.insert("/ws/README.md", b"");

        let mut found = glob(Path::new("/ws/crates/*")).unwrap();
        found.sort();
        assert_eq!(
            found,
            [
                PathBuf::from("/ws/crates/alpha"),
                PathBuf::from("/ws/crates/beta"),
            ]
        );

        // A missing literal prefix matches nothing rather than erroring.
        assert!(glob(Path::new("/ws/nope/*")).unwrap().is_empty());

        // `members = ["./crates/*"]` — `.` is inert on a real filesystem
        // and must be inert in the pattern too.
        let mut found_dot = glob(Path::new("/ws/./crates/*")).unwrap();
        found_dot.sort();
        assert_eq!(found_dot, found);
    }
}
