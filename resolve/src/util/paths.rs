//! Filesystem helpers ported from `cargo-util/src/paths.rs`, narrowed to the
//! surface the vendored resolver sources use and routed through
//! [`crate::util::fs`] (the VFS boundary) instead of `std::fs`.

use crate::util::filetime::FileTime;
use anyhow::{Context, Result, anyhow};
use std::env;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

use crate::util::fs::{self, File, Metadata};

/// Normalize the path by removing redundant components (except `..` when it
/// would escape the root — preserved like cargo does).
pub fn normalize_path(path: &Path) -> PathBuf {
    let mut components = path.components().peekable();
    let mut ret = if let Some(c @ Component::Prefix(..)) = components.peek().cloned() {
        components.next();
        PathBuf::from(c.as_os_str())
    } else {
        PathBuf::new()
    };

    for component in components {
        match component {
            Component::Prefix(..) => unreachable!(),
            Component::RootDir => {
                ret.push(Component::RootDir);
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if ret.ends_with(Component::ParentDir) {
                    ret.push(Component::ParentDir);
                } else {
                    let popped = ret.pop();
                    if !popped && !ret.has_root() {
                        ret.push(Component::ParentDir);
                    }
                }
            }
            Component::Normal(c) => {
                ret.push(c);
            }
        }
    }
    ret
}

/// Returns the absolute path of where the given executable is located based
/// on searching the `PATH` environment variable.
///
/// Returns an error if it cannot be found.
pub fn resolve_executable(exec: &Path) -> Result<PathBuf> {
    if exec.components().count() == 1 {
        let paths = crate::util::env::var_os("PATH").ok_or_else(|| anyhow!("no PATH"))?;
        let candidates = env::split_paths(&paths).flat_map(|path| {
            [
                path.join(exec),
                path.join(format!("{}.exe", exec.display())),
            ]
        });
        for candidate in candidates {
            if fs::metadata(&candidate).is_ok() {
                return Ok(candidate);
            }
        }
        Err(anyhow!(
            "no executable for `{}` found in PATH",
            exec.display()
        ))
    } else if fs::metadata(exec).is_ok() {
        Ok(exec.to_path_buf())
    } else {
        Err(anyhow!("`{}` is not a file", exec.display()))
    }
}

/// Equivalent to [`std::fs::metadata`] with better error messages.
pub fn metadata<P: AsRef<Path>>(path: P) -> Result<Metadata> {
    let path = path.as_ref();
    fs::metadata(path)
        .with_context(|| format!("failed to load metadata for path `{}`", path.display()))
}

/// Equivalent to [`std::fs::symlink_metadata`] with better error messages.
pub fn symlink_metadata<P: AsRef<Path>>(path: P) -> Result<Metadata> {
    let path = path.as_ref();
    fs::symlink_metadata(path)
        .with_context(|| format!("failed to load metadata for path `{}`", path.display()))
}

/// Reads a file to a string.
///
/// Equivalent to [`std::fs::read_to_string`] with better error messages.
pub fn read(path: &Path) -> Result<String> {
    match String::from_utf8(read_bytes(path)?) {
        Ok(s) => Ok(s),
        Err(_) => anyhow::bail!("path at `{}` was not valid utf-8", path.display()),
    }
}

/// Reads a file into a bytes vector.
///
/// Equivalent to [`std::fs::read`] with better error messages.
pub fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("failed to read `{}`", path.display()))
}

/// Writes a file to disk.
///
/// Equivalent to [`std::fs::write`] with better error messages.
pub fn write<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> Result<()> {
    let path = path.as_ref();
    fs::write(path, contents.as_ref())
        .with_context(|| format!("failed to write `{}`", path.display()))
}

/// Writes a file to disk atomically.
///
/// Over the VFS a single `write` is already atomic for our callers; the
/// temp-file dance is only needed for crash-atomicity on real disks.
pub fn write_atomic<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> Result<()> {
    write(path, contents)
}

/// Writes a file if the contents have changed.
pub fn write_if_changed<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> Result<()> {
    let path = path.as_ref();
    match fs::read(path) {
        Ok(current) if current == contents.as_ref() => return Ok(()),
        _ => {}
    }
    write(path, contents)
}

/// Appends contents to a file, creating it if it does not exist.
pub fn append(path: &Path, contents: &[u8]) -> Result<()> {
    let mut data = fs::read(path).unwrap_or_default();
    data.extend_from_slice(contents);
    fs::write(path, &data).with_context(|| format!("failed to write `{}`", path.display()))
}

/// Creates an empty file or truncates an existing one.
pub fn create<P: AsRef<Path>>(path: P) -> Result<File> {
    let path = path.as_ref();
    fs::create(path).with_context(|| format!("failed to create file `{}`", path.display()))
}

/// Opens an existing file.
pub fn open<P: AsRef<Path>>(path: P) -> Result<File> {
    let path = path.as_ref();
    fs::open(path).with_context(|| format!("failed to open file `{}`", path.display()))
}

/// Returns the last modification time of a file.
pub fn mtime(path: &Path) -> Result<FileTime> {
    let meta = metadata(path)?;
    let t = fs::current()
        .mtime(path)
        .with_context(|| format!("failed to get mtime of `{}`", path.display()))?;
    let _ = meta;
    Ok(FileTime::from_system_time(t))
}

/// Iterates over the ancestors of `path`, stopping when `stop_root_at` is hit.
pub fn ancestors<'a>(path: &'a Path, stop_root_at: Option<&Path>) -> PathAncestors<'a> {
    PathAncestors::new(path, stop_root_at)
}

pub struct PathAncestors<'a> {
    current: Option<&'a Path>,
    stop_at: Option<PathBuf>,
}

impl<'a> PathAncestors<'a> {
    fn new(path: &'a Path, stop_root_at: Option<&Path>) -> PathAncestors<'a> {
        let stop_at = crate::util::env::var("__CARGO_TEST_ROOT")
            .ok()
            .map(PathBuf::from)
            .or_else(|| stop_root_at.map(|p| p.to_path_buf()));
        PathAncestors {
            current: Some(path),
            stop_at,
        }
    }
}

impl<'a> Iterator for PathAncestors<'a> {
    type Item = &'a Path;

    fn next(&mut self) -> Option<&'a Path> {
        if let Some(path) = self.current {
            self.current = path.parent();

            if let Some(ref stop_at) = self.stop_at {
                if path == stop_at {
                    self.current = None;
                }
            }

            Some(path)
        } else {
            None
        }
    }
}

/// Equivalent to [`std::fs::create_dir_all`] with better error messages.
pub fn create_dir_all(p: impl AsRef<Path>) -> Result<()> {
    let p = p.as_ref();
    fs::create_dir_all(p).with_context(|| format!("failed to create directory `{}`", p.display()))
}

/// Equivalent to [`std::fs::remove_dir_all`] with better error messages.
pub fn remove_dir_all<P: AsRef<Path>>(p: P) -> Result<()> {
    let p = p.as_ref();
    fs::remove_dir_all(p).with_context(|| format!("failed to remove directory `{}`", p.display()))
}

/// Equivalent to [`std::fs::remove_dir`] with better error messages.
pub fn remove_dir<P: AsRef<Path>>(p: P) -> Result<()> {
    let p = p.as_ref();
    fs::remove_dir(p).with_context(|| format!("failed to remove directory `{}`", p.display()))
}

/// Equivalent to [`std::fs::remove_file`] with better error messages.
pub fn remove_file<P: AsRef<Path>>(p: P) -> Result<()> {
    let p = p.as_ref();
    fs::remove_file(p).with_context(|| format!("failed to remove file `{}`", p.display()))
}

/// Equivalent to [`std::fs::copy`] with better error messages.
pub fn copy<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> Result<u64> {
    let from = from.as_ref();
    let to = to.as_ref();
    let data = fs::read(from).with_context(|| format!("failed to read `{}`", from.display()))?;
    let len = data.len() as u64;
    fs::write(to, &data).with_context(|| format!("failed to write `{}`", to.display()))?;
    Ok(len)
}

/// `path.strip_prefix(base)` after canonicalizing both sides; on platforms or
/// filesystems where canonicalization is unsupported the uncanonicalized
/// path is used (same fallback cargo has).
pub fn strip_prefix_canonical(
    path: impl AsRef<Path>,
    base: impl AsRef<Path>,
) -> Result<PathBuf, std::path::StripPrefixError> {
    let safe_canonicalize = |path: &Path| match fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("cannot canonicalize {:?}: {:?}", path, e);
            path.to_path_buf()
        }
    };
    let canon_path = safe_canonicalize(path.as_ref());
    let canon_base = safe_canonicalize(base.as_ref());
    canon_path.strip_prefix(canon_base).map(|p| p.to_path_buf())
}

/// Marks a directory for exclusion from OS backup/indexing facilities.
///
/// The VFS has no OS-level backup or indexing integration, so this is a
/// documented no-op: the files it would affect live inside a resolve-local
/// tree that no OS service can see anyway.
pub fn exclude_from_backups_and_indexing(_p: impl AsRef<Path>) {}

/// `join_paths` from cargo-util: joins paths for an env var.
pub fn join_paths<T: AsRef<OsStr>>(paths: &[T], env: &str) -> Result<OsString> {
    let joined = env::join_paths(paths.iter().map(|p| PathBuf::from(p.as_ref())))?;
    let _ = env;
    Ok(joined)
}

/// Returns the name of the environment variable used for dynamic library
/// searches on this platform.
#[cfg(not(target_family = "wasm"))]
pub fn dylib_path_envvar() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "PATH"
    }
    #[cfg(target_os = "macos")]
    {
        "DYLD_FALLBACK_LIBRARY_PATH"
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        "LD_LIBRARY_PATH"
    }
}

/// Returns the dylib search path from the environment.
#[cfg(not(target_family = "wasm"))]
pub fn dylib_path() -> Vec<PathBuf> {
    crate::util::env::var_os(dylib_path_envvar())
        .map(|paths| env::split_paths(&paths).collect())
        .unwrap_or_default()
}
