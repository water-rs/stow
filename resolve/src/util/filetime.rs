//! `filetime::FileTime` carried as a local type.
//!
//! The `filetime` crate cannot compile on `wasm32-unknown-unknown` (it wraps
//! libc/Win32 calls to set file times). `FileTime` itself is a pure
//! seconds-plus-nanoseconds value, so it is ported verbatim here; the setters
//! go through the [`Vfs`](crate::util::fs::Vfs) so `MemoryVfs` records them
//! and `OsVfs` delegates to the real `filetime` calls on hosts.

use std::io;
use std::path::Path;
use std::time::SystemTime;

use super::fs;

/// A file timestamp, matching `filetime::FileTime`'s representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileTime {
    seconds: i64,
    nanoseconds: u32,
}

impl std::fmt::Display for FileTime {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{:09}s", self.seconds, self.nanoseconds)
    }
}

impl FileTime {
    /// The `filetime::FileTime::zero` constructor.
    pub fn zero() -> FileTime {
        FileTime {
            seconds: 0,
            nanoseconds: 0,
        }
    }

    /// The `filetime::FileTime::from_unix_time` constructor.
    pub fn from_unix_time(seconds: i64, nanoseconds: i64) -> FileTime {
        FileTime {
            seconds: seconds + nanoseconds.div_euclid(1_000_000_000),
            nanoseconds: nanoseconds.rem_euclid(1_000_000_000) as u32,
        }
    }

    /// The `filetime::FileTime::from_system_time` constructor.
    pub fn from_system_time(t: SystemTime) -> FileTime {
        match t.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => FileTime::from_unix_time(d.as_secs() as i64, d.subsec_nanos() as i64),
            Err(e) => {
                let d = e.duration();
                FileTime::from_unix_time(-(d.as_secs() as i64), -(d.subsec_nanos() as i64))
            }
        }
    }

    /// The `filetime::FileTime::from_last_modification_time` constructor.
    /// Takes a real `std::fs::Metadata`; only ever reached on host paths,
    /// since nothing on wasm can produce a real `Metadata`.
    pub fn from_last_modification_time(meta: &std::fs::Metadata) -> FileTime {
        FileTime::from_system_time(meta.modified().unwrap_or(SystemTime::UNIX_EPOCH))
    }

    /// The `filetime::FileTime::from_creation_time` constructor.
    pub fn from_creation_time(meta: &std::fs::Metadata) -> FileTime {
        FileTime::from_system_time(meta.created().unwrap_or(SystemTime::UNIX_EPOCH))
    }

    /// The `filetime::FileTime::seconds_relative_to_1970` accessor.
    pub fn seconds_relative_to_1970(&self) -> i64 {
        self.seconds
    }

    /// The `filetime::FileTime::nanoseconds` accessor.
    pub fn nanoseconds(&self) -> i64 {
        self.nanoseconds as i64
    }

    fn to_system_time(self) -> SystemTime {
        if self.seconds >= 0 {
            SystemTime::UNIX_EPOCH + std::time::Duration::new(self.seconds as u64, self.nanoseconds)
        } else {
            SystemTime::UNIX_EPOCH
                - std::time::Duration::new((-self.seconds) as u64, self.nanoseconds)
        }
    }
}

/// `filetime::set_file_mtime`, routed through the VFS.
pub fn set_file_mtime(path: &Path, mtime: FileTime) -> io::Result<()> {
    fs::current().set_mtime(path, mtime.to_system_time())
}
