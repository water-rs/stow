//! The `util` hub: re-exports shared by every vendored module.
//!
//! Layout mirrors `cargo::util` — each vendored file lives in the same
//! relative module path, plus the adaptation shims (`fs`, `process`, `shell`,
//! `network`, `context`, `global_cache_tracker`, `progress`, `rand`,
//! `timer`).

pub mod cache_lock;
pub mod canonical_url;
pub mod context;
pub mod counter;
pub mod edit_distance;
pub mod env;
pub mod errors;
pub mod filetime;
pub mod flock;
pub mod frontmatter;
pub mod fs;
pub mod graph;
pub mod hasher;
pub mod hex;
pub mod important_paths;
pub mod interning;
pub mod into_url;
pub mod into_url_with_base;
pub mod io;
pub mod local_poll_adapter;
pub mod network;
pub mod once;
pub mod paths;
pub mod progress;
pub mod rand;
pub mod registry;
pub mod report;
pub mod restricted_names;
pub mod rustc;
pub mod semver_eval_ext;
pub mod semver_ext;
pub mod sha256;
pub mod shell;
pub mod style;
pub mod time;
pub mod time_span;
pub mod timer;
pub mod toml;
pub mod urls;

pub use self::canonical_url::CanonicalUrl;
pub use self::context::{ConfigValue, GlobalContext};
pub use self::counter::MetricsCounter;
pub use self::edit_distance::{closest, closest_msg, edit_distance};
pub use self::errors::CliError;
pub use self::errors::{CargoResult, CliResult, internal};
pub use self::flock::{FileLock, Filesystem};
pub use self::graph::Graph;
pub use self::hasher::StableHasher;
pub use self::hex::{hash_u64, short_hash, to_hex};
pub use self::into_url::IntoUrl;
pub use self::into_url_with_base::IntoUrlWithBase;
pub use self::io::LimitErrorReader;
pub use self::local_poll_adapter::LocalPollAdapter;
pub use self::once::OnceExt;
pub use self::progress::{Progress, ProgressStyle};
pub use self::rustc::Rustc;
pub use self::semver_ext::{OptVersionReq, VersionExt};
pub use self::shell::Shell;

use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

/// Whether or not this is running in a Continuous Integration environment.
///
/// Mirrors `cargo_util::is_ci` verbatim.
pub fn is_ci() -> bool {
    env::var("CI").is_ok() || env::var("TF_BUILD").is_ok()
}

/// Formats a number of bytes into a human readable SI-prefixed size.
pub struct HumanBytes(pub u64);

impl std::fmt::Display for HumanBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
        let bytes = self.0 as f32;
        let i = ((bytes.log2() / 10.0) as usize).min(UNITS.len() - 1);
        let unit = UNITS[i];
        let size = bytes / 1024_f32.powi(i as i32);

        // Don't show a fractional number of bytes.
        if i == 0 {
            return write!(f, "{size}{unit}");
        }

        let Some(precision) = f.precision() else {
            return write!(f, "{size}{unit}");
        };
        write!(f, "{size:.precision$}{unit}",)
    }
}

pub fn indented_lines(text: &str) -> String {
    text.lines()
        .map(|line| {
            if line.is_empty() {
                String::from("\n")
            } else {
                format!("  {}\n", line)
            }
        })
        .collect()
}

pub fn truncate_with_ellipsis(s: &str, max_width: usize) -> String {
    // We should truncate at grapheme-boundary and compute character-widths,
    // yet the dependencies on unicode-segmentation and unicode-width are
    // not worth it.
    let mut chars = s.chars();
    let mut prefix = (&mut chars).take(max_width - 1).collect::<String>();
    if chars.next().is_some() {
        prefix.push('…');
    }
    prefix
}

#[inline]
pub fn try_canonicalize<P: AsRef<Path>>(path: P) -> std::io::Result<PathBuf> {
    crate::util::fs::canonicalize(&path)
}

/// Get the current [`umask`] value.
///
/// [`umask`]: https://man7.org/linux/man-pages/man2/umask.2.html
#[cfg(unix)]
pub fn get_umask() -> u32 {
    use std::sync::OnceLock;
    static UMASK: OnceLock<libc::mode_t> = OnceLock::new();
    // SAFETY: Syscalls are unsafe. Calling `umask` twice is even unsafer for
    // multithreading program, since it doesn't provide a way to retrieve the
    // value without modifications. We use a static `OnceLock` here to ensure
    // it only gets call once during the entire program lifetime.
    // `mode_t` is u32 on Linux but u16 on macOS — widen for the u32
    // signature.
    *UMASK.get_or_init(|| unsafe {
        let umask = libc::umask(0o022);
        libc::umask(umask);
        umask
    }) as u32
}

#[cfg(not(unix))]
pub fn get_umask() -> u32 {
    // On Windows the default umask-equivalent permission is 0o666 for files.
    // wasm32-unknown-unknown has no filesystem umask either; tar extraction
    // through the VFS applies no permission bits, so 0 is the truthful value.
    0
}

pub fn elapsed(duration: Duration) -> String {
    let secs = duration.as_secs();

    if secs >= 60 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!("{}.{:02}s", secs, duration.subsec_nanos() / 10_000_000)
    }
}
