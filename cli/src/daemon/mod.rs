//! The per-user stow daemon: one long-running process per user, started
//! by whichever client needs it first (stow#1435).
//!
//! * [`serve`] is the daemon: it takes `daemon.lock` in the runtime
//!   directory, binds its endpoint there, reports readiness and answers
//!   [`protocol`] requests. A build is a [`session`] of it: the driver
//!   opens one over a control connection ([`client::DaemonSession`]) and
//!   the build's wrappers name it by id ([`client::WrapperConnection`]);
//!   a wrapper in a sandbox reaches the daemon through the driver's
//!   [`relay`].
//! * [`start`] is the one path every client uses to reach it: connect,
//!   else take `start.lock`, spawn the daemon detached, wait for its
//!   readiness notification, connect. It is synchronous and std-only —
//!   no runtime, no configuration — because the clients it serves run
//!   hundreds of times per build.
//! * [`launch_agent`] is the macOS login trigger `stow setup` installs.
//!   Nothing else touches the service manager.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use stow_types::error::{Context, Result};

use crate::cli_args::{DaemonArgs, DaemonCommand};
use crate::write_stdout;

pub mod client;
#[cfg(unix)]
mod descriptors;
pub mod events;
#[cfg(target_os = "macos")]
pub mod launch_agent;
mod log;
mod notify;
pub mod protocol;
pub mod relay;
mod serve;
pub mod session;
mod start;
mod table;
#[cfg(windows)]
mod windows;

pub use start::connect_or_start;

/// Overrides the runtime directory.
pub const STOW_DAEMON_DIR_ENV: &str = "STOW_DAEMON_DIR";
/// How long a connected daemon may take to answer, in seconds.
const STOW_DAEMON_ANSWER_SECS_ENV: &str = "STOW_DAEMON_ANSWER_SECS";
/// How long a client waits for the daemon it started, in seconds.
const STOW_DAEMON_START_SECS_ENV: &str = "STOW_DAEMON_START_SECS";

/// A live daemon answers a `Hello` in milliseconds, so this bound only
/// separates a wedged daemon from a slow machine: long enough that a
/// heavily loaded build host never trips it, short enough that a wedged
/// daemon fails the build instead of stalling it.
const DEFAULT_ANSWER_SECS: u64 = 10;
/// A cold start maps a large binary, binds the endpoint and answers: well
/// under a second normally. Thirty seconds covers the same binary paged in
/// from a cold disk on a host whose cores cargo's jobs already saturate.
const DEFAULT_START_SECS: u64 = 30;
/// A daemon logs a few lines per start and per refused connection, so
/// 8 MiB is weeks of history; with the one predecessor the log is bounded
/// at 16 MiB, small beside the cache the daemon sits next to.
const DEFAULT_LOG_BYTES: u64 = 8 * 1024 * 1024;
/// The size at which the daemon rotates its log, in bytes.
const STOW_DAEMON_LOG_BYTES_ENV: &str = "STOW_DAEMON_LOG_BYTES";

/// The bounds the client path works within.
///
/// Read from the environment alone: the client path runs before and
/// without the stow configuration, so a config-file key would cost every
/// invocation a file read and parse this path exists to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// How long a connected daemon may take to answer.
    pub answer: Duration,
    /// How long a client waits for the daemon it started.
    pub start: Duration,
    /// The size at which the daemon rotates its log.
    pub log_bytes: u64,
}

impl Settings {
    /// The settings the process environment names.
    ///
    /// # Errors
    ///
    /// A variable is set but is not a positive whole number of seconds.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let positive = |key: &str, default: u64| -> Result<u64> {
            let Some(raw) = lookup(key) else {
                return Ok(default);
            };
            match raw.parse::<u64>() {
                Ok(0) | Err(_) => Err(stow_types::stow_error!(
                    "{key} must be a positive whole number, not `{raw}`"
                )),
                Ok(value) => Ok(value),
            }
        };
        Ok(Self {
            answer: Duration::from_secs(positive(
                STOW_DAEMON_ANSWER_SECS_ENV,
                DEFAULT_ANSWER_SECS,
            )?),
            start: Duration::from_secs(positive(STOW_DAEMON_START_SECS_ENV, DEFAULT_START_SECS)?),
            log_bytes: positive(STOW_DAEMON_LOG_BYTES_ENV, DEFAULT_LOG_BYTES)?,
        })
    }
}

/// The runtime directory: owner-only, holding the locks, the endpoint and
/// the log of one user's daemon.
#[derive(Debug, Clone)]
pub struct RunDir(PathBuf);

impl RunDir {
    /// Where this user's runtime directory is: `STOW_DAEMON_DIR`, else
    /// `stow/run` under the platform's per-user cache directory.
    ///
    /// # Errors
    ///
    /// The override is empty or relative, or the platform has no cache
    /// directory.
    pub fn locate() -> Result<PathBuf> {
        Self::locate_with(std::env::var_os(STOW_DAEMON_DIR_ENV), dirs::cache_dir())
    }

    fn locate_with(over: Option<OsString>, cache_dir: Option<PathBuf>) -> Result<PathBuf> {
        if let Some(value) = over {
            let path = PathBuf::from(value);
            // The daemon runs in this directory, so a relative path would
            // name a different place for it than for its starter.
            if !path.is_absolute() {
                return Err(stow_types::stow_error!(
                    "{STOW_DAEMON_DIR_ENV} must be an absolute path, not `{}`",
                    path.display()
                ));
            }
            return Ok(path);
        }
        cache_dir
            .map(|dir| dir.join("stow").join("run"))
            .ok_or_else(|| stow_types::stow_error!("resolve the daemon runtime directory"))
    }

    /// Create `path` owner-only if it is missing and check what is there.
    ///
    /// # Errors
    ///
    /// The directory cannot be created, is not a directory, belongs to
    /// someone else, or is accessible to anyone but its owner (Unix).
    pub fn prepare(path: PathBuf) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&path)
                .wrap_err_with(|| {
                    format!("create the daemon runtime directory {}", path.display())
                })?;
            let metadata = std::fs::symlink_metadata(&path).wrap_err_with(|| {
                format!("inspect the daemon runtime directory {}", path.display())
            })?;
            if !metadata.is_dir() {
                return Err(stow_types::stow_error!(
                    "the daemon runtime directory {} is not a directory",
                    path.display()
                ));
            }
            // SAFETY: `geteuid` has no preconditions and cannot fail.
            if metadata.uid() != unsafe { libc::geteuid() } {
                return Err(stow_types::stow_error!(
                    "the daemon runtime directory {} belongs to another user",
                    path.display()
                ));
            }
            if metadata.mode() & 0o077 != 0 {
                return Err(stow_types::stow_error!(
                    "the daemon runtime directory {} has mode {:o}; it must be accessible to its owner only",
                    path.display(),
                    metadata.mode() & 0o777
                ));
            }
        }
        #[cfg(windows)]
        {
            // The per-user cache directory's inherited ACL already limits
            // it to its owner; there is no mode to check.
            std::fs::create_dir_all(&path).wrap_err_with(|| {
                format!("create the daemon runtime directory {}", path.display())
            })?;
        }
        Ok(Self(path))
    }

    /// The directory itself.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// The lock a running daemon holds.
    #[must_use]
    pub fn daemon_lock(&self) -> PathBuf {
        self.0.join("daemon.lock")
    }

    /// The lock that serializes client starts.
    #[must_use]
    pub fn start_lock(&self) -> PathBuf {
        self.0.join("start.lock")
    }

    /// The daemon's log.
    #[must_use]
    pub fn log(&self) -> PathBuf {
        self.0.join("daemon.log")
    }

    /// The directory holding one subdirectory per open session.
    #[must_use]
    pub fn sessions(&self) -> PathBuf {
        self.0.join("sessions")
    }

    /// Where clients reach the daemon: a Unix socket in the directory, or
    /// on Windows a named pipe named after it, since pipes live in one
    /// machine-wide namespace.
    #[must_use]
    pub fn endpoint(&self) -> PathBuf {
        #[cfg(unix)]
        {
            self.0.join("daemon.sock")
        }
        #[cfg(windows)]
        {
            let digest = blake3::hash(self.0.as_os_str().as_encoded_bytes()).to_hex();
            // Thirty-two hex digits are 128 bits: distinct directories
            // never share a pipe.
            PathBuf::from(format!(r"\\.\pipe\stow-daemon-{}", &digest[..32]))
        }
    }

    /// Where a starting client listens for the daemon's readiness
    /// notification. Only the holder of `start.lock` uses it.
    #[cfg(unix)]
    fn notify_endpoint(&self) -> PathBuf {
        self.0.join("ready.sock")
    }
}

/// Whether `args` run the daemon itself — `stow daemon` — rather than a
/// client of it.
#[must_use]
pub fn is_serving(args: &[OsString]) -> bool {
    args.get(1).is_some_and(|word| word == "daemon")
        && args.get(2).is_none_or(|word| word != "status")
}

/// Make this process the daemon's: close every inherited descriptor above
/// stderr and make everything it creates owner-only (Unix). Called before
/// anything else in the process opens a descriptor.
///
/// # Errors
///
/// The open descriptors cannot be enumerated.
pub fn prepare_process() -> Result<()> {
    #[cfg(unix)]
    {
        let inherited = descriptors::open_from(descriptors::FIRST_INHERITED)
            .wrap_err("list the inherited descriptors")?;
        descriptors::close(&inherited);
        // SAFETY: `umask` has no preconditions and cannot fail.
        unsafe { libc::umask(0o077) };
    }
    Ok(())
}

/// `stow daemon`: serve, or with `status` report the running daemon.
///
/// # Errors
///
/// The daemon cannot start or serve, or the daemon asked about does not
/// answer.
pub async fn run(args: DaemonArgs) -> Result<()> {
    match args.command {
        Some(DaemonCommand::Status) => status().await,
        None => serve::run(args.ready).await,
    }
}

/// `stow daemon status`: reach the daemon through the start path and
/// print what it reports.
async fn status() -> Result<()> {
    let reply = tokio::task::spawn_blocking(|| {
        let exe = std::env::current_exe().wrap_err("resolve the current executable")?;
        let settings = Settings::from_env()?;
        connect_or_start(&exe, settings)?.status()
    })
    .await
    .wrap_err("run the daemon status client")??;
    write_stdout(&format!(
        "version: {}\nprotocol: {}\n",
        reply.stow_version, reply.protocol
    ))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{RunDir, Settings, is_serving};

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn settings_default_and_parse() {
        let defaults = Settings::from_lookup(lookup(&[])).expect("defaults");
        assert_eq!(defaults.answer, Duration::from_secs(10));
        assert_eq!(defaults.start, Duration::from_secs(30));
        assert_eq!(defaults.log_bytes, 8 * 1024 * 1024);
        let sized =
            Settings::from_lookup(lookup(&[("STOW_DAEMON_LOG_BYTES", "4096")])).expect("sized");
        assert_eq!(sized.log_bytes, 4096);
        let set = Settings::from_lookup(lookup(&[
            ("STOW_DAEMON_ANSWER_SECS", "3"),
            ("STOW_DAEMON_START_SECS", "7"),
        ]))
        .expect("set");
        assert_eq!(set.answer, Duration::from_secs(3));
        assert_eq!(set.start, Duration::from_secs(7));
    }

    #[test]
    fn a_malformed_or_zero_bound_is_an_error() {
        for bad in ["0", "soon", "-1", ""] {
            assert!(
                Settings::from_lookup(lookup(&[("STOW_DAEMON_START_SECS", bad)])).is_err()
                    && Settings::from_lookup(lookup(&[("STOW_DAEMON_LOG_BYTES", bad)])).is_err(),
                "`{bad}` must be refused"
            );
        }
    }

    #[test]
    fn the_runtime_directory_is_the_override_or_the_cache_dir() {
        let cache = Some(PathBuf::from("/cache"));
        assert_eq!(
            RunDir::locate_with(None, cache.clone()).expect("default"),
            PathBuf::from("/cache/stow/run")
        );
        #[cfg(unix)]
        assert_eq!(
            RunDir::locate_with(Some(OsString::from("/over")), cache.clone()).expect("override"),
            PathBuf::from("/over")
        );
        assert!(RunDir::locate_with(Some(OsString::from("relative")), cache).is_err());
        assert!(RunDir::locate_with(None, None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_runtime_directory_open_to_others_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let parent = tempfile::tempdir().expect("tempdir");
        let path = parent.path().join("run");
        RunDir::prepare(path.clone()).expect("created owner-only");
        assert_eq!(
            std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o750)).expect("chmod");
        let error = RunDir::prepare(path).expect_err("group access is refused");
        assert!(error.to_string().contains("owner"), "{error}");
    }

    #[test]
    fn only_the_bare_daemon_command_serves() {
        let args = |parts: &[&str]| parts.iter().map(OsString::from).collect::<Vec<_>>();
        assert!(is_serving(&args(&["stow", "daemon"])));
        assert!(is_serving(&args(&["stow", "daemon", "--ready", "x"])));
        assert!(!is_serving(&args(&["stow", "daemon", "status"])));
        assert!(!is_serving(&args(&["stow", "status"])));
        assert!(!is_serving(&args(&["stow"])));
    }
}
