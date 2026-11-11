//! The environment every integration test's `stow-cli` invocation shares.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The environment a hermetic `stow-cli` invocation needs: `edge_url` as
/// both the edge and the OCI registry root (no path: the registry
/// client rejects a base URL carrying one, stow#1032) — without the second the CLI
/// reaches the real registry, and once the public index covers a
/// fixture's crates an "all-miss" build is no longer one (stow#608) — an
/// isolated cache dir, a `home` the child's home directories all point
/// at, and loopback's proxy exclusions.
#[allow(
    dead_code,
    reason = "each test crate compiles this module whole; only some call it"
)]
pub fn hermetic_stow_env(command: &mut Command, edge_url: &str, cache_dir: &Path, home: &Path) {
    sealed_home_env(command, home);
    command
        .env("STOW_EDGE_URL", edge_url)
        .env("STOW_REGISTRY_BASE_URL", edge_url)
        .env("STOW_CACHE_DIR", cache_dir)
        // Isolate from the developer's ambient stow config: a user-level
        // `verify_mode = "mock-key"` (or an inherited `STOW_CONFIG_BLOB`)
        // would make this binary reject the config and skip the cache.
        // Every other `STOW_*` knob `StowConfig::load` and the wrapper
        // environment read is removed for the same reason — the test's
        // own values go on the command after this call (stow#800).
        .env("STOW_VERIFY_MODE", "github-ci")
        .env_remove("STOW_CONFIG_BLOB")
        .env_remove("STOW_INDEX_REFRESH_SECS")
        .env_remove("STOW_ARTIFACT_CACHE_MAX_BYTES")
        .env_remove("STOW_MOCK_PUBLIC_KEY_PATH")
        .env_remove("STOW_ENABLE_SEMANTIC_FALLBACK")
        .env_remove("STOW_PUBLIC_CACHE_RUSTC_VERSION")
        .env_remove("STOW_PUBLIC_CACHE_TARGET")
        .env_remove("STOW_CACHE_POLICY_PATH")
        .env_remove("STOW_EXPANDED_GRAPH_PATH")
        .env_remove("STOW_PREFETCH_ARTIFACTS_PATH")
        .env_remove("STOW_SESSION")
        .env_remove("STOW_TRACE_FILE")
        .env_remove("STOW_TRACE_WRAPPED_COMPILERS")
        .env_remove("STOW_IDENTITY_TRACE")
        .env_remove("STOW_NO_ANALYTICS")
        .env_remove("STOW_REAL_CC")
        .env_remove("STOW_REAL_CXX")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost");
}

/// The OCI `DENIED` envelope GHCR answers the anonymous token exchange
/// with for a package that does not exist — what `ensure_slice` resolves
/// to the empty index (stow#844).
#[allow(
    dead_code,
    reason = "each test crate compiles this module whole; only some call it"
)]
const DENIED_BODY: &str =
    r#"{"errors":[{"code":"DENIED","message":"requested access to the resource is denied"}]}"#;

/// A registry that reports every package missing: `/v2` requests get the
/// bearer challenge and the token exchange answers `DENIED`, the shape
/// the slice fetch resolves to the empty index with no signature to
/// verify (stow#844). `stow setup` fetches the host slice since
/// stow#1032, so every setup in a test needs an answer like this —
/// a refused port fails the fetch and the command with it.
///
/// Returns the server's base URL; use it where an edge URL is expected —
/// `hermetic_stow_env` derives `STOW_REGISTRY_BASE_URL` from it.
#[allow(
    dead_code,
    reason = "each test crate compiles this module whole; only some call it"
)]
pub fn denied_registry() -> String {
    use std::io::Write as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    let realm = url.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.ends_with(b"\r\n\r\n") {
                let read = std::io::Read::read(&mut stream, &mut buffer).unwrap_or(0);
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            let path = request
                .split(|byte| *byte == b' ')
                .nth(1)
                .unwrap_or_default();
            // `/v2` may sit under the registry base URL's path prefix
            // (`{base}/v2/…`): match it wherever it lands. `/token`
            // and everything else take the DENIED answer.
            if path.windows(3).any(|window| window == b"/v2") {
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"{realm}/token\",service=\"mock\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                );
            } else {
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{DENIED_BODY}",
                        DENIED_BODY.len()
                    )
                    .as_bytes(),
                );
            }
        }
    });
    url
}

/// The home a hermetic child process gets: `HOME` and the platform's
/// per-user config/data/cache variables all point under `home`, so
/// `~/.stow`, the user-level stow config, `~/.gitconfig` and
/// `~/.cargo/config.toml` (when `CARGO_HOME` is unset) can never leak in
/// from the developer's machine. `RUSTUP_HOME` still names the real
/// toolchains — a rustup shim under a redirected `HOME` would resolve
/// none. Compiler-hijack variables a developer might export are
/// cleared; a test that needs one sets it after this call.
///
/// Every directory a variable names exists before the child runs: on
/// Windows `dirs` resolves the config and local-data dirs through
/// `SHGetKnownFolderPath` without `KF_FLAG_DONT_VERIFY`, which fails on a
/// folder that does not exist, and stow then skips its config entirely.
#[allow(
    dead_code,
    reason = "each test crate compiles this module whole; only some call it"
)]
pub fn sealed_home_env(command: &mut Command, home: &Path) {
    let dirs = [
        ("HOME", home.to_path_buf()),
        ("USERPROFILE", home.to_path_buf()),
        ("XDG_CONFIG_HOME", home.join(".config")),
        ("XDG_DATA_HOME", home.join(".local").join("share")),
        ("XDG_CACHE_HOME", home.join(".cache")),
        ("APPDATA", home.join("AppData").join("Roaming")),
        ("LOCALAPPDATA", home.join("AppData").join("Local")),
    ];
    for (key, dir) in dirs {
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|error| panic!("create {key} dir {}: {error}", dir.display()));
        command.env(key, dir);
    }
    command
        // Every build starts the user's daemon when none is running: this
        // test's own runs under its home, where [`PrivateDaemon`] finds and
        // stops it.
        .env("STOW_DAEMON_DIR", PrivateDaemon::run_dir_of(home))
        // `stow setup` installs the daemon's login trigger through
        // `launchctl` on macOS (stow#1435); a test must never reach the
        // developer's launchd. `true` answers every query as "loaded", so
        // setup runs the code path and changes nothing.
        .env("STOW_LAUNCHCTL", "/usr/bin/true")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("CC")
        .env_remove("CXX");
    if let Some(rustup_home) = real_rustup_home() {
        command.env("RUSTUP_HOME", rustup_home);
    }
}

/// The toolchain home the machine's rustup shims resolve: `RUSTUP_HOME`
/// when the developer exports it, else `~/.rustup` under the real home —
/// resolved before `sealed_home_env` redirects `HOME` on the child.
#[allow(
    dead_code,
    reason = "each test crate compiles this module whole; only some call it"
)]
fn real_rustup_home() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("RUSTUP_HOME") {
        return Some(PathBuf::from(home));
    }
    let key = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(key).map(|home| PathBuf::from(home).join(".rustup"))
}

/// Write the stow global config under each of `homes`: the directory the
/// platform's config dir resolves to for a child whose home is sealed there
/// (`$XDG_CONFIG_HOME` on Linux, `Library/Application Support` on macOS,
/// `AppData/Roaming` on Windows). Every spelling is written, since a test
/// cannot tell which home the child will resolve against.
#[allow(
    dead_code,
    reason = "each test crate compiles this module whole; only some call it"
)]
pub fn write_global_config(homes: &[&Path], contents: &str) {
    for home in homes {
        for config_dir in [
            home.join(".config"),
            home.join("Library").join("Application Support"),
            home.join("AppData").join("Roaming"),
        ] {
            let dir = config_dir.join("stow");
            std::fs::create_dir_all(&dir)
                .unwrap_or_else(|error| panic!("create {}: {error}", dir.display()));
            std::fs::write(dir.join("config.toml"), contents).unwrap_or_else(|error| {
                panic!("write the stow config in {}: {error}", dir.display())
            });
        }
    }
}

/// The daemon a test's `stow-cli` runs started under `home`
/// ([`sealed_home_env`] points `STOW_DAEMON_DIR` there): found by the pids
/// its own log names, and stopped when this drops, so a test never leaves
/// a daemon behind and never touches one it did not start.
#[allow(
    dead_code,
    reason = "each test crate compiles this module whole; only some call it"
)]
pub struct PrivateDaemon {
    run_dir: PathBuf,
}

#[allow(
    dead_code,
    reason = "each test crate compiles this module whole; only some call it"
)]
impl PrivateDaemon {
    /// The runtime directory [`sealed_home_env`] names for `home`.
    pub fn run_dir_of(home: &Path) -> PathBuf {
        home.join("run")
    }

    /// The daemon of a child whose home is `home`.
    pub fn in_home(home: &Path) -> Self {
        Self {
            run_dir: Self::run_dir_of(home),
        }
    }

    pub fn run_dir(&self) -> &Path {
        &self.run_dir
    }

    /// The daemon log's lines that contain `needle`.
    pub fn log_lines(&self, needle: &str) -> Vec<String> {
        std::fs::read_to_string(self.run_dir.join("daemon.log"))
            .unwrap_or_default()
            .lines()
            .filter(|line| line.contains(needle))
            .map(str::to_owned)
            .collect()
    }

    /// The pids of the daemons that bound the endpoint, from their log.
    pub fn serving_pids(&self) -> Vec<u32> {
        self.log_lines("stow daemon serving")
            .iter()
            .filter_map(|line| {
                let rest = line.split("pid=").nth(1)?;
                rest.split_whitespace().next()?.parse().ok()
            })
            .collect()
    }

    /// Stop every daemon the log names and wait until they are gone.
    pub fn stop(&self) {
        for pid in self.serving_pids() {
            terminate(pid);
        }
    }

    /// End every daemon the log names with no chance to clean up, as a
    /// crash would.
    pub fn crash(&self) {
        for pid in self.serving_pids() {
            kill_hard(pid);
        }
    }
}

impl Drop for PrivateDaemon {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(unix)]
fn terminate(pid: u32) {
    let pid = libc::pid_t::try_from(pid).expect("a logged pid fits pid_t");
    // SAFETY: signalling a pid this test's own daemon logged.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    // SAFETY: signal 0 only probes.
    while unsafe { libc::kill(pid, 0) } == 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[cfg(unix)]
fn kill_hard(pid: u32) {
    let pid = libc::pid_t::try_from(pid).expect("a logged pid fits pid_t");
    // SAFETY: signalling a pid this test's own daemon logged.
    unsafe { libc::kill(pid, libc::SIGKILL) };
}

#[cfg(windows)]
fn terminate(pid: u32) {
    kill_hard(pid);
}

/// Windows ends a process only by force.
#[cfg(windows)]
fn kill_hard(pid: u32) {
    let _ = Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .output();
}

/// A temporary directory a test's children use as (or under) their home:
/// it stops the daemons they started before the directory goes, so no test
/// leaves one running.
#[allow(
    dead_code,
    reason = "each test crate compiles this module whole; only some call it"
)]
pub struct TempDir(tempfile::TempDir);

/// [`tempfile::tempdir`] with the daemon reaping of [`TempDir`].
#[allow(
    dead_code,
    reason = "each test crate compiles this module whole; only some call it"
)]
pub fn tempdir() -> std::io::Result<TempDir> {
    tempfile::tempdir().map(TempDir)
}

impl std::ops::Deref for TempDir {
    type Target = tempfile::TempDir;

    fn deref(&self) -> &tempfile::TempDir {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // A test seals its child's home as the directory itself, as
        // `stow-home` under it, or as `stow-home` under one of its project
        // directories.
        let root = self.0.path();
        let mut homes = vec![root.to_path_buf(), root.join("stow-home")];
        for entry in std::fs::read_dir(root).into_iter().flatten().flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                homes.push(entry.path().join("stow-home"));
            }
        }
        for home in homes {
            drop(PrivateDaemon::in_home(&home));
        }
    }
}
