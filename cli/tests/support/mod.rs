//! The environment every integration test's `stow-cli` invocation shares.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long a process's piped output may stay open once the process has
/// exited. Only a process it started can hold the pipes then, and none of
/// stow's may — a daemon or drain it starts detaches holding none of its
/// descriptors or handles — so the bound only has to outlast the last
/// bytes reaching the reader.
const OUTPUT_AFTER_EXIT_BOUND: Duration = Duration::from_mins(1);

/// Wait for `child`, whose stdout and stderr are piped, to exit, and
/// collect its output. Output that stays open past
/// [`OUTPUT_AFTER_EXIT_BOUND`] after the exit fails the test naming that,
/// instead of waiting for whatever process holds it: `what` names the
/// child.
#[allow(
    dead_code,
    reason = "each test crate compiles this module whole; only some call it"
)]
pub fn output_of(mut child: Child, what: &str) -> Output {
    let stdout = read_on_a_thread(child.stdout.take());
    let stderr = read_on_a_thread(child.stderr.take());
    let status = child
        .wait()
        .unwrap_or_else(|error| panic!("wait for {what}: {error}"));
    let deadline = Instant::now() + OUTPUT_AFTER_EXIT_BOUND;
    let collect = |stream: mpsc::Receiver<Vec<u8>>, name: &str| {
        stream
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(|_| {
                panic!(
                    "{what} exited ({status}) but its {name} stayed open for {} s after: a process it started holds it",
                    OUTPUT_AFTER_EXIT_BOUND.as_secs()
                )
            })
    };
    Output {
        status,
        stdout: collect(stdout, "stdout"),
        stderr: collect(stderr, "stderr"),
    }
}

/// Read `stream` to its end on a thread of its own; the bytes arrive on
/// the returned channel once every writer has closed it.
fn read_on_a_thread<R: Read + Send + 'static>(stream: Option<R>) -> mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut stream) = stream {
            stream
                .read_to_end(&mut bytes)
                .expect("read the child's output");
        }
        let _ = sender.send(bytes);
    });
    receiver
}

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
        // `verify_mode = "mock-key"` would make this binary reject the
        // config and skip the cache.
        // Every other `STOW_*` knob `StowConfig::load` and the wrapper
        // environment read is removed for the same reason — the test's
        // own values go on the command after this call (stow#800).
        .env("STOW_VERIFY_MODE", "github-ci")
        .env_remove("STOW_INDEX_REFRESH_SECS")
        .env_remove("STOW_ARTIFACT_CACHE_MAX_BYTES")
        .env_remove("STOW_MOCK_PUBLIC_KEY_PATH")
        .env_remove("STOW_PUBLIC_CACHE_RUSTC_VERSION")
        .env_remove("STOW_PUBLIC_CACHE_TARGET")
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

/// Longer than the daemon takes to notice an exited cargo and end its
/// session; a session that never ends fails the test here.
#[allow(
    dead_code,
    reason = "each test crate compiles this module whole; only some call it"
)]
const SESSION_END_LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

/// A command that runs the toolchain's own `cargo`, the one that built this
/// test. A test waits for the session of the cargo it started
/// ([`PrivateDaemon::wait_session_ended`]), which the daemon opens for the
/// process cargo names in `CARGO`. `cargo` found on `PATH` is rustup's proxy
/// on a machine with rustup; on Windows the proxy runs the real cargo as its
/// child instead of replacing itself, so the pid a test holds would not be
/// the cargo the daemon owns the session for.
#[allow(
    dead_code,
    reason = "each test crate compiles this module whole; only some call it"
)]
pub fn cargo_command() -> Command {
    Command::new(env!("CARGO"))
}

/// Run `command`, a plain `cargo` build through the stow wrappers, to its
/// end and collect its output; then wait until the daemon under `home` has
/// ended the session of that cargo ([`PrivateDaemon::wait_session_ended`]),
/// so the cache and the target directory hold everything the build left.
#[allow(
    dead_code,
    reason = "each test crate compiles this module whole; only some call it"
)]
pub fn output_after_session(command: &mut Command, home: &Path) -> std::process::Output {
    let child = command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start cargo");
    let pid = child.id();
    let output = child.wait_with_output().expect("wait for cargo");
    wait_session_ended_in(&PrivateDaemon::run_dir_of(home), pid);
    output
}

/// [`PrivateDaemon::wait_session_ended`] over the daemon log in `run_dir`.
fn wait_session_ended_in(run_dir: &Path, cargo_pid: u32) {
    // The daemon logs the owner as `pid <pid> started at tick <tick>`.
    let owner = format!("pid {cargo_pid} started");
    let logged = |message: &str| {
        log_lines_in(run_dir, message)
            .iter()
            .any(|line| line.contains(&owner))
    };
    if !logged("opened a session for a cargo") {
        return;
    }
    let deadline = std::time::Instant::now() + SESSION_END_LIMIT;
    while !logged("ended a cargo's session") {
        assert!(
            std::time::Instant::now() < deadline,
            "the daemon never ended the session of cargo {cargo_pid}:\n{}",
            log_lines_in(run_dir, "").join("\n")
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// The lines of the daemon log in `run_dir` that contain `needle`.
fn log_lines_in(run_dir: &Path, needle: &str) -> Vec<String> {
    std::fs::read_to_string(run_dir.join("daemon.log"))
        .unwrap_or_default()
        .lines()
        .filter(|line| line.contains(needle))
        .map(str::to_owned)
        .collect()
}

/// The daemon a test's `stow-cli` runs started under `home`
/// ([`sealed_home_env`] points `STOW_DAEMON_DIR` there): found by the pids
/// its own log names, and stopped when this drops, so a test never leaves
/// a daemon behind and never touches one it did not start.
///
/// On Windows a build starts the daemon only through the Task Scheduler,
/// so [`PrivateDaemon::in_home`] registers the task of the private run
/// directory, as `stow setup` does for the user's, and dropping it deletes
/// the task.
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

    /// The daemon of a child whose home is `home`; on Windows, with the
    /// task that starts it registered.
    ///
    /// # Panics
    ///
    /// On Windows, when the task cannot be registered.
    pub fn in_home(home: &Path) -> Self {
        let daemon = Self::at(Self::run_dir_of(home));
        #[cfg(windows)]
        stow_cli::scheduled_task::register(
            daemon.run_dir(),
            Path::new(env!("CARGO_BIN_EXE_stow-cli")),
        )
        .unwrap_or_else(|error| panic!("register the daemon's scheduled task: {error}"));
        daemon
    }

    /// The daemon that would run in `run_dir`, with nothing registered.
    const fn at(run_dir: PathBuf) -> Self {
        Self { run_dir }
    }

    pub fn run_dir(&self) -> &Path {
        &self.run_dir
    }

    /// The daemon log's lines that contain `needle`.
    pub fn log_lines(&self, needle: &str) -> Vec<String> {
        log_lines_in(&self.run_dir, needle)
    }

    /// Wait until the daemon has ended the session it opened for the cargo
    /// `cargo_pid`, if it opened one.
    ///
    /// A plain build's wrappers exit as soon as their compilers do; the
    /// session's bookkeeping — the stores, the records, the miss journal —
    /// completes when the daemon sees the cargo exit, so anything that reads
    /// the cache after the build waits for this first. A cargo that never
    /// ran a wrapper has no session, and there is nothing to wait for.
    pub fn wait_session_ended(&self, cargo_pid: u32) {
        wait_session_ended_in(&self.run_dir, cargo_pid);
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
        // A run directory that was never prepared has no task. A failure
        // to delete one is not a test's failure, and a panic here would
        // mask the failure that is.
        #[cfg(windows)]
        if self.run_dir.exists() {
            let _ = stow_cli::scheduled_task::unregister(&self.run_dir);
        }
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
            drop(PrivateDaemon::at(PrivateDaemon::run_dir_of(&home)));
        }
    }
}
