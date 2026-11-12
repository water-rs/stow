//! A daemon gives way to a newer stow without failing the build that found
//! it: when stow is installed over the executable a daemon runs, when a
//! newer client says hello, and when a build it holds open outlives the
//! drain. Every test runs against a daemon in its own temporary runtime
//! directory and an install of its own, a copy of the stow under test.

mod support;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use stow_cli::protocol::{ControlRequest, Hello, Response, Role};
use support::{PrivateDaemon, hermetic_stow_env};

/// How long a test waits for something a healthy daemon does within a few
/// seconds, drain bounds included.
const BOUND: Duration = Duration::from_secs(60);

/// The drain bound the daemons of these tests wait for the builds they
/// hold, in seconds: long enough that the build that triggers a retirement
/// finds its predecessor's session ended, short enough to cut one the test
/// keeps open.
const DRAIN_SECS: &str = "2";

/// The stow under test.
fn stow() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_stow-cli"))
}

/// An install of the stow under test: a runtime executable that is a copy
/// of it, and the rustc wrapper beside it that starts the daemon from that
/// runtime. [`Install::replace`] installs over the runtime, as an update
/// does.
struct Install {
    dir: support::TempDir,
    replacements: usize,
}

impl Install {
    fn new() -> Self {
        let dir = support::tempdir().expect("install dir");
        let install = Self {
            dir,
            replacements: 0,
        };
        std::fs::copy(stow(), install.runtime()).expect("copy the runtime");
        let wrapper = install.wrapper();
        #[cfg(unix)]
        std::os::unix::fs::symlink(install.runtime(), &wrapper).expect("link the wrapper");
        #[cfg(windows)]
        std::fs::copy(stow(), &wrapper).expect("copy the wrapper");
        install
    }

    fn runtime(&self) -> PathBuf {
        self.dir
            .path()
            .join(format!("stow-runtime{}", std::env::consts::EXE_SUFFIX))
    }

    fn wrapper(&self) -> PathBuf {
        self.dir.path().join(format!(
            "stow-rustc-wrapper{}",
            std::env::consts::EXE_SUFFIX
        ))
    }

    /// Install a new file over the runtime: a different file at the same
    /// path, as an installer leaves it.
    fn replace(&mut self) {
        self.replacements += 1;
        let next = self.dir.path().join(format!("next-{}", self.replacements));
        std::fs::copy(stow(), &next).expect("copy the new runtime");
        // Windows cannot overwrite a running executable, but it can move
        // one out of the way.
        #[cfg(windows)]
        std::fs::rename(
            self.runtime(),
            self.dir.path().join(format!("old-{}", self.replacements)),
        )
        .expect("move the running runtime away");
        std::fs::rename(&next, self.runtime()).expect("install the new runtime");
    }

    /// Point the daemon's task at this install's runtime, as `stow setup`
    /// from this install does; every sealed command registers the stow under
    /// test again, so it is done after the command is built.
    #[cfg(windows)]
    fn register_task(&self, run_dir: &Path) {
        stow_cli::scheduled_task::register(run_dir, &self.runtime())
            .unwrap_or_else(|error| panic!("register the daemon's scheduled task: {error}"));
    }

    #[cfg(unix)]
    #[expect(
        clippy::unused_self,
        reason = "the one interface of the test on every platform"
    )]
    const fn register_task(&self, _run_dir: &Path) {}
}

fn write_crate(dir: &Path) {
    std::fs::create_dir_all(dir.join("src")).expect("src dir");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"plain\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("manifest");
    std::fs::write(dir.join("src").join("lib.rs"), "pub fn one() -> u8 { 1 }\n").expect("lib");
}

/// A project with a build script that says it started and then waits for
/// `go`, which keeps its build's cargo, and so its session, open.
fn write_waiting_crate(dir: &Path, started: &Path, go: &Path) {
    write_crate(dir);
    let literal = |path: &Path| format!("{:?}", path.to_str().expect("utf-8 path"));
    std::fs::write(
        dir.join("build.rs"),
        format!(
            "fn main() {{\n\
             \x20   std::fs::write({started}, \"started\").expect(\"say it started\");\n\
             \x20   while !std::path::Path::new({go}).exists() {{\n\
             \x20       std::thread::sleep(std::time::Duration::from_millis(20));\n\
             \x20   }}\n\
             }}\n",
            started = literal(started),
            go = literal(go),
        ),
    )
    .expect("build script");
}

/// A project's directories, and the stow home its builds and daemon share.
struct Project {
    dir: support::TempDir,
    cache: support::TempDir,
    cargo_home: support::TempDir,
}

impl Project {
    fn new() -> Self {
        let project = Self {
            dir: support::tempdir().expect("project dir"),
            cache: support::tempdir().expect("cache dir"),
            cargo_home: support::tempdir().expect("cargo home"),
        };
        support::write_global_config(&[&project.home()], "[cache]\nremote = false\n");
        project
    }

    fn home(&self) -> PathBuf {
        self.dir.path().join("stow-home")
    }

    fn run_dir(&self) -> PathBuf {
        PrivateDaemon::run_dir_of(&self.home())
    }

    /// A plain `cargo build` of the project into `target`, its rustc
    /// wrapped by `install`'s wrapper.
    fn plain_build(&self, install: &Install, target: &str) -> Command {
        let mut command = support::cargo_command(&self.home());
        hermetic_stow_env(
            &mut command,
            &support::denied_registry(),
            self.cache.path(),
            &self.home(),
        );
        command
            .arg("build")
            .current_dir(self.dir.path())
            .env("CARGO_HOME", self.cargo_home.path())
            .env("CARGO_TARGET_DIR", self.dir.path().join(target))
            .env("CARGO_INCREMENTAL", "0")
            .env("RUSTC_WRAPPER", install.wrapper())
            .env("STOW_DAEMON_DRAIN_SECS", DRAIN_SECS);
        install.register_task(&self.run_dir());
        command
    }

    /// `stow build` of the project into `target` by `install`'s runtime,
    /// which the daemon's session is opened by.
    fn stow_build(&self, install: &Install, target: &str) -> Command {
        let mut command = Command::new(install.runtime());
        command
            .args(["build", "--isolation", "off"])
            .current_dir(self.dir.path())
            .env("CARGO_HOME", self.cargo_home.path());
        hermetic_stow_env(
            &mut command,
            &support::denied_registry(),
            self.cache.path(),
            &self.home(),
        );
        command
            .env("CARGO_INCREMENTAL", "0")
            .env("CARGO_TARGET_DIR", self.dir.path().join(target))
            .env("STOW_DAEMON_DRAIN_SECS", DRAIN_SECS)
            .env_remove("RUST_LOG");
        install.register_task(&self.run_dir());
        command
    }

    /// `stow setup` by `install`'s runtime: the one-time configuration a
    /// `stow build` of a Linux host needs.
    fn stow_setup(&self, install: &Install) {
        let mut setup = Command::new(install.runtime());
        setup
            .arg("setup")
            .current_dir(self.dir.path())
            .env("CARGO_HOME", self.cargo_home.path());
        hermetic_stow_env(
            &mut setup,
            &support::denied_registry(),
            self.cache.path(),
            &self.home(),
        );
        install.register_task(&self.run_dir());
        let output = setup.output().expect("run stow setup");
        assert!(
            output.status.success(),
            "stow setup failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn succeeds(mut command: Command, what: &str) {
    let output = command.output().expect("run the build");
    assert!(
        output.status.success(),
        "{what} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Wait until `done` holds.
fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + BOUND;
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// What a replacement leaves of the daemon that gave way: the pid it kept
/// (Unix replaces the image in place) or the new process the task started
/// (Windows), and a start of the daemon logged for each image.
fn assert_replaced_once(daemon: &PrivateDaemon, first: u32) {
    let pids = daemon.serving_pids();
    let log = daemon.log_lines("");
    assert_eq!(
        daemon.log_lines("stow daemon process started").len(),
        2,
        "the daemon started twice:\n{}",
        log.join("\n")
    );
    assert_eq!(pids[0], first);
    if cfg!(unix) {
        assert_eq!(
            pids,
            [first],
            "the successor keeps the pid:\n{}",
            log.join("\n")
        );
    } else {
        assert_eq!(pids.len(), 2, "{}", log.join("\n"));
        assert_ne!(pids[1], first, "the successor is a new process");
    }
    assert!(
        !daemon.log_lines("retiring: draining").is_empty(),
        "{}",
        log.join("\n")
    );
}

/// Stow installed over the runtime a daemon runs: the next plain cargo
/// build's wrapper finds the daemon giving way, waits for the successor and
/// is served by it, and the build succeeds.
#[test]
fn a_replaced_install_serves_the_next_plain_cargo_build() {
    let mut install = Install::new();
    let project = Project::new();
    write_crate(project.dir.path());
    let daemon = PrivateDaemon::in_home(&project.home());

    succeeds(project.plain_build(&install, "target-a"), "the first build");
    let [first] = daemon.serving_pids()[..] else {
        panic!("one daemon serves: {:?}", daemon.serving_pids());
    };

    install.replace();
    succeeds(
        project.plain_build(&install, "target-b"),
        "the second build",
    );

    assert_replaced_once(&daemon, first);
    assert_eq!(
        daemon.log_lines("opened a session for a cargo").len(),
        2,
        "each build had its session, the second on the successor"
    );
}

/// The same through the driver: `stow build` opens its session on the
/// successor of the daemon that found the install replaced.
#[test]
fn a_replaced_install_serves_the_next_stow_build() {
    let mut install = Install::new();
    let project = Project::new();
    write_crate(project.dir.path());
    let daemon = PrivateDaemon::in_home(&project.home());
    project.stow_setup(&install);

    succeeds(project.stow_build(&install, "target-a"), "the first build");
    let [first] = daemon.serving_pids()[..] else {
        panic!("one daemon serves: {:?}", daemon.serving_pids());
    };

    install.replace();
    succeeds(project.stow_build(&install, "target-b"), "the second build");

    assert_replaced_once(&daemon, first);
}

/// The body of the child process [`support::spawn_old_daemon`] starts.
#[test]
fn old_daemon_child() {
    support::old_daemon_child_body();
}

/// A daemon of a protocol too old to be asked to retire refuses the
/// wrapper's hello. The wrapper ends it, starts a daemon of its own stow
/// and the build succeeds on that one.
#[test]
fn a_plain_cargo_build_ends_a_daemon_too_old_to_retire() {
    let install = Install::new();
    let project = Project::new();
    write_crate(project.dir.path());
    let daemon = PrivateDaemon::in_home(&project.home());
    let (old, reaped) = support::spawn_old_daemon(&project.run_dir());

    succeeds(project.plain_build(&install, "target-a"), "the build");

    let status = reaped.join().expect("the old daemon's reaper");
    assert!(!status.success(), "the old daemon was ended: {status:?}");
    let [new] = daemon.serving_pids()[..] else {
        panic!("one daemon serves: {:?}", daemon.serving_pids());
    };
    assert_ne!(new, old, "the daemon is a new process");
    assert_eq!(
        daemon.log_lines("opened a session for a cargo").len(),
        1,
        "the build's session is the new daemon's"
    );
}

/// Connect to the daemon of `run_dir`.
#[cfg(unix)]
fn endpoint(run_dir: &Path) -> std::io::Result<std::os::unix::net::UnixStream> {
    std::os::unix::net::UnixStream::connect(run_dir.join("daemon.sock"))
}

/// Connect to the daemon of `run_dir`: its pipe is named after the same
/// run directory as its task.
#[cfg(windows)]
fn endpoint(run_dir: &Path) -> std::io::Result<std::fs::File> {
    /// `ERROR_PIPE_BUSY`: every instance of the pipe is serving a client.
    const PIPE_BUSY: i32 = 231;
    let pipe = PathBuf::from(format!(
        r"\\.\pipe\{}",
        stow_cli::scheduled_task::task_name(run_dir)
    ));
    let deadline = Instant::now() + BOUND;
    loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&pipe)
        {
            Err(error) if error.raw_os_error() == Some(PIPE_BUSY) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            opened => return opened,
        }
    }
}

/// The bytes the protocol carries a path as.
fn os_bytes(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;
        path.as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect()
    }
}

/// Say hello to the daemon of `run_dir` as a driver of stow `version`
/// running `exe`, send `request` and read the answer within the bound.
fn ask(
    run_dir: &Path,
    version: &str,
    exe: &Path,
    request: &ControlRequest,
) -> std::io::Result<Response> {
    let mut stream = endpoint(run_dir)?;
    let hello = Hello {
        stow_version: version.to_owned(),
        ..Hello::new(Role::Control, exe)
    };
    let mut bytes = stow_cli::protocol::encode(&hello).expect("encode the hello");
    bytes.extend(stow_cli::protocol::encode(request).expect("encode the request"));
    stream.write_all(&bytes)?;
    let mut reading = stream.try_clone()?;
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let answer = stow_cli::protocol::read_frame(&mut reading)
            .and_then(|frame| stow_cli::protocol::read_response(&frame));
        let _ = sender.send(answer.map_err(|error| error.to_string()));
    });
    receiver
        .recv_timeout(BOUND)
        .map_err(|error| std::io::Error::other(format!("no answer: {error}")))?
        .map_err(std::io::Error::other)
}

/// `stow daemon status` of the stow under test against the project's
/// daemon, which starts it when none runs, and what it reported.
fn daemon_status(project: &Project) -> String {
    let mut status = Command::new(stow());
    support::sealed_home_env(&mut status, &project.home());
    let output = status
        .args(["daemon", "status"])
        .stdin(Stdio::null())
        .output()
        .expect("run stow daemon status");
    assert!(
        output.status.success(),
        "the status client failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf-8 status")
}

/// A stow newer than the one under test, by its version.
fn newer_version() -> String {
    let version = semver::Version::parse(env!("CARGO_PKG_VERSION")).expect("a version");
    semver::Version::new(version.major, version.minor, version.patch + 1).to_string()
}

/// A client that is a newer stow gets the daemon replaced by the
/// executable it names: the daemon answers that it is retiring, drains and
/// is succeeded; the next client of the version under test is served.
#[test]
fn a_newer_client_gets_the_daemon_replaced_by_its_executable() {
    let mut install = Install::new();
    let project = Project::new();
    let daemon = PrivateDaemon::in_home(&project.home());
    let run_dir = project.run_dir();
    daemon_status(&project);
    let [first] = daemon.serving_pids()[..] else {
        panic!("one daemon serves: {:?}", daemon.serving_pids());
    };

    // The newer stow's file, which the daemon starts in its place.
    install.replace();
    let reply = ask(
        &run_dir,
        &newer_version(),
        &install.runtime(),
        &ControlRequest::Status,
    )
    .expect("the daemon answers a newer client");
    assert!(
        matches!(reply, Response::Retiring { .. }),
        "a newer stow is told the daemon is retiring: {reply:?}"
    );

    // A client reaches the successor through the start path: on Windows
    // that is what asks the task to run it.
    daemon_status(&project);
    assert_replaced_once(&daemon, first);
    #[cfg(unix)]
    assert!(
        daemon
            .log_lines("replacing this daemon's image")
            .iter()
            .any(|line| line.contains(&install.runtime().display().to_string())),
        "the daemon was replaced by the client's executable:\n{}",
        daemon.log_lines("").join("\n")
    );
}

/// A build the daemon holds open when its drain bound runs out is cut: the
/// successor refuses the cargo's next wrapper, and the build fails naming
/// the daemon and the restart.
#[test]
fn a_build_open_across_a_restart_fails_naming_the_daemon() {
    let install = Install::new();
    let project = Project::new();
    let started = project.dir.path().join("started");
    let go = project.dir.path().join("go");
    write_waiting_crate(project.dir.path(), &started, &go);
    let daemon = PrivateDaemon::in_home(&project.home());

    let mut build = project.plain_build(&install, "target-a");
    let cargo: Child = build
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start cargo");
    until("the build script never started", || started.exists());
    let [first] = daemon.serving_pids()[..] else {
        panic!("one daemon serves: {:?}", daemon.serving_pids());
    };
    assert_eq!(
        daemon.log_lines("opened a session for a cargo").len(),
        1,
        "the build holds a session"
    );

    let reply = ask(
        &project.run_dir(),
        env!("CARGO_PKG_VERSION"),
        &install.runtime(),
        &ControlRequest::Retire {
            executable: os_bytes(&install.runtime()),
        },
    )
    .expect("retire the daemon");
    assert!(matches!(reply, Response::Retiring { .. }), "{reply:?}");
    // Nothing but a client starts a successor on Windows, where the daemon
    // exits and the task runs the next one when asked: the build's own
    // wrapper is parked in its build script, so a client of its own asks.
    daemon_status(&project);
    until("the successor never served", || {
        daemon.log_lines("stow daemon serving").len() == 2
    });

    // The build goes on: its next wrapper reaches the successor, which
    // does not have the session of the build it did not start.
    std::fs::write(&go, "go").expect("let the build script end");
    let output = cargo.wait_with_output().expect("wait for cargo");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a build whose session was cut must fail:\n{stderr}"
    );
    assert!(
        stderr.contains("restarted during this cargo build") && stderr.contains("daemon.log"),
        "the failure names the restart and the daemon:\n{stderr}"
    );
    assert_replaced_once(&daemon, first);
}
