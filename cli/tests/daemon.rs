//! The per-user daemon (stow#1435): single instance, the clients' start
//! path and what a client-started daemon keeps of its starter. Every test
//! runs against a daemon in its own temporary runtime directory, named by
//! `STOW_DAEMON_DIR`.
#![cfg(unix)]

use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

mod support;

use stow_cli::protocol::{ControlRequest, Hello, Response, Role};
use support::PrivateDaemon;

/// How long a test waits for something a healthy daemon does at once.
const BOUND: Duration = Duration::from_secs(60);

struct Fixture {
    /// The test's daemon: found by its log, stopped when the fixture
    /// drops. Declared before `dir`, so it stops while its log still
    /// exists.
    daemon: PrivateDaemon,
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        Self {
            daemon: PrivateDaemon::in_home(dir.path()),
            dir,
        }
    }

    fn run_dir(&self) -> PathBuf {
        self.dir.path().join("run")
    }

    /// A `stow-cli` command with nothing of this process's environment but
    /// what the test names, plus a marker the daemon must never inherit.
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
        command
            .args(args)
            .env_clear()
            .env("HOME", self.dir.path())
            .env("STOW_DAEMON_DIR", self.run_dir())
            .env("STOW_TEST_STARTER_MARKER", "from-the-starter")
            .stdin(Stdio::null());
        command
    }

    fn log_lines(&self, needle: &str) -> Vec<String> {
        self.daemon.log_lines(needle)
    }

    /// [`PrivateDaemon::wait_log_lines`] of the daemon of this fixture.
    fn wait_log_lines(&self, needle: &str, at_least: usize) -> Vec<String> {
        self.daemon.wait_log_lines(needle, at_least)
    }

    /// The pids of the daemons that bound the endpoint, from their log,
    /// once the first has logged that it serves.
    fn serving_pids(&self) -> Vec<libc::pid_t> {
        self.daemon
            .wait_serving_pids()
            .into_iter()
            .map(|pid| libc::pid_t::try_from(pid).expect("a logged pid fits pid_t"))
            .collect()
    }
}

fn run_status(command: &mut Command) -> String {
    let output = command.output().expect("run stow-cli daemon status");
    assert!(
        output.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8")
}

fn expected_status() -> String {
    format!(
        "version: {}\nprotocol: {}\n",
        env!("CARGO_PKG_VERSION"),
        stow_cli::protocol::PROTOCOL
    )
}

/// Mode bits of `path`.
fn mode(path: &Path) -> u32 {
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn status_round_trips_through_an_owner_only_runtime_directory() {
    let fixture = Fixture::new();
    assert_eq!(
        run_status(&mut fixture.command(&["daemon", "status"])),
        expected_status()
    );
    assert_eq!(mode(&fixture.run_dir()), 0o700);
    assert_eq!(mode(&fixture.run_dir().join("daemon.sock")), 0o600);
    // A second client finds the daemon up and starts nothing.
    assert_eq!(
        run_status(&mut fixture.command(&["daemon", "status"])),
        expected_status()
    );
    assert_eq!(
        fixture
            .wait_log_lines("stow daemon process started", 1)
            .len(),
        1
    );
}

#[test]
fn two_daemons_started_at_once_leave_one_running_and_the_other_exits_zero() {
    let fixture = Fixture::new();
    std::fs::create_dir_all(fixture.dir.path().join("notify")).expect("notify dir");
    let daemons: Vec<(Child, mpsc::Receiver<String>)> = (0..2)
        .map(|index| {
            let endpoint = fixture.dir.path().join(format!("notify/{index}.sock"));
            let listener = UnixListener::bind(&endpoint).expect("bind notify endpoint");
            let (sender, receiver) = mpsc::channel();
            std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut line = String::new();
                stream.read_to_string(&mut line).expect("read");
                let _ = sender.send(line);
            });
            let child = fixture
                .command(&["daemon", "--ready", endpoint.to_str().expect("utf8")])
                .spawn()
                .expect("spawn daemon");
            (child, receiver)
        })
        .collect();

    let mut winner = None;
    let mut loser = None;
    for (child, receiver) in daemons {
        match receiver.recv_timeout(BOUND).expect("notification").as_str() {
            "ready\n" => winner = Some(child),
            "lock-held\n" => loser = Some(child),
            other => panic!("unexpected notification {other:?}"),
        }
    }
    let mut winner = winner.expect("exactly one daemon reports ready");
    let mut loser = loser.expect("exactly one daemon reports the lock held");
    let status = loser.wait().expect("wait for the second daemon");
    assert!(status.success(), "the second daemon exits 0, got {status}");
    assert!(
        winner.try_wait().expect("poll the first").is_none(),
        "the first daemon is still running"
    );
    // The survivor answers.
    assert_eq!(
        run_status(&mut fixture.command(&["daemon", "status"])),
        expected_status()
    );
    winner.kill().expect("stop the daemon this test spawned");
    winner.wait().expect("reap it");
}

#[test]
fn clients_that_find_the_daemon_down_start_exactly_one() {
    const CLIENTS: usize = 12;
    let fixture = Fixture::new();
    let clients: Vec<Child> = (0..CLIENTS)
        .map(|_| {
            fixture
                .command(&["daemon", "status"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn client")
        })
        .collect();
    for client in clients {
        let output = client.wait_with_output().expect("client output");
        assert!(
            output.status.success(),
            "client failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&output.stdout), expected_status());
    }
    assert_eq!(
        fixture
            .wait_log_lines("stow daemon process started", 1)
            .len(),
        1,
        "one daemon process was spawned for {CLIENTS} clients"
    );
    assert_eq!(fixture.serving_pids().len(), 1);
}

/// The environment `pid` runs with, as one string.
fn environment_of(pid: libc::pid_t) -> String {
    #[cfg(target_os = "linux")]
    {
        let raw = std::fs::read(format!("/proc/{pid}/environ")).expect("read the environment");
        String::from_utf8_lossy(&raw).replace('\0', " ")
    }
    #[cfg(not(target_os = "linux"))]
    {
        let output = Command::new("ps")
            .args(["-E", "-ww", "-o", "command=", "-p", &pid.to_string()])
            .output()
            .expect("run ps");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }
}

/// Mark `fd` inheritable across the next `exec` of `command`.
fn inherit(command: &mut Command, fd: i32) {
    // SAFETY: `fcntl` is async-signal-safe and the hook touches nothing else.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Whether every write end of `reader`'s pipe is closed: a read returns
/// end-of-file at once instead of waiting for data.
fn all_writers_closed(reader: &mut std::io::PipeReader) -> bool {
    // SAFETY: `fcntl` on a descriptor this function owns.
    unsafe {
        let flags = libc::fcntl(reader.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    match reader.read(&mut [0; 1]) {
        Ok(0) => true,
        Ok(_) => panic!("nothing writes to this pipe"),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
        Err(error) => panic!("read the pipe: {error}"),
    }
}

#[test]
fn a_client_started_daemon_holds_none_of_its_starters_descriptors_or_environment() {
    let fixture = Fixture::new();
    let (mut reader, writer) = std::io::pipe().expect("pipe");

    // The control: a process that really holds the write end keeps the
    // pipe open, so the read below can tell open from closed.
    let mut holder = Command::new("sleep");
    inherit(&mut holder, writer.as_raw_fd());
    let mut holder = holder.arg("60").spawn().expect("spawn the control");
    assert!(!all_writers_closed(&mut reader));
    holder.kill().expect("stop the control");
    holder.wait().expect("reap the control");

    // The starter holds the write end too, inheritably.
    let mut client = fixture.command(&["daemon", "status"]);
    inherit(&mut client, writer.as_raw_fd());
    assert_eq!(run_status(&mut client), expected_status());
    drop(writer);
    assert!(
        all_writers_closed(&mut reader),
        "the daemon the client started still holds the starter's descriptor"
    );

    let pids = fixture.serving_pids();
    assert_eq!(pids.len(), 1);
    let daemon = pids[0];
    let environment = environment_of(daemon);
    assert!(
        environment.contains("STOW_DAEMON_DIR="),
        "the environment reader works: {environment}"
    );
    assert!(
        !environment.contains("STOW_TEST_STARTER_MARKER"),
        "the daemon inherited the starter's environment: {environment}"
    );
    // SAFETY: `getsid` only reads.
    assert_eq!(
        unsafe { libc::getsid(daemon) },
        daemon,
        "the daemon leads a session of its own"
    );
}

#[test]
fn a_daemon_closes_the_descriptors_it_inherited() {
    let fixture = Fixture::new();
    let (mut reader, writer) = std::io::pipe().expect("pipe");
    let endpoint = fixture.dir.path().join("ready.sock");
    let listener = UnixListener::bind(&endpoint).expect("bind notify endpoint");
    let mut command = fixture.command(&["daemon", "--ready", endpoint.to_str().expect("utf8")]);
    inherit(&mut command, writer.as_raw_fd());
    let mut daemon = command.spawn().expect("spawn daemon");
    drop(writer);
    let (mut stream, _) = listener.accept().expect("accept");
    let mut line = String::new();
    stream.read_to_string(&mut line).expect("read");
    assert_eq!(line, "ready\n");
    assert!(
        all_writers_closed(&mut reader),
        "the daemon kept a descriptor it inherited"
    );
    daemon.kill().expect("stop the daemon this test spawned");
    daemon.wait().expect("reap it");
}

/// The executable of the stow under test, as the daemon is started from it.
fn stow() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_stow-cli"))
}

/// Say hello to the daemon of `run_dir` as a driver running `exe`, send
/// `request` and read the answer.
fn ask(
    run_dir: &Path,
    exe: &Path,
    request: &ControlRequest,
) -> std::io::Result<stow_cli::protocol::Response> {
    let mut stream = UnixStream::connect(run_dir.join("daemon.sock"))?;
    stream.set_read_timeout(Some(BOUND))?;
    let mut bytes =
        stow_cli::protocol::encode(&Hello::new(Role::Control, exe)).expect("encode the hello");
    bytes.extend(stow_cli::protocol::encode(request).expect("encode the request"));
    stream.write_all(&bytes)?;
    let frame = stow_cli::protocol::read_frame(&mut stream)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    stow_cli::protocol::read_response(&frame)
        .map_err(|error| std::io::Error::other(error.to_string()))
}

/// `Retire` onto `exe`.
fn retire_request(exe: &Path) -> ControlRequest {
    ControlRequest::Retire {
        executable: exe.as_os_str().as_bytes().to_vec(),
    }
}

/// Wait until `done` holds.
fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + BOUND;
    while !done() {
        assert!(std::time::Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Retire the daemon of `fixture` onto the stow under test and wait for
/// the successor to answer a status request.
fn retire_and_wait(fixture: &Fixture) {
    let reply = ask(&fixture.run_dir(), &stow(), &retire_request(&stow())).expect("retire");
    assert!(
        matches!(reply, Response::Retiring { .. }),
        "a retire is answered with Retiring: {reply:?}"
    );
    until("the successor never answered", || {
        matches!(
            ask(&fixture.run_dir(), &stow(), &ControlRequest::Status),
            Ok(Response::Status { .. })
        )
    });
    // The successor's reply can reach this test before its records are in
    // the log, which a daemon writes from a thread.
    fixture.wait_log_lines("stow daemon serving", 2);
    fixture.wait_log_lines("stow daemon process started", 2);
}

#[test]
fn a_retired_daemon_reexecs_keeping_its_pid_lock_and_endpoint() {
    let fixture = Fixture::new();
    run_status(&mut fixture.command(&["daemon", "status"]));
    let socket = fixture.run_dir().join("daemon.sock");
    let inode = std::fs::metadata(&socket).expect("socket").ino();
    let [pid] = fixture.serving_pids()[..] else {
        panic!("one daemon serves: {:?}", fixture.serving_pids());
    };

    retire_and_wait(&fixture);

    assert_eq!(fixture.serving_pids(), [pid], "the successor has the pid");
    assert_eq!(
        fixture.log_lines("stow daemon process started").len(),
        2,
        "the image started again"
    );
    assert_eq!(
        std::fs::metadata(&socket).expect("socket").ino(),
        inode,
        "the endpoint was never replaced"
    );
    // SAFETY: signal 0 only probes.
    assert_eq!(unsafe { libc::kill(pid, 0) }, 0, "the daemon lives");
    // The lock is held across the exec: a daemon started meanwhile finds it
    // held and exits 0.
    let second = fixture
        .command(&["daemon"])
        .output()
        .expect("run a second daemon");
    assert!(second.status.success(), "{second:?}");
    assert_eq!(
        fixture
            .wait_log_lines("another stow daemon holds the lock", 1)
            .len(),
        1
    );
    assert_eq!(fixture.serving_pids(), [pid]);
}

/// The body of the child process [`support::spawn_old_daemon`] starts.
#[test]
fn old_daemon_child() {
    support::old_daemon_child_body();
}

/// A daemon of a protocol older than any that can retire refuses this
/// stow's hello. The client ends the process at the other end of its
/// connection and takes the start path: it is served by a daemon of this
/// stow, and the old one is gone.
#[test]
fn a_daemon_too_old_to_retire_is_ended_and_replaced() {
    let fixture = Fixture::new();
    let (old, reaped) = support::spawn_old_daemon(&fixture.run_dir());

    assert_eq!(
        run_status(&mut fixture.command(&["daemon", "status"])),
        expected_status(),
        "the client was served by a daemon of its own stow"
    );

    let status = reaped.join().expect("the old daemon's reaper");
    assert!(!status.success(), "the old daemon was ended: {status:?}");
    let [new] = fixture.serving_pids()[..] else {
        panic!("one daemon serves: {:?}", fixture.serving_pids());
    };
    assert_ne!(
        u32::try_from(new).expect("a pid"),
        old,
        "the daemon is a new process"
    );
}

/// The body of the child process [`support::retire_onto_in_child`] runs.
#[test]
fn retire_onto_child() {
    support::retire_onto_child_body();
}

/// What `stow update` asks of the daemon: a running one is replaced by the
/// installed stow and the successor's version is reported; one that is not
/// running is left alone.
#[test]
fn retire_onto_replaces_a_running_daemon_and_starts_none() {
    let fixture = Fixture::new();
    assert_eq!(
        support::retire_onto_in_child(&fixture.run_dir(), &stow()),
        "none"
    );
    assert!(
        fixture.log_lines("stow daemon serving").is_empty(),
        "nothing was started"
    );

    run_status(&mut fixture.command(&["daemon", "status"]));
    let [pid] = fixture.serving_pids()[..] else {
        panic!("one daemon serves: {:?}", fixture.serving_pids());
    };
    let version = env!("CARGO_PKG_VERSION");
    assert_eq!(
        support::retire_onto_in_child(&fixture.run_dir(), &stow()),
        format!("restarted {version} {version}")
    );
    fixture.wait_log_lines("stow daemon serving", 2);
    assert_eq!(fixture.serving_pids(), [pid], "the successor has the pid");
    assert_eq!(
        fixture
            .wait_log_lines("stow daemon process started", 2)
            .len(),
        2
    );
}

#[test]
fn a_connect_during_the_exec_is_answered_by_the_new_image() {
    const CLIENTS: usize = 8;
    const ASKS: usize = 40;
    let fixture = Fixture::new();
    run_status(&mut fixture.command(&["daemon", "status"]));
    let run_dir = fixture.run_dir();
    let reply = ask(&run_dir, &stow(), &retire_request(&stow())).expect("retire");
    assert!(matches!(reply, Response::Retiring { .. }), "{reply:?}");
    // Clients that connect from the retirement on are each answered, by the
    // old image with a request to retry or by the new one with its status;
    // none sees a connection closed unanswered.
    #[expect(
        clippy::needless_collect,
        reason = "every client runs before the first is joined"
    )]
    let clients: Vec<_> = (0..CLIENTS)
        .map(|_| {
            let run_dir = run_dir.clone();
            std::thread::spawn(move || {
                (0..ASKS)
                    .map(|_| {
                        ask(&run_dir, &stow(), &ControlRequest::Status)
                            .expect("every connection is answered")
                    })
                    .filter(|reply| matches!(reply, Response::Status { .. }))
                    .count()
            })
        })
        .collect();
    let answered: usize = clients
        .into_iter()
        .map(|client| client.join().expect("a client"))
        .sum();
    assert!(answered > 0, "the new image answered");
    assert_eq!(
        fixture
            .wait_log_lines("stow daemon process started", 2)
            .len(),
        2
    );
}

#[test]
fn a_reexeced_daemon_holds_only_its_own_descriptors() {
    let fixture = Fixture::new();
    let (mut reader, writer) = std::io::pipe().expect("pipe");
    let endpoint = fixture.dir.path().join("ready.sock");
    let listener = UnixListener::bind(&endpoint).expect("bind notify endpoint");
    let mut command = fixture.command(&["daemon", "--ready", endpoint.to_str().expect("utf8")]);
    inherit(&mut command, writer.as_raw_fd());
    let mut daemon = command.spawn().expect("spawn daemon");
    drop(writer);
    let (mut stream, _) = listener.accept().expect("accept");
    let mut line = String::new();
    stream.read_to_string(&mut line).expect("read");
    assert_eq!(line, "ready\n");

    retire_and_wait(&fixture);

    assert!(
        all_writers_closed(&mut reader),
        "the daemon kept a descriptor it inherited"
    );
    #[cfg(target_os = "linux")]
    {
        let pid = daemon.id();
        let held_by_name = |name: &str| {
            std::fs::read_dir(format!("/proc/{pid}/fd"))
                .expect("list the descriptors")
                .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
                .filter(|target| target.file_name().is_some_and(|file| file == name))
                .count()
        };
        assert_eq!(held_by_name("daemon.log"), 1, "one descriptor of the log");
        assert_eq!(held_by_name("daemon.lock"), 1, "one descriptor of the lock");
    }
    daemon.kill().expect("stop the daemon this test spawned");
    daemon.wait().expect("reap it");
}
