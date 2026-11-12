//! The start path on Windows, where the Task Scheduler starts the daemon
//! and queues a request made while a run is live: a client must find a
//! daemon that began starting before it asked, and must never end one; a
//! daemon that retires is succeeded through the task.
#![cfg(windows)]

use std::io::Write as _;
use std::os::windows::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

mod support;

use stow_cli::protocol::{ControlRequest, Hello, Response, Role};
use support::PrivateDaemon;

/// The start bound a client under test waits: well above what a healthy
/// daemon takes, and the time a client that waits it out would burn.
const START_SECS: u64 = 20;

fn client(run_dir: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_stow-cli"))
        .args(["daemon", "status"])
        .env("STOW_DAEMON_DIR", run_dir)
        .env("STOW_DAEMON_START_SECS", START_SECS.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn a daemon status client")
}

fn assert_answered(client: Child, started: Instant) {
    let output = client.wait_with_output().expect("wait for the client");
    assert!(
        output.status.success(),
        "the client did not reach the daemon:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        started.elapsed() < Duration::from_secs(START_SECS),
        "the client waited out the start bound"
    );
}

/// A daemon the logon trigger (here, a run requested by hand) began
/// starting before the client published its address never notifies the
/// client, and the client's own request is ignored: the client still
/// reaches the daemon at once, and the daemon survives it.
#[test]
fn a_client_finds_a_daemon_that_was_already_starting() {
    let home = support::tempdir().expect("home");
    let daemon = PrivateDaemon::in_home(home.path());
    let run_dir = daemon.run_dir().to_owned();
    let name = stow_cli::scheduled_task::task_name(&run_dir);
    let requested = Command::new("schtasks.exe")
        .args(["/Run", "/TN", &name])
        .output()
        .expect("run schtasks");
    assert!(requested.status.success(), "{requested:?}");

    let started = Instant::now();
    assert_answered(client(&run_dir), started);
    assert_eq!(
        daemon.serving_pids().len(),
        1,
        "a daemon was started twice or ended:\n{:?}",
        daemon.log_lines("stow daemon")
    );

    // Still serving: a second client finds the same daemon.
    assert_answered(client(&run_dir), Instant::now());
    assert_eq!(daemon.serving_pids().len(), 1);
}

/// Clients that all find no daemon share one start: every one reaches it
/// and exactly one daemon serves.
#[test]
fn concurrent_first_clients_share_one_daemon() {
    let home = support::tempdir().expect("home");
    let daemon = PrivateDaemon::in_home(home.path());
    let run_dir = daemon.run_dir().to_owned();

    let started = Instant::now();
    let clients: Vec<Child> = (0..4).map(|_| client(&run_dir)).collect();
    for client in clients {
        assert_answered(client, started);
    }
    assert_eq!(
        daemon.serving_pids().len(),
        1,
        "{:?}",
        daemon.log_lines("stow daemon")
    );
}

/// The stow under test, which the task runs and a client hellos as.
fn stow() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_stow-cli"))
}

/// The daemon's pipe: it is named after the same run directory as the task.
fn pipe_of(run_dir: &Path) -> PathBuf {
    PathBuf::from(format!(
        r"\\.\pipe\{}",
        stow_cli::scheduled_task::task_name(run_dir)
    ))
}

/// Connect to the daemon's pipe.
fn open_pipe(run_dir: &Path) -> std::fs::File {
    /// `ERROR_PIPE_BUSY`: every instance of the pipe is serving a client.
    const PIPE_BUSY: i32 = 231;
    let deadline = Instant::now() + Duration::from_secs(START_SECS);
    loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe_of(run_dir))
        {
            Ok(pipe) => return pipe,
            Err(error) if error.raw_os_error() == Some(PIPE_BUSY) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("connect to the daemon's pipe: {error}"),
        }
    }
}

/// Say hello to the daemon as a driver, send `request`, and read the
/// answer within the start bound. The pipe is returned so a caller can hold
/// the connection.
fn ask(run_dir: &Path, request: &ControlRequest) -> (Response, std::fs::File) {
    let mut pipe = open_pipe(run_dir);
    let mut bytes =
        stow_cli::protocol::encode(&Hello::new(Role::Control, &stow())).expect("encode the hello");
    bytes.extend(stow_cli::protocol::encode(request).expect("encode the request"));
    pipe.write_all(&bytes).expect("send the request");
    let mut reading = pipe.try_clone().expect("clone the pipe");
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let answer = stow_cli::protocol::read_frame(&mut reading)
            .and_then(|frame| stow_cli::protocol::read_response(&frame));
        let _ = sender.send(answer.map_err(|error| error.to_string()));
    });
    let response = receiver
        .recv_timeout(Duration::from_secs(START_SECS))
        .expect("the daemon answered within the bound")
        .expect("a response");
    (response, pipe)
}

/// Whether the process `pid` is running.
fn alive(pid: u32) -> bool {
    let listed = Command::new("tasklist.exe")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output()
        .expect("run tasklist");
    String::from_utf8_lossy(&listed.stdout)
        .split_whitespace()
        .any(|word| word == pid.to_string())
}

/// A retired daemon drains, releases the pipe and the lock and exits; the
/// next client finds the pipe gone, asks the task for a run and is served
/// by a new process of the registered command. A connection held across the
/// hand-over does not stop the successor from binding the pipe.
#[test]
fn a_retired_daemon_is_succeeded_through_the_task() {
    let home = support::tempdir().expect("home");
    let daemon = PrivateDaemon::in_home(home.path());
    let run_dir = daemon.run_dir().to_owned();
    assert_answered(client(&run_dir), Instant::now());
    let [first] = daemon.serving_pids()[..] else {
        panic!("one daemon serves: {:?}", daemon.serving_pids());
    };

    let (held, connection) = ask(&run_dir, &ControlRequest::Status);
    assert!(matches!(held, Response::Status { .. }), "{held:?}");
    let (retiring, _) = ask(
        &run_dir,
        &ControlRequest::Retire {
            executable: stow()
                .as_os_str()
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect(),
        },
    );
    assert!(
        matches!(retiring, Response::Retiring { .. }),
        "{retiring:?}"
    );

    // The old daemon leaves, and the connection stays open across the
    // hand-over.
    let deadline = Instant::now() + Duration::from_secs(START_SECS);
    while alive(first) {
        assert!(Instant::now() < deadline, "the retired daemon never exited");
        std::thread::sleep(Duration::from_millis(100));
    }

    assert_answered(client(&run_dir), Instant::now());
    drop(connection);
    let pids = daemon.serving_pids();
    assert_eq!(pids.len(), 2, "{:?}", daemon.log_lines("stow daemon"));
    assert_eq!(pids[0], first);
    assert_ne!(pids[1], first, "the successor is a new process");
    assert!(alive(pids[1]), "the successor serves");
}
