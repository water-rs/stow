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

/// Say hello to the daemon as a driver and send `request`, answering what
/// came back within the start bound, or `None` when the pipe does not
/// exist: no daemon serves. A connection that closes without a frame is an
/// error.
fn try_ask(run_dir: &Path, request: &ControlRequest) -> Result<Option<Response>, String> {
    /// `ERROR_PIPE_BUSY`: every instance of the pipe is serving a client.
    const PIPE_BUSY: i32 = 231;
    let deadline = Instant::now() + Duration::from_secs(START_SECS);
    let mut pipe = loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe_of(run_dir))
        {
            Ok(pipe) => break pipe,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) if error.raw_os_error() == Some(PIPE_BUSY) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(format!("connect to the daemon's pipe: {error}")),
        }
    };
    let mut bytes = stow_cli::protocol::encode(&Hello::new(Role::Control, &stow()))
        .map_err(|error| error.to_string())?;
    bytes.extend(stow_cli::protocol::encode(request).map_err(|error| error.to_string())?);
    pipe.write_all(&bytes).map_err(|error| error.to_string())?;
    let mut reading = pipe.try_clone().map_err(|error| error.to_string())?;
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let answer = stow_cli::protocol::read_frame(&mut reading)
            .and_then(|frame| stow_cli::protocol::read_response(&frame));
        let _ = sender.send(answer.map_err(|error| error.to_string()));
    });
    receiver
        .recv_timeout(Duration::from_secs(START_SECS))
        .map_err(|error| format!("no answer: {error}"))?
        .map(Some)
}

/// Clients that connect all through a retirement, up to the moment its
/// drain ends and the daemon exits, each get a frame: a client that reaches
/// the pipe as the daemon stops serving is answered, never hung up on, and
/// once the pipe is gone it finds no daemon.
#[test]
fn clients_connecting_as_the_drain_ends_are_answered() {
    /// Clients hammering the pipe at once.
    const CLIENTS: usize = 8;
    let home = support::tempdir().expect("home");
    let daemon = PrivateDaemon::in_home(home.path());
    let run_dir = daemon.run_dir().to_owned();
    assert_answered(client(&run_dir), Instant::now());
    let [first] = daemon.serving_pids()[..] else {
        panic!("one daemon serves: {:?}", daemon.serving_pids());
    };

    // Each client reports its first answer, so the retirement starts only
    // once every one of them is connecting: a client that first reached the
    // pipe after the daemon left would prove nothing.
    let (first_answer, first_answers) = mpsc::channel();
    let hammers: Vec<_> = (0..CLIENTS)
        .map(|_| {
            let run_dir = run_dir.clone();
            let first_answer = first_answer.clone();
            std::thread::spawn(move || {
                let mut answered = 0_usize;
                while let Some(response) = try_ask(&run_dir, &ControlRequest::Status)? {
                    assert!(
                        matches!(
                            response,
                            Response::Status { .. } | Response::Retiring { .. }
                        ),
                        "{response:?}"
                    );
                    if answered == 0 {
                        let _ = first_answer.send(());
                    }
                    answered += 1;
                }
                Ok::<_, String>(answered)
            })
        })
        .collect();
    for _ in 0..CLIENTS {
        first_answers
            .recv_timeout(Duration::from_secs(START_SECS))
            .expect("every client is answered before the retirement");
    }

    let retiring = try_ask(
        &run_dir,
        &ControlRequest::Retire {
            executable: stow()
                .as_os_str()
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect(),
        },
    )
    .expect("the retirement is answered")
    .expect("the daemon serves");
    assert!(
        matches!(retiring, Response::Retiring { .. }),
        "{retiring:?}"
    );

    for hammer in hammers {
        let answered = hammer
            .join()
            .expect("a client thread")
            .unwrap_or_else(|error| {
                panic!(
                    "a client was not answered: {error}\n{:?}",
                    daemon.log_lines("stow daemon")
                )
            });
        assert!(answered > 0, "a client was never answered");
    }
    assert!(!alive(first), "the retired daemon exited");
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

/// The body of the child process [`support::retire_onto_in_child`] runs.
#[test]
fn retire_onto_child() {
    support::retire_onto_child_body();
}

/// What `stow update` asks of the daemon: a running one drains and is
/// succeeded through the task, and the successor's version is reported; one
/// that is not running is not started.
#[test]
fn retire_onto_succeeds_a_running_daemon_through_the_task_and_starts_none() {
    let home = support::tempdir().expect("home");
    let daemon = PrivateDaemon::in_home(home.path());
    let run_dir = daemon.run_dir().to_owned();
    assert_eq!(support::retire_onto_in_child(&run_dir, &stow()), "none");
    assert!(daemon.serving_pids().is_empty(), "nothing was started");

    assert_answered(client(&run_dir), Instant::now());
    let [first] = daemon.serving_pids()[..] else {
        panic!("one daemon serves: {:?}", daemon.serving_pids());
    };
    let version = env!("CARGO_PKG_VERSION");
    assert_eq!(
        support::retire_onto_in_child(&run_dir, &stow()),
        format!("restarted {version} {version}")
    );
    let pids = daemon.serving_pids();
    assert_eq!(pids.len(), 2, "{:?}", daemon.log_lines("stow daemon"));
    assert_eq!(pids[0], first);
    assert_ne!(pids[1], first, "the successor is a new process");
}

/// The body of the child process [`support::spawn_old_daemon`] starts.
#[test]
fn old_daemon_child() {
    support::old_daemon_child_body();
}

/// A daemon of a protocol too old to be asked to retire refuses this
/// stow's hello. The client ends the process at the other end of its pipe
/// and asks the task for a daemon of this stow.
#[test]
fn a_daemon_too_old_to_retire_is_ended_and_the_task_starts_a_new_one() {
    let home = support::tempdir().expect("home");
    let daemon = PrivateDaemon::in_home(home.path());
    let run_dir = daemon.run_dir().to_owned();
    let (old, reaped) = support::spawn_old_daemon(&run_dir);

    assert_answered(client(&run_dir), Instant::now());

    let status = reaped.join().expect("the old daemon's reaper");
    assert!(!status.success(), "the old daemon was ended: {status:?}");
    let [new] = daemon.serving_pids()[..] else {
        panic!("one daemon serves: {:?}", daemon.serving_pids());
    };
    assert_ne!(new, old, "the daemon is a new process");
}
