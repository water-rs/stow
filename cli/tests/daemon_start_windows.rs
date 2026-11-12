//! The start path on Windows, where the Task Scheduler starts the daemon
//! and ignores a request made while a run is live: a client must find a
//! daemon that began starting before it asked, and must never end one.
#![cfg(windows)]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod support;

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
