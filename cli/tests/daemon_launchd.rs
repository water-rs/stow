//! A daemon that launchd runs replaces its own image in place on a retire,
//! so launchd still has the one job and its process, and starts no second
//! daemon.
//!
//! The test bootstraps an agent of its own, labelled for this test process,
//! into the user's GUI domain and runs its daemon in a private runtime
//! directory. It needs the domain to exist, which a logged-in user's session
//! provides: it runs on GitHub Actions, where `GITHUB_ACTIONS` is set, and
//! anywhere else when `STOW_TEST_LAUNCHD=1` says to; otherwise it reports
//! that it did not run. A runner without the domain fails it at the
//! bootstrap, with launchd's own message.
#![cfg(target_os = "macos")]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use askama::Template;
use stow_cli::protocol::{ControlRequest, Hello, Response, Role};

mod support;

use support::PrivateDaemon;

/// How long the test waits for launchd and the daemon.
const BOUND: Duration = Duration::from_secs(60);

#[derive(Template)]
#[template(path = "../tests/fixtures/launchd_test_agent.xml")]
struct Agent<'a> {
    label: &'a str,
    program: &'a str,
    run_dir: &'a str,
}

/// The test's agent in the user's GUI domain, booted out when dropped.
struct Loaded {
    service: String,
}

impl Loaded {
    fn bootstrap(label: &str, plist: &Path) -> Self {
        // SAFETY: `getuid` has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        let output = Command::new("launchctl")
            .arg("bootstrap")
            .arg(format!("gui/{uid}"))
            .arg(plist)
            .output()
            .expect("run launchctl");
        assert!(
            output.status.success(),
            "launchctl bootstrap gui/{uid} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        Self {
            service: format!("gui/{uid}/{label}"),
        }
    }

    /// The process launchd runs the job as, from `launchctl print`.
    fn pid(&self) -> Option<u32> {
        let printed = Command::new("launchctl")
            .arg("print")
            .arg(&self.service)
            .output()
            .expect("run launchctl");
        assert!(
            printed.status.success(),
            "launchctl print {} failed: {}",
            self.service,
            String::from_utf8_lossy(&printed.stderr)
        );
        String::from_utf8_lossy(&printed.stdout)
            .lines()
            .find_map(|line| line.trim().strip_prefix("pid = ")?.trim().parse().ok())
    }
}

impl Drop for Loaded {
    fn drop(&mut self) {
        // Stops the job with it; nothing of the test is left in launchd.
        let _ = Command::new("launchctl")
            .arg("bootout")
            .arg(&self.service)
            .output();
    }
}

/// What a failure of the test shows: the daemon's log and launchd's view of
/// the job.
fn describe(agent: &Loaded, daemon: &PrivateDaemon) -> String {
    let printed = Command::new("launchctl")
        .arg("print")
        .arg(&agent.service)
        .output()
        .expect("run launchctl");
    format!(
        "daemon log:\n{}\nlaunchctl print {}:\n{}",
        daemon.log_lines("").join("\n"),
        agent.service,
        String::from_utf8_lossy(&printed.stdout)
    )
}

fn until<T>(what: &str, describe: impl Fn() -> String, mut found: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + BOUND;
    loop {
        if let Some(value) = found() {
            return value;
        }
        assert!(Instant::now() < deadline, "{what}:\n{}", describe());
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Retire the daemon of `run_dir` onto `exe`.
fn retire(run_dir: &Path, exe: &Path) -> Response {
    use std::os::unix::ffi::OsStrExt as _;

    let mut stream =
        std::os::unix::net::UnixStream::connect(run_dir.join("daemon.sock")).expect("connect");
    let mut bytes = stow_cli::protocol::encode(&Hello::new(Role::Control, exe)).expect("encode");
    bytes.extend(
        stow_cli::protocol::encode(&ControlRequest::Retire {
            executable: exe.as_os_str().as_bytes().to_vec(),
        })
        .expect("encode"),
    );
    stream.write_all(&bytes).expect("send");
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let answer = stow_cli::protocol::read_frame(&mut stream)
            .and_then(|frame| stow_cli::protocol::read_response(&frame));
        let _ = sender.send(answer.map_err(|error| error.to_string()));
    });
    receiver
        .recv_timeout(BOUND)
        .expect("the daemon answered")
        .expect("a response")
}

#[test]
fn a_daemon_launchd_runs_keeps_its_job_and_process_across_a_retire() {
    if std::env::var_os("GITHUB_ACTIONS").is_none()
        && std::env::var_os("STOW_TEST_LAUNCHD").is_none()
    {
        eprintln!(
            "not run: it bootstraps a launch agent into the user's GUI domain; \
             set STOW_TEST_LAUNCHD=1 to run it"
        );
        return;
    }
    let home = support::tempdir().expect("home");
    let daemon = PrivateDaemon::in_home(home.path());
    let run_dir = daemon.run_dir().to_owned();
    // The daemon starts only in an owner-only directory.
    std::fs::create_dir_all(&run_dir).expect("run dir");
    std::fs::set_permissions(
        &run_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("restrict the run dir");
    let stow = PathBuf::from(env!("CARGO_BIN_EXE_stow-cli"));
    let label = format!("dev.waterui.stow-test.{}", std::process::id());
    let plist = home.path().join(format!("{label}.plist"));
    let rendered = Agent {
        label: &label,
        program: stow.to_str().expect("utf-8 path"),
        run_dir: run_dir.to_str().expect("utf-8 path"),
    }
    .render()
    .expect("render the agent");
    std::fs::write(&plist, rendered).expect("write the plist");

    let agent = Loaded::bootstrap(&label, &plist);
    // RunAtLoad starts the daemon.
    let job = until(
        "launchd never started the daemon",
        || describe(&agent, &daemon),
        || daemon.serving_pids().first().copied(),
    );
    assert_eq!(agent.pid(), Some(job), "launchd runs the daemon it started");

    let reply = retire(&run_dir, &stow);
    assert!(matches!(reply, Response::Retiring { .. }), "{reply:?}");
    until(
        "the daemon never served again",
        || describe(&agent, &daemon),
        || (daemon.log_lines("stow daemon serving").len() == 2).then_some(()),
    );

    // The image was replaced in place: one process, the one launchd holds,
    // and launchd started nothing beside it.
    assert_eq!(daemon.serving_pids(), [job], "the successor has the pid");
    assert_eq!(agent.pid(), Some(job), "launchd still runs that process");
    assert_eq!(
        daemon.log_lines("stow daemon process started").len(),
        2,
        "no second daemon started:\n{}",
        daemon.log_lines("").join("\n")
    );
    assert!(
        daemon
            .log_lines("another stow daemon holds the lock")
            .is_empty(),
        "launchd started a daemon beside the first:\n{}",
        daemon.log_lines("").join("\n")
    );
}
