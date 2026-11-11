//! Builds are sessions of one per-user daemon (stow#1453): several run at
//! once on one daemon without seeing each other's units, a daemon that
//! dies under a build fails it naming the daemon, and a driver that dies
//! ends its session.
//!
//! Every build's script holds it open until the test releases it, so the
//! test acts while the sessions are open: the script writes the session
//! the build runs under (cargo's environment names it) into a rendezvous
//! directory and waits for a `release` file.

mod support;

// The shared fixture carries helpers this test does not call; each
// integration binary lints them per target.
#[allow(dead_code)]
mod build_fixture;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use build_fixture::{
    refused_url, stored_entries, stow_build_command, stow_setup_in, write_fixture,
};
use support::{PrivateDaemon, hermetic_stow_env};

/// How long a test waits for something a healthy build or daemon does
/// without being held up.
const BOUND: Duration = Duration::from_secs(60);

/// The build script every project carries.
const RENDEZVOUS_BUILD_SCRIPT: &str = include_str!("fixtures/rendezvous_build.rs");

/// One project to build: its own sources, cargo home, cache and target.
struct Project {
    name: &'static str,
    dir: support::TempDir,
    cargo_home: support::TempDir,
    cache: support::TempDir,
    target: support::TempDir,
}

impl Project {
    fn new(name: &'static str, dependencies: &str) -> Self {
        let project = Self {
            name,
            dir: support::tempdir().expect("project dir"),
            cargo_home: support::tempdir().expect("cargo home"),
            cache: support::tempdir().expect("cache dir"),
            target: support::tempdir().expect("target dir"),
        };
        write_fixture(project.dir.path(), project.cargo_home.path(), dependencies);
        std::fs::write(project.dir.path().join("build.rs"), RENDEZVOUS_BUILD_SCRIPT)
            .expect("write the build script");
        stow_setup_in(project.dir.path(), project.cargo_home.path());
        project
    }

    /// The home this project's `stow-cli` runs seal.
    fn home(&self) -> PathBuf {
        self.dir.path().join("stow-home")
    }

    /// The build, on the daemon whose run directory is `run_dir`, held
    /// open by the build script until `rendezvous` holds a `release`.
    fn build(&self, run_dir: &Path, rendezvous: &Path) -> Command {
        let edge = refused_url();
        let registry = refused_url();
        let mut command = stow_build_command(
            self.dir.path(),
            &["build", "--offline"],
            &edge,
            &registry,
            self.cache.path(),
            self.cargo_home.path(),
            self.target.path(),
            &[
                ("STOW_DAEMON_DIR", utf8(run_dir)),
                ("STOW_TEST_RENDEZVOUS", utf8(rendezvous)),
                ("STOW_TEST_BUILD_NAME", self.name),
            ],
            true,
        );
        command.stdin(Stdio::null());
        command
    }

    /// The crates the project's local cache holds.
    fn stored_crates(&self) -> Vec<String> {
        let mut crates: Vec<String> = stored_entries(&self.cache.path().join("state-v3.sqlite3"))
            .into_iter()
            .map(|entry| entry.crate_name)
            .collect();
        crates.sort();
        crates.dedup();
        crates
    }
}

fn utf8(path: &Path) -> &str {
    path.to_str().expect("a utf-8 path")
}

/// The session `name`'s build runs under, once its script announced it.
fn session_of(rendezvous: &Path, name: &str) -> String {
    let file = rendezvous.join(format!("{name}.started"));
    let deadline = Instant::now() + BOUND;
    loop {
        if let Ok(session) = std::fs::read_to_string(&file) {
            return session;
        }
        assert!(
            Instant::now() < deadline,
            "the {name} build never reached its build script"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn release(rendezvous: &Path) {
    std::fs::write(rendezvous.join("release"), b"").expect("release the builds");
}

/// Wait for `child` to exit, within [`BOUND`], and collect its output.
fn finish(mut child: Child, what: &str) -> std::process::Output {
    let deadline = Instant::now() + BOUND;
    while child.try_wait().expect("poll the child").is_none() {
        assert!(Instant::now() < deadline, "{what} did not finish");
        std::thread::sleep(Duration::from_millis(20));
    }
    child
        .wait_with_output()
        .expect("collect the child's output")
}

fn stderr_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn spawn(mut command: Command) -> Child {
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start stow build")
}

/// Two builds on one daemon, both inside their build scripts at once: one
/// daemon, two sessions, and a request that names one build's session but
/// the other build's directory is refused.
#[test]
fn one_daemon_serves_two_concurrent_builds_and_neither_sees_the_others_session() {
    // The shared daemon's home: its run directory is what both builds name.
    let shared = support::tempdir().expect("shared home");
    let daemon = PrivateDaemon::in_home(shared.path());
    let rendezvous = support::tempdir().expect("rendezvous");
    let alpha = Project::new("alpha", "cfg-if = \"1\"\n");
    let beta = Project::new("beta", "unicode-ident = \"1\"\n");

    let alpha_build = spawn(alpha.build(daemon.run_dir(), rendezvous.path()));
    let beta_build = spawn(beta.build(daemon.run_dir(), rendezvous.path()));
    let alpha_session = session_of(rendezvous.path(), "alpha");
    let beta_session = session_of(rendezvous.path(), "beta");
    assert_ne!(alpha_session, beta_session, "two builds share one session");
    assert_eq!(
        daemon.log_lines("stow daemon serving").len(),
        1,
        "the builds started more than one daemon"
    );
    assert_eq!(
        daemon.log_lines("opened a session").len(),
        2,
        "the daemon opened a session per build"
    );

    // Alpha's session, naming beta's target directory: a wrapper cannot
    // reach another build's outputs through its own session.
    let beta_deps = beta.target.path().join("debug").join("deps");
    let mut stray = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
    stray
        .arg("rustc")
        .arg(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned()))
        .args(["--crate-name", "stray", "--crate-type", "lib", "--out-dir"])
        .arg(&beta_deps)
        .current_dir(alpha.dir.path());
    hermetic_stow_env(
        &mut stray,
        &refused_url(),
        alpha.cache.path(),
        &alpha.home(),
    );
    let stray = stray
        .env("STOW_DAEMON_DIR", daemon.run_dir())
        .env("STOW_SESSION", &alpha_session)
        .output()
        .expect("run the stray wrapper");
    assert!(
        !stray.status.success(),
        "a request naming another build's directory was served"
    );
    assert!(
        stderr_of(&stray).contains("out-dir"),
        "the refusal does not name the directory:\n{}",
        stderr_of(&stray)
    );

    release(rendezvous.path());
    let alpha_output = finish(alpha_build, "the alpha build");
    let beta_output = finish(beta_build, "the beta build");
    // The refused request was made in alpha's session, and a refusal fails
    // the build that owns it; beta's session never heard of it.
    assert!(
        !alpha_output.status.success() && stderr_of(&alpha_output).contains("out-dir"),
        "alpha's session did not report the refused request:\n{}",
        stderr_of(&alpha_output)
    );
    assert!(
        beta_output.status.success(),
        "beta failed:\n{}",
        stderr_of(&beta_output)
    );

    // Each build stored its own crates and none of the other's.
    assert_eq!(alpha.stored_crates(), ["cfg-if"]);
    assert_eq!(beta.stored_crates(), ["unicode-ident"]);
    assert_eq!(
        daemon.log_lines("ended a session").len(),
        2,
        "every session ended with its build"
    );
}

/// A daemon that dies under a running build fails the build, and the
/// failure names the daemon.
#[test]
fn a_build_whose_daemon_dies_fails_naming_it() {
    let home = support::tempdir().expect("daemon home");
    let daemon = PrivateDaemon::in_home(home.path());
    let rendezvous = support::tempdir().expect("rendezvous");
    let project = Project::new("lone", "cfg-if = \"1\"\n");

    let build = spawn(project.build(daemon.run_dir(), rendezvous.path()));
    session_of(rendezvous.path(), "lone");
    let pids = daemon.serving_pids();
    assert_eq!(pids.len(), 1, "one daemon serves the build");
    daemon.crash();

    let output = finish(build, "the build whose daemon died");
    assert!(
        !output.status.success(),
        "a build survived the loss of its daemon"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains(&format!("pid {}", pids[0])) && stderr.contains("daemon.log"),
        "the failure does not name the daemon:\n{stderr}"
    );
    // The orphaned build script leaves with the release.
    release(rendezvous.path());
}

/// A daemon that speaks a protocol outside this stow's range fails the
/// build before cargo runs, and the failure names the daemon by pid and
/// log and says what each side speaks. The daemon here is a listener that
/// answers every connection with a frame stamped with a protocol number
/// nothing speaks.
#[cfg(unix)]
#[test]
fn a_daemon_outside_the_protocol_range_fails_the_build_naming_it() {
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;

    /// A protocol number no stow has spoken or will soon.
    const FOREIGN_PROTOCOL: u16 = 9999;

    let home = support::tempdir().expect("daemon home");
    let daemon = PrivateDaemon::in_home(home.path());
    let run_dir = daemon.run_dir().to_owned();
    std::fs::create_dir_all(&run_dir).expect("run dir");
    std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o700))
        .expect("restrict the run dir");
    // The line the daemon logs when it binds its endpoint, which is where
    // an error finds the pid to name.
    std::fs::write(
        run_dir.join("daemon.log"),
        "INFO stow daemon serving pid=4242 endpoint=daemon.sock\n",
    )
    .expect("write the daemon log");
    let listener = UnixListener::bind(run_dir.join("daemon.sock")).expect("bind the daemon");
    let json = br#"{"response":"Status","stow_version":"0.0.0","protocol":9999}"#;
    let mut reply = u32::try_from(json.len() + 2)
        .expect("length")
        .to_be_bytes()
        .to_vec();
    reply.extend_from_slice(&FOREIGN_PROTOCOL.to_be_bytes());
    reply.extend_from_slice(json);
    let serving = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept the client");
        // The client's `Hello` and `Status`, written together.
        let mut hello = [0; 1];
        stream.read_exact(&mut hello).expect("read the hello");
        stream.write_all(&reply).expect("answer");
    });

    let rendezvous = support::tempdir().expect("rendezvous");
    let project = Project::new("foreign", "cfg-if = \"1\"\n");
    let output = finish(
        spawn(project.build(&run_dir, rendezvous.path())),
        "the build against a foreign daemon",
    );
    serving.join().expect("the fake daemon served");
    assert!(
        !output.status.success(),
        "a build ran against a daemon of another protocol"
    );
    let stderr = stderr_of(&output);
    for expected in [
        "pid 4242",
        "daemon.log",
        &format!("protocol {FOREIGN_PROTOCOL}"),
        "this stow speaks",
        " through ",
    ] {
        assert!(
            stderr.contains(expected),
            "the failure does not say `{expected}`:\n{stderr}"
        );
    }
    release(rendezvous.path());
}

/// A driver that dies without ending its session does not leave the
/// session behind: the daemon ends it when the connection closes.
#[test]
fn a_killed_driver_ends_its_session() {
    let home = support::tempdir().expect("daemon home");
    let daemon = PrivateDaemon::in_home(home.path());
    let rendezvous = support::tempdir().expect("rendezvous");
    let project = Project::new("doomed", "cfg-if = \"1\"\n");

    let mut build = spawn(project.build(daemon.run_dir(), rendezvous.path()));
    let session = session_of(rendezvous.path(), "doomed");
    build.kill().expect("kill the driver");
    build.wait().expect("reap the driver");

    let deadline = Instant::now() + BOUND;
    while !daemon
        .log_lines("went away")
        .iter()
        .any(|line| line.contains(&session))
    {
        assert!(
            Instant::now() < deadline,
            "the daemon never ended the killed driver's session {session}:\n{}",
            daemon.log_lines("").join("\n")
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    release(rendezvous.path());
}
