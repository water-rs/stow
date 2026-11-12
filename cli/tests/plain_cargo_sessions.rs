//! A plain `cargo build` through the wrapper shim has no driver: the daemon
//! opens a session of the cargo the wrapper runs under and ends it when that
//! cargo exits.

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use support::{PrivateDaemon, hermetic_stow_env};

/// Longer than the daemon takes to notice an exited cargo and end its
/// session; a session that never ends fails the test here.
const END_LIMIT: Duration = Duration::from_secs(60);

/// The tools directory `stow setup` produces: the wrapper's name and the
/// runtime link the wrapper starts the daemon from, both this binary.
fn install_shims(tools: &Path) -> PathBuf {
    let exe = env!("CARGO_BIN_EXE_stow-cli");
    let suffix = std::env::consts::EXE_SUFFIX;
    let shim = tools.join(format!("stow-rustc-wrapper{suffix}"));
    let runtime = tools.join(format!("stow-runtime{suffix}"));
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(exe, &shim).expect("link the wrapper");
        std::os::unix::fs::symlink(exe, &runtime).expect("link the runtime");
    }
    #[cfg(windows)]
    {
        std::fs::copy(exe, &shim).expect("copy the wrapper");
        std::fs::copy(exe, &runtime).expect("copy the runtime");
    }
    shim
}

fn write_crate(dir: &Path) {
    write_named_crate(dir, "plain");
}

fn write_named_crate(dir: &Path, name: &str) {
    std::fs::create_dir_all(dir.join("src")).expect("src dir");
    std::fs::write(
        dir.join("Cargo.toml"),
        format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
    )
    .expect("manifest");
    std::fs::write(dir.join("src").join("lib.rs"), "pub fn one() -> u8 { 1 }\n").expect("lib");
}

/// Wait until the daemon has logged `needle`.
fn wait_for_log(daemon: &PrivateDaemon, needle: &str) -> Vec<String> {
    let deadline = Instant::now() + END_LIMIT;
    loop {
        let lines = daemon.log_lines(needle);
        if !lines.is_empty() {
            return lines;
        }
        assert!(
            Instant::now() < deadline,
            "the daemon never logged {needle:?}:\n{}",
            daemon.log_lines("").join("\n")
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A plain `cargo build` of the project in `dir`, its rustc wrapped by
/// `shim` when there is one.
fn cargo_build_command(
    dir: &Path,
    cargo_home: &Path,
    shim: Option<&Path>,
    cache: &Path,
    target: &Path,
) -> Command {
    cargo_build_command_in(dir, &dir.join("stow-home"), cargo_home, shim, cache, target)
}

/// [`cargo_build_command`] with the build's stow home, and so its daemon,
/// named: two builds of different projects share a daemon by sharing it.
fn cargo_build_command_in(
    dir: &Path,
    home: &Path,
    cargo_home: &Path,
    shim: Option<&Path>,
    cache: &Path,
    target: &Path,
) -> Command {
    let mut command = support::cargo_command();
    hermetic_stow_env(&mut command, &support::denied_registry(), cache, home);
    command
        .arg("build")
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_TARGET_DIR", target)
        .env("CARGO_INCREMENTAL", "0");
    if let Some(shim) = shim {
        command.env("RUSTC_WRAPPER", shim);
    }
    command
}

fn build(dir: &Path, cargo_home: &Path, shim: &Path, cache: &Path, target: &Path) {
    let output = cargo_build_command(dir, cargo_home, Some(shim), cache, target)
        .output()
        .expect("run cargo build");
    assert!(
        output.status.success(),
        "cargo build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_plain_cargo_build_gets_a_session_that_ends_with_its_cargo() {
    let dir = support::tempdir().expect("temp dir");
    let cache = support::tempdir().expect("cache dir");
    let cargo_home = support::tempdir().expect("cargo home");
    let tools = support::tempdir().expect("tools dir");
    write_crate(dir.path());
    support::write_global_config(
        &[&dir.path().join("stow-home")],
        "[cache]\nremote = false\n",
    );
    let shim = install_shims(tools.path());
    // The wrapper starts the daemon under the build's home; it is stopped
    // with the test.
    let daemon = PrivateDaemon::in_home(&dir.path().join("stow-home"));

    build(
        dir.path(),
        cargo_home.path(),
        &shim,
        cache.path(),
        &dir.path().join("target"),
    );

    let opened = daemon.log_lines("opened a session for a cargo");
    assert_eq!(opened.len(), 1, "one session for one cargo: {opened:?}");
    // The cargo has exited, so its session ends by itself.
    wait_for_log(&daemon, "ended a cargo's session");
    assert_eq!(
        daemon.serving_pids().len(),
        1,
        "the first wrapper started one daemon"
    );
}

#[test]
fn two_builds_get_two_sessions_on_one_daemon() {
    let dir = support::tempdir().expect("temp dir");
    let cache = support::tempdir().expect("cache dir");
    let cargo_home = support::tempdir().expect("cargo home");
    let tools = support::tempdir().expect("tools dir");
    write_crate(dir.path());
    support::write_global_config(
        &[&dir.path().join("stow-home")],
        "[cache]\nremote = false\n",
    );
    let shim = install_shims(tools.path());
    let daemon = PrivateDaemon::in_home(&dir.path().join("stow-home"));

    for target in ["target-a", "target-b"] {
        build(
            dir.path(),
            cargo_home.path(),
            &shim,
            cache.path(),
            &dir.path().join(target),
        );
    }

    assert_eq!(
        daemon.log_lines("opened a session for a cargo").len(),
        2,
        "each cargo has its own session"
    );
    assert_eq!(daemon.serving_pids().len(), 1, "both share one daemon");
}

/// The wrapper's own command line for a rustc invocation: what cargo runs,
/// the rustc to wrap first.
fn wrapper_command(shim: &Path, dir: &Path, cache: &Path) -> Command {
    let mut command = Command::new(shim);
    hermetic_stow_env(
        &mut command,
        &support::denied_registry(),
        cache,
        &dir.join("stow-home"),
    );
    command.current_dir(dir).arg("rustc");
    command
}

/// The wrapper's command line for the demo crate's lib unit, compiled into
/// `out_dir`, run with no `CARGO` so its parent owns its session.
fn lib_unit_command(shim: &Path, dir: &Path, cache: &Path, out_dir: &Path) -> Command {
    let mut command = wrapper_command(shim, dir, cache);
    command
        .args([
            "--crate-name",
            "plain",
            "--edition",
            "2021",
            "--crate-type",
            "lib",
        ])
        .args(["--emit=link", "-C", "metadata=0123abcd"])
        .args(["-C", "extra-filename=-0123abcd", "--out-dir"])
        .arg(out_dir)
        .arg(dir.join("src").join("lib.rs"))
        .env_remove("CARGO");
    command
}

/// A probe — `-vV`, `--print` — has nothing to cache and no build to
/// belong to: the wrapper runs it as the daemon answers, and the daemon
/// opens no session for it.
#[test]
fn a_probe_is_answered_without_a_session() {
    let dir = support::tempdir().expect("temp dir");
    let cache = support::tempdir().expect("cache dir");
    let tools = support::tempdir().expect("tools dir");
    let shim = install_shims(tools.path());
    let daemon = PrivateDaemon::in_home(&dir.path().join("stow-home"));

    for probe in [&["-vV"][..], &["--print", "cfg"][..]] {
        let expected = Command::new("rustc")
            .args(probe)
            .output()
            .expect("run rustc directly");
        assert!(expected.status.success(), "rustc {probe:?} failed");
        let output = wrapper_command(&shim, dir.path(), cache.path())
            .args(probe)
            .output()
            .expect("run the wrapper");
        assert!(
            output.status.success(),
            "the wrapper failed {probe:?}:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&expected.stdout),
            "the wrapper changed the answer to {probe:?}"
        );
    }

    assert_eq!(
        daemon.serving_pids().len(),
        1,
        "the first probe started the daemon"
    );
    assert!(
        daemon.log_lines("opened a session").is_empty(),
        "a probe opened a session: {:?}",
        daemon.log_lines("opened a session")
    );
}

/// A wrapper whose environment has no `CARGO` has no cargo to find among
/// its ancestors: its parent owns the session.
#[test]
fn a_wrapper_with_no_cargo_variable_is_owned_by_its_parent() {
    let dir = support::tempdir().expect("temp dir");
    let cache = support::tempdir().expect("cache dir");
    let tools = support::tempdir().expect("tools dir");
    write_crate(dir.path());
    support::write_global_config(
        &[&dir.path().join("stow-home")],
        "[cache]\nremote = false\n",
    );
    let shim = install_shims(tools.path());
    let daemon = PrivateDaemon::in_home(&dir.path().join("stow-home"));

    let out_dir = dir.path().join("target").join("debug").join("deps");
    let output = lib_unit_command(&shim, dir.path(), cache.path(), &out_dir)
        .output()
        .expect("run the wrapper");
    assert!(
        output.status.success(),
        "the wrapper failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        out_dir.join("libplain-0123abcd.rlib").is_file(),
        "the unit was not compiled into {}",
        out_dir.display()
    );

    // This test process started the wrapper, so it owns the session.
    let opened = daemon.log_lines("opened a session for a cargo");
    assert_eq!(opened.len(), 1, "one session: {opened:?}");
    assert!(
        opened[0].contains(&format!("pid {} started", std::process::id())),
        "the session is not the parent's: {}",
        opened[0]
    );
}

/// A build script's C compiler reaches the daemon before any rustc unit of
/// the build when the build's rustc is not wrapped: the daemon opens the
/// session from the build script's environment, stores the object, and the
/// next build's compiler wrapper is served it.
#[cfg(unix)]
#[test]
fn a_build_scripts_c_compiler_opens_the_session_and_is_cached() {
    if Command::new("cc").arg("--version").output().is_err() {
        return;
    }
    let dir = support::tempdir().expect("temp dir");
    let cache = support::tempdir().expect("cache dir");
    let cargo_home = support::tempdir().expect("cargo home");
    let tools = support::tempdir().expect("tools dir");
    write_crate(dir.path());
    std::fs::write(
        dir.path().join("build.rs"),
        r#"
fn main() {
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let cc = std::env::var_os("STOW_TEST_CC").expect("STOW_TEST_CC");
    std::fs::write(out.join("probe.c"), "int probe(void) { return 7; }\n").expect("write probe.c");
    let status = std::process::Command::new(cc)
        .current_dir(&out)
        .args(["-c", "probe.c", "-o", "probe.o"])
        .status()
        .expect("run the C compiler");
    assert!(status.success());
}
"#,
    )
    .expect("write the build script");
    support::write_global_config(
        &[&dir.path().join("stow-home")],
        "[cache]\nremote = false\n",
    );
    // The `CC` shim: the runtime under the compiler's name, with the
    // runtime link the wrapper starts the daemon from beside it.
    let _ = install_shims(tools.path());
    let cc_shim = tools.path().join("stow-cc");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stow-cli"), &cc_shim).expect("link the cc shim");
    let daemon = PrivateDaemon::in_home(&dir.path().join("stow-home"));

    for (round, target) in ["target-a", "target-b"].into_iter().enumerate() {
        let mut command = cargo_build_command(
            dir.path(),
            cargo_home.path(),
            None,
            cache.path(),
            &dir.path().join(target),
        );
        command.env("STOW_TEST_CC", &cc_shim);
        let output = support::output_after_session(&mut command, &dir.path().join("stow-home"));
        assert!(
            output.status.success(),
            "cargo build failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            daemon.log_lines("opened a session for a cargo").len(),
            round + 1,
            "each build's C compiler opened the session of its cargo"
        );
    }
    assert!(
        !daemon.log_lines("stored C/C++ compilation").is_empty(),
        "the first build's object was never stored:\n{}",
        daemon.log_lines("").join("\n")
    );
    assert!(
        !daemon.log_lines("served C/C++ compilation").is_empty(),
        "the second build's object was not served from the cache:\n{}",
        daemon.log_lines("").join("\n")
    );
}

/// A plain build held in its build script: cargo has started the wrapper
/// that started the daemon, and the script waits on the test's rendezvous
/// directory.
struct ScriptBuild {
    /// Stops the daemon first, while its log still exists.
    daemon: PrivateDaemon,
    cargo: std::process::Child,
    cargo_pid: u32,
    home: PathBuf,
    rendezvous: support::TempDir,
    /// Kept for as long as the build runs.
    _dirs: [support::TempDir; 4],
}

impl ScriptBuild {
    /// Start `cargo build` of a crate whose build script holds until the
    /// test releases it, and wait until the script is running.
    fn start() -> Self {
        let dir = support::tempdir().expect("temp dir");
        let cache = support::tempdir().expect("cache dir");
        let cargo_home = support::tempdir().expect("cargo home");
        let tools = support::tempdir().expect("tools dir");
        let rendezvous = support::tempdir().expect("rendezvous");
        write_crate(dir.path());
        std::fs::write(
            dir.path().join("build.rs"),
            include_str!("fixtures/rendezvous_build.rs"),
        )
        .expect("write the build script");
        let home = dir.path().join("stow-home");
        support::write_global_config(&[&home], "[cache]\nremote = false\n");
        let shim = install_shims(tools.path());
        let daemon = PrivateDaemon::in_home(&home);

        let cargo = cargo_build_command(
            dir.path(),
            cargo_home.path(),
            Some(&shim),
            cache.path(),
            &dir.path().join("target"),
        )
        .env("STOW_TEST_RENDEZVOUS", rendezvous.path())
        .env("STOW_TEST_BUILD_NAME", "held")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start cargo");
        let cargo_pid = cargo.id();
        let build = Self {
            daemon,
            cargo,
            cargo_pid,
            home,
            rendezvous,
            _dirs: [dir, cache, cargo_home, tools],
        };

        // The script's own compile went through the wrapper, which opened
        // the session before the script ran.
        let started = build.rendezvous.path().join("held.started");
        let deadline = Instant::now() + END_LIMIT;
        while !started.exists() {
            assert!(
                Instant::now() < deadline,
                "the build never reached its script"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        build
    }

    /// Kill cargo alone and wait for the daemon to end its session. The
    /// script and compilers are other processes, which neither `kill` nor
    /// the termination call takes with it.
    fn kill_cargo(&mut self) {
        self.cargo.kill().expect("kill cargo");
        self.cargo.wait().expect("reap cargo");
        self.daemon.wait_session_ended(self.cargo_pid);
    }

    /// Let the held script finish.
    fn release_script(&self) {
        std::fs::write(self.rendezvous.path().join("release"), b"").expect("release the script");
    }
}

/// A cargo killed under its build script ends its session at once. On Unix
/// the script it left behind runs on: the session follows the cargo, not
/// the processes cargo started. On Windows cargo's job object ends the
/// script with it, whatever stow does.
#[test]
fn a_killed_cargo_ends_its_session_while_its_build_script_lives() {
    let mut build = ScriptBuild::start();
    build.kill_cargo();
    assert!(
        !build.rendezvous.path().join("held.finished").exists(),
        "the script was still held when the session ended"
    );
    assert!(
        std::fs::read_dir(build.daemon.run_dir().join("sessions"))
            .into_iter()
            .flatten()
            .next()
            .is_none(),
        "the ended session's directory is still there"
    );

    // Release the orphaned script, and see that it lived to finish.
    #[cfg(unix)]
    {
        build.release_script();
        let finished = build.rendezvous.path().join("held.finished");
        let deadline = Instant::now() + END_LIMIT;
        while !finished.exists() {
            assert!(
                Instant::now() < deadline,
                "the script did not outlive its cargo"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// The daemon a build's wrapper started serves every build of the user, so
/// it outlives the cargo that started it: killing that cargo — as Ctrl-C
/// does — leaves it running. On Windows cargo's job object ends every
/// process the cargo's wrappers start, so only a daemon the Task Scheduler
/// started survives.
#[test]
fn a_daemon_started_for_a_build_outlives_the_cargo_killed_under_it() {
    let mut build = ScriptBuild::start();
    let started = build.daemon.serving_pids();
    assert_eq!(
        started.len(),
        1,
        "the build's wrapper starts one daemon:\n{}",
        build.daemon.log_lines("").join("\n")
    );
    build.kill_cargo();

    // A client of the daemon finds the one that is running: a daemon that
    // died with the cargo would be started afresh, and log serving again.
    let mut status = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
    status.args(["daemon", "status"]).stdin(Stdio::null());
    support::sealed_home_env(&mut status, &build.home);
    let output = status.output().expect("ask the daemon for its status");
    assert!(
        output.status.success(),
        "the daemon did not answer after its starter's cargo was killed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        build.daemon.serving_pids(),
        started,
        "the daemon that served the build ended with its cargo:\n{}",
        build.daemon.log_lines("").join("\n")
    );
    build.release_script();
}

/// What the daemon logs at `warn` while deciding a plain build's request
/// reaches that wrapper's stderr, since no driver's terminal carries it: a
/// unit named for an output directory outside the build's target is refused
/// and logged, and the wrapper prints the daemon's record of it.
#[test]
fn a_plain_builds_refusal_warning_reaches_the_wrappers_stderr() {
    let dir = support::tempdir().expect("temp dir");
    let cache = support::tempdir().expect("cache dir");
    let tools = support::tempdir().expect("tools dir");
    write_crate(dir.path());
    support::write_global_config(
        &[&dir.path().join("stow-home")],
        "[cache]\nremote = false\n",
    );
    let shim = install_shims(tools.path());
    let _daemon = PrivateDaemon::in_home(&dir.path().join("stow-home"));
    let deps = |target: &str| dir.path().join(target).join("debug").join("deps");

    let opened = lib_unit_command(&shim, dir.path(), cache.path(), &deps("target"))
        .output()
        .expect("run the wrapper");
    assert!(
        opened.status.success(),
        "the opening unit failed:\n{}",
        String::from_utf8_lossy(&opened.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&opened.stderr).contains("daemon_target"),
        "a request the daemon had nothing to warn about printed a record:\n{}",
        String::from_utf8_lossy(&opened.stderr)
    );

    let refused = lib_unit_command(&shim, dir.path(), cache.path(), &deps("elsewhere"))
        .output()
        .expect("run the wrapper");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !refused.status.success(),
        "a unit outside the build's target directory was served:\n{stderr}"
    );
    // The wrapper's own failure message is one line; the daemon's record of
    // what it logged carries the module that logged it.
    assert!(
        stderr.contains("daemon_target=") && stderr.contains("refused a"),
        "the daemon's warning did not reach the wrapper:\n{stderr}"
    );
}

/// A daemon that restarts under a running cargo has lost the session's
/// in-flight state and provenance marks: the new daemon refuses that
/// cargo's wrappers, so the build fails naming the restart instead of
/// compiling against marks that no longer exist. Once the cargo has exited
/// the refusal and its record are gone.
#[test]
fn a_cargo_whose_daemon_restarted_is_refused_until_it_exits() {
    let dir = support::tempdir().expect("temp dir");
    let cache = support::tempdir().expect("cache dir");
    let cargo_home = support::tempdir().expect("cargo home");
    let tools = support::tempdir().expect("tools dir");
    let rendezvous = support::tempdir().expect("rendezvous");
    write_crate(dir.path());
    std::fs::write(
        dir.path().join("build.rs"),
        include_str!("fixtures/rendezvous_build.rs"),
    )
    .expect("write the build script");
    support::write_global_config(
        &[&dir.path().join("stow-home")],
        "[cache]\nremote = false\n",
    );
    let shim = install_shims(tools.path());
    let daemon = PrivateDaemon::in_home(&dir.path().join("stow-home"));

    let cargo = cargo_build_command(
        dir.path(),
        cargo_home.path(),
        Some(&shim),
        cache.path(),
        &dir.path().join("target"),
    )
    .env("STOW_TEST_RENDEZVOUS", rendezvous.path())
    .env("STOW_TEST_BUILD_NAME", "held")
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .expect("start cargo");

    // The script's own compile opened the session before the script ran.
    let started = rendezvous.path().join("held.started");
    let deadline = Instant::now() + END_LIMIT;
    while !started.exists() {
        assert!(
            Instant::now() < deadline,
            "the build never reached its script"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(daemon.log_lines("opened a session for a cargo").len(), 1);

    // The daemon dies under the build; the next wrapper starts another.
    daemon.crash();
    std::fs::write(rendezvous.path().join("release"), b"").expect("release the script");
    let output = cargo.wait_with_output().expect("wait for cargo");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "the build went on against a restarted daemon:\n{stderr}"
    );
    assert!(
        stderr.contains("the stow daemon restarted during this cargo build"),
        "the failure does not name the restart:\n{stderr}"
    );
    assert!(
        stderr.contains("daemon.log"),
        "the failure does not name the daemon's log:\n{stderr}"
    );
    assert_eq!(
        daemon.serving_pids().len(),
        2,
        "a second daemon served the cargo's wrappers"
    );

    // The cargo is gone: nothing refuses it, and nothing of it is kept.
    wait_for_log(
        &daemon,
        "a cargo that outlived the previous daemon has exited",
    );
    let sessions = daemon.run_dir().join("sessions");
    let deadline = Instant::now() + END_LIMIT;
    while std::fs::read_dir(&sessions)
        .into_iter()
        .flatten()
        .next()
        .is_some()
    {
        assert!(
            Instant::now() < deadline,
            "the record of the exited cargo is still in {}",
            sessions.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Every file under `dir`, by path relative to it.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    fn walk(root: &Path, dir: &Path, found: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, found);
            } else {
                found.push(path.strip_prefix(root).expect("under root").to_owned());
            }
        }
    }
    let mut found = Vec::new();
    walk(dir, dir, &mut found);
    found
}

/// Whether one of `marks` is the mark of a crate whose name starts with
/// `prefix`: a mark is `<crate name>-<hash>`.
fn names_crate(marks: &[PathBuf], prefix: &str) -> bool {
    marks.iter().any(|mark| {
        mark.file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with(prefix))
    })
}

/// A build held inside its build script by the rendezvous fixture.
struct HeldBuild {
    dir: support::TempDir,
    _cache: support::TempDir,
    rendezvous: support::TempDir,
    cargo: std::process::Child,
}

/// Start a plain build of a project named `name` (a crate with a path
/// dependency, `dep_<name>`, and the rendezvous build script) that holds
/// inside its script until the test releases it. The dependency compiles
/// while the script holds, and its mark is the session's record of it.
fn start_held_build(name: &str, stow_home: &Path, cargo_home: &Path, shim: &Path) -> HeldBuild {
    let dir = support::tempdir().expect("project dir");
    let cache = support::tempdir().expect("cache dir");
    let rendezvous = support::tempdir().expect("rendezvous");
    let crate_name = name.replace('-', "_");
    write_named_crate(dir.path(), &crate_name);
    let dependency = format!("dep_{crate_name}");
    std::fs::create_dir_all(dir.path().join("dep").join("src")).expect("dependency dir");
    std::fs::write(
        dir.path().join("dep").join("Cargo.toml"),
        format!("[package]\nname = \"{dependency}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
    )
    .expect("dependency manifest");
    std::fs::write(
        dir.path().join("dep").join("src").join("lib.rs"),
        "pub fn two() -> u8 { 2 }\n",
    )
    .expect("dependency lib");
    std::fs::write(
        dir.path().join("Cargo.toml"),
        format!(
            "[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\n{dependency} = {{ path = \"dep\" }}\n"
        ),
    )
    .expect("manifest with the dependency");
    std::fs::write(
        dir.path().join("build.rs"),
        include_str!("fixtures/rendezvous_build.rs"),
    )
    .expect("write the build script");
    let cargo = cargo_build_command_in(
        dir.path(),
        stow_home,
        cargo_home,
        Some(shim),
        cache.path(),
        &dir.path().join("target"),
    )
    .env("STOW_TEST_RENDEZVOUS", rendezvous.path())
    .env("STOW_TEST_BUILD_NAME", name)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::piped())
    .spawn()
    .expect("start cargo");
    HeldBuild {
        dir,
        _cache: cache,
        rendezvous,
        cargo,
    }
}

/// The marks of each session directory under `sessions`: every file in it
/// but the record of its owner.
fn session_marks(sessions: &Path) -> Vec<Vec<PathBuf>> {
    std::fs::read_dir(sessions)
        .expect("the sessions directory")
        .map(|entry| {
            let mut marks = files_under(&entry.expect("entry").path());
            marks.retain(|mark| mark != Path::new("owner"));
            marks
        })
        .collect()
}

/// Two cargos building different projects at once on one daemon each get a
/// session of their own: what one records as locally built never lands in
/// the other's.
#[test]
fn two_concurrent_plain_builds_get_two_sessions() {
    let home = support::tempdir().expect("home");
    let cargo_home = support::tempdir().expect("cargo home");
    let tools = support::tempdir().expect("tools dir");
    let stow_home = home.path().join("stow-home");
    support::write_global_config(&[&stow_home], "[cache]\nremote = false\n");
    let shim = install_shims(tools.path());
    let daemon = PrivateDaemon::in_home(&stow_home);

    let names = ["held-a", "held-b"];
    let projects: Vec<HeldBuild> = names
        .iter()
        .map(|name| start_held_build(name, &stow_home, cargo_home.path(), &shim))
        .collect();

    // Both builds are inside their scripts, so both sessions are open.
    for (project, name) in projects.iter().zip(names) {
        let started = project.rendezvous.path().join(format!("{name}.started"));
        let deadline = Instant::now() + END_LIMIT;
        while !started.exists() {
            assert!(Instant::now() < deadline, "{name} never reached its script");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    let sessions = daemon.run_dir().join("sessions");
    let deadline = Instant::now() + END_LIMIT;
    let marks = loop {
        let marks = session_marks(&sessions);
        if marks.len() == 2 && marks.iter().all(|marks| names_crate(marks, "dep_")) {
            break marks;
        }
        assert!(
            Instant::now() < deadline,
            "two sessions with marks never appeared in {}: {marks:?}",
            sessions.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(
        daemon.log_lines("opened a session for a cargo").len(),
        2,
        "one session for each of the two cargos"
    );
    for crate_name in ["dep_held_a", "dep_held_b"] {
        assert_eq!(
            marks
                .iter()
                .filter(|marks| names_crate(marks, crate_name))
                .count(),
            1,
            "{crate_name} is in exactly one build's session: {marks:?}"
        );
    }

    for mut project in projects {
        std::fs::write(project.rendezvous.path().join("release"), b"").expect("release the script");
        let cargo_pid = project.cargo.id();
        let status = project.cargo.wait().expect("wait for cargo");
        assert!(
            status.success(),
            "the build in {} failed",
            project.dir.path().display()
        );
        daemon.wait_session_ended(cargo_pid);
    }
    assert_eq!(daemon.serving_pids().len(), 1, "both shared one daemon");
}

/// A wrapper that cannot reach the daemon, nor start it, fails the build at
/// cargo's first probe naming the daemon's run directory, and nothing in a
/// wrapper process opens the cache.
#[test]
fn a_wrapper_that_cannot_reach_the_daemon_fails_naming_it_and_touches_no_cache() {
    let dir = support::tempdir().expect("temp dir");
    let cache = support::tempdir().expect("cache dir");
    let cargo_home = support::tempdir().expect("cargo home");
    let tools = support::tempdir().expect("tools dir");
    write_crate(dir.path());
    let shim = install_shims(tools.path());
    // A run directory that cannot be created: its parent is a file.
    let blocker = dir.path().join("not-a-directory");
    std::fs::write(&blocker, b"").expect("write the blocker");
    let run_dir = blocker.join("run");

    let output = cargo_build_command(
        dir.path(),
        cargo_home.path(),
        Some(&shim),
        cache.path(),
        &dir.path().join("target"),
    )
    .env("STOW_DAEMON_DIR", &run_dir)
    .output()
    .expect("run cargo build");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "the build ran without a daemon:\n{stderr}"
    );
    assert!(
        stderr.contains("stow daemon") && stderr.contains(&run_dir.display().to_string()),
        "the failure does not name the daemon and its run directory:\n{stderr}"
    );
    assert!(
        !dir.path()
            .join("target")
            .join("debug")
            .join("deps")
            .exists()
            || files_under(&dir.path().join("target").join("debug").join("deps"))
                .iter()
                .all(|file| file.extension().is_none_or(|extension| extension != "rlib")),
        "a unit was compiled without the daemon"
    );
    assert!(
        files_under(cache.path()).is_empty(),
        "a wrapper touched the cache: {:?}",
        files_under(cache.path())
    );
}

/// A socket the process may not open is the shape a sandbox's deny takes:
/// the build fails naming the daemon's endpoint instead of compiling on its
/// own.
#[cfg(unix)]
#[test]
fn a_socket_this_process_may_not_open_fails_the_build_naming_it() {
    use std::os::unix::fs::PermissionsExt as _;

    // The permission bits of the socket do not bind the superuser.
    // SAFETY: `geteuid` reads this process's credentials.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let dir = support::tempdir().expect("temp dir");
    let cache = support::tempdir().expect("cache dir");
    let cargo_home = support::tempdir().expect("cargo home");
    let tools = support::tempdir().expect("tools dir");
    write_crate(dir.path());
    support::write_global_config(
        &[&dir.path().join("stow-home")],
        "[cache]\nremote = false\n",
    );
    let shim = install_shims(tools.path());
    let daemon = PrivateDaemon::in_home(&dir.path().join("stow-home"));

    // A probe starts the daemon, which binds the socket.
    let probe = wrapper_command(&shim, dir.path(), cache.path())
        .arg("-vV")
        .output()
        .expect("run the wrapper");
    assert!(probe.status.success(), "the daemon did not start");
    let socket = daemon.run_dir().join("daemon.sock");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o000))
        .expect("close the socket to this process");

    let output = cargo_build_command(
        dir.path(),
        cargo_home.path(),
        Some(&shim),
        cache.path(),
        &dir.path().join("target"),
    )
    .output()
    .expect("run cargo build");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "the build ran without reaching the daemon:\n{stderr}"
    );
    assert!(
        stderr.contains("daemon.sock") && stderr.contains("stow daemon"),
        "the failure does not name the daemon's endpoint:\n{stderr}"
    );
}
