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
    std::fs::create_dir_all(dir.join("src")).expect("src dir");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"plain\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
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
    let mut command = Command::new("cargo");
    hermetic_stow_env(
        &mut command,
        &support::denied_registry(),
        cache,
        &dir.join("stow-home"),
    );
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
    let output = wrapper_command(&shim, dir.path(), cache.path())
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
        .arg(&out_dir)
        .arg(dir.path().join("src").join("lib.rs"))
        .env_remove("CARGO")
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

/// A cargo killed under its build script ends its session at once, and the
/// script it left behind runs on: the session follows the cargo, not the
/// processes cargo started.
#[test]
fn a_killed_cargo_ends_its_session_while_its_build_script_lives() {
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

    let mut cargo = cargo_build_command(
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

    // The script's own compile went through the wrapper, which opened the
    // session before the script ran.
    let started = rendezvous.path().join("held.started");
    let deadline = Instant::now() + END_LIMIT;
    while !started.exists() {
        assert!(
            Instant::now() < deadline,
            "the build never reached its script"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    // Only cargo: its script and compilers are other processes, which
    // neither `kill` nor the termination call takes with it.
    cargo.kill().expect("kill cargo");
    cargo.wait().expect("reap cargo");
    daemon.wait_session_ended(cargo_pid);
    assert!(
        !rendezvous.path().join("held.finished").exists(),
        "the script was still held when the session ended"
    );
    assert!(
        std::fs::read_dir(daemon.run_dir().join("sessions"))
            .into_iter()
            .flatten()
            .next()
            .is_none(),
        "the ended session's directory is still there"
    );

    // Release the orphaned script, and see that it lived to finish.
    std::fs::write(rendezvous.path().join("release"), b"").expect("release the script");
    let finished = rendezvous.path().join("held.finished");
    let deadline = Instant::now() + END_LIMIT;
    while !finished.exists() {
        assert!(
            Instant::now() < deadline,
            "the script did not outlive its cargo"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
