//! A plain `cargo build` through the wrapper shim has no driver: the daemon
//! opens a session of the cargo the wrapper runs under and ends it when that
//! cargo exits.

mod support;

use std::path::{Path, PathBuf};
use std::process::Command;
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

fn build(dir: &Path, cargo_home: &Path, shim: &Path, cache: &Path, target: &Path) {
    let mut command = Command::new("cargo");
    hermetic_stow_env(
        &mut command,
        &support::denied_registry(),
        cache,
        &dir.join("stow-home"),
    );
    let output = command
        .arg("build")
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home)
        .env("RUSTC_WRAPPER", shim)
        .env("CARGO_TARGET_DIR", target)
        .env("CARGO_INCREMENTAL", "0")
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
