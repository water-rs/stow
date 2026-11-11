//! The `rustc` wrapper's stdout must stay byte-identical to the wrapped
//! compiler's.
//!
//! Cargo probes `rustc -vV` *through* `RUSTC_WRAPPER` and hashes the
//! resulting version string into every unit's `-C metadata`. One log line
//! on stdout changes that hash — and because each line carries a timestamp,
//! it changes on every invocation, so no dependency can ever hit the cache
//! and any package with a build script fails outright.

use std::process::Command;

// The shared fixture carries helpers this test does not call; each
// integration binary lints them per target.
#[allow(dead_code)]
mod build_fixture;
mod support;

use build_fixture::refused_url;
use support::hermetic_stow_env;

fn rustc_path() -> String {
    std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned())
}

fn plain_version_output() -> Vec<u8> {
    let output = Command::new(rustc_path())
        .arg("-vV")
        .output()
        .expect("run rustc -vV");
    assert!(output.status.success(), "rustc -vV failed");
    output.stdout
}

fn wrapper_version_output(env: &[(&str, &str)]) -> Vec<u8> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
    command.arg("rustc").arg(rustc_path()).arg("-vV");
    // A wrapper invocation reads the stow config and the ambient
    // session variables — the sealed home and cleared `STOW_*` keep
    // the developer's `~/.stow` and shell exports out of it (stow#800).
    let home = support::tempdir().expect("home");
    hermetic_stow_env(
        &mut command,
        &refused_url(),
        &home.path().join("stow-cache"),
        home.path(),
    );
    command.env_remove("RUST_LOG");
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().expect("run stow-cli rustc -vV");
    assert!(
        output.status.success(),
        "stow-cli rustc -vV failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// A wrapper naming a session the daemon never opened — the daemon
/// restarted, or the build that opened it ended — fails the build and says
/// so, rather than compiling uncached on its own.
#[test]
fn a_wrapper_naming_an_unknown_session_fails_saying_so() {
    let home = support::tempdir().expect("home");
    let session = "00112233445566778899aabbccddeeff";
    let mut command = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
    command.arg("rustc").arg(rustc_path()).arg("-vV");
    hermetic_stow_env(
        &mut command,
        &refused_url(),
        &home.path().join("stow-cache"),
        home.path(),
    );
    let output = command
        .env("STOW_SESSION", session)
        .output()
        .expect("run the wrapper under an unknown session");
    assert!(
        !output.status.success(),
        "a session the daemon never opened was served"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("no session {session}")),
        "stderr does not name the session:\n{stderr}"
    );
}

#[test]
fn rustc_probe_stdout_is_never_polluted_by_logging() {
    let expected = plain_version_output();

    // Every combination of log filter and the wrapper-tracing escape hatch
    // must leave stdout untouched.
    for rust_log in ["", "info", "debug", "trace", "stow_cli=trace"] {
        for trace_wrapped in ["", "0", "1"] {
            let mut env = Vec::new();
            if !rust_log.is_empty() {
                env.push(("RUST_LOG", rust_log));
            }
            if !trace_wrapped.is_empty() {
                env.push(("STOW_TRACE_WRAPPED_COMPILERS", trace_wrapped));
            }
            let actual = wrapper_version_output(&env);
            assert_eq!(
                String::from_utf8_lossy(&actual),
                String::from_utf8_lossy(&expected),
                "stdout differs with RUST_LOG={rust_log:?} \
                 STOW_TRACE_WRAPPED_COMPILERS={trace_wrapped:?}"
            );
        }
    }
}
