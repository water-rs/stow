//! The `stow rustc` shim stands in for `rustc` itself, so cargo parses whatever
//! it writes to stdout. Cargo hashes the output of the `rustc -vV` probe into
//! every unit's `-C metadata`; a stray log line there changes the cache key on
//! every invocation and makes build scripts fail to link.

use std::process::Command;

fn rustc_path() -> String {
    std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned())
}

fn wrapper_probe_stdout(rust_log: &str) -> Vec<u8> {
    let output = Command::new(env!("CARGO_BIN_EXE_stow-cli"))
        .args(["rustc", &rustc_path(), "-vV"])
        .env("RUST_LOG", rust_log)
        .output()
        .expect("run stow rustc wrapper");
    assert!(
        output.status.success(),
        "wrapper probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

#[test]
fn rustc_probe_stdout_matches_plain_rustc_at_every_log_level() {
    let expected = Command::new(rustc_path())
        .arg("-vV")
        .output()
        .expect("run rustc -vV")
        .stdout;

    for rust_log in ["", "info", "debug", "stow_cli=trace"] {
        assert_eq!(
            wrapper_probe_stdout(rust_log),
            expected,
            "stow rustc wrapper polluted rustc stdout with RUST_LOG={rust_log:?}"
        );
    }
}
