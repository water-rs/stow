//! Every cargo an integration test starts is sealed to the test's own stow
//! home.
//!
//! A cargo whose `CARGO_HOME` configures stow's rustc wrapper runs
//! `rustc -vV` through it even for `cargo fetch` and `cargo metadata`, and
//! the wrapper reaches the daemon of its `STOW_DAEMON_DIR`. Unsealed, that is
//! the developer's real run directory (and on Windows a scheduled task that
//! is not registered). `support::cargo_command` seals; this test fails on any
//! test source that starts cargo another way.

use std::path::Path;

/// The spellings that start a cargo without the seal.
const UNSEALED_SPELLINGS: [&str; 2] = ["Command::new(\"cargo\")", "env!(\"CARGO\")"];

fn sources(dir: &Path, found: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read the tests directory") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            sources(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

#[test]
fn every_cargo_a_test_starts_comes_from_the_sealed_constructor() {
    let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut files = Vec::new();
    sources(&tests, &mut files);
    // The constructor itself, and this file naming the spellings.
    let allowed = [
        tests.join("support").join("mod.rs"),
        tests.join("sealed_cargo.rs"),
    ];
    let mut offenders = Vec::new();
    for file in files.iter().filter(|file| !allowed.contains(file)) {
        let text = std::fs::read_to_string(file).expect("read a test source");
        for (number, line) in text.lines().enumerate() {
            if UNSEALED_SPELLINGS
                .iter()
                .any(|spelling| line.contains(spelling))
            {
                offenders.push(format!(
                    "{}:{}: {}",
                    file.display(),
                    number + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "start cargo through support::cargo_command(home), which seals it to the test's stow home:\n{}",
        offenders.join("\n")
    );
}
