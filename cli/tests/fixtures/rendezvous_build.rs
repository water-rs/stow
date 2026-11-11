//! A build script that holds its build open until the test releases it,
//! and tells the test which session the build runs under.

use std::time::{Duration, Instant};

/// Longer than any test waits for what it is holding the build for; a
/// build nobody releases ends here instead of hanging.
const HOLD_LIMIT: Duration = Duration::from_secs(120);

fn main() {
    let dir = std::path::PathBuf::from(
        std::env::var_os("STOW_TEST_RENDEZVOUS").expect("STOW_TEST_RENDEZVOUS names the directory"),
    );
    let name = std::env::var("STOW_TEST_BUILD_NAME").expect("STOW_TEST_BUILD_NAME names the build");
    let session = std::env::var("STOW_SESSION").expect("a build under stow names its session");

    // Written whole then renamed, so the test never reads half of it.
    let pending = dir.join(format!("{name}.pending"));
    std::fs::write(&pending, session).expect("announce the session");
    std::fs::rename(&pending, dir.join(format!("{name}.started"))).expect("publish the session");

    let release = dir.join("release");
    let deadline = Instant::now() + HOLD_LIMIT;
    while !release.exists() {
        assert!(Instant::now() < deadline, "the test never released the build");
        std::thread::sleep(Duration::from_millis(20));
    }
}
