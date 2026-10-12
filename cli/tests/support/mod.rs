//! Helpers shared by the `stow build` end-to-end integration tests.

use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};

/// Write a single-binary fixture package whose `[dependencies]` table is
/// `dependencies`, then resolve it now so the builds under test are not
/// also network tests.
pub fn write_fixture(dir: &Path, cargo_home: &Path, dependencies: &str) {
    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\n{dependencies}"
        ),
    )
    .expect("write manifest");
    std::fs::create_dir_all(dir.join("src")).expect("create src");
    std::fs::write(dir.join("src").join("main.rs"), "fn main() {}\n").expect("write main.rs");
    let fetched = Command::new("cargo")
        .arg("fetch")
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home)
        .output()
        .expect("run cargo fetch");
    assert!(
        fetched.status.success(),
        "cargo fetch failed:\n{}",
        String::from_utf8_lossy(&fetched.stderr)
    );
}

/// A local port with nothing listening on it: the edge and the registry
/// both fail fast instead of hanging the build.
pub fn refused_url() -> String {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind to pick a port");
        listener.local_addr().expect("local addr").port()
    };
    format!("http://127.0.0.1:{port}")
}

/// `stow-cli setup` in the isolated `CARGO_HOME` — the one-time mold
/// selection, kept out of the builds under test (stow#294: a Linux
/// `stow build` refuses to run without it).
pub fn stow_setup_in(dir: &Path, cargo_home: &Path) {
    let setup = Command::new(env!("CARGO_BIN_EXE_stow-cli"))
        .arg("setup")
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home)
        .output()
        .expect("run stow-cli setup");
    assert!(
        setup.status.success(),
        "stow setup failed:\n{}",
        String::from_utf8_lossy(&setup.stderr)
    );
}

pub fn stow_build_in(
    dir: &Path,
    args: &[&str],
    edge_url: &str,
    registry_url: &str,
    cache_dir: &Path,
    cargo_home: &Path,
    target_dir: &Path,
) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stow-cli"))
        .args(args)
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home)
        .env("STOW_EDGE_URL", edge_url)
        .env("STOW_REGISTRY_BASE_URL", registry_url)
        .env("STOW_CACHE_DIR", cache_dir)
        // Isolate from the developer's ambient stow config: a user-level
        // `verify_mode = "mock-key"` (or an inherited `STOW_CONFIG_BLOB`)
        // would make this binary reject the config and skip the cache.
        .env("STOW_VERIFY_MODE", "github-ci")
        .env_remove("STOW_CONFIG_BLOB")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TARGET_DIR", target_dir)
        .env_remove("RUST_LOG")
        .output()
        .expect("run stow-cli build")
}
