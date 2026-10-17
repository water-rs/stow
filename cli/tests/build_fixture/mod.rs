//! The fixture project and the hermetic `stow build` the end-to-end
//! integration tests share.

use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};

use crate::support::hermetic_stow_env;

/// Write a single-binary fixture package whose `[dependencies]` table is
/// `dependencies`, then resolve it now so the builds under test are not
/// also network tests.
#[allow(dead_code)] // not every fixture binary uses the plain-manifest writer
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

#[allow(dead_code)] // callers needing extra env use stow_build_in_with_env
pub fn stow_build_in(
    dir: &Path,
    args: &[&str],
    edge_url: &str,
    registry_url: &str,
    cache_dir: &Path,
    cargo_home: &Path,
    target_dir: &Path,
) -> Output {
    stow_build_in_with_env(
        dir,
        args,
        edge_url,
        registry_url,
        cache_dir,
        cargo_home,
        target_dir,
        &[],
    )
}

/// [`stow_build_in`] with caller-supplied environment layered on top —
/// a `RUST_LOG` a test wants set, or the `STOW_TRACE_FILE` one reads
/// afterwards.
#[allow(clippy::too_many_arguments)]
pub fn stow_build_in_with_env(
    dir: &Path,
    args: &[&str],
    edge_url: &str,
    registry_url: &str,
    cache_dir: &Path,
    cargo_home: &Path,
    target_dir: &Path,
    env: &[(&str, &str)],
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
    hermetic_stow_env(&mut command, edge_url, cache_dir);
    command
        .args(args)
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home)
        .env("STOW_REGISTRY_BASE_URL", registry_url)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TARGET_DIR", target_dir)
        // The default filter, whatever the developer's shell exports: the
        // supervisor runs in this process, so the warnings it logs are on
        // this stderr, where a test can assert on them (stow#619).
        .env_remove("RUST_LOG")
        // Level markers and cargo's status lines are asserted on as
        // plain text, whatever colour the environment asks for.
        .env("NO_COLOR", "1")
        .env("CARGO_TERM_COLOR", "never");
    command.envs(env.iter().copied());
    command.output().expect("run stow-cli build")
}
