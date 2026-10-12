//! A cache-served `stow build` prints cargo's output and stow's summary
//! line, and nothing else (stow#633).
//!
//! Served units used to leak three raw rustc artifact-notification JSON
//! lines each — written by the supervisor process, so cargo never saw
//! them either — plus per-unit `INFO` lines and a per-attempt `WARN` for
//! every retry of the unreachable registry. The notifications now travel
//! with the serve decision to the facade cargo spawned, and the default
//! verbosity is `warn` with per-unit and per-attempt lines at `debug`.

use std::net::TcpListener;
use std::path::Path;
use std::process::Command;

/// Four leaf dependencies — four cacheable units, no dependency-identity
/// chains, so every build-1 store and every build-2 serve keys exactly.
fn write_fixture(dir: &Path, cargo_home: &Path) {
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
         [dependencies]\n\
         cfg-if = \"1\"\n\
         itoa = \"1\"\n\
         ryu = \"1\"\n\
         unicode-ident = \"1\"\n",
    )
    .expect("write manifest");
    std::fs::create_dir_all(dir.join("src")).expect("create src");
    std::fs::write(dir.join("src").join("main.rs"), "fn main() {}\n").expect("write main.rs");
    // Resolve now, so the builds under test are not also network tests.
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
fn refused_url() -> String {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind to pick a port");
        listener.local_addr().expect("local addr").port()
    };
    format!("http://127.0.0.1:{port}")
}

/// `stow-cli setup` in the isolated `CARGO_HOME` — the one-time mold
/// selection, kept out of the builds under test.
fn stow_setup_in(dir: &Path, cargo_home: &Path) {
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

fn stow_build_in(
    dir: &Path,
    edge_url: &str,
    registry_url: &str,
    cache_dir: &Path,
    cargo_home: &Path,
    target_dir: &Path,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_stow-cli"))
        .args(["build", "--offline"])
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
        // The level markers the assertions look for are plain text.
        .env("NO_COLOR", "1")
        .output()
        .expect("run stow-cli build")
}

/// The lines cargo itself may legitimately print to stderr — indented,
/// like cargo prints them. Anything else there is stow noise reaching
/// the user's terminal.
fn is_cargo_line(line: &str) -> bool {
    let line = line.trim_start();
    [
        "Compiling ",
        "Finished ",
        "Downloaded ",
        "Downloading ",
        "Updating ",
        "Locking ",
        "Adding ",
        "Removing ",
        "Fresh ",
        "Dirty ",
        "Running ",
        "warning: ",
        "error: ",
    ]
    .iter()
    .any(|prefix| line.starts_with(prefix))
}

/// The `warn`-level conditions an unreachable edge and registry can
/// legitimately surface — each at most once per build (stow#633). The
/// in-build analysis is a detached task that the runtime cuts short when
/// cargo finishes, so whether its warn fires at all is a race between
/// the registry retries' backoff and the build's exit.
fn allowed_warn(line: &str) -> bool {
    line.contains("background build analysis failed; the build keeps its filesystem-only plan")
}

/// Build 1 compiles the fixture into a shared stow cache; build 2, on a
/// fresh target dir, serves every dependency from the local cache. The
/// second build's stderr must be cargo's lines alone — no leaked
/// artifact-notification JSON, no tracing below `warn`.
#[test]
fn a_served_build_prints_cargo_output_and_the_summary_only() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    write_fixture(dir.path(), cargo_home.path());
    stow_setup_in(dir.path(), cargo_home.path());
    let edge_url = refused_url();
    let registry_url = format!("{}/v2/water-rs/stow-cache", refused_url());
    let cache = tempfile::tempdir().expect("cache dir");

    // First build: all misses, every unit stored locally.
    let target_a = tempfile::tempdir().expect("target dir a");
    let first = stow_build_in(
        dir.path(),
        &edge_url,
        &registry_url,
        cache.path(),
        cargo_home.path(),
        target_a.path(),
    );
    assert!(
        first.status.success(),
        "first stow build failed:\n{}",
        String::from_utf8_lossy(&first.stderr)
    );

    // Second build: the shared cache serves every dependency.
    let target_b = tempfile::tempdir().expect("target dir b");
    let second = stow_build_in(
        dir.path(),
        &edge_url,
        &registry_url,
        cache.path(),
        cargo_home.path(),
        target_b.path(),
    );
    assert!(
        second.status.success(),
        "second stow build failed:\n{}",
        String::from_utf8_lossy(&second.stderr)
    );

    let stdout = String::from_utf8_lossy(&second.stdout);
    let stderr = String::from_utf8_lossy(&second.stderr);

    // The summary line is stow's own deliberate output — written to
    // stdout by `report_cache_coverage`, once per build.
    assert!(
        stdout.contains("stow: served 4 of 4 cacheable dependencies"),
        "expected the served-units summary on stdout, got:\n{stdout}"
    );

    let mut seen_warns = Vec::new();
    for line in stderr.lines() {
        assert!(
            !line.starts_with('{'),
            "raw JSON on second build stderr:\n{line}\nfull stderr:\n{stderr}"
        );
        assert!(
            !line.contains(" INFO ")
                && !line.contains("DEBUG ")
                && !line.contains("TRACE ")
                && !line.contains("ERROR "),
            "tracing line on second build stderr:\n{line}\nfull stderr:\n{stderr}"
        );
        if line.contains(" WARN ") {
            assert!(
                allowed_warn(line) && !seen_warns.contains(&line),
                "unexpected or repeated WARN on second build stderr:\n{line}\nfull stderr:\n{stderr}"
            );
            seen_warns.push(line);
            continue;
        }
        assert!(
            is_cargo_line(line),
            "line on second build stderr that cargo never prints:\n{line}\nfull stderr:\n{stderr}"
        );
    }
}
