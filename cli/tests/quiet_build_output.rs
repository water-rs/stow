//! A cache-served `stow build` prints cargo's output and stow's summary
//! line, and nothing else (stow#633).
//!
//! Served units used to leak three raw rustc artifact-notification JSON
//! lines each — written by the supervisor process, so cargo never saw
//! them either — plus per-unit `INFO` lines and a per-attempt `WARN` for
//! every retry of the unreachable registry. The notifications now travel
//! with the serve decision to the facade cargo spawned, and the default
//! verbosity is `warn` with per-unit and per-attempt lines at `debug`.

mod build_fixture;
mod support;

use build_fixture::{refused_url, stow_build_in, stow_setup_in, write_fixture};

/// Four leaf dependencies — four cacheable units, no dependency-identity
/// chains, so every build-1 store and every build-2 serve keys exactly.
const FIXTURE_DEPENDENCIES: &str =
    "cfg-if = \"1\"\nitoa = \"1\"\nryu = \"1\"\nunicode-ident = \"1\"\n";

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
    write_fixture(dir.path(), cargo_home.path(), FIXTURE_DEPENDENCIES);
    stow_setup_in(dir.path(), cargo_home.path());
    let edge_url = refused_url();
    let registry_url = format!("{}/v2/water-rs/stow-cache", refused_url());
    let cache = tempfile::tempdir().expect("cache dir");

    // First build: all misses, every unit stored locally.
    let target_a = tempfile::tempdir().expect("target dir a");
    let first = stow_build_in(
        dir.path(),
        &["build", "--offline"],
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
        &["build", "--offline"],
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
