//! An unreachable registry or edge degrades the build to local-only,
//! detected once — it does not stall every local miss on a fetch that
//! cannot answer (stow#977).
//!
//! Before the fix the build's index fetch retried a transport failure
//! eight times under exponential backoff while every local miss parked
//! on `serve_map_ready`, and an already-flying edge download waited out
//! its whole `request_timeout`. Now the CLI's registry client fails a
//! connect/DNS failure on its first try under a short connect bound,
//! and that failure trips the build's circuit: every waiter releases
//! at once to local compile, one `tracing::warn!` naming the host is
//! the whole diagnostic, and in-flight downloads abandon on the trip.
//!
//! Two unreachable shapes are exercised: connections refused outright,
//! and a black-holed address that lets the connect hang until the
//! client's bound fires. Both run a fill build (everything compiles
//! and stores) and a serve build (the stored units answer locally),
//! and each must report the single unreachable-registry warning.

mod build_fixture;
mod support;

use std::path::Path;
use std::process::Output;
use std::time::{Duration, Instant};

use build_fixture::{refused_url, stow_build_in, stow_setup_in, write_fixture};

/// Registry crates small enough to keep the fixture quick: two leaf
/// crates, and the `proc-macro2`/`quote` pair that also drags in
/// `unicode-ident`.
const FIXTURE_DEPENDENCIES: &str = "cfg-if = \"1\"\n\
     memchr = \"2\"\n\
     proc-macro2 = \"1\"\n\
     quote = \"1\"\n";

/// The unreachable-registry warning the driver emits once per build —
/// the whole diagnostic the outage is allowed (stow#977).
const UNREACHABLE_WARNING: &str = "stow index registry is unreachable";

/// A generous bound on a build that should pay no remote wait at all:
/// one 2 s connect attempt per index fetch, then plain cargo. It is
/// loose enough to hold on a loaded runner and still orders of
/// magnitude under what the pre-fix code paid — eight retried
/// connects of minutes each for a black hole, and a whole
/// `request_timeout` per in-flight download.
const BUILD_TIME_BOUND: Duration = Duration::from_secs(180);

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The count `stow: served N of M cacheable dependencies` reports.
fn served_count(output: &Output) -> usize {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            line.strip_prefix("stow: served ")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .unwrap_or_else(|| panic!("no `stow: served` summary line in stdout"))
}

/// The unreachable host is reported exactly once per build — the
/// warning names the registry base URL the fetch failed against.
fn assert_single_unreachable_warning(output: &Output, registry_url: &str, label: &str) {
    let stderr = stderr_of(output);
    let warnings = stderr
        .lines()
        .filter(|line| line.contains(UNREACHABLE_WARNING))
        .count();
    assert_eq!(
        warnings, 1,
        "{label} must emit exactly one unreachable-registry warning:\n{stderr}"
    );
    let host = registry_url.trim_end_matches('/');
    assert!(
        stderr
            .lines()
            .any(|line| line.contains(UNREACHABLE_WARNING) && line.contains(host)),
        "{label} warning must name the unreachable host {host}:\n{stderr}"
    );
}

/// `stow build` under a deadline: the build must succeed and finish
/// inside `BUILD_TIME_BOUND` — any per-unit remote wait would blow it
/// by minutes, not seconds.
#[allow(clippy::too_many_arguments)]
fn timed_build(
    dir: &Path,
    args: &[&str],
    edge_url: &str,
    registry_url: &str,
    cache: &Path,
    cargo_home: &Path,
    target: &Path,
    label: &str,
) -> Output {
    let started = Instant::now();
    let output = stow_build_in(dir, args, edge_url, registry_url, cache, cargo_home, target);
    let elapsed = started.elapsed();
    assert!(
        output.status.success(),
        "{label} failed:\n{}",
        stderr_of(&output)
    );
    assert!(
        elapsed < BUILD_TIME_BOUND,
        "{label} took {elapsed:?} — remote unreachability must be paid once, \
         not per unit:\n{}",
        stderr_of(&output)
    );
    output
}

/// The crate names the fixture's all-miss build must store.
fn expected_stored_crates() -> std::collections::BTreeSet<&'static str> {
    ["cfg-if", "memchr", "proc-macro2", "quote", "unicode-ident"]
        .into_iter()
        .collect()
}

fn stored_crate_names(db: &Path) -> std::collections::BTreeSet<String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            let options = sqlx::sqlite::SqliteConnectOptions::new()
                .filename(db)
                .read_only(true);
            let pool = sqlx::SqlitePool::connect_with(options)
                .await
                .expect("open the state db read-only");
            let stored = sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(
                "SELECT crate_name FROM artifact_cache_entries".to_owned(),
            ))
            .fetch_all(&pool)
            .await
            .expect("list stored crates")
            .into_iter()
            .collect();
            pool.close().await;
            stored
        })
}

/// Registry and edge refuse every connection: the index fetch fails
/// its connect on the first attempt, the circuit trips, and the build
/// runs local-only — fill stores every compiled unit, serve answers
/// them from the local cache.
#[test]
fn refused_registry_and_edge_run_the_build_local_only() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    write_fixture(dir.path(), cargo_home.path(), FIXTURE_DEPENDENCIES);
    stow_setup_in(dir.path(), cargo_home.path());
    let edge_url = refused_url();
    let registry_url = refused_url();
    let cache = tempfile::tempdir().expect("stow cache dir");

    // Fill: everything compiles and stores — remote was never asked
    // twice for the same outage.
    let target = tempfile::tempdir().expect("target dir");
    let output = timed_build(
        dir.path(),
        &["build", "--offline"],
        &edge_url,
        &registry_url,
        cache.path(),
        cargo_home.path(),
        target.path(),
        "fill build",
    );
    assert_single_unreachable_warning(&output, &registry_url, "fill build");
    assert_eq!(
        stored_crate_names(&cache.path().join("state-v3.sqlite3")),
        expected_stored_crates()
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<std::collections::BTreeSet<_>>(),
        "fill build must store every cacheable unit it compiled"
    );

    // Serve: a fresh target dir against the same cache answers the
    // stored units locally — the local listing needs no network.
    let target = tempfile::tempdir().expect("target dir");
    let output = timed_build(
        dir.path(),
        &["build", "--offline"],
        &edge_url,
        &registry_url,
        cache.path(),
        cargo_home.path(),
        target.path(),
        "serve build",
    );
    assert_single_unreachable_warning(&output, &registry_url, "serve build");
    assert!(
        served_count(&output) > 0,
        "serve build must answer locally stored units"
    );
}

/// Registry and edge black-holed: the address accepts nothing, so the
/// connect hangs until the client's short bound fires — `192.0.0.8`
/// is the IETF-assigned IPv4 dummy address, never routable. The trip
/// must still release every waiter to local compile.
#[test]
fn blackholed_registry_and_edge_run_the_build_local_only() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    write_fixture(dir.path(), cargo_home.path(), FIXTURE_DEPENDENCIES);
    stow_setup_in(dir.path(), cargo_home.path());
    let blackholed_url = "http://192.0.0.8:9".to_owned();
    let cache = tempfile::tempdir().expect("stow cache dir");

    // Fill: the connect hangs, the bound fires, the circuit trips, and
    // the build compiles and stores everything locally.
    let target = tempfile::tempdir().expect("target dir");
    let output = timed_build(
        dir.path(),
        &["build", "--offline"],
        &blackholed_url,
        &blackholed_url,
        cache.path(),
        cargo_home.path(),
        target.path(),
        "fill build",
    );
    assert_single_unreachable_warning(&output, &blackholed_url, "fill build");
    assert_eq!(
        stored_crate_names(&cache.path().join("state-v3.sqlite3")),
        expected_stored_crates()
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<std::collections::BTreeSet<_>>(),
        "fill build must store every cacheable unit it compiled"
    );

    // Serve: the stored units answer locally; the hung connect is
    // bounded once, not once per miss.
    let target = tempfile::tempdir().expect("target dir");
    let output = timed_build(
        dir.path(),
        &["build", "--offline"],
        &blackholed_url,
        &blackholed_url,
        cache.path(),
        cargo_home.path(),
        target.path(),
        "serve build",
    );
    assert_single_unreachable_warning(&output, &blackholed_url, "serve build");
    assert!(
        served_count(&output) > 0,
        "serve build must answer locally stored units"
    );
}
