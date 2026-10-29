//! The `cache_mode` option of the global config (stow#1059).
//!
//! `local` keeps the local cache and makes no network request; `off` reads
//! and writes no cache either. Registry and edge both point at a listener
//! that counts the connections it is offered, so any request a build makes
//! shows up as a nonzero count, and the build's stderr must carry no
//! warning for a network the user chose not to have.

mod build_fixture;
mod support;

use std::path::Path;
use std::process::Output;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use build_fixture::{
    stow_build_in, stow_cli_in, stow_setup_in, tripwire_url, write_fixture, write_fixture_config,
};

/// Registry crates small enough to keep the fixture quick: two leaf crates
/// and the `proc-macro2`/`quote` pair with `unicode-ident`.
const FIXTURE_DEPENDENCIES: &str = "cfg-if = \"1\"\n\
     memchr = \"2\"\n\
     proc-macro2 = \"1\"\n\
     quote = \"1\"\n";

/// The units the fixture's all-miss build stores in the local cache.
const CACHEABLE_UNITS: usize = 5;

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// One `stow build --offline` against the tripwire, with a fresh target
/// directory so the cache is the only thing that can carry over.
fn build(dir: &Path, cargo_home: &Path, cache: &Path, tripwire: &str, label: &str) -> Output {
    let target = tempfile::tempdir().expect("target dir");
    let output = stow_build_in(
        dir,
        &["build", "--offline"],
        tripwire,
        tripwire,
        cache,
        cargo_home,
        target.path(),
    );
    assert!(
        output.status.success(),
        "{label} failed:\n{}",
        stderr_of(&output)
    );
    output
}

fn assert_no_network_and_no_warning(output: &Output, connections: &Arc<AtomicUsize>, label: &str) {
    assert_eq!(
        connections.load(Ordering::SeqCst),
        0,
        "{label} made a network request"
    );
    let stderr = stderr_of(output);
    assert!(
        !stderr.lines().any(|line| {
            let line = line.to_ascii_lowercase();
            line.contains("warn") || line.contains("unreachable")
        }),
        "{label} warned about a network it was told not to use:\n{stderr}"
    );
}

fn stored_entries(cache: &Path) -> Option<i64> {
    let db = cache.join("state-v3.sqlite3");
    if !db.exists() {
        return None;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            let options = sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&db)
                .read_only(true);
            let pool = sqlx::SqlitePool::connect_with(options)
                .await
                .expect("open the state db read-only");
            let count = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(
                "SELECT count(*) FROM artifact_cache_entries".to_owned(),
            ))
            .fetch_one(&pool)
            .await
            .ok();
            pool.close().await;
            count
        })
}

/// What `stow stats --json` reports: served hits and the compile time they
/// saved, in milliseconds.
fn stats(dir: &Path, cargo_home: &Path, cache: &Path) -> (u64, u64) {
    let output = stow_cli_in(dir, &["stats", "--json"], cache, cargo_home);
    assert!(
        output.status.success(),
        "stow stats failed:\n{}",
        stderr_of(&output)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stats --json is JSON");
    (
        report["hits"].as_u64().expect("hits"),
        report["cpu_millis_saved"]
            .as_u64()
            .expect("cpu_millis_saved"),
    )
}

/// A build in local-only mode makes no network attempt and prints no
/// warning, and `stow stats` reports the compile time its local hits saved.
#[test]
fn local_mode_builds_offline_and_reports_the_time_local_hits_saved() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    let cache = tempfile::tempdir().expect("cache dir");
    write_fixture(dir.path(), cargo_home.path(), FIXTURE_DEPENDENCIES);
    write_fixture_config(dir.path(), "cache_mode = \"local\"\n");
    stow_setup_in(dir.path(), cargo_home.path());
    let (tripwire, connections) = tripwire_url();

    let fill = build(
        dir.path(),
        cargo_home.path(),
        cache.path(),
        &tripwire,
        "fill build",
    );
    assert_no_network_and_no_warning(&fill, &connections, "the fill build");
    assert_eq!(
        stored_entries(cache.path()),
        Some(i64::try_from(CACHEABLE_UNITS).expect("count fits")),
        "the fill build stores every cacheable unit locally"
    );
    assert_eq!(
        stats(dir.path(), cargo_home.path(), cache.path()).0,
        0,
        "nothing was served yet"
    );

    let serve = build(
        dir.path(),
        cargo_home.path(),
        cache.path(),
        &tripwire,
        "serve build",
    );
    assert_no_network_and_no_warning(&serve, &connections, "the serve build");
    let (hits, saved_millis) = stats(dir.path(), cargo_home.path(), cache.path());
    assert!(
        hits >= u64::try_from(CACHEABLE_UNITS).expect("count fits"),
        "the serve build must hit the local cache for every unit, got {hits} hits:\n{}",
        stderr_of(&serve)
    );
    assert!(
        saved_millis > 0,
        "local hits must report the compile time they saved"
    );
}

/// A build with the cache off reads and writes no cache and makes no
/// network attempt. (Isolation under `off` is covered by the sandbox
/// suite, which runs its boundary probes with the cache off.)
#[test]
fn off_mode_reads_and_writes_no_cache() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    let cache = tempfile::tempdir().expect("cache dir");
    write_fixture(dir.path(), cargo_home.path(), FIXTURE_DEPENDENCIES);
    write_fixture_config(dir.path(), "cache_mode = \"off\"\n");
    stow_setup_in(dir.path(), cargo_home.path());
    let (tripwire, connections) = tripwire_url();

    for run in ["first build", "second build"] {
        let output = build(dir.path(), cargo_home.path(), cache.path(), &tripwire, run);
        assert_no_network_and_no_warning(&output, &connections, run);
        assert_eq!(
            stored_entries(cache.path()).unwrap_or(0),
            0,
            "{run}: the off mode writes no cache entry"
        );
    }
    assert_eq!(
        stats(dir.path(), cargo_home.path(), cache.path()),
        (0, 0),
        "the off mode serves nothing"
    );
}
