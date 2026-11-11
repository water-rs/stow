//! A unit whose serve fails says at which stage and why, in the default
//! build output (stow#1439).
//!
//! The summary used to count such a unit `errored` and name only the
//! crate; the reason went to a debug log nobody reads. Now each errored
//! unit gets one line after the summary naming the stage and the reason.

mod build_fixture;
mod support;

use build_fixture::{refused_url, stow_build_in, stow_setup_in, write_fixture};

const FIXTURE_DEPENDENCIES: &str = "cfg-if = \"1\"\nitoa = \"1\"\n";

/// Build 1 stores every unit locally. The local entry of `cfg-if` is then
/// made to describe another version, so build 2 finds it under the unit's
/// exact key and rejects it: the unit errors at the identity check.
#[test]
fn an_errored_unit_names_its_stage_and_reason() {
    let dir = support::tempdir().expect("temp dir");
    let cargo_home = support::tempdir().expect("cargo home");
    write_fixture(dir.path(), cargo_home.path(), FIXTURE_DEPENDENCIES);
    stow_setup_in(dir.path(), cargo_home.path());
    let edge_url = refused_url();
    let registry_url = refused_url();
    let cache = support::tempdir().expect("cache dir");

    let target_a = support::tempdir().expect("target dir a");
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

    let db = cache.path().join("state-v3.sqlite3");
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            let pool = sqlx::SqlitePool::connect_with(
                sqlx::sqlite::SqliteConnectOptions::new().filename(&db),
            )
            .await
            .expect("connect state db");
            let tampered = sqlx::query(sqlx::AssertSqlSafe(
                "UPDATE artifact_cache_entries SET crate_version = '0.0.0' \
                 WHERE crate_name = 'cfg-if'"
                    .to_owned(),
            ))
            .execute(&pool)
            .await
            .expect("tamper with the stored entry")
            .rows_affected();
            assert!(tampered > 0, "build 1 stored no `cfg_if` entry to tamper");
            pool.close().await;
        });

    let target_b = support::tempdir().expect("target dir b");
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
    assert!(
        stdout.contains("1 errored (cfg_if)"),
        "the summary counts the errored unit:\n{stdout}"
    );
    let line = stdout
        .lines()
        .find(|line| line.starts_with("stow: cfg_if: "))
        .unwrap_or_else(|| panic!("no line naming the errored unit's failure:\n{stdout}"));
    assert!(
        line.contains("local cache entry identity check failed: ")
            && line.contains("exact bundle version mismatch: cached 0.0.0"),
        "the line names the stage and the reason: {line}"
    );
}
