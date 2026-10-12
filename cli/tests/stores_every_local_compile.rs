//! Every unit a build compiled is in the local cache before the build
//! exits (stow#618).
//!
//! An all-miss build used to lose its tail two ways: the last unit's
//! store was cancelled when the runtime dropped the supervisor's
//! connection tasks, and a dependent whose bookkeeping ran before its
//! dependency's skipped its store silently. Both are fixed — the
//! supervisor drains its connections, and a post-compile waits for the
//! in-flight units its `--extern` set names — so the count is the whole
//! set every time.

mod support;

use std::path::Path;

use support::{refused_url, stow_build_in, stow_setup_in, write_fixture};

/// The fixture's dependency list: the `proc-macro2`/`quote` pair — a
/// dependent small enough to finish before its dependency's rustc exits
/// — and two plain leaf crates. `unicode-ident` rides along as
/// `proc-macro2`'s own dependency.
const FIXTURE_DEPENDENCIES: &str = "cfg-if = \"1\"\n\
     memchr = \"2\"\n\
     proc-macro2 = \"1\"\n\
     quote = \"1\"\n";

/// Every `crate_name` the fixture's all-miss build must store — the
/// cacheable units of the tree, named explicitly.
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
            sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(
                "SELECT crate_name FROM artifact_cache_entries".to_owned(),
            ))
            .fetch_all(&pool)
            .await
            .expect("list stored crates")
            .into_iter()
            .collect()
        })
}

/// Three all-miss builds, each with a fresh cache and target dir: the
/// local store holds every cacheable unit the build compiled — the
/// `proc-macro2`/`quote` race included (stow#618).
#[test]
fn every_compiled_unit_is_stored_before_the_build_exits() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    write_fixture(dir.path(), cargo_home.path(), FIXTURE_DEPENDENCIES);
    stow_setup_in(dir.path(), cargo_home.path());
    let edge_url = refused_url();
    let registry_url = refused_url();

    for run in 1..=3 {
        let cache = tempfile::tempdir().expect("cache dir");
        let target = tempfile::tempdir().expect("target dir");
        let output = stow_build_in(
            dir.path(),
            &["build", "--offline"],
            &edge_url,
            &registry_url,
            cache.path(),
            cargo_home.path(),
            target.path(),
        );
        assert!(
            output.status.success(),
            "stow build {run} failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        // `proc-macro2` compiles a `build_script_build` `bin` unit, which
        // the cache can never hold — its post-compile must not warn
        // about an identity it was never owed (stow#619).
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr
                .lines()
                .any(|line| line.contains("failed to resolve local artifact identity")),
            "run {run}: a never-cacheable unit is not an identity failure:\n{stderr}"
        );
        let stored = stored_crate_names(&cache.path().join("state-v3.sqlite3"));
        let expected = expected_stored_crates()
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            stored, expected,
            "run {run}: the local store must hold every cacheable unit of the fixture:\n{stderr}"
        );
    }
}
