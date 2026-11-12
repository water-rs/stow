//! Every unit a build compiled is in the local cache before the build
//! exits (stow#618).
//!
//! An all-miss build used to lose its tail two ways: the last unit's
//! store was cancelled when the runtime dropped the session's
//! connection tasks, and a dependent whose bookkeeping ran before its
//! dependency's skipped its store silently. Both are fixed — the
//! session drains its connections, and a post-compile waits for the
//! in-flight units its `--extern` set names — so the count is the whole
//! set every time.

mod build_fixture;
mod support;

use std::path::Path;

use build_fixture::{refused_url, stow_build_in, stow_setup_in, write_fixture};

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
            let stored = sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(
                "SELECT crate_name FROM artifact_cache_entries".to_owned(),
            ))
            .fetch_all(&pool)
            .await
            .expect("list stored crates")
            .into_iter()
            .collect();
            // The next run's stow opens a database of its own; this
            // reader leaves nothing open behind it (stow#682).
            pool.close().await;
            stored
        })
}

/// Three all-miss builds, each with a fresh cache and target dir: the
/// local store holds every cacheable unit the build compiled — the
/// `proc-macro2`/`quote` race included (stow#618).
#[test]
fn every_compiled_unit_is_stored_before_the_build_exits() {
    let dir = support::tempdir().expect("temp dir");
    let cargo_home = support::tempdir().expect("cargo home");
    write_fixture(dir.path(), cargo_home.path(), FIXTURE_DEPENDENCIES);
    stow_setup_in(dir.path(), cargo_home.path());
    let edge_url = refused_url();
    let registry_url = refused_url();

    for run in 1..=3 {
        let cache = support::tempdir().expect("cache dir");
        let target = support::tempdir().expect("target dir");
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

/// How long after its compiler exited a unit's wrapper may exit: the report
/// and its receipt, and nothing the daemon does with the report. The bound
/// is generous so a loaded machine does not fail it; storing a unit takes
/// longer than this only when the wrapper waits for it.
#[cfg(unix)]
const WRAPPER_EXIT_BOUND: std::time::Duration = std::time::Duration::from_secs(2);

/// A plain `cargo build` through the wrapper `stow setup` installs: each
/// locally compiled unit's wrapper exits with its compiler, and the daemon
/// stores the unit afterwards.
///
/// `RUSTC` and `RUSTC_WRAPPER` are shell scripts around the real compiler
/// and the stow wrapper, each recording when it exited under the number of
/// the wrapper script that ran it. Unix only: the scripts are `sh`.
#[cfg(unix)]
#[test]
fn a_plain_builds_wrappers_exit_with_their_compilers() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let dir = support::tempdir().expect("temp dir");
    let cargo_home = support::tempdir().expect("cargo home");
    write_fixture(dir.path(), cargo_home.path(), FIXTURE_DEPENDENCIES);
    let tools = support::tempdir().expect("tools");
    let record = support::tempdir().expect("record");
    let stow_home = dir.path().join("stow-home");

    // The shipped shape: the runtime under the wrapper's name, with the
    // runtime link the wrapper starts the daemon from beside it.
    let stow_wrapper = tools.path().join("stow-rustc-wrapper");
    symlink(env!("CARGO_BIN_EXE_stow-cli"), &stow_wrapper).expect("link the wrapper");
    symlink(
        env!("CARGO_BIN_EXE_stow-cli"),
        tools.path().join("stow-runtime"),
    )
    .expect("link the runtime");
    let script = |name: &str, body: &str| {
        let path = tools.path().join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}")).expect("write the script");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("make the script executable");
        path
    };
    let rustc = script(
        "recording-rustc",
        "rustc \"$@\"\nstatus=$?\n\
         if [ -n \"$STOW_TEST_UNIT\" ]; then : > \"$STOW_TEST_RECORD/rustc-exit-$STOW_TEST_UNIT\"; fi\n\
         exit $status\n",
    );
    let wrapper = script(
        "recording-wrapper",
        "STOW_TEST_UNIT=$$ \"$STOW_TEST_STOW_WRAPPER\" \"$@\"\nstatus=$?\n\
         : > \"$STOW_TEST_RECORD/wrapper-exit-$$\"\nexit $status\n",
    );

    let cache = support::tempdir().expect("cache dir");
    let target = support::tempdir().expect("target dir");
    let mut command = support::cargo_command();
    support::hermetic_stow_env(&mut command, &refused_url(), cache.path(), &stow_home);
    command
        .arg("build")
        .current_dir(dir.path())
        .env("CARGO_HOME", cargo_home.path())
        .env("CARGO_TARGET_DIR", target.path())
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_NET_OFFLINE", "true")
        .env("RUSTC", &rustc)
        .env("RUSTC_WRAPPER", &wrapper)
        .env("STOW_TEST_STOW_WRAPPER", &stow_wrapper)
        .env("STOW_TEST_RECORD", record.path());
    let output = support::output_after_session(&mut command, &stow_home);
    let _daemon = support::PrivateDaemon::in_home(&stow_home);
    assert!(
        output.status.success(),
        "the build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let modified = |name: &std::ffi::OsStr| {
        std::fs::metadata(record.path().join(name))
            .and_then(|metadata| metadata.modified())
            .expect("a recorded exit time")
    };
    let mut units = 0;
    for entry in std::fs::read_dir(record.path()).expect("list the record") {
        let name = entry.expect("entry").file_name();
        let Some(unit) = name
            .to_string_lossy()
            .strip_prefix("wrapper-exit-")
            .map(str::to_owned)
        else {
            continue;
        };
        let compiler_exit = modified(std::ffi::OsStr::new(&format!("rustc-exit-{unit}")));
        let wrapper_exit = modified(&name);
        let lag = wrapper_exit
            .duration_since(compiler_exit)
            .unwrap_or_else(|_| panic!("unit {unit}: the wrapper exited before its compiler"));
        assert!(
            lag < WRAPPER_EXIT_BOUND,
            "unit {unit}: the wrapper exited {lag:?} after its compiler"
        );
        units += 1;
    }
    assert!(
        units >= expected_stored_crates().len(),
        "only {units} units compiled through a wrapper"
    );

    // The session has ended, so the daemon's bookkeeping is complete.
    let stored = stored_crate_names(&cache.path().join("state-v3.sqlite3"));
    let expected = expected_stored_crates()
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(stored, expected, "the daemon stored every compiled unit");
}
