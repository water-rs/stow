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

use std::net::TcpListener;
use std::path::Path;
use std::process::Command;

/// The fixture's dependency list: the `proc-macro2`/`quote` pair — a
/// dependent small enough to finish before its dependency's rustc exits
/// — and two plain leaf crates. `unicode-ident` rides along as
/// `proc-macro2`'s own dependency.
fn write_fixture(dir: &Path, cargo_home: &Path) {
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
         [dependencies]\n\
         cfg-if = \"1\"\n\
         memchr = \"2\"\n\
         proc-macro2 = \"1\"\n\
         quote = \"1\"\n",
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

/// Every `crate_name` the fixture's all-miss build must store — the
/// cacheable units of the tree, named explicitly.
fn expected_stored_crates() -> std::collections::BTreeSet<&'static str> {
    ["cfg-if", "memchr", "proc-macro2", "quote", "unicode-ident"]
        .into_iter()
        .collect()
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
/// selection, kept out of the builds under test (stow#294: a Linux
/// `stow build` refuses to run without it).
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
        // The supervisor runs in this process, so its warnings are on
        // this stderr once `RUST_LOG` lets them through — the assertion
        // below needs them visible (stow#619).
        .env("RUST_LOG", "stow_cli=warn")
        .output()
        .expect("run stow-cli build")
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
    write_fixture(dir.path(), cargo_home.path());
    stow_setup_in(dir.path(), cargo_home.path());
    let edge_url = refused_url();
    let registry_url = refused_url();

    for run in 1..=3 {
        let cache = tempfile::tempdir().expect("cache dir");
        let target = tempfile::tempdir().expect("target dir");
        let output = stow_build_in(
            dir.path(),
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
            "run {run}: the local store must hold every cacheable unit of the fixture"
        );
    }
}
