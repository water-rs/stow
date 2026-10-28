//! The fixture project and the hermetic `stow build` the end-to-end
//! integration tests share.

use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};

use crate::support::{hermetic_stow_env, sealed_home_env};

/// The home the fixture's child processes get — one directory per
/// fixture, shared by every command the test runs in `dir` so `stow
/// setup`'s installs are visible to the builds (stow#800).
fn fixture_home(dir: &Path) -> std::path::PathBuf {
    dir.join("stow-home")
}

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
    let mut fetch = Command::new("cargo");
    fetch
        .arg("fetch")
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home);
    sealed_home_env(&mut fetch, &fixture_home(dir));
    let fetched = fetch.output().expect("run cargo fetch");
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
    let mut setup = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
    setup
        .arg("setup")
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home);
    // Setup reads `StowConfig::load` (and on Linux writes a link-cache
    // row into its state DB): without the sealed home and the pinned
    // stow variables it would consult the developer's `~/.stow` and
    // user-level config, and mold would install under the real home.
    let home = fixture_home(dir);
    hermetic_stow_env(&mut setup, &refused_url(), &home.join("stow-cache"), &home);
    let setup = setup.output().expect("run stow-cli setup");
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
    hermetic_stow_env(&mut command, edge_url, cache_dir, &fixture_home(dir));
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

/// Copy the directory tree at `from` into `to`.
#[allow(dead_code)] // only the fixtures that vendor a registry source call it
pub fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("create copy target");
    for entry in std::fs::read_dir(from).expect("read copy source") {
        let entry = entry.expect("copy source entry");
        let dest = to.join(entry.file_name());
        if entry.file_type().expect("entry type").is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            std::fs::copy(entry.path(), &dest).expect("copy file");
        }
    }
}

/// Copy the extracted registry source of `package` (any version) out of
/// the isolated `cargo_home` into `to`.
#[allow(dead_code)] // only the fixtures that vendor a registry source call it
pub fn copy_registry_package(cargo_home: &Path, package: &str, to: &Path) {
    let registry_src = cargo_home.join("registry").join("src");
    let prefix = format!("{package}-");
    for index in std::fs::read_dir(&registry_src).expect("read registry src") {
        for entry in
            std::fs::read_dir(index.expect("index dir").path()).expect("read registry package dir")
        {
            let entry = entry.expect("package entry");
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(&prefix))
            {
                copy_tree(&entry.path(), to);
                return;
            }
        }
    }
    panic!("the fetched {package} source was not found");
}

/// Turn `repo` into a git repository with every file committed, and
/// return the `file://` URL cargo clones it from.
#[allow(dead_code)] // only the git fixtures call it
pub fn commit_git_repo(repo: &Path, home: &Path) -> String {
    for args in [
        &["init", "--quiet", "--initial-branch=main"][..],
        &["add", "--all"],
        &[
            "-c",
            "user.name=stow-test",
            "-c",
            "user.email=stow-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "--message=fixture",
        ],
    ] {
        let mut git = Command::new("git");
        git.args(args).current_dir(repo);
        sealed_home_env(&mut git, home);
        let output = git.output().expect("run git");
        assert!(
            output.status.success(),
            "git {args:?} failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    format!("file://{}", repo.display())
}

/// `cargo fetch` in `dir` against the isolated `cargo_home`, so the
/// builds under test never need the network (git checkouts included).
#[allow(dead_code)] // only the fixtures that edit their manifest call it
pub fn cargo_fetch(dir: &Path, cargo_home: &Path) {
    let mut fetch = Command::new("cargo");
    fetch
        .arg("fetch")
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home);
    sealed_home_env(&mut fetch, &fixture_home(dir));
    let fetched = fetch.output().expect("run cargo fetch");
    assert!(
        fetched.status.success(),
        "cargo fetch failed:\n{}",
        String::from_utf8_lossy(&fetched.stderr)
    );
}

/// One `artifact_cache_entries` row the local store holds.
#[allow(dead_code)] // only the local-only fixtures read the store
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct StoredEntry {
    pub crate_name: String,
    pub compile_key: String,
    pub c_metadata: String,
    pub reach: i64,
}

/// Every entry the state db at `db` stores; empty when the build stored
/// nothing and so never created the db.
#[allow(dead_code)] // only the local-only fixtures read the store
pub fn stored_entries(db: &Path) -> Vec<StoredEntry> {
    if !db.exists() {
        return Vec::new();
    }
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
            let rows = sqlx::query_as::<_, StoredEntry>(sqlx::AssertSqlSafe(
                "SELECT crate_name, compile_key, c_metadata, reach FROM artifact_cache_entries"
                    .to_owned(),
            ))
            .fetch_all(&pool)
            .await
            .expect("list stored entries");
            pool.close().await;
            rows
        })
}

/// Every request line a [`recording_edge`] has received.
#[allow(dead_code)] // only the local-only fixtures record requests
pub type RecordedRequests = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

/// A local edge and registry that answers every request `404` and
/// records its request line: what a build asked the remote for.
#[allow(dead_code)] // only the local-only fixtures record requests
pub fn recording_edge() -> (String, RecordedRequests) {
    use std::io::{BufRead, Write};
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a recording edge");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    let recorded: RecordedRequests = std::sync::Arc::default();
    let requests = std::sync::Arc::clone(&recorded);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let requests = std::sync::Arc::clone(&requests);
            std::thread::spawn(move || {
                let mut line = String::new();
                let Ok(clone) = stream.try_clone() else {
                    return;
                };
                if std::io::BufReader::new(clone).read_line(&mut line).is_ok() {
                    requests
                        .lock()
                        .expect("recorded requests lock")
                        .push(line.trim_end().to_owned());
                }
                let _ = stream.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            });
        }
    });
    (url, recorded)
}

/// The miss journals and drain claims `target_dir` holds: a build that
/// reported a miss leaves `stow-misses.*` there until its detached
/// drain has admitted it.
#[allow(dead_code)] // only the local-only fixtures read the journals
pub fn journal_files(target_dir: &Path) -> Vec<String> {
    std::fs::read_dir(target_dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with("stow-misses."))
                .collect()
        })
        .unwrap_or_default()
}
