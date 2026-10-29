//! The fixture project and the hermetic `stow build` the end-to-end
//! integration tests share.

use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};

use crate::support::{denied_registry, hermetic_stow_env, sealed_home_env};

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
#[allow(
    dead_code,
    reason = "each test crate compiles this module whole; only some call it"
)]
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
#[allow(
    dead_code,
    reason = "each test crate compiles this module whole; only some call it"
)]
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
    // Since stow#1032 setup also fetches the host index slice, so its
    // registry must answer — `denied_registry` reports the package
    // missing, which resolves to the empty index.
    let home = fixture_home(dir);
    hermetic_stow_env(
        &mut setup,
        &denied_registry(),
        &home.join("stow-cache"),
        &home,
    );
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
    // A drive-letter path is `file:///C:/...` with forward slashes;
    // spelling the path into the URL by hand leaves backslashes a TOML
    // basic string reads as escapes.
    url::Url::from_file_path(repo)
        .unwrap_or_else(|()| panic!("{} is not an absolute path", repo.display()))
        .to_string()
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

/// The `(host triple, release)` of the `rustc` on `PATH` — the same
/// probe the builds' wrapper answers these facts with.
#[allow(dead_code)] // only the local-only fixtures seed an index
pub fn rustc_host_and_release() -> (String, String) {
    let output = Command::new("rustc")
        .arg("-vV")
        .output()
        .expect("run rustc -vV");
    assert!(
        output.status.success(),
        "rustc -vV failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let vv = String::from_utf8_lossy(&output.stdout).into_owned();
    let field = |name: &str| {
        vv.lines()
            .find_map(|line| line.strip_prefix(&format!("{name}: ")))
            .unwrap_or_else(|| panic!("rustc -vV output is missing {name}"))
            .to_owned()
    };
    (field("host"), field("release"))
}

/// A package as cargo resolves it for a project: the version and the
/// feature set an index row for the package must carry to match the
/// build's own lookup.
#[allow(dead_code)] // only the local-only fixtures seed an index
pub struct ResolvedPackage {
    pub version: semver::Version,
    pub features: Vec<String>,
}

/// Every package `project` resolves, by name, as `cargo metadata`
/// reports it against `cargo_home`'s offline registry.
#[allow(dead_code)] // only the local-only fixtures seed an index
pub fn resolved_packages(
    project: &Path,
    cargo_home: &Path,
) -> std::collections::BTreeMap<String, ResolvedPackage> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--offline"])
        .current_dir(project)
        .env("CARGO_HOME", cargo_home)
        .output()
        .expect("run cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata is JSON");
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .expect("resolve nodes");
    metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .map(|package| {
            let name = package["name"].as_str().expect("package name").to_owned();
            let id = &package["id"];
            let node = nodes
                .iter()
                .find(|node| &node["id"] == id)
                .unwrap_or_else(|| panic!("{name} has no resolve node"));
            let features = node["features"]
                .as_array()
                .expect("node features")
                .iter()
                .map(|feature| feature.as_str().expect("feature name").to_owned())
                .collect();
            let version = package["version"]
                .as_str()
                .expect("package version")
                .parse()
                .expect("package version is semver");
            (name, ResolvedPackage { version, features })
        })
        .collect()
}

/// Write the index slice a remote serve of `entries` would resolve into
/// `cache`'s slice directory: one row per entry, keyed on the stored
/// `c_metadata`, carrying the version and feature set `resolved` gives
/// its package, and each `bundle_digest` carrying the stored
/// `compile_key` so a bundle fetch it triggers has that key in the
/// request line. A semantic lookup (`STOW_ENABLE_SEMANTIC_FALLBACK`)
/// of a leaf crate finds its row by that identity.
///
/// The file layout is the verified index cache's own
/// (`index/<target>/<rustc>/current.json`, its digest-named blob and the
/// `slice.lock` every locked read opens):
/// the read path decodes the blob without re-verifying, so a test can
/// stand in for a published slice the signature path would produce.
#[allow(dead_code)] // only the local-only fixtures seed an index
pub fn seed_index_slice(
    cache_dir: &Path,
    target: &str,
    rustc_version: &str,
    entries: &[StoredEntry],
    resolved: &std::collections::BTreeMap<String, ResolvedPackage>,
) {
    use sha2::Digest as _;
    use stow_types::identity::{
        CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, FeaturesJson, TargetTriple,
        WireRustcVersion,
    };
    use stow_types::index::{
        ARTIFACT_INDEX_FORMAT_VERSION, ArtifactIndex, ArtifactIndexHeader, ArtifactIndexRow,
    };
    let rows: Vec<ArtifactIndexRow> = entries
        .iter()
        .map(|entry| {
            let package = entry.crate_name.replace('_', "-");
            let resolved = resolved
                .get(&package)
                .unwrap_or_else(|| panic!("{package} is not resolved by the project"));
            ArtifactIndexRow {
                crate_name: CrateName::parse(package).expect("crate name"),
                version: CrateVersion::new(resolved.version.clone()),
                features_json: FeaturesJson::canonicalize(resolved.features.clone())
                    .expect("features"),
                dependency_c_metadata_json: DependencyCMetadataJson::default(),
                dependency_task_ids: Vec::new(),
                c_metadata: CMetadata::parse(entry.c_metadata.clone()).expect("c_metadata"),
                compile_key: entry.compile_key.clone(),
                bundle_digest: format!("sha256:{}", entry.compile_key),
                bundle_size: 1,
                artifact_kind: stow_types::artifact::ArtifactKind::Rlib,
                crate_types: vec![stow_types::artifact::RustCrateType::Rlib],
                profile: stow_types::platform::Profile {
                    opt_level: "0".to_owned(),
                    debuginfo: 2,
                    debug_assertions: true,
                    overflow_checks: true,
                    panic: stow_types::platform::PanicStrategy::Unwind,
                    strip: stow_types::platform::StripLevel::None,
                },
                emit: vec!["link".to_owned(), "metadata".to_owned()],
                unit_shape: stow_types::public_cache::UnitShape {
                    side: stow_types::public_cache::UnitSide::Target,
                    invocation: stow_types::public_cache::UnitInvocation::Native,
                    kind: stow_types::public_cache::UnitKind::Linked,
                },
                min_glibc: None,
            }
        })
        .collect();
    let index = ArtifactIndex {
        header: ArtifactIndexHeader {
            format_version: ARTIFACT_INDEX_FORMAT_VERSION,
            target: TargetTriple::parse(target.to_owned()).expect("target"),
            rustc_version: WireRustcVersion::parse(rustc_version.to_owned())
                .expect("rustc version"),
            generated_at: "2026-01-01T00:00:00Z".to_owned(),
            generation: 1,
            row_count: rows.len() as u64,
        },
        rows,
    };
    let blob = stow_types::index::encode(&index).expect("encode index");
    let manifest_digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob)));
    let dir = cache_dir.join("index").join(target).join(rustc_version);
    std::fs::create_dir_all(&dir).expect("create slice dir");
    std::fs::write(dir.join("slice.lock"), []).expect("write slice lock");
    std::fs::write(dir.join(manifest_digest.replace(':', "_")), &blob).expect("write slice blob");
    let fetched_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    std::fs::write(
        dir.join("current.json"),
        format!(
            "{{\"manifest_digest\":\"{manifest_digest}\",\"fetched_at\":{fetched_at},\"row_count\":{}}}",
            index.rows.len()
        ),
    )
    .expect("write slice pointer");
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
