//! `stow build` must degrade to plain `cargo build`, never break it.
//!
//! Everything stow does before cargo launches — the resolver, the graph
//! analysis, the prefetch — is an optimization layer over a build that would
//! have succeeded without it. A degraded or hostile edge is therefore allowed
//! to cost cache hits and nothing else. Propagating one HTTP 500 out of the
//! prefetch used to fail the build outright, which is not "slower than cargo",
//! it is broken.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;

use stow_cli::protocol::{Answer, Request};

mod support;

use support::hermetic_stow_env;

/// An edge that answers the miss-admissions mint with an empty list and
/// then fails every other call with a 500.
///
/// This is the shape that actually broke a build: the mint call succeeds,
/// so stow proceeds as if the edge were up, and only then does the edge
/// start failing.
fn spawn_failing_edge(answer_admissions: bool) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a local edge");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            serve_one(stream, answer_admissions);
        }
    });
    (url, handle)
}

fn serve_one(mut stream: std::net::TcpStream, answer_admissions: bool) {
    let mut reader =
        std::io::BufReader::new(stream.try_clone().expect("clone the accepted stream"));
    let mut request_line = String::new();
    if std::io::BufRead::read_line(&mut reader, &mut request_line).is_err() {
        return;
    }
    let _body = read_request_body(&mut reader);

    let response_body = if answer_admissions && request_line.contains("/api/v1/admissions") {
        Some(EMPTY_ADMISSIONS.to_owned())
    } else {
        None
    };

    let response = response_body.map_or_else(
        || {
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_owned()
        },
        |body| {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        },
    );
    let _ = stream.write_all(response.as_bytes());
}

fn read_request_body(reader: &mut impl std::io::BufRead) -> Vec<u8> {
    let mut content_length = 0usize;
    let mut chunked = false;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
            break;
        }
        let lowered = header.to_ascii_lowercase();
        if let Some(value) = lowered.strip_prefix("content-length:") {
            content_length = value.trim().parse().unwrap_or(0);
        }
        if lowered.starts_with("transfer-encoding:") && lowered.contains("chunked") {
            chunked = true;
        }
    }
    let mut body = Vec::new();
    if chunked {
        loop {
            let mut size_line = String::new();
            if reader.read_line(&mut size_line).is_err() {
                break;
            }
            let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or("0"), 16)
                .unwrap_or(0);
            if size == 0 {
                break;
            }
            let mut chunk = vec![0u8; size];
            if std::io::Read::read_exact(reader, &mut chunk).is_err() {
                break;
            }
            body.extend_from_slice(&chunk);
            let mut terminator = [0u8; 2];
            let _ = std::io::Read::read_exact(reader, &mut terminator);
        }
    } else if content_length > 0 {
        body.resize(content_length, 0);
        let _ = std::io::Read::read_exact(reader, &mut body);
    }
    body
}

/// The `POST /api/v1/admissions` answer that mints nothing — the call
/// succeeds and redeems no tickets, so the only edge traffic left is
/// what every other call's 500 breaks.
const EMPTY_ADMISSIONS: &str = "[]";

fn write_crate(dir: &Path, cargo_home: &Path) {
    write_probe_crate(dir, cargo_home, "cfg-if = \"1\"\n");
}

/// Four leaf dependencies — four cacheable units, no dependency-identity
/// chains, so every build-1 store and every build-2 serve keys exactly.
fn write_leaf_dep_crate(dir: &Path, cargo_home: &Path) {
    write_probe_crate(
        dir,
        cargo_home,
        "cfg-if = \"1\"\nitoa = \"1\"\nryu = \"1\"\nunicode-ident = \"1\"\n",
    );
}

fn write_probe_crate(dir: &Path, cargo_home: &Path, dependencies: &str) {
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
    // Resolve now, so the build under test is not also a network test.
    // The fetch must share the isolated CARGO_HOME the builds use.
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

/// stow#608: a `STOW_CACHE_DIR` that cannot be used — here one below a
/// regular file, which fails for root too — costs cache hits, never the
/// build: every cache-state failure is a logged miss, and the build
/// still produces its binary.
#[test]
fn an_unusable_cache_dir_costs_cache_hits_not_the_build() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    write_crate(dir.path(), cargo_home.path());
    let setup_cache = tempfile::tempdir().expect("setup cache");
    let edge_url = unreachable_edge_url();
    stow_setup_in(dir.path(), &edge_url, setup_cache.path(), cargo_home.path());

    let blocker = tempfile::NamedTempFile::new().expect("blocker file");
    let cache_dir = blocker.path().join("cache");
    let target = tempfile::tempdir().expect("target");
    let output = stow_build_command(
        dir.path(),
        &edge_url,
        &cache_dir,
        cargo_home.path(),
        target.path(),
    );
    assert!(
        output.status.success(),
        "stow build failed with an unusable cache dir:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        probe_binary(target.path()).exists(),
        "the build still produced its binary"
    );
}

/// The probe crate's binary under `target_dir`, with the platform suffix.
fn probe_binary(target_dir: &Path) -> std::path::PathBuf {
    target_dir
        .join("debug")
        .join(format!("probe{}", std::env::consts::EXE_SUFFIX))
}

/// `stow-cli setup` in the isolated `CARGO_HOME` — the one-time mold
/// selection, kept out of every timed build.
fn stow_setup_in(dir: &Path, edge_url: &str, cache_dir: &Path, cargo_home: &Path) {
    // stow#294: a Linux `stow build` refuses to run without a mold
    // selection — `stow setup` installs mold and writes it. Idempotent.
    // Setup writes the global cargo config; the isolated CARGO_HOME keeps
    // the developer's real one untouched, and every call carries its own
    // STOW_CACHE_DIR so no test writes the developer's state DB — the
    // link-resolution row `stow setup` records lands where the caller
    // points (stow#608).
    let mut setup = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
    setup
        .arg("setup")
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home);
    hermetic_stow_env(&mut setup, edge_url, cache_dir);
    let setup = setup.output().expect("run stow-cli setup");
    assert!(
        setup.status.success(),
        "stow setup failed:\n{}",
        String::from_utf8_lossy(&setup.stderr)
    );
}

fn stow_build_in(
    dir: &Path,
    edge_url: &str,
    cache_dir: &Path,
    cargo_home: &Path,
) -> std::process::Output {
    stow_setup_in(dir, edge_url, cache_dir, cargo_home);
    stow_build_command(dir, edge_url, cache_dir, cargo_home, &dir.join("target"))
}

fn stow_build_command(
    dir: &Path,
    edge_url: &str,
    cache_dir: &Path,
    cargo_home: &Path,
    target_dir: &Path,
) -> std::process::Output {
    stow_build(dir, edge_url, cache_dir, cargo_home, target_dir)
        .output()
        .expect("run stow-cli build")
}

/// The `stow-cli build` invocation every build under test shares, before
/// it runs — a test that needs one more variable adds it here.
fn stow_build(
    dir: &Path,
    edge_url: &str,
    cache_dir: &Path,
    cargo_home: &Path,
    target_dir: &Path,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
    command
        .arg("build")
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home);
    hermetic_stow_env(&mut command, edge_url, cache_dir);
    command
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_TARGET_DIR", target_dir)
        .env_remove("RUST_LOG");
    command
}

fn state_db_pool(db: &Path) -> sqlx::SqlitePool {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(db))
                .await
                .expect("connect state db")
        })
}

fn state_db_query_i64(pool: &sqlx::SqlitePool, sql: &str) -> i64 {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .fetch_one(pool)
                .await
                .expect("query state db")
        })
}

fn state_db_exec(pool: &sqlx::SqlitePool, sql: &str) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(pool)
                .await
                .expect("write state db");
        });
}

#[test]
fn a_failing_edge_costs_cache_hits_not_the_build() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cache = tempfile::tempdir().expect("cache dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    write_crate(dir.path(), cargo_home.path());

    let (edge_url, _edge) = spawn_failing_edge(true);
    let output = stow_build_in(dir.path(), &edge_url, cache.path(), cargo_home.path());

    assert!(
        output.status.success(),
        "stow build failed against an edge that answers 500:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        probe_binary(&dir.path().join("target")).exists(),
        "stow build reported success without producing the binary"
    );
}

#[test]
fn an_edge_that_fails_every_call_costs_cache_hits_not_the_build() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cache = tempfile::tempdir().expect("cache dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    write_crate(dir.path(), cargo_home.path());

    let (edge_url, _edge) = spawn_failing_edge(false);
    let output = stow_build_in(dir.path(), &edge_url, cache.path(), cargo_home.path());

    assert!(
        output.status.success(),
        "stow build failed against an edge that answers 500 to everything:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn an_unreachable_edge_costs_cache_hits_not_the_build() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cache = tempfile::tempdir().expect("cache dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    write_crate(dir.path(), cargo_home.path());

    // Nothing is listening on this port.
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind to pick a port");
        listener.local_addr().expect("local addr").port()
    };
    let output = stow_build_in(
        dir.path(),
        &format!("http://127.0.0.1:{port}"),
        cache.path(),
        cargo_home.path(),
    );

    assert!(
        output.status.success(),
        "stow build failed against an unreachable edge:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The live `cargo --unit-graph` processes of the build whose cache
/// directory is `cache_dir`: the analysis's cargo child inherits the
/// build's `STOW_CACHE_DIR`, and keeps it when stow's exit reparents it —
/// the parent link is what an orphan loses. A process that has exited
/// reads back no environment and no command line.
#[cfg(target_os = "linux")]
fn live_unit_graph_children(cache_dir: &Path) -> Vec<u32> {
    let marker = format!("STOW_CACHE_DIR={}", cache_dir.display());
    let fields = |pid: u32, file: &str| -> Vec<Vec<u8>> {
        std::fs::read(format!("/proc/{pid}/{file}"))
            .unwrap_or_default()
            .split(|byte| *byte == 0)
            .map(<[u8]>::to_vec)
            .collect()
    };
    std::fs::read_dir("/proc")
        .expect("list /proc")
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            fields(*pid, "environ")
                .iter()
                .any(|field| field == marker.as_bytes())
                && fields(*pid, "cmdline")
                    .iter()
                    .any(|arg| arg == b"--unit-graph")
        })
        .collect()
}

/// stow#624: the in-build analysis stops with cargo. Its `cargo
/// --unit-graph` child used to outlive stow and keep probing rustc
/// through the wrapper after the build had returned; an empty crate is
/// the build whose cargo finishes before that child does.
#[cfg(target_os = "linux")]
#[test]
fn a_build_leaves_no_unit_graph_child_behind() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cache = tempfile::tempdir().expect("cache dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    write_empty_crate(dir.path());
    let output = stow_build_in(
        dir.path(),
        &unreachable_edge_url(),
        cache.path(),
        cargo_home.path(),
    );
    assert!(
        output.status.success(),
        "stow build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let orphans = live_unit_graph_children(cache.path());
    assert!(
        orphans.is_empty(),
        "stow returned with its unit-graph children still running: {orphans:?}"
    );
}

/// Build an empty crate whose `main.rs` is `main_rs` and list what the
/// build left where a build writes its generated files (stow#630): its
/// scratch and socket directories under the system temp directory —
/// pointed at a root this test owns, so every `stow-` entry there is this
/// build's — and the two places those files lived before the scratch
/// directory, `<STOW_CACHE_DIR>/graph-plans` and the target directory's
/// `rustc-extra-args-*`.
fn build_leftovers(main_rs: &str) -> (std::process::Output, Vec<std::path::PathBuf>) {
    let dir = tempfile::tempdir().expect("temp dir");
    let cache = tempfile::tempdir().expect("cache dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    let target = tempfile::tempdir().expect("target dir");
    let temp_root = tempfile::tempdir().expect("temp root");
    write_empty_crate(dir.path());
    std::fs::write(dir.path().join("src").join("main.rs"), main_rs).expect("write main.rs");
    let setup_cache = tempfile::tempdir().expect("setup cache");
    let edge_url = unreachable_edge_url();
    stow_setup_in(dir.path(), &edge_url, setup_cache.path(), cargo_home.path());
    let output = stow_build(
        dir.path(),
        &edge_url,
        cache.path(),
        cargo_home.path(),
        target.path(),
    )
    // `std::env::temp_dir` reads `TMPDIR` on Unix, `TMP` and `TEMP` on
    // Windows.
    .env("TMPDIR", temp_root.path())
    .env("TMP", temp_root.path())
    .env("TEMP", temp_root.path())
    .output()
    .expect("run stow-cli build");

    let named = |dir: &Path, prefix: &str| -> Vec<std::path::PathBuf> {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(error) => panic!("list {}: {error}", dir.display()),
        };
        entries
            .map(|entry| entry.expect("read directory entry"))
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
            .map(|entry| entry.path())
            .collect()
    };
    let mut leftovers = named(temp_root.path(), "stow-");
    leftovers.extend(named(&cache.path().join("graph-plans"), ""));
    leftovers.extend(named(target.path(), "rustc-extra-args"));
    (output, leftovers)
}

/// stow#630: a build removes the directory its generated files live in
/// when it ends.
#[test]
fn a_successful_build_leaves_no_generated_files_behind() {
    let (output, leftovers) = build_leftovers("fn main() {}\n");
    assert!(
        output.status.success(),
        "stow build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(leftovers.is_empty(), "the build left {leftovers:?}");
}

/// stow#630: a failing build leaves through `std::process::exit`, which
/// runs no destructors — its directories are removed all the same.
#[test]
fn a_failing_build_leaves_no_generated_files_behind() {
    let (output, leftovers) = build_leftovers("fn main() { let _: u32 = \"not a number\"; }\n");
    assert!(
        !output.status.success(),
        "a crate that does not compile built:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("mismatched types"),
        "the build failed before rustc did:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(leftovers.is_empty(), "the build left {leftovers:?}");
}

/// The `stow rustc` wrapper as `RUSTC_WRAPPER` — the shape `stow setup`
/// installs into `.cargo/config.toml`, exercised here against plain `cargo`.
fn write_rustc_wrapper_shim(dir: &Path) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let shim = dir.join("stow-rustc-wrapper.cmd");
        std::fs::write(
            &shim,
            format!(
                "@echo off\r\n\"{}\" rustc %*\r\n",
                env!("CARGO_BIN_EXE_stow-cli")
            ),
        )
        .expect("write rustc wrapper shim");
        shim
    }
    #[cfg(unix)]
    {
        // The shipped shape: the runtime itself under the wrapper name, which
        // is how it recovers the `rustc` role. A shell script here would
        // measure a fork of `sh` this build no longer pays for.
        let shim = dir.join("stow-rustc-wrapper");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stow-cli"), &shim)
            .expect("link rustc wrapper shim");
        shim
    }
}

fn cargo_build_in(
    dir: &Path,
    edge_url: &str,
    cache_dir: &Path,
    wrapper: &Path,
    target_dir: &Path,
    extra_envs: &[(&str, &str)],
    cargo_home: &Path,
) -> std::process::Output {
    let mut command = Command::new("cargo");
    command
        .arg("build")
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home);
    // The wrapper shim is `stow-cli rustc` under cargo: same hermetic
    // environment as a driver invocation.
    hermetic_stow_env(&mut command, edge_url, cache_dir);
    command
        .env("RUSTC_WRAPPER", wrapper)
        .env("CARGO_TARGET_DIR", target_dir)
        .env("CARGO_INCREMENTAL", "0")
        .env_remove("RUST_LOG")
        .envs(extra_envs.iter().copied());
    command.output().expect("run cargo build")
}

/// A remote miss compiles once and stores the outputs locally; every later
/// build — even inside a tripped circuit-breaker window — is served from the
/// local entry without touching the network.
#[test]
fn a_tripped_circuit_still_serves_local_entries() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cache = tempfile::tempdir().expect("cache dir");
    let target_a = tempfile::tempdir().expect("target dir a");
    let target_b = tempfile::tempdir().expect("target dir b");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    write_crate(dir.path(), cargo_home.path());
    let wrapper = write_rustc_wrapper_shim(dir.path());

    // Nothing is listening on this port: every remote lookup misses fast.
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind to pick a port");
        listener.local_addr().expect("local addr").port()
    };
    let edge_url = format!("http://127.0.0.1:{port}");

    // First build: no cached index slice means no remote attempt at all —
    // rustc compiles cfg-if and the outputs land in the local artifact
    // cache.
    let output = cargo_build_in(
        dir.path(),
        &edge_url,
        cache.path(),
        &wrapper,
        target_a.path(),
        &[],
        cargo_home.path(),
    );
    assert!(
        output.status.success(),
        "first cargo build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let pool = state_db_pool(&cache.path().join("state-v3.sqlite3"));
    assert_eq!(
        state_db_query_i64(
            &pool,
            "SELECT count(*) FROM artifact_cache_entries WHERE provenance = 'local'"
        ),
        1,
        "the passthrough build must store cfg-if as a local entry"
    );

    // Trip the breaker exactly the way a run of fetch failures would. The
    // window must not disable the local cache — a local hit never reaches the
    // network, so it keeps paying off through the outage that tripped it.
    let tripped_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_millis();
    state_db_exec(
        &pool,
        &format!(
            "INSERT INTO circuit_state (singleton, consecutive_failures, tripped_at_ms) \
             VALUES (1, 99, {tripped_at_ms}) \
             ON CONFLICT(singleton) DO UPDATE SET \
             consecutive_failures = 99, tripped_at_ms = {tripped_at_ms}"
        ),
    );

    // Second build, fresh target dir: cfg-if is served from the local entry.
    let output = cargo_build_in(
        dir.path(),
        &edge_url,
        cache.path(),
        &wrapper,
        target_b.path(),
        &[],
        cargo_home.path(),
    );
    assert!(
        output.status.success(),
        "second cargo build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        probe_binary(target_b.path()).exists(),
        "second build produced no binary"
    );

    // The hit counter proves the serve happened. The error counter staying
    // at zero proves no remote fetch was even attempted: under the local
    // index the wrapper consults the network only after a verified index
    // slice names a bundle, and this cache has no slice at all.
    assert_eq!(
        state_db_query_i64(
            &pool,
            "SELECT hits FROM crate_stats WHERE crate_name = 'cfg_if'"
        ),
        1
    );
    assert_eq!(
        state_db_query_i64(
            &pool,
            "SELECT errors FROM crate_stats WHERE crate_name = 'cfg_if'"
        ),
        0
    );
}

/// The frames a stub supervisor collected, bucketed by the crate each
/// frame's argv compiled (`--crate-name`). The empty key carries frames
/// with no argv — `Compiled` reports — and rustc probes like `-vV`,
/// which name no crate at all.
#[derive(Debug, Default)]
struct StubSupervision {
    plans: std::collections::BTreeMap<String, usize>,
    compiled: std::collections::BTreeMap<String, usize>,
    observed_marks: std::collections::BTreeMap<String, usize>,
    observed_reports: std::collections::BTreeMap<String, usize>,
}

/// The crate a supervisor frame compiled: `--crate-name`'s value in the
/// decoded argv. Frames with no argv — `Compiled`, `AwaitServeMap` —
/// name no crate.
fn frame_crate_name(request: &Request) -> String {
    let args = match request {
        Request::Plan(plan) => plan.args(),
        Request::Observed(observed) => observed.args(),
        _ => return String::new(),
    }
    .expect("the facade's args decode on this platform");
    args.iter()
        .position(|arg| arg == "--crate-name")
        .and_then(|index| args.get(index + 1))
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// One stub-supervisor connection: plans are told to compile, reports are
/// acknowledged, observations need no answer. Every frame is counted.
fn serve_stub_connection(
    mut stream: std::net::TcpStream,
    counts: &std::sync::Mutex<StubSupervision>,
) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(120)));
    let mut ticket = 0u64;
    loop {
        let mut length = [0u8; 4];
        if stream.read_exact(&mut length).is_err() {
            return;
        }
        let mut body = vec![0u8; u32::from_le_bytes(length) as usize];
        if stream.read_exact(&mut body).is_err() {
            return;
        }
        let Ok(request) = Request::from_frame_body(&body) else {
            return;
        };
        let crate_name = frame_crate_name(&request);
        let answer = match &request {
            Request::Plan(_) => {
                counts
                    .lock()
                    .expect("frame counts")
                    .plans
                    .entry(crate_name)
                    .and_modify(|count| *count += 1)
                    .or_insert(1);
                ticket += 1;
                Some(Answer::Compile { ticket })
            }
            Request::Compiled(_) => {
                counts
                    .lock()
                    .expect("frame counts")
                    .compiled
                    .entry(crate_name)
                    .and_modify(|count| *count += 1)
                    .or_insert(1);
                Some(Answer::Recorded)
            }
            Request::Observed(observed) => {
                let mut counts = counts.lock().expect("frame counts");
                let bucket = if observed.success.is_some() {
                    &mut counts.observed_reports
                } else {
                    &mut counts.observed_marks
                };
                bucket
                    .entry(crate_name)
                    .and_modify(|count| *count += 1)
                    .or_insert(1);
                None
            }
            Request::AwaitServeMap(_) => None,
        };
        let Some(answer) = answer else { continue };
        let body = serde_json::to_vec(&answer).expect("encode answer");
        let length = u32::try_from(body.len()).expect("frame body under the wire limit");
        if stream
            .write_all(&length.to_le_bytes())
            .and_then(|()| stream.write_all(&body))
            .and_then(|()| stream.flush())
            .is_err()
        {
            return;
        }
    }
}

/// A supervisor that answers every plan with `Compile` and every report
/// with `Recorded`, while counting which frames each crate produced.
/// Returns the loopback endpoint pieces and the shared count map.
fn spawn_stub_supervisor() -> (String, std::sync::Arc<std::sync::Mutex<StubSupervision>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub supervisor");
    let port = listener.local_addr().expect("local addr").port();
    let counts = std::sync::Arc::new(std::sync::Mutex::new(StubSupervision::default()));
    let accept_counts = std::sync::Arc::clone(&counts);
    std::thread::spawn(move || {
        let mut connections = Vec::new();
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            connections.push(std::thread::spawn({
                let counts = std::sync::Arc::clone(&accept_counts);
                move || serve_stub_connection(stream, &counts)
            }));
        }
        for connection in connections {
            let _ = connection.join();
        }
    });
    (format!("tcp:{port}"), counts)
}

/// A port nothing listens on, for the edge URL: every remote lookup is a
/// fast refused connect, which is the all-miss shape the issue profiles.
fn unreachable_edge_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind to pick a port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    format!("http://127.0.0.1:{port}")
}

/// The all-miss case issue stow#347 measured: the serve map is present
/// and covers nothing, so every registry compile still needs its mark and
/// report — but none of them may wait on a plan round trip. The frame
/// census is the regression signal a wall clock cannot catch: an
/// uncovered unit planning again is the per-invocation overhead the issue
/// traced, multiplied across every compile the build runs.
#[test]
fn an_all_miss_build_never_waits_on_the_supervisor() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cache = tempfile::tempdir().expect("cache dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    write_crate(dir.path(), cargo_home.path());
    let wrapper = write_rustc_wrapper_shim(dir.path());
    let (endpoint, counts) = spawn_stub_supervisor();
    let map_path = dir.path().join("serve-map.json");
    std::fs::write(&map_path, "{\"target\":[],\"host\":[]}").expect("write serve map");
    let map_path = map_path.to_str().expect("utf8 path");

    let output = cargo_build_in(
        dir.path(),
        &unreachable_edge_url(),
        cache.path(),
        &wrapper,
        &dir.path().join("target"),
        &[
            ("STOW_SUPERVISOR_ENDPOINT", endpoint.as_str()),
            ("STOW_SUPERVISOR_TOKEN", "test-token"),
            ("STOW_SERVE_MAP_FILE", map_path),
        ],
        cargo_home.path(),
    );
    assert!(
        output.status.success(),
        "stow build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        probe_binary(&dir.path().join("target")).exists(),
        "build produced no binary"
    );

    // Connection threads finish the instant each facade closes its
    // stream; the build's exit guarantees all frames were sent, and the
    // lock sees them once the stub has drained them.
    std::thread::sleep(std::time::Duration::from_millis(200));
    let (cfg_if_plans, cfg_if_marks, cfg_if_reports, probe_plans, debug) = {
        let counts = counts.lock().expect("frame counts");
        let values = (
            counts.plans.get("cfg_if").copied().unwrap_or(0),
            counts.observed_marks.get("cfg_if").copied().unwrap_or(0),
            counts.observed_reports.get("cfg_if").copied().unwrap_or(0),
            counts.plans.get("probe").copied().unwrap_or(0),
            format!("{counts:?}"),
        );
        drop(counts);
        values
    };
    assert_eq!(
        cfg_if_plans, 0,
        "an uncovered unit must never send a plan frame: {debug}"
    );
    assert_eq!(
        cfg_if_marks, 1,
        "the uncovered compile must still mark before rustc runs: {debug}"
    );
    assert_eq!(
        cfg_if_reports, 1,
        "the uncovered compile must still report afterwards: {debug}"
    );
    assert!(
        probe_plans >= 1,
        "the workspace crate, which the map cannot model, still plans: {debug}"
    );
}

/// The serve map's other half: a unit it covers still takes the plan
/// path, because only the supervisor can actually serve it. The map
/// answers "could anything serve this", not "compile".
#[test]
fn a_covered_unit_still_takes_the_plan_path() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cache = tempfile::tempdir().expect("cache dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    write_crate(dir.path(), cargo_home.path());
    let wrapper = write_rustc_wrapper_shim(dir.path());
    let (endpoint, counts) = spawn_stub_supervisor();
    // `cfg-if` compiles unspelled — no `--target` on a native build — so
    // the host side carries it, at any version. Map entries are
    // canonical crate names (underscores).
    let map_path = dir.path().join("serve-map.json");
    std::fs::write(&map_path, "{\"target\":[],\"host\":[[\"cfg_if\",\"*\"]]}")
        .expect("write serve map");
    let map_path = map_path.to_str().expect("utf8 path");

    let output = cargo_build_in(
        dir.path(),
        &unreachable_edge_url(),
        cache.path(),
        &wrapper,
        &dir.path().join("target"),
        &[
            ("STOW_SUPERVISOR_ENDPOINT", endpoint.as_str()),
            ("STOW_SUPERVISOR_TOKEN", "test-token"),
            ("STOW_SERVE_MAP_FILE", map_path),
        ],
        cargo_home.path(),
    );
    assert!(
        output.status.success(),
        "stow build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    std::thread::sleep(std::time::Duration::from_millis(200));
    let (cfg_if_plans, cfg_if_observed, debug) = {
        let counts = counts.lock().expect("frame counts");
        let values = (
            counts.plans.get("cfg_if").copied().unwrap_or(0),
            counts.observed_marks.get("cfg_if").copied().unwrap_or(0)
                + counts.observed_reports.get("cfg_if").copied().unwrap_or(0),
            format!("{counts:?}"),
        );
        drop(counts);
        values
    };
    assert_eq!(
        cfg_if_plans, 1,
        "a covered unit must keep the plan round trip: {debug}"
    );
    assert_eq!(
        cfg_if_observed, 0,
        "a covered unit emits no observations: {debug}"
    );
}

/// `STOW_DISABLE_PUBLIC_CACHE` disables the public edge, not the local
/// artifact cache: a stored entry still serves while the kill switch is set.
#[test]
fn a_disabled_public_cache_still_serves_local_entries() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cache = tempfile::tempdir().expect("cache dir");
    let target_a = tempfile::tempdir().expect("target dir a");
    let target_b = tempfile::tempdir().expect("target dir b");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    write_crate(dir.path(), cargo_home.path());
    let wrapper = write_rustc_wrapper_shim(dir.path());

    // Nothing is listening on this port: every remote lookup misses fast.
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind to pick a port");
        listener.local_addr().expect("local addr").port()
    };
    let edge_url = format!("http://127.0.0.1:{port}");
    let kill_switch = [("STOW_DISABLE_PUBLIC_CACHE", "1")];

    // First build under the kill switch: no public lookup happens, but the
    // passthrough still stores cfg-if in the local artifact cache.
    let output = cargo_build_in(
        dir.path(),
        &edge_url,
        cache.path(),
        &wrapper,
        target_a.path(),
        &kill_switch,
        cargo_home.path(),
    );
    assert!(
        output.status.success(),
        "first cargo build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let pool = state_db_pool(&cache.path().join("state-v3.sqlite3"));
    assert_eq!(
        state_db_query_i64(
            &pool,
            "SELECT count(*) FROM artifact_cache_entries WHERE provenance = 'local'"
        ),
        1,
        "the passthrough build must store cfg-if as a local entry"
    );

    // Second build, fresh target dir, kill switch still set: cfg-if is served
    // from the local entry — it is not a public artifact.
    let output = cargo_build_in(
        dir.path(),
        &edge_url,
        cache.path(),
        &wrapper,
        target_b.path(),
        &kill_switch,
        cargo_home.path(),
    );
    assert!(
        output.status.success(),
        "second cargo build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        probe_binary(target_b.path()).exists(),
        "second build produced no binary"
    );
    assert_eq!(
        state_db_query_i64(
            &pool,
            "SELECT hits FROM crate_stats WHERE crate_name = 'cfg_if'"
        ),
        1
    );
}

/// stow#617: a unit the local cache holds must serve whether or not a
/// graph or an index slice is cached. Build 2 runs the same cache
/// against a fresh target dir — before the fix the graph cache key
/// hashed `CARGO_TARGET_DIR`, so the lite pass saw no graph, admitted
/// no local units into the serve map, and every facade compiled over a
/// populated cache.
#[test]
fn a_fresh_target_dir_serves_everything_the_local_cache_holds() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cache = tempfile::tempdir().expect("cache dir");
    let target_a = tempfile::tempdir().expect("target dir a");
    let target_b = tempfile::tempdir().expect("target dir b");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    write_leaf_dep_crate(dir.path(), cargo_home.path());

    // Nothing listens on this port: the edge and the index registry
    // both refuse every connection, so build 2 can only serve from the
    // local artifact cache.
    let edge_url = unreachable_edge_url();
    stow_setup_in(dir.path(), &edge_url, cache.path(), cargo_home.path());

    let first = stow_build_command(
        dir.path(),
        &edge_url,
        cache.path(),
        cargo_home.path(),
        target_a.path(),
    );
    assert!(
        first.status.success(),
        "first stow build failed:\n{}",
        String::from_utf8_lossy(&first.stderr)
    );

    let output = stow_build_command(
        dir.path(),
        &edge_url,
        cache.path(),
        cargo_home.path(),
        target_b.path(),
    );
    assert!(
        output.status.success(),
        "second stow build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let summary = stdout
        .lines()
        .find(|line| line.contains("stow: served"))
        .expect("the coverage summary line");
    assert_eq!(
        summary.trim(),
        "stow: served 4 of 4 cacheable dependencies",
        "every locally stored dependency must serve on a fresh target dir\n\
         first build stderr:\n{}\nsecond build stderr:\n{}",
        String::from_utf8_lossy(&first.stderr),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// An empty crate: the build whose pre-cargo window is nothing but the
/// wrapper's own startup — spawn, config load, serve-map write, cargo
/// spawn — against cargo's window on the same nothing.
fn write_empty_crate(dir: &Path) {
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"empty\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write manifest");
    std::fs::create_dir_all(dir.join("src")).expect("create src");
    std::fs::write(dir.join("src").join("main.rs"), "fn main() {}\n").expect("write main.rs");
}

/// One timed pair on `dir`: plain cargo, then stow in a fresh
/// `STOW_CACHE_DIR` right after `stow setup`, each into a fresh target
/// directory — `(cargo, stow)`, each side its wall clock and its
/// pre-cargo window. The pair runs back to back so both sides see the
/// same machine load.
fn timed_pair(dir: &Path, cargo_home: &Path, edge_url: &str) -> (TimedBuild, TimedBuild) {
    let cargo_target = tempfile::tempdir().expect("cargo target");
    let mut command = Command::new("cargo");
    command
        .arg("build")
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_TARGET_DIR", cargo_target.path())
        .env("CARGO_INCREMENTAL", "0")
        // An empty RUSTC_WRAPPER is no wrapper to cargo, and it
        // overrides the `build.rustc-wrapper` stow setup wrote into
        // the shared cargo home — so the baseline is plain cargo
        // (stow#608).
        .env("RUSTC_WRAPPER", "")
        .env_remove("RUST_LOG");
    let (output, wall, window) = timed_build(&mut command);
    assert!(
        output.status.success(),
        "plain cargo build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cargo = TimedBuild { wall, window };

    let stow_cache = tempfile::tempdir().expect("stow cache");
    let stow_target = tempfile::tempdir().expect("stow target");
    stow_setup_in(dir, edge_url, stow_cache.path(), cargo_home);
    let mut command = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
    command
        .arg("build")
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home);
    hermetic_stow_env(&mut command, edge_url, stow_cache.path());
    command
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_TARGET_DIR", stow_target.path())
        .env_remove("RUST_LOG");
    let (output, wall, window) = timed_build(&mut command);
    assert!(
        output.status.success(),
        "stow build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // stow's in-build `--unit-graph` query must never take the
    // package-cache lock ahead of the real cargo — when it wins the
    // race, cargo's own resolve prints this on the user's stderr
    // (stow#608).
    assert!(
        !String::from_utf8_lossy(&output.stderr)
            .contains("Blocking waiting for file lock on package cache"),
        "stow's unit-graph query held the package-cache lock ahead of \
         the real cargo, which printed `Blocking waiting for file \
         lock`:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    (cargo, TimedBuild { wall, window })
}

/// One timed build's two clocks.
struct TimedBuild {
    wall: std::time::Duration,
    window: std::time::Duration,
}

/// A real multi-package project's manifest: fifty crates from
/// crates.io spanning leaf, mid-graph and proc-macro shapes — enough
/// rustc invocations for pre-cargo overhead to show on the wall clock,
/// and enough build time that the machine's noise floor resolves a few
/// percent.
fn write_multi_crate(dir: &Path, cargo_home: &Path) {
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
         [dependencies]\n\
         adler2 = \"2\"\naho-corasick = \"1\"\nanstyle = \"1\"\narc-swap = \"1\"\n\
         base64 = \"0.22\"\nbeef = \"0.5\"\nbitflags = \"2\"\nbytes = \"1\"\n\
         cfg_aliases = \"0.2\"\ncfg-if = \"1\"\ncrc32fast = \"1\"\ncrossbeam-utils = \"0.8\"\n\
         diff = \"0.1\"\ndunce = \"1\"\neither = \"1\"\nequivalent = \"1\"\n\
         fastrand = \"2\"\nfnv = \"1\"\nfoldhash = \"0.1\"\ngetopts = \"0.2\"\n\
         hashbrown = \"0.15\"\nhex = \"0.4\"\nindoc = \"2\"\nitoa = \"1\"\n\
         lazy_static = \"1\"\nlibm = \"0.2\"\nlog = \"0.4\"\nmatches = \"0.1\"\n\
         memchr = \"2\"\nminimal-lexical = \"0.2\"\nonce_cell = \"1\"\npaste = \"1\"\n\
         percent-encoding = \"2\"\npin-project-lite = \"0.2\"\nproc-macro2 = \"1\"\nquote = \"1\"\n\
         regex-syntax = \"0.8\"\nrustc-hash = \"2\"\nrustversion = \"1\"\nryu = \"1\"\n\
         scopeguard = \"1\"\nserde = \"1\"\nsmallvec = \"1\"\nstable_deref_trait = \"1\"\n\
         strsim = \"0.11\"\ntermcolor = \"1\"\ntinyvec = \"1\"\nunicase = \"2\"\n\
         unicode-ident = \"1\"\nunicode-width = \"0.2\"\nutf8parse = \"0.2\"\nversion_check = \"0.9\"\n\
         winnow = \"0.7\"\nwyz = \"0.5\"\nyoke = \"0.8\"\nzerocopy = \"0.8\"\n",
    )
    .expect("write manifest");
    std::fs::create_dir_all(dir.join("src")).expect("create src");
    std::fs::write(dir.join("src").join("main.rs"), "fn main() {}\n").expect("write main.rs");
    // Resolve now, so the build under test is not also a network test.
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

/// Timed runs per side: five is the smallest count whose median is
/// stable against the occasional scheduling stall while keeping the
/// suite fast.
const TIMED_RUNS: usize = 5;

fn median(times: &[std::time::Duration]) -> std::time::Duration {
    let mut sorted = times.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

/// How far a typical run drifts from the median — the second-largest
/// absolute deviation, so a single freak stall cannot widen the gate a
/// regression would hide inside.
fn typical_deviation(
    times: &[std::time::Duration],
    median: std::time::Duration,
) -> std::time::Duration {
    let mut deviations: Vec<std::time::Duration> =
        times.iter().map(|time| time.abs_diff(median)).collect();
    deviations.sort_unstable();
    deviations[deviations.len().saturating_sub(2)]
}

/// The tested `stow-cli` is built at the same profile as this test
/// crate. Under `cargo test` that is the debug build, whose fixed
/// per-invocation cost — process spawn, JSON parsing, sqlite open in
/// unoptimized code, ~45ms per rustc invocation on this host against
/// ~4ms for the release build — lands near +3s on this 60-unit build
/// through no fault of the implementation: an artifact of the harness,
/// not a shape users run. The wall-clock gate below therefore binds
/// only where the measured binary matches what ships — a release
/// build, where the allowance is zero and the gate is the raw noise
/// band. In debug the pre-cargo window gate still asserts the
/// regression the issue measured, because serial work before cargo's
/// first rustc cannot hide in an overlapped profile.
#[cfg(debug_assertions)]
const WALL_GATE_ENABLED: bool = false;
#[cfg(not(debug_assertions))]
const WALL_GATE_ENABLED: bool = true;

/// The medians comparison the wall-clock test asserts, separated from
/// the builds so the gate itself is testable: `residual` is how far
/// stow's median exceeds cargo's, `tolerance` is the combined measured
/// spread — cargo's own typical run-to-run deviation plus stow's —
/// plus `allowance`, the profile cost the debug binary legitimately
/// pays. A medians difference inside that band cannot be told from
/// machine noise on this host; a real regression stands above it.
struct WallComparison {
    cargo_median: std::time::Duration,
    stow_median: std::time::Duration,
    residual: std::time::Duration,
    tolerance: std::time::Duration,
}

impl WallComparison {
    fn passes(&self) -> bool {
        self.residual <= self.tolerance
    }
}

fn compare_wall_clock(
    cargo_times: &[std::time::Duration],
    stow_times: &[std::time::Duration],
    allowance: std::time::Duration,
) -> WallComparison {
    let cargo_median = median(cargo_times);
    let stow_median = median(stow_times);
    WallComparison {
        cargo_median,
        stow_median,
        residual: stow_median.saturating_sub(cargo_median),
        tolerance: typical_deviation(cargo_times, cargo_median)
            + typical_deviation(stow_times, stow_median)
            + allowance,
    }
}

/// One side's pre-cargo windows: on the measured project and on the
/// empty crate, the build whose window is nothing but startup.
struct Windows<'a> {
    project: &'a [std::time::Duration],
    empty: &'a [std::time::Duration],
}

/// The pre-cargo window comparison the test asserts. The one serial
/// cost a wrapper cannot remove is its own existence — stow-cli's
/// spawn, config load, serve-map write and cargo spawn — and that
/// `floor` is measured rather than asserted, so it scales with the
/// tested binary's profile: stow's window on a build with nothing to
/// compile, net of cargo's window on that same build. `residual` is
/// what stow adds on the project beyond that floor — the serial *work*
/// stow#347 bans: an index pull, a metadata pass, a graph analysis.
///
/// `tolerance` is the typical run-to-run deviation of all four sample
/// sets. The floor is a difference of two measured medians and is as
/// uncertain as they are: a band that left its two deviations out
/// would call the floor's own scatter a regression whenever the
/// project's samples happened to land tight (stow#608).
struct WindowComparison {
    floor: std::time::Duration,
    residual: std::time::Duration,
    tolerance: std::time::Duration,
}

impl WindowComparison {
    fn passes(&self) -> bool {
        self.residual <= self.tolerance
    }
}

fn compare_windows(cargo: &Windows<'_>, stow: &Windows<'_>) -> WindowComparison {
    let floor = median(stow.empty).saturating_sub(median(cargo.empty));
    WindowComparison {
        floor,
        residual: median(stow.project)
            .saturating_sub(median(cargo.project))
            .saturating_sub(floor),
        tolerance: [cargo.project, stow.project, cargo.empty, stow.empty]
            .into_iter()
            .map(|times| typical_deviation(times, median(times)))
            .sum(),
    }
}

/// Run a build to completion and report its wall clock along with the
/// time its first `Compiling` line arrived — the end of the pre-cargo
/// window the issue profiles. stderr is drained line by line so the
/// timestamp is read live, and kept for failure messages.
fn timed_build(
    command: &mut Command,
) -> (
    std::process::Output,
    std::time::Duration,
    std::time::Duration,
) {
    let mut child = command
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn build");
    let started = std::time::Instant::now();
    let stderr = child.stderr.take().expect("piped stderr");
    let mut first_compile = None;
    let mut collected = String::new();
    for line in std::io::BufRead::lines(std::io::BufReader::new(stderr)) {
        let Ok(line) = line else { break };
        if first_compile.is_none() && line.contains("Compiling") {
            first_compile = Some(started.elapsed());
        }
        collected.push_str(&line);
        collected.push('\n');
    }
    let status = child.wait().expect("wait on build");
    (
        std::process::Output {
            status,
            stdout: Vec::new(),
            stderr: collected.into_bytes(),
        },
        started.elapsed(),
        // A build that printed nothing compiled nothing; treat the
        // window as the whole wall clock rather than dropping it.
        first_compile.unwrap_or_else(|| started.elapsed()),
    )
}

/// The wall-clock floor the frame census above cannot see: on a cold
/// cache with the edge unreachable, everything stow pays before cargo
/// starts — index pulls, `cargo metadata`, the graph analysis — is time
/// the user feels. stow#347 measured 5% on a 295-package build and its
/// acceptance criterion is wall time: stow must never be slower than
/// cargo.
///
/// What is measured is an all-miss build on a machine where stow has
/// already run once: each stow iteration still gets a fresh
/// `STOW_CACHE_DIR`, so no artifact of the measured project is cached,
/// but an untimed `stow build` of the empty crate primes that cache dir
/// first — paying the one-time, per-machine cost the link resolution's
/// `rustc --print cfg` evaluation and the mold link probe are, the same
/// row `stow setup` records so a user's first build is already warm
/// (stow#608).
///
/// Two measurements per run, each side `TIMED_RUNS` times, interleaved
/// so both samples see the same machine load:
///
/// - the **pre-cargo window**: wall clock until the first `Compiling`
///   line. The regression this test exists for was ~3.5s of serial work
///   before cargo's first rustc — a window measurement isolates it at
///   ~50ms resolution in any build profile, because work overlapped
///   with cargo can never delay the first unit. The same pair is
///   timed on an empty crate in the same loop, which measures the
///   startup floor — the wrapper's own spawn/init cost, the one serial
///   cost a wrapper cannot remove — and what stow adds beyond that
///   floor is compared against the measured spread of all four sample
///   sets ([`compare_windows`]).
/// - the **total wall clock**: medians compared against the measured
///   spread plus `PROFILE_RESIDUAL_ALLOWANCE`, which covers the debug
///   binary's own per-invocation cost the suite cannot remove. In a
///   release build the allowance is zero and the gate is the raw noise
///   band — a systematic 5% bias stands above it.
///
/// Each timed stow build is the first build after `stow setup` in a
/// fresh `STOW_CACHE_DIR` (stow#608): the one-time machine-level costs
/// `stow setup` records — the link resolution's `rustc --print cfg`
/// evaluation and the driver's mold link probe — are warm on every
/// platform where a link resolution exists, while the project's own
/// artifacts stay all-miss. The same priming covers the startup floor.
#[test]
fn an_all_miss_build_is_never_slower_than_cargo() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    write_multi_crate(dir.path(), cargo_home.path());
    let setup_cache = tempfile::tempdir().expect("setup cache");
    let edge_url = unreachable_edge_url();
    stow_setup_in(dir.path(), &edge_url, setup_cache.path(), cargo_home.path());

    let empty_dir = tempfile::tempdir().expect("empty dir");
    write_empty_crate(empty_dir.path());

    let mut cargo_walls = Vec::with_capacity(TIMED_RUNS);
    let mut cargo_windows = Vec::with_capacity(TIMED_RUNS);
    let mut stow_walls = Vec::with_capacity(TIMED_RUNS);
    let mut stow_windows = Vec::with_capacity(TIMED_RUNS);
    let mut cargo_empty_windows = Vec::with_capacity(TIMED_RUNS);
    let mut stow_empty_windows = Vec::with_capacity(TIMED_RUNS);
    for _ in 0..TIMED_RUNS {
        let (cargo, stow) = timed_pair(empty_dir.path(), cargo_home.path(), &edge_url);
        cargo_empty_windows.push(cargo.window);
        stow_empty_windows.push(stow.window);

        let (cargo, stow) = timed_pair(dir.path(), cargo_home.path(), &edge_url);
        cargo_walls.push(cargo.wall);
        cargo_windows.push(cargo.window);
        stow_walls.push(stow.wall);
        stow_windows.push(stow.window);
    }

    let window_comparison = compare_windows(
        &Windows {
            project: &cargo_windows,
            empty: &cargo_empty_windows,
        },
        &Windows {
            project: &stow_windows,
            empty: &stow_empty_windows,
        },
    );
    assert!(
        window_comparison.passes(),
        "stow must never put serial work in front of cargo: \
         cargo windows {cargo_windows:?} on the project and {cargo_empty_windows:?} on the \
         empty crate, stow windows {stow_windows:?} and {stow_empty_windows:?}: beyond the \
         measured {:?} startup floor stow adds {:?}, which exceeds the measured run-to-run \
         spread {:?}",
        window_comparison.floor,
        window_comparison.residual,
        window_comparison.tolerance,
    );

    if WALL_GATE_ENABLED {
        let wall_comparison =
            compare_wall_clock(&cargo_walls, &stow_walls, std::time::Duration::ZERO);
        assert!(
            wall_comparison.passes(),
            "stow must never be slower than cargo on an all-miss build: \
             cargo runs {cargo_walls:?} (median {:?}), \
             stow runs {stow_walls:?} (median {:?}), \
             residual {:?} exceeds tolerance {:?} (the measured run-to-run spread)",
            wall_comparison.cargo_median,
            wall_comparison.stow_median,
            wall_comparison.residual,
            wall_comparison.tolerance
        );
    }
}

/// The window gate must reject serial work in front of cargo: the
/// ~95 ms stow#608 measured stands far above a startup floor and the
/// samples' scatter.
#[test]
fn the_window_gate_rejects_serial_work_beyond_the_floor() {
    let ms = |millis| std::time::Duration::from_millis(millis);
    let comparison = compare_windows(
        &Windows {
            project: &[65, 66, 64, 64, 66].map(ms),
            empty: &[41, 42, 42, 44, 42].map(ms),
        },
        &Windows {
            project: &[201, 207, 205, 212, 204].map(ms),
            empty: &[80, 87, 80, 81, 83].map(ms),
        },
    );
    assert!(!comparison.passes());
}

/// …and it must accept a window that is the startup floor and nothing
/// else, including when the project's samples land tighter than the
/// floor's: the floor is measured, so its scatter is part of the band.
#[test]
fn the_window_gate_accepts_the_startup_floor_within_its_own_scatter() {
    let ms = |millis| std::time::Duration::from_millis(millis);
    let comparison = compare_windows(
        &Windows {
            project: &[65, 65, 65, 65, 65].map(ms),
            empty: &[41, 42, 42, 44, 42].map(ms),
        },
        &Windows {
            project: &[107, 107, 107, 107, 107].map(ms),
            empty: &[80, 87, 80, 81, 83].map(ms),
        },
    );
    assert_eq!(comparison.floor, ms(39));
    assert_eq!(comparison.residual, ms(3));
    assert!(comparison.passes());
}

/// The gate must reject the shape stow#347 measured: a constant ~3.5s
/// paid before cargo starts — dozens of times the noise band at any
/// realistic build size.
#[test]
fn the_wall_clock_gate_rejects_the_pre_cargo_regression() {
    let ms = |millis| std::time::Duration::from_millis(millis);
    let cargo = [3200, 3250, 3180, 3220, 3210].map(ms);
    let stow = [6700, 6750, 6680, 6720, 6710].map(ms);
    assert!(!compare_wall_clock(&cargo, &stow, std::time::Duration::ZERO).passes());
}

/// The gate must reject a systematic +5% — the smallest bias stow#347's
/// acceptance criterion cares about — the moment it rises above the
/// samples' own spread.
#[test]
fn the_wall_clock_gate_rejects_a_five_percent_regression() {
    let ms = |millis| std::time::Duration::from_millis(millis);
    let cargo = [3200, 3230, 3170, 3210, 3190].map(ms);
    let stow = [3360, 3390, 3330, 3370, 3350].map(ms);
    assert!(!compare_wall_clock(&cargo, &stow, std::time::Duration::ZERO).passes());
}

/// …and it must accept the difference that is only noise: medians a
/// fraction of a percent apart with ordinary scatter stay inside the
/// measured band.
#[test]
fn the_wall_clock_gate_accepts_noise_level_differences() {
    let ms = |millis| std::time::Duration::from_millis(millis);
    let cargo = [3200, 3240, 3160, 3220, 3180].map(ms);
    let stow = [3210, 3250, 3170, 3230, 3190].map(ms);
    assert!(compare_wall_clock(&cargo, &stow, std::time::Duration::ZERO).passes());
}
