//! `stow build` must degrade to plain `cargo build`, never break it.
//!
//! Everything stow does before cargo launches — the resolver, the graph
//! analysis, the prefetch — is an optimization layer over a build that would
//! have succeeded without it. A degraded or hostile edge is therefore allowed
//! to cost cache hits and nothing else. Propagating one HTTP 500 out of the
//! prefetch used to fail the build outright, which is not "slower than cargo",
//! it is broken.

use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;

/// An edge that answers the graph analysis with a plausible plan and then
/// fails every artifact fetch with a 500.
///
/// This is the shape that actually broke a build: the graph call succeeds, so
/// stow decides the cache covers the workspace and enters the prefetch phase,
/// and only then does the edge start failing.
fn spawn_failing_edge(advertise_artifacts: bool) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a local edge");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            serve_one(stream, advertise_artifacts);
        }
    });
    (url, handle)
}

fn serve_one(mut stream: std::net::TcpStream, advertise_artifacts: bool) {
    let mut reader =
        std::io::BufReader::new(stream.try_clone().expect("clone the accepted stream"));
    let mut request_line = String::new();
    if std::io::BufRead::read_line(&mut reader, &mut request_line).is_err() {
        return;
    }
    let body = read_request_body(&mut reader);

    let response_body = if request_line.contains("/api/v1/catalog/resolve-lockfile") {
        Some(NO_LOCKFILE_RESPONSE.to_owned())
    } else if advertise_artifacts && request_line.contains("/api/v1/catalog/graph") {
        Some(graph_response(&body))
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

/// Echo an analysis entry for every dependency the client asked about, and
/// advertise one cached artifact each, so stow believes the cache covers this
/// workspace and proceeds to prefetch.
fn graph_response(request_body: &[u8]) -> String {
    let request: serde_json::Value =
        serde_json::from_slice(request_body).unwrap_or(serde_json::Value::Null);
    let asked = request
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut entries = Vec::new();
    let mut prefetch = Vec::new();
    for (index, dependency) in asked.iter().enumerate() {
        let c_metadata = format!("{index:016x}");
        entries.push(serde_json::json!({
            "dependency": dependency,
            "current_artifact_count": 1,
            "current_artifacts": [{"c_metadata": c_metadata}],
            "recommended": serde_json::Value::Null,
        }));
        prefetch.push(serde_json::json!({
            "crate_name": dependency.get("crate_name"),
            "c_metadata": c_metadata,
        }));
    }
    prefetch.sort_by_key(|entry| entry["crate_name"].as_str().unwrap_or_default().to_owned());

    serde_json::json!({
        "entries": entries,
        "expanded_cached": prefetch.len(),
        "expanded_total": prefetch.len(),
        "expanded_entries": [],
        "prefetch_artifacts": prefetch,
    })
    .to_string()
}

const NO_LOCKFILE_RESPONSE: &str = r#"{"lockfile_toml":null,"uncovered_direct":[],"candidates_considered":0,"seed_diagnostics":[]}"#;

fn write_crate(dir: &Path, cargo_home: &Path) {
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
         [dependencies]\ncfg-if = \"1\"\n",
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

/// The probe crate's binary under `target_dir`, with the platform suffix.
fn probe_binary(target_dir: &Path) -> std::path::PathBuf {
    target_dir
        .join("debug")
        .join(format!("probe{}", std::env::consts::EXE_SUFFIX))
}

fn stow_build_in(
    dir: &Path,
    edge_url: &str,
    cache_dir: &Path,
    cargo_home: &Path,
) -> std::process::Output {
    // stow#294: a Linux `stow build` refuses to run without a mold
    // selection — `stow setup` installs mold and writes it. Idempotent.
    // Setup writes the global cargo config; the isolated CARGO_HOME keeps
    // the developer's real one untouched.
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
    Command::new(env!("CARGO_BIN_EXE_stow-cli"))
        .arg("build")
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home)
        .env("STOW_EDGE_URL", edge_url)
        .env("STOW_CACHE_DIR", cache_dir)
        // Isolate from the developer's ambient stow config: a user-level
        // `verify_mode = "mock-key"` (or an inherited `STOW_CONFIG_BLOB`)
        // would make this binary reject the config and skip the cache.
        .env("STOW_VERIFY_MODE", "github-ci")
        .env_remove("STOW_CONFIG_BLOB")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .env("CARGO_INCREMENTAL", "0")
        .env_remove("RUST_LOG")
        .output()
        .expect("run stow-cli build")
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
            sqlx::query_scalar::<_, i64>(sql)
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
            sqlx::query(sql)
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
        .env("CARGO_HOME", cargo_home)
        .env("STOW_EDGE_URL", edge_url)
        .env("STOW_CACHE_DIR", cache_dir)
        // Isolate from the developer's ambient stow config: a user-level
        // `verify_mode = "mock-key"` (or an inherited `STOW_CONFIG_BLOB`)
        // would make the wrapper reject the config and skip the cache.
        .env("STOW_VERIFY_MODE", "github-ci")
        .env_remove("STOW_CONFIG_BLOB")
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

/// What a stub supervisor hears from the facades during a build, counted
/// by frame kind. The wire protocol is the u32 little-endian length +
/// JSON frame `cli/src/supervisor/protocol.rs` defines, re-implemented
/// here because integration tests cannot reach the crate internals.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Default)]
struct FrameCounts {
    plans: usize,
    compiled: usize,
    marks: usize,
    observed: usize,
}

/// A supervisor that answers every request the way a build with nothing
/// cached would: `Plan` gets `Compile` with a minted ticket and
/// `Compiled` gets `Recorded`. `Observed` frames are fire-and-forget in
/// both directions — the `success: null` provenance mark and the
/// `Some(_)` report alike get no reply.
#[cfg(unix)]
fn spawn_stub_supervisor() -> (
    String,
    std::sync::Arc<std::sync::Mutex<FrameCounts>>,
    std::net::TcpListener,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub supervisor");
    let endpoint = format!("tcp:{}", listener.local_addr().expect("local addr").port());
    let counts = std::sync::Arc::new(std::sync::Mutex::new(FrameCounts::default()));
    (endpoint, counts, listener)
}

#[cfg(unix)]
fn stub_serve(listener: &TcpListener, counts: &std::sync::Mutex<FrameCounts>) {
    let mut next_ticket = 1u64;
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else {
            break;
        };
        while let Some(frame) = read_frame(&mut stream) {
            let request: serde_json::Value =
                serde_json::from_slice(&frame).expect("supervisor frame must be JSON");
            if request.get("Plan").is_some() {
                counts.lock().expect("counts").plans += 1;
                let ticket = next_ticket;
                next_ticket += 1;
                write_frame(
                    &mut stream,
                    &serde_json::json!({"Compile": {"ticket": ticket}}),
                );
            } else if request.get("Compiled").is_some() {
                counts.lock().expect("counts").compiled += 1;
                write_frame(&mut stream, &serde_json::json!("Recorded"));
            } else if let Some(observed) = request.get("Observed") {
                if observed
                    .get("success")
                    .is_some_and(serde_json::Value::is_null)
                {
                    counts.lock().expect("counts").marks += 1;
                    // The mark is one-way: the facade never reads a reply.
                    continue;
                }
                counts.lock().expect("counts").observed += 1;
                // The report is one-way too: the facade never reads a reply.
            } else {
                panic!("unknown supervisor frame: {request}");
            }
        }
    }
}

/// One-way frames (marks, observed reports) sit in the socket backlog
/// until the stub's reader thread schedules — a count read the moment the
/// last facade exits can miss in-flight deliveries on a loaded runner.
/// Wait for the expected totals instead: the frames were already sent, so
/// delivery is certain; the deadline only bounds a genuinely broken wire.
#[cfg(unix)]
fn wait_for_frames(
    counts: &std::sync::Mutex<FrameCounts>,
    want: impl Fn(&FrameCounts) -> bool,
) -> FrameCounts {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let snapshot = *counts.lock().expect("counts");
        if want(&snapshot) || std::time::Instant::now() >= deadline {
            return snapshot;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[cfg(unix)]
fn read_frame(stream: &mut impl std::io::Read) -> Option<Vec<u8>> {
    let mut header = [0u8; 4];
    std::io::Read::read_exact(stream, &mut header).ok()?;
    let len = u32::from_le_bytes(header) as usize;
    let mut body = vec![0u8; len];
    std::io::Read::read_exact(stream, &mut body).ok()?;
    Some(body)
}

#[cfg(unix)]
fn write_frame(stream: &mut impl std::io::Write, value: &serde_json::Value) {
    let body = serde_json::to_vec(value).expect("answer frame serializes");
    stream
        .write_all(
            &u32::try_from(body.len())
                .expect("frame body fits in u32")
                .to_le_bytes(),
        )
        .expect("write frame length");
    stream.write_all(&body).expect("write frame body");
}

/// stow#347: an all-miss build must not pay a serve check per rustc
/// invocation. With the once-per-build serve map in place, a unit the map
/// does not cover is known a miss before any IPC — the facade marks the
/// unit's provenance, compiles, and reports the observation. A `Plan`
/// request reaching the supervisor here means the per-invocation check is
/// back.
#[cfg(unix)]
#[test]
fn an_uncovered_unit_never_asks_the_supervisor_for_a_plan() {
    const UNITS: usize = 30;
    let dir = tempfile::tempdir().expect("temp dir");
    let source = dir.path().join("lib.rs");
    std::fs::write(&source, "pub fn value() -> u32 { 1 }\n").expect("write lib.rs");
    let out_dir = dir.path().join("out");
    std::fs::create_dir(&out_dir).expect("create out dir");

    let (endpoint, counts, listener) = spawn_stub_supervisor();
    let counts_for_stub = counts.clone();
    std::thread::spawn(move || stub_serve(&listener, &counts_for_stub));

    let units = serde_json::json!([["covered_crate", "*"]]).to_string();
    let run = |crate_name: &str| {
        Command::new(env!("CARGO_BIN_EXE_stow-cli"))
            .arg("rustc")
            // A real rustc over a trivial unit: the point is the frames
            // around the compile, and their cost, not the compile itself.
            .arg("rustc")
            .arg("--crate-name")
            .arg(crate_name)
            .arg(&source)
            .arg("--crate-type")
            .arg("lib")
            .arg("--emit")
            .arg("metadata")
            .arg("--out-dir")
            .arg(&out_dir)
            .env("STOW_SUPERVISOR_ENDPOINT", &endpoint)
            .env("STOW_SUPERVISOR_TOKEN", "stub")
            .env("STOW_SERVABLE_UNITS_JSON", &units)
            .env_remove("STOW_CONFIG_BLOB")
            .output()
            .expect("run stow rustc facade")
    };

    for index in 0..UNITS {
        let output = run(&format!("probe_{index}"));
        assert!(
            output.status.success(),
            "facade invocation failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    {
        // A Plan request is answered synchronously: had any facade sent
        // one, its count would already be in — no wait is needed to know
        // zero is final.
        assert_eq!(
            counts.lock().expect("counts").plans,
            0,
            "uncovered units asked the supervisor for a plan"
        );
        let counts = wait_for_frames(&counts, |snapshot| {
            snapshot.marks == UNITS && snapshot.observed == UNITS
        });
        assert_eq!(counts.marks, UNITS, "missing provenance marks");
        assert_eq!(counts.observed, UNITS, "missing observed reports");
        assert_eq!(counts.compiled, 0, "uncovered units reported Compiled");
    }

    // A unit the map covers still takes the plan path — and a probe
    // (unparseable args) does too. Both cost exactly one round trip.
    let covered = run("covered_crate");
    assert!(covered.status.success(), "covered invocation failed");
    let probe = Command::new(env!("CARGO_BIN_EXE_stow-cli"))
        .arg("rustc")
        .arg("rustc")
        .arg("--version")
        .env("STOW_SUPERVISOR_ENDPOINT", &endpoint)
        .env("STOW_SUPERVISOR_TOKEN", "stub")
        .env("STOW_SERVABLE_UNITS_JSON", &units)
        .output()
        .expect("run probe facade");
    assert!(probe.status.success(), "probe invocation failed");
    let counts = wait_for_frames(&counts, |snapshot| {
        snapshot.plans == 2 && snapshot.compiled == 2 && snapshot.marks == UNITS
    });
    assert_eq!(counts.plans, 2, "covered unit and probe must plan");
    assert_eq!(counts.compiled, 2, "planned units report Compiled");
    assert_eq!(counts.marks, UNITS, "the fast path must not send marks");
}

/// stow#347: a cold C-object store is the same once-per-build answer the
/// serve map gives rustc — so a `stow cc` facade under
/// `STOW_CC_PENDING_JOURNAL` must exec the compiler exactly once, with
/// only the compile arguments, and journal the compile for the drain. A
/// facade that re-runs the lookup pipeline would spawn the compiler
/// again for `--version` or `-E`; the stub compiler counts every call.
#[cfg(unix)]
#[test]
fn a_cold_cc_store_journals_the_compile_instead_of_looking_up() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("temp dir");
    let calls_log = dir.path().join("calls.log");
    let compiler = dir.path().join("cc");
    std::fs::write(
        &compiler,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$STOW_TEST_CALLS_LOG\"\nexit 0\n",
    )
    .expect("write stub compiler");
    std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o755))
        .expect("chmod stub compiler");
    let journal = dir.path().join("stow-cc-pending.stow-test.jsonl");

    let output = Command::new(env!("CARGO_BIN_EXE_stow-cli"))
        .arg("cc")
        .arg(&compiler)
        .args(["-c", "foo.c", "-o", "foo.o"])
        .env("STOW_CC_PENDING_JOURNAL", &journal)
        .env("STOW_TEST_CALLS_LOG", &calls_log)
        .output()
        .expect("run stow cc facade");
    assert!(
        output.status.success(),
        "cc facade invocation failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let calls = std::fs::read_to_string(&calls_log).expect("stub compiler never ran");
    assert_eq!(
        calls, "-c\nfoo.c\n-o\nfoo.o\n",
        "the facade must exec the compiler once, with only the compile args — a `--version` or `-E` call means the lookup path is back"
    );

    let line = std::fs::read_to_string(&journal)
        .expect("no pending journal written")
        .lines()
        .next()
        .expect("journal has no entries")
        .to_owned();
    let entry: serde_json::Value = serde_json::from_str(&line).expect("pending entry is JSON");
    assert_eq!(entry["program"], compiler.to_str().expect("utf8 path"));
    assert_eq!(
        entry["args"],
        serde_json::json!(["-c", "foo.c", "-o", "foo.o"])
    );
    assert_eq!(entry["success"], true);
}

/// stow#347: the serve decision travels with the build once, as the
/// serve map cargo hands every facade — not as a per-invocation lookup.
/// Each member's build script reports back the map it inherited, so this
/// test counts the invocations that saw it.
/// A `members`-crate workspace of path dependencies whose build scripts
/// each record the serve map they inherited into `STOW_TEST_UNITS_LOG`.
fn write_probe_workspace(dir: &Path, members: usize) {
    let mut names = String::new();
    for index in 0..members {
        use std::fmt::Write as _;
        let _ = write!(names, "\"member_{index}\",");
    }
    std::fs::write(
        dir.join("Cargo.toml"),
        format!("[workspace]\nresolver = \"2\"\nmembers = [{names}]\n"),
    )
    .expect("write workspace manifest");
    for index in 0..members {
        let member = dir.join(format!("member_{index}"));
        std::fs::create_dir_all(member.join("src")).expect("create member");
        std::fs::write(
            member.join("Cargo.toml"),
            format!(
                "[package]\nname = \"member_{index}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
            ),
        )
        .expect("write member manifest");
        std::fs::write(member.join("src").join("lib.rs"), "pub fn f() {}\n")
            .expect("write member lib");
        std::fs::write(
            member.join("build.rs"),
            r#"fn main() {
    // Under plain cargo (the comparison build) neither env exists.
    if let Ok(log) = std::env::var("STOW_TEST_UNITS_LOG") {
        let endpoint = u8::from(std::env::var_os("STOW_SUPERVISOR_ENDPOINT").is_some());
        // The complete map arrives in the env; a build whose index fetch
        // is still in flight hands the file instead, refreshed in place.
        let units = std::env::var("STOW_SERVABLE_UNITS_JSON")
            .ok()
            .or_else(|| {
                std::env::var("STOW_SERVE_MAP_FILE")
                    .ok()
                    .and_then(|path| std::fs::read_to_string(path).ok())
            })
            .unwrap_or_else(|| "ABSENT".to_owned());
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .expect("open units log");
        // One write: build-script runs race for the log, and separate
        // writes interleave into unparseable lines.
        let line = format!("{}|{endpoint}|{units}\n", env!("CARGO_PKG_NAME"));
        let _ = std::io::Write::write_all(&mut file, line.as_bytes());
    }
}
"#,
        )
        .expect("write member build.rs");
    }
}

#[test]
fn a_workspace_build_shares_one_serve_map() {
    const MEMBERS: usize = 30;
    let dir = tempfile::tempdir().expect("temp dir");
    let cache = tempfile::tempdir().expect("cache dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    let units_log = dir.path().join("units.log");
    write_probe_workspace(dir.path(), MEMBERS);

    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind to pick a port");
        listener.local_addr().expect("local addr").port()
    };
    let edge_url = format!("http://127.0.0.1:{port}");

    // The stow build: path dependencies are never covered, so every one
    // of these units is a miss decided by the serve map, not by a plan.
    let output = Command::new(env!("CARGO_BIN_EXE_stow-cli"))
        .arg("build")
        .current_dir(dir.path())
        .env("CARGO_HOME", cargo_home.path())
        // Isolate HOME the same way CARGO_HOME is isolated: a stray user
        // stow config on the runner would change which build path runs.
        .env("HOME", cargo_home.path())
        .env("STOW_EDGE_URL", &edge_url)
        .env("STOW_CACHE_DIR", cache.path())
        .env("STOW_VERIFY_MODE", "github-ci")
        .env("STOW_TEST_UNITS_LOG", &units_log)
        .env_remove("STOW_CONFIG_BLOB")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .env("CARGO_INCREMENTAL", "0")
        .env_remove("RUST_LOG")
        .output()
        .expect("run stow build");
    assert!(
        output.status.success(),
        "stow build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = std::fs::read_to_string(&units_log).unwrap_or_else(|error| {
        panic!(
            "no member saw the serve map ({error}); stow build stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let mut seen = 0usize;
    for line in log.lines() {
        let mut fields = line.splitn(3, '|');
        let name = fields.next().expect("log line has a member name");
        assert_eq!(
            fields.next(),
            Some("1"),
            "{name} ran with no supervisor endpoint; stow build stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let units = fields.next().expect("log line has a serve map");
        assert_ne!(
            units,
            "ABSENT",
            "{name} ran supervised with no serve map; stow build stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let map: Vec<Vec<String>> =
            serde_json::from_str(units).expect("serve map must be a JSON pair list");
        assert!(
            map.iter().all(|pair| pair.len() == 2 && pair[0] != name),
            "{name} is a path dependency — it must not be in its own serve map"
        );
        seen += 1;
    }
    assert_eq!(seen, MEMBERS, "not every member's build script ran");

    // No wall-clock comparison: a bound loose enough to never flake would
    // pass even a real regression, and a tighter one flakes. The precise
    // guard stays the zero-Plan-frames assertion in the test above.
}

/// Partial coverage with real serves: a mock registry holds signed bundles
/// and index rows for the consumer's heavy dependency subtrees, and
/// deliberately lacks the leaf `hex`. The build-start prefetch fetches and
/// verifies every covered bundle off the wall clock — a covered unit's
/// wrapper only does a local lookup + inject — so `stow build` stays at or
/// under `cargo build` even while the uncovered leaf still compiles
/// (stow#347). The covered subtree is most of the wall clock, so the
/// ordering holds even on a loaded runner.
#[cfg(unix)]
#[test]
fn partial_coverage_network_serves_stay_at_or_under_cargo() {
    use partial::*;
    let work = tempfile::tempdir().expect("work dir");
    let consumer = work.path().join("consumer");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    let stow_cache = tempfile::tempdir().expect("stow cache");
    let registry_root = work.path().join("registry");
    std::fs::create_dir_all(&consumer).expect("consumer dir");

    // A leaf-heavy covered set (~15 crates) plus one uncovered leaf, hex:
    // the partial-coverage shape stow#347 measured as slower than cargo.
    write_consumer(&consumer, cargo_home.path());
    let bin_dir = build_serve_binaries();
    let (private_key, public_key) = write_mock_key_pair(&work.path().join("keys"));

    // stow setup writes the mold config into the shared CARGO_HOME, so the
    // capture and the measured build key linked units identically.
    run("stow setup", {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
        command
            .arg("setup")
            .current_dir(&consumer)
            .env("CARGO_HOME", cargo_home.path());
        command
    });
    let mut registry = serve_registry(&bin_dir, &registry_root);
    let edge_url = registry.wait_with_output_url();
    // `stow-build` runs with the real HOME — its sandboxed cargo execs the
    // mold at the managed install path, which an isolated HOME would
    // shadow — and only consumes the mock env for its cache staging.
    capture_and_publish(
        &bin_dir,
        &consumer,
        &edge_url,
        cargo_home.path(),
        &registry_root,
        &private_key,
        &public_key,
        work.path(),
    );

    let mock_env = |command: &mut Command| {
        mock_registry_env(
            command,
            &edge_url,
            stow_cache.path(),
            cargo_home.path(),
            &public_key,
        );
        command.env("CARGO_INCREMENTAL", "0").env_remove("RUST_LOG");
    };
    // Warm the signed index slice: the measured build's prefetch then only
    // fetches bundles, like the real pipeline.
    run("stow index refresh", {
        let mut command = Command::new(bin_dir.join("stow-cli"));
        command.arg("index").arg("refresh").current_dir(&consumer);
        mock_env(&mut command);
        command
    });

    // Interleave three pairs and take medians: a single cold build is
    // subject to runner noise that exceeds the margin being measured.
    let (mut cargo_secs, mut stow_outputs) = (Vec::new(), Vec::new());
    for _ in 0..3 {
        let (secs, output) = measure_interleaved(&consumer, cargo_home.path(), &bin_dir, &mock_env);
        cargo_secs.push(secs);
        stow_outputs.push(output);
    }
    let _ = registry.kill();
    let _ = registry.child.wait();
    let cargo_secs = median_secs(cargo_secs);
    let stow_secs = median_secs(stow_outputs.iter().map(|output| output.secs).collect());

    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&stow_outputs[1].output.stdout),
        String::from_utf8_lossy(&stow_outputs[1].output.stderr)
    );
    // Real serves happened and coverage stayed partial: at least one unit
    // served from the mock registry, and `hex` — absent from the index by
    // construction — compiled.
    let (served, missed) = served_missed(&report);
    assert!(
        served >= 1,
        "expected at least one network serve; stow output:\n{report}"
    );
    assert!(
        missed >= 1,
        "expected partial coverage — hex must compile; stow output:\n{report}"
    );
    // The structural invariant, not a clock reading: a covered unit's
    // wrapper does a local lookup + inject — fetch and signature verify
    // belong to the build-start prefetch. A per-invocation `download`,
    // `verify`, or `verify_store` phase means a wrapper paid the network
    // or the trust root itself, which is exactly the regression stow#347
    // measured. Up to two may legitimately race the prefetch's ledger
    // registration and serve themselves; beyond that, the prefetch is
    // leaving fetch or verify on the wall clock.
    let per_invocation_costs = ["download", "verify", "verify_store"]
        .iter()
        .map(|phase| count_serve_phase(&report, phase))
        .sum::<usize>();
    assert!(
        per_invocation_costs <= 2,
        "{per_invocation_costs} wrappers fetched or verified a covered bundle themselves; \
         the prefetch must keep fetch+verify off the wall clock; stow output:\n{report}"
    );
    // The wall bound tolerates scheduler noise — stow's fixed spawn and
    // serve-map costs are tens of milliseconds on a sub-second project —
    // but not the shape it guards: per-invocation fetch+verify costs
    // ≥500ms per covered unit on a real index (xh measured ~640ms),
    // hundreds of milliseconds locally.
    assert!(
        stow_secs <= cargo_secs + 0.5,
        "stow {stow_secs:.2}s exceeded cargo {cargo_secs:.2}s by over 500ms \
         on a partially covered build; the prefetch must keep fetch+verify \
         off the wall clock"
    );
}

#[cfg(unix)]
mod partial {
    use super::*;

    /// Capture every consumer dep (discovery + bounded re-capture) into the
    /// running registry — the phase that makes the build's prefetch find
    /// real bundles on the network.
    #[allow(clippy::too_many_arguments)]
    pub fn capture_and_publish(
        bin_dir: &Path,
        consumer: &Path,
        edge_url: &str,
        cargo_home: &Path,
        registry_root: &Path,
        private_key: &Path,
        public_key: &Path,
        work: &Path,
    ) {
        let capture_env = |command: &mut Command| {
            command
                .env("CARGO_HOME", cargo_home)
                .env("STOW_EDGE_URL", edge_url)
                .env(
                    "STOW_REGISTRY_BASE_URL",
                    format!("{edge_url}/v2/water-rs/stow-cache"),
                )
                .env("STOW_CACHE_DIR", work.join("capture-cache"))
                .env("STOW_VERIFY_MODE", "mock-key")
                .env("STOW_MOCK_PUBLIC_KEY_PATH", public_key)
                .env_remove("STOW_CONFIG_BLOB")
                .env("NO_PROXY", "127.0.0.1,localhost")
                .env("no_proxy", "127.0.0.1,localhost");
        };
        capture_dep_units(
            bin_dir,
            consumer,
            &capture_env,
            registry_root,
            private_key,
            public_key,
            work,
        );
    }

    /// Point a command's environment at the running mock registry — the same
    /// env `stow build`/`stow-build`/`stow index refresh` all read.
    pub fn mock_registry_env(
        command: &mut Command,
        edge_url: &str,
        cache_dir: &Path,
        cargo_home: &Path,
        public_key: &Path,
    ) {
        command
            .env("CARGO_HOME", cargo_home)
            .env("HOME", cargo_home)
            .env("STOW_EDGE_URL", edge_url)
            .env(
                "STOW_REGISTRY_BASE_URL",
                format!("{edge_url}/v2/water-rs/stow-cache"),
            )
            .env("STOW_CACHE_DIR", cache_dir)
            .env("STOW_VERIFY_MODE", "mock-key")
            .env("STOW_MOCK_PUBLIC_KEY_PATH", public_key)
            .env_remove("STOW_CONFIG_BLOB")
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost");
    }

    /// The consumer fixture: a bin on a leaf-heavy dep set (the covered
    /// subtrees) plus `hex` (deliberately uncovered), fetched so the measured
    /// builds are not also a fetch test.
    ///
    /// The covered set is chosen so every demanded dep context is reproducible
    /// by a per-crate task — a unit's compile key embeds its deps' `c_metadata`,
    /// so subtrees whose consumer-side feature unions diverge from the crate's
    /// own resolution (proc-macro trees with feature forwarding, e.g.
    /// `clap_derive`'s `proc-macro2` union) can never be served to a per-crate
    /// `stow-build` and the gated build defects on them forever.
    pub fn write_consumer(consumer: &Path, cargo_home: &Path) {
        std::fs::write(
            consumer.join("Cargo.toml"),
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
         [dependencies]\nitoa = \"1\"\n\
         ryu = \"1\"\nmemchr = \"2\"\nsmallvec = \"1\"\nscopeguard = \"1\"\n\
         once_cell = \"1\"\npercent-encoding = \"2\"\nunicode-bidi = \"0.3\"\n\
         tinyvec = \"1\"\nequivalent = \"1\"\n\
         unicode-normalization = \"0.1\"\nbyteorder = \"1\"\n\
         hex = \"0.4\"\n",
        )
        .expect("write consumer manifest");
        std::fs::create_dir_all(consumer.join("src")).expect("create src");
        std::fs::write(
            consumer.join("src").join("main.rs"),
            "fn main() { let _ = hex::encode([1u8]); }\n",
        )
        .expect("write main.rs");
        run("cargo fetch", {
            let mut command = Command::new("cargo");
            command
                .arg("fetch")
                .current_dir(consumer)
                .env("CARGO_HOME", cargo_home);
            command
        });
    }

    /// The host triple the capture + consumer builds share.
    pub fn host_target_triple() -> String {
        let output = Command::new("rustc")
            .arg("-vV")
            .output()
            .expect("rustc -vV");
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .expect("rustc host triple")
            .to_owned()
    }

    /// Build `stow-build` + `stow-mock-registry` once for the serve fixture —
    /// they are workspace members, not binaries of the package under test.
    pub fn build_serve_binaries() -> std::path::PathBuf {
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("cli package has a workspace root")
            .to_path_buf();
        // stow-cli with mock-verify — `STOW_VERIFY_MODE=mock-key` errors on a
        // default-feature build — plus the capture and registry helpers.
        run("cargo build serve binaries", {
            let mut command = Command::new("cargo");
            command
                .arg("build")
                .args([
                    "-p",
                    "stow-cli",
                    "--features",
                    "mock-verify",
                    "-p",
                    "stow-build",
                    "-p",
                    "stow-mock-registry",
                ])
                .current_dir(&workspace_root);
            command
        });
        workspace_root.join("target").join("debug")
    }

    /// P-256 PKCS#8 key pair — the format sigstore accepts (docs/MOCK.md).
    pub fn write_mock_key_pair(keys_dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
        std::fs::create_dir_all(keys_dir).expect("keys dir");
        let private_key = keys_dir.join("private.pem");
        let public_key = keys_dir.join("public.pem");
        run("openssl keygen", {
            let mut command = Command::new("openssl");
            command
                .args(["ecparam", "-name", "prime256v1", "-genkey", "-noout"])
                .arg("-out")
                .arg(&private_key);
            command
        });
        run("openssl pkcs8", {
            let mut command = Command::new("openssl");
            command
                .args(["pkcs8", "-topk8", "-nocrypt", "-in"])
                .arg(&private_key)
                .arg("-out")
                .arg(keys_dir.join("private.pkcs8.pem"));
            command
        });
        std::fs::rename(keys_dir.join("private.pkcs8.pem"), &private_key).expect("pkcs8 key");
        run("openssl pubkey", {
            let mut command = Command::new("openssl");
            command
                .args(["ec", "-in"])
                .arg(&private_key)
                .args(["-pubout", "-out"])
                .arg(&public_key);
            command
        });
        (private_key, public_key)
    }

    /// Capture the whole covered subtree bottom-up: each task builds exactly
    /// one crate while its already-captured deps stage from the mock registry
    /// — the gated `stow-build` refuses a build that compiles foreign units,
    /// so dep order matters. Each plan's records join `records.json` and the
    /// index slice is republished before the next task's consume stage
    /// fetches it.
    ///
    /// A node identity includes the resolved feature set, and a task's
    /// internal dep resolution computes sets the consumer never does (e.g.
    /// `quote` needs proc-macro2 `{proc-macro}` while the consumer's union
    /// is `{default,proc-macro}`). When a task's gate reports such a unit,
    /// its entry lands back in the queue right before the task that needed
    /// it — stow-build names the exact nodes cargo resolved, so discovery
    /// converges without reimplementing cargo's feature resolver.
    pub fn capture_dep_units(
        bin_dir: &Path,
        consumer: &Path,
        capture_env: &dyn Fn(&mut Command),
        registry_root: &Path,
        private_key: &Path,
        public_key: &Path,
        work: &Path,
    ) {
        let rustc_version_output = Command::new("rustc")
            .arg("--version")
            .output()
            .expect("rustc --version");
        let rustc_version = String::from_utf8_lossy(&rustc_version_output.stdout)
            .split_whitespace()
            .nth(1)
            .expect("rustc version")
            .to_owned();
        let target = host_target_triple();
        let records_file = work.join("records.json");
        let mut records = Vec::<serde_json::Value>::new();
        let mut queue = dep_chain(consumer);
        // Captures per unit are bounded, not one-shot: a demanded compile key
        // embeds the served deps' keys, and the serve layer prefers an exact
        // emit match — so a unit captured before a dep's unlinked variant row
        // exists publishes keys nobody demands any more. Re-capturing it once
        // the dep's fuller row set exists produces the demanded key.
        let mut captures = std::collections::BTreeMap::<String, u32>::new();
        for unit in &queue {
            captures.insert(
                format!(
                    "{}|{}|{}|{}",
                    unit.name, unit.version, unit.features_json, unit.host_side
                ),
                1,
            );
        }
        let mut retries = DefectRetries::default();
        let mut index = 0;
        while index < queue.len() {
            // Cloned: the defect path inserts discovered units ahead of this
            // index, which borrows `queue` mutably.
            let unit = queue[index].clone();
            let task = serde_json::json!({
                "task_id": format!("t-{index}-{}", unit.name),
                "crate_name": unit.name,
                "version": unit.version,
                "features_json": unit.features_json,
                "target": target,
                "rustc_version": rustc_version,
                // Drop the crate's bundled lock: the wrapper then resolves the
                // same latest semver the consumer's fresh lock pinned, so dep
                // versions — and therefore `c_metadata` — agree across tasks.
                "preserve_lockfile": false,
                "host_side": unit.host_side,
            });
            let capture_out = work.join("capture").join(format!("{index}-{}", unit.name));
            let build = {
                let mut command = Command::new(bin_dir.join("stow-build"));
                command.arg("build").arg("--output-dir").arg(&capture_out);
                command
                    .env("STOW_BUILD_TASK_JSON", task.to_string())
                    .current_dir(consumer);
                capture_env(&mut command);
                command.output().expect("run stow-build build")
            };
            if !build.status.success() {
                handle_defected_task(
                    &unit,
                    &build.stderr,
                    index,
                    &mut queue,
                    &mut captures,
                    &mut retries,
                    &records_file,
                );
                continue;
            }
            retries.stale_defect_rounds = 0;
            captures
                .entry(format!(
                    "{}|{}|{}|{}",
                    unit.name, unit.version, unit.features_json, unit.host_side
                ))
                .and_modify(|ran| *ran = (*ran).max(1))
                .or_insert(1);
            publish_plan(
                bin_dir,
                &capture_out.join("upload-plan.json"),
                registry_root,
                private_key,
                public_key,
                work.join(format!("records-{index}-{}.json", unit.name))
                    .as_path(),
            );
            let batch: Vec<serde_json::Value> = serde_json::from_slice(
                &std::fs::read(work.join(format!("records-{index}-{}.json", unit.name)))
                    .expect("read records"),
            )
            .expect("parse records");
            records.extend(batch);
            std::fs::write(&records_file, serde_json::to_vec_pretty(&records).unwrap())
                .expect("write combined records");
            run("mock-registry index-from-records", {
                let mut command = Command::new(bin_dir.join("stow-mock-registry"));
                command
                    .arg("index-from-records")
                    .arg("--records")
                    .arg(&records_file)
                    .arg("--registry-root")
                    .arg(registry_root)
                    .arg("--private-key")
                    .arg(private_key);
                command
            });
            index += 1;
        }
    }

    /// Bounded retry budgets for the capture loop: infra flakes ride out a
    /// few retries, and a defect demanding nothing new three rounds in a row
    /// is a real coverage bug — the published key set cannot produce the
    /// demanded key — and fails the test with the published records dumped.
    #[derive(Default)]
    pub struct DefectRetries {
        pub infra_retries: usize,
        pub stale_defect_rounds: usize,
    }

    /// One failed `stow-build build`: a foreign-unit defect means the demanded
    /// dep units need captures first (insert them ahead of the failing index,
    /// bounded at three captures per unit), while an empty defect list is a
    /// sandbox/infra failure.
    pub fn handle_defected_task(
        unit: &CaptureUnit,
        stderr: &[u8],
        index: usize,
        queue: &mut Vec<CaptureUnit>,
        captures: &mut std::collections::BTreeMap<String, u32>,
        retries: &mut DefectRetries,
        records_file: &Path,
    ) {
        let missing = foreign_units(stderr);
        if missing.is_empty() {
            // No foreign-unit defect: this is a sandbox/infra failure
            // (wrapper exec denied, identity-sidecar timeout), not a
            // coverage gap. Bounded retries ride out heel flakes.
            retries.infra_retries += 1;
            let infra_retries = retries.infra_retries;
            assert!(
                infra_retries <= 4,
                "stow-build build failed {infra_retries} times in a row:\n{}",
                String::from_utf8_lossy(stderr)
            );
            return;
        }
        retries.infra_retries = 0;
        let mut added = 0usize;
        let enqueue =
            |unit: &CaptureUnit,
             index: usize,
             queue: &mut Vec<CaptureUnit>,
             captures: &mut std::collections::BTreeMap<String, u32>| {
                let key = format!(
                    "{}|{}|{}|{}",
                    unit.name, unit.version, unit.features_json, unit.host_side
                );
                let ran = captures.entry(key).or_insert(0);
                (*ran < 3) && {
                    *ran += 1;
                    queue.insert(index, unit.clone());
                    true
                }
            };
        for unit in &missing {
            if enqueue(unit, index, queue, captures) {
                added += 1;
            }
        }
        if added == 0 {
            // `target=host` in the defect only means the unit compiled under
            // the native spelling — a target-side dep of the failing crate
            // shows the same. Retry the opposite side: the other task shape
            // publishes the other shape's keys.
            for unit in &missing {
                let flipped = CaptureUnit {
                    host_side: !unit.host_side,
                    name: unit.name.clone(),
                    version: unit.version.clone(),
                    features_json: unit.features_json.clone(),
                };
                if enqueue(&flipped, index, queue, captures) {
                    added += 1;
                }
            }
        }
        if added == 0 {
            retries.stale_defect_rounds += 1;
            if retries.stale_defect_rounds > 3 {
                let unit_name = unit.name.clone();
                std::fs::copy(records_file, format!("/tmp/stale-records-{unit_name}.json")).ok();
            }
            let stale_defect_rounds = retries.stale_defect_rounds;
            assert!(
                stale_defect_rounds <= 3,
                "foreign-unit defect repeated with no new units — published keys do not cover the demand (records dumped to /tmp/stale-records-{}.json):\n{}",
                unit.name,
                String::from_utf8_lossy(stderr)
            );
        } else {
            retries.stale_defect_rounds = 0;
        }
    }

    /// Parse the gated-build defect's unit list — `name version
    /// features=[a,b] target=host` per line — into the task entries the
    /// queue needs before retrying. A foreign unit without a stable compile
    /// key (the "would have been served" suffix is absent) can never be
    /// staged, so the build fails for real and panics here.
    pub fn foreign_units(stderr: &[u8]) -> Vec<CaptureUnit> {
        // The defect text arrives inside a `Message("...\n...")` wrapper —
        // its line breaks are literal backslash-n escapes, so unescape first.
        let text = String::from_utf8_lossy(stderr).replace("\\n", "\n");
        let mut units = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            let Some((head, _key)) =
                line.split_once(" — would have been served under compile key ")
            else {
                continue;
            };
            let mut fields = head.split_whitespace();
            let (Some(name), Some(version)) = (fields.next(), fields.next()) else {
                continue;
            };
            let Some(features) = fields
                .next()
                .and_then(|field| field.strip_prefix("features=["))
                .and_then(|field| field.strip_suffix(']'))
            else {
                continue;
            };
            let features_json = serde_json::to_string(
                &features
                    .split(',')
                    .filter(|feature| !feature.is_empty())
                    .collect::<Vec<_>>(),
            )
            .expect("features json");
            units.push(CaptureUnit {
                name: name.to_owned(),
                version: version.to_owned(),
                features_json,
                host_side: fields.next() == Some("target=host"),
            });
        }
        units
    }

    /// One covered crate to capture, in dependency order.
    #[derive(Clone)]
    pub struct CaptureUnit {
        pub name: String,
        pub version: String,
        pub features_json: String,
        pub host_side: bool,
    }

    /// Every registry dep of the consumer except the deliberately uncovered
    /// `hex`, in dependency order, with the side the consumer needs it at:
    /// a proc-macro crate — or one only ever pulled by host-side crates —
    /// builds a `host_side` task so its captured units are the host shapes
    /// the consumer's proc-macro/build-script invocations key on.
    pub fn dep_chain(consumer: &Path) -> Vec<CaptureUnit> {
        let output = Command::new("cargo")
            .arg("metadata")
            .arg("--format-version")
            .arg("1")
            .arg("--filter-platform")
            .arg(host_target_triple())
            .current_dir(consumer)
            .output()
            .expect("cargo metadata");
        assert!(
            output.status.success(),
            "cargo metadata failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let metadata: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("parse cargo metadata");
        let nodes = metadata["resolve"]["nodes"]
            .as_array()
            .expect("resolve nodes");
        let registry_name = |id: &str| -> Option<String> {
            let package = metadata["packages"]
                .as_array()
                .expect("packages array")
                .iter()
                .find(|package| package["id"] == id)
                .unwrap_or_else(|| panic!("package {id} in metadata"));
            if package["source"].is_null() {
                return None;
            }
            Some(package["name"].as_str().expect("package name").to_owned())
        };
        let DepGraph {
            deps_of,
            dependents,
            mut host,
        } = dep_graph(&metadata, &registry_name);
        // Host side: proc-macro crates unconditionally, plus every crate
        // whose dependents are all host (reached only through proc-macro
        // edges). `hex` stays out of the graph — the uncovered leaf.
        loop {
            let mut grew = false;
            for (name, dependents) in &dependents {
                if name == "hex" || host.contains(name) {
                    continue;
                }
                if dependents.iter().all(|dependent| host.contains(dependent)) {
                    host.insert(name.clone());
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
        // Post-order DFS: each crate after the covered crates it depends on.
        let mut order = Vec::<String>::new();
        let mut seen = std::collections::BTreeSet::<String>::new();
        for name in deps_of.keys() {
            if name != "hex" {
                visit(name, &deps_of, &mut seen, &mut order);
            }
        }
        order
            .into_iter()
            .map(|name| {
                let node = nodes
                    .iter()
                    .find(|node| {
                        registry_name(node["id"].as_str().expect("node id")).as_deref()
                            == Some(name.as_str())
                    })
                    .expect("node for covered crate");
                let package = metadata["packages"]
                    .as_array()
                    .expect("packages array")
                    .iter()
                    .find(|package| package["id"] == node["id"])
                    .expect("package for covered crate");
                CaptureUnit {
                    host_side: host.contains(&name),
                    name,
                    version: package["version"].as_str().expect("version").to_owned(),
                    features_json: serde_json::to_string(
                        &node["features"].as_array().expect("node features"),
                    )
                    .expect("features json"),
                }
            })
            .collect()
    }

    /// The consumer's dep graph as (deps, dependents, proc-macro seeds) — the
    /// inputs the side fixpoint and the topological order both need.
    pub struct DepGraph {
        pub deps_of: std::collections::BTreeMap<String, Vec<String>>,
        pub dependents: std::collections::BTreeMap<String, Vec<String>>,
        pub host: std::collections::BTreeSet<String>,
    }

    pub fn dep_graph(
        metadata: &serde_json::Value,
        registry_name: &dyn Fn(&str) -> Option<String>,
    ) -> DepGraph {
        let packages = metadata["packages"].as_array().expect("packages array");
        let nodes = metadata["resolve"]["nodes"]
            .as_array()
            .expect("resolve nodes");
        let mut deps_of = std::collections::BTreeMap::<String, Vec<String>>::new();
        let mut dependents = std::collections::BTreeMap::<String, Vec<String>>::new();
        let mut host = std::collections::BTreeSet::<String>::new();
        for node in nodes {
            // Non-registry dependents (the consumer root itself) join the map
            // under a sentinel name so a crate depended on only by the root is
            // never mistaken for host-side.
            let dependent = registry_name(node["id"].as_str().expect("node id"))
                .unwrap_or_else(|| "<root>".to_owned());
            for dep in node["deps"].as_array().expect("node deps") {
                if let Some(dep_name) = registry_name(dep["pkg"].as_str().expect("dep pkg")) {
                    dependents
                        .entry(dep_name)
                        .or_default()
                        .push(dependent.clone());
                }
            }
            let Some(name) = registry_name(node["id"].as_str().expect("node id")) else {
                continue;
            };
            deps_of.insert(
                name.clone(),
                node["deps"]
                    .as_array()
                    .expect("node deps")
                    .iter()
                    .filter_map(|dep| registry_name(dep["pkg"].as_str().expect("dep pkg")))
                    .collect(),
            );
            let is_proc_macro = packages
                .iter()
                .find(|package| package["id"] == node["id"])
                .unwrap_or_else(|| panic!("package for {name}"))["targets"]
                .as_array()
                .expect("targets")
                .iter()
                .any(|target| {
                    target["kind"]
                        .as_array()
                        .is_some_and(|kinds| kinds.iter().any(|kind| kind == "proc-macro"))
                });
            if is_proc_macro {
                host.insert(name);
            }
        }
        DepGraph {
            deps_of,
            dependents,
            host,
        }
    }

    /// Post-order DFS over the consumer's dep graph: each covered crate lands
    /// in `order` after the covered crates it depends on.
    pub fn visit(
        name: &str,
        deps_of: &std::collections::BTreeMap<String, Vec<String>>,
        seen: &mut std::collections::BTreeSet<String>,
        order: &mut Vec<String>,
    ) {
        if !seen.insert(name.to_owned()) {
            return;
        }
        if let Some(deps) = deps_of.get(name) {
            for dep in deps {
                if dep != "hex" && deps_of.contains_key(dep) {
                    visit(dep, deps_of, seen, order);
                }
            }
        }
        order.push(name.to_owned());
    }

    /// Signed bundles + a records file for one task's upload plan — the edge
    /// byte path and the OCI index pull become real network serves, not stubs.
    pub fn publish_plan(
        bin_dir: &Path,
        upload_plan: &Path,
        registry_root: &Path,
        private_key: &Path,
        public_key: &Path,
        records: &Path,
    ) {
        run("mock-registry populate", {
            let mut command = Command::new(bin_dir.join("stow-mock-registry"));
            command
                .arg("populate")
                .arg("--upload-plan")
                .arg(upload_plan)
                .arg("--registry-root")
                .arg(registry_root)
                .arg("--private-key")
                .arg(private_key)
                .arg("--public-key")
                .arg(public_key)
                .arg("--records-out")
                .arg(records);
            command
        });
    }

    /// Spawn the mock registry on an ephemeral port.
    pub fn serve_registry(bin_dir: &Path, registry_root: &Path) -> RegistryServer {
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind to pick a port");
            listener.local_addr().expect("local addr").port()
        };
        let child = Command::new(bin_dir.join("stow-mock-registry"))
            .arg("serve")
            .arg("--registry-root")
            .arg(registry_root)
            .arg("--listen")
            .arg(format!("127.0.0.1:{port}"))
            .spawn()
            .expect("spawn mock registry");
        RegistryServer {
            child,
            url: format!("http://127.0.0.1:{port}"),
        }
    }

    pub struct RegistryServer {
        pub child: std::process::Child,
        pub url: String,
    }

    impl RegistryServer {
        pub fn wait_with_output_url(&self) -> String {
            self.url.clone()
        }

        pub fn kill(&mut self) -> std::io::Result<()> {
            self.child.kill()
        }
    }

    pub struct TimedOutput {
        pub output: std::process::Output,
        pub secs: f64,
    }

    /// Run a setup command to success or fail the test with its stderr.
    pub fn run(what: &str, mut command: Command) {
        let output = command
            .output()
            .unwrap_or_else(|error| panic!("run {what}: {error}"));
        assert!(
            output.status.success(),
            "{what} failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Run a build command, fail on error, and return its wall clock.
    pub fn timed(what: &str, command: Command) -> f64 {
        timed_output(what, command).secs
    }

    /// Run a build command, fail on error, and return output + wall clock.
    pub fn timed_output(what: &str, mut command: Command) -> TimedOutput {
        let started = std::time::Instant::now();
        let output = command
            .output()
            .unwrap_or_else(|error| panic!("run {what}: {error}"));
        let secs = started.elapsed().as_secs_f64();
        assert!(
            output.status.success(),
            "{what} failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        TimedOutput { output, secs }
    }

    /// One cargo-vs-stow build pair on a fresh target dir; the stow side
    /// runs with the serve-phase debug target on so the report carries the
    /// per-phase instrumentation.
    pub fn measure_interleaved(
        consumer: &Path,
        cargo_home: &Path,
        bin_dir: &Path,
        mock_env: &dyn Fn(&mut Command),
    ) -> (f64, TimedOutput) {
        let cargo_secs = timed("cargo build", {
            let mut command = Command::new("cargo");
            command
                .arg("build")
                .arg("-q")
                .current_dir(consumer)
                .env("CARGO_HOME", cargo_home)
                .env("HOME", cargo_home)
                .env("CARGO_INCREMENTAL", "0");
            command
        });
        std::fs::remove_dir_all(consumer.join("target")).expect("clear target for stow run");
        let stow_output = timed_output("stow build", {
            let mut command = Command::new(bin_dir.join("stow-cli"));
            command.arg("build").arg("-q").current_dir(consumer);
            mock_env(&mut command);
            command.env("RUST_LOG", "stow.serve_phase=debug");
            command
        });
        std::fs::remove_dir_all(consumer.join("target")).expect("clear target for cargo run");
        (cargo_secs, stow_output)
    }

    /// Median of an odd-length wall-clock sample.
    pub fn median_secs(mut secs: Vec<f64>) -> f64 {
        secs.sort_by(f64::total_cmp);
        secs[secs.len() / 2]
    }

    /// Count `stow.serve_phase` events for one phase name in a build
    /// report captured with `RUST_LOG=stow.serve_phase=debug`.
    pub fn count_serve_phase(report: &str, phase: &str) -> usize {
        let quoted = format!("phase=\"{phase}\"");
        let bare = format!("phase={phase} ");
        report
            .lines()
            .filter(|line| line.contains(&quoted) || line.contains(&bare))
            .count()
    }

    /// Parse `served X of Y cacheable dependencies, Z missed` from stow's
    /// build report.
    pub fn served_missed(report: &str) -> (u64, u64) {
        let needle = "served ";
        let start = report.find(needle).expect("stow coverage report") + needle.len();
        let rest = &report[start..];
        let mut numbers = rest
            .split(|ch: char| !ch.is_ascii_digit())
            .filter(|piece| !piece.is_empty())
            .map(|piece| piece.parse::<u64>().expect("coverage number"));
        (
            numbers.next().expect("served count"),
            numbers.nth(1).expect("missed count"),
        )
    }
}
