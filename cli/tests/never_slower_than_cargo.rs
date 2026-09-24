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
/// cached would: `Plan` gets `Compile` with a minted ticket, `Compiled`
/// and an `Observed` report get `Recorded`, and an `Observed` provenance
/// mark — the fire-and-forget `success: null` frame — gets no reply.
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
                write_frame(&mut stream, &serde_json::json!("Recorded"));
            } else {
                panic!("unknown supervisor frame: {request}");
            }
        }
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
            // /bin/true: the point is the frames around the compile, and
            // their cost, not the compile itself.
            .arg("/bin/true")
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
        let counts = *counts.lock().expect("counts");
        assert_eq!(
            counts.plans, 0,
            "uncovered units asked the supervisor for a plan"
        );
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
        .arg("/bin/true")
        .arg("--version")
        .env("STOW_SUPERVISOR_ENDPOINT", &endpoint)
        .env("STOW_SUPERVISOR_TOKEN", "stub")
        .env("STOW_SERVABLE_UNITS_JSON", &units)
        .output()
        .expect("run probe facade");
    assert!(probe.status.success(), "probe invocation failed");
    let counts = *counts.lock().expect("counts");
    assert_eq!(counts.plans, 2, "covered unit and probe must plan");
    assert_eq!(counts.compiled, 2, "planned units report Compiled");
    assert_eq!(counts.marks, UNITS, "the fast path must not send marks");
}

/// stow#347: the serve decision travels with the build once, as the
/// serve map cargo hands every facade — not as a per-invocation lookup.
/// Each member's build script reports back the map it inherited, so this
/// test counts the invocations that saw it; it also times the build
/// against plain cargo as a coarse regression tripwire.
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
        let units = std::env::var("STOW_SERVABLE_UNITS_JSON").unwrap_or_default();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .expect("open units log");
        let _ = std::io::Write::write_all(&mut file, env!("CARGO_PKG_NAME").as_bytes());
        let _ = std::io::Write::write_all(&mut file, b" ");
        let _ = std::io::Write::write_all(&mut file, units.as_bytes());
        let _ = std::io::Write::write_all(&mut file, b"\n");
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
    let started = std::time::Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_stow-cli"))
        .arg("build")
        .current_dir(dir.path())
        .env("CARGO_HOME", cargo_home.path())
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
    let stow_wall = started.elapsed();
    assert!(
        output.status.success(),
        "stow build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = std::fs::read_to_string(&units_log)
        .expect("no member saw the serve map — the env never shipped");
    let mut seen = 0usize;
    for line in log.lines() {
        let (name, units) = line.split_once(' ').expect("log line is name + map");
        let map: Vec<Vec<String>> =
            serde_json::from_str(units).expect("serve map must be a JSON pair list");
        assert!(
            map.iter().all(|pair| pair.len() == 2 && pair[0] != name),
            "{name} is a path dependency — it must not be in its own serve map"
        );
        seen += 1;
    }
    assert_eq!(seen, MEMBERS, "not every member's build script ran");

    // Plain cargo over the same workspace: the tripwire compares wall time
    // loosely — the precise guard is the frame-count test above; this one
    // only fails on a regression gross enough to matter at this size.
    let target = tempfile::tempdir().expect("target dir");
    let started = std::time::Instant::now();
    let output = Command::new("cargo")
        .arg("build")
        .current_dir(dir.path())
        .env("CARGO_HOME", cargo_home.path())
        .env("CARGO_TARGET_DIR", target.path())
        .env("CARGO_INCREMENTAL", "0")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUST_LOG")
        .output()
        .expect("run cargo build");
    let cargo_wall = started.elapsed();
    assert!(
        output.status.success(),
        "cargo build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stow_wall <= cargo_wall + cargo_wall / 2 + std::time::Duration::from_secs(5),
        "stow took {stow_wall:?} against cargo's {cargo_wall:?} on a {MEMBERS}-crate all-miss build"
    );
}
