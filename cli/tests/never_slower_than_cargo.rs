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

/// The frames a stub supervisor collected, bucketed by the crate each
/// frame's argv compiled (`--crate-name`). The empty key carries rustc
/// probes like `-vV`, which name no crate at all.
#[derive(Debug, Default)]
struct StubSupervision {
    plans: std::collections::BTreeMap<String, usize>,
    compiled: std::collections::BTreeMap<String, usize>,
    observed_marks: std::collections::BTreeMap<String, usize>,
    observed_reports: std::collections::BTreeMap<String, usize>,
}

/// The crate a supervisor frame compiled, from its argv. A `Request` on
/// the wire is `{"Plan": {...}}`, `{"Compiled": {...}}` or
/// `{"Observed": {...}}`; `args` is a list of byte strings.
fn frame_crate_name(request: &serde_json::Value) -> String {
    let args = request
        .get("Plan")
        .or_else(|| request.get("Observed"))
        .and_then(|body| body.get("args"))
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|arg| {
            arg.as_array()
                .map(|bytes| {
                    bytes
                        .iter()
                        .filter_map(serde_json::Value::as_u64)
                        .filter_map(|byte| u8::try_from(byte).ok())
                        .collect::<Vec<u8>>()
                })
                .unwrap_or_default()
        })
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .collect::<Vec<String>>();
    args.iter()
        .position(|arg| arg == "--crate-name")
        .and_then(|index| args.get(index + 1))
        .cloned()
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
        let Ok(request) = serde_json::from_slice::<serde_json::Value>(&body) else {
            return;
        };
        let crate_name = frame_crate_name(&request);
        let answer = if request.get("Plan").is_some() {
            counts
                .lock()
                .expect("frame counts")
                .plans
                .entry(crate_name)
                .and_modify(|count| *count += 1)
                .or_insert(1);
            ticket += 1;
            Some(serde_json::json!({"Compile": {"ticket": ticket}}))
        } else if request.get("Compiled").is_some() {
            counts
                .lock()
                .expect("frame counts")
                .compiled
                .entry(crate_name)
                .and_modify(|count| *count += 1)
                .or_insert(1);
            Some(serde_json::json!("Recorded"))
        } else if request.get("Observed").is_some() {
            let mut counts = counts.lock().expect("frame counts");
            let is_report = request
                .get("Observed")
                .and_then(|body| body.get("success"))
                .is_some_and(|success| !success.is_null());
            let bucket = if is_report {
                &mut counts.observed_reports
            } else {
                &mut counts.observed_marks
            };
            bucket
                .entry(crate_name)
                .and_modify(|count| *count += 1)
                .or_insert(1);
            None
        } else {
            None
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

    let output = cargo_build_in(
        dir.path(),
        &unreachable_edge_url(),
        cache.path(),
        &wrapper,
        &dir.path().join("target"),
        &[
            ("STOW_SUPERVISOR_ENDPOINT", endpoint.as_str()),
            ("STOW_SUPERVISOR_TOKEN", "test-token"),
            ("STOW_SERVABLE_UNITS_JSON", "{\"target\":[],\"host\":[]}"),
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

    let output = cargo_build_in(
        dir.path(),
        &unreachable_edge_url(),
        cache.path(),
        &wrapper,
        &dir.path().join("target"),
        &[
            ("STOW_SUPERVISOR_ENDPOINT", endpoint.as_str()),
            ("STOW_SUPERVISOR_TOKEN", "test-token"),
            // `cfg-if` compiles unspelled — no `--target` on a native
            // build — so the host side carries it, at any version. Map
            // entries are canonical crate names (underscores).
            (
                "STOW_SERVABLE_UNITS_JSON",
                "{\"target\":[],\"host\":[[\"cfg_if\",\"*\"]]}",
            ),
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
