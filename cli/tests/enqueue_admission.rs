//! Miss admissions minted by `POST /api/v1/admissions` are redeemed
//! against `POST /api/v1/enqueue` with the stateless ticket shape:
//! `{task_id, challenge, nonce, request}`.
//!
//! Resolution is local under the signed index (stow#194): the test seeds
//! the wrapper's slice cache with an empty verified index — every graph
//! package is then a miss, which is exactly the condition that earns an
//! admissions round trip. A local TCP edge answers the admissions post
//! with one zero-difficulty admission, captures whatever the CLI posts to
//! the enqueue endpoint, and the test asserts the exact path and payload
//! shape — the contract the edge's HMAC + proof-of-work gate verifies.

use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const TARGET: &str = "x86_64-unknown-linux-gnu";
const RUSTC_VERSION: &str = "1.85.0";
const ADMISSION_TASK_ID: &str = "cfg-if-1.0.0-testtask-x86_64_unknown_linux_gnu-1_85_0";
const ADMISSION_CHALLENGE: &str = "0123456789abcdef";

/// The admissions payload the edge mints for this analysis's misses —
/// one zero-difficulty admission the CLI must redeem.
const ADMISSIONS_RESPONSE: &str = r#"[{
    "task_id": "cfg-if-1.0.0-testtask-x86_64_unknown_linux_gnu-1_85_0",
    "challenge": "0123456789abcdef",
    "difficulty": 0,
    "request": {
        "crate_name": "cfg-if",
        "version": "1.0.0",
        "features_json": "[]",
        "target": "x86_64-unknown-linux-gnu",
        "rustc_version": "1.85.0",
        "downloads": 0,
        "source": "CacheMiss",
        "depends_on": [],
        "preserve_lockfile": false
    }
}]"#;

/// Seed `cache_dir/index/<target>/<rustc>/` with an empty index blob and a
/// fresh `current.json` pointer: `ensure_slice` serves it straight from
/// disk, so the test never touches a registry and every dependency
/// resolves as a miss.
fn seed_empty_index_slice(cache_dir: &Path) {
    let index = stow_types::index::ArtifactIndex {
        header: stow_types::index::ArtifactIndexHeader {
            format_version: stow_types::index::ARTIFACT_INDEX_FORMAT_VERSION,
            target: stow_types::identity::TargetTriple::parse(TARGET).expect("target"),
            rustc_version: stow_types::identity::WireRustcVersion::parse(RUSTC_VERSION)
                .expect("rustc version"),
            generated_at: "2026-09-24T12:00:00Z".to_owned(),
            row_count: 0,
        },
        rows: Vec::new(),
    };
    let blob = stow_types::index::encode(&index).expect("encode index");
    let manifest_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    let dir = cache_dir.join("index").join(TARGET).join(RUSTC_VERSION);
    std::fs::create_dir_all(&dir).expect("create slice dir");
    std::fs::write(dir.join(manifest_digest.replace(':', "_")), &blob).expect("write index blob");
    let fetched_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let pointer = serde_json::json!({
        "manifest_digest": manifest_digest,
        "fetched_at": fetched_at,
        "row_count": 0,
    });
    std::fs::write(dir.join("current.json"), pointer.to_string()).expect("write pointer");
}

/// Captured `(request_line, body)` pairs for requests the CLI makes.
type Captured = Arc<Mutex<Vec<(String, String)>>>;

fn spawn_test_edge() -> (String, Captured, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a local edge");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    let captured: Captured = Arc::new(Mutex::new(Vec::new()));
    let requests = Arc::clone(&captured);
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            serve_one(stream, &requests);
        }
    });
    (url, captured, handle)
}

fn serve_one(mut stream: std::net::TcpStream, captured: &Captured) {
    let mut reader =
        std::io::BufReader::new(stream.try_clone().expect("clone the accepted stream"));
    let mut request_line = String::new();
    if std::io::BufRead::read_line(&mut reader, &mut request_line).is_err() {
        return;
    }
    let body = read_request_body(&mut reader);
    let body_text = String::from_utf8_lossy(&body).into_owned();

    if request_line.starts_with("POST /api/v1/enqueue ") {
        captured
            .lock()
            .expect("captured requests lock")
            .push((request_line.clone(), body_text));
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}",
        );
        return;
    }

    let (status, response_body) = if request_line.contains("/api/v1/admissions") {
        ("200 OK", ADMISSIONS_RESPONSE.to_owned())
    } else {
        ("404 Not Found", String::new())
    };
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
            response_body.len()
        )
        .as_bytes(),
    );
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
    // The fetch must share the isolated CARGO_HOME the build uses.
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

#[test]
fn miss_admissions_post_stateless_tickets_to_the_enqueue_endpoint() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cache = tempfile::tempdir().expect("cache dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    write_crate(dir.path(), cargo_home.path());
    seed_empty_index_slice(cache.path());

    let (edge_url, captured, _edge) = spawn_test_edge();
    // stow#294: a Linux `stow build` refuses to run without a mold
    // selection — `stow setup` installs mold and writes it. Setup writes
    // the global cargo config; the isolated CARGO_HOME keeps the
    // developer's real one untouched.
    let setup = Command::new(env!("CARGO_BIN_EXE_stow-cli"))
        .arg("setup")
        .current_dir(dir.path())
        .env("CARGO_HOME", cargo_home.path())
        .output()
        .expect("run stow-cli setup");
    assert!(
        setup.status.success(),
        "stow setup failed:\n{}",
        String::from_utf8_lossy(&setup.stderr)
    );
    let output = Command::new(env!("CARGO_BIN_EXE_stow-cli"))
        .arg("build")
        .current_dir(dir.path())
        .env("CARGO_HOME", cargo_home.path())
        .env("STOW_EDGE_URL", &edge_url)
        .env("STOW_CACHE_DIR", cache.path())
        // Isolate from the developer's ambient stow config: a user-level
        // `verify_mode = "mock-key"` (or an inherited `STOW_CONFIG_BLOB`)
        // would abort analysis before any admission is minted.
        .env("STOW_VERIFY_MODE", "github-ci")
        .env_remove("STOW_CONFIG_BLOB")
        // The public cache only serves recent stable toolchains; pin the
        // probed identity so the analysis runs even when the host rustc is
        // a nightly build.
        .env("STOW_PUBLIC_CACHE_RUSTC_VERSION", RUSTC_VERSION)
        .env("STOW_PUBLIC_CACHE_TARGET", TARGET)
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .env("CARGO_INCREMENTAL", "0")
        .env_remove("RUST_LOG")
        .output()
        .expect("run stow-cli build");

    assert!(
        output.status.success(),
        "stow build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The admission minted by this build's misses is posted by the
    // detached `__drain-misses` child — `stow build` returns when cargo
    // does — so the enqueue post lands after the command exits. Poll for
    // it instead of asserting on an empty capture.
    let deadline = std::time::Instant::now() + std::time::Duration::from_mins(1);
    let (request_line, body) = loop {
        let found = {
            let requests = captured.lock().expect("captured requests lock");
            requests.first().cloned()
        };
        if let Some(pair) = found {
            break pair;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for the drained /api/v1/enqueue post"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_eq!(
        captured.lock().expect("captured requests lock").len(),
        1,
        "expected exactly one /api/v1/enqueue post"
    );
    assert!(
        request_line.starts_with("POST /api/v1/enqueue "),
        "unexpected enqueue request line: {request_line}"
    );

    let ticket: serde_json::Value =
        serde_json::from_str(&body).expect("enqueue body is valid JSON");
    for field in ["task_id", "challenge", "nonce", "request"] {
        assert!(
            ticket.get(field).is_some(),
            "enqueue ticket missing `{field}`: {body}"
        );
    }
    assert_eq!(ticket["task_id"].as_str(), Some(ADMISSION_TASK_ID));
    assert_eq!(ticket["challenge"].as_str(), Some(ADMISSION_CHALLENGE));
    assert!(ticket["nonce"].is_u64(), "nonce must be an integer: {body}");
    assert_eq!(
        ticket["request"]["crate_name"].as_str(),
        Some("cfg-if"),
        "the ticket must carry the admission's canonical request: {body}"
    );
}

/// The `stow setup` path: a plain `cargo build` with `RUSTC_WRAPPER`
/// pointed at the wrapper shim and no stow parent process. Compiles
/// journal their observations into `<target>/stow-misses.<cargo
/// pid>.jsonl`; the first wrapper invocation after that cargo exits
/// spawns the detached drain that posts the admission (stow#317).
///
/// The test builds once (journals cfg-if's compile), rebuilds after
/// touching the crate (the new cargo's first wrapper call sees the old
/// cargo dead and drains its journal), and waits for the enqueue post
/// the minted admission redeems.
#[test]
fn standalone_wrapper_journals_misses_and_the_next_build_drains_them() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cache = tempfile::tempdir().expect("cache dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    let tools = tempfile::tempdir().expect("tools dir");
    write_crate(dir.path(), cargo_home.path());
    seed_empty_index_slice(cache.path());
    let (edge_url, captured, _edge) = spawn_test_edge();

    // The installed layout is the wrapper shim name pointing at this
    // binary: `WrapperRole::from_program` keys on the name.
    let shim = tools.path().join("stow-rustc-wrapper");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stow-cli"), &shim).expect("symlink shim");

    let cargo_build = |dir: &Path| {
        let output = Command::new("cargo")
            .arg("build")
            .current_dir(dir)
            .env("CARGO_HOME", cargo_home.path())
            .env("RUSTC_WRAPPER", &shim)
            .env("STOW_EDGE_URL", &edge_url)
            .env("STOW_CACHE_DIR", cache.path())
            .env("STOW_VERIFY_MODE", "github-ci")
            .env_remove("STOW_CONFIG_BLOB")
            .env("STOW_PUBLIC_CACHE_RUSTC_VERSION", RUSTC_VERSION)
            .env("STOW_PUBLIC_CACHE_TARGET", TARGET)
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost")
            .env("CARGO_INCREMENTAL", "0")
            .env_remove("RUST_LOG")
            .output()
            .expect("run cargo build");
        assert!(
            output.status.success(),
            "cargo build failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };

    cargo_build(dir.path());
    let target_dir = dir.path().join("target");
    let journals: Vec<_> = std::fs::read_dir(&target_dir)
        .expect("read target dir")
        .filter_map(std::result::Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("stow-misses.")
        })
        .collect();
    assert_eq!(
        journals.len(),
        1,
        "expected exactly one miss journal under {target_dir:?}"
    );
    let journal = journals[0].path();
    let observed = std::fs::read_to_string(&journal).expect("read miss journal");
    assert!(
        observed.lines().any(|line| line.contains("cfg-if")),
        "the compiled crate must be journaled: {observed}"
    );

    // The next build's first wrapper invocation finds the first cargo's
    // journal finished (its pid is gone) and kicks the detached drain.
    std::fs::write(dir.path().join("src").join("main.rs"), "fn main() {}\n\n")
        .expect("touch main.rs");
    cargo_build(dir.path());

    let deadline = std::time::Instant::now() + std::time::Duration::from_mins(1);
    loop {
        let found = {
            let requests = captured.lock().expect("captured requests lock");
            requests.first().cloned()
        };
        if let Some((request_line, body)) = found {
            assert!(
                request_line.starts_with("POST /api/v1/enqueue "),
                "unexpected enqueue request line: {request_line}"
            );
            let ticket: serde_json::Value =
                serde_json::from_str(&body).expect("enqueue body is valid JSON");
            assert_eq!(ticket["task_id"].as_str(), Some(ADMISSION_TASK_ID));
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for the drained /api/v1/enqueue post"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        !journal.exists(),
        "the drained journal must be gone: {}",
        journal.display()
    );
}
