//! The CLI redeems graph-analysis miss admissions against
//! `POST /api/v1/enqueue` with the stateless ticket shape:
//! `{task_id, challenge, nonce, request}`.
//!
//! A local TCP edge answers the analysis with one zero-difficulty
//! admission, captures whatever the CLI posts to the enqueue endpoint, and
//! the test asserts the exact path and payload shape — the contract the
//! edge's HMAC + proof-of-work gate verifies.

use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

/// Minimal canned pieces of the edge protocol. The lockfile resolver
/// answers "no cached assignment" so `stow build` proceeds to the graph
/// analysis, which returns a miss admission redeemable without a nonce
/// scan (difficulty 0).
const NO_LOCKFILE_RESPONSE: &str = r#"{"lockfile_toml":null,"uncovered_direct":[],"candidates_considered":0,"seed_diagnostics":[]}"#;

const ADMISSION_TASK_ID: &str = "cfg-if-1.0.0-testtask-x86_64_unknown_linux_gnu-1_85_0";
const ADMISSION_CHALLENGE: &str = "0123456789abcdef";

/// Answer the graph analysis with an entry per requested dependency — all
/// misses — plus one zero-difficulty miss admission the CLI must redeem.
fn graph_response(request_body: &[u8]) -> String {
    let request: serde_json::Value =
        serde_json::from_slice(request_body).unwrap_or(serde_json::Value::Null);
    let entries = request
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|dependency| {
            serde_json::json!({
                "dependency": dependency,
                "current_artifact_count": 0,
                "current_artifacts": [],
                "recommended": serde_json::Value::Null,
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "entries": entries,
        "expanded_cached": 0,
        "expanded_total": 0,
        "expanded_entries": [],
        "prefetch_artifacts": [],
        "miss_admissions": [{
            "task_id": ADMISSION_TASK_ID,
            "challenge": ADMISSION_CHALLENGE,
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
                "preserve_lockfile": false,
            },
        }],
    })
    .to_string()
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

    let (status, response_body) = if request_line.contains("/api/v1/catalog/resolve-lockfile") {
        ("200 OK", NO_LOCKFILE_RESPONSE.to_owned())
    } else if request_line.contains("/api/v1/catalog/graph") {
        ("200 OK", graph_response(&body))
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

fn write_crate(dir: &Path) {
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
         [dependencies]\ncfg-if = \"1\"\n",
    )
    .expect("write manifest");
    std::fs::create_dir_all(dir.join("src")).expect("create src");
    std::fs::write(dir.join("src").join("main.rs"), "fn main() {}\n").expect("write main.rs");
    // Resolve now, so the build under test is not also a network test.
    let fetched = Command::new("cargo")
        .arg("fetch")
        .current_dir(dir)
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
    write_crate(dir.path());

    let (edge_url, captured, _edge) = spawn_test_edge();
    let output = Command::new(env!("CARGO_BIN_EXE_stow-cli"))
        .arg("build")
        .current_dir(dir.path())
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
        .env("STOW_PUBLIC_CACHE_RUSTC_VERSION", "1.85.0")
        .env("STOW_PUBLIC_CACHE_TARGET", "x86_64-unknown-linux-gnu")
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

    let (request_line, body) = {
        let requests = captured.lock().expect("captured requests lock");
        assert_eq!(
            requests.len(),
            1,
            "expected exactly one /api/v1/enqueue post, got {}: {requests:?}",
            requests.len()
        );
        requests[0].clone()
    };
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
