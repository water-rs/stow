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
    seed_empty_index_slice(cache.path());

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
