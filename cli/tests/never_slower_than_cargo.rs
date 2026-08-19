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

    let response = match response_body {
        Some(body) => format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
        None => "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_owned(),
    };
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

fn stow_build_in(dir: &Path, edge_url: &str, cache_dir: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_stow-cli"))
        .arg("build")
        .current_dir(dir)
        .env("STOW_EDGE_URL", edge_url)
        .env("STOW_CACHE_DIR", cache_dir)
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .env("CARGO_INCREMENTAL", "0")
        .env_remove("RUST_LOG")
        .output()
        .expect("run stow-cli build")
}

#[test]
fn a_failing_edge_costs_cache_hits_not_the_build() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cache = tempfile::tempdir().expect("cache dir");
    write_crate(dir.path());

    let (edge_url, _edge) = spawn_failing_edge(true);
    let output = stow_build_in(dir.path(), &edge_url, cache.path());

    assert!(
        output.status.success(),
        "stow build failed against an edge that answers 500:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        dir.path().join("target").join("debug").join("probe").exists(),
        "stow build reported success without producing the binary"
    );
}

#[test]
fn an_edge_that_fails_every_call_costs_cache_hits_not_the_build() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cache = tempfile::tempdir().expect("cache dir");
    write_crate(dir.path());

    let (edge_url, _edge) = spawn_failing_edge(false);
    let output = stow_build_in(dir.path(), &edge_url, cache.path());

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
    write_crate(dir.path());

    // Nothing is listening on this port.
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind to pick a port");
        listener.local_addr().expect("local addr").port()
    };
    let output = stow_build_in(dir.path(), &format!("http://127.0.0.1:{port}"), cache.path());

    assert!(
        output.status.success(),
        "stow build failed against an unreachable edge:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
