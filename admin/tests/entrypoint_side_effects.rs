//! Real-binary side-effect proofs for the workflow entrypoints
//! (stow#593): the stub-PATH harness asserts the scripts' argv; these
//! runs drive the compiled `stow-admin` against loopback fixtures so
//! the pieces the scripts only name are themselves proven — Analytics
//! Engine query substitution, per-request OIDC minting, malformed
//! entry fail-fast, and invalid-input rejection before any network
//! call. Nothing here can reach Cloudflare, crates.io, the edge, or
//! GitHub: every URL is a bound `127.0.0.1` listener.

#![allow(clippy::missing_panics_doc)]

use std::collections::VecDeque;
use std::net::TcpListener as StdListener;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use serde_json::{Value, json};

/// One inbound request the loopback server recorded.
#[derive(Debug)]
struct Recorded {
    /// Path the request hit.
    path: String,
    /// Raw `Authorization` header value.
    auth: Option<String>,
    /// Request body as text (SQL or JSON).
    body: String,
}

/// What the analytics route answers — a scripted `FORMAT JSON`
/// envelope.
#[derive(Debug)]
struct Fixture {
    /// `top_missed` entries for the scripted row.
    entries: Vec<String>,
    /// `target` on the scripted row.
    target: String,
}

#[derive(Debug)]
struct App {
    requests: Mutex<Vec<Recorded>>,
    fixture: Mutex<Fixture>,
    /// Sequential OIDC answers — `jwt-1`, `jwt-2`, … so the test can
    /// tell which request carried which minted token.
    minted: Mutex<VecDeque<String>>,
}

async fn analytics(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    body: String,
) -> impl IntoResponse {
    app.requests.lock().expect("requests").push(Recorded {
        path: uri.path().to_owned(),
        auth: headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        body,
    });
    let fixture = app.fixture.lock().expect("fixture");
    let response = json!({
        "data": [{
            "target": fixture.target,
            "top_missed": fixture.entries,
        }],
        "meta": {},
        "rows": 1,
        "rows_before_limit_at_least": 1,
    });
    drop(fixture);
    Json(response)
}

async fn submit_ids(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let tasks =
        serde_json::from_str::<Value>(&body).expect("submit-ids body is a JSON object")["tasks"]
            .as_array()
            .expect("tasks is a JSON array")
            .clone();
    let n = u32::try_from(tasks.len()).expect("submit body fits u32");
    app.requests.lock().expect("requests").push(Recorded {
        path: "/api/v1/scheduler/tasks/submit-ids".to_owned(),
        auth: headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        body,
    });
    // The DO reports ids its node store does not hold — the fixture
    // marks them with a `nomatch` tag — never re-minting them.
    let unknown: Vec<&str> = tasks
        .iter()
        .filter_map(|task| task["task_id"].as_str())
        .filter(|id| id.contains("nomatch"))
        .collect();
    Json(
        json!({"submitted": n, "inserted": n - u32::try_from(unknown.len()).unwrap(), "unknown": unknown}),
    )
}

async fn oidc(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(q): Query<std::collections::BTreeMap<String, String>>,
) -> Result<impl IntoResponse, StatusCode> {
    app.requests.lock().expect("requests").push(Recorded {
        path: format!(
            "/oidc?audience={}",
            q.get("audience").map_or("?", String::as_str)
        ),
        auth: headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        body: String::new(),
    });
    let mut minted = app.minted.lock().expect("minted");
    let value = minted
        .pop_front()
        .unwrap_or_else(|| format!("jwt-{}", minted.len() + 1));
    drop(minted);
    Ok(Json(json!({"value": value})))
}

/// Bound loopback server + its address; serves until dropped.
struct Server {
    addr: std::net::SocketAddr,
    app: Arc<App>,
    _thread: std::thread::JoinHandle<()>,
}

impl Server {
    fn spawn(fixture: Fixture, minted: VecDeque<String>) -> Self {
        let app = Arc::new(App {
            requests: Mutex::new(Vec::new()),
            fixture: Mutex::new(fixture),
            minted: Mutex::new(minted),
        });
        let router = Router::new()
            .route("/accounts/{account}/analytics_engine/sql", post(analytics))
            .route("/api/v1/scheduler/tasks/submit-ids", post(submit_ids))
            .route("/oidc", get(oidc))
            .with_state(app.clone());
        let std_listener = StdListener::bind("127.0.0.1:0").expect("bind loopback");
        std_listener.set_nonblocking(true).expect("nonblocking");
        let addr = std_listener.local_addr().expect("addr");
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async move {
                let listener =
                    tokio::net::TcpListener::from_std(std_listener).expect("tokio listener");
                axum::serve(listener, router).await.expect("serve");
            });
        });
        Self {
            addr,
            app,
            _thread: thread,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// All requests recorded, in arrival order.
    fn requests(&self) -> Vec<Recorded> {
        self.app
            .requests
            .lock()
            .expect("requests")
            .drain(..)
            .collect()
    }

    fn requests_on(&self, path_prefix: &str) -> Vec<Recorded> {
        self.app
            .requests
            .lock()
            .expect("requests")
            .iter()
            .filter(|r| r.path.starts_with(path_prefix))
            .map(|r| Recorded {
                path: r.path.clone(),
                auth: r.auth.clone(),
                body: r.body.clone(),
            })
            .collect()
    }
}

/// `stow-admin preheat missed` with the workflow's own env contract —
/// loopback edge, loopback analytics base (the `STOW_CF_ANALYTICS_SQL_BASE`
/// test seam), Actions OIDC variables.
fn missed_command(server: &Server, extra_args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stow-admin"));
    cmd.args(["preheat", "missed"])
        .args(extra_args)
        .env("STOW_EDGE_URL", server.url())
        .env("STOW_CF_ANALYTICS_SQL_BASE", server.url())
        .env("CF_ACCOUNT_ID", "test-account")
        .env("CF_ANALYTICS_TOKEN", "test-cf-token")
        .env(
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            format!("{}/oidc", server.url()),
        )
        .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-request-token")
        .env("STOW_OIDC_AUDIENCE", "test-audience");
    cmd
}

fn run(mut cmd: Command) -> Output {
    cmd.output().expect("spawn stow-admin")
}

/// `task_id;misses` — the Analytics Engine element shape
/// `missed_task_id_entry` parses (stow#588). The lane promotes by the
/// id alone; the scheduler re-derives the subgraph from its node store.
fn entry(task_id: &str, misses: u64) -> String {
    format!("{task_id};{misses}")
}

#[test]
fn missed_lane_end_to_end() {
    // 1001 entries → SUBMIT_CHUNK=1000 splits the submit into exactly
    // two edge POSTs, which is what proves the OIDC mint is per request.
    // The id one slot carries a `nomatch` tag — the mock edge reports it
    // as unknown, exercising the report-never-remint path (stow#588).
    let entries: Vec<String> = (0..1001)
        .map(|i| {
            let tag = if i == 500 { "-nomatch" } else { "" };
            entry(
                &format!("serde-1.0.228--x86_64-unknown-linux-gnu-r1.98.1-d{i:016x}{tag}"),
                40 + u64::try_from(i % 3).expect("small i"),
            )
        })
        .collect();
    let server = Server::spawn(
        Fixture {
            entries,
            target: "x86_64-unknown-linux-gnu".to_owned(),
        },
        VecDeque::from(["jwt-first".to_owned(), "jwt-second".to_owned()]),
    );

    let out = run(missed_command(
        &server,
        &[
            "--rustc-version",
            "1.98.1",
            "--limit",
            "7",
            "--since-days",
            "2",
            "--targets",
            "x86_64-unknown-linux-gnu",
            "--yes",
        ],
    ));
    assert!(
        out.status.success(),
        "exit {}\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // The analytics call: POST to the loopback base's
    // `/accounts/{id}/analytics_engine/sql` with the env token as
    // bearer and the rendered query — placeholders gone, values in.
    let analytics = server.requests_on("/accounts/");
    assert_eq!(analytics.len(), 1, "{analytics:?}");
    let req = &analytics[0];
    assert!(
        req.path
            .contains("/accounts/test-account/analytics_engine/sql"),
        "{}",
        req.path
    );
    assert_eq!(req.auth.as_deref(), Some("Bearer test-cf-token"));
    for needle in [
        "topKWeighted(7)",
        "INTERVAL '2' DAY",
        "blob5 IN ('x86_64-unknown-linux-gnu')",
        "FORMAT JSON",
    ] {
        assert!(
            req.body.contains(needle),
            "query missing {needle}:\n{}",
            req.body
        );
    }
    assert!(
        !req.body.contains("__LIMIT__") && !req.body.contains("__TARGETS__"),
        "placeholder leaked into the query:\n{}",
        req.body
    );

    // Two submit chunks of 1000+1 — and each POST minted its own OIDC
    // token rather than reusing the first.
    let submits = server.requests_on("/api/v1/scheduler/tasks/submit-ids");
    assert_eq!(submits.len(), 2, "{submits:?}");
    assert_eq!(submits[0].auth.as_deref(), Some("Bearer jwt-first"));
    assert_eq!(submits[1].auth.as_deref(), Some("Bearer jwt-second"));
    let mints = server.requests_on("/oidc");
    assert_eq!(mints.len(), 2, "{mints:?}");
    for m in &mints {
        assert_eq!(m.path, "/oidc?audience=test-audience");
        assert_eq!(m.auth.as_deref(), Some("bearer test-request-token"));
    }

    // The submitted payloads are the fixture task ids verbatim — the
    // lane promotes by id and never re-mints or reshapes them.
    let mut seen = 0usize;
    for s in &submits {
        let body: Value = serde_json::from_str(&s.body).expect("submit-ids body");
        let tasks = body["tasks"].as_array().expect("tasks array");
        for t in tasks {
            let task_id = t["task_id"].as_str().expect("task_id");
            assert!(
                task_id.starts_with("serde-1.0.228--x86_64-unknown-linux-gnu-r1.98.1-d"),
                "{t}"
            );
            assert!(t["downloads"].as_u64().expect("downloads") >= 40, "{t}");
            seen += 1;
        }
    }
    assert_eq!(seen, 1001);

    // The unknown id the edge reported surfaces in the lane's output —
    // reported, never re-minted.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("unknown 1"),
        "stdout:
{stdout}"
    );
    assert!(
        stdout.contains("nomatch"),
        "the unknown id is named:
{stdout}"
    );
}

#[test]
fn missed_malformed_entry_fails_before_submit() {
    // Four `;` fields — the dataset diverged from miss_logger's layout;
    // the lane must fail loudly rather than skip or submit a guess.
    let server = Server::spawn(
        Fixture {
            entries: vec!["serde;1.0.228;[\"default\"];42".to_owned()],
            target: "x86_64-unknown-linux-gnu".to_owned(),
        },
        VecDeque::new(),
    );
    let out = run(missed_command(
        &server,
        &["--rustc-version", "1.98.1", "--yes"],
    ));
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("malformed top_missed"), "stderr:\n{stderr}");
    assert!(
        server
            .requests_on("/api/v1/scheduler/tasks/submit-ids")
            .is_empty(),
        "submit ran after a malformed entry: {:?}",
        server.requests()
    );
}

#[test]
fn missed_invalid_inputs_fail_without_network() {
    let server = Server::spawn(
        Fixture {
            entries: vec![],
            target: "x86_64-unknown-linux-gnu".to_owned(),
        },
        VecDeque::new(),
    );
    for (args, needle) in [
        (
            vec!["--rustc-version", "1.98.1", "--limit", "0", "--yes"],
            "--limit must be at least 1",
        ),
        (
            vec!["--rustc-version", "1.98.1", "--since-days", "0", "--yes"],
            "--since-days must be at least 1",
        ),
        (
            vec![
                "--rustc-version",
                "1.98.1",
                "--targets",
                "not-a-triple",
                "--yes",
            ],
            "is not a CI target",
        ),
    ] {
        let out = run(missed_command(&server, &args));
        assert!(!out.status.success(), "{args:?} unexpectedly succeeded");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(needle), "{args:?} stderr:\n{stderr}");
    }
    assert!(
        server.requests().is_empty(),
        "an invalid input still reached the network: {:?}",
        server.requests()
    );
}
