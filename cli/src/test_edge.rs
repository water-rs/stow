//! A stub edge for tests: serves a fixed route table on a loopback port
//! and captures the request line of every connection it answers.
//!
//! The stub speaks minimal HTTP/1.1 — read the request line, headers and
//! body, then write `connection: close` with the canned status and body —
//! which is all the zenwave client under test needs; it opens a fresh
//! connection per request.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The request timeout a test pointed at the stub uses. It only bounds a
/// hung stub: a tight one fails a request that merely waited on a loaded
/// runner, where the accept loop's 2 ms poll sleeps a whole timer tick on
/// Windows (stow#949).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// One canned answer: the first route whose `path` appears in the
/// request line replies with `status` and `body`.
pub struct Route {
    /// Substring of the request line the route matches — the request's
    /// path, since the line is `METHOD path HTTP/1.1`. `""` matches
    /// every request.
    pub path: &'static str,
    /// The status line's tail after `HTTP/1.1 `, e.g. `"200 OK"`.
    pub status: &'static str,
    /// Response body bytes.
    pub body: Vec<u8>,
}

/// A running stub edge. Dropping it stops the accept loop.
pub struct StubEdge {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    halt: Arc<AtomicBool>,
}

impl StubEdge {
    /// The stub's base URL — what `StowConfig::edge_url` points at.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Point `config` at the stub, with the stub's request timeout.
    pub fn configure(&self, config: &mut crate::config::StowConfig) {
        config.edge_url.clone_from(&self.url);
        config.request_timeout = REQUEST_TIMEOUT;
    }

    /// The request lines (`METHOD path HTTP/1.1`) answered so far.
    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("requests lock").clone()
    }
}

impl Drop for StubEdge {
    fn drop(&mut self) {
        self.halt.store(true, Ordering::Relaxed);
    }
}

/// One answer a scripted stub gives to one request.
pub struct Reply {
    /// The status line's tail after `HTTP/1.1 `, e.g. `"200 OK"`.
    pub status: &'static str,
    /// Extra header lines, each ending in `\r\n`.
    pub headers: &'static str,
    /// Response body bytes.
    pub body: Vec<u8>,
    /// Write only this many body bytes, then close the connection — the
    /// head still promises the whole body, so the client sees it cut off.
    pub cut_body_at: Option<usize>,
}

impl Reply {
    /// A complete answer.
    pub fn new(status: &'static str, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: "",
            body,
            cut_body_at: None,
        }
    }
}

/// Serve `routes` on a loopback port. A request no route matches is
/// answered `404 Not Found`; the accept loop stops when the returned
/// [`StubEdge`] drops, or at a deadline so a leaked stub cannot hold the
/// test process open.
pub fn serve(routes: Vec<Route>) -> StubEdge {
    serve_with(move |request_line, _| {
        routes
            .iter()
            .find(|route| request_line.contains(route.path))
            .map_or_else(
                || Reply::new("404 Not Found", Vec::new()),
                |route| Reply::new(route.status, route.body.clone()),
            )
    })
}

/// [`serve`] with the answer chosen per request: `respond` gets the
/// request line and how many requests the stub answered before it.
pub fn serve_with(mut respond: impl FnMut(&str, usize) -> Reply + Send + 'static) -> StubEdge {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub edge");
    listener.set_nonblocking(true).expect("nonblocking");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let halt = Arc::new(AtomicBool::new(false));
    {
        let requests = Arc::clone(&requests);
        let halt = Arc::clone(&halt);
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < deadline && !halt.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(_) => break,
                };
                // The accepted socket inherits the listener's nonblocking
                // flag on some platforms — the reads below are blocking.
                stream.set_nonblocking(false).expect("blocking stream");
                let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    continue;
                }
                let mut content_length = 0_u64;
                loop {
                    let mut header = String::new();
                    match reader.read_line(&mut header) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    if header == "\r\n" {
                        break;
                    }
                    if let Some(value) = header
                        .to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::to_owned)
                    {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
                // The body must be consumed before the close: replying
                // over unread request bytes can RST the response before
                // the client reads it.
                let _ = std::io::copy(&mut reader.take(content_length), &mut std::io::sink());
                let answered = {
                    let mut requests = requests.lock().expect("requests lock");
                    requests.push(request_line.clone());
                    requests.len() - 1
                };
                let reply = respond(&request_line, answered);
                let head = format!(
                    "HTTP/1.1 {}\r\n{}content-length: {}\r\nconnection: close\r\n\r\n",
                    reply.status,
                    reply.headers,
                    reply.body.len()
                );
                let sent = reply.cut_body_at.map_or(&reply.body[..], |cut| {
                    &reply.body[..cut.min(reply.body.len())]
                });
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(sent);
                let _ = stream.flush();
            }
        });
    }
    StubEdge {
        url,
        requests,
        halt,
    }
}
