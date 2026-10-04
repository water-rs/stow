//! A loopback HTTP/1.1 server each test owns outright — scripted
//! per-connection behavior, no globals or shared state, and `join`
//! reaps the accept task so nothing outlives the test.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// What one accepted connection does.
#[derive(Debug)]
pub enum Step {
    /// Close without answering — the server-side drop the local CI
    /// poll met when its request outlived the server's idle window.
    Drop,
    /// Answer `status` with `body`, carrying `Retry-After` seconds
    /// when a hint is scripted.
    Respond {
        /// The status line's code.
        status: u16,
        /// `Retry-After` delta-seconds to answer with.
        retry_after: Option<u64>,
        /// The response body.
        body: &'static str,
    },
}

/// One scripted loopback server — accepts `steps.len()` connections
/// in order, then its task exits.
#[derive(Debug)]
pub struct Loopback {
    /// Base URL — `http://127.0.0.1:<port>`.
    pub url: String,
    requests: Arc<AtomicUsize>,
    heads: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl Loopback {
    /// Bind a free loopback port and serve `steps` in order.
    pub async fn start(steps: Vec<Step>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback binds");
        let addr = listener.local_addr().expect("bound address");
        let requests = Arc::new(AtomicUsize::new(0));
        let heads = Arc::new(Mutex::new(Vec::new()));
        let counted = requests.clone();
        let recorded = heads.clone();
        let task = tokio::spawn(async move {
            for step in steps {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                counted.fetch_add(1, Ordering::SeqCst);
                let head = drain_request_head(&stream).await;
                recorded
                    .lock()
                    .expect("request heads")
                    .push(String::from_utf8_lossy(&head).into_owned());
                match step {
                    Step::Drop => drop(stream),
                    Step::Respond {
                        status,
                        retry_after,
                        body,
                    } => write_response(&stream, status, retry_after, body).await,
                }
            }
        });
        Self {
            url: format!("http://{addr}"),
            requests,
            heads,
            task,
        }
    }

    /// Connections accepted so far.
    #[must_use]
    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    /// The request head each accepted connection carried, in order.
    #[must_use]
    pub fn request_heads(&self) -> Vec<String> {
        self.heads.lock().expect("request heads").clone()
    }

    /// Reap the accept task — a test whose script ran to completion
    /// leaves nothing behind.
    pub async fn join(self) {
        let _ = self.task.await;
    }
}

/// Read through the request head (`\r\n\r\n`); a peer that
/// disconnects mid-head ends the drain, and the collected bytes are
/// returned either way.
async fn drain_request_head(stream: &TcpStream) -> Vec<u8> {
    let mut head = Vec::with_capacity(1024);
    let mut buf = [0u8; 4096];
    loop {
        if stream.readable().await.is_err() {
            return head;
        }
        match stream.try_read(&mut buf) {
            Ok(0) => return head,
            Ok(n) => {
                head.extend_from_slice(&buf[..n]);
                if head.windows(4).any(|window| window == b"\r\n\r\n") || head.len() > 64 * 1024 {
                    return head;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return head,
        }
    }
}

/// Write a minimal HTTP/1.1 response with `Connection: close`.
async fn write_response(stream: &TcpStream, status: u16, retry_after: Option<u64>, body: &str) {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        408 => "Request Timeout",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    };
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(hint) = retry_after {
        let _ = write!(response, "Retry-After: {hint}\r\n");
    }
    response.push_str("\r\n");
    response.push_str(body);
    let mut written = 0;
    let bytes = response.as_bytes();
    while written < bytes.len() {
        if stream.writable().await.is_err() {
            return;
        }
        match stream.try_write(&bytes[written..]) {
            Ok(0) => return,
            Ok(n) => written += n,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return,
        }
    }
}
