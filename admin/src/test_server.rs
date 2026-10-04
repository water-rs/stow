//! A loopback HTTP/1.1 server each test owns outright — scripted
//! per-connection behavior on a maintained Hyper connection, request
//! heads returned by the joined task, no locks or shared state. The
//! server stays up until `join` shuts it down and answers a success
//! sentinel once the script runs out, so a client retrying where the
//! contract forbids it is answered — and the test fails — rather than
//! being refused by a closed listener.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http::HeaderValue;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// One connection's service may not stall the server forever, and the
/// shutdown join may not wait forever — a stuck server fails the test
/// inside the bound instead of hanging the suite.
const CONNECTION_BOUND: Duration = Duration::from_secs(15);
const JOIN_BOUND: Duration = Duration::from_secs(10);

/// The answer every request past the scripted steps gets: a success
/// the test did not ask for, so an out-of-contract retry succeeds
/// where the assertion expected failure.
const SENTINEL: Step = Step::Respond {
    status: 200,
    retry_after: None,
    body: r#"{"ok":true}"#,
};

/// What one accepted connection's requests do.
#[derive(Debug, Clone)]
pub enum Step {
    /// Read the request, then fail the connection without a response —
    /// the server-side drop the local CI poll met. The request is
    /// captured first: a replay of an unsent message would never reach
    /// this arm, so a retry here is the real bounded-read policy.
    Drop,
    /// Answer `status` with `body`, carrying `Retry-After` seconds
    /// when a hint is scripted.
    Respond {
        /// The status code.
        status: u16,
        /// `Retry-After` delta-seconds to answer with.
        retry_after: Option<u64>,
        /// The response body.
        body: &'static str,
    },
}

/// A captured request's head — method, URI, and the typed headers.
pub type RequestHead = http::request::Parts;

/// One scripted loopback server — accepts connections until `join`
/// shuts it down.
#[derive(Debug)]
pub struct Loopback {
    /// Base URL — `http://127.0.0.1:<port>`.
    pub url: String,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Vec<RequestHead>>>,
}

impl Loopback {
    /// Bind a free loopback port and serve `steps` in order, one per
    /// accepted connection; requests past the script get `SENTINEL`.
    pub async fn start(steps: Vec<Step>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback binds");
        let addr: SocketAddr = listener.local_addr().expect("bound address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(run(listener, steps.into(), shutdown_rx));
        Self {
            url: format!("http://{addr}"),
            shutdown: Some(shutdown_tx),
            task: Some(task),
        }
    }

    /// Shut the listener down and reap the task, returning every
    /// request head the server accepted, in order. A server panic or a
    /// shutdown that misses `JOIN_BOUND` propagates as a panic.
    pub async fn join(mut self) -> Vec<RequestHead> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let task = self.task.take().expect("server task");
        tokio::time::timeout(JOIN_BOUND, task).await.map_or_else(
            |_| panic!("loopback server did not stop inside {JOIN_BOUND:?}"),
            |joined| joined.expect("loopback task panicked"),
        )
    }
}

impl Drop for Loopback {
    /// A test that panics or is cancelled before `join` still drops the
    /// server — abort its task rather than leave a listener behind.
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// The accept loop: one connection at a time, each answered by the
/// next scripted step or `SENTINEL`, until shutdown. Request heads
/// come back through the bounded channel and leave with the task —
/// the single producer and the single consumer share no lock.
async fn run(
    listener: TcpListener,
    mut steps: VecDeque<Step>,
    mut shutdown: oneshot::Receiver<()>,
) -> Vec<RequestHead> {
    let (head_tx, mut head_rx) = mpsc::channel::<RequestHead>(64);
    let mut heads = Vec::new();
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { break };
                let step = steps.pop_front().unwrap_or(SENTINEL);
                let tx = head_tx.clone();
                let service = service_fn(move |request: Request<Incoming>| {
                    let tx = tx.clone();
                    let step = step.clone();
                    async move {
                        let (head, _body) = request.into_parts();
                        let _ = tx.try_send(head);
                        match step {
                            Step::Drop => Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "loopback drop",
                            )),
                            Step::Respond {
                                status,
                                retry_after,
                                body,
                            } => respond(status, retry_after, body),
                        }
                    }
                });
                let io = TokioIo::new(stream);
                // keep-alive off: one request per connection, so the
                // script advances per request and the loop keeps
                // accepting instead of holding an idle conn.
                let _ = tokio::time::timeout(
                    CONNECTION_BOUND,
                    http1::Builder::new()
                        .keep_alive(false)
                        .serve_connection(io, service),
                )
                .await;
                while let Ok(head) = head_rx.try_recv() {
                    heads.push(head);
                }
            }
        }
    }
    while let Ok(head) = head_rx.try_recv() {
        heads.push(head);
    }
    heads
}

/// A typed h1 response for the scripted status, with `Retry-After`
/// when the step carries a hint.
fn respond(
    status: u16,
    retry_after: Option<u64>,
    body: &'static str,
) -> io::Result<Response<Full<Bytes>>> {
    let mut response = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .map_err(io::Error::other)?;
    if let Some(hint) = retry_after {
        response
            .headers_mut()
            .insert(http::header::RETRY_AFTER, HeaderValue::from(hint));
    }
    Ok(response)
}
