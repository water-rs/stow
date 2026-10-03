//! The supervisor side: bind an endpoint, answer every facade, shut down
//! when the build ends.
//!
//! Connections are handled concurrently — cargo runs many rustc
//! invocations at once, and serialising them behind one task would undo
//! the parallelism the cache is supposed to accelerate. The only mutable
//! state the server itself owns is the table of compiles it has asked for,
//! and that lives in one task reached over a channel rather than behind a
//! lock.

use std::future::Future;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};

use super::protocol::{
    Answer, AwaitServeMap, Compiled, Observed, Plan, Request, read_frame, write_frame,
};
use super::{ENDPOINT_ENV, Endpoint, TOKEN_ENV};

/// What a supervisor does with the invocations its facades send.
///
/// Implemented by the build's own state, which owns the config, the index
/// slice, the local cache and the one edge connection the whole build
/// shares.
pub trait Handler: Send + Sync + 'static {
    /// Decide one invocation. `Answer::Compile`'s ticket is allocated by
    /// the server, so the handler returns the decision without one.
    /// `build_script_out_dir` is the `OUT_DIR` the facade's invocation
    /// environment carried — read it from the request, never this
    /// process's environment.
    fn plan(
        self: &Arc<Self>,
        executable: std::ffi::OsString,
        args: Vec<std::ffi::OsString>,
        build_script_out_dir: Option<std::ffi::OsString>,
    ) -> impl Future<Output = Decision<Self::Pending>> + Send;

    /// Finish the work that only exists after a real compile.
    fn compiled(
        self: &Arc<Self>,
        pending: Self::Pending,
        success: bool,
    ) -> impl Future<Output = ()> + Send;

    /// The bookkeeping a facade-owned compile still needs: the mark before
    /// rustc starts (`observation.success` is `None`) and the observation
    /// after it ends (`Some`). One-way — nothing comes back.
    fn observed(self: &Arc<Self>, observation: Observation) -> impl Future<Output = ()> + Send;

    /// Answer `AwaitServeMap` on the build's schedule: resolve when the
    /// build's serve map is final — the pending map's final write landed
    /// — and immediately when it already is. Every platform speaks this
    /// over the transport it already carries (stow#347).
    fn await_serve_map(self: &Arc<Self>) -> impl Future<Output = ()> + Send;

    /// What the handler needs to remember between asking for a compile and
    /// hearing that it finished.
    type Pending: Send + 'static;
}

/// A compile the facade already ran — or is about to — without a plan
/// round trip: the mark and the report a unit the serve map ruled out
/// still owes the build.
#[derive(Debug)]
pub struct Observation {
    /// The real rustc the facade ran.
    pub executable: std::ffi::OsString,
    /// Everything after the executable, in order.
    pub args: Vec<std::ffi::OsString>,
    /// The `OUT_DIR` the facade's invocation environment carried.
    pub build_script_out_dir: Option<std::ffi::OsString>,
    /// `None` marks the unit as compiling locally; `Some` reports how the
    /// finished compile exited.
    pub success: Option<bool>,
}

/// A handler's decision about one invocation.
pub enum Decision<P> {
    /// The outputs are in place; the facade exits 0.
    Served,
    /// The facade runs rustc and reports back with `pending` restored.
    Compile(P),
}

/// A running supervisor: the endpoint its facades connect to, and the
/// tasks that serve them.
pub struct Supervisor {
    endpoint: Endpoint,
    token: String,
    shutdown: Option<oneshot::Sender<()>>,
    /// Removed when the supervisor drops, taking the socket with it.
    #[cfg(unix)]
    _socket_dir: Option<tempfile::TempDir>,
}

impl Supervisor {
    /// The environment a cargo invocation needs to reach this supervisor.
    #[must_use]
    pub fn env(&self) -> [(&'static str, String); 2] {
        [
            (ENDPOINT_ENV, self.endpoint.encode()),
            (TOKEN_ENV, self.token.clone()),
        ]
    }

    /// Stop accepting, and drop the socket. In-flight facades finish the
    /// exchange they are in.
    pub fn shutdown(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Messages the ticket task owns the state for.
enum Ticket<P> {
    Allocate(P, oneshot::Sender<u64>),
    Take(u64, oneshot::Sender<Option<P>>),
}

/// Bind a supervisor for this build and start serving `handler`.
///
/// # Errors
///
/// Binding failures: a socket directory that cannot be created, a port
/// that cannot be bound.
pub fn start<H>(handler: Arc<H>) -> Result<Supervisor, String>
where
    H: Handler,
{
    let token = mint_token();
    let (tickets, ticket_rx) = mpsc::unbounded_channel::<Ticket<H::Pending>>();
    tokio::spawn(run_tickets(ticket_rx));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    #[cfg(unix)]
    {
        let socket_dir = tempfile::Builder::new()
            .prefix("stow-supervisor-")
            .tempdir()
            .map_err(|error| format!("create supervisor socket directory: {error}"))?;
        let path = socket_dir.path().join("sock");
        let listener = tokio::net::UnixListener::bind(&path)
            .map_err(|error| format!("bind supervisor socket {}: {error}", path.display()))?;
        restrict_socket(&path)?;
        tokio::spawn(accept_unix(
            listener,
            handler,
            tickets,
            token.clone(),
            shutdown_rx,
        ));
        tracing::debug!(endpoint = %path.display(), "build supervisor listening");
        Ok(Supervisor {
            endpoint: Endpoint::Unix(path),
            token,
            shutdown: Some(shutdown_tx),
            _socket_dir: Some(socket_dir),
        })
    }

    #[cfg(not(unix))]
    {
        // Bound through the std listener so binding needs no runtime of
        // its own: the supervisor is started from ordinary code, and the
        // accept loop is what belongs on the runtime.
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .map_err(|error| format!("bind supervisor loopback listener: {error}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("set the supervisor listener non-blocking: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| format!("read supervisor listener port: {error}"))?
            .port();
        let listener = tokio::net::TcpListener::from_std(listener)
            .map_err(|error| format!("adopt the supervisor listener: {error}"))?;
        tokio::spawn(accept_loopback(
            listener,
            handler,
            tickets,
            token.clone(),
            shutdown_rx,
        ));
        tracing::debug!(port, "build supervisor listening");
        Ok(Supervisor {
            endpoint: Endpoint::Loopback(port),
            token,
            shutdown: Some(shutdown_tx),
        })
    }
}

/// 128 bits of randomness, hex. The Unix socket's mode already keeps other
/// users out; this is what protects the loopback listener, which every
/// local process can connect to.
fn mint_token() -> String {
    let mut bytes = [0u8; 16];
    getrandom(&mut bytes);
    hex::encode(bytes)
}

fn getrandom(bytes: &mut [u8; 16]) {
    // blake3 of two clocks and the pid: the token only has to be
    // unguessable by another process on this machine for the length of one
    // build, and this avoids a dependency whose only user is this line.
    let seed = format!(
        "{}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        std::time::Instant::now()
    );
    bytes.copy_from_slice(&blake3::hash(seed.as_bytes()).as_bytes()[..16]);
}

#[cfg(unix)]
fn restrict_socket(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("restrict supervisor socket {}: {error}", path.display()))
}

async fn run_tickets<P>(mut messages: mpsc::UnboundedReceiver<Ticket<P>>) {
    let mut next = 1u64;
    let mut pending = std::collections::HashMap::<u64, P>::new();
    while let Some(message) = messages.recv().await {
        match message {
            Ticket::Allocate(value, reply) => {
                let ticket = next;
                next = next.wrapping_add(1);
                pending.insert(ticket, value);
                if reply.send(ticket).is_err() {
                    // The facade disconnected before it heard the answer,
                    // so nothing will ever report this compile.
                    pending.remove(&ticket);
                }
            }
            Ticket::Take(ticket, reply) => {
                let _ = reply.send(pending.remove(&ticket));
            }
        }
    }
}

#[cfg(unix)]
async fn accept_unix<H: Handler>(
    listener: tokio::net::UnixListener,
    handler: Arc<H>,
    tickets: mpsc::UnboundedSender<Ticket<H::Pending>>,
    token: String,
    mut shutdown: oneshot::Receiver<()>,
) {
    loop {
        let accepted = tokio::select! {
            () = async { (&mut shutdown).await.ok(); } => return,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, _)) => {
                tokio::spawn(serve_connection(
                    stream,
                    Arc::clone(&handler),
                    tickets.clone(),
                    token.clone(),
                ));
            }
            Err(error) => {
                tracing::warn!(%error, "supervisor accept failed");
                return;
            }
        }
    }
}

#[cfg(not(unix))]
async fn accept_loopback<H: Handler>(
    listener: tokio::net::TcpListener,
    handler: Arc<H>,
    tickets: mpsc::UnboundedSender<Ticket<H::Pending>>,
    token: String,
    mut shutdown: oneshot::Receiver<()>,
) {
    loop {
        let accepted = tokio::select! {
            () = async { (&mut shutdown).await.ok(); } => return,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, _)) => {
                tokio::spawn(serve_connection(
                    stream,
                    Arc::clone(&handler),
                    tickets.clone(),
                    token.clone(),
                ));
            }
            Err(error) => {
                tracing::warn!(%error, "supervisor accept failed");
                return;
            }
        }
    }
}

async fn serve_connection<S, H>(
    mut stream: S,
    handler: Arc<H>,
    tickets: mpsc::UnboundedSender<Ticket<H::Pending>>,
    token: String,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    H: Handler,
{
    loop {
        let request: Request = match read_frame(&mut stream).await {
            Ok(Some(request)) => request,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(%error, "supervisor could not read a facade frame");
                return;
            }
        };
        if let Some(answer) = answer_request(&handler, &tickets, &token, request).await
            && let Err(error) = write_frame(&mut stream, &answer).await
        {
            tracing::warn!(%error, "supervisor could not answer a facade");
            return;
        }
    }
}

/// Answer the request, or `None` when the request is one-way — an
/// observation carries no reply because the facade that sent it is not
/// waiting on one.
async fn answer_request<H: Handler>(
    handler: &Arc<H>,
    tickets: &mpsc::UnboundedSender<Ticket<H::Pending>>,
    token: &str,
    request: Request,
) -> Option<Answer> {
    match request {
        Request::Plan(plan) => Some(answer_plan(handler, tickets, token, plan).await),
        Request::Compiled(report) => Some(answer_report(handler, tickets, token, report).await),
        Request::Observed(observed) => {
            answer_observation(handler, token, observed).await;
            None
        }
        Request::AwaitServeMap(await_map) => {
            Some(answer_await_serve_map(handler, token, await_map).await)
        }
    }
}

/// Hold the answer until the build's serve map is final. The handler's
/// wait resolves on the driver's schedule, so this frame is how a
/// `pending` map's facades hear the final write land (stow#347).
async fn answer_await_serve_map<H: Handler>(
    handler: &Arc<H>,
    token: &str,
    await_map: AwaitServeMap,
) -> Answer {
    if await_map.token != token {
        return Answer::Failed {
            message: "supervisor token mismatch".to_owned(),
        };
    }
    handler.await_serve_map().await;
    Answer::ServeMapReady
}

async fn answer_plan<H: Handler>(
    handler: &Arc<H>,
    tickets: &mpsc::UnboundedSender<Ticket<H::Pending>>,
    token: &str,
    plan: Plan,
) -> Answer {
    if plan.token != token {
        return Answer::Failed {
            message: "supervisor token mismatch".to_owned(),
        };
    }
    let (executable, args, build_script_out_dir) =
        match (plan.executable(), plan.args(), plan.build_script_out_dir()) {
            (Ok(executable), Ok(args), Ok(out_dir)) => (executable, args, out_dir),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
                return Answer::Failed { message: error };
            }
        };
    match handler.plan(executable, args, build_script_out_dir).await {
        Decision::Served => Answer::Served,
        Decision::Compile(pending) => {
            let (sender, allocated) = oneshot::channel();
            if tickets.send(Ticket::Allocate(pending, sender)).is_err() {
                return Answer::Failed {
                    message: "supervisor ticket task is gone".to_owned(),
                };
            }
            allocated.await.map_or_else(
                |_| Answer::Failed {
                    message: "supervisor ticket task dropped the allocation".to_owned(),
                },
                |ticket| Answer::Compile { ticket },
            )
        }
    }
}

async fn answer_observation<H: Handler>(handler: &Arc<H>, token: &str, observed: Observed) {
    if observed.token != token {
        tracing::warn!("supervisor observation with the wrong token dropped");
        return;
    }
    let (Ok(executable), Ok(args), Ok(build_script_out_dir)) = (
        observed.executable(),
        observed.args(),
        observed.build_script_out_dir(),
    ) else {
        tracing::warn!("supervisor observation could not be decoded; dropped");
        return;
    };
    handler
        .observed(Observation {
            executable,
            args,
            build_script_out_dir,
            success: observed.success,
        })
        .await;
}

async fn answer_report<H: Handler>(
    handler: &Arc<H>,
    tickets: &mpsc::UnboundedSender<Ticket<H::Pending>>,
    token: &str,
    report: Compiled,
) -> Answer {
    if report.token != token {
        return Answer::Failed {
            message: "supervisor token mismatch".to_owned(),
        };
    }
    let (sender, restored) = oneshot::channel();
    if tickets.send(Ticket::Take(report.ticket, sender)).is_err() {
        return Answer::Failed {
            message: "supervisor ticket task is gone".to_owned(),
        };
    }
    match restored.await {
        Ok(Some(pending)) => {
            handler.compiled(pending, report.success).await;
            Answer::Recorded
        }
        Ok(None) => Answer::Failed {
            message: format!("supervisor has no record of compile {}", report.ticket),
        },
        Err(_) => Answer::Failed {
            message: "supervisor ticket task dropped the lookup".to_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{Decision, Handler, start};
    use crate::supervisor::client::{Connection, Decision as ClientDecision};

    /// Serves anything whose first argument is `--serve-me`, asks for a
    /// compile otherwise, and counts the reports it receives.
    struct Stub {
        reports: AtomicUsize,
    }

    impl Handler for Stub {
        type Pending = OsString;

        fn plan(
            self: &Arc<Self>,
            _executable: OsString,
            args: Vec<OsString>,
            _build_script_out_dir: Option<OsString>,
        ) -> impl std::future::Future<Output = Decision<Self::Pending>> + Send {
            std::future::ready(if args.first().is_some_and(|arg| arg == "--serve-me") {
                Decision::Served
            } else {
                Decision::Compile(args.first().cloned().unwrap_or_default())
            })
        }

        fn compiled(
            self: &Arc<Self>,
            _pending: Self::Pending,
            success: bool,
        ) -> impl std::future::Future<Output = ()> + Send {
            if success {
                self.reports.fetch_add(1, Ordering::SeqCst);
            }
            std::future::ready(())
        }

        fn observed(
            self: &Arc<Self>,
            _observation: super::Observation,
        ) -> impl std::future::Future<Output = ()> + Send {
            std::future::ready(())
        }

        fn await_serve_map(self: &Arc<Self>) -> impl std::future::Future<Output = ()> + Send {
            std::future::ready(())
        }
    }

    /// The whole round trip a facade makes: ask, be told to compile, run
    /// the compile, report it. This is the assertion that fails if either
    /// side of the wire changes without the other.
    #[tokio::test]
    async fn a_facade_plans_and_reports_over_the_wire() {
        let handler = Arc::new(Stub {
            reports: AtomicUsize::new(0),
        });
        let supervisor = start(Arc::clone(&handler)).expect("start the supervisor");
        let [(_, endpoint), (_, token)] = supervisor.env();
        let endpoint = crate::supervisor::Endpoint::parse(&endpoint).expect("endpoint");

        let mut connection = Connection::open(&endpoint, token)
            .await
            .expect("connect to the supervisor");
        let decision = connection
            .plan(
                std::ffi::OsStr::new("/usr/bin/rustc"),
                &[OsString::from("--crate-name"), OsString::from("serde")],
                None,
            )
            .await
            .expect("plan");
        let ClientDecision::Compile(ticket) = decision else {
            panic!("the stub asks for a compile");
        };
        connection.report(&ticket, true).await.expect("report");
        assert_eq!(handler.reports.load(Ordering::SeqCst), 1);
    }

    /// The serve-map wait rides the loopback transport the Windows
    /// build uses: the handler's word releases the answer, so a facade
    /// blocked on it hears the final map land and nothing else
    /// (stow#347).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_serve_map_wait_answers_when_the_map_is_final() {
        use std::io::{Read as _, Write as _};
        use std::time::Duration;

        struct Gated {
            ready: tokio::sync::watch::Receiver<bool>,
        }
        impl Handler for Gated {
            type Pending = OsString;

            fn plan(
                self: &Arc<Self>,
                _executable: OsString,
                _args: Vec<OsString>,
                _build_script_out_dir: Option<OsString>,
            ) -> impl std::future::Future<Output = Decision<Self::Pending>> + Send {
                std::future::ready(Decision::Served)
            }

            fn compiled(
                self: &Arc<Self>,
                _pending: Self::Pending,
                _success: bool,
            ) -> impl std::future::Future<Output = ()> + Send {
                std::future::ready(())
            }

            fn observed(
                self: &Arc<Self>,
                _observation: super::Observation,
            ) -> impl std::future::Future<Output = ()> + Send {
                std::future::ready(())
            }

            fn await_serve_map(self: &Arc<Self>) -> impl std::future::Future<Output = ()> + Send {
                let mut ready = self.ready.clone();
                async move {
                    if !*ready.borrow() {
                        let _ = ready.changed().await;
                    }
                }
            }
        }

        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let handler = Arc::new(Gated { ready: ready_rx });
        let (tickets, ticket_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::task::spawn(super::run_tickets(ticket_rx));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        let token = "the-token".to_owned();
        tokio::task::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept the facade");
            super::serve_connection(stream, handler, tickets, token).await;
        });

        let (answered_tx, answered_rx) = std::sync::mpsc::channel();
        let facade = std::thread::spawn(move || {
            let mut peer = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
            let request =
                super::Request::AwaitServeMap(crate::supervisor::protocol::AwaitServeMap {
                    token: "the-token".to_owned(),
                });
            let body = serde_json::to_vec(&request).expect("request frame");
            peer.write_all(
                &u32::try_from(body.len())
                    .expect("frame length fits u32")
                    .to_le_bytes(),
            )
            .expect("write length");
            peer.write_all(&body).expect("write body");
            let mut length_bytes = [0_u8; 4];
            peer.read_exact(&mut length_bytes).expect("read length");
            let mut answer_body = vec![0_u8; u32::from_le_bytes(length_bytes) as usize];
            peer.read_exact(&mut answer_body).expect("read body");
            let answer: super::Answer = serde_json::from_slice(&answer_body).expect("answer frame");
            answered_tx.send(answer).expect("report answer");
        });

        // Nothing may answer while the map is still pending.
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            answered_rx.try_recv().is_err(),
            "the wait answered before the final map landed"
        );
        ready_tx.send(true).expect("release the map");
        let answer = answered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the wait must answer");
        facade.join().expect("facade thread");
        assert_eq!(answer, super::Answer::ServeMapReady);
    }

    /// A served unit never runs rustc, so it never reports.
    #[tokio::test]
    async fn a_served_unit_ends_the_exchange() {
        let handler = Arc::new(Stub {
            reports: AtomicUsize::new(0),
        });
        let supervisor = start(Arc::clone(&handler)).expect("start the supervisor");
        let [(_, endpoint), (_, token)] = supervisor.env();
        let endpoint = crate::supervisor::Endpoint::parse(&endpoint).expect("endpoint");

        let mut connection = Connection::open(&endpoint, token)
            .await
            .expect("connect to the supervisor");
        let decision = connection
            .plan(
                std::ffi::OsStr::new("/usr/bin/rustc"),
                &[OsString::from("--serve-me")],
                Some(std::ffi::OsStr::new("/tmp/build/demo-aaa/out")),
            )
            .await
            .expect("plan");
        assert!(matches!(decision, ClientDecision::Served));
        assert_eq!(handler.reports.load(Ordering::SeqCst), 0);
    }

    /// The token is what protects the loopback listener Windows uses, so a
    /// frame carrying the wrong one is refused rather than answered.
    #[tokio::test]
    async fn a_wrong_token_is_refused() {
        let handler = Arc::new(Stub {
            reports: AtomicUsize::new(0),
        });
        let supervisor = start(handler).expect("start the supervisor");
        let [(_, endpoint), _] = supervisor.env();
        let endpoint = crate::supervisor::Endpoint::parse(&endpoint).expect("endpoint");

        let mut connection = Connection::open(&endpoint, "not-the-token".to_owned())
            .await
            .expect("connect to the supervisor");
        let error = connection
            .plan(std::ffi::OsStr::new("/usr/bin/rustc"), &[], None)
            .await
            .expect_err("a wrong token must be refused");
        assert!(error.contains("token mismatch"), "{error}");
    }
}
