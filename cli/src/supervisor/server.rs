//! The supervisor side: bind an endpoint, answer every facade, shut down
//! when the build ends.
//!
//! Connections are handled concurrently — cargo runs many rustc
//! invocations at once, and serialising them behind one task would undo
//! the parallelism the cache is supposed to accelerate. The server owns
//! two pieces of mutable state: the table of compiles it has asked for,
//! which lives in one task reached over a channel rather than behind a
//! lock, and the units whose post-compile bookkeeping is still running —
//! the in-flight registry a dependent's bookkeeping waits on (stow#618).

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use stow_types::rustc::ParsedRustcArgs;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};

use super::protocol::{
    Answer, AwaitServeMap, Compiled, Observed, Plan, Request, ServedStderr, read_frame, write_frame,
};
use super::{BINARY_ENV, BinaryIdentity, ENDPOINT_ENV, Endpoint, TOKEN_ENV};

/// What a supervisor does with the invocations its facades send.
///
/// Implemented by the build's own state, which owns the config, the index
/// slice, the local cache and the one edge connection the whole build
/// shares.
pub trait Handler: Send + Sync + 'static {
    /// Decide one invocation. `Answer::Compile`'s ticket is allocated by
    /// the server, so the handler returns the decision without one.
    fn plan(
        self: &Arc<Self>,
        executable: std::ffi::OsString,
        args: Vec<std::ffi::OsString>,
        invocation: crate::unit_cache::InvocationEnv,
    ) -> impl Future<Output = Decision<Self::Pending>> + Send;

    /// Finish the work that only exists after a real compile. `stderr` is
    /// rustc's, when the decision asked the facade to capture it. An
    /// `Err` fails the facade's invocation with its message.
    fn compiled(
        self: &Arc<Self>,
        pending: Self::Pending,
        success: bool,
        stderr: Option<String>,
    ) -> impl Future<Output = Result<(), String>> + Send;

    /// The bookkeeping a facade-owned compile still needs: the mark before
    /// rustc starts (`observation.success` is `None`) and the observation
    /// after it ends (`Some`). One-way — nothing comes back.
    fn observed(self: &Arc<Self>, observation: Observation) -> impl Future<Output = ()> + Send;

    /// Answer `AwaitServeMap` on the build's schedule: resolve when the
    /// build's serve map is final — the pending map's final write landed
    /// — and immediately when it already is. Every platform speaks this
    /// over the transport it already carries (stow#347).
    fn await_serve_map(self: &Arc<Self>) -> impl Future<Output = ()> + Send;

    /// The host triple `executable`'s rustc compiles target-less units
    /// for — its `rustc -vV` `host:` line, probed once per executable and
    /// memoized for the build. A locally compiling unit's recordable
    /// outputs are named under it, so the lookup never comes back empty:
    /// a probe that fails is an error the request reports, not a skipped
    /// mark (stow#618).
    fn rustc_host_target(
        self: &Arc<Self>,
        executable: &std::ffi::OsStr,
    ) -> impl Future<Output = Result<String, String>> + Send;

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
    /// `None` marks the unit as compiling locally; `Some` reports how the
    /// finished compile exited.
    pub success: Option<bool>,
}

/// A handler's decision about one invocation.
pub enum Decision<P> {
    /// The outputs are in place; the facade exits 0. The payload is the
    /// stderr lines the facade owes cargo first (stow#633).
    Served(ServedStderr),
    /// The facade runs rustc and reports back with `pending` restored.
    Compile {
        pending: P,
        /// Whether the report carries rustc's stderr (stow#978).
        capture_stderr: bool,
    },
    /// The invocation fails with this message: deciding it hit a failure
    /// no compile would route around (stow#978).
    Failed(String),
}

/// How long [`Supervisor::shutdown`] waits for accepted connections to run
/// to their end after cargo has exited (stow#618). Every facade has exited
/// by then, so a connection only remains while the bookkeeping its frames
/// queued still runs — sqlite writes and file copies that take
/// milliseconds. The bound exists for the bookkeeping that hangs instead:
/// a wedged store must not hang a build that is already over.
const CONNECTION_DRAIN_BUDGET: Duration = Duration::from_secs(30);

/// A running supervisor: the endpoint its facades connect to, and the
/// tasks that serve them.
pub struct Supervisor {
    endpoint: Endpoint,
    token: String,
    /// The identity of the runtime executable this build's shims resolve
    /// to — exported so a facade running a different build of the binary
    /// refuses before it sends a frame (stow#645).
    binary: BinaryIdentity,
    shutdown: Option<oneshot::Sender<()>>,
    /// The accept task: ends once it has stopped accepting *and* every
    /// connection it accepted has run to its end (stow#618).
    accept_task: Option<tokio::task::JoinHandle<()>>,
    /// Live connection count, read by the drain's overrun warning.
    connections: Arc<Connections>,
    /// Holds the socket. Removed by [`Self::shutdown`], or when the
    /// supervisor drops without reaching it.
    #[cfg(unix)]
    socket_dir: Option<tempfile::TempDir>,
}

impl Supervisor {
    /// The environment a cargo invocation needs to reach this supervisor:
    /// the endpoint and token the transport wants, and the binary
    /// identity the facade's own executable must match.
    #[must_use]
    pub fn env(&self) -> [(&'static str, String); 3] {
        [
            (ENDPOINT_ENV, self.endpoint.encode()),
            (TOKEN_ENV, self.token.clone()),
            (BINARY_ENV, self.binary.encode()),
        ]
    }

    /// Stop accepting, then wait for every in-flight connection to run to
    /// its end. After cargo has exited every facade has exited too, so each
    /// connection ends at end-of-stream once its queued frames — including
    /// the last units' post-compile stores — are handled (stow#618).
    ///
    /// The wait is bounded: on overrun it warns with the number of
    /// connections abandoned rather than hanging the build. Returns that
    /// number — `0` is a clean drain.
    ///
    /// The socket's directory is removed here rather than at drop: the
    /// close reports a removal failure a drop would swallow (stow#630).
    pub async fn shutdown(&mut self) -> usize {
        let abandoned = self.shutdown_within(CONNECTION_DRAIN_BUDGET).await;
        #[cfg(unix)]
        if let Some(socket_dir) = self.socket_dir.take()
            && let Err(error) = socket_dir.close()
        {
            tracing::warn!(%error, "could not remove the supervisor socket directory");
        }
        abandoned
    }

    /// [`Self::shutdown`] with an explicit bound — the constant lives at
    /// [`CONNECTION_DRAIN_BUDGET`]; tests pick their own.
    async fn shutdown_within(&mut self, budget: Duration) -> usize {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let Some(mut task) = self.accept_task.take() else {
            return 0;
        };
        match tokio::time::timeout(budget, &mut task).await {
            Ok(Ok(())) => 0,
            Ok(Err(error)) => {
                tracing::warn!(%error, "supervisor accept task failed during shutdown");
                0
            }
            Err(_elapsed) => {
                let abandoned = self.connections.live.load(Ordering::SeqCst);
                tracing::warn!(
                    abandoned,
                    "supervisor shutdown abandoned in-flight facade connections"
                );
                // Aborting the accept task drops its `JoinSet`, which
                // aborts the connections it was still draining.
                task.abort();
                abandoned
            }
        }
    }
}

impl Drop for Supervisor {
    /// The early-error path: a `?` inside the build drops the supervisor
    /// without reaching [`Self::shutdown`], and there is no wait possible
    /// here. This only stops the accept loop — the connections it already
    /// accepted keep draining on the runtime for as long as it stays
    /// alive, but nothing awaits them, so a store still in flight when the
    /// process exits is lost the way the pre-stow#618 build lost its last
    /// unit.
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

/// Messages the ticket task owns the state for.
pub enum Ticket<P> {
    Allocate(P, oneshot::Sender<u64>),
    Take(u64, oneshot::Sender<Option<P>>),
}

/// Bind a supervisor for this build and start serving `handler`.
///
/// `in_flight` is the build's registry of locally compiling units — the
/// caller shares it with the handler, whose post-compiles wait on it
/// (stow#618). `runtime_executable` is the binary the build's shims
/// resolve to: its identity goes to cargo so a facade running a different
/// build of the binary refuses to connect (stow#645).
///
/// # Errors
///
/// Binding failures: a socket directory that cannot be created, a port
/// that cannot be bound, a runtime executable that cannot be statted.
pub fn start<H>(
    handler: Arc<H>,
    in_flight: InFlightUnits,
    runtime_executable: &std::path::Path,
) -> Result<Supervisor, String>
where
    H: Handler,
{
    let binary = BinaryIdentity::of(runtime_executable)
        .map_err(|error| format!("identity of {}: {error}", runtime_executable.display()))?;
    let token = mint_token();
    let (tickets, ticket_rx) = mpsc::unbounded_channel::<Ticket<H::Pending>>();
    tokio::spawn(run_tickets(ticket_rx));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let connections = Arc::new(Connections::default());
    let listener = super::bind("stow-supervisor-")?;
    let endpoint = listener.endpoint();

    #[cfg(unix)]
    {
        let super::Listener::Unix {
            listener,
            dir: socket_dir,
        } = listener;
        let accept_task = tokio::spawn(accept_unix(
            listener,
            handler,
            tickets,
            token.clone(),
            shutdown_rx,
            in_flight,
            Arc::clone(&connections),
        ));
        tracing::debug!(endpoint = %endpoint.encode(), "build supervisor listening");
        Ok(Supervisor {
            endpoint,
            token,
            binary,
            shutdown: Some(shutdown_tx),
            accept_task: Some(accept_task),
            connections,
            socket_dir: Some(socket_dir),
        })
    }

    #[cfg(not(unix))]
    {
        let super::Listener::Loopback { listener, port } = listener;
        let accept_task = tokio::spawn(accept_loopback(
            listener,
            handler,
            tickets,
            token.clone(),
            shutdown_rx,
            in_flight,
            Arc::clone(&connections),
        ));
        tracing::debug!(port, "build supervisor listening");
        Ok(Supervisor {
            endpoint,
            token,
            binary,
            shutdown: Some(shutdown_tx),
            accept_task: Some(accept_task),
            connections,
        })
    }
}

/// 128 bits of randomness, hex. The Unix socket's mode already keeps other
/// users out; this is what protects the loopback listener, which every
/// local process can connect to.
pub fn mint_token() -> String {
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

pub async fn run_tickets<P>(mut messages: mpsc::UnboundedReceiver<Ticket<P>>) {
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

/// The locally-compiled units of this build whose post-compile
/// bookkeeping has not finished, keyed by the output paths a dependent's
/// `--extern` arguments can name (stow#618).
///
/// A unit is in flight from the moment the supervisor learns cargo is
/// compiling it — the `success = None` mark on the uncovered path, the
/// `Compile` answer on the plan path — until its bookkeeping ends one way
/// or another: the report's store finished, the report errored or
/// skipped, or the facade's connection ended without a report at all. A
/// dependent's identity resolution reads the `materialized_outputs` rows
/// that bookkeeping writes, so its post-compile waits on every in-flight
/// unit its `--extern` set names instead of racing the write.
///
/// `std::sync::Mutex` around a map rather than another actor: completing a
/// unit has to happen in `Drop` — an early return, an error and a dead
/// connection all end the flight the same way — and a drop cannot await a
/// channel send. Every critical section is a handful of map operations;
/// nothing awaits inside one.
#[derive(Debug, Default, Clone)]
pub struct InFlightUnits {
    units: Arc<std::sync::Mutex<HashMap<String, Arc<InFlightUnit>>>>,
}

impl InFlightUnits {
    /// Put the unit owning `paths` in flight; the returned guard is the
    /// flight's lifetime — dropping it completes the unit.
    fn register(&self, paths: Vec<String>) -> Completion {
        let unit = Arc::new(InFlightUnit {
            paths,
            done: crate::Latch::pending(),
        });
        {
            let mut units = self.units.lock().expect("in-flight units mutex");
            for path in &unit.paths {
                units.insert(path.clone(), Arc::clone(&unit));
            }
        }
        Completion {
            registry: self.clone(),
            unit,
        }
    }

    /// Resolve once `waits` dependents have parked on the in-flight unit
    /// registered under `path` — the test observation
    /// [`crate::Latch::parked`] carries, reached by an `--extern` path
    /// (stow#810).
    #[cfg(test)]
    pub(crate) async fn parked_on(&self, path: &str, waits: usize) {
        let unit = Arc::clone(
            self.units
                .lock()
                .expect("in-flight units mutex")
                .get(path)
                .unwrap_or_else(|| panic!("no unit in flight under {path}")),
        );
        unit.done.parked(waits).await;
    }

    /// Wait for the bookkeeping of every in-flight unit one of `parsed`'s
    /// `--extern` dependencies could be. The paths come from the same
    /// `extern_output_paths` derivation the identity resolution uses, so
    /// the wait covers exactly the units whose `materialized_outputs`
    /// rows it reads (stow#618).
    pub async fn wait_for_externs(&self, parsed: &ParsedRustcArgs) {
        let externs = crate::artifact_cache::extern_output_paths(parsed).unwrap_or_default();
        let waiting = {
            let units = self.units.lock().expect("in-flight units mutex");
            // One unit registers several paths and a dependent can name
            // more than one of them — dedupe on the unit itself.
            let mut seen = HashSet::new();
            externs
                .iter()
                .filter_map(|(_, path)| units.get(path))
                .filter(|unit| seen.insert(Arc::as_ptr(unit)))
                .cloned()
                .collect::<Vec<Arc<InFlightUnit>>>()
        };
        for unit in waiting {
            unit.wait().await;
        }
    }

    /// End a flight: lift the unit's registrations and release its
    /// waiters. A registration a different unit has since taken is left
    /// alone — the pointer check keeps one flight from completing
    /// another's.
    fn complete(&self, unit: &Arc<InFlightUnit>) {
        {
            let mut units = self.units.lock().expect("in-flight units mutex");
            for path in &unit.paths {
                if units
                    .get(path)
                    .is_some_and(|registered| Arc::ptr_eq(registered, unit))
                {
                    units.remove(path);
                }
            }
        }
        // A dependent waits on its dependencies one at a time, so this
        // flight can end before the dependent has subscribed to it: the
        // latch stores the end either way (stow#642).
        unit.done.complete();
    }
}

/// One in-flight unit: the paths it registered under and the signal its
/// bookkeeping's end sends.
#[derive(Debug)]
struct InFlightUnit {
    /// Every `--extern`-addressable output path this unit's bookkeeping
    /// records — normalized by the same `path_to_string` the
    /// `materialized_outputs` rows and the extern lookup use.
    paths: Vec<String>,
    /// Fired once the flight ends; a waiter that arrives late resolves
    /// at once.
    done: crate::Latch,
}

impl InFlightUnit {
    /// Resolve once this unit's bookkeeping has finished — immediately
    /// when it already has.
    async fn wait(&self) {
        self.done.wait().await;
    }
}

/// The guard a connection holds on one registered flight. Dropping it —
/// at the end of the report's bookkeeping, on an early return or an error
/// inside it, or with the rest of a connection's marks when the facade
/// goes away mid-flight — completes the unit (stow#618).
struct Completion {
    registry: InFlightUnits,
    unit: Arc<InFlightUnit>,
}

impl Drop for Completion {
    fn drop(&mut self) {
        self.registry.complete(&self.unit);
    }
}

/// A flight one connection started and has not yet reported: the
/// uncovered path's mark pairs with its report by position, the plan
/// path's `Compile` answer pairs with the report's ticket.
pub struct ConnectionMark {
    ticket: Option<u64>,
    completion: Completion,
}

/// The output paths a locally-compiled unit's bookkeeping records in
/// `materialized_outputs` — the paths a dependent's `--extern` names,
/// whose platform naming follows `host`. `None` only when the paths
/// themselves cannot be derived: nothing records them, so nothing waits
/// on them.
fn recordable_output_paths(parsed: &ParsedRustcArgs, host: &str) -> Option<Vec<String>> {
    let paths = crate::artifact_cache::materialized_output_paths(parsed, host).ok()?;
    paths
        .iter()
        .map(|path| crate::artifact_cache::path_to_string(path))
        .collect::<Result<Vec<_>, _>>()
        .ok()
}

/// The supervisor's accepted connections, as the shutdown drain sees them.
#[derive(Debug, Default)]
struct Connections {
    /// Connections whose `serve_connection` task has not ended — the
    /// count the drain's overrun warning reports as abandoned.
    live: AtomicUsize,
    /// Test observation (stow#810): the connections the shutdown drain
    /// still waits on, published once the accept loop stops and after
    /// every join. A test reaches the point where only the connection it
    /// holds is left through this, rather than sleeping and hoping the
    /// drain had its chance to return early.
    #[cfg(test)]
    draining: tokio::sync::watch::Sender<Option<usize>>,
}

/// Decrement the live-connection count when a `serve_connection` task
/// ends, whatever way it ended.
struct ConnectionGuard(Arc<Connections>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(unix)]
async fn accept_unix<H: Handler>(
    listener: tokio::net::UnixListener,
    handler: Arc<H>,
    tickets: mpsc::UnboundedSender<Ticket<H::Pending>>,
    token: String,
    mut shutdown: oneshot::Receiver<()>,
    in_flight: InFlightUnits,
    connections: Arc<Connections>,
) {
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        let accepted = tokio::select! {
            () = async { (&mut shutdown).await.ok(); } => break,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, _)) => {
                connections.live.fetch_add(1, Ordering::SeqCst);
                tasks.spawn(serve_connection(
                    stream,
                    Arc::clone(&handler),
                    tickets.clone(),
                    token.clone(),
                    in_flight.clone(),
                    Arc::clone(&connections),
                ));
            }
            Err(error) => {
                tracing::warn!(%error, "supervisor accept failed");
                break;
            }
        }
    }
    drain_connections(tasks, &connections).await;
}

#[cfg(not(unix))]
async fn accept_loopback<H: Handler>(
    listener: tokio::net::TcpListener,
    handler: Arc<H>,
    tickets: mpsc::UnboundedSender<Ticket<H::Pending>>,
    token: String,
    mut shutdown: oneshot::Receiver<()>,
    in_flight: InFlightUnits,
    connections: Arc<Connections>,
) {
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        let accepted = tokio::select! {
            () = async { (&mut shutdown).await.ok(); } => break,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, _)) => {
                connections.live.fetch_add(1, Ordering::SeqCst);
                tasks.spawn(serve_connection(
                    stream,
                    Arc::clone(&handler),
                    tickets.clone(),
                    token.clone(),
                    in_flight.clone(),
                    Arc::clone(&connections),
                ));
            }
            Err(error) => {
                tracing::warn!(%error, "supervisor accept failed");
                break;
            }
        }
    }
    drain_connections(tasks, &connections).await;
}

/// Wait for every accepted connection to run to its end. The build is
/// over when the last facade's queued bookkeeping has run: stopping
/// accepting is not enough (stow#618).
///
/// Every task is joined, whatever the ones before it returned. A
/// `JoinSet` hands back the connections that finished long ago first,
/// and dropping it aborts the rest — a drain that stopped at the first
/// clean join cut off exactly the stores it exists to wait for
/// (stow#660).
async fn drain_connections(
    mut tasks: tokio::task::JoinSet<()>,
    #[cfg_attr(not(test), expect(unused_variables))] connections: &Connections,
) {
    #[cfg(test)]
    connections.draining.send_replace(Some(tasks.len()));
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            tracing::warn!(%error, "supervisor connection task failed");
        }
        #[cfg(test)]
        connections.draining.send_replace(Some(tasks.len()));
    }
}

async fn serve_connection<S, H>(
    mut stream: S,
    handler: Arc<H>,
    tickets: mpsc::UnboundedSender<Ticket<H::Pending>>,
    token: String,
    in_flight: InFlightUnits,
    connections: Arc<Connections>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    H: Handler,
{
    let _guard = ConnectionGuard(connections);
    // Flights this connection started and has not yet reported: the vec
    // itself is the abandonment path — a connection that ends mid-flight
    // drops it here and completes every unit whose report never came, so
    // no dependent waits on bookkeeping that will never run (stow#618).
    let mut marks: Vec<ConnectionMark> = Vec::new();
    loop {
        let request: Request = match read_frame(&mut stream).await {
            Ok(Some(request)) => request,
            Ok(None) => break,
            Err(error) => {
                tracing::warn!(%error, "supervisor could not read a facade frame");
                break;
            }
        };
        if let Some(answer) =
            answer_request(&handler, &tickets, &token, &in_flight, &mut marks, request).await
            && let Err(error) = write_frame(&mut stream, &answer).await
        {
            tracing::warn!(%error, "supervisor could not answer a facade");
            break;
        }
    }
}

/// Answer the request, or `None` when the request is one-way — an
/// observation carries no reply because the facade that sent it is not
/// waiting on one.
pub async fn answer_request<H: Handler>(
    handler: &Arc<H>,
    tickets: &mpsc::UnboundedSender<Ticket<H::Pending>>,
    token: &str,
    in_flight: &InFlightUnits,
    marks: &mut Vec<ConnectionMark>,
    request: Request,
) -> Option<Answer> {
    match request {
        Request::Plan(plan) => {
            Some(answer_plan(handler, tickets, token, in_flight, marks, plan).await)
        }
        Request::Compiled(report) => {
            Some(answer_report(handler, tickets, token, marks, report).await)
        }
        Request::Observed(observed) => {
            answer_observation(handler, token, in_flight, marks, observed).await;
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
    in_flight: &InFlightUnits,
    marks: &mut Vec<ConnectionMark>,
    plan: Plan,
) -> Answer {
    if plan.token != token {
        return Answer::Failed {
            message: "supervisor token mismatch".to_owned(),
        };
    }
    let (executable, args, invocation) = match (plan.executable(), plan.args(), plan.invocation()) {
        (Ok(executable), Ok(args), Ok(invocation)) => (executable, args, invocation),
        (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
            return Answer::Failed { message: error };
        }
    };
    // The host names the unit's recordable outputs; an invocation the
    // parser cannot model records nothing and never probes. A probe
    // that fails fails the request — the mark a dependent blocks on is
    // never skipped quietly (stow#618).
    let recordable_paths = match ParsedRustcArgs::parse(&args) {
        Ok(parsed) => match handler.rustc_host_target(&executable).await {
            Ok(host) => recordable_output_paths(&parsed, &host),
            Err(error) => {
                return Answer::Failed {
                    message: format!("could not probe the rustc host target: {error}"),
                };
            }
        },
        Err(_) => None,
    };
    match handler.plan(executable, args, invocation).await {
        Decision::Served(notifications) => Answer::Served(notifications),
        Decision::Failed(message) => Answer::Failed { message },
        Decision::Compile {
            pending,
            capture_stderr,
        } => {
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
                |ticket| {
                    // The facade was told to compile: the unit is in
                    // flight until the `Compiled` report's bookkeeping —
                    // or this connection's end — completes it (stow#618).
                    if let Some(paths) = recordable_paths {
                        marks.push(ConnectionMark {
                            ticket: Some(ticket),
                            completion: in_flight.register(paths),
                        });
                    }
                    Answer::Compile {
                        ticket,
                        capture_stderr,
                    }
                },
            )
        }
    }
}

async fn answer_observation<H: Handler>(
    handler: &Arc<H>,
    token: &str,
    in_flight: &InFlightUnits,
    marks: &mut Vec<ConnectionMark>,
    observed: Observed,
) {
    if observed.token != token {
        tracing::warn!("supervisor observation with the wrong token dropped");
        return;
    }
    let (Ok(executable), Ok(args)) = (observed.executable(), observed.args()) else {
        tracing::warn!("supervisor observation could not be decoded; dropped");
        return;
    };
    // The flight spans the mark frame's arrival to the end of this call:
    // on the report the mark's guard moves into this scope, so the
    // bookkeeping below — including every early return and error inside
    // it — is what the unit's waiters are blocked on (stow#618).
    let _completion = match observed.success {
        None => {
            if let Ok(parsed) = ParsedRustcArgs::parse(&args) {
                match handler.rustc_host_target(&executable).await {
                    Ok(host) => {
                        if let Some(paths) = recordable_output_paths(&parsed, &host) {
                            marks.push(ConnectionMark {
                                ticket: None,
                                completion: in_flight.register(paths),
                            });
                        }
                    }
                    // The frame is one-way, so the probe's failure is
                    // reported in the build's log rather than answered;
                    // the observation itself still reaches the handler.
                    Err(error) => {
                        tracing::warn!(%error, "supervisor could not probe the rustc host target, registering no in-flight mark");
                    }
                }
            }
            None
        }
        Some(_) => marks
            .iter()
            .position(|mark| mark.ticket.is_none())
            .map(|index| marks.remove(index).completion),
    };
    handler
        .observed(Observation {
            executable,
            args,
            success: observed.success,
        })
        .await;
}

async fn answer_report<H: Handler>(
    handler: &Arc<H>,
    tickets: &mpsc::UnboundedSender<Ticket<H::Pending>>,
    token: &str,
    marks: &mut Vec<ConnectionMark>,
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
            // The compile's bookkeeping is the flight's last leg: hold
            // the mark's guard across it so the unit's waiters release
            // exactly when the store has run, succeeded or not
            // (stow#618).
            let _completion = marks
                .iter()
                .position(|mark| mark.ticket == Some(report.ticket))
                .map(|index| marks.remove(index).completion);
            match handler
                .compiled(pending, report.success, report.stderr)
                .await
            {
                Ok(()) => Answer::Recorded,
                Err(message) => Answer::Failed { message },
            }
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
    use crate::supervisor::protocol::ServedStderr;

    /// A real file for the supervisor's binary identity — any path
    /// `BinaryIdentity::of` can stat answers.
    fn test_executable() -> std::path::PathBuf {
        std::env::current_exe().expect("current exe")
    }

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
            _invocation: crate::unit_cache::InvocationEnv,
        ) -> impl std::future::Future<Output = Decision<Self::Pending>> + Send {
            std::future::ready(if args.first().is_some_and(|arg| arg == "--serve-me") {
                Decision::Served(ServedStderr::default())
            } else {
                Decision::Compile {
                    pending: args.first().cloned().unwrap_or_default(),
                    capture_stderr: false,
                }
            })
        }

        fn compiled(
            self: &Arc<Self>,
            _pending: Self::Pending,
            success: bool,
            _stderr: Option<String>,
        ) -> impl std::future::Future<Output = Result<(), String>> + Send {
            if success {
                self.reports.fetch_add(1, Ordering::SeqCst);
            }
            std::future::ready(Ok(()))
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

        fn rustc_host_target(
            self: &Arc<Self>,
            _executable: &std::ffi::OsStr,
        ) -> impl std::future::Future<Output = Result<String, String>> + Send {
            std::future::ready(Ok("aarch64-apple-darwin".to_owned()))
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
        let supervisor = start(
            Arc::clone(&handler),
            super::InFlightUnits::default(),
            &test_executable(),
        )
        .expect("start the supervisor");
        let [(_, endpoint), (_, token), _] = supervisor.env();
        let endpoint = crate::supervisor::Endpoint::parse(&endpoint).expect("endpoint");

        let mut connection = Connection::open(&endpoint, token)
            .await
            .expect("connect to the supervisor");
        let decision = connection
            .plan(
                std::ffi::OsStr::new("/usr/bin/rustc"),
                &[OsString::from("--crate-name"), OsString::from("serde")],
                &crate::unit_cache::InvocationEnv::current().expect("invocation"),
            )
            .await
            .expect("plan");
        let ClientDecision::Compile(ticket) = decision else {
            panic!("the stub asks for a compile");
        };
        connection
            .report(&ticket, true, None)
            .await
            .expect("report");
        assert_eq!(handler.reports.load(Ordering::SeqCst), 1);
    }

    /// A blocking facade's `AwaitServeMap` exchange on the loopback
    /// `port`: the answer it read, and the instant it read it.
    fn await_serve_map_blocking(port: u16) -> (super::Answer, std::time::Instant) {
        use std::io::{Read as _, Write as _};

        let mut peer = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let request = super::Request::AwaitServeMap(crate::supervisor::protocol::AwaitServeMap {
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
        let answer = serde_json::from_slice(&answer_body).expect("answer frame");
        (answer, std::time::Instant::now())
    }

    /// The serve-map wait rides the loopback transport the Windows
    /// build uses: the handler's word releases the answer, so a facade
    /// blocked on it hears the final map land and nothing else
    /// (stow#347).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_serve_map_wait_answers_when_the_map_is_final() {
        use std::time::{Duration, Instant};

        /// Answers the wait once `ready` turns true, and reports on
        /// `parked` the moment a wait has subscribed to it — the point
        /// from which the answer can only come from the release.
        struct Gated {
            ready: tokio::sync::watch::Receiver<bool>,
            parked: tokio::sync::mpsc::UnboundedSender<()>,
        }
        impl Handler for Gated {
            type Pending = OsString;

            fn plan(
                self: &Arc<Self>,
                _executable: OsString,
                _args: Vec<OsString>,
                _invocation: crate::unit_cache::InvocationEnv,
            ) -> impl std::future::Future<Output = Decision<Self::Pending>> + Send {
                std::future::ready(Decision::Served(ServedStderr::default()))
            }

            fn compiled(
                self: &Arc<Self>,
                _pending: Self::Pending,
                _success: bool,
                _stderr: Option<String>,
            ) -> impl std::future::Future<Output = Result<(), String>> + Send {
                std::future::ready(Ok(()))
            }

            fn observed(
                self: &Arc<Self>,
                _observation: super::Observation,
            ) -> impl std::future::Future<Output = ()> + Send {
                std::future::ready(())
            }

            fn await_serve_map(self: &Arc<Self>) -> impl std::future::Future<Output = ()> + Send {
                let mut ready = self.ready.clone();
                let parked = self.parked.clone();
                async move {
                    if !*ready.borrow() {
                        parked.send(()).expect("report the park");
                        let _ = ready.changed().await;
                    }
                }
            }

            fn rustc_host_target(
                self: &Arc<Self>,
                _executable: &std::ffi::OsStr,
            ) -> impl std::future::Future<Output = Result<String, String>> + Send {
                std::future::ready(Ok("aarch64-apple-darwin".to_owned()))
            }
        }

        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let (parked_tx, mut parked_rx) = tokio::sync::mpsc::unbounded_channel();
        let handler = Arc::new(Gated {
            ready: ready_rx,
            parked: parked_tx,
        });
        let (tickets, ticket_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::task::spawn(super::run_tickets(ticket_rx));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        let token = "the-token".to_owned();
        tokio::task::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept the facade");
            super::serve_connection(
                stream,
                handler,
                tickets,
                token,
                super::InFlightUnits::default(),
                Arc::new(super::Connections::default()),
            )
            .await;
        });

        let (answered_tx, mut answered_rx) = tokio::sync::oneshot::channel();
        let facade = std::thread::spawn(move || {
            answered_tx
                .send(await_serve_map_blocking(port))
                .expect("report answer");
        });

        // The wait reaches the handler and parks on the pending map;
        // from here nothing but the release can answer it.
        tokio::time::timeout(Duration::from_secs(5), parked_rx.recv())
            .await
            .expect("the wait must park on the pending map")
            .expect("the handler reports its park");
        assert!(
            matches!(
                answered_rx.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
            "the wait answered before the final map landed"
        );
        let released = Instant::now();
        ready_tx.send(true).expect("release the map");
        let (answer, answered) = tokio::time::timeout(Duration::from_secs(5), answered_rx)
            .await
            .expect("the wait must answer")
            .expect("the facade reports its answer");
        facade.join().expect("facade thread");
        assert_eq!(answer, super::Answer::ServeMapReady);
        assert!(
            answered >= released,
            "the wait's answer arrived before the map was released"
        );
    }

    /// A served unit never runs rustc, so it never reports.
    #[tokio::test]
    async fn a_served_unit_ends_the_exchange() {
        let handler = Arc::new(Stub {
            reports: AtomicUsize::new(0),
        });
        let supervisor = start(
            Arc::clone(&handler),
            super::InFlightUnits::default(),
            &test_executable(),
        )
        .expect("start the supervisor");
        let [(_, endpoint), (_, token), _] = supervisor.env();
        let endpoint = crate::supervisor::Endpoint::parse(&endpoint).expect("endpoint");

        let mut connection = Connection::open(&endpoint, token)
            .await
            .expect("connect to the supervisor");
        let decision = connection
            .plan(
                std::ffi::OsStr::new("/usr/bin/rustc"),
                &[OsString::from("--serve-me")],
                &crate::unit_cache::InvocationEnv::current().expect("invocation"),
            )
            .await
            .expect("plan");
        assert!(matches!(decision, ClientDecision::Served(_)));
        assert_eq!(handler.reports.load(Ordering::SeqCst), 0);
    }

    /// The token is what protects the loopback listener Windows uses, so a
    /// frame carrying the wrong one is refused rather than answered.
    #[tokio::test]
    async fn a_wrong_token_is_refused() {
        let handler = Arc::new(Stub {
            reports: AtomicUsize::new(0),
        });
        let supervisor = start(handler, super::InFlightUnits::default(), &test_executable())
            .expect("start the supervisor");
        let [(_, endpoint), ..] = supervisor.env();
        let endpoint = crate::supervisor::Endpoint::parse(&endpoint).expect("endpoint");

        let mut connection = Connection::open(&endpoint, "not-the-token".to_owned())
            .await
            .expect("connect to the supervisor");
        let error = connection
            .plan(
                std::ffi::OsStr::new("/usr/bin/rustc"),
                &[],
                &crate::unit_cache::InvocationEnv::current().expect("invocation"),
            )
            .await
            .expect_err("a wrong token must be refused");
        assert!(error.contains("token mismatch"), "{error}");
    }

    /// A handler whose post-compile bookkeeping releases on a signal:
    /// `started` counts reports whose bookkeeping has begun — and
    /// notifies, so a test waits on the event rather than sampling it —
    /// `finished` counts ones whose bookkeeping ran to its end
    /// (stow#618, stow#810).
    struct Bookkeeping {
        release: tokio::sync::watch::Sender<bool>,
        started: tokio::sync::watch::Sender<usize>,
        finished: AtomicUsize,
    }

    impl Bookkeeping {
        /// Bookkeeping held until the test releases it.
        fn held() -> Arc<Self> {
            Arc::new(Self {
                release: tokio::sync::watch::channel(false).0,
                started: tokio::sync::watch::channel(0).0,
                finished: AtomicUsize::new(0),
            })
        }

        /// Resolve once `reports` reports' bookkeeping has begun.
        async fn started(&self, reports: usize) {
            let mut started = self.started.subscribe();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                started.wait_for(|begun| *begun >= reports),
            )
            .await
            .expect("the report's bookkeeping never started")
            .expect("the handler outlives the wait");
        }
    }

    impl Handler for Bookkeeping {
        type Pending = OsString;

        fn plan(
            self: &Arc<Self>,
            _executable: OsString,
            _args: Vec<OsString>,
            _invocation: crate::unit_cache::InvocationEnv,
        ) -> impl std::future::Future<Output = Decision<Self::Pending>> + Send {
            std::future::ready(Decision::Served(ServedStderr::default()))
        }

        fn compiled(
            self: &Arc<Self>,
            _pending: Self::Pending,
            _success: bool,
            _stderr: Option<String>,
        ) -> impl std::future::Future<Output = Result<(), String>> + Send {
            std::future::ready(Ok(()))
        }

        fn observed(
            self: &Arc<Self>,
            observation: super::Observation,
        ) -> impl std::future::Future<Output = ()> + Send {
            let this = Arc::clone(self);
            async move {
                if observation.success.is_none() {
                    return;
                }
                let mut release = this.release.subscribe();
                this.started.send_modify(|begun| *begun += 1);
                while !*release.borrow() {
                    if release.changed().await.is_err() {
                        return;
                    }
                }
                this.finished.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn await_serve_map(self: &Arc<Self>) -> impl std::future::Future<Output = ()> + Send {
            std::future::ready(())
        }

        fn rustc_host_target(
            self: &Arc<Self>,
            _executable: &std::ffi::OsStr,
        ) -> impl std::future::Future<Output = Result<String, String>> + Send {
            std::future::ready(Ok("aarch64-apple-darwin".to_owned()))
        }
    }

    /// Open the raw transport to the supervisor — no client framing: the
    /// test writes its `Observed` frames itself.
    #[cfg(unix)]
    async fn connect_raw(endpoint: &crate::supervisor::Endpoint) -> tokio::net::UnixStream {
        let crate::supervisor::Endpoint::Unix(path) = endpoint else {
            panic!("the unix transport is the only one this platform starts");
        };
        tokio::net::UnixStream::connect(path)
            .await
            .expect("connect to the supervisor")
    }

    /// Open the raw transport to the supervisor — no client framing: the
    /// test writes its `Observed` frames itself.
    #[cfg(not(unix))]
    async fn connect_raw(endpoint: &crate::supervisor::Endpoint) -> tokio::net::TcpStream {
        let crate::supervisor::Endpoint::Loopback(port) = endpoint else {
            panic!("the loopback transport is the only one this platform starts");
        };
        tokio::net::TcpStream::connect(("127.0.0.1", *port))
            .await
            .expect("connect to the supervisor")
    }

    /// Write the one-way post-compile `Observed` frame a facade sends
    /// after its rustc exits.
    async fn send_report<S>(stream: &mut S, token: &str)
    where
        S: tokio::io::AsyncWrite + Unpin + Send,
    {
        use crate::supervisor::protocol::{Observed, Request, write_frame};
        let report = Observed::new(
            token.to_owned(),
            std::ffi::OsStr::new("rustc"),
            &[
                OsString::from("--crate-name"),
                OsString::from("demo"),
                OsString::from("--crate-type"),
                OsString::from("lib"),
            ],
            Some(true),
        );
        write_frame(&mut *stream, &Request::Observed(report))
            .await
            .expect("write the report frame");
    }

    /// Drive the shutdown `drain` until it waits on exactly one
    /// connection — the one whose bookkeeping the test holds, since every
    /// other connection ends at its EOF on its own. The drain publishes
    /// what it still waits on once the accept loop stops and after each
    /// join, so this is the drain's own word that it had every chance to
    /// return and did not; a drain that returns first fails the test
    /// (stow#810).
    async fn drain_until_only_the_held_connection_remains(
        drain: std::pin::Pin<&mut impl std::future::Future<Output = usize>>,
        mut draining: tokio::sync::watch::Receiver<Option<usize>>,
    ) {
        tokio::select! {
            biased;
            abandoned = drain => panic!("shutdown returned {abandoned} early"),
            left = draining.wait_for(|left| *left == Some(1)) => {
                left.expect("the drain's progress");
            }
        }
    }

    /// A connection whose bookkeeping is still running when the
    /// supervisor is stopped is waited for: the store its report was
    /// writing lands before the stop returns — the shape stow#618 lost
    /// when the runtime dropped the task mid-store.
    #[tokio::test]
    async fn shutdown_drains_in_flight_connections() {
        let handler = Bookkeeping::held();
        let mut supervisor = start(
            Arc::clone(&handler),
            super::InFlightUnits::default(),
            &test_executable(),
        )
        .expect("start the supervisor");
        let [(_, endpoint), (_, token), _] = supervisor.env();
        let endpoint = crate::supervisor::Endpoint::parse(&endpoint).expect("endpoint");
        let mut stream = connect_raw(&endpoint).await;
        send_report(&mut stream, &token).await;
        handler.started(1).await;

        let draining = supervisor.connections.draining.subscribe();
        let mut drain = std::pin::pin!(supervisor.shutdown());
        drain_until_only_the_held_connection_remains(drain.as_mut(), draining).await;
        assert_eq!(handler.finished.load(Ordering::SeqCst), 0);
        handler.release.send(true).expect("release the bookkeeping");
        drop(stream);
        assert_eq!(drain.await, 0, "the drain finishes cleanly");
        assert_eq!(handler.finished.load(Ordering::SeqCst), 1);
    }

    /// The drain waits for every connection, not for the first one it
    /// joins: a build's early connections end long before the stop, and
    /// the one still storing is behind them (stow#660).
    #[tokio::test]
    async fn shutdown_drains_past_connections_that_already_finished() {
        let handler = Bookkeeping::held();
        let mut supervisor = start(
            Arc::clone(&handler),
            super::InFlightUnits::default(),
            &test_executable(),
        )
        .expect("start the supervisor");
        let [(_, endpoint), (_, token), _] = supervisor.env();
        let endpoint = crate::supervisor::Endpoint::parse(&endpoint).expect("endpoint");

        // Connections that end without any bookkeeping in flight. Accept
        // is FIFO, so the held report's bookkeeping starting below means
        // all three were accepted ahead of it and sit in the drain's set;
        // each ends at its EOF, so a drain that stopped at its first
        // clean join returns on one of them.
        for _ in 0..3 {
            drop(connect_raw(&endpoint).await);
        }
        let mut stream = connect_raw(&endpoint).await;
        send_report(&mut stream, &token).await;
        handler.started(1).await;

        let draining = supervisor.connections.draining.subscribe();
        let mut drain = std::pin::pin!(supervisor.shutdown());
        drain_until_only_the_held_connection_remains(drain.as_mut(), draining).await;
        assert_eq!(handler.finished.load(Ordering::SeqCst), 0);
        handler.release.send(true).expect("release the bookkeeping");
        drop(stream);
        assert_eq!(drain.await, 0, "the drain finishes cleanly");
        assert_eq!(handler.finished.load(Ordering::SeqCst), 1);
    }

    /// Bookkeeping that outlives the drain bound is abandoned with the
    /// count in the warning, and the stop returns — a hung store must not
    /// hang the build (stow#618).
    #[tokio::test]
    async fn shutdown_abandons_bookkeeping_past_the_budget() {
        let handler = Bookkeeping::held();
        let mut supervisor = start(
            Arc::clone(&handler),
            super::InFlightUnits::default(),
            &test_executable(),
        )
        .expect("start the supervisor");
        let [(_, endpoint), (_, token), _] = supervisor.env();
        let endpoint = crate::supervisor::Endpoint::parse(&endpoint).expect("endpoint");
        let mut stream = connect_raw(&endpoint).await;
        send_report(&mut stream, &token).await;
        handler.started(1).await;

        // The release never comes: the drain must give the connection up.
        let abandoned = supervisor
            .shutdown_within(std::time::Duration::from_millis(100))
            .await;
        assert_eq!(abandoned, 1);
        assert_eq!(handler.finished.load(Ordering::SeqCst), 0);
    }

    /// A dependent waits on its in-flight dependencies one at a time, so
    /// a dependency can finish before the dependent has subscribed to
    /// it. That completion has to be there when the dependent gets to
    /// it: a signal handed to no subscriber was dropped, and the
    /// dependent's post-compile — and the build behind it — waited
    /// forever.
    #[tokio::test]
    async fn a_flight_ending_before_its_waiter_subscribes_still_releases_it() {
        let in_flight = super::InFlightUnits::default();
        let first = in_flight.register(vec!["/deps/libfirst.rlib".to_owned()]);
        let second = in_flight.register(vec!["/deps/libsecond.rlib".to_owned()]);
        let dependent = crate::rustc_args::ParsedRustcArgs::parse(
            &[
                "--crate-name",
                "dependent",
                "--crate-type",
                "lib",
                "--extern",
                "first=/deps/libfirst.rlib",
                "--extern",
                "second=/deps/libsecond.rlib",
                "src/lib.rs",
            ]
            .map(OsString::from),
        )
        .expect("parse the dependent's invocation");
        let waiter = tokio::spawn({
            let in_flight = in_flight.clone();
            async move { in_flight.wait_for_externs(&dependent).await }
        });
        // The waiter parks on `first`, the flight it reaches first; it
        // has not subscribed to `second` yet.
        in_flight.parked_on("/deps/libfirst.rlib", 1).await;
        assert_eq!(
            *second.unit.done.parked.borrow(),
            0,
            "the waiter subscribed to `second` before `first` ended"
        );
        drop(second);
        drop(first);
        tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("the dependent is released once both flights have ended")
            .expect("join the waiter");
    }
}
