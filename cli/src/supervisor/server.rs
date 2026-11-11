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

use super::invocation::{Refusal, RefusalPolicy, VerifiedInvocation};
use super::protocol::{
    Answer, ArtifactNotifications, AwaitServeMap, CcCompiled, CcLookup, Compiled, Observed, Plan,
    Request, read_frame, write_frame,
};
use super::{BINARY_ENV, BinaryIdentity, ENDPOINT_ENV, TOKEN_ENV};
use crate::local_socket::{self, Endpoint};
use crate::toolchain::BuildToolchain;

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
        invocation: VerifiedInvocation,
        env: crate::supervisor::protocol::InvocationEnv,
    ) -> impl Future<Output = Decision<Self::Pending>> + Send;

    /// Finish the work that only exists after a real compile.
    fn compiled(
        self: &Arc<Self>,
        pending: Self::Pending,
        success: bool,
        compile_time: Duration,
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

    /// The toolchain this build compiles with, resolved by the driver
    /// before cargo started: the only source of every rustc fact the
    /// supervisor uses, and what a request's executable is checked
    /// against.
    fn toolchain(self: &Arc<Self>) -> &Arc<BuildToolchain>;

    /// What this build does with a refused request, fixed when the
    /// handler was built.
    fn refusal_policy(self: &Arc<Self>) -> RefusalPolicy;

    /// Record a request the supervisor refused under
    /// [`RefusalPolicy::FailBuild`], so the build fails naming the field
    /// once cargo has exited — a one-way report has no answer to carry
    /// the refusal. Never called under [`RefusalPolicy::CompileUncached`].
    fn refused(self: &Arc<Self>, refusal: Refusal);

    /// The config whose C/C++ object cache and state database answer the
    /// C compiler wrapper — the build's own, so the wrappers never open
    /// the database themselves. `None` — the default — when the handler
    /// has no C/C++ cache to answer from.
    fn cc_config(self: &Arc<Self>) -> Option<&crate::config::StowConfig> {
        None
    }

    /// The build's output roots: the only places a compiler output a
    /// wrapper reports, or an `--out-dir` it names, may live. `None` — the
    /// default — when the handler does not know them, which refuses every
    /// report and every request that names an output directory.
    fn output_roots(self: &Arc<Self>) -> Option<&super::invocation::OutputRoots> {
        None
    }

    /// What the handler needs to remember between asking for a compile and
    /// hearing that it finished. Its default is the pending of a compile
    /// with no bookkeeping: what a refused plan is answered with under
    /// [`RefusalPolicy::CompileUncached`].
    type Pending: Default + Send + 'static;
}

/// A compile the facade already ran — or is about to — without a plan
/// round trip: the mark and the report a unit the serve map ruled out
/// still owes the build.
#[derive(Debug)]
pub struct Observation {
    /// The invocation the facade ran, checked against the build.
    pub invocation: VerifiedInvocation,
    /// `None` marks the unit as compiling locally; `Some` reports how the
    /// finished compile exited.
    pub success: Option<bool>,
    /// How long the finished compile ran; zero on the mark.
    pub compile_time: Duration,
    /// The invocation's environment the supervisor cannot see.
    pub env: crate::supervisor::protocol::InvocationEnv,
}

/// A handler's decision about one invocation.
pub enum Decision<P> {
    /// The outputs are in place; the facade exits 0. The payload is the
    /// artifact-notification lines the facade owes cargo's stderr first
    /// (stow#633).
    Served(ArtifactNotifications),
    /// The facade runs rustc and reports back with `pending` restored.
    Compile(P),
}

/// How long [`Supervisor::shutdown`] waits for accepted connections to run
/// to their end after cargo has exited (stow#618). Every facade has exited
/// by then, so a connection only remains while the bookkeeping its frames
/// queued still runs — sqlite writes and file copies that take
/// milliseconds. The bound exists for the bookkeeping that hangs instead:
/// a wedged store must not hang a build that is already over.
pub(super) const CONNECTION_DRAIN_BUDGET: Duration = Duration::from_secs(30);

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
    let listener = local_socket::bind("stow-supervisor-")?;
    let endpoint = listener.endpoint();

    #[cfg(unix)]
    {
        let local_socket::Listener::Unix {
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
        let local_socket::Listener::Loopback { listener, port } = listener;
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
/// The flight has two legs and the report frame's arrival is the boundary
/// between them. Until the frame arrives rustc is running; the facade
/// exits once the receipt for its report arrives — sent as soon as this
/// latch has fired, before the bookkeeping — so from the frame on only
/// the supervisor's bookkeeping is left, and a dependent cargo starts
/// after the facade's exit always finds the latch fired (stow#1431). A dependent's plan
/// waits for a unit in its second leg — cargo starts a dependent after a
/// proc macro or a build script has fully finished, and that dependent
/// plans against the unit's rows — and never for one in its first, which
/// a pipelined dependent legitimately plans against while it compiles.
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
            exited: crate::Latch::pending(),
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
        self.flight(path).done.parked(waits).await;
    }

    /// The unit in flight under `path`, for a test that observes its
    /// flight directly.
    #[cfg(test)]
    fn flight(&self, path: &str) -> Arc<InFlightUnit> {
        Arc::clone(
            self.units
                .lock()
                .expect("in-flight units mutex")
                .get(path)
                .unwrap_or_else(|| panic!("no unit in flight under {path}")),
        )
    }

    /// The in-flight units one of `parsed`'s `--extern` dependencies could
    /// be, deduplicated, that satisfy `keep`. The paths come from the same
    /// `extern_output_paths` derivation the identity resolution uses, so
    /// the set covers exactly the units whose `materialized_outputs` rows
    /// it reads (stow#618).
    fn externs_in_flight(
        &self,
        parsed: &ParsedRustcArgs,
        keep: impl Fn(&InFlightUnit) -> bool,
    ) -> Vec<Arc<InFlightUnit>> {
        let externs = crate::artifact_cache::extern_output_paths(parsed).unwrap_or_default();
        let units = self.units.lock().expect("in-flight units mutex");
        // One unit registers several paths and a dependent can name
        // more than one of them — dedupe on the unit itself.
        let mut seen = HashSet::new();
        externs
            .iter()
            .filter_map(|(_, path)| units.get(path))
            .filter(|unit| keep(unit))
            .filter(|unit| seen.insert(Arc::as_ptr(unit)))
            .cloned()
            .collect()
    }

    /// Wait for the bookkeeping of every in-flight unit one of `parsed`'s
    /// `--extern` dependencies could be, whichever leg it is in: the
    /// dependent's post-compile reads their rows once its own rustc has
    /// finished (stow#618).
    pub async fn wait_for_externs(&self, parsed: &ParsedRustcArgs) {
        for unit in self.externs_in_flight(parsed, |_| true) {
            unit.wait().await;
        }
    }

    /// Wait for the bookkeeping of every in-flight unit one of `parsed`'s
    /// `--extern` dependencies could be whose rustc has exited — the
    /// units whose rows are about to land. A dependency still compiling
    /// is not waited for: nothing recorded it yet and nothing will until
    /// it exits, so a pipelined dependent plans against it as it always
    /// did (stow#1431).
    pub async fn wait_for_exited_externs(&self, parsed: &ParsedRustcArgs) {
        for unit in self.externs_in_flight(parsed, |unit| unit.exited.has_completed()) {
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
        // latch stores the end either way (stow#642). A flight that ends
        // without a report ends its first leg with it.
        unit.exited.complete();
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
    /// Fired when the report frame arrives: rustc has exited and only the
    /// supervisor's bookkeeping is left (stow#1431).
    exited: crate::Latch,
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

impl Completion {
    /// The report frame arrived: rustc has exited, the flight's second
    /// leg — the bookkeeping — begins (stow#1431).
    fn rustc_exited(&self) {
        self.unit.exited.complete();
    }
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
        let reply =
            answer_request(&handler, &tickets, &token, &in_flight, &mut marks, request).await;
        let answered = match reply.answer {
            Some(answer) => write_frame(&mut stream, &answer).await,
            None => Ok(()),
        };
        // The receipt is out: the bookkeeping runs now, whether or not
        // the facade is still there to hear anything more (stow#1431).
        if let Some(work) = reply.work {
            finish_report(&handler, work).await;
        }
        if let Err(error) = answered {
            tracing::warn!(%error, "supervisor could not answer a facade");
            break;
        }
    }
}

/// What a request earns: the answer the facade reads, if it reads one,
/// and the bookkeeping the answer precedes.
pub struct Reply<P> {
    answer: Option<Answer>,
    /// The post-compile bookkeeping of a report, to run once the answer
    /// is out — the facade's wait ends at the receipt, never at this.
    work: Option<ReportWork<P>>,
}

impl<P> Reply<P> {
    const fn answer(answer: Answer) -> Self {
        Self {
            answer: Some(answer),
            work: None,
        }
    }

    fn failed(message: impl Into<String>) -> Self {
        Self::answer(Answer::Failed {
            message: message.into(),
        })
    }

    const fn nothing() -> Self {
        Self {
            answer: None,
            work: None,
        }
    }

    /// The answer to write and the bookkeeping to run after it, for a
    /// transport that schedules the two itself.
    pub fn split(self) -> (Option<Answer>, Option<ReportWork<P>>) {
        (self.answer, self.work)
    }
}

/// A report's post-compile bookkeeping, with the guard that ends the
/// unit's flight: dropping it — when the bookkeeping ends, or unrun —
/// completes the unit (stow#618).
pub struct ReportWork<P> {
    completion: Option<Completion>,
    kind: ReportKind<P>,
}

enum ReportKind<P> {
    /// A `Compiled` report with its restored ticket.
    Compiled {
        pending: P,
        success: bool,
        compile_time: Duration,
    },
    /// An `Observed` report of the finished compile.
    Observed(Observation),
    /// The records a C compiler wrapper's answer precedes.
    Cc(crate::cc::CcRecord),
}

/// Run a report's bookkeeping; the flight ends when it does, succeeded
/// or not.
pub async fn finish_report<H: Handler>(handler: &Arc<H>, work: ReportWork<H::Pending>) {
    let ReportWork { completion, kind } = work;
    match kind {
        ReportKind::Compiled {
            pending,
            success,
            compile_time,
        } => handler.compiled(pending, success, compile_time).await,
        ReportKind::Observed(observation) => handler.observed(observation).await,
        ReportKind::Cc(record) => {
            if let Some(config) = handler.cc_config() {
                crate::cc::write_record(config, record).await;
            }
        }
    }
    drop(completion);
}

/// Answer the request. A report is answered with a receipt as soon as the
/// unit's `exited` latch has fired — before any bookkeeping is awaited,
/// which the reply carries for the transport to run after the answer is
/// out (stow#1431). A mark is one-way: the facade reads nothing for it.
pub async fn answer_request<H: Handler>(
    handler: &Arc<H>,
    tickets: &mpsc::UnboundedSender<Ticket<H::Pending>>,
    token: &str,
    in_flight: &InFlightUnits,
    marks: &mut Vec<ConnectionMark>,
    request: Request,
) -> Reply<H::Pending> {
    match request {
        Request::Plan(plan) => {
            Reply::answer(answer_plan(handler, tickets, token, in_flight, marks, plan).await)
        }
        Request::Compiled(report) => accept_report(tickets, token, marks, report).await,
        Request::Observed(observed) => {
            answer_observation(handler, token, in_flight, marks, observed).await
        }
        Request::AwaitServeMap(await_map) => {
            Reply::answer(answer_await_serve_map(handler, token, await_map).await)
        }
        Request::CcLookup(lookup) => answer_cc_lookup(handler, token, lookup).await,
        Request::CcCompiled(report) => answer_cc_compiled(handler, token, report).await,
    }
}

/// Look the object up in the build's C/C++ cache. A hit is answered at
/// once — the wrapper clones the object while the LRU stamp and the hit
/// statistic are written after the answer, like a rustc report's
/// bookkeeping (stow#1431).
async fn answer_cc_lookup<H: Handler>(
    handler: &Arc<H>,
    token: &str,
    lookup: CcLookup,
) -> Reply<H::Pending> {
    if lookup.token != token {
        return Reply::failed("supervisor token mismatch");
    }
    let Some(config) = handler.cc_config() else {
        return Reply::failed("the build has no config for the C/C++ cache");
    };
    if !config.cache.uses_cc_cache() {
        return Reply::failed("the C/C++ cache layer is off for this build");
    }
    if !crate::cc::is_cache_key(&lookup.cache_key) {
        return Reply::failed("malformed C/C++ cache key");
    }
    match crate::cc::locate_cached_object(config, &lookup.cache_key).await {
        Ok(Some(object)) => Reply {
            answer: Some(Answer::CcHit {
                object: super::os_bytes::encode(object.as_os_str()),
            }),
            work: Some(ReportWork {
                completion: None,
                kind: ReportKind::Cc(crate::cc::CcRecord::Hit {
                    cache_key: lookup.cache_key,
                }),
            }),
        },
        Ok(None) => Reply::answer(Answer::CcMiss),
        Err(error) => Reply::failed(format!("C/C++ cache lookup failed: {error}")),
    }
}

/// Accept the report of a C compile a miss sent the wrapper to run. The
/// object is snapshotted into the cache directory before the receipt —
/// the wrapper's output file may be rewritten as soon as the compiler's
/// caller moves on — and the publish, the LRU row, the eviction pass and
/// the statistic follow it.
async fn answer_cc_compiled<H: Handler>(
    handler: &Arc<H>,
    token: &str,
    report: CcCompiled,
) -> Reply<H::Pending> {
    if report.token != token {
        return Reply::failed("supervisor token mismatch");
    }
    let Some(config) = handler.cc_config() else {
        return Reply::failed("the build has no config for the C/C++ cache");
    };
    if !crate::cc::is_cache_key(&report.cache_key) {
        return Reply::failed("malformed C/C++ cache key");
    }
    let output_path = match report.output_path() {
        Ok(path) => path,
        Err(error) => return Reply::failed(error),
    };
    let record = if report.success {
        // The path is the wrapper's word and this process is not
        // sandboxed: the file is opened and checked as one descriptor,
        // and staged from it, so a refused path is never read.
        let Some(roots) = handler.output_roots().map(|roots| roots.dirs().to_vec()) else {
            return refuse_cc_output(&output_path, "the build's target directory is unknown");
        };
        let opened = {
            let output_path = output_path.clone();
            smol::unblock(move || crate::cc::open_reported_output(&output_path, &roots)).await
        };
        let source = match opened {
            Ok(source) => source,
            Err(message) => return refuse_cc_output(&output_path, &message),
        };
        let cache_path = crate::cc::cached_object_path(config, &report.cache_key);
        let staged = match crate::cc::stage_opened_object(&cache_path, source, &output_path).await {
            Ok(staged) => Some(staged),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    cache_key = %report.cache_key,
                    output_path = %output_path.display(),
                    "failed to stage C/C++ compilation for the local stow cache"
                );
                None
            }
        };
        crate::cc::CcRecord::Compiled {
            cache_key: report.cache_key,
            staged,
        }
    } else {
        crate::cc::CcRecord::Failed {
            cache_key: report.cache_key,
        }
    };
    Reply {
        answer: Some(Answer::Received),
        work: Some(ReportWork {
            completion: None,
            kind: ReportKind::Cc(record),
        }),
    }
}

/// Refuse a reported C/C++ output: logged, answered `Failed`, nothing
/// staged. `message` already names the path unless the refusal is about
/// the build, so the path is named here too.
fn refuse_cc_output<P>(output_path: &std::path::Path, message: &str) -> Reply<P> {
    tracing::warn!(output_path = %output_path.display(), reason = %message, "refused a reported C/C++ output");
    Reply::failed(format!(
        "refused the C/C++ output {}: {message}",
        output_path.display()
    ))
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
    let (executable, args) = match (plan.executable(), plan.args()) {
        (Ok(executable), Ok(args)) => (executable, args),
        (Err(error), _) | (_, Err(error)) => {
            return Answer::Failed { message: error };
        }
    };
    let invocation = match VerifiedInvocation::verify(
        handler.toolchain(),
        handler.output_roots(),
        executable,
        args,
        &plan.env,
    )
    .await
    {
        Ok(invocation) => invocation,
        Err(refusal) => {
            return match settle_refusal(handler, refusal, "plan request") {
                Settled::Fail(message) => Answer::Failed { message },
                // The facade compiles and reports back: the report finds
                // a pending that does no bookkeeping, and no mark is
                // registered for a unit nothing recorded.
                Settled::CompileUncached => {
                    match allocate_ticket(tickets, H::Pending::default()).await {
                        Ok(ticket) => Answer::Compile { ticket },
                        Err(failed) => failed,
                    }
                }
            };
        }
    };
    // The build's host names the unit's recordable outputs; an
    // invocation the parser cannot model records nothing (stow#618).
    let recordable_paths = ParsedRustcArgs::parse(invocation.args())
        .ok()
        .and_then(|parsed| recordable_output_paths(&parsed, handler.toolchain().host_target()));
    match handler.plan(invocation, plan.env).await {
        Decision::Served(notifications) => Answer::Served(notifications),
        Decision::Compile(pending) => match allocate_ticket(tickets, pending).await {
            Ok(ticket) => {
                // The facade was told to compile: the unit is in
                // flight until the `Compiled` report's bookkeeping —
                // or this connection's end — completes it (stow#618).
                if let Some(paths) = recordable_paths {
                    marks.push(ConnectionMark {
                        ticket: Some(ticket),
                        completion: in_flight.register(paths),
                    });
                }
                Answer::Compile { ticket }
            }
            Err(failed) => failed,
        },
    }
}

/// What a refused request earns, decided in one place by the handler's
/// [`RefusalPolicy`].
enum Settled {
    /// Answer the request with this failure.
    Fail(String),
    /// Take no cache action: compile uncached, or drop a one-way frame.
    CompileUncached,
}

/// The one place a refusal is acted on: logged once at `warn` naming the
/// field and reason, then either recorded for the build to fail on or
/// left with no effect at all, per the handler's policy.
fn settle_refusal<H: Handler>(handler: &Arc<H>, refusal: Refusal, request: &str) -> Settled {
    let message = refusal.to_string();
    tracing::warn!(%message, "refused a {request}");
    match handler.refusal_policy() {
        RefusalPolicy::FailBuild => {
            handler.refused(refusal);
            Settled::Fail(message)
        }
        RefusalPolicy::CompileUncached => Settled::CompileUncached,
    }
}

/// Hand `pending` to the ticket task and return the ticket the facade's
/// report carries back, or the failure answer when the task is gone.
async fn allocate_ticket<P>(
    tickets: &mpsc::UnboundedSender<Ticket<P>>,
    pending: P,
) -> Result<u64, Answer> {
    let (sender, allocated) = oneshot::channel();
    if tickets.send(Ticket::Allocate(pending, sender)).is_err() {
        return Err(Answer::Failed {
            message: "supervisor ticket task is gone".to_owned(),
        });
    }
    allocated.await.map_err(|_| Answer::Failed {
        message: "supervisor ticket task dropped the allocation".to_owned(),
    })
}

async fn answer_observation<H: Handler>(
    handler: &Arc<H>,
    token: &str,
    in_flight: &InFlightUnits,
    marks: &mut Vec<ConnectionMark>,
    observed: Observed,
) -> Reply<H::Pending> {
    // Only the report is answered, so only the report's refusal is: the
    // mark's facade reads nothing, and its refusal is logged.
    let is_report = observed.success.is_some();
    if observed.token != token {
        if is_report {
            return Reply::failed("supervisor token mismatch");
        }
        tracing::warn!("supervisor observation with the wrong token dropped");
        return Reply::nothing();
    }
    let (Ok(executable), Ok(args)) = (observed.executable(), observed.args()) else {
        if is_report {
            return Reply::failed("supervisor report could not be decoded");
        }
        tracing::warn!("supervisor observation could not be decoded; dropped");
        return Reply::nothing();
    };
    let invocation = match VerifiedInvocation::verify(
        handler.toolchain(),
        handler.output_roots(),
        executable,
        args,
        &observed.env,
    )
    .await
    {
        Ok(invocation) => invocation,
        Err(refusal) => {
            // A report is answered with the refusal and a mark has no
            // answer, so the handler records it for the build to fail on
            // after cargo exits. Compiling uncached, the report gets the
            // receipt its facade waits for, with no bookkeeping behind
            // it, and the mark is dropped. Neither touches `marks`: the
            // refused request has no flight of its own.
            return match settle_refusal(handler, refusal, "observation") {
                Settled::Fail(message) if is_report => Reply::failed(message),
                Settled::CompileUncached if is_report => Reply::answer(Answer::Received),
                Settled::Fail(_) | Settled::CompileUncached => Reply::nothing(),
            };
        }
    };
    let observation = Observation {
        invocation,
        success: observed.success,
        compile_time: Duration::from_millis(observed.compile_millis),
        env: observed.env,
    };
    if is_report {
        // The report frame ends the flight's first leg: rustc has exited.
        // The mark's guard rides with the bookkeeping, so the unit's
        // waiters release exactly when it has run, including every early
        // return and error inside it (stow#618, stow#1431).
        let completion = marks
            .iter()
            .position(|mark| mark.ticket.is_none())
            .map(|index| marks.remove(index).completion)
            .inspect(Completion::rustc_exited);
        return Reply {
            answer: Some(Answer::Received),
            work: Some(ReportWork {
                completion,
                kind: ReportKind::Observed(observation),
            }),
        };
    }
    // The flight spans the mark frame's arrival to its report's
    // bookkeeping: registered here, before rustc starts (stow#618).
    if let Ok(parsed) = ParsedRustcArgs::parse(observation.invocation.args())
        && let Some(paths) = recordable_output_paths(&parsed, handler.toolchain().host_target())
    {
        marks.push(ConnectionMark {
            ticket: None,
            completion: in_flight.register(paths),
        });
    }
    handler.observed(observation).await;
    Reply::nothing()
}

/// Accept the report of a compile the supervisor asked for: fire the
/// unit's `exited` latch and answer with a receipt, carrying the
/// bookkeeping for the transport to run after it (stow#1431). A report
/// the supervisor cannot use is refused — the facade is listening for
/// the receipt.
async fn accept_report<P>(
    tickets: &mpsc::UnboundedSender<Ticket<P>>,
    token: &str,
    marks: &mut Vec<ConnectionMark>,
    report: Compiled,
) -> Reply<P> {
    if report.token != token {
        return Reply::failed("supervisor token mismatch");
    }
    // The mark's guard is taken before anything awaits: a refusal below
    // drops it and ends the flight, and an accepted report hands it to
    // the bookkeeping (stow#618).
    let completion = marks
        .iter()
        .position(|mark| mark.ticket == Some(report.ticket))
        .map(|index| marks.remove(index).completion)
        .inspect(Completion::rustc_exited);
    let (sender, restored) = oneshot::channel();
    if tickets.send(Ticket::Take(report.ticket, sender)).is_err() {
        return Reply::failed("supervisor ticket task is gone");
    }
    match restored.await {
        Ok(Some(pending)) => Reply {
            answer: Some(Answer::Received),
            work: Some(ReportWork {
                completion,
                kind: ReportKind::Compiled {
                    pending,
                    success: report.success,
                    compile_time: Duration::from_millis(report.compile_millis),
                },
            }),
        },
        Ok(None) => Reply::failed(format!(
            "supervisor has no record of compile {}",
            report.ticket
        )),
        Err(_) => Reply::failed("supervisor ticket task dropped the lookup"),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::{
        BuildToolchain, Decision, Handler, Refusal, RefusalPolicy, VerifiedInvocation, start,
    };
    use crate::supervisor::client::{Connection, Decision as ClientDecision};
    use crate::supervisor::protocol::ArtifactNotifications;

    /// A real file for the supervisor's binary identity — any path
    /// `BinaryIdentity::of` can stat answers.
    fn test_executable() -> std::path::PathBuf {
        std::env::current_exe().expect("current exe")
    }

    /// Output roots that contain every path: the fixtures name an
    /// `--out-dir` that is no real build's.
    fn everywhere() -> crate::supervisor::invocation::OutputRoots {
        crate::supervisor::invocation::OutputRoots::new(
            std::path::PathBuf::from(std::path::MAIN_SEPARATOR_STR),
            None,
        )
    }

    /// Serves anything whose first argument is `--serve-me`, asks for a
    /// compile otherwise, and counts the reports it receives.
    struct Stub {
        reports: AtomicUsize,
        roots: crate::supervisor::invocation::OutputRoots,
        /// Every call that reached the handler's own decision or
        /// bookkeeping: what a refused request must not add to.
        plans: AtomicUsize,
        observations: AtomicUsize,
        policy: RefusalPolicy,
        toolchain: Arc<BuildToolchain>,
        refusals: std::sync::Mutex<Vec<String>>,
    }

    impl Stub {
        async fn new() -> Arc<Self> {
            Self::with_policy(RefusalPolicy::FailBuild).await
        }

        async fn with_policy(policy: RefusalPolicy) -> Arc<Self> {
            Arc::new(Self {
                reports: AtomicUsize::new(0),
                roots: everywhere(),
                plans: AtomicUsize::new(0),
                observations: AtomicUsize::new(0),
                policy,
                toolchain: BuildToolchain::for_tests().await,
                refusals: std::sync::Mutex::default(),
            })
        }
    }

    impl Handler for Stub {
        type Pending = OsString;

        fn plan(
            self: &Arc<Self>,
            invocation: VerifiedInvocation,
            _env: crate::supervisor::protocol::InvocationEnv,
        ) -> impl std::future::Future<Output = Decision<Self::Pending>> + Send {
            self.plans.fetch_add(1, Ordering::SeqCst);
            let args = invocation.into_args();
            std::future::ready(if args.first().is_some_and(|arg| arg == "--serve-me") {
                Decision::Served(ArtifactNotifications::default())
            } else {
                Decision::Compile(args.first().cloned().unwrap_or_default())
            })
        }

        fn compiled(
            self: &Arc<Self>,
            _pending: Self::Pending,
            success: bool,
            _compile_time: Duration,
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
            self.observations.fetch_add(1, Ordering::SeqCst);
            std::future::ready(())
        }

        fn await_serve_map(self: &Arc<Self>) -> impl std::future::Future<Output = ()> + Send {
            std::future::ready(())
        }

        fn toolchain(self: &Arc<Self>) -> &Arc<BuildToolchain> {
            &self.toolchain
        }

        fn refusal_policy(self: &Arc<Self>) -> RefusalPolicy {
            self.policy
        }

        fn output_roots(self: &Arc<Self>) -> Option<&crate::supervisor::invocation::OutputRoots> {
            Some(&self.roots)
        }

        fn refused(self: &Arc<Self>, refusal: Refusal) {
            self.refusals
                .lock()
                .expect("refusals mutex")
                .push(refusal.to_string());
        }
    }

    /// The whole exchange a facade makes: ask, be told to compile, run
    /// the compile, report it for a receipt and close. The bookkeeping
    /// is applied after the receipt, so the assertion reads it once the
    /// shutdown drain has run. This is the assertion that fails if either
    /// side of the wire changes without the other.
    #[tokio::test]
    async fn a_facade_plans_and_reports_over_the_wire() {
        let handler = Stub::new().await;
        let mut supervisor = start(
            Arc::clone(&handler),
            super::InFlightUnits::default(),
            &test_executable(),
        )
        .expect("start the supervisor");
        let [(_, endpoint), (_, token), _] = supervisor.env();
        let endpoint = crate::local_socket::Endpoint::parse(&endpoint).expect("endpoint");

        let mut connection = Connection::open(&endpoint, token)
            .await
            .expect("connect to the supervisor");
        let decision = connection
            .plan(
                std::ffi::OsStr::new("rustc"),
                &[OsString::from("--crate-name"), OsString::from("serde")],
            )
            .await
            .expect("plan");
        let ClientDecision::Compile(ticket) = decision else {
            panic!("the stub asks for a compile");
        };
        connection
            .report(&ticket, true, Duration::ZERO)
            .await
            .expect("report");
        connection.close().await.expect("close");
        assert_eq!(supervisor.shutdown().await, 0, "the drain finishes cleanly");
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

    /// Answers the serve-map wait once `ready` turns true, and reports on
    /// `parked` the moment a wait has subscribed to it — the point from
    /// which the answer can only come from the release.
    struct Gated {
        ready: tokio::sync::watch::Receiver<bool>,
        parked: tokio::sync::mpsc::UnboundedSender<()>,
        toolchain: Arc<BuildToolchain>,
        roots: crate::supervisor::invocation::OutputRoots,
    }

    impl Handler for Gated {
        type Pending = OsString;

        fn plan(
            self: &Arc<Self>,
            _invocation: VerifiedInvocation,
            _env: crate::supervisor::protocol::InvocationEnv,
        ) -> impl std::future::Future<Output = Decision<Self::Pending>> + Send {
            std::future::ready(Decision::Served(ArtifactNotifications::default()))
        }

        fn compiled(
            self: &Arc<Self>,
            _pending: Self::Pending,
            _success: bool,
            _compile_time: Duration,
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
            let parked = self.parked.clone();
            async move {
                if !*ready.borrow() {
                    parked.send(()).expect("report the park");
                    let _ = ready.changed().await;
                }
            }
        }

        fn toolchain(self: &Arc<Self>) -> &Arc<BuildToolchain> {
            &self.toolchain
        }

        fn refusal_policy(self: &Arc<Self>) -> RefusalPolicy {
            RefusalPolicy::FailBuild
        }

        fn refused(self: &Arc<Self>, _refusal: Refusal) {}

        fn output_roots(self: &Arc<Self>) -> Option<&crate::supervisor::invocation::OutputRoots> {
            Some(&self.roots)
        }
    }

    /// The serve-map wait rides the loopback transport the Windows
    /// build uses: the handler's word releases the answer, so a facade
    /// blocked on it hears the final map land and nothing else
    /// (stow#347).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_serve_map_wait_answers_when_the_map_is_final() {
        use std::time::Instant;

        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let (parked_tx, mut parked_rx) = tokio::sync::mpsc::unbounded_channel();
        let handler = Arc::new(Gated {
            ready: ready_rx,
            parked: parked_tx,
            toolchain: BuildToolchain::for_tests().await,
            roots: everywhere(),
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
        let handler = Stub::new().await;
        let supervisor = start(
            Arc::clone(&handler),
            super::InFlightUnits::default(),
            &test_executable(),
        )
        .expect("start the supervisor");
        let [(_, endpoint), (_, token), _] = supervisor.env();
        let endpoint = crate::local_socket::Endpoint::parse(&endpoint).expect("endpoint");

        let mut connection = Connection::open(&endpoint, token)
            .await
            .expect("connect to the supervisor");
        let decision = connection
            .plan(
                std::ffi::OsStr::new("rustc"),
                &[OsString::from("--serve-me")],
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
        let handler = Stub::new().await;
        let supervisor = start(handler, super::InFlightUnits::default(), &test_executable())
            .expect("start the supervisor");
        let [(_, endpoint), ..] = supervisor.env();
        let endpoint = crate::local_socket::Endpoint::parse(&endpoint).expect("endpoint");

        let mut connection = Connection::open(&endpoint, "not-the-token".to_owned())
            .await
            .expect("connect to the supervisor");
        let error = connection
            .plan(std::ffi::OsStr::new("rustc"), &[])
            .await
            .expect_err("a wrong token must be refused");
        assert!(error.contains("token mismatch"), "{error}");
    }

    /// A request naming a program that is not the build's rustc is
    /// refused naming the field on every path that carries an
    /// executable — the request/answer plan, and the one-way mark and
    /// the answered report of an observation — and the program is never
    /// started: the tripwire would leave its sentinel behind.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_request_naming_another_executable_is_refused_and_never_run() {
        use std::os::unix::fs::PermissionsExt as _;

        use crate::supervisor::protocol::{Answer, InvocationEnv, Observed, Request};

        let dir = tempfile::tempdir().expect("tempdir");
        let sentinel = dir.path().join("ran");
        let other = dir.path().join("rustc");
        std::fs::write(
            &other,
            format!("#!/bin/sh\ntouch '{}'\n", sentinel.display()),
        )
        .expect("write the tripwire");
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o755))
            .expect("chmod the tripwire");

        let handler = Stub::new().await;
        let mut supervisor = start(
            Arc::clone(&handler),
            super::InFlightUnits::default(),
            &test_executable(),
        )
        .expect("start the supervisor");
        let [(_, endpoint), (_, token), _] = supervisor.env();
        let endpoint = crate::local_socket::Endpoint::parse(&endpoint).expect("endpoint");

        let mut connection = Connection::open(&endpoint, token.clone())
            .await
            .expect("connect to the supervisor");
        let error = connection
            .plan(other.as_os_str(), &[])
            .await
            .expect_err("a plan naming another executable is refused");
        assert!(error.contains("executable"), "{error}");

        let mut stream = connect_raw(&endpoint).await;
        let observed = |success| {
            Request::Observed(Observed::new(
                token.clone(),
                other.as_os_str(),
                &[],
                success,
                0,
                InvocationEnv::for_tests(),
            ))
        };
        super::write_frame(&mut stream, &observed(None))
            .await
            .expect("write the mark");
        super::write_frame(&mut stream, &observed(Some(true)))
            .await
            .expect("write the report");
        let Some(Answer::Failed { message }) = super::read_frame(&mut stream)
            .await
            .expect("read the report's answer")
        else {
            panic!("a report naming another executable is answered with a failure");
        };
        assert!(message.contains("executable"), "{message}");

        assert!(!sentinel.exists(), "the refused program was started");
        assert_eq!(
            handler.refusals.lock().expect("refusals mutex").len(),
            3,
            "the plan, the mark and the report are each recorded"
        );
        drop(stream);
        drop(connection);
        supervisor.shutdown().await;
    }

    /// Under `CompileUncached` a refused request takes no cache action
    /// on any path: the plan is answered with a compile whose report
    /// carries no bookkeeping, the mark is dropped and the report is
    /// received — and the program is never started, the handler never
    /// asked to decide or record, and no refusal is left to fail the
    /// build on.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_refused_request_compiles_uncached_and_takes_no_cache_action() {
        use std::os::unix::fs::PermissionsExt as _;

        use crate::supervisor::protocol::{Answer, InvocationEnv, Observed, Request};

        let dir = tempfile::tempdir().expect("tempdir");
        let sentinel = dir.path().join("ran");
        let other = dir.path().join("rustc");
        std::fs::write(
            &other,
            format!("#!/bin/sh\ntouch '{}'\n", sentinel.display()),
        )
        .expect("write the tripwire");
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o755))
            .expect("chmod the tripwire");

        let handler = Stub::with_policy(RefusalPolicy::CompileUncached).await;
        let mut supervisor = start(
            Arc::clone(&handler),
            super::InFlightUnits::default(),
            &test_executable(),
        )
        .expect("start the supervisor");
        let [(_, endpoint), (_, token), _] = supervisor.env();
        let endpoint = crate::local_socket::Endpoint::parse(&endpoint).expect("endpoint");

        // The plan: told to compile, and the report that follows is
        // received.
        let mut connection = Connection::open(&endpoint, token.clone())
            .await
            .expect("connect to the supervisor");
        let decision = connection
            .plan(other.as_os_str(), &[])
            .await
            .expect("a refused plan is answered with a compile");
        let ClientDecision::Compile(ticket) = decision else {
            panic!("a refused plan is answered with a compile, never served");
        };
        connection
            .report(&ticket, true, Duration::ZERO)
            .await
            .expect("the compile's report is received");
        connection.close().await.expect("close");

        // The one-way mark is dropped and the report is received.
        let mut stream = connect_raw(&endpoint).await;
        let observed = |success| {
            Request::Observed(Observed::new(
                token.clone(),
                other.as_os_str(),
                &[],
                success,
                0,
                InvocationEnv::for_tests(),
            ))
        };
        super::write_frame(&mut stream, &observed(None))
            .await
            .expect("write the mark");
        super::write_frame(&mut stream, &observed(Some(true)))
            .await
            .expect("write the report");
        let answer: Option<Answer> = super::read_frame(&mut stream)
            .await
            .expect("read the report's answer");
        assert!(
            matches!(answer, Some(Answer::Received)),
            "a refused report is received: {answer:?}"
        );
        drop(stream);
        assert_eq!(supervisor.shutdown().await, 0, "the drain finishes cleanly");

        assert!(!sentinel.exists(), "the refused program was started");
        assert_eq!(
            handler.plans.load(Ordering::SeqCst),
            0,
            "nothing was planned"
        );
        assert_eq!(
            handler.observations.load(Ordering::SeqCst),
            0,
            "nothing was observed"
        );
        assert!(
            handler.refusals.lock().expect("refusals mutex").is_empty(),
            "nothing is left to fail the build on"
        );
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
        toolchain: Arc<BuildToolchain>,
        roots: crate::supervisor::invocation::OutputRoots,
    }

    impl Bookkeeping {
        /// Bookkeeping held until the test releases it.
        async fn held() -> Arc<Self> {
            Arc::new(Self {
                release: tokio::sync::watch::channel(false).0,
                started: tokio::sync::watch::channel(0).0,
                finished: AtomicUsize::new(0),
                toolchain: BuildToolchain::for_tests().await,
                roots: everywhere(),
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
            _invocation: VerifiedInvocation,
            _env: crate::supervisor::protocol::InvocationEnv,
        ) -> impl std::future::Future<Output = Decision<Self::Pending>> + Send {
            std::future::ready(Decision::Compile(OsString::new()))
        }

        fn compiled(
            self: &Arc<Self>,
            _pending: Self::Pending,
            _success: bool,
            _compile_time: Duration,
        ) -> impl std::future::Future<Output = ()> + Send {
            let this = Arc::clone(self);
            async move {
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

        fn observed(
            self: &Arc<Self>,
            _observation: super::Observation,
        ) -> impl std::future::Future<Output = ()> + Send {
            std::future::ready(())
        }

        fn await_serve_map(self: &Arc<Self>) -> impl std::future::Future<Output = ()> + Send {
            std::future::ready(())
        }

        fn toolchain(self: &Arc<Self>) -> &Arc<BuildToolchain> {
            &self.toolchain
        }

        fn refusal_policy(self: &Arc<Self>) -> RefusalPolicy {
            RefusalPolicy::FailBuild
        }

        fn refused(self: &Arc<Self>, _refusal: Refusal) {}

        fn output_roots(self: &Arc<Self>) -> Option<&crate::supervisor::invocation::OutputRoots> {
            Some(&self.roots)
        }
    }

    /// Open the raw transport to the supervisor — no client framing: the
    /// test writes its frames itself.
    #[cfg(unix)]
    async fn connect_raw(endpoint: &crate::local_socket::Endpoint) -> tokio::net::UnixStream {
        let crate::local_socket::Endpoint::Unix(path) = endpoint else {
            panic!("the unix transport is the only one this platform starts");
        };
        tokio::net::UnixStream::connect(path)
            .await
            .expect("connect to the supervisor")
    }

    /// Open the raw transport to the supervisor — no client framing: the
    /// test writes its frames itself.
    #[cfg(not(unix))]
    async fn connect_raw(endpoint: &crate::local_socket::Endpoint) -> tokio::net::TcpStream {
        let crate::local_socket::Endpoint::Loopback(port) = endpoint else {
            panic!("the loopback transport is the only one this platform starts");
        };
        tokio::net::TcpStream::connect(("127.0.0.1", *port))
            .await
            .expect("connect to the supervisor")
    }

    /// What a facade does around its rustc: plan the invocation, hear
    /// `Compile`, and — once rustc has exited — write the `Compiled`
    /// report and read its receipt. Returns after the receipt, not after
    /// the bookkeeping is applied.
    async fn plan_and_report<S>(stream: &mut S, token: &str)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        use crate::supervisor::protocol::{
            Answer, Compiled, InvocationEnv, Plan, Request, read_frame, write_frame,
        };
        let plan = Plan::new(
            token.to_owned(),
            std::ffi::OsStr::new("rustc"),
            &[
                OsString::from("--crate-name"),
                OsString::from("demo"),
                OsString::from("--crate-type"),
                OsString::from("lib"),
            ],
            InvocationEnv::for_tests(),
        );
        write_frame(&mut *stream, &Request::Plan(plan))
            .await
            .expect("write the plan frame");
        let Some(Answer::Compile { ticket }) = read_frame(&mut *stream)
            .await
            .expect("read the plan's answer")
        else {
            panic!("the handler asks for a compile");
        };
        let report = Compiled {
            token: token.to_owned(),
            ticket,
            success: true,
            compile_millis: 0,
        };
        write_frame(&mut *stream, &Request::Compiled(report))
            .await
            .expect("write the report frame");
        let receipt: Option<Answer> = read_frame(&mut *stream)
            .await
            .expect("read the report's receipt");
        assert_eq!(receipt, Some(Answer::Received));
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
        let handler = Bookkeeping::held().await;
        let mut supervisor = start(
            Arc::clone(&handler),
            super::InFlightUnits::default(),
            &test_executable(),
        )
        .expect("start the supervisor");
        let [(_, endpoint), (_, token), _] = supervisor.env();
        let endpoint = crate::local_socket::Endpoint::parse(&endpoint).expect("endpoint");
        let mut stream = connect_raw(&endpoint).await;
        plan_and_report(&mut stream, &token).await;
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
        let handler = Bookkeeping::held().await;
        let mut supervisor = start(
            Arc::clone(&handler),
            super::InFlightUnits::default(),
            &test_executable(),
        )
        .expect("start the supervisor");
        let [(_, endpoint), (_, token), _] = supervisor.env();
        let endpoint = crate::local_socket::Endpoint::parse(&endpoint).expect("endpoint");

        // Connections that end without any bookkeeping in flight. Accept
        // is FIFO, so the held report's bookkeeping starting below means
        // all three were accepted ahead of it and sit in the drain's set;
        // each ends at its EOF, so a drain that stopped at its first
        // clean join returns on one of them.
        for _ in 0..3 {
            drop(connect_raw(&endpoint).await);
        }
        let mut stream = connect_raw(&endpoint).await;
        plan_and_report(&mut stream, &token).await;
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
        let handler = Bookkeeping::held().await;
        let mut supervisor = start(
            Arc::clone(&handler),
            super::InFlightUnits::default(),
            &test_executable(),
        )
        .expect("start the supervisor");
        let [(_, endpoint), (_, token), _] = supervisor.env();
        let endpoint = crate::local_socket::Endpoint::parse(&endpoint).expect("endpoint");
        let mut stream = connect_raw(&endpoint).await;
        plan_and_report(&mut stream, &token).await;
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

    /// The argv of one library unit compiling into `/deps`: `-C metadata`
    /// and `--out-dir` make it a unit whose outputs the supervisor
    /// records and registers a flight for, and each `externs` entry is a
    /// dependency's rlib.
    fn unit_args(name: &str, externs: &[&str]) -> Vec<OsString> {
        let mut args = [
            "--crate-name",
            name,
            "--crate-type",
            "lib",
            "--emit",
            "dep-info,metadata,link",
            "--out-dir",
            "/deps",
            "-C",
            "metadata=m",
            "-C",
            "extra-filename=-m",
            "src/lib.rs",
        ]
        .map(OsString::from)
        .to_vec();
        for rlib in externs {
            args.push(OsString::from("--extern"));
            args.push(OsString::from(format!("dep={rlib}")));
        }
        args
    }

    /// The rlib path a unit's flight is registered under.
    fn rlib_path(args: &[OsString]) -> String {
        let parsed = crate::rustc_args::ParsedRustcArgs::parse(args).expect("parse the unit");
        crate::artifact_cache::path_to_string(&parsed.output_rlib_path().expect("an rlib unit"))
            .expect("utf-8 output path")
    }

    /// The facade's report returns — its receipt read — and the
    /// connection ends while the supervisor's bookkeeping is still held,
    /// and a dependent's plan waits for the unit's rows once its rustc
    /// has exited — until the bookkeeping ends (stow#1431).
    #[tokio::test]
    async fn a_report_returns_while_its_bookkeeping_is_held() {
        let handler = Bookkeeping::held().await;
        let in_flight = super::InFlightUnits::default();
        let mut supervisor = start(Arc::clone(&handler), in_flight.clone(), &test_executable())
            .expect("start the supervisor");
        let [(_, endpoint), (_, token), _] = supervisor.env();
        let endpoint = crate::local_socket::Endpoint::parse(&endpoint).expect("endpoint");

        let dep_args = unit_args("dep", &[]);
        let dep_rlib = rlib_path(&dep_args);
        let mut connection = Connection::open(&endpoint, token)
            .await
            .expect("connect to the supervisor");
        let ClientDecision::Compile(ticket) = connection
            .plan(std::ffi::OsStr::new("rustc"), &dep_args)
            .await
            .expect("plan")
        else {
            panic!("the handler asks for a compile");
        };
        let dependent =
            crate::rustc_args::ParsedRustcArgs::parse(&unit_args("consumer", &[&dep_rlib]))
                .expect("parse the dependent");

        // Still compiling: a dependent's plan is not held.
        tokio::time::timeout(
            Duration::from_secs(5),
            in_flight.wait_for_exited_externs(&dependent),
        )
        .await
        .expect("a dependent of a unit still compiling is not held");

        // The facade reports and leaves; the bookkeeping is still held.
        connection
            .report(&ticket, true, Duration::ZERO)
            .await
            .expect("the report returns without the bookkeeping");
        connection.close().await.expect("the connection ends");
        handler.started(1).await;
        assert_eq!(
            handler.finished.load(Ordering::SeqCst),
            0,
            "the report returned while its bookkeeping was held"
        );

        // rustc has exited and the rows are not written: the plan waits.
        let planning = tokio::spawn({
            let in_flight = in_flight.clone();
            async move { in_flight.wait_for_exited_externs(&dependent).await }
        });
        in_flight.parked_on(&dep_rlib, 1).await;
        assert!(
            !planning.is_finished(),
            "the plan ran before the rows landed"
        );

        handler.release.send(true).expect("release the bookkeeping");
        tokio::time::timeout(Duration::from_secs(5), planning)
            .await
            .expect("the plan is released once the bookkeeping ends")
            .expect("join the plan");
        assert_eq!(supervisor.shutdown().await, 0, "the drain finishes cleanly");
        assert_eq!(handler.finished.load(Ordering::SeqCst), 1);
    }

    /// A dependent's plan issued the moment the report's receipt is read
    /// waits: the receipt is sent only once the unit's `exited` latch
    /// has fired, so no gap exists between a facade's exit and the
    /// plan's wait. Nothing synchronizes with the bookkeeping first
    /// (stow#1431).
    #[tokio::test]
    async fn a_plan_right_after_the_report_always_waits() {
        let handler = Bookkeeping::held().await;
        let in_flight = super::InFlightUnits::default();
        let mut supervisor = start(Arc::clone(&handler), in_flight.clone(), &test_executable())
            .expect("start the supervisor");
        let [(_, endpoint), (_, token), _] = supervisor.env();
        let endpoint = crate::local_socket::Endpoint::parse(&endpoint).expect("endpoint");

        let dep_args = unit_args("dep", &[]);
        let dep_rlib = rlib_path(&dep_args);
        let dependent =
            crate::rustc_args::ParsedRustcArgs::parse(&unit_args("consumer", &[&dep_rlib]))
                .expect("parse the dependent");
        let mut connection = Connection::open(&endpoint, token)
            .await
            .expect("connect to the supervisor");
        let ClientDecision::Compile(ticket) = connection
            .plan(std::ffi::OsStr::new("rustc"), &dep_args)
            .await
            .expect("plan")
        else {
            panic!("the handler asks for a compile");
        };
        let flight = in_flight.flight(&dep_rlib);
        connection
            .report(&ticket, true, Duration::ZERO)
            .await
            .expect("the report returns");
        assert!(
            flight.exited.has_completed(),
            "the receipt came before the unit was recorded as exited"
        );
        // The dependent plans at once; it must park on the unit.
        let planning = tokio::spawn({
            let in_flight = in_flight.clone();
            async move { in_flight.wait_for_exited_externs(&dependent).await }
        });
        in_flight.parked_on(&dep_rlib, 1).await;
        assert!(!planning.is_finished());

        handler.release.send(true).expect("release the bookkeeping");
        tokio::time::timeout(Duration::from_secs(5), planning)
            .await
            .expect("the plan is released once the bookkeeping ends")
            .expect("join the plan");
        connection.close().await.expect("close");
        assert_eq!(supervisor.shutdown().await, 0);
    }

    /// A report the supervisor cannot use is refused with `Failed` — the
    /// facade is listening for a receipt — and the unit's flight ends
    /// with the facade's connection (stow#1431).
    #[tokio::test]
    async fn a_report_with_an_unknown_ticket_is_refused() {
        let handler = Bookkeeping::held().await;
        let in_flight = super::InFlightUnits::default();
        let mut supervisor = start(Arc::clone(&handler), in_flight.clone(), &test_executable())
            .expect("start the supervisor");
        let [(_, endpoint), (_, token), _] = supervisor.env();
        let endpoint = crate::local_socket::Endpoint::parse(&endpoint).expect("endpoint");

        let dep_args = unit_args("dep", &[]);
        let mut stream = connect_raw(&endpoint).await;
        let flight = {
            use crate::supervisor::protocol::{
                Answer, Compiled, InvocationEnv, Plan, Request, read_frame, write_frame,
            };
            let plan = Plan::new(
                token.clone(),
                std::ffi::OsStr::new("rustc"),
                &dep_args,
                InvocationEnv::for_tests(),
            );
            write_frame(&mut stream, &Request::Plan(plan))
                .await
                .expect("write the plan");
            let Some(Answer::Compile { ticket }) =
                read_frame(&mut stream).await.expect("read the answer")
            else {
                panic!("the handler asks for a compile");
            };
            // Another ticket than the one the plan was given.
            let report = Compiled {
                token,
                ticket: ticket + 1,
                success: true,
                compile_millis: 0,
            };
            // The plan's answer came after the flight registered.
            let flight = in_flight.flight(&rlib_path(&dep_args));
            write_frame(&mut stream, &Request::Compiled(report))
                .await
                .expect("write the report");
            let refusal: Option<Answer> = read_frame(&mut stream)
                .await
                .expect("read the report's answer");
            assert!(
                matches!(&refusal, Some(Answer::Failed { message }) if message.contains("no record")),
                "{refusal:?}"
            );
            flight
        };
        // The report matches no flight, so it ends none: the unit stays
        // in flight until its facade's connection ends, as for a facade
        // that dies without reporting. The bookkeeping never runs.
        drop(stream);
        tokio::time::timeout(Duration::from_secs(5), flight.wait())
            .await
            .expect("the connection's end releases the flight");
        assert_eq!(supervisor.shutdown().await, 0);
        assert_eq!(handler.started.borrow().to_owned(), 0);
    }

    /// The first leg of a flight is rustc running: a plan does not wait
    /// for it. The second leg — the report arrived, the rows are
    /// pending — it does, until the flight ends however it ends
    /// (stow#1431).
    #[tokio::test]
    async fn a_plan_waits_for_exited_units_only() {
        let in_flight = super::InFlightUnits::default();
        let flight = in_flight.register(vec!["/deps/libdep-m.rlib".to_owned()]);
        let dependent = crate::rustc_args::ParsedRustcArgs::parse(&unit_args(
            "consumer",
            &["/deps/libdep-m.rlib"],
        ))
        .expect("parse the dependent");

        tokio::time::timeout(
            Duration::from_secs(5),
            in_flight.wait_for_exited_externs(&dependent),
        )
        .await
        .expect("a unit still compiling is not waited for");

        flight.rustc_exited();
        let planning = tokio::spawn({
            let in_flight = in_flight.clone();
            async move { in_flight.wait_for_exited_externs(&dependent).await }
        });
        in_flight.parked_on("/deps/libdep-m.rlib", 1).await;
        assert!(!planning.is_finished());
        // The facade's connection ending without anything more releases it.
        drop(flight);
        tokio::time::timeout(Duration::from_secs(5), planning)
            .await
            .expect("the plan is released when the flight ends")
            .expect("join the plan");
    }

    /// A handler with a build config and no rustc work: the C object
    /// cache is all it answers.
    struct CcCache {
        config: crate::config::StowConfig,
        roots: crate::supervisor::invocation::OutputRoots,
        toolchain: Arc<BuildToolchain>,
    }

    impl Handler for CcCache {
        type Pending = OsString;

        fn cc_config(self: &Arc<Self>) -> Option<&crate::config::StowConfig> {
            Some(&self.config)
        }

        fn output_roots(self: &Arc<Self>) -> Option<&crate::supervisor::invocation::OutputRoots> {
            Some(&self.roots)
        }

        fn plan(
            self: &Arc<Self>,
            _invocation: VerifiedInvocation,
            _env: crate::supervisor::protocol::InvocationEnv,
        ) -> impl std::future::Future<Output = Decision<Self::Pending>> + Send {
            std::future::ready(Decision::Compile(OsString::new()))
        }

        fn compiled(
            self: &Arc<Self>,
            _pending: Self::Pending,
            _success: bool,
            _compile_time: Duration,
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
            std::future::ready(())
        }

        fn toolchain(self: &Arc<Self>) -> &Arc<BuildToolchain> {
            &self.toolchain
        }

        fn refusal_policy(self: &Arc<Self>) -> RefusalPolicy {
            RefusalPolicy::FailBuild
        }

        fn refused(self: &Arc<Self>, _refusal: Refusal) {}
    }

    /// The C wrapper's exchange with the daemon: a lookup that misses, a
    /// report of the compile, then a later lookup that hits. The store,
    /// the LRU row and the statistics land in the daemon's own state
    /// database — the wrapper holds no handle on it — and the object
    /// stays in the cache directory for the wrapper to clone.
    #[tokio::test]
    async fn a_c_wrapper_is_served_and_recorded_by_the_daemon() {
        use crate::supervisor::client::CcDecision;

        let cache = tempfile::tempdir().expect("cache dir");
        let config = crate::config::StowConfig {
            cache: crate::config::CacheLayers::default(),
            edge_url: "http://127.0.0.1:8787".to_owned(),
            registry_base_url: "http://127.0.0.1:8787".to_owned(),
            cache_dir: cache.path().to_path_buf(),
            request_timeout: Duration::from_secs(15),
            negative_cache_ttl: Duration::from_mins(5),
            circuit_reset_after: Duration::from_mins(1),
            circuit_trip_threshold: 5,
            artifact_cache_max_bytes: crate::config::DEFAULT_ARTIFACT_CACHE_MAX_BYTES,
            index_refresh_interval: Duration::from_mins(1),
            verify_mode: crate::config::VerifyMode::GithubCi,
            switches: crate::config::Switches::default(),
            state_db: crate::state_db::StateDb::default(),
            trust_material: Arc::default(),
            registry_http: Arc::default(),
            artifact_cache_staging: Arc::default(),
        };
        let target = tempfile::tempdir().expect("target dir");
        let handler = Arc::new(CcCache {
            config: config.clone(),
            roots: crate::supervisor::invocation::OutputRoots::new(
                target.path().to_path_buf(),
                None,
            ),
            toolchain: BuildToolchain::for_tests().await,
        });
        let mut supervisor = start(
            Arc::clone(&handler),
            super::InFlightUnits::default(),
            &test_executable(),
        )
        .expect("start the supervisor");
        let [(_, endpoint), (_, token), _] = supervisor.env();
        let endpoint = crate::local_socket::Endpoint::parse(&endpoint).expect("endpoint");
        let output = target.path().join("probe.o");
        std::fs::write(&output, b"object bytes").expect("write the compiler's output");

        let mut connection = Connection::open(&endpoint, token.clone())
            .await
            .expect("connect to the supervisor");
        assert!(matches!(
            connection.cc_lookup(CC_KEY).await.expect("first lookup"),
            CcDecision::Miss
        ));
        assert_eq!(
            connection
                .cc_report(CC_KEY, &output, true)
                .await
                .expect("report the compile"),
            None,
            "an output inside the target directory is taken"
        );
        connection.close().await.expect("close");

        let mut connection = Connection::open(&endpoint, token)
            .await
            .expect("connect to the supervisor");
        // The store follows the receipt, so a lookup racing it may still
        // miss; the shutdown drain is what makes the rest deterministic.
        let first = connection.cc_lookup(CC_KEY).await.expect("second lookup");
        connection.close().await.expect("close");
        assert_eq!(supervisor.shutdown().await, 0, "the drain finishes cleanly");

        let object = crate::cc::cached_object_path(&config, CC_KEY);
        assert_eq!(
            std::fs::read(&object).expect("the daemon stored the object"),
            b"object bytes"
        );
        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM cc_cache_entries WHERE cache_key = ?")
                .bind(CC_KEY)
                .fetch_one(&config.state_db_pool().await.expect("state db"))
                .await
                .expect("count rows");
        assert_eq!(rows, 1, "the daemon wrote the object's LRU row");
        let summary = crate::stats::read_summary(&config).await.expect("stats");
        assert_eq!(summary.cc_misses, 1, "the compile is recorded as a miss");
        match first {
            CcDecision::Hit(path) => {
                assert_eq!(path, object);
                assert_eq!(summary.cc_hits, 1, "the served hit is recorded");
            }
            CcDecision::Miss => assert_eq!(summary.cc_hits, 0),
            CcDecision::Bypass(reason) => panic!("the cache was consulted: {reason}"),
        }
        config.state_db.close().await;
    }

    /// A C/C++ cache key: the hex of a SHA-256 digest, as the wrapper
    /// computes it.
    const CC_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// The supervisor is not sandboxed, so a report naming a file the
    /// sandbox keeps from the wrapper must not make it read that file into
    /// the cache the sandbox can read: an output outside the target
    /// directory, a link inside it that points outside, and a file reached
    /// through a directory link inside it, are refused, answered `Failed`
    /// naming the path, and nothing reaches the cache directory.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_c_report_outside_the_target_directory_is_refused() {
        let cache = tempfile::tempdir().expect("cache dir");
        let target = tempfile::tempdir().expect("target dir");
        let outside = tempfile::tempdir().expect("outside dir");
        let secret = outside.path().join("id_ed25519");
        std::fs::write(&secret, b"private key").expect("write the secret");
        let link = target.path().join("probe.o");
        std::os::unix::fs::symlink(&secret, &link).expect("link to the secret");
        // A directory link is followed by the open; only the descriptor's
        // real path tells it apart from a file in the target directory.
        std::os::unix::fs::symlink(outside.path(), target.path().join("out"))
            .expect("link to the secret's directory");
        let through_directory = target.path().join("out").join("id_ed25519");
        let config = crate::config::StowConfig {
            cache: crate::config::CacheLayers::default(),
            edge_url: "http://127.0.0.1:8787".to_owned(),
            registry_base_url: "http://127.0.0.1:8787".to_owned(),
            cache_dir: cache.path().to_path_buf(),
            request_timeout: Duration::from_secs(15),
            negative_cache_ttl: Duration::from_mins(5),
            circuit_reset_after: Duration::from_mins(1),
            circuit_trip_threshold: 5,
            artifact_cache_max_bytes: crate::config::DEFAULT_ARTIFACT_CACHE_MAX_BYTES,
            index_refresh_interval: Duration::from_mins(1),
            verify_mode: crate::config::VerifyMode::GithubCi,
            switches: crate::config::Switches::default(),
            state_db: crate::state_db::StateDb::closed(),
            trust_material: Arc::default(),
            registry_http: Arc::default(),
            artifact_cache_staging: Arc::default(),
        };
        let handler = Arc::new(CcCache {
            config: config.clone(),
            roots: crate::supervisor::invocation::OutputRoots::new(
                target.path().to_path_buf(),
                None,
            ),
            toolchain: BuildToolchain::for_tests().await,
        });
        let mut supervisor = start(
            Arc::clone(&handler),
            super::InFlightUnits::default(),
            &test_executable(),
        )
        .expect("start the supervisor");
        let [(_, endpoint), (_, token), _] = supervisor.env();
        let endpoint = crate::local_socket::Endpoint::parse(&endpoint).expect("endpoint");

        let mut connection = Connection::open(&endpoint, token)
            .await
            .expect("connect to the supervisor");
        for reported in [&secret, &link, &through_directory] {
            let refusal = connection
                .cc_report(CC_KEY, reported, true)
                .await
                .expect("the refusal is an answer")
                .expect("a report outside the target directory is refused");
            assert!(
                refusal.contains(&reported.display().to_string()),
                "the refusal names the path: {refusal}"
            );
        }
        connection.close().await.expect("close");
        assert_eq!(supervisor.shutdown().await, 0, "the drain finishes cleanly");

        let leftovers: Vec<_> = walkdir::WalkDir::new(cache.path())
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_file())
            .collect();
        assert!(
            leftovers.is_empty(),
            "nothing may be staged for a refused report: {leftovers:?}"
        );
    }
}
