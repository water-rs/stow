//! The supervisor's heel-IPC transport (stow#779).
//!
//! A sandboxed cargo build's facades cannot open the supervisor's usual
//! unix socket or loopback listener: heel's `deny network*` profile
//! leaves exactly one outbound channel — the sandbox's own IPC socket —
//! and on Windows an `AppContainer` without a network capability cannot
//! open loopback at all. So under `--isolation` the supervisor's frames
//! ride heel's IPC instead: one `IpcCall` per supervisor `Request`,
//! answered with the `Answer` the socket transport would have written.
//!
//! The supervisor protocol is stateful per connection — a `Compile`
//! answer's flight lives until the report — so each facade mints a
//! conversation id at connect and the calls below share a flights table
//! keyed by it. `Close` drops the entry, which completes the
//! conversation's flight exactly the way a socket teardown does. A
//! facade that dies without closing leaves its flight until the build
//! ends, where the table's drop releases it the same way.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::protocol::{Answer, Request};
use super::server::{self, Flight, Handler, InFlightUnits};
use super::{BINARY_ENV, BinaryIdentity, ENDPOINT_ENV, TOKEN_ENV};
use crate::local_socket::Endpoint;

/// The method name the IPC router registers the supervisor under —
/// `[A-Za-z][A-Za-z0-9_-]*`, since heel also spells it as a shim's file
/// name.
pub const IPC_METHOD: &str = "stow-supervisor";

/// The id a facade mints for its conversation at connect: 64 bits of
/// randomness keyed on the same unguessable seed the supervisor token
/// uses, since the id only has to be unique within one build.
pub fn mint_connection_id() -> u64 {
    let seed = format!(
        "{}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        std::time::Instant::now()
    );
    let hash = blake3::hash(seed.as_bytes());
    u64::from_le_bytes(hash.as_bytes()[..8].try_into().expect("8 bytes"))
}

/// One call a sandboxed facade makes on the IPC socket.
#[derive(Debug, Serialize, Deserialize)]
pub struct IpcCall {
    /// The facade's conversation: minted when it connects, shared by
    /// every frame it sends, so its marks pair across calls.
    pub connection: u64,
    /// What the call carries.
    pub body: IpcCallBody,
}

/// A supervisor frame, or the conversation's end.
#[derive(Debug, Serialize, Deserialize)]
pub enum IpcCallBody {
    /// One `Request` frame; the call's response carries the `Answer`
    /// the socket transport would have written.
    Request(Request),
    /// The conversation is over: drop the flight it still holds, the
    /// teardown a socket close performs.
    Close,
}

/// The conversation table one build's facades share — the per-connection
/// state `serve_connection` keeps as its `flight`, keyed by the facade's
/// own id. Dropping an entry drops the `Completion` it held, ending the
/// flight the same way the socket teardown does (stow#618).
type Conversations<P> = Arc<Mutex<HashMap<u64, Option<Flight<P>>>>>;

/// The running bookkeeping of the reports. A report's call returns its
/// receipt at once — the facade must not wait for its bookkeeping, as it
/// does not on the socket transport — so the bookkeeping outlives the
/// call and the shutdown drain is what waits for it (stow#1431).
type Reports = Arc<Mutex<tokio::task::JoinSet<()>>>;

/// The `heel::IpcCommand` serving one build's supervisor requests.
///
/// Every field names the same state the socket supervisor's accept task
/// hands each connection: the handler, the shared token, and the
/// in-flight registry.
struct SupervisorIpc<H: Handler> {
    handler: Arc<H>,
    token: String,
    in_flight: InFlightUnits,
    conversations: Conversations<H::Pending>,
    /// The bookkeeping tasks the reports spawned: the sandboxed
    /// build's equivalent of the socket supervisor's connection set,
    /// drained at shutdown (stow#1431).
    reports: Reports,
    /// The build's tokio runtime. Heel serves IPC calls on its own
    /// executor, and the supervisor's work — `spawn_blocking` probes,
    /// `tokio` timers — wants a reactor: `handle` spawns each answer
    /// onto this one rather than borrowing heel's.
    rt: tokio::runtime::Handle,
}

impl<H: Handler> heel::ipc::IpcCommand for SupervisorIpc<H> {
    fn name(&self) -> std::borrow::Cow<'static, str> {
        IPC_METHOD.into()
    }

    type Args = IpcCall;

    type Response = Option<Answer>;

    fn handle(
        &self,
        call: IpcCall,
        // The supervisor protocol carries its own paths; the caller's
        // working directory plays no part in it.
        _context: heel::IpcContext,
    ) -> impl Future<Output = Result<Option<Answer>, heel::IpcError>> + Send {
        let conversations = Arc::clone(&self.conversations);
        let handler = Arc::clone(&self.handler);
        let token = self.token.clone();
        let in_flight = self.in_flight.clone();
        let reports = Arc::clone(&self.reports);
        let rt = self.rt.clone();
        async move {
            Ok(match call.body {
                IpcCallBody::Close => {
                    conversations
                        .lock()
                        .expect("supervisor conversations mutex")
                        .remove(&call.connection);
                    None
                }
                IpcCallBody::Request(request) => {
                    // The flight leaves the table while the request is
                    // served so the lock is never held across an await; a
                    // facade serializes its own calls, so nothing can
                    // interleave into the conversation it is using.
                    let flight = conversations
                        .lock()
                        .expect("supervisor conversations mutex")
                        .entry(call.connection)
                        .or_default()
                        .take();
                    // The answer is spawned onto the build's runtime —
                    // the supervisor's `spawn_blocking` probes and timers
                    // need that reactor, and heel's executor must stay
                    // free to serve the next call — with owned inputs so
                    // the task is 'static; the flight rides in and back
                    // so it can be parked under the lock again.
                    let (flight, reply) = rt
                        .spawn({
                            let handler = Arc::clone(&handler);
                            let mut flight = flight;
                            async move {
                                let reply = server::answer_request(
                                    &handler,
                                    &token,
                                    &in_flight,
                                    &mut flight,
                                    request,
                                )
                                .await;
                                (flight, reply)
                            }
                        })
                        .await
                        .expect("the supervisor answer task panicked");
                    conversations
                        .lock()
                        .expect("supervisor conversations mutex")
                        .insert(call.connection, flight);
                    let (answer, work) = reply.split();
                    // A report's receipt has fired the unit's `exited`
                    // latch; its bookkeeping runs on its own task, the
                    // call returns the receipt at once, and the shutdown
                    // drain waits for the task (stow#1431).
                    if let Some(work) = work {
                        let mut reports = reports.lock().expect("supervisor reports mutex");
                        // Reap the bookkeeping that already ended so the
                        // set holds only what still runs.
                        while reports.try_join_next().is_some() {}
                        reports.spawn_on(
                            async move { server::finish_report(&handler, work).await },
                            &rt,
                        );
                    }
                    Some(answer)
                }
            })
        }
    }
}

/// What the driver assembles before the sandbox exists: the supervisor
/// state minus its endpoint, paired with the router the sandbox's IPC
/// server is built from. `finish` fills in the endpoint once the
/// sandbox has bound its socket.
pub struct PendingSupervisor<P> {
    token: String,
    binary: BinaryIdentity,
    conversations: Conversations<P>,
    reports: Reports,
}

/// The supervisor half a sandboxed build exports to its facades — the
/// same `env` triple the socket supervisor hands cargo, with heel's IPC
/// socket as the endpoint.
pub struct SandboxedSupervisor<P> {
    endpoint: Endpoint,
    token: String,
    binary: BinaryIdentity,
    conversations: Conversations<P>,
    reports: Reports,
}

/// Start the supervisor state and fold it into the IPC router the
/// sandbox is built with. `runtime_executable` is the binary the
/// build's shims resolve to: its identity goes to cargo so a facade
/// running a different build of the binary refuses before a frame is
/// sent (stow#645).
///
/// # Errors
///
/// A runtime executable that cannot be statted.
pub fn start<H: Handler>(
    handler: Arc<H>,
    in_flight: InFlightUnits,
    runtime_executable: &Path,
) -> Result<(PendingSupervisor<H::Pending>, heel::IpcRouter), String> {
    let binary = BinaryIdentity::of(runtime_executable)
        .map_err(|error| format!("identity of {}: {error}", runtime_executable.display()))?;
    let token = server::mint_token();
    let conversations: Conversations<H::Pending> = Arc::new(Mutex::new(HashMap::new()));
    let reports: Reports = Arc::default();
    let command = SupervisorIpc {
        handler,
        token: token.clone(),
        in_flight,
        conversations: Arc::clone(&conversations),
        reports: Arc::clone(&reports),
        rt: tokio::runtime::Handle::current(),
    };
    Ok((
        PendingSupervisor {
            token,
            binary,
            conversations,
            reports,
        },
        heel::IpcRouter::new().register(command),
    ))
}

impl<P> PendingSupervisor<P> {
    /// The finished supervisor: `socket` is the IPC endpoint the running
    /// sandbox exposes through `heel::Sandbox::ipc_endpoint`.
    pub fn finish(self, socket: &Path) -> SandboxedSupervisor<P> {
        SandboxedSupervisor {
            endpoint: Endpoint::Ipc(socket.to_path_buf()),
            token: self.token,
            binary: self.binary,
            conversations: self.conversations,
            reports: self.reports,
        }
    }
}

impl<P> SandboxedSupervisor<P> {
    /// The environment a cargo invocation needs to reach this supervisor,
    /// spelled the same as the socket supervisor's.
    #[must_use]
    pub fn env(&self) -> [(&'static str, String); 3] {
        [
            (ENDPOINT_ENV, self.endpoint.encode()),
            (TOKEN_ENV, self.token.clone()),
            (BINARY_ENV, self.binary.encode()),
        ]
    }

    /// The build is over: wait for the reports' bookkeeping still running
    /// — bounded like the socket drain, for the same reason — then drop
    /// the conversations, which completes every flight still held the
    /// way the socket drain does — the router itself goes down with the
    /// sandbox (stow#618, stow#1431).
    pub async fn shutdown(&self) {
        let mut reports =
            std::mem::take(&mut *self.reports.lock().expect("supervisor reports mutex"));
        let drained = tokio::time::timeout(server::CONNECTION_DRAIN_BUDGET, async {
            while let Some(result) = reports.join_next().await {
                if let Err(error) = result {
                    tracing::warn!(%error, "supervisor report task failed");
                }
            }
        })
        .await;
        if drained.is_err() {
            tracing::warn!(
                abandoned = reports.len(),
                "supervisor shutdown abandoned in-flight report bookkeeping"
            );
        }
        self.conversations
            .lock()
            .expect("supervisor conversations mutex")
            .clear();
    }
}
