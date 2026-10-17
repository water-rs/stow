//! The supervisor's heel-IPC transport (stow#779).
//!
//! A sandboxed cargo build's facades cannot open the supervisor's usual
//! unix socket or loopback listener: heel's `deny network*` profile
//! leaves exactly one outbound channel — the sandbox's own IPC socket —
//! and on Windows an `AppContainer` without a network capability cannot
//! open loopback at all. So under `--sandbox` the supervisor's frames
//! ride heel's IPC instead: one `IpcCall` per supervisor `Request`,
//! answered with the `Answer` the socket transport would have written.
//!
//! The supervisor protocol is stateful per connection — a `Compile`
//! ticket's flight and an `Observed` mark live between frames — so each
//! facade mints a conversation id at connect and the calls below share a
//! marks table keyed by it. `Close` drops the entry, which completes the
//! conversation's flights exactly the way a socket teardown does. A
//! facade that dies without closing leaves its marks until the build
//! ends, where the table's drop releases them the same way.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use super::protocol::{Answer, Request};
use super::server::{self, ConnectionMark, Handler, InFlightUnits, Ticket};
use super::{BINARY_ENV, BinaryIdentity, ENDPOINT_ENV, Endpoint, TOKEN_ENV};

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
    /// the socket transport would have written, `None` for the one-way
    /// `Observed`.
    Request(Request),
    /// The conversation is over: drop the marks it still holds, the
    /// teardown a socket close performs.
    Close,
}

/// The conversation table one build's facades share — the per-connection
/// state `serve_connection` keeps as its `marks`, keyed by the facade's
/// own id. Dropping an entry drops every `Completion` it held, ending
/// the flight the same way the socket teardown does (stow#618).
type Conversations = Arc<Mutex<HashMap<u64, Vec<ConnectionMark>>>>;

/// The `heel::IpcCommand` serving one build's supervisor requests.
///
/// Every field names the same state the socket supervisor's accept task
/// hands each connection: the handler, the ticket channel, the shared
/// token, and the in-flight registry.
struct SupervisorIpc<H: Handler> {
    handler: Arc<H>,
    tickets: mpsc::UnboundedSender<Ticket<H::Pending>>,
    token: String,
    in_flight: InFlightUnits,
    conversations: Conversations,
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

    fn handle(&self, call: IpcCall) -> impl Future<Output = Option<Answer>> + Send {
        let conversations = Arc::clone(&self.conversations);
        let handler = Arc::clone(&self.handler);
        let tickets = self.tickets.clone();
        let token = self.token.clone();
        let in_flight = self.in_flight.clone();
        let rt = self.rt.clone();
        async move {
            match call.body {
                IpcCallBody::Close => {
                    conversations
                        .lock()
                        .expect("supervisor conversations mutex")
                        .remove(&call.connection);
                    None
                }
                IpcCallBody::Request(request) => {
                    // The marks leave the table while the request is
                    // served so the lock is never held across an await; a
                    // facade serializes its own calls, so nothing can
                    // interleave into the conversation it is using.
                    let marks = conversations
                        .lock()
                        .expect("supervisor conversations mutex")
                        .entry(call.connection)
                        .or_default()
                        .split_off(0);
                    // The answer is spawned onto the build's runtime —
                    // the supervisor's `spawn_blocking` probes and timers
                    // need that reactor, and heel's executor must stay
                    // free to serve the next call — with owned inputs so
                    // the task is 'static; the marks ride in and back so
                    // they can be parked under the lock again.
                    let (mut marks, answer) = rt
                        .spawn({
                            let mut marks = marks;
                            async move {
                                let answer = server::answer_request(
                                    &handler, &tickets, &token, &in_flight, &mut marks, request,
                                )
                                .await;
                                (marks, answer)
                            }
                        })
                        .await
                        .expect("the supervisor answer task panicked");
                    conversations
                        .lock()
                        .expect("supervisor conversations mutex")
                        .entry(call.connection)
                        .or_default()
                        .append(&mut marks);
                    answer
                }
            }
        }
    }
}

/// What the driver assembles before the sandbox exists: the supervisor
/// state minus its endpoint, paired with the router the sandbox's IPC
/// server is built from. `finish` fills in the endpoint once the
/// sandbox has bound its socket.
pub struct PendingSupervisor {
    token: String,
    binary: BinaryIdentity,
    conversations: Conversations,
    tickets_task: tokio::task::JoinHandle<()>,
}

/// The supervisor half a sandboxed build exports to its facades — the
/// same `env` triple the socket supervisor hands cargo, with heel's IPC
/// socket as the endpoint.
pub struct SandboxedSupervisor {
    endpoint: Endpoint,
    token: String,
    binary: BinaryIdentity,
    conversations: Conversations,
    tickets_task: tokio::task::JoinHandle<()>,
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
) -> Result<(PendingSupervisor, heel::IpcRouter), String> {
    let binary = BinaryIdentity::of(runtime_executable)
        .map_err(|error| format!("identity of {}: {error}", runtime_executable.display()))?;
    let token = server::mint_token();
    let (tickets, ticket_rx) = mpsc::unbounded_channel::<Ticket<H::Pending>>();
    let tickets_task = tokio::spawn(server::run_tickets(ticket_rx));
    let conversations: Conversations = Arc::new(Mutex::new(HashMap::new()));
    let command = SupervisorIpc {
        handler,
        tickets,
        token: token.clone(),
        in_flight,
        conversations: Arc::clone(&conversations),
        rt: tokio::runtime::Handle::current(),
    };
    Ok((
        PendingSupervisor {
            token,
            binary,
            conversations,
            tickets_task,
        },
        heel::IpcRouter::new().register(command),
    ))
}

impl PendingSupervisor {
    /// The finished supervisor: `socket` is the IPC endpoint the running
    /// sandbox exposes through `heel::Sandbox::ipc_endpoint`.
    pub fn finish(self, socket: &Path) -> SandboxedSupervisor {
        SandboxedSupervisor {
            endpoint: Endpoint::Ipc(socket.to_path_buf()),
            token: self.token,
            binary: self.binary,
            conversations: self.conversations,
            tickets_task: self.tickets_task,
        }
    }
}

impl SandboxedSupervisor {
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

    /// The build is over: drop the conversations, which completes every
    /// flight still marked the way the socket drain does, and stop the
    /// ticket task — the router itself goes down with the sandbox.
    pub fn shutdown(&self) {
        self.conversations
            .lock()
            .expect("supervisor conversations mutex")
            .clear();
        self.tickets_task.abort();
    }
}
