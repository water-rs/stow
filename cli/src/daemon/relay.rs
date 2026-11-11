//! The driver's relay: how a sandboxed build's wrappers reach the daemon.
//!
//! A sandbox leaves one outbound channel, its own IPC socket (stow#779),
//! and on Windows an `AppContainer` could not reach the daemon's pipe or
//! start a daemon that outlives the sandbox's job object. So the driver,
//! which runs outside the sandbox, serves that socket: each wrapper
//! conversation is one `RelayCall` per request, forwarded over a daemon
//! connection the relay holds for the conversation, and the daemon's answer
//! is the call's response.
//!
//! The relay forwards only [`WrapperRequest`]s, under the session it was
//! created for. A sandboxed wrapper therefore holds neither the daemon's
//! endpoint nor a session id, and cannot name another session.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::Settings;
use super::client::{Stream, WrapperStream, connect};
use super::protocol::{SessionRef, WrapperRequest};
use super::session::SessionId;
use crate::daemon::wrapper::Answer;

/// The method name the IPC router registers the relay under —
/// `[A-Za-z][A-Za-z0-9_-]*`, since heel also spells it as a shim's file
/// name.
pub const RELAY_METHOD: &str = "stow-daemon";

/// The id a wrapper mints for its conversation at connect: 64 random bits,
/// unique within one build.
///
/// # Panics
///
/// The operating system has no randomness to give.
#[must_use]
pub fn mint_connection_id() -> u64 {
    let mut bytes = [0; 8];
    getrandom::fill(&mut bytes).expect("the operating system's randomness is available");
    u64::from_le_bytes(bytes)
}

/// One call a sandboxed wrapper makes on the IPC socket.
#[derive(Debug, Serialize, Deserialize)]
pub struct RelayCall {
    /// The wrapper's conversation: minted when it connects, shared by every
    /// frame it sends, so the daemon pairs its report with its plan.
    pub connection: u64,
    /// What the call carries.
    pub body: RelayBody,
}

/// A request, or the conversation's end.
#[derive(Debug, Serialize, Deserialize)]
pub enum RelayBody {
    /// One request; the call's response carries the answer the daemon gave.
    Request(WrapperRequest),
    /// The conversation is over: close its daemon connection, which ends
    /// the flight it still holds.
    Close,
}

/// The daemon connections of the conversations in progress.
type Conversations = Mutex<HashMap<u64, WrapperStream<Stream>>>;

/// Where the relay reaches the daemon and for which session.
struct Shared {
    session: SessionId,
    exe: PathBuf,
    settings: Settings,
    conversations: Conversations,
}

impl Shared {
    async fn serve(&self, call: RelayCall) -> Option<Answer> {
        match call.body {
            RelayBody::Close => {
                // Dropping the stream closes it: the daemon reads the end
                // and ends the flight.
                self.conversations
                    .lock()
                    .expect("relay conversations mutex")
                    .remove(&call.connection);
                None
            }
            RelayBody::Request(request) => Some(self.forward(call.connection, &request).await),
        }
    }

    /// Forward `request` on the conversation's daemon connection, opening
    /// it through the start path the first time. The connection leaves the
    /// table while the request is served so the lock is never held across
    /// an await; a wrapper serializes its own calls.
    async fn forward(&self, connection: u64, request: &WrapperRequest) -> Answer {
        let held = self
            .conversations
            .lock()
            .expect("relay conversations mutex")
            .remove(&connection);
        let mut stream = match held {
            Some(stream) => stream,
            None => match connect(self.exe.clone(), self.settings).await {
                Ok(stream) => {
                    WrapperStream::new(stream, SessionRef::Id(self.session), self.settings.answer)
                }
                Err(error) => {
                    return Answer::Failed {
                        message: format!("{error:#}"),
                    };
                }
            },
        };
        match stream.exchange(request).await {
            Ok(answer) => {
                self.conversations
                    .lock()
                    .expect("relay conversations mutex")
                    .insert(connection, stream);
                answer
            }
            // The connection is not put back: a later call on this
            // conversation opens another, which the daemon answers as a
            // request with no flight.
            Err(message) => Answer::Failed { message },
        }
    }
}

/// The `heel::IpcCommand` serving one build's wrappers.
struct Relay {
    shared: Arc<Shared>,
    /// The driver's tokio runtime. Heel serves IPC calls on its own
    /// executor, and the daemon connection wants a reactor: each call is
    /// spawned onto this one.
    rt: tokio::runtime::Handle,
}

impl heel::ipc::IpcCommand for Relay {
    fn name(&self) -> std::borrow::Cow<'static, str> {
        RELAY_METHOD.into()
    }

    type Args = RelayCall;

    type Response = Option<Answer>;

    fn handle(
        &self,
        call: RelayCall,
        // The requests carry their own paths; the caller's working
        // directory plays no part.
        _context: heel::IpcContext,
    ) -> impl Future<Output = Result<Option<Answer>, heel::IpcError>> + Send {
        let shared = Arc::clone(&self.shared);
        let rt = self.rt.clone();
        async move {
            Ok(rt
                .spawn(async move { shared.serve(call).await })
                .await
                .expect("the relay task panicked"))
        }
    }
}

/// The IPC router a sandbox is built with, relaying the wrappers of
/// `session`. `exe` is the stow binary that starts the daemon when the
/// connection must be re-established.
///
/// Must be called on the driver's tokio runtime.
#[must_use]
pub fn router(session: SessionId, exe: PathBuf, settings: Settings) -> heel::IpcRouter {
    heel::IpcRouter::new().register(Relay {
        shared: Arc::new(Shared {
            session,
            exe,
            settings,
            conversations: Mutex::default(),
        }),
        rt: tokio::runtime::Handle::current(),
    })
}
