//! The facade side: one connection, one question, one answer.

use std::ffi::OsString;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::ipc::{IPC_METHOD, IpcCall, IpcCallBody, mint_connection_id};
use super::protocol::{
    Answer, ArtifactNotifications, Compiled, Plan, Request, read_frame, write_frame,
};
use super::{Endpoint, Stream};

/// What the supervisor decided for this invocation.
#[derive(Debug)]
pub enum Decision {
    /// The outputs are already in place; exit 0 after writing the
    /// artifact-notification lines cargo is owed to this process's
    /// stderr (stow#633).
    Served(ArtifactNotifications),
    /// Run the real rustc, then call [`report`] with its outcome.
    Compile(Ticket),
}

/// The supervisor's handle on a compile it asked the facade to run.
#[derive(Debug)]
pub struct Ticket {
    ticket: u64,
}

/// The transport a [`Connection`] speaks: the build's own socket, or a
/// conversation tunneled through heel's IPC socket when the build runs
/// sandboxed (stow#779).
enum ConnectionInner {
    /// A connected unix socket or loopback stream.
    Stream(Stream),
    /// A client of heel's IPC server plus this facade's conversation id.
    /// The client leaves its slot while a call blocks on the worker
    /// thread and is always put back, so a call never finds it gone.
    Ipc {
        client: Option<heel::IpcClient>,
        connection: u64,
    },
}

/// Connection to the supervisor, kept open across the plan and the report
/// so the compile's outcome reaches the same conversation.
pub struct Connection {
    inner: ConnectionInner,
    token: String,
}

impl Connection {
    /// Connect to `endpoint`.
    ///
    /// # Errors
    ///
    /// Any connection failure. The caller fails the build: an endpoint in
    /// the environment that cannot be reached means the supervisor died,
    /// and a build that quietly stops using the cache is the failure that
    /// hides.
    pub async fn open(endpoint: &Endpoint, token: String) -> Result<Self, String> {
        if let Endpoint::Ipc(path) = endpoint {
            let path = path.clone();
            let client = smol::unblock(move || heel::IpcClient::connect(path))
                .await
                .map_err(|error| format!("connect to supervisor over heel IPC: {error}"))?;
            return Ok(Self {
                inner: ConnectionInner::Ipc {
                    client: Some(client),
                    connection: mint_connection_id(),
                },
                token,
            });
        }
        let stream = super::connect(endpoint).await?;
        Ok(Self {
            inner: ConnectionInner::Stream(stream),
            token,
        })
    }

    /// Ask what to do with one rustc invocation.
    ///
    /// # Errors
    ///
    /// Transport failures, and a supervisor that answers with a failure of
    /// its own.
    pub async fn plan(
        &mut self,
        executable: &std::ffi::OsStr,
        args: &[OsString],
    ) -> Result<Decision, String> {
        let plan = Plan::new(self.token.clone(), executable, args);
        match self.exchange(&Request::Plan(plan)).await? {
            Answer::Served(notifications) => Ok(Decision::Served(notifications)),
            Answer::Compile { ticket } => Ok(Decision::Compile(Ticket { ticket })),
            Answer::Recorded | Answer::ServeMapReady => {
                Err("supervisor answered a plan with an answer that is not a decision".to_owned())
            }
            Answer::Failed { message } => Err(message),
        }
    }

    /// Report the compile the supervisor asked for.
    ///
    /// # Errors
    ///
    /// Transport failures, and a supervisor that answers with a failure of
    /// its own.
    pub async fn report(&mut self, ticket: &Ticket, success: bool) -> Result<(), String> {
        let report = Compiled {
            token: self.token.clone(),
            ticket: ticket.ticket,
            success,
        };
        match self.exchange(&Request::Compiled(report)).await? {
            Answer::Recorded => Ok(()),
            Answer::Failed { message } => Err(message),
            Answer::Served(..) | Answer::Compile { .. } | Answer::ServeMapReady => {
                Err("supervisor answered a report with a plan answer".to_owned())
            }
        }
    }

    /// End the conversation: send the stream's end and release the
    /// connection. A process that exits with the loopback connection
    /// still open resets it — the supervisor then reads an error where
    /// the conversation simply ended (stow#633). No facade leaves through
    /// `std::process::exit` with a connection in hand (stow#682), so a
    /// drop releases it too; the close stays explicit because it ends the
    /// stream in order and reports a shutdown that fails, where a drop
    /// reports nothing.
    ///
    /// # Errors
    ///
    /// A stream that cannot be shut down, or a close the IPC transport
    /// could not deliver — the conversation's marks then stay until the
    /// build ends instead of completing now.
    pub async fn close(mut self) -> Result<(), String> {
        match &mut self.inner {
            ConnectionInner::Stream(stream) => match stream {
                #[cfg(unix)]
                Stream::Unix(stream) => stream.shutdown().await,
                Stream::Loopback(stream) => stream.shutdown().await,
            }
            .map_err(|error| format!("close the supervisor connection: {error}")),
            ConnectionInner::Ipc { client, connection } => {
                let Some(mut client) = client.take() else {
                    return Ok(());
                };
                let call = IpcCall {
                    connection: *connection,
                    body: IpcCallBody::Close,
                };
                smol::unblock(move || {
                    client
                        .call::<_, Option<Answer>>(IPC_METHOD, &call)
                        .map(|_| ())
                        .map_err(|error| format!("close the supervisor IPC conversation: {error}"))
                })
                .await
            }
        }
    }

    async fn exchange(&mut self, request: &Request) -> Result<Answer, String> {
        match &mut self.inner {
            ConnectionInner::Stream(stream) => match stream {
                #[cfg(unix)]
                Stream::Unix(stream) => exchange_on(stream, request).await,
                Stream::Loopback(stream) => exchange_on(stream, request).await,
            },
            ConnectionInner::Ipc { client, connection } => {
                let mut ipc = client
                    .take()
                    .expect("the IPC client is restored after every call");
                let call = IpcCall {
                    connection: *connection,
                    body: IpcCallBody::Request(request.clone()),
                };
                let (ipc, answer) = smol::unblock(move || {
                    let answer = ipc
                        .call::<_, Option<Answer>>(IPC_METHOD, &call)
                        .map_err(|error| format!("supervisor IPC call: {error}"));
                    (ipc, answer)
                })
                .await;
                *client = Some(ipc);
                answer?.ok_or_else(|| {
                    "supervisor IPC answered a two-way request with nothing".to_owned()
                })
            }
        }
    }
}

async fn exchange_on<S>(stream: &mut S, request: &Request) -> Result<Answer, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    write_frame(stream, request).await?;
    read_frame(stream)
        .await?
        .ok_or_else(|| "supervisor closed the connection without answering".to_owned())
}
