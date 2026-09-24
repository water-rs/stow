//! The facade side: one connection, one question, one answer.
//!
//! The synchronous half the fast-path wrapper speaks lives in
//! `stow_facade::client` — re-exported here so `supervisor::client`
//! remains the one spelling for both transports.

use std::ffi::OsString;

use tokio::io::{AsyncRead, AsyncWrite};

use super::Endpoint;
use super::protocol::{Answer, Compiled, Plan, Request, read_frame, write_frame};

pub use stow_facade::client::{Decision, Ticket};

/// Connection to the supervisor, kept open across the plan and the report
/// so the compile's outcome reaches the same conversation.
pub struct Connection {
    stream: Stream,
    token: String,
}

enum Stream {
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    Loopback(tokio::net::TcpStream),
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
        let stream = match endpoint {
            #[cfg(unix)]
            Endpoint::Unix(path) => tokio::net::UnixStream::connect(path)
                .await
                .map(Stream::Unix)
                .map_err(|error| format!("connect to supervisor at {}: {error}", path.display()))?,
            Endpoint::Loopback(port) => tokio::net::TcpStream::connect(("127.0.0.1", *port))
                .await
                .map(Stream::Loopback)
                .map_err(|error| format!("connect to supervisor on port {port}: {error}"))?,
        };
        Ok(Self { stream, token })
    }

    /// Ask what to do with one rustc invocation.
    ///
    /// # Errors
    ///
    /// Transport failures, and a supervisor that answers with a failure
    /// of its own.
    pub async fn plan(
        &mut self,
        executable: &std::ffi::OsStr,
        args: &[OsString],
    ) -> Result<Decision, String> {
        let plan = Plan::new(self.token.clone(), executable, args);
        match self.exchange(&Request::Plan(plan)).await? {
            Answer::Served => Ok(Decision::Served),
            Answer::Compile { ticket } => Ok(Decision::Compile(Ticket::new(ticket))),
            Answer::Recorded => Err("supervisor answered a plan with a report ack".to_owned()),
            Answer::Failed { message } => Err(message),
        }
    }

    /// Report the compile the supervisor asked for.
    ///
    /// # Errors
    ///
    /// Transport failures, and a supervisor that answers with a failure
    /// of its own.
    pub async fn report(&mut self, ticket: &Ticket, success: bool) -> Result<(), String> {
        let report = Compiled {
            token: self.token.clone(),
            ticket: ticket.value(),
            success,
        };
        match self.exchange(&Request::Compiled(report)).await? {
            Answer::Recorded => Ok(()),
            Answer::Failed { message } => Err(message),
            Answer::Served | Answer::Compile { .. } => {
                Err("supervisor answered a report with a plan answer".to_owned())
            }
        }
    }

    async fn exchange(&mut self, request: &Request) -> Result<Answer, String> {
        match &mut self.stream {
            #[cfg(unix)]
            Stream::Unix(stream) => exchange_on(stream, request).await,
            Stream::Loopback(stream) => exchange_on(stream, request).await,
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
