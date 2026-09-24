//! The facade side: one connection, one question, one answer.

use std::ffi::OsString;

use tokio::io::{AsyncRead, AsyncWrite};

use super::Endpoint;
use super::protocol::{Answer, Compiled, Plan, Request, read_frame, write_frame};

/// What the supervisor decided for this invocation.
#[derive(Debug)]
pub enum Decision {
    /// The outputs are already in place; exit 0 without running rustc.
    Served,
    /// Run the real rustc, then call [`report`] with its outcome.
    Compile(Ticket),
}

/// The supervisor's handle on a compile it asked the facade to run.
#[derive(Debug)]
pub struct Ticket {
    ticket: u64,
}

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
    /// Transport failures, and a supervisor that answers with a failure of
    /// its own.
    pub async fn plan(
        &mut self,
        executable: &std::ffi::OsStr,
        args: &[OsString],
    ) -> Result<Decision, String> {
        let plan = Plan::new(self.token.clone(), executable, args);
        match self.exchange(&Request::Plan(plan)).await? {
            Answer::Served => Ok(Decision::Served),
            Answer::Compile { ticket } => Ok(Decision::Compile(Ticket { ticket })),
            Answer::Recorded => Err("supervisor answered a plan with a report ack".to_owned()),
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

/// The synchronous facade connection: the fast-path wrapper owns no
/// tokio runtime, so it speaks the same frames over blocking `std`
/// streams (stow#347).
pub struct SyncConnection {
    stream: SyncStream,
    token: String,
}

enum SyncStream {
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
    Loopback(std::net::TcpStream),
}

impl SyncConnection {
    /// Connect to `endpoint`, blocking.
    ///
    /// # Errors
    ///
    /// Same contract as [`Connection::open`]: a dead supervisor fails the
    /// build loudly rather than degrading it.
    pub fn open(endpoint: &Endpoint, token: String) -> Result<Self, String> {
        let stream = match endpoint {
            #[cfg(unix)]
            Endpoint::Unix(path) => std::os::unix::net::UnixStream::connect(path)
                .map(SyncStream::Unix)
                .map_err(|error| format!("connect to supervisor at {}: {error}", path.display()))?,
            Endpoint::Loopback(port) => std::net::TcpStream::connect(("127.0.0.1", *port))
                .map(SyncStream::Loopback)
                .map_err(|error| format!("connect to supervisor on port {port}: {error}"))?,
        };
        Ok(Self { stream, token })
    }

    /// Record that this invocation is compiling, ahead of rustc — the
    /// provenance mark a dependent's plan consults. One write, no answer
    /// awaited: the mark does not block rustc's start.
    ///
    /// # Errors
    ///
    /// Transport failures; the supervisor drops the frame itself, so a
    /// write error is the only failure it can have.
    pub fn mark(&mut self, executable: &std::ffi::OsStr, args: &[OsString]) -> Result<(), String> {
        let request = Request::Observed(super::protocol::Observed {
            token: self.token.clone(),
            plan: Plan::new(self.token.clone(), executable, args),
            success: None,
        });
        match &mut self.stream {
            #[cfg(unix)]
            SyncStream::Unix(stream) => super::protocol::write_frame_sync(stream, &request),
            SyncStream::Loopback(stream) => super::protocol::write_frame_sync(stream, &request),
        }
    }

    /// Ask what to do with one rustc invocation — the same round trip
    /// [`Connection::plan`] makes, over blocking streams. This is the one
    /// frame allowed to block rustc's start: the answer changes what the
    /// invocation does (stow#347).
    ///
    /// # Errors
    ///
    /// Transport failures, and a supervisor that answers with a failure
    /// of its own.
    pub fn plan(
        &mut self,
        executable: &std::ffi::OsStr,
        args: &[OsString],
    ) -> Result<Decision, String> {
        let plan = Plan::new(self.token.clone(), executable, args);
        match self.exchange(&Request::Plan(plan))? {
            Answer::Served => Ok(Decision::Served),
            Answer::Compile { ticket } => Ok(Decision::Compile(Ticket { ticket })),
            Answer::Recorded => Err("supervisor answered a plan with a report ack".to_owned()),
            Answer::Failed { message } => Err(message),
        }
    }

    /// Report the compile the supervisor asked for — the same round trip
    /// [`Connection::report`] makes, over blocking streams.
    ///
    /// # Errors
    ///
    /// Transport failures, and a supervisor that answers with a failure
    /// of its own.
    pub fn report(&mut self, ticket: &Ticket, success: bool) -> Result<(), String> {
        let report = Compiled {
            token: self.token.clone(),
            ticket: ticket.ticket,
            success,
        };
        match self.exchange(&Request::Compiled(report))? {
            Answer::Recorded => Ok(()),
            Answer::Failed { message } => Err(message),
            Answer::Served | Answer::Compile { .. } => {
                Err("supervisor answered a report with a plan answer".to_owned())
            }
        }
    }

    /// Report the finished compile for the deferred bookkeeping. One
    /// round trip, paid after rustc exits.
    ///
    /// # Errors
    ///
    /// Transport failures, and a supervisor that answers with a failure
    /// of its own.
    pub fn report_observed(
        &mut self,
        executable: &std::ffi::OsStr,
        args: &[OsString],
        success: bool,
    ) -> Result<(), String> {
        let request = Request::Observed(super::protocol::Observed {
            token: self.token.clone(),
            plan: Plan::new(self.token.clone(), executable, args),
            success: Some(success),
        });
        match self.exchange(&request)? {
            Answer::Recorded => Ok(()),
            Answer::Failed { message } => Err(message),
            Answer::Served | Answer::Compile { .. } => {
                Err("supervisor answered a report with a plan answer".to_owned())
            }
        }
    }

    fn exchange(&mut self, request: &Request) -> Result<Answer, String> {
        match &mut self.stream {
            #[cfg(unix)]
            SyncStream::Unix(stream) => exchange_sync_on(stream, request),
            SyncStream::Loopback(stream) => exchange_sync_on(stream, request),
        }
    }
}

fn exchange_sync_on<S>(stream: &mut S, request: &Request) -> Result<Answer, String>
where
    S: std::io::Read + std::io::Write,
{
    super::protocol::write_frame_sync(stream, request)?;
    super::protocol::read_frame_sync::<_, Answer>(stream)?
        .ok_or_else(|| "supervisor closed the connection without answering".to_owned())
}
