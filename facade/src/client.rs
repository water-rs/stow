//! The facade side: one connection, one question, one answer — spoken
//! over blocking `std` streams, because the facade owns no tokio runtime
//! (stow#347).

use std::ffi::OsString;

use crate::endpoint::Endpoint;
use crate::protocol::{Answer, Compiled, Observed, Plan, Request};

/// What the supervisor decided for this invocation.
#[derive(Debug)]
pub enum Decision {
    /// The outputs are already in place; exit 0 without running rustc.
    Served,
    /// Run the real rustc, then call [`report`](SyncConnection::report)
    /// with its outcome.
    Compile(Ticket),
}

/// The supervisor's handle on a compile it asked the facade to run.
#[derive(Debug)]
pub struct Ticket {
    ticket: u64,
}

impl Ticket {
    /// Wrap a ticket number the wire carried — the driver's async side
    /// needs the same type the sync connection returns.
    #[must_use]
    pub const fn new(ticket: u64) -> Self {
        Self { ticket }
    }

    /// The supervisor-issued ticket number.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.ticket
    }
}

/// The synchronous facade connection: the fast-path wrapper owns no
/// tokio runtime, so it speaks the same frames over blocking `std`
/// streams (stow#347).
#[derive(Debug)]
pub struct SyncConnection {
    stream: SyncStream,
    token: String,
}

#[derive(Debug)]
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
    /// Any connection failure. The caller fails the build: an endpoint in
    /// the environment that cannot be reached means the supervisor died,
    /// and a build that quietly stops using the cache is the failure that
    /// hides.
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
        let request = Request::Observed(Observed {
            token: self.token.clone(),
            plan: Plan::new(self.token.clone(), executable, args),
            success: None,
        });
        match &mut self.stream {
            #[cfg(unix)]
            SyncStream::Unix(stream) => crate::protocol::write_frame_sync(stream, &request),
            SyncStream::Loopback(stream) => crate::protocol::write_frame_sync(stream, &request),
        }
    }

    /// Ask what to do with one rustc invocation — the one frame allowed
    /// to block rustc's start: the answer changes what the invocation
    /// does (stow#347).
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
    /// an ordinary-path report makes, over blocking streams.
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

    /// Report the finished compile for the deferred bookkeeping: one
    /// write like [`mark`](Self::mark), paid after rustc exits — the
    /// supervisor drops rather than answers the frame, so the facade's
    /// exit code path never waits on the socket (stow#347).
    ///
    /// # Errors
    ///
    /// Transport failures; a write error is the only failure it can have.
    pub fn report_observed(
        &mut self,
        executable: &std::ffi::OsStr,
        args: &[OsString],
        success: bool,
    ) -> Result<(), String> {
        let request = Request::Observed(Observed {
            token: self.token.clone(),
            plan: Plan::new(self.token.clone(), executable, args),
            success: Some(success),
        });
        match &mut self.stream {
            #[cfg(unix)]
            SyncStream::Unix(stream) => crate::protocol::write_frame_sync(stream, &request),
            SyncStream::Loopback(stream) => crate::protocol::write_frame_sync(stream, &request),
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
    crate::protocol::write_frame_sync(stream, request)?;
    crate::protocol::read_frame_sync::<_, Answer>(stream)?
        .ok_or_else(|| "supervisor closed the connection without answering".to_owned())
}
