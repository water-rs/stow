//! The daemon process: `stow daemon`.
//!
//! It takes `daemon.lock` without blocking, so a second daemon — one the
//! login trigger started beside a client's, say — finds the lock held and
//! exits 0. The holder removes a stale endpoint, binds its own, reports
//! readiness to the client that spawned it (`--ready <endpoint>`) and
//! serves. The lock is a file lock, so a dead daemon releases it and no
//! pid file is needed.
//!
//! A connection says what it is in its `Hello`. A *control* connection
//! belongs to a driver: it asks for status, or opens one build's session
//! and then owns it for as long as the connection lives. A *wrapper*
//! connection belongs to one rustc or C/C++ wrapper of a session and can
//! decode only the requests such a wrapper makes.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use stow_types::error::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::Instrument as _;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer as _};

use super::events::{LogInterest, SessionLogs};
use super::log::LogWriter;
use super::notify::{self, Notification};
use super::protocol::{
    ControlRequest, Event, Frame, Hello, PROTOCOL, PROTOCOL_FLOOR, Response, Role, SessionRef,
    WrapperRequest, read_frame_async, speaks, write_frame_async,
};
use super::session::{CacheDirHandles, Session, SessionFacts, SessionId};
use super::table::SessionTable;
use super::{RunDir, Settings};
use crate::daemon::session::handler::{Flight, Handler, InFlightUnits, Reports, answer_and_book};
use crate::daemon::wrapper::Answer;
use crate::file_lock::FileLock;

#[cfg(unix)]
type Listener = tokio::net::UnixListener;

#[cfg(windows)]
struct Listener {
    name: PathBuf,
    server: tokio::net::windows::named_pipe::NamedPipeServer,
}

/// What every connection of one daemon shares.
#[derive(Debug, Clone)]
struct Daemon {
    /// Where the sessions' directories live.
    sessions: PathBuf,
    settings: Settings,
    /// The routes carrying a session's events to the driver that owns it.
    logs: SessionLogs,
    table: SessionTable,
}

/// Run the daemon until it fails. Returns `Ok` only when another daemon
/// already holds the lock.
pub async fn run(ready: Option<PathBuf>) -> Result<()> {
    let logs = SessionLogs::default();
    let run_dir = blocking({
        let logs = logs.clone();
        move || {
            let run_dir = RunDir::prepare(RunDir::locate()?)?;
            install_logging(&run_dir, &logs)?;
            Ok(run_dir)
        }
    })
    .await?;
    tracing::info!(
        pid = std::process::id(),
        version = env!("CARGO_PKG_VERSION"),
        run_dir = %run_dir.path().display(),
        "stow daemon process started"
    );
    let lock_path = run_dir.daemon_lock();
    let Some(_lock) = blocking(move || take_lock(&lock_path)).await? else {
        tracing::info!("another stow daemon holds the lock; exiting");
        notify_ready(ready, Notification::LockHeld).await?;
        return Ok(());
    };
    // The lock is held, so no process of a previous daemon is alive: every
    // session directory under the run directory is a dead build's.
    let sessions = run_dir.sessions();
    let swept = blocking({
        let sessions = sessions.clone();
        move || sweep_sessions(&sessions)
    })
    .await?;
    if swept > 0 {
        tracing::info!(swept, "removed the sessions a previous daemon left");
    }
    let endpoint = run_dir.endpoint();
    let listener = bind(&endpoint).await?;
    let daemon = Daemon {
        sessions,
        settings: blocking(Settings::from_env).await?,
        logs,
        table: SessionTable::start(),
    };
    tracing::info!(
        pid = std::process::id(),
        endpoint = %endpoint.display(),
        "stow daemon serving"
    );
    notify_ready(ready, Notification::Ready).await?;
    accept_loop(listener, daemon).await
}

/// Run `work` off the executor: it does file work.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .wrap_err("run the daemon's blocking work")?
}

/// Remove every session directory under `sessions`, returning how many.
fn sweep_sessions(sessions: &Path) -> Result<usize> {
    let entries = match std::fs::read_dir(sessions) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            return Err(error).wrap_err_with(|| format!("list {}", sessions.display()));
        }
    };
    let mut swept = 0;
    for entry in entries {
        let path = entry
            .wrap_err_with(|| format!("list {}", sessions.display()))?
            .path();
        std::fs::remove_dir_all(&path)
            .wrap_err_with(|| format!("remove the dead session {}", path.display()))?;
        swept += 1;
    }
    Ok(swept)
}

/// Send the client that spawned this daemon its notification, when it
/// asked for one.
async fn notify_ready(ready: Option<PathBuf>, notification: Notification) -> Result<()> {
    let Some(endpoint) = ready else {
        return Ok(());
    };
    blocking(move || notify::send(&endpoint, notification)).await
}

/// The daemon writes its own log in the runtime directory: its stderr is
/// the null device, so nothing it says would otherwise be kept. Events
/// recorded for a session are also routed to the driver that owns it; that
/// layer sees every level, and only the log file is filtered.
fn install_logging(run_dir: &RunDir, logs: &SessionLogs) -> Result<()> {
    let writer = LogWriter::open(&run_dir.log(), Settings::from_env()?.log_bytes)?;
    // The daemon's environment is cleared, so `RUST_LOG` only reaches it
    // when started by hand; the default is what a log of a long-lived
    // process should carry.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let file = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .with_ansi(false)
        .with_filter(filter);
    tracing_subscriber::registry()
        .with(logs.layer())
        .with(file)
        .try_init()
        .map_err(|error| stow_types::stow_error!("install the daemon log: {error}"))
}

fn take_lock(path: &Path) -> Result<Option<FileLock>> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .wrap_err_with(|| format!("open {}", path.display()))?;
    FileLock::try_exclusive(file).wrap_err_with(|| format!("lock {}", path.display()))
}

/// Bind the endpoint, which only the lock's holder may do: whatever is
/// already at the address is a dead daemon's.
#[cfg(unix)]
async fn bind(endpoint: &Path) -> Result<Listener> {
    let stale = endpoint.to_owned();
    blocking(move || match std::fs::remove_file(&stale) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).wrap_err_with(|| format!("remove the stale {}", stale.display())),
    })
    .await?;
    let listener = Listener::bind(endpoint)
        .wrap_err_with(|| format!("bind the daemon endpoint {}", endpoint.display()))?;
    // A socket file is created `rwxrwxrwx` minus the umask, so even under
    // 077 it carries an execute bit. The runtime directory is owner-only,
    // which keeps the window before this call closed to everyone else.
    let socket = endpoint.to_owned();
    blocking(move || {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .wrap_err_with(|| format!("restrict {}", socket.display()))
    })
    .await?;
    Ok(listener)
}

/// Create the first instance of the pipe: it fails when any other process
/// already owns the name, which is the squatting this flag exists to catch.
#[cfg(windows)]
async fn bind(endpoint: &Path) -> Result<Listener> {
    let server = super::windows::create_server(endpoint, true)
        .wrap_err_with(|| format!("create the daemon pipe {}", endpoint.display()))?;
    Ok(Listener {
        name: endpoint.to_owned(),
        server,
    })
}

#[cfg(unix)]
async fn accept_loop(listener: Listener, daemon: Daemon) -> Result<()> {
    let mut connections = JoinSet::new();
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .wrap_err("accept a daemon connection")?;
        connections.spawn(serve_connection(stream, daemon.clone()));
        reap(&mut connections);
    }
}

#[cfg(windows)]
async fn accept_loop(mut listener: Listener, daemon: Daemon) -> Result<()> {
    let mut connections = JoinSet::new();
    loop {
        listener
            .server
            .connect()
            .await
            .wrap_err("accept a daemon connection")?;
        // The next instance exists before the connected one is served, so
        // the name never has a moment with none to connect to.
        let next = super::windows::create_server(&listener.name, false)
            .wrap_err("create the next daemon pipe instance")?;
        let connected = std::mem::replace(&mut listener.server, next);
        connections.spawn(serve_connection(connected, daemon.clone()));
        reap(&mut connections);
    }
}

/// Log the connections that have finished.
fn reap(connections: &mut JoinSet<Result<()>>) {
    while let Some(joined) = connections.try_join_next() {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(%error, "daemon connection failed"),
            Err(error) => tracing::error!(%error, "daemon connection task panicked"),
        }
    }
}

/// One client: its `Hello`, then what its role asks until it hangs up.
async fn serve_connection<S>(mut stream: S, daemon: Daemon) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some(first) = read_frame_async(&mut stream).await? else {
        return Ok(());
    };
    let hello = match check_hello(&first) {
        Ok(hello) => hello,
        Err(reason) => {
            tracing::warn!(%reason, "daemon connection refused");
            return reject(&mut stream, reason).await;
        }
    };
    match hello.role {
        Role::Control => serve_control(stream, &daemon).await,
        Role::Wrapper {
            session: SessionRef::Id(id),
        } => serve_wrapper(stream, &daemon, id).await,
    }
}

fn check_hello(first: &Frame) -> std::result::Result<Hello, String> {
    if !speaks(first.protocol) {
        return Err(protocol_mismatch(first.protocol));
    }
    let hello = first
        .decode::<Hello>()
        .map_err(|error| format!("the first frame must be a Hello: {error}"))?;
    if !speaks(hello.protocol) {
        return Err(protocol_mismatch(hello.protocol));
    }
    tracing::debug!(client_version = %hello.stow_version, "daemon client connected");
    Ok(hello)
}

fn protocol_mismatch(peer: u16) -> String {
    format!(
        "the client speaks protocol {peer}, this daemon speaks protocols {PROTOCOL_FLOOR} through {PROTOCOL}"
    )
}

async fn reject<S: AsyncWrite + Unpin + Send>(stream: &mut S, reason: String) -> Result<()> {
    write_frame_async(stream, &Response::Rejected { reason }).await
}

/// A driver's connection: status requests, until it opens a session and
/// the connection becomes the session's.
async fn serve_control<S>(mut stream: S, daemon: &Daemon) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    while let Some(frame) = read_frame_async(&mut stream).await? {
        if !speaks(frame.protocol) {
            return reject(&mut stream, protocol_mismatch(frame.protocol)).await;
        }
        match frame.decode::<ControlRequest>() {
            Ok(ControlRequest::Status) => {
                write_frame_async(
                    &mut stream,
                    &Response::Status {
                        stow_version: env!("CARGO_PKG_VERSION").to_owned(),
                        protocol: PROTOCOL,
                    },
                )
                .await?;
            }
            Ok(ControlRequest::OpenSession(facts)) => {
                return serve_session(stream, daemon, *facts).await;
            }
            Ok(ControlRequest::EndSession) => {
                return reject(
                    &mut stream,
                    "no session is open on this connection".to_owned(),
                )
                .await;
            }
            Err(error) => return reject(&mut stream, error.to_string()).await,
        }
    }
    Ok(())
}

/// The events a driver wants back from its session: what its `RUST_LOG`
/// selects, and everything stow's own crates record when it writes a trace
/// file.
fn interest_of(facts: &SessionFacts) -> LogInterest {
    let var = |name: &str| {
        facts
            .build
            .environ
            .iter()
            .find(|(key, _)| stow_types::env_name::eq(key, name))
            .map(|(_, value)| value)
    };
    let rust_log = var("RUST_LOG").and_then(|value| value.to_str());
    let trace_file = var(crate::STOW_TRACE_FILE_ENV).is_some();
    // A `RUST_LOG` the filter parser rejects falls back to the driver's
    // terminal default, as the driver's own subscriber does.
    LogInterest::new(rust_log, trace_file).unwrap_or_else(|reason| {
        tracing::warn!(%reason, "ignoring the driver's RUST_LOG for its session's events");
        LogInterest::new(None, trace_file).expect("the default filter parses")
    })
}

/// Open the session `facts` describe and serve its control connection
/// until the driver ends the session or goes away.
async fn serve_session<S>(stream: S, daemon: &Daemon, facts: SessionFacts) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut read, mut write) = tokio::io::split(stream);
    let id = SessionId::mint();
    // The route exists before the session's tasks do, so none of their
    // events is recorded without one.
    let mut events = daemon.logs.register(id, interest_of(&facts));
    let handles = match &facts.build.config {
        Some(config) => daemon.table.handles_for(config.cache_dir.clone()).await,
        None => CacheDirHandles::default(),
    };
    let session = match Session::open(id, facts, &handles, &daemon.sessions).await {
        Ok(session) => session,
        Err(error) => {
            daemon.logs.unregister(id);
            tracing::warn!(%error, "a session could not be opened");
            return reject(&mut write, format!("{error:#}")).await;
        }
    };
    daemon.table.insert(Arc::clone(&session));
    tracing::info!(session = %id, "opened a session");
    // The answer to `OpenSession` precedes every event the session's tasks
    // have recorded: those wait in `events` until the drive loop forwards
    // them.
    let answered = write_frame_async(&mut write, &Response::SessionOpened { session: id }).await;
    let driven = match answered {
        Ok(()) => drive_session(&mut read, &mut write, &session, &mut events).await,
        Err(error) => Err(error),
    };
    // Removed first, so a wrapper arriving from here on is refused rather
    // than answered by a session that is closing.
    daemon.table.remove(id);
    let finished = match driven {
        Ok(Driven::Ended) => Ok(()),
        Ok(Driven::DriverGone) => {
            tracing::info!(session = %id, "the driver of a session went away; ending it");
            session.abort().await
        }
        Err(error) => {
            // The connection broke under the session: the driver is gone
            // for the purposes of its build.
            tracing::warn!(session = %id, %error, "a session's control connection failed; ending it");
            session.abort().await
        }
    };
    daemon.logs.unregister(id);
    finished
}

/// How a session's control connection ended.
enum Driven {
    /// The driver asked for the end and was answered.
    Ended,
    /// The connection closed before the driver ended the session.
    DriverGone,
}

/// Forward the session's events to its driver and wait for it to end the
/// session. Reads happen on a task of their own: a frame read is not
/// cancel-safe, and this loop also waits on the events.
async fn drive_session<R, W>(
    read: &mut R,
    write: &mut W,
    session: &Arc<Session>,
    events: &mut mpsc::UnboundedReceiver<Event>,
) -> Result<Driven>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let resolution_done = session.resolution_done();
    let mut resolution_sent = false;
    let id = session.id();
    // The reader is scoped to this call, so it ends with it.
    let (frames, mut inbox) = mpsc::channel::<Result<Frame>>(1);
    let read = &mut *read;
    let reading = async move {
        loop {
            match read_frame_async(read).await {
                Ok(Some(frame)) => {
                    if frames.send(Ok(frame)).await.is_err() {
                        return;
                    }
                }
                Ok(None) => return,
                Err(error) => {
                    let _ = frames.send(Err(error)).await;
                    return;
                }
            }
        }
    };
    let serving = async {
        loop {
            tokio::select! {
                frame = inbox.recv() => {
                    let Some(frame) = frame else {
                        return Ok::<_, stow_types::error::Error>(Driven::DriverGone);
                    };
                    let frame = frame?;
                    if !speaks(frame.protocol) {
                        reject(write, protocol_mismatch(frame.protocol)).await?;
                        return Ok(Driven::DriverGone);
                    }
                    match frame.decode::<ControlRequest>() {
                        Ok(ControlRequest::EndSession) => {
                            let end = session.end().await?;
                            // What the session recorded before it ended
                            // reaches the driver ahead of the answer.
                            while let Ok(event) = events.try_recv() {
                                write_frame_async(write, &Response::Event(event)).await?;
                            }
                            write_frame_async(write, &Response::SessionEnded(end)).await?;
                            tracing::info!(session = %id, "ended a session");
                            return Ok(Driven::Ended);
                        }
                        Ok(other) => {
                            reject(
                                write,
                                format!("a session's connection takes only EndSession, not {other:?}"),
                            )
                            .await?;
                            return Ok(Driven::DriverGone);
                        }
                        Err(error) => {
                            reject(write, error.to_string()).await?;
                            return Ok(Driven::DriverGone);
                        }
                    }
                }
                Some(event) = events.recv() => {
                    write_frame_async(write, &Response::Event(event)).await?;
                }
                () = resolution_done.wait(), if !resolution_sent => {
                    resolution_sent = true;
                    write_frame_async(write, &Response::Event(Event::ResolutionDone)).await?;
                }
            }
        }
    };
    tokio::pin!(reading);
    tokio::pin!(serving);
    // `reading` finishes only by dropping its sender, which `serving`
    // observes as the driver going away; it is polled alongside so it
    // makes progress.
    tokio::select! {
        driven = &mut serving => driven,
        () = &mut reading => (&mut serving).await,
    }
}

/// One wrapper's conversation with its session: a request, its answer,
/// until the wrapper hangs up — which ends a flight it still holds.
async fn serve_wrapper<S>(mut stream: S, daemon: &Daemon, id: SessionId) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some(session) = daemon.table.join(id).await else {
        return reject(
            &mut stream,
            format!("no session {id}: the stow daemon restarted or the build that opened it ended"),
        )
        .await;
    };
    let every = daemon.settings.answer / 2;
    let span = session.span().clone();
    async {
        let mut flight = None;
        while let Some(frame) = read_frame_async(&mut stream).await? {
            if !speaks(frame.protocol) {
                return reject(&mut stream, protocol_mismatch(frame.protocol)).await;
            }
            let request = match frame.decode::<WrapperRequest>() {
                Ok(request) => request,
                Err(error) => return reject(&mut stream, error.to_string()).await,
            };
            let answer = answer_with_progress(
                &mut stream,
                &session,
                session.in_flight(),
                session.reports(),
                &mut flight,
                request,
                every,
            )
            .await?;
            write_frame_async(&mut stream, &Response::Answer(answer)).await?;
        }
        Ok(())
    }
    .instrument(span)
    .await
}

/// Answer `request`, telling the wrapper every `every` that the decision
/// is still being made: a wrapper bounds its wait for a frame, and a
/// decision that fetches from the network legitimately outlasts that.
async fn answer_with_progress<S, H>(
    stream: &mut S,
    handler: &Arc<H>,
    in_flight: &InFlightUnits,
    reports: &Reports,
    flight: &mut Option<Flight<H::Pending>>,
    request: WrapperRequest,
    every: Duration,
) -> Result<Answer>
where
    S: AsyncWrite + Unpin + Send,
    H: Handler,
{
    let answering = answer_and_book(handler, in_flight, reports, flight, request);
    tokio::pin!(answering);
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    loop {
        tokio::select! {
            answer = &mut answering => return Ok(answer),
            _ = tick.tick() => write_frame_async(stream, &Response::Working).await?,
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::ffi::OsString;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::{AsyncWriteExt as _, DuplexStream};

    use super::{Daemon, answer_with_progress, serve_connection, sweep_sessions};
    use crate::daemon::Settings;
    use crate::daemon::events::SessionLogs;
    use crate::daemon::protocol::{
        ControlRequest, Hello, PROTOCOL, Response, Role, SessionRef, WrapperRequest, encode,
        read_frame_async,
    };
    use crate::daemon::session::handler::{Decision, Flight, Handler, InFlightUnits, Reports};
    use crate::daemon::session::invocation::{OutputRoots, RefusalPolicy};
    use crate::daemon::session::{SessionFacts, SessionId};
    use crate::daemon::table::SessionTable;
    use crate::daemon::wrapper::{Answer, InvocationEnv, Plan};
    use crate::toolchain::BuildToolchain;

    fn daemon(sessions: &std::path::Path) -> Daemon {
        Daemon {
            sessions: sessions.to_owned(),
            settings: Settings {
                answer: Duration::from_millis(60),
                start: Duration::from_secs(30),
                log_bytes: 1 << 20,
            },
            logs: SessionLogs::default(),
            table: SessionTable::start(),
        }
    }

    /// One connection to `daemon`, served on a task of its own.
    fn connect(
        daemon: &Daemon,
    ) -> (
        DuplexStream,
        tokio::task::JoinHandle<stow_types::error::Result<()>>,
    ) {
        let (client, daemon_end) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(serve_connection(daemon_end, daemon.clone()));
        (client, task)
    }

    async fn send<T: serde::Serialize + Sync>(stream: &mut DuplexStream, message: &T) {
        stream
            .write_all(&encode(message).expect("encode"))
            .await
            .expect("write");
    }

    async fn receive(stream: &mut DuplexStream) -> Response {
        read_frame_async(stream)
            .await
            .expect("read")
            .expect("a frame")
            .decode::<Response>()
            .expect("response")
    }

    /// Facts over the test machine's own rustc whose outputs live under
    /// `target`.
    async fn facts(target: &std::path::Path) -> SessionFacts {
        SessionFacts::for_tests(
            BuildToolchain::for_tests().await.facts(),
            OutputRoots::new(target.to_owned(), None),
            RefusalPolicy::FailBuild,
        )
    }

    /// Open a session on `daemon` the way a driver does; returns the
    /// control connection, which owns the session, and the session's id.
    async fn open(
        daemon: &Daemon,
        target: &std::path::Path,
    ) -> (
        DuplexStream,
        tokio::task::JoinHandle<stow_types::error::Result<()>>,
        SessionId,
    ) {
        let (mut control, task) = connect(daemon);
        send(&mut control, &Hello::new(Role::Control)).await;
        send(
            &mut control,
            &ControlRequest::OpenSession(Box::new(facts(target).await)),
        )
        .await;
        let Response::SessionOpened { session } = receive(&mut control).await else {
            panic!("the session did not open");
        };
        (control, task, session)
    }

    async fn plan_in(daemon: &Daemon, session: SessionId, out_dir: &std::path::Path) -> Response {
        let (mut wrapper, task) = connect(daemon);
        send(
            &mut wrapper,
            &Hello::new(Role::Wrapper {
                session: SessionRef::Id(session),
            }),
        )
        .await;
        let toolchain = BuildToolchain::for_tests().await;
        let args: Vec<OsString> = ["--crate-name", "demo", "--crate-type", "lib", "--out-dir"]
            .into_iter()
            .map(OsString::from)
            .chain([out_dir.as_os_str().to_owned()])
            .collect();
        send(
            &mut wrapper,
            &WrapperRequest::Plan(Plan::new(
                toolchain.rustc().as_os_str(),
                &args,
                InvocationEnv::for_tests(),
            )),
        )
        .await;
        let response = loop {
            match receive(&mut wrapper).await {
                Response::Working => {}
                other => break other,
            }
        };
        wrapper.shutdown().await.expect("shutdown");
        task.await.expect("join").expect("served");
        response
    }

    #[tokio::test]
    async fn a_wrapper_connection_cannot_open_a_session() {
        let sessions = tempfile::tempdir().expect("sessions");
        let target = tempfile::tempdir().expect("target");
        let daemon = daemon(sessions.path());
        let (control, _task, id) = open(&daemon, target.path()).await;
        let (mut wrapper, task) = connect(&daemon);
        send(
            &mut wrapper,
            &Hello::new(Role::Wrapper {
                session: SessionRef::Id(id),
            }),
        )
        .await;
        send(
            &mut wrapper,
            &ControlRequest::OpenSession(Box::new(facts(target.path()).await)),
        )
        .await;
        assert!(
            matches!(receive(&mut wrapper).await, Response::Rejected { .. }),
            "a wrapper's connection decodes no OpenSession"
        );
        task.await.expect("join").expect("served");
        drop(control);
    }

    #[tokio::test]
    async fn a_wrapper_naming_an_unknown_session_is_rejected() {
        let sessions = tempfile::tempdir().expect("sessions");
        let daemon = daemon(sessions.path());
        let (mut wrapper, task) = connect(&daemon);
        send(
            &mut wrapper,
            &Hello::new(Role::Wrapper {
                session: SessionRef::Id(SessionId::mint()),
            }),
        )
        .await;
        let Response::Rejected { reason } = receive(&mut wrapper).await else {
            panic!("an unknown session must be rejected");
        };
        assert!(reason.contains("no session"), "{reason}");
        task.await.expect("join").expect("served");
    }

    #[tokio::test]
    async fn a_session_ends_when_its_control_connection_closes() {
        let sessions = tempfile::tempdir().expect("sessions");
        let target = tempfile::tempdir().expect("target");
        let daemon = daemon(sessions.path());
        let (mut control, task, id) = open(&daemon, target.path()).await;
        assert!(sessions.path().join(id.to_string()).is_dir());
        control
            .shutdown()
            .await
            .expect("close the control connection");
        task.await.expect("join").expect("served");
        assert!(
            !sessions.path().join(id.to_string()).exists(),
            "the session's directory goes with it"
        );
        assert!(
            daemon.table.join(id).await.is_none(),
            "the session is no longer joinable"
        );
    }

    #[tokio::test]
    async fn an_out_dir_in_another_sessions_target_is_refused() {
        let sessions = tempfile::tempdir().expect("sessions");
        let target_a = tempfile::tempdir().expect("target a");
        let target_b = tempfile::tempdir().expect("target b");
        let daemon = daemon(sessions.path());
        let (_control_a, _task_a, session_a) = open(&daemon, target_a.path()).await;
        let (_control_b, _task_b, _session_b) = open(&daemon, target_b.path()).await;
        let Response::Answer(Answer::Failed { message }) =
            plan_in(&daemon, session_a, target_b.path()).await
        else {
            panic!("a request naming another build's directory must fail");
        };
        assert!(message.contains("out-dir"), "{message}");
    }

    /// A handler whose plan takes longer than the progress interval.
    struct Slow {
        toolchain: Arc<BuildToolchain>,
    }

    impl Handler for Slow {
        type Pending = ();

        async fn plan(
            self: &Arc<Self>,
            _invocation: crate::daemon::session::invocation::VerifiedInvocation,
            _env: InvocationEnv,
        ) -> Decision<()> {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Decision::Compile(())
        }

        async fn compiled(self: &Arc<Self>, (): (), _success: bool, _time: Duration) {}

        fn toolchain(self: &Arc<Self>) -> &Arc<BuildToolchain> {
            &self.toolchain
        }

        fn refusal_policy(self: &Arc<Self>) -> RefusalPolicy {
            RefusalPolicy::FailBuild
        }

        fn refused(self: &Arc<Self>, _refusal: crate::daemon::session::invocation::Refusal) {}
    }

    #[tokio::test]
    async fn a_slow_plan_keeps_the_wrapper_waiting_through_working_frames() {
        let toolchain = Arc::new(BuildToolchain::for_tests().await);
        let handler = Arc::new(Slow {
            toolchain: Arc::clone(&toolchain),
        });
        let (mut wrapper, mut daemon_end) = tokio::io::duplex(1 << 20);
        let mut flight: Option<Flight<()>> = None;
        let args = [OsString::from("--crate-name"), OsString::from("demo")];
        let request = WrapperRequest::Plan(Plan::new(
            toolchain.rustc().as_os_str(),
            &args,
            InvocationEnv::for_tests(),
        ));
        let answer = answer_with_progress(
            &mut daemon_end,
            &handler,
            &InFlightUnits::default(),
            &Reports::default(),
            &mut flight,
            request,
            Duration::from_millis(20),
        )
        .await
        .expect("answered");
        assert!(matches!(answer, Answer::Compile(_)), "{answer:?}");
        drop(daemon_end);
        let mut working = 0;
        while let Some(frame) = read_frame_async(&mut wrapper).await.expect("read") {
            assert_eq!(
                frame.decode::<Response>().expect("response"),
                Response::Working
            );
            working += 1;
        }
        assert!(
            working >= 2,
            "a 100 ms plan outlasts several 20 ms intervals: {working}"
        );
    }

    #[test]
    fn a_daemon_start_sweeps_dead_sessions() {
        let sessions = tempfile::tempdir().expect("sessions");
        for name in ["a", "b"] {
            let dir = sessions.path().join(name);
            std::fs::create_dir_all(dir.join("local-build")).expect("session dir");
            std::fs::write(dir.join("local-build").join("mark"), b"x").expect("mark");
        }
        assert_eq!(sweep_sessions(sessions.path()).expect("sweep"), 2);
        assert_eq!(std::fs::read_dir(sessions.path()).expect("list").count(), 0);
        assert_eq!(
            sweep_sessions(&sessions.path().join("missing")).expect("a missing directory"),
            0
        );
    }

    #[tokio::test]
    async fn status_after_hello_reports_version_and_protocol() {
        let sessions = tempfile::tempdir().expect("sessions");
        let (mut client, _task) = connect(&daemon(sessions.path()));
        send(&mut client, &Hello::new(Role::Control)).await;
        send(&mut client, &ControlRequest::Status).await;
        assert_eq!(
            receive(&mut client).await,
            Response::Status {
                stow_version: env!("CARGO_PKG_VERSION").to_owned(),
                protocol: PROTOCOL,
            }
        );
    }

    #[tokio::test]
    async fn a_first_frame_that_is_not_a_hello_is_rejected() {
        let sessions = tempfile::tempdir().expect("sessions");
        let (mut client, _task) = connect(&daemon(sessions.path()));
        send(&mut client, &ControlRequest::Status).await;
        assert!(matches!(
            receive(&mut client).await,
            Response::Rejected { .. }
        ));
    }

    #[tokio::test]
    async fn a_hello_for_another_protocol_is_rejected_naming_both() {
        let sessions = tempfile::tempdir().expect("sessions");
        let (mut client, _task) = connect(&daemon(sessions.path()));
        send(
            &mut client,
            &Hello {
                protocol: PROTOCOL + 1,
                stow_version: "9.9.9".to_owned(),
                role: Role::Control,
            },
        )
        .await;
        let Response::Rejected { reason } = receive(&mut client).await else {
            panic!("a newer protocol must be rejected");
        };
        assert!(
            reason.contains(&(PROTOCOL + 1).to_string()) && reason.contains(&PROTOCOL.to_string()),
            "{reason}"
        );
    }
}
