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
use super::owner::{self, CargoOwner, OsProcesses, Processes};
use super::protocol::{
    ControlRequest, Event, Frame, Hello, PROTOCOL, PROTOCOL_FLOOR, Response, Role, SessionRef,
    WrapperRequest, read_frame_async, speaks, write_frame_async,
};
use super::session::{
    CacheDirHandles, Cargo, Opener, Origin, Session, SessionFacts, SessionId, keep_only_owner,
    open_facts, os_bytes, recorded_owner,
};
use super::table::SessionTable;
use super::{RunDir, Settings};
use crate::daemon::session::handler::answer_and_book;
use crate::daemon::wrapper::{Answer, BuildEnvironment, CompileCommand};
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
struct Daemon<P> {
    /// Where the sessions' directories live.
    sessions: PathBuf,
    settings: Settings,
    /// The routes carrying a session's events to the driver that owns it.
    logs: SessionLogs,
    table: SessionTable,
    /// The machine's processes: which cargo a wrapper runs under, and when
    /// it exits.
    processes: P,
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
    // session directory under the run directory is a dead build's. A cargo
    // that is still running keeps only the record of its owner: its build
    // lost the session's in-flight state and provenance marks, so its
    // wrappers are refused until it exits.
    let sessions = run_dir.sessions();
    let swept = blocking({
        let sessions = sessions.clone();
        move || sweep_sessions(&sessions, &OsProcesses)
    })
    .await?;
    if swept.removed > 0 {
        tracing::info!(
            swept = swept.removed,
            "removed the sessions a previous daemon left"
        );
    }
    let endpoint = run_dir.endpoint();
    let listener = bind(&endpoint).await?;
    let daemon = Daemon {
        sessions,
        settings: blocking(Settings::from_env).await?,
        logs,
        table: SessionTable::start(),
        processes: OsProcesses,
    };
    for outlived in swept.outlived {
        refuse_until_exit(&daemon, outlived);
    }
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

/// What a start of the daemon found under the sessions directory.
#[derive(Debug, Default)]
struct Swept {
    /// The session directories removed.
    removed: usize,
    /// The cargos still running whose session a previous daemon held.
    outlived: Vec<Outlived>,
}

/// A cargo that outlived the daemon that held its session, and the
/// directory that records it.
#[derive(Debug)]
struct Outlived {
    owner: CargoOwner,
    dir: PathBuf,
}

/// Remove every session directory under `sessions`, except the owner
/// record of a cargo that is still running.
fn sweep_sessions(sessions: &Path, processes: &impl Processes) -> Result<Swept> {
    let entries = match std::fs::read_dir(sessions) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Swept::default()),
        Err(error) => {
            return Err(error).wrap_err_with(|| format!("list {}", sessions.display()));
        }
    };
    let mut swept = Swept::default();
    for entry in entries {
        let path = entry
            .wrap_err_with(|| format!("list {}", sessions.display()))?
            .path();
        match recorded_owner(&path)? {
            Some(owner) if processes.is_running(owner) => {
                keep_only_owner(&path)?;
                swept.outlived.push(Outlived { owner, dir: path });
            }
            _ => {
                std::fs::remove_dir_all(&path)
                    .wrap_err_with(|| format!("remove the dead session {}", path.display()))?;
                swept.removed += 1;
            }
        }
    }
    Ok(swept)
}

/// Refuse the wrappers of `outlived`'s cargo until it exits, then forget it
/// and remove the record of it.
fn refuse_until_exit<P: Processes>(daemon: &Daemon<P>, outlived: Outlived) {
    let Outlived { owner, dir } = outlived;
    let exited = match daemon.processes.watch(owner) {
        Ok(exited) => exited,
        Err(reason) => {
            // Gone or replaced by another process between the sweep and the
            // watch: there is nothing left to refuse.
            tracing::warn!(%owner, %reason, "a cargo that outlived the previous daemon cannot be watched");
            if let Err(error) = std::fs::remove_dir_all(&dir) {
                tracing::warn!(%error, dir = %dir.display(), "remove the record of a cargo");
            }
            return;
        }
    };
    daemon.table.outlived_daemon(owner);
    tracing::info!(%owner, "a cargo outlived the previous daemon; refusing its wrappers until it exits");
    let table = daemon.table.clone();
    tokio::spawn(async move {
        if let Err(error) = exited.await {
            tracing::warn!(%owner, %error, "watching a cargo for its exit failed; no longer refusing it");
        }
        table.remove_cargo(owner);
        if let Err(error) = tokio::fs::remove_dir_all(&dir).await {
            tracing::warn!(%error, dir = %dir.display(), "remove the record of a cargo");
        }
        tracing::info!(%owner, "a cargo that outlived the previous daemon has exited");
    });
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
async fn accept_loop(listener: Listener, daemon: Daemon<OsProcesses>) -> Result<()> {
    let mut connections = JoinSet::new();
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .wrap_err("accept a daemon connection")?;
        let peer = peer_of(owner::peer_pid(&stream));
        connections.spawn(serve_connection(stream, peer, daemon.clone()));
        reap(&mut connections);
    }
}

#[cfg(windows)]
async fn accept_loop(mut listener: Listener, daemon: Daemon<OsProcesses>) -> Result<()> {
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
        let peer = peer_of(owner::peer_pid(&connected));
        connections.spawn(serve_connection(connected, peer, daemon.clone()));
        reap(&mut connections);
    }
}

/// The process on the other end of a connection, when the platform says.
/// Only a wrapper that names no session needs it, and that wrapper is
/// refused when the daemon has none.
fn peer_of(peer: std::io::Result<u32>) -> Option<u32> {
    peer.inspect_err(|error| tracing::warn!(%error, "the connecting process is unknown"))
        .ok()
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
///
/// `peer` is the process that connected, when the platform says.
async fn serve_connection<S, P>(mut stream: S, peer: Option<u32>, daemon: Daemon<P>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    P: Processes,
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
        Role::Wrapper {
            session: SessionRef::Cargo { cargo },
        } => serve_cargo_wrapper(stream, &daemon, peer, cargo).await,
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
async fn serve_control<S, P>(mut stream: S, daemon: &Daemon<P>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    P: Processes,
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
async fn serve_session<S, P>(stream: S, daemon: &Daemon<P>, facts: SessionFacts) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    P: Processes,
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
async fn serve_wrapper<S, P>(mut stream: S, daemon: &Daemon<P>, id: SessionId) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    P: Processes,
{
    let Some(session) = daemon.table.join(id).await else {
        return reject(
            &mut stream,
            format!("no session {id}: the stow daemon restarted or the build that opened it ended"),
        )
        .await;
    };
    converse(&mut stream, &session, daemon.settings.answer / 2, None).await
}

/// What a wrapper's connection delivered.
enum Incoming {
    /// The wrapper hung up.
    Closed,
    Request(WrapperRequest),
    /// A frame the daemon will not serve; the reason is the wrapper's to read.
    Refused(String),
}

async fn read_request<S: AsyncRead + Unpin + Send>(stream: &mut S) -> Result<Incoming> {
    let Some(frame) = read_frame_async(stream).await? else {
        return Ok(Incoming::Closed);
    };
    if !speaks(frame.protocol) {
        return Ok(Incoming::Refused(protocol_mismatch(frame.protocol)));
    }
    Ok(match frame.decode::<WrapperRequest>() {
        Ok(request) => Incoming::Request(request),
        Err(error) => Incoming::Refused(error.to_string()),
    })
}

/// One wrapper's conversation with `session`: `first` when its request was
/// already read, then a request and its answer until the wrapper hangs up
/// — which ends a flight it still holds.
async fn converse<S, O>(
    stream: &mut S,
    session: &Arc<Session<O>>,
    every: Duration,
    first: Option<WrapperRequest>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    O: Origin,
{
    async {
        let mut flight = None;
        let mut next = first;
        loop {
            let request = match next.take() {
                Some(request) => request,
                None => match read_request(stream).await? {
                    Incoming::Closed => return Ok(()),
                    Incoming::Refused(reason) => return reject(stream, reason).await,
                    Incoming::Request(request) => request,
                },
            };
            // The decision path's future is large and lives for one unit.
            let answering = Box::pin(answer_and_book(
                session,
                session.in_flight(),
                session.reports(),
                &mut flight,
                request,
            ));
            let answer = working_meanwhile(stream, every, answering).await?;
            write_frame_async(stream, &Response::Answer(answer)).await?;
        }
    }
    .instrument(session.span().clone())
    .await
}

/// Await `work`, telling the wrapper every `every` that it is still being
/// done: a wrapper bounds its wait for a frame, and a decision that
/// fetches from the network, like the opening of a session, legitimately
/// outlasts that.
async fn working_meanwhile<S, T>(
    stream: &mut S,
    every: Duration,
    work: impl std::future::Future<Output = T>,
) -> Result<T>
where
    S: AsyncWrite + Unpin + Send,
{
    tokio::pin!(work);
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    loop {
        tokio::select! {
            done = &mut work => return Ok(done),
            _ = tick.tick() => write_frame_async(stream, &Response::Working).await?,
        }
    }
}

/// A wrapper of a cargo no driver opened a session for: the session of
/// that cargo, opened by the first of its wrappers to need one.
async fn serve_cargo_wrapper<S, P>(
    mut stream: S,
    daemon: &Daemon<P>,
    peer: Option<u32>,
    cargo: Option<Vec<u8>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    P: Processes,
{
    let first = match read_request(&mut stream).await? {
        Incoming::Closed => return Ok(()),
        Incoming::Refused(reason) => return reject(&mut stream, reason).await,
        Incoming::Request(request) => request,
    };
    // A probe belongs to no build: it needs neither a cargo nor a session.
    if is_probe(&first) {
        return serve_probe(stream, first).await;
    }
    let owner = match owner_of(daemon, peer, cargo).await {
        Ok(owner) => owner,
        Err(reason) => {
            tracing::warn!(%reason, "a wrapper's cargo could not be found");
            return reject(&mut stream, reason).await;
        }
    };
    let every = daemon.settings.answer / 2;
    let slot = daemon.table.cargo_slot(owner).await;
    if slot.is_outlived_daemon() {
        return reject(
            &mut stream,
            "the stow daemon restarted during this cargo build: its in-flight state and provenance marks are gone; run the build again".to_owned(),
        )
        .await;
    }
    if let Some(session) = slot.session() {
        return converse(&mut stream, &session, every, Some(first)).await;
    }
    // Nothing was settled before cargo started: the wrapper says what it
    // runs in, and the request it was holding is answered once the session
    // is open.
    write_frame_async(&mut stream, &Response::Answer(Answer::Describe)).await?;
    let environment = match read_request(&mut stream).await? {
        Incoming::Closed => return Ok(()),
        Incoming::Refused(reason) => return reject(&mut stream, reason).await,
        Incoming::Request(WrapperRequest::Describe(environment)) => environment,
        Incoming::Request(other) => {
            return reject(
                &mut stream,
                format!("the daemon asked for the build's environment, not {other:?}"),
            )
            .await;
        }
    };
    let opener = match Opener::of(&first) {
        Ok(opener) => opener,
        Err(reason) => return reject(&mut stream, reason).await,
    };
    let opening = slot.open_with(|| open_cargo_session(daemon.clone(), owner, opener, environment));
    let session = match working_meanwhile(&mut stream, every, opening).await? {
        Ok(session) => session,
        Err(reason) => {
            tracing::warn!(%owner, %reason, "a cargo's session could not be opened");
            return reject(&mut stream, reason).await;
        }
    };
    converse(&mut stream, &session, every, Some(first)).await
}

/// The cargo a wrapper connecting from `peer` runs under.
async fn owner_of<P: Processes>(
    daemon: &Daemon<P>,
    peer: Option<u32>,
    cargo: Option<Vec<u8>>,
) -> std::result::Result<CargoOwner, String> {
    let peer = peer.ok_or_else(|| {
        "the daemon cannot tell which process connected, so it cannot find its cargo".to_owned()
    })?;
    let cargo = cargo
        .map(|bytes| os_bytes::decode(&bytes).map(PathBuf::from))
        .transpose()?;
    let processes = daemon.processes.clone();
    tokio::task::spawn_blocking(move || processes.owner_of(peer, cargo.as_deref()))
        .await
        .map_err(|error| format!("join the lookup of the wrapper's cargo: {error}"))?
}

/// Whether `request` asks for no decision the cache could make: cargo's
/// probes of the compiler (`-vV`, `--print`, the `___` crate) and arguments
/// that are not a unit. They run before any build exists and are never
/// recorded.
fn is_probe(request: &WrapperRequest) -> bool {
    let WrapperRequest::Plan(plan) = request else {
        return false;
    };
    plan.args().ok().is_none_or(|args| {
        crate::classify_invocation(&args).map_or(true, |parsed| !crate::is_compile_unit(&parsed))
    })
}

/// A probe's conversation: told to run what it asked for, and its report
/// received. No session is opened or touched.
async fn serve_probe<S>(mut stream: S, first: WrapperRequest) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut next = Some(first);
    loop {
        let request = match next.take() {
            Some(request) => request,
            None => match read_request(&mut stream).await? {
                Incoming::Closed => return Ok(()),
                Incoming::Refused(reason) => return reject(&mut stream, reason).await,
                Incoming::Request(request) => request,
            },
        };
        let answer = match request {
            WrapperRequest::Plan(plan) => Answer::Compile(CompileCommand {
                executable: plan.executable,
                args: plan.args,
            }),
            WrapperRequest::Compiled(_) => Answer::Received,
            other => Answer::Failed {
                message: format!("a probe's connection takes a plan and its report, not {other:?}"),
            },
        };
        write_frame_async(&mut stream, &Response::Answer(answer)).await?;
    }
}

/// Open the session of `owner`'s cargo and arrange for it to end when the
/// cargo exits.
async fn open_cargo_session<P: Processes>(
    daemon: Daemon<P>,
    owner: CargoOwner,
    opener: Opener,
    environment: BuildEnvironment,
) -> std::result::Result<Arc<Session<Cargo>>, String> {
    let build = open_facts(&opener, &environment, &daemon.table).await?;
    let handles = match &build.config {
        Some(config) => daemon.table.handles_for(config.cache_dir.clone()).await,
        None => CacheDirHandles::default(),
    };
    // Armed before the session exists: a cargo that is already gone fails
    // the open rather than leaving a session nothing ends.
    let exited = daemon.processes.watch(owner)?;
    let id = SessionId::mint();
    let session = Session::open_cargo(id, owner, build, &handles, &daemon.sessions)
        .await
        .map_err(|error| format!("{error:#}"))?;
    tracing::info!(session = %id, %owner, "opened a session for a cargo");
    tokio::spawn(end_with_cargo(
        exited,
        owner,
        Arc::clone(&session),
        daemon.table.clone(),
    ));
    Ok(session)
}

/// End `session` when its cargo has exited, as a driver ends its own at the
/// end of a build: drain the bookkeeping, write the miss journal and then
/// do what follows a build.
async fn end_with_cargo(
    exited: futures_util::future::BoxFuture<'static, std::io::Result<()>>,
    owner: CargoOwner,
    session: Arc<Session<Cargo>>,
    table: SessionTable,
) {
    let span = session.span().clone();
    async move {
        if let Err(error) = exited.await {
            tracing::warn!(%owner, %error, "watching a cargo for its exit failed; ending its session");
        }
        // Removed first, so a wrapper arriving from here on opens a session
        // of its own instead of finding one that is closing.
        table.remove_cargo(owner);
        match session.end().await {
            Ok(end) => tracing::info!(
                %owner,
                journal_written = end.journal_written,
                "ended a cargo's session"
            ),
            Err(error) => tracing::warn!(%owner, %error, "a cargo's session did not end cleanly"),
        }
        session.conclude().await;
    }
    .instrument(span)
    .await;
}

#[cfg(all(test, unix))]
mod tests {
    use std::ffi::OsString;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::{AsyncWriteExt as _, DuplexStream};

    use super::{Daemon, refuse_until_exit, serve_connection, sweep_sessions, working_meanwhile};
    use crate::daemon::Settings;
    use crate::daemon::events::SessionLogs;
    use crate::daemon::owner::{CargoOwner, Processes};
    use crate::daemon::protocol::{
        ControlRequest, Hello, PROTOCOL, Response, Role, SessionRef, WrapperRequest, encode,
        read_frame_async,
    };
    use crate::daemon::session::handler::{
        Decision, Flight, Handler, InFlightUnits, Reports, answer_and_book,
    };
    use crate::daemon::session::invocation::{OutputRoots, RefusalPolicy};
    use crate::daemon::session::{SessionFacts, SessionId};
    use crate::daemon::table::SessionTable;
    use crate::daemon::wrapper::{Answer, BuildEnvironment, InvocationEnv, Plan};
    use crate::session_env::SessionEnv;
    use crate::toolchain::BuildToolchain;

    /// The processes of a made-up machine: which cargo each wrapper runs
    /// under, and which cargos have exited.
    #[derive(Clone, Default)]
    struct Machine {
        state: Arc<std::sync::Mutex<MachineState>>,
    }

    #[derive(Default)]
    struct MachineState {
        cargo_of: std::collections::HashMap<u32, u32>,
        exited: std::collections::HashMap<u32, tokio::sync::watch::Sender<bool>>,
    }

    impl Machine {
        /// Process `wrapper` was started by the cargo `cargo`.
        fn start(&self, wrapper: u32, cargo: u32) {
            self.state
                .lock()
                .expect("machine")
                .cargo_of
                .insert(wrapper, cargo);
        }

        /// The cargo `pid` exits.
        fn exit(&self, cargo: u32) {
            self.state
                .lock()
                .expect("machine")
                .exited
                .entry(cargo)
                .or_insert_with(|| tokio::sync::watch::channel(false).0)
                .send_replace(true);
        }
    }

    impl Processes for Machine {
        fn owner_of(
            &self,
            peer: u32,
            _cargo: Option<&std::path::Path>,
        ) -> Result<CargoOwner, String> {
            self.state
                .lock()
                .expect("machine")
                .cargo_of
                .get(&peer)
                .map(|&pid| CargoOwner { pid, started: 1 })
                .ok_or_else(|| format!("no process {peer}"))
        }

        fn watch(
            &self,
            owner: CargoOwner,
        ) -> Result<futures_util::future::BoxFuture<'static, std::io::Result<()>>, String> {
            let mut exited = self
                .state
                .lock()
                .expect("machine")
                .exited
                .entry(owner.pid)
                .or_insert_with(|| tokio::sync::watch::channel(false).0)
                .subscribe();
            Ok(Box::pin(async move {
                exited
                    .wait_for(|exited| *exited)
                    .await
                    .map(|_| ())
                    .map_err(std::io::Error::other)
            }))
        }

        fn is_running(&self, owner: CargoOwner) -> bool {
            !self
                .state
                .lock()
                .expect("machine")
                .exited
                .get(&owner.pid)
                .is_some_and(|exited| *exited.borrow())
        }
    }

    fn daemon(sessions: &std::path::Path) -> Daemon<Machine> {
        Daemon {
            sessions: sessions.to_owned(),
            settings: Settings {
                answer: Duration::from_millis(60),
                start: Duration::from_secs(30),
                log_bytes: 1 << 20,
            },
            logs: SessionLogs::default(),
            table: SessionTable::start(),
            processes: Machine::default(),
        }
    }

    /// One connection to `daemon` from no known process, served on a task
    /// of its own.
    fn connect(
        daemon: &Daemon<Machine>,
    ) -> (
        DuplexStream,
        tokio::task::JoinHandle<stow_types::error::Result<()>>,
    ) {
        connect_from(daemon, None)
    }

    /// One connection to `daemon` from the process `peer`.
    fn connect_from(
        daemon: &Daemon<Machine>,
        peer: Option<u32>,
    ) -> (
        DuplexStream,
        tokio::task::JoinHandle<stow_types::error::Result<()>>,
    ) {
        let (client, daemon_end) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(serve_connection(daemon_end, peer, daemon.clone()));
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
        daemon: &Daemon<Machine>,
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

    async fn plan_in(
        daemon: &Daemon<Machine>,
        session: SessionId,
        out_dir: &std::path::Path,
    ) -> Response {
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
        let in_flight = InFlightUnits::default();
        let reports = Reports::default();
        let answering = answer_and_book(&handler, &in_flight, &reports, &mut flight, request);
        let answer = working_meanwhile(&mut daemon_end, Duration::from_millis(20), answering)
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
        let machine = Machine::default();
        let swept = sweep_sessions(sessions.path(), &machine).expect("sweep");
        assert_eq!(swept.removed, 2);
        assert!(swept.outlived.is_empty());
        assert_eq!(std::fs::read_dir(sessions.path()).expect("list").count(), 0);
        assert_eq!(
            sweep_sessions(&sessions.path().join("missing"), &machine)
                .expect("a missing directory")
                .removed,
            0
        );
    }

    /// A session of a cargo that is still running keeps only the record of
    /// its owner; the session of one that exited, and a driver's, go.
    #[tokio::test]
    async fn a_sweep_keeps_only_the_record_of_a_cargo_that_is_still_running() {
        let sessions = tempfile::tempdir().expect("sessions");
        let machine = Machine::default();
        let running = CargoOwner { pid: 7, started: 1 };
        let gone = CargoOwner { pid: 8, started: 1 };
        for (name, owner) in [
            ("running", Some(running)),
            ("gone", Some(gone)),
            ("driver", None),
        ] {
            let dir = sessions.path().join(name);
            std::fs::create_dir_all(dir.join("local-build")).expect("session dir");
            std::fs::write(dir.join("local-build").join("mark"), b"x").expect("mark");
            if let Some(owner) = owner {
                std::fs::write(
                    dir.join("owner"),
                    format!("{} {}\n", owner.pid, owner.started),
                )
                .expect("owner record");
            }
        }
        machine.exit(8);

        let swept = sweep_sessions(sessions.path(), &machine).expect("sweep");
        assert_eq!(swept.removed, 2);
        assert_eq!(swept.outlived.len(), 1);
        let kept = &swept.outlived[0];
        assert_eq!(kept.owner, running);
        assert_eq!(
            std::fs::read_dir(&kept.dir)
                .expect("list")
                .map(|entry| entry.expect("entry").file_name())
                .collect::<Vec<_>>(),
            [OsString::from("owner")],
            "the marks are gone, the record stays"
        );

        // Its wrappers are refused until it exits, and then it is a cargo
        // like any other.
        let target = tempfile::tempdir().expect("target");
        let daemon = Daemon {
            processes: machine,
            ..daemon(sessions.path())
        };
        let request = unit_request(target.path()).await;
        let outlived = swept.outlived.into_iter().next().expect("outlived");
        let dir = outlived.dir.clone();
        refuse_until_exit(&daemon, outlived);
        let (_wrapper, _task, refused) = wrapper_of(&daemon, 70, 7, &request).await;
        let Response::Rejected { reason } = refused else {
            panic!("a cargo that outlived the daemon is refused: {refused:?}");
        };
        assert!(reason.contains("daemon restarted"), "{reason}");
        daemon.processes.exit(7);
        until(|| !dir.exists()).await;
        let (_wrapper, _task, asked) = wrapper_of(&daemon, 71, 7, &request).await;
        assert_eq!(asked, Response::Answer(Answer::Describe));
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

    /// The environment a plain cargo's wrapper runs in: this process's,
    /// with a home, a cache directory and a configuration of its own that
    /// keeps the build off the network.
    fn environment(home: &std::path::Path) -> BuildEnvironment {
        let cache = home.join("cache");
        let config_home = home.join("config");
        let overrides = [
            ("HOME", home.as_os_str()),
            ("XDG_CONFIG_HOME", config_home.as_os_str()),
            ("STOW_CACHE_DIR", cache.as_os_str()),
        ];
        let mut environ: Vec<(OsString, OsString)> = std::env::vars_os()
            .filter(|(name, _)| !overrides.iter().any(|(own, _)| name == *own))
            .collect();
        environ.extend(
            overrides
                .iter()
                .map(|(name, value)| (OsString::from(name), (*value).to_owned())),
        );
        let cwd = std::env::current_dir().expect("cwd");
        let config = crate::config::config_file_path(&SessionEnv::new(environ.clone(), cwd))
            .expect("config path");
        std::fs::create_dir_all(config.parent().expect("config dir")).expect("config dir");
        std::fs::write(&config, "[cache]\nremote = false\n").expect("config");
        BuildEnvironment {
            environ: environ
                .iter()
                .map(|(name, value)| {
                    (
                        crate::daemon::session::os_bytes::encode(name),
                        crate::daemon::session::os_bytes::encode(value),
                    )
                })
                .collect(),
            cwd: crate::daemon::session::os_bytes::encode(
                std::env::current_dir().expect("cwd").as_os_str(),
            ),
        }
    }

    /// The request of a unit cargo compiles into `<target>/debug/deps`.
    async fn unit_request(target: &std::path::Path) -> WrapperRequest {
        let toolchain = BuildToolchain::for_tests().await;
        let out_dir = target.join("debug").join("deps");
        let args: Vec<OsString> = ["--crate-name", "demo", "--crate-type", "lib", "--out-dir"]
            .into_iter()
            .map(OsString::from)
            .chain([out_dir.into_os_string()])
            .collect();
        WrapperRequest::Plan(Plan::new(
            toolchain.rustc().as_os_str(),
            &args,
            InvocationEnv::for_tests(),
        ))
    }

    /// The next answer, past the daemon's progress frames.
    async fn answer(stream: &mut DuplexStream) -> Response {
        loop {
            match receive(stream).await {
                Response::Working => {}
                other => return other,
            }
        }
    }

    /// A wrapper of the cargo `cargo`, started as process `wrapper`, that
    /// sends `request` first.
    async fn wrapper_of(
        daemon: &Daemon<Machine>,
        wrapper: u32,
        cargo: u32,
        request: &WrapperRequest,
    ) -> (
        DuplexStream,
        tokio::task::JoinHandle<stow_types::error::Result<()>>,
        Response,
    ) {
        daemon.processes.start(wrapper, cargo);
        let (mut stream, task) = connect_from(daemon, Some(wrapper));
        send(
            &mut stream,
            &Hello::new(Role::Wrapper {
                session: SessionRef::Cargo { cargo: None },
            }),
        )
        .await;
        send(&mut stream, request).await;
        let first = answer(&mut stream).await;
        (stream, task, first)
    }

    /// Wait until `done` holds, yielding to the daemon's tasks.
    async fn until(mut done: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(30), async {
            while !done() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the condition did not come true");
    }

    #[tokio::test]
    async fn a_session_less_wrapper_is_asked_for_its_environment_and_then_answered() {
        let sessions = tempfile::tempdir().expect("sessions");
        let home = tempfile::tempdir().expect("home");
        let target = tempfile::tempdir().expect("target");
        let daemon = daemon(sessions.path());
        let request = unit_request(target.path()).await;
        let (mut wrapper, task, first) = wrapper_of(&daemon, 11, 1, &request).await;
        assert_eq!(first, Response::Answer(Answer::Describe));
        send(
            &mut wrapper,
            &WrapperRequest::Describe(environment(home.path())),
        )
        .await;
        let decision = answer(&mut wrapper).await;
        assert!(
            matches!(decision, Response::Answer(Answer::Compile(_))),
            "the held request is answered once the session is open: {decision:?}"
        );
        let slot = daemon
            .table
            .cargo_slot(CargoOwner { pid: 1, started: 1 })
            .await;
        assert!(slot.session().is_some(), "the cargo has a session");
        wrapper.shutdown().await.expect("shutdown");
        task.await.expect("join").expect("served");
    }

    #[tokio::test]
    async fn two_wrappers_of_one_cargo_share_one_session() {
        let sessions = tempfile::tempdir().expect("sessions");
        let home = tempfile::tempdir().expect("home");
        let target = tempfile::tempdir().expect("target");
        let daemon = daemon(sessions.path());
        let request = unit_request(target.path()).await;
        let (mut first, _first_task, asked) = wrapper_of(&daemon, 11, 1, &request).await;
        assert_eq!(asked, Response::Answer(Answer::Describe));
        send(
            &mut first,
            &WrapperRequest::Describe(environment(home.path())),
        )
        .await;
        answer(&mut first).await;
        let (_second, _second_task, decision) = wrapper_of(&daemon, 12, 1, &request).await;
        assert!(
            matches!(decision, Response::Answer(Answer::Compile(_))),
            "a second wrapper of the cargo is answered without being asked: {decision:?}"
        );
        assert_eq!(
            std::fs::read_dir(sessions.path())
                .expect("sessions")
                .count(),
            1,
            "one session directory"
        );
    }

    #[tokio::test]
    async fn wrappers_of_two_cargos_get_two_sessions() {
        let sessions = tempfile::tempdir().expect("sessions");
        let home = tempfile::tempdir().expect("home");
        let target = tempfile::tempdir().expect("target");
        let daemon = daemon(sessions.path());
        let request = unit_request(target.path()).await;
        let mut kept = Vec::new();
        for (wrapper, cargo) in [(11, 1), (21, 2)] {
            // The connections stay open, so neither session has ended.
            let (mut stream, task, asked) = wrapper_of(&daemon, wrapper, cargo, &request).await;
            assert_eq!(
                asked,
                Response::Answer(Answer::Describe),
                "cargo {cargo} has no session yet"
            );
            send(
                &mut stream,
                &WrapperRequest::Describe(environment(home.path())),
            )
            .await;
            answer(&mut stream).await;
            kept.push((stream, task));
        }
        assert_eq!(
            std::fs::read_dir(sessions.path())
                .expect("sessions")
                .count(),
            2,
            "a session directory for each cargo"
        );
        assert_eq!(kept.len(), 2, "both wrappers' connections were open");
    }

    #[tokio::test]
    async fn a_probe_with_no_session_is_answered_without_opening_one() {
        let sessions = tempfile::tempdir().expect("sessions");
        let daemon = daemon(sessions.path());
        let toolchain = BuildToolchain::for_tests().await;
        let probe = WrapperRequest::Plan(Plan::new(
            toolchain.rustc().as_os_str(),
            &[OsString::from("-vV")],
            InvocationEnv::for_tests(),
        ));
        let (mut wrapper, task, first) = wrapper_of(&daemon, 11, 1, &probe).await;
        let Response::Answer(Answer::Compile(command)) = first else {
            panic!("a probe is told to run as asked: {first:?}");
        };
        assert_eq!(command.args, vec![b"-vV".to_vec()]);
        send(
            &mut wrapper,
            &WrapperRequest::Compiled(crate::daemon::wrapper::Compiled {
                success: true,
                compile_millis: 1,
            }),
        )
        .await;
        assert_eq!(
            answer(&mut wrapper).await,
            Response::Answer(Answer::Received)
        );
        wrapper.shutdown().await.expect("shutdown");
        task.await.expect("join").expect("served");
        let slot = daemon
            .table
            .cargo_slot(CargoOwner { pid: 1, started: 1 })
            .await;
        assert!(slot.session().is_none(), "no session was opened");
        assert_eq!(
            std::fs::read_dir(sessions.path())
                .expect("sessions")
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn a_session_ends_when_its_cargo_exits() {
        let sessions = tempfile::tempdir().expect("sessions");
        let home = tempfile::tempdir().expect("home");
        let target = tempfile::tempdir().expect("target");
        let daemon = daemon(sessions.path());
        let request = unit_request(target.path()).await;
        let (mut wrapper, _task, asked) = wrapper_of(&daemon, 11, 1, &request).await;
        assert_eq!(asked, Response::Answer(Answer::Describe));
        send(
            &mut wrapper,
            &WrapperRequest::Describe(environment(home.path())),
        )
        .await;
        answer(&mut wrapper).await;
        let dir = std::fs::read_dir(sessions.path())
            .expect("sessions")
            .next()
            .expect("a session directory")
            .expect("entry")
            .path();
        daemon.processes.exit(1);
        until(|| !dir.exists()).await;
        send(&mut wrapper, &request).await;
        let Response::Answer(Answer::Failed { message }) = answer(&mut wrapper).await else {
            panic!("an ended session answers no further request");
        };
        assert!(message.contains("has ended"), "{message}");
    }

    #[tokio::test]
    async fn an_ended_session_answers_no_further_request_on_an_open_connection() {
        let sessions = tempfile::tempdir().expect("sessions");
        let target = tempfile::tempdir().expect("target");
        let daemon = daemon(sessions.path());
        let (mut control, _task, id) = open(&daemon, target.path()).await;
        let (mut wrapper, _wrapper_task) = connect(&daemon);
        send(
            &mut wrapper,
            &Hello::new(Role::Wrapper {
                session: SessionRef::Id(id),
            }),
        )
        .await;
        send(&mut wrapper, &unit_request(target.path()).await).await;
        assert!(matches!(answer(&mut wrapper).await, Response::Answer(_)));
        send(&mut control, &ControlRequest::EndSession).await;
        // The session's events reach the driver ahead of the answer.
        while let Response::Event(_) = receive(&mut control).await {}
        send(&mut wrapper, &unit_request(target.path()).await).await;
        let Response::Answer(Answer::Failed { message }) = answer(&mut wrapper).await else {
            panic!("an ended session answers no further request");
        };
        assert!(message.contains("has ended"), "{message}");
    }

    #[tokio::test]
    async fn a_wrapper_the_daemon_cannot_place_is_rejected() {
        let sessions = tempfile::tempdir().expect("sessions");
        let daemon = daemon(sessions.path());
        let (mut wrapper, task) = connect_from(&daemon, Some(99));
        send(
            &mut wrapper,
            &Hello::new(Role::Wrapper {
                session: SessionRef::Cargo { cargo: None },
            }),
        )
        .await;
        send(&mut wrapper, &unit_request(sessions.path()).await).await;
        let Response::Rejected { reason } = receive(&mut wrapper).await else {
            panic!("a wrapper with no known cargo is rejected");
        };
        assert!(reason.contains("no process 99"), "{reason}");
        task.await.expect("join").expect("served");
    }
}
