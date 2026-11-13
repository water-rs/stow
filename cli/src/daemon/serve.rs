//! The daemon process: `stow daemon`.
//!
//! It takes `daemon.lock` without blocking, so a second daemon — one the
//! login trigger started beside a client's, say — finds the lock held and
//! exits 0. The holder removes a stale endpoint, binds its own, reports
//! readiness to the client that started it (`--ready <endpoint>`, or on
//! Windows the address that client published) and serves. The lock is a file lock, so a dead daemon releases it and no
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

use super::events::{LogInterest, SESSION_SPAN, SessionLogs};
use super::log::LogWriter;
use super::notify::{self, Notification};
use super::owner::{self, CargoOwner, OsProcesses, Processes};
use super::protocol::{
    Admission, ControlRequest, Event, Frame, Hello, HelloCore, Negotiated, PROTOCOL,
    PROTOCOL_FLOOR, Response, Role, SessionRef, WrapperRequest, negotiate, read_frame_async,
    write_core_async, write_frame_async,
};
use super::retire::{Busy, Held, Installed, Pending, Retirement, is_newer};
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
    /// Whether this daemon is giving way to another stow, and onto what.
    retirement: Retirement,
    /// What the daemon holds that giving way would cut.
    busy: Busy,
    /// The executable this daemon started from, which a later install may
    /// replace.
    installed: Arc<Installed>,
}

/// Who asks a daemon for a session, as far as giving way to it goes.
#[derive(Debug, Clone)]
struct Client {
    stow_version: String,
    executable: Vec<u8>,
}

impl Client {
    fn of(core: &HelloCore) -> Self {
        Self {
            stow_version: core.stow_version.clone(),
            executable: core.executable.clone(),
        }
    }
}

impl<P: Processes> Daemon<P> {
    /// The answer to a request that would open a session, when this daemon
    /// must give way before serving it: it is already retiring, the client
    /// is a newer stow, or stow was installed over this daemon's own
    /// executable. Nothing of the request is acted on, so the client
    /// replays it. `None` when the daemon serves the request.
    async fn give_way(&self, client: &Client) -> std::result::Result<Option<Response>, String> {
        if let Some(retiring) = self.retirement.reply() {
            return Ok(Some(retiring));
        }
        let successor = if is_newer(env!("CARGO_PKG_VERSION"), &client.stow_version)? {
            tracing::info!(client_version = %client.stow_version, "a newer stow asks for a session");
            Some(successor_of(&client.executable)?)
        } else {
            let installed = Arc::clone(&self.installed);
            let replaced = tokio::task::spawn_blocking(move || {
                installed.replaced().map(|path| path.map(Path::to_owned))
            })
            .await
            .map_err(|error| format!("join the check of the daemon's executable: {error}"))?
            .map_err(|error| format!("read the daemon's executable: {error}"))?;
            if replaced.is_some() {
                tracing::info!("stow was installed over the daemon's executable");
            }
            replaced
        };
        Ok(successor.and_then(|successor| {
            self.retirement.begin(successor);
            self.retirement.reply()
        }))
    }
}

/// The lock and the listening socket of the daemon that replaced its own
/// image with this process's: the descriptors it passed on.
#[cfg(unix)]
pub struct Inherited {
    /// The descriptor of `daemon.lock`, held locked.
    pub lock: std::os::fd::RawFd,
    /// The descriptor of the endpoint's listening socket.
    pub listener: std::os::fd::RawFd,
}

/// Writes what the daemon's log has queued when dropped, so that no way
/// the process ends leaves records behind: the thread that writes the log
/// ends with the process. The one end that skips destructors, the exec of
/// a successor's image, flushes explicitly first (`replace_image`).
struct LogGuard(LogWriter);

impl Drop for LogGuard {
    fn drop(&mut self) {
        // The log is all there is to report a failed flush to.
        let _ = std::io::Write::flush(&mut self.0);
    }
}

/// Run the daemon until it retires or fails. Returns `Ok` when another
/// daemon already holds the lock, and on Windows when it has drained and
/// released the pipe and the lock for its successor; on Unix a retiring
/// daemon replaces its image and never returns. Whatever way it ends, the
/// records it queued are written first, and a failure is the log's last
/// record.
pub async fn run(
    ready: Option<PathBuf>,
    given_dir: Option<PathBuf>,
    #[cfg(unix)] inherited: Option<Inherited>,
) -> Result<()> {
    let logs = SessionLogs::default();
    let (run_dir, log) = blocking({
        let logs = logs.clone();
        move || {
            let run_dir = RunDir::prepare(RunDir::locate_given(given_dir)?)?;
            let log = install_logging(&run_dir, &logs)?;
            Ok((run_dir, log))
        }
    })
    .await?;
    let log = LogGuard(log);
    let outcome = serve(
        ready,
        run_dir,
        logs,
        &log.0,
        #[cfg(unix)]
        inherited,
    )
    .await;
    if let Err(error) = &outcome {
        tracing::error!("stow daemon failed: {error}");
    }
    outcome
}

/// The daemon's life after its log is installed.
async fn serve(
    ready: Option<PathBuf>,
    run_dir: RunDir,
    logs: SessionLogs,
    log: &LogWriter,
    #[cfg(unix)] inherited: Option<Inherited>,
) -> Result<()> {
    tracing::info!(
        pid = std::process::id(),
        version = env!("CARGO_PKG_VERSION"),
        run_dir = %run_dir.path().display(),
        "stow daemon process started"
    );
    let lock_path = run_dir.daemon_lock();
    let Some(lock) = hold_lock(
        lock_path,
        #[cfg(unix)]
        inherited.as_ref().map(|inherited| inherited.lock),
    )
    .await?
    else {
        tracing::info!("another stow daemon holds the lock; exiting");
        notify_ready(ready, &run_dir, Notification::LockHeld).await?;
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
    let listener = listen(
        &endpoint,
        #[cfg(unix)]
        inherited.as_ref().map(|inherited| inherited.listener),
    )
    .await?;
    let settings = blocking(Settings::from_env).await?;
    let daemon = Daemon {
        sessions,
        settings,
        logs,
        table: SessionTable::start(),
        processes: OsProcesses,
        retirement: Retirement::new(settings.drain),
        busy: Busy::default(),
        installed: Arc::new(Installed::of_current().wrap_err("read this daemon's own executable")?),
    };
    for outlived in swept.outlived {
        refuse_until_exit(&daemon, outlived);
    }
    tracing::info!(
        pid = std::process::id(),
        endpoint = %endpoint.display(),
        "stow daemon serving"
    );
    notify_ready(ready, &run_dir, Notification::Ready).await?;
    #[cfg(unix)]
    {
        let retired = accept_loop(&listener, daemon).await?;
        replace_image(&retired, &run_dir, &lock, &listener, log).await
    }
    #[cfg(windows)]
    {
        let retired = accept_loop(listener, daemon).await?;
        // The pipe is closed with the listener; the lock is released as the
        // last thing, so the successor the next client starts finds both
        // free.
        drop(lock);
        tracing::info!(
            successor = %retired.successor.display(),
            "drained; the pipe and the lock are released for the successor"
        );
        Ok(())
    }
}

/// Replace this daemon's image with its successor's, carrying the lock and
/// the listener over. Only a failed exec returns: the process then exits,
/// which releases the lock, and the next client starts a daemon.
#[cfg(unix)]
async fn replace_image(
    retired: &Pending,
    run_dir: &RunDir,
    lock: &FileLock,
    listener: &Listener,
    log: &LogWriter,
) -> Result<()> {
    tracing::info!(
        successor = %retired.successor.display(),
        "drained; replacing this daemon's image with its successor's"
    );
    // The log's thread dies with the old image: what it has queued, this
    // drain's own record included, is written first.
    flush_log(log).await?;
    let error = super::retire::exec_into(
        &retired.successor,
        run_dir.path(),
        lock.as_raw_fd(),
        std::os::fd::AsRawFd::as_raw_fd(listener),
    );
    Err(error).wrap_err_with(|| {
        format!(
            "replace the stow daemon with its successor {}",
            retired.successor.display()
        )
    })
}

/// The lock of `daemon.lock`: taken without blocking, `None` when another
/// daemon holds it — or on Unix, when `inherited` names the descriptor of
/// the lock the daemon that replaced its image with this process's holds,
/// which is adopted: locking the file again would conflict with it.
async fn hold_lock(
    path: PathBuf,
    #[cfg(unix)] inherited: Option<std::os::fd::RawFd>,
) -> Result<Option<FileLock>> {
    #[cfg(unix)]
    if let Some(fd) = inherited {
        use std::os::fd::FromRawFd as _;
        // SAFETY: the daemon that executed this image passed `fd` on its
        // command line as the open lock file it holds locked, and nothing
        // else in this process owns it.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let lock = FileLock::inherited(file);
        super::descriptors::mark_close_on_exec(&[fd]).wrap_err("close the lock on exec")?;
        return Ok(Some(lock));
    }
    blocking(move || take_lock(&path)).await
}

/// The listener of `endpoint`: bound here, or on Unix adopted from the
/// descriptor `inherited` names, which the daemon that replaced its image
/// with this process's kept listening, so the endpoint never stopped
/// existing.
async fn listen(
    endpoint: &Path,
    #[cfg(unix)] inherited: Option<std::os::fd::RawFd>,
) -> Result<Listener> {
    #[cfg(unix)]
    if let Some(fd) = inherited {
        use std::os::fd::FromRawFd as _;
        // SAFETY: the daemon that executed this image passed `fd` on its
        // command line as its listening socket, and nothing else in this
        // process owns it.
        let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
        listener
            .set_nonblocking(true)
            .wrap_err("make the inherited listener non-blocking")?;
        super::descriptors::mark_close_on_exec(&[fd]).wrap_err("close the listener on exec")?;
        return Listener::from_std(listener).wrap_err("adopt the inherited listener");
    }
    bind(endpoint).await
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
///
/// A client that spawned the daemon names its endpoint on the command line.
/// On Windows the Task Scheduler starts the daemon, so the endpoint is the
/// one the client published in the run directory before it asked for the
/// run, if it did: the login trigger starts a daemon nobody waits for, and
/// a client that gave up leaves its address behind, so a failed
/// notification there is logged, not fatal.
async fn notify_ready(
    ready: Option<PathBuf>,
    run_dir: &RunDir,
    notification: Notification,
) -> Result<()> {
    #[cfg(unix)]
    {
        let _ = run_dir;
        let Some(endpoint) = ready else {
            return Ok(());
        };
        blocking(move || notify::send(&endpoint, notification)).await
    }
    #[cfg(windows)]
    {
        let Some(endpoint) = ready.or_else(|| notify::published_address(run_dir)) else {
            return Ok(());
        };
        if let Err(error) = blocking(move || notify::send(&endpoint, notification)).await {
            tracing::warn!(%error, "no client took the daemon's notification");
        }
        Ok(())
    }
}

/// The daemon writes its own log in the runtime directory: its stderr is
/// the null device, so nothing it says would otherwise be kept. Events
/// recorded for a session are also routed to the driver that owns it; that
/// layer sees every level, and only the log file is filtered.
/// Wait until the log's thread has written everything queued.
async fn flush_log(log: &LogWriter) -> Result<()> {
    let mut log = log.clone();
    blocking(move || std::io::Write::flush(&mut log).wrap_err("flush the daemon log")).await
}

fn install_logging(run_dir: &RunDir, logs: &SessionLogs) -> Result<LogWriter> {
    let writer = LogWriter::open(&run_dir.log(), Settings::from_env()?.log_bytes)?;
    // The daemon's environment is cleared, so `RUST_LOG` only reaches it
    // when started by hand; the default is what a log of a long-lived
    // process should carry.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let file = tracing_subscriber::fmt::layer()
        .with_writer(writer.clone())
        .with_ansi(false)
        .with_filter(filter);
    tracing_subscriber::registry()
        .with(logs.layer())
        .with(file)
        .try_init()
        .map_err(|error| stow_types::stow_error!("install the daemon log: {error}"))?;
    Ok(writer)
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

/// Serve until a retirement has drained, and return it. On Unix the
/// listener is the caller's, which keeps it open: connections that arrive
/// from here on wait in its backlog for the successor.
///
/// A connection holds the daemon busy from the moment it is accepted, so a
/// drain that ends never leaves one accepted and unanswered.
#[cfg(unix)]
async fn accept_loop(listener: &Listener, daemon: Daemon<OsProcesses>) -> Result<Pending> {
    let mut connections = JoinSet::new();
    let drained = daemon
        .retirement
        .drained(&daemon.busy, daemon.settings.answer);
    tokio::pin!(drained);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.wrap_err("accept a daemon connection")?;
                let request = daemon.busy.request();
                let peer = peer_of(owner::peer_pid(&stream));
                connections.spawn(serve_connection(stream, peer, daemon.clone(), request));
                reap(&mut connections);
            }
            pending = &mut drained => return Ok(pending),
        }
    }
}

/// Serve until a retirement has drained, and return it. The listener and
/// the connections end with this call, which frees the pipe for the
/// successor.
#[cfg(windows)]
async fn accept_loop(mut listener: Listener, daemon: Daemon<OsProcesses>) -> Result<Pending> {
    let mut connections = JoinSet::new();
    let drained = daemon
        .retirement
        .drained(&daemon.busy, daemon.settings.answer);
    tokio::pin!(drained);
    loop {
        tokio::select! {
            connected = listener.server.connect() => {
                connected.wrap_err("accept a daemon connection")?;
                let request = daemon.busy.request();
                // The next instance exists before the connected one is
                // served, so the name never has a moment with none to
                // connect to.
                let next = super::windows::create_server(&listener.name, false)
                    .wrap_err("create the next daemon pipe instance")?;
                let connected = std::mem::replace(&mut listener.server, next);
                let peer = peer_of(owner::peer_pid(&connected));
                connections.spawn(serve_connection(connected, peer, daemon.clone(), request));
                reap(&mut connections);
            }
            pending = &mut drained => return Ok(pending),
        }
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
/// `peer` is the process that connected, when the platform says. `request`
/// holds the daemon busy until the connection's first request has been
/// answered or handed to the session it belongs to.
async fn serve_connection<S, P>(
    mut stream: S,
    peer: Option<u32>,
    daemon: Daemon<P>,
    request: Held,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    P: Processes,
{
    let Some(first) = read_frame_async(&mut stream).await? else {
        return Ok(());
    };
    let (hello, at) = match greet(&first) {
        Greeting::Admitted(hello, at) => (hello, at),
        Greeting::Refused { stamp, reason } => {
            tracing::warn!(%reason, "daemon connection refused");
            return write_core_async(&mut stream, stamp, &Response::Rejected { reason }).await;
        }
        Greeting::Newer(core) => {
            // A client that speaks only protocols this daemon does not: it
            // is a newer stow, which this daemon gives way to. The client
            // reads the answer stamped with the daemon's protocol because
            // it is a core response.
            let answer = match daemon.give_way(&Client::of(&core)).await {
                Ok(Some(retiring)) => retiring,
                Ok(None) => Response::Rejected {
                    reason: format!(
                        "the client (stow {}) speaks protocols {} through {}, this daemon speaks protocols {PROTOCOL_FLOOR} through {PROTOCOL}",
                        core.stow_version, core.floor, core.protocol
                    ),
                },
                Err(reason) => Response::Rejected { reason },
            };
            return write_core_async(&mut stream, PROTOCOL, &answer).await;
        }
    };
    let client = Client {
        stow_version: hello.stow_version,
        executable: hello.executable,
    };
    match hello.role {
        Role::Control => serve_control(stream, &daemon, at, &client, request).await,
        Role::Wrapper {
            session: SessionRef::Id(id),
        } => serve_wrapper(stream, &daemon, at, id, request).await,
        Role::Wrapper {
            session: SessionRef::Cargo { cargo, rust_log },
        } => {
            let wrapper = CargoWrapper {
                peer,
                cargo,
                rust_log,
            };
            serve_cargo_wrapper(stream, &daemon, at, &client, wrapper, request).await
        }
    }
}

/// What the daemon made of a connection's first frame.
enum Greeting {
    /// A client the daemon serves, and the protocol it serves it at.
    Admitted(Hello, Negotiated),
    /// A client the daemon refuses, in a frame stamped `stamp` so that the
    /// client reads it.
    Refused { stamp: u16, reason: String },
    /// A client that speaks only protocols newer than this daemon's.
    Newer(HelloCore),
}

fn greet(first: &Frame) -> Greeting {
    let core = match first.decode::<HelloCore>() {
        Ok(core) => core,
        Err(error) => {
            return Greeting::Refused {
                stamp: first.protocol,
                reason: format!("the first frame must be a Hello: {error}"),
            };
        }
    };
    if first.protocol != core.protocol {
        return Greeting::Refused {
            stamp: first.protocol,
            reason: format!(
                "a Hello stamped with protocol {} names protocol {}",
                first.protocol, core.protocol
            ),
        };
    }
    match negotiate(&core, &(PROTOCOL_FLOOR..=PROTOCOL)) {
        Admission::Serve(at) => match first.decode::<Hello>() {
            Ok(hello) => {
                tracing::debug!(client_version = %hello.stow_version, "daemon client connected");
                Greeting::Admitted(hello, at)
            }
            Err(error) => Greeting::Refused {
                stamp: core.protocol,
                reason: format!(
                    "the Hello does not decode at protocol {}: {error}",
                    core.protocol
                ),
            },
        },
        Admission::Newer => Greeting::Newer(core),
        Admission::Older { peer, reason } => Greeting::Refused {
            stamp: peer,
            reason,
        },
    }
}

/// The refusal of a frame that does not belong to the connection's
/// negotiated protocol.
fn foreign_stamp(at: Negotiated, stamp: u16) -> String {
    format!(
        "a frame stamped with protocol {stamp} on a connection negotiated at protocol {}",
        at.protocol()
    )
}

async fn reject<S: AsyncWrite + Unpin + Send>(
    stream: &mut S,
    at: Negotiated,
    reason: String,
) -> Result<()> {
    write_frame_async(stream, at, &Response::Rejected { reason }).await
}

/// A driver's connection: status requests, until it opens a session and
/// the connection becomes the session's.
async fn serve_control<S, P>(
    mut stream: S,
    daemon: &Daemon<P>,
    at: Negotiated,
    client: &Client,
    request: Held,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    P: Processes,
{
    let mut request = Some(request);
    while let Some(frame) = read_frame_async(&mut stream).await? {
        if !at.admits(frame.protocol) {
            return reject(&mut stream, at, foreign_stamp(at, frame.protocol)).await;
        }
        match frame.decode::<ControlRequest>() {
            Ok(ControlRequest::Status) => {
                // A status request is a request to open a session as far as
                // giving way is concerned: its asker is about to build.
                let answer = match daemon.give_way(client).await {
                    Ok(Some(retiring)) => retiring,
                    Ok(None) => Response::Status {
                        stow_version: env!("CARGO_PKG_VERSION").to_owned(),
                        protocol: PROTOCOL,
                        floor: PROTOCOL_FLOOR,
                    },
                    Err(reason) => return reject(&mut stream, at, reason).await,
                };
                write_frame_async(&mut stream, at, &answer).await?;
                request = None;
            }
            Ok(ControlRequest::Retire { executable }) => {
                let successor = match successor_of(&executable) {
                    Ok(successor) => successor,
                    Err(reason) => return reject(&mut stream, at, reason).await,
                };
                daemon.retirement.begin(successor);
                let retiring = daemon
                    .retirement
                    .reply()
                    .expect("a daemon that began retiring is retiring");
                write_frame_async(&mut stream, at, &retiring).await?;
                request = None;
            }
            Ok(ControlRequest::OpenSession(facts)) => {
                match daemon.give_way(client).await {
                    Ok(Some(retiring)) => {
                        return write_frame_async(&mut stream, at, &retiring).await;
                    }
                    Ok(None) => {}
                    Err(reason) => return reject(&mut stream, at, reason).await,
                }
                let driver = daemon.busy.driver();
                drop(request.take());
                return serve_session(stream, daemon, at, *facts, driver).await;
            }
            Ok(ControlRequest::EndSession) => {
                return reject(
                    &mut stream,
                    at,
                    "no session is open on this connection".to_owned(),
                )
                .await;
            }
            Err(error) => return reject(&mut stream, at, error.to_string()).await,
        }
    }
    Ok(())
}

/// The executable a `Retire` names, which must be a file at an absolute
/// path: it is executed in place of this daemon.
fn successor_of(executable: &[u8]) -> std::result::Result<PathBuf, String> {
    let successor = PathBuf::from(os_bytes::decode(executable)?);
    if !successor.is_absolute() || !successor.is_file() {
        return Err(format!(
            "the successor {} is not an executable file at an absolute path",
            successor.display()
        ));
    }
    Ok(successor)
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
async fn serve_session<S, P>(
    stream: S,
    daemon: &Daemon<P>,
    at: Negotiated,
    facts: SessionFacts,
    // Held until the session is gone, so a retirement waits for it.
    _driver: Held,
) -> Result<()>
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
            return reject(&mut write, at, format!("{error:#}")).await;
        }
    };
    daemon.table.insert(Arc::clone(&session));
    tracing::info!(session = %id, "opened a session");
    // The answer to `OpenSession` precedes every event the session's tasks
    // have recorded: those wait in `events` until the drive loop forwards
    // them.
    let answered =
        write_frame_async(&mut write, at, &Response::SessionOpened { session: id }).await;
    let driven = match answered {
        Ok(()) => {
            drive_session(
                &mut read,
                &mut write,
                at,
                &session,
                &mut events,
                &daemon.retirement,
            )
            .await
        }
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
        Ok(Driven::Restarted) => {
            tracing::warn!(session = %id, "the restart cut a session; ending it");
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
    /// The daemon's drain bound ran out while the session was open, and the
    /// driver was told so.
    Restarted,
}

/// Forward the session's events to its driver and wait for it to end the
/// session. Reads happen on a task of their own: a frame read is not
/// cancel-safe, and this loop also waits on the events.
async fn drive_session<R, W>(
    read: &mut R,
    write: &mut W,
    at: Negotiated,
    session: &Arc<Session>,
    events: &mut mpsc::UnboundedReceiver<Event>,
    retirement: &Retirement,
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
                    if !at.admits(frame.protocol) {
                        reject(write, at, foreign_stamp(at, frame.protocol)).await?;
                        return Ok(Driven::DriverGone);
                    }
                    match frame.decode::<ControlRequest>() {
                        Ok(ControlRequest::EndSession) => {
                            let end = session.end().await?;
                            // What the session recorded before it ended
                            // reaches the driver ahead of the answer.
                            while let Ok(event) = events.try_recv() {
                                write_frame_async(write, at, &Response::Event(event)).await?;
                            }
                            write_frame_async(write, at, &Response::SessionEnded(end)).await?;
                            tracing::info!(session = %id, "ended a session");
                            // A driver on Windows may run inside the job
                            // object of a cargo (`cargo stow`) that ends
                            // with every process it holds, a drain the
                            // driver started included: the daemon, which no
                            // cargo holds, starts it, after the driver has
                            // released its foreground hold.
                            #[cfg(windows)]
                            session.conclude().await;
                            return Ok(Driven::Ended);
                        }
                        Ok(other) => {
                            reject(
                                write,
                                at,
                                format!("a session's connection takes only EndSession, not {other:?}"),
                            )
                            .await?;
                            return Ok(Driven::DriverGone);
                        }
                        Err(error) => {
                            reject(write, at, error.to_string()).await?;
                            return Ok(Driven::DriverGone);
                        }
                    }
                }
                Some(event) = events.recv() => {
                    write_frame_async(write, at, &Response::Event(event)).await?;
                }
                () = resolution_done.wait(), if !resolution_sent => {
                    resolution_sent = true;
                    write_frame_async(write, at, &Response::Event(Event::ResolutionDone)).await?;
                }
                () = retirement.cut() => {
                    let successor = retirement
                        .pending()
                        .map_or_default(|pending| pending.successor.display().to_string());
                    reject(
                        write,
                        at,
                        format!("the stow daemon is restarting onto {successor} and this build's session cannot carry over; run the build again"),
                    )
                    .await?;
                    return Ok(Driven::Restarted);
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
async fn serve_wrapper<S, P>(
    mut stream: S,
    daemon: &Daemon<P>,
    at: Negotiated,
    id: SessionId,
    request: Held,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    P: Processes,
{
    let Some(session) = daemon.table.join(id).await else {
        return reject(
            &mut stream,
            at,
            format!("no session {id}: the stow daemon restarted or the build that opened it ended"),
        )
        .await;
    };
    // The session holds the daemon busy from here on.
    drop(request);
    let span = session.span().clone();
    converse(
        &mut stream,
        at,
        &session,
        daemon.settings.answer / 2,
        None,
        None,
        span,
    )
    .await
}

/// What a wrapper's connection delivered.
enum Incoming {
    /// The wrapper hung up.
    Closed,
    Request(WrapperRequest),
    /// A frame the daemon will not serve; the reason is the wrapper's to read.
    Refused(String),
}

async fn read_request<S: AsyncRead + Unpin + Send>(
    stream: &mut S,
    at: Negotiated,
) -> Result<Incoming> {
    let Some(frame) = read_frame_async(stream).await? else {
        return Ok(Incoming::Closed);
    };
    if !at.admits(frame.protocol) {
        return Ok(Incoming::Refused(foreign_stamp(at, frame.protocol)));
    }
    Ok(match frame.decode::<WrapperRequest>() {
        Ok(request) => Incoming::Request(request),
        Err(error) => Incoming::Refused(error.to_string()),
    })
}

/// A cargo wrapper's conversation with `session`, whose requests run under
/// a span of their own: what they log reaches this wrapper as events, as
/// far as `interest` wants, because no driver's connection carries a plain
/// build's events.
async fn converse_returning_events<S, P>(
    stream: &mut S,
    at: Negotiated,
    daemon: &Daemon<P>,
    session: &Arc<Session<Cargo>>,
    first: WrapperRequest,
    interest: LogInterest,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    P: Processes,
{
    // The nearest session span names the route an event goes to, so this
    // one, nested in the session's own, takes this wrapper's events.
    let route = SessionId::mint();
    let mut events = daemon.logs.register(route, interest);
    let span = tracing::info_span!(parent: session.span(), SESSION_SPAN, session = %route);
    let served = converse(
        stream,
        at,
        session,
        daemon.settings.answer / 2,
        Some(first),
        Some(&mut events),
        span,
    )
    .await;
    daemon.logs.unregister(route);
    served
}

/// One wrapper's conversation with `session`: `first` when its request was
/// already read, then a request and its answer until the wrapper hangs up
/// — which ends a flight it still holds. Requests run under `span`; the
/// events `events` collects from it go ahead of each answer.
async fn converse<S, O>(
    stream: &mut S,
    at: Negotiated,
    session: &Arc<Session<O>>,
    every: Duration,
    first: Option<WrapperRequest>,
    mut events: Option<&mut mpsc::UnboundedReceiver<Event>>,
    span: tracing::Span,
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
                None => match read_request(stream, at).await? {
                    Incoming::Closed => return Ok(()),
                    Incoming::Refused(reason) => return reject(stream, at, reason).await,
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
            let answer = working_meanwhile(stream, at, every, answering).await?;
            if let Some(events) = events.as_mut() {
                while let Ok(event) = events.try_recv() {
                    write_frame_async(stream, at, &Response::Event(event)).await?;
                }
            }
            write_frame_async(stream, at, &Response::Answer(answer)).await?;
        }
    }
    .instrument(span)
    .await
}

/// Await `work`, telling the wrapper every `every` that it is still being
/// done: a wrapper bounds its wait for a frame, and a decision that
/// fetches from the network, like the opening of a session, legitimately
/// outlasts that.
async fn working_meanwhile<S, T>(
    stream: &mut S,
    at: Negotiated,
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
            _ = tick.tick() => write_frame_async(stream, at, &Response::Working).await?,
        }
    }
}

/// What a wrapper of a cargo no driver opened a session for says about
/// itself.
struct CargoWrapper {
    /// The process that connected, when the platform says.
    peer: Option<u32>,
    /// The wrapper's `CARGO`.
    cargo: Option<Vec<u8>>,
    /// The `RUST_LOG` directives it wants its events at.
    rust_log: Option<String>,
}

/// A wrapper of a cargo no driver opened a session for: the session of
/// that cargo, opened by the first of its wrappers to need one.
async fn serve_cargo_wrapper<S, P>(
    mut stream: S,
    daemon: &Daemon<P>,
    at: Negotiated,
    client: &Client,
    wrapper: CargoWrapper,
    request: Held,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    P: Processes,
{
    let CargoWrapper {
        peer,
        cargo,
        rust_log,
    } = wrapper;
    // A `RUST_LOG` the filter parser rejects asks for no more than the
    // warnings and errors every wrapper gets.
    let interest = LogInterest::of_wrapper(rust_log.as_deref()).unwrap_or_else(|reason| {
        tracing::warn!(%reason, "ignoring the wrapper's RUST_LOG for its events");
        LogInterest::of_wrapper(None).expect("the default filter parses")
    });
    let first = match read_request(&mut stream, at).await? {
        Incoming::Closed => return Ok(()),
        Incoming::Refused(reason) => return reject(&mut stream, at, reason).await,
        Incoming::Request(request) => request,
    };
    // A probe belongs to no build: it needs neither a cargo nor a session.
    if is_probe(&first) {
        return serve_probe(stream, at, first, request).await;
    }
    let owner = match owner_of(daemon, peer, cargo).await {
        Ok(owner) => owner,
        Err(reason) => {
            tracing::warn!(%reason, "a wrapper's cargo could not be found");
            return reject(&mut stream, at, reason).await;
        }
    };
    let every = daemon.settings.answer / 2;
    let slot = daemon.table.cargo_slot(owner).await;
    if slot.is_outlived_daemon() {
        return reject(
            &mut stream,
            at,
            "the stow daemon restarted during this cargo build: its in-flight state and provenance marks are gone; run the build again".to_owned(),
        )
        .await;
    }
    if let Some(session) = slot.session() {
        // The session holds the daemon busy: a build already under way is
        // served through a retirement.
        drop(request);
        return converse_returning_events(&mut stream, at, daemon, &session, first, interest).await;
    }
    // A cargo with no session is about to open one, which a daemon that
    // must give way leaves to its successor: nothing of the request is
    // acted on, so the wrapper replays it.
    match daemon.give_way(client).await {
        Ok(Some(retiring)) => return write_frame_async(&mut stream, at, &retiring).await,
        Ok(None) => {}
        Err(reason) => return reject(&mut stream, at, reason).await,
    }
    // Nothing was settled before cargo started: the wrapper says what it
    // runs in, and the request it was holding is answered once the session
    // is open.
    write_frame_async(&mut stream, at, &Response::Answer(Answer::Describe)).await?;
    let environment = match read_request(&mut stream, at).await? {
        Incoming::Closed => return Ok(()),
        Incoming::Refused(reason) => return reject(&mut stream, at, reason).await,
        Incoming::Request(WrapperRequest::Describe(environment)) => environment,
        Incoming::Request(other) => {
            return reject(
                &mut stream,
                at,
                format!("the daemon asked for the build's environment, not {other:?}"),
            )
            .await;
        }
    };
    let opener = match Opener::of(&first) {
        Ok(opener) => opener,
        Err(reason) => return reject(&mut stream, at, reason).await,
    };
    let opening = slot.open_with(|| open_cargo_session(daemon.clone(), owner, opener, environment));
    let session = match working_meanwhile(&mut stream, at, every, opening).await? {
        Ok(session) => session,
        Err(reason) => {
            tracing::warn!(%owner, %reason, "a cargo's session could not be opened");
            return reject(&mut stream, at, reason).await;
        }
    };
    drop(request);
    converse_returning_events(&mut stream, at, daemon, &session, first, interest).await
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
async fn serve_probe<S>(
    mut stream: S,
    at: Negotiated,
    first: WrapperRequest,
    // Held for the probe's conversation, which a restart would cut.
    _request: Held,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut next = Some(first);
    loop {
        let request = match next.take() {
            Some(request) => request,
            None => match read_request(&mut stream, at).await? {
                Incoming::Closed => return Ok(()),
                Incoming::Refused(reason) => return reject(&mut stream, at, reason).await,
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
        write_frame_async(&mut stream, at, &Response::Answer(answer)).await?;
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
    // Held from the opening until the session's end has concluded, so a
    // retirement waits for the build and for its journal.
    let held = daemon.busy.cargo();
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
        held,
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
    held: Held,
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
        drop(held);
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

    use super::{
        Busy, Daemon, Installed, Retirement, refuse_until_exit, serve_connection, sweep_sessions,
        working_meanwhile,
    };
    use crate::daemon::Settings;
    use crate::daemon::events::SessionLogs;
    use crate::daemon::owner::{CargoOwner, Processes};
    use crate::daemon::protocol::{
        ControlRequest, Hello, Negotiated, PROTOCOL, PROTOCOL_FLOOR, Response, Role, SessionRef,
        WrapperRequest, encode, encode_at, read_frame_async,
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

    /// The bound a test daemon's drain lasts.
    const DRAIN: Duration = Duration::from_millis(400);

    fn daemon(sessions: &std::path::Path) -> Daemon<Machine> {
        Daemon {
            sessions: sessions.to_owned(),
            settings: Settings {
                answer: Duration::from_millis(60),
                start: Duration::from_secs(30),
                log_bytes: 1 << 20,
                drain: DRAIN,
            },
            logs: SessionLogs::default(),
            table: SessionTable::start(),
            processes: Machine::default(),
            retirement: Retirement::new(DRAIN),
            busy: Busy::default(),
            installed: Arc::new(Installed::of_current().expect("this test's executable")),
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
        let task = tokio::spawn(serve_connection(
            daemon_end,
            peer,
            daemon.clone(),
            daemon.busy.request(),
        ));
        (client, task)
    }

    /// The hello of a client of this build running `/stow`.
    fn hello(role: Role) -> Hello {
        Hello::new(role, std::path::Path::new("/stow"))
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
        send(&mut control, &hello(Role::Control)).await;
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
            &hello(Role::Wrapper {
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
            &hello(Role::Wrapper {
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
            &hello(Role::Wrapper {
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
        let answer = working_meanwhile(
            &mut daemon_end,
            Negotiated::for_tests(),
            Duration::from_millis(20),
            answering,
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
        send(&mut client, &hello(Role::Control)).await;
        send(&mut client, &ControlRequest::Status).await;
        assert_eq!(
            receive(&mut client).await,
            Response::Status {
                stow_version: env!("CARGO_PKG_VERSION").to_owned(),
                protocol: PROTOCOL,
                floor: PROTOCOL_FLOOR,
            }
        );
    }

    /// The bytes of an executable file that exists: this test binary.
    fn executable() -> Vec<u8> {
        crate::daemon::session::os_bytes::encode(
            std::env::current_exe().expect("current exe").as_os_str(),
        )
    }

    async fn retire(daemon: &Daemon<Machine>) -> Response {
        let (mut client, _task) = connect(daemon);
        send(&mut client, &hello(Role::Control)).await;
        send(
            &mut client,
            &ControlRequest::Retire {
                executable: executable(),
            },
        )
        .await;
        receive(&mut client).await
    }

    #[tokio::test]
    async fn a_retire_begins_a_retirement_and_is_answered_with_the_time_left() {
        let sessions = tempfile::tempdir().expect("sessions");
        let daemon = daemon(sessions.path());
        let Response::Retiring {
            stow_version,
            until_millis,
        } = retire(&daemon).await
        else {
            panic!("a retire is answered with Retiring");
        };
        assert_eq!(stow_version, env!("CARGO_PKG_VERSION"));
        assert!(until_millis <= 400, "{until_millis}");
        assert_eq!(
            daemon.retirement.pending().expect("retiring").successor,
            std::path::PathBuf::from(
                crate::daemon::session::os_bytes::decode(&executable()).expect("decode")
            )
        );
    }

    #[tokio::test]
    async fn a_retire_naming_no_executable_file_is_refused() {
        let sessions = tempfile::tempdir().expect("sessions");
        let daemon = daemon(sessions.path());
        for executable in [b"relative/stow".to_vec(), b"/no/such/stow".to_vec()] {
            let (mut client, _task) = connect(&daemon);
            send(&mut client, &hello(Role::Control)).await;
            send(&mut client, &ControlRequest::Retire { executable }).await;
            assert!(
                matches!(receive(&mut client).await, Response::Rejected { .. }),
                "a successor must be a file at an absolute path"
            );
        }
        assert!(daemon.retirement.pending().is_none());
    }

    /// A retiring daemon leaves the opening of sessions to its successor:
    /// the asker is told, and nothing of its request is acted on.
    #[tokio::test]
    async fn a_retiring_daemon_answers_session_opening_requests_with_retiring() {
        let sessions = tempfile::tempdir().expect("sessions");
        let target = tempfile::tempdir().expect("target");
        let daemon = daemon(sessions.path());
        retire(&daemon).await;
        let (mut status, _task) = connect(&daemon);
        send(&mut status, &hello(Role::Control)).await;
        send(&mut status, &ControlRequest::Status).await;
        assert!(matches!(
            receive(&mut status).await,
            Response::Retiring { .. }
        ));
        let (mut opener, _task) = connect(&daemon);
        send(&mut opener, &hello(Role::Control)).await;
        send(
            &mut opener,
            &ControlRequest::OpenSession(Box::new(facts(target.path()).await)),
        )
        .await;
        assert!(matches!(
            receive(&mut opener).await,
            Response::Retiring { .. }
        ));
        assert_eq!(
            std::fs::read_dir(sessions.path())
                .expect("sessions")
                .count(),
            0,
            "no session was opened"
        );
    }

    /// A build under way is carried through the drain: its wrappers are
    /// served, while anything that would open a session is not.
    #[tokio::test]
    async fn a_wrapper_of_an_open_session_is_served_through_a_retirement() {
        let sessions = tempfile::tempdir().expect("sessions");
        let target = tempfile::tempdir().expect("target");
        let daemon = daemon(sessions.path());
        let (_control, _task, id) = open(&daemon, target.path()).await;
        retire(&daemon).await;
        let planned = plan_in(&daemon, id, &target.path().join("debug").join("deps")).await;
        assert!(
            matches!(planned, Response::Answer(Answer::Compile(_))),
            "{planned:?}"
        );
    }

    /// A cargo with no session is told to retry, and one that has a session
    /// is served.
    #[tokio::test]
    async fn a_cargo_with_no_session_retries_and_one_with_a_session_is_served() {
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
        retire(&daemon).await;
        let (_second, _second_task, served) = wrapper_of(&daemon, 12, 1, &request).await;
        assert!(
            matches!(served, Response::Answer(Answer::Compile(_))),
            "the cargo's session is open: {served:?}"
        );
        let (_other, _other_task, told) = wrapper_of(&daemon, 21, 2, &request).await;
        assert!(
            matches!(told, Response::Retiring { .. }),
            "another cargo has no session yet: {told:?}"
        );
        assert_eq!(
            std::fs::read_dir(sessions.path())
                .expect("sessions")
                .count(),
            1,
            "no session was opened for it"
        );
    }

    /// A probe belongs to no build and is served through a retirement, so
    /// the build that follows it is not cut.
    #[tokio::test]
    async fn a_probe_is_served_through_a_retirement() {
        let sessions = tempfile::tempdir().expect("sessions");
        let daemon = daemon(sessions.path());
        retire(&daemon).await;
        let toolchain = BuildToolchain::for_tests().await;
        let probe = WrapperRequest::Plan(Plan::new(
            toolchain.rustc().as_os_str(),
            &[OsString::from("-vV")],
            InvocationEnv::for_tests(),
        ));
        let (_wrapper, _task, first) = wrapper_of(&daemon, 11, 1, &probe).await;
        assert!(
            matches!(first, Response::Answer(Answer::Compile(_))),
            "{first:?}"
        );
    }

    #[tokio::test]
    async fn the_drain_ends_when_the_last_driver_session_ends() {
        let sessions = tempfile::tempdir().expect("sessions");
        let target = tempfile::tempdir().expect("target");
        let daemon = daemon(sessions.path());
        let (mut control, task, _id) = open(&daemon, target.path()).await;
        retire(&daemon).await;
        let began = std::time::Instant::now();
        let drained = tokio::spawn({
            let daemon = daemon.clone();
            async move {
                daemon
                    .retirement
                    .drained(&daemon.busy, daemon.settings.answer)
                    .await
            }
        });
        send(&mut control, &ControlRequest::EndSession).await;
        while let Response::Event(_) = receive(&mut control).await {}
        task.await.expect("join").expect("served");
        drained.await.expect("the drain");
        assert!(
            began.elapsed() < DRAIN,
            "it ended with the build, not at the bound"
        );
    }

    #[tokio::test]
    async fn a_driver_session_still_open_at_the_bound_is_cut_naming_the_restart() {
        let sessions = tempfile::tempdir().expect("sessions");
        let target = tempfile::tempdir().expect("target");
        let daemon = daemon(sessions.path());
        let (mut control, task, id) = open(&daemon, target.path()).await;
        retire(&daemon).await;
        let drained = tokio::spawn({
            let daemon = daemon.clone();
            async move {
                daemon
                    .retirement
                    .drained(&daemon.busy, daemon.settings.answer)
                    .await
            }
        });
        let refusal = loop {
            match receive(&mut control).await {
                Response::Event(_) => {}
                other => break other,
            }
        };
        let Response::Rejected { reason } = refusal else {
            panic!("the cut session is refused: {refusal:?}");
        };
        assert!(reason.contains("restarting"), "{reason}");
        task.await.expect("join").expect("served");
        drained
            .await
            .expect("the drain ends once the session is cut");
        assert!(daemon.table.join(id).await.is_none(), "the session is gone");
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

    /// A client's `Hello` for `protocol`, which also stamps its frame.
    async fn send_hello_for(client: &mut DuplexStream, protocol: u16) {
        let hello = Hello {
            protocol,
            floor: protocol,
            stow_version: "9.9.9".to_owned(),
            ..hello(Role::Control)
        };
        client
            .write_all(&encode_at(protocol, &hello).expect("encode"))
            .await
            .expect("write");
    }

    /// The next frame's stamp and response.
    async fn receive_stamped(stream: &mut DuplexStream) -> (u16, Response) {
        let frame = read_frame_async(stream)
            .await
            .expect("read")
            .expect("a frame");
        (
            frame.protocol,
            frame.decode::<Response>().expect("response"),
        )
    }

    #[tokio::test]
    async fn an_older_client_is_refused_naming_both_ranges_in_its_own_protocol() {
        let sessions = tempfile::tempdir().expect("sessions");
        let (mut client, _task) = connect(&daemon(sessions.path()));
        send_hello_for(&mut client, PROTOCOL_FLOOR - 1).await;
        let (stamp, Response::Rejected { reason }) = receive_stamped(&mut client).await else {
            panic!("a client below the floor must be rejected");
        };
        assert_eq!(
            stamp,
            PROTOCOL_FLOOR - 1,
            "the refusal is stamped so the client reads it"
        );
        assert!(
            reason.contains(&(PROTOCOL_FLOOR - 1).to_string())
                && reason.contains(&PROTOCOL.to_string()),
            "{reason}"
        );
    }

    /// A client that speaks only newer protocols is a newer stow: the
    /// daemon gives way to its executable, and says so in its own protocol,
    /// which the client reads because the answer is core.
    #[tokio::test]
    async fn a_client_of_a_newer_protocol_is_given_way_to() {
        let sessions = tempfile::tempdir().expect("sessions");
        let daemon = daemon(sessions.path());
        let (mut client, _task) = connect(&daemon);
        let hello = Hello {
            protocol: PROTOCOL + 1,
            floor: PROTOCOL + 1,
            stow_version: "9.9.9".to_owned(),
            executable: executable(),
            ..hello(Role::Control)
        };
        client
            .write_all(&encode_at(PROTOCOL + 1, &hello).expect("encode"))
            .await
            .expect("write");
        let (stamp, response) = receive_stamped(&mut client).await;
        assert_eq!(stamp, PROTOCOL);
        assert!(
            matches!(response, Response::Retiring { .. }),
            "{response:?}"
        );
        assert_eq!(
            daemon.retirement.pending().expect("retiring").successor,
            std::path::PathBuf::from(
                crate::daemon::session::os_bytes::decode(&executable()).expect("decode")
            )
        );
    }

    #[tokio::test]
    async fn a_client_of_a_newer_protocol_naming_no_executable_is_refused() {
        let sessions = tempfile::tempdir().expect("sessions");
        let daemon = daemon(sessions.path());
        let (mut client, _task) = connect(&daemon);
        send_hello_for(&mut client, PROTOCOL + 1).await;
        let (stamp, response) = receive_stamped(&mut client).await;
        assert_eq!(stamp, PROTOCOL);
        assert!(
            matches!(response, Response::Rejected { .. }),
            "{response:?}"
        );
        assert!(daemon.retirement.pending().is_none());
    }

    /// A status request from a client of `stow_version` running
    /// `executable`.
    async fn status_from(
        daemon: &Daemon<Machine>,
        stow_version: &str,
        executable: Vec<u8>,
    ) -> Response {
        let (mut client, _task) = connect(daemon);
        let hello = Hello {
            stow_version: stow_version.to_owned(),
            executable,
            ..hello(Role::Control)
        };
        send(&mut client, &hello).await;
        send(&mut client, &ControlRequest::Status).await;
        receive(&mut client).await
    }

    #[tokio::test]
    async fn a_newer_stow_is_given_way_to_at_its_first_request() {
        let sessions = tempfile::tempdir().expect("sessions");
        let daemon = daemon(sessions.path());
        for same_or_older in [env!("CARGO_PKG_VERSION"), "0.0.1"] {
            assert!(
                matches!(
                    status_from(&daemon, same_or_older, b"/stow".to_vec()).await,
                    Response::Status { .. }
                ),
                "stow {same_or_older} does not displace this daemon"
            );
        }
        assert!(daemon.retirement.pending().is_none());
        let newer = semver::Version::parse(env!("CARGO_PKG_VERSION")).expect("version");
        let newer = semver::Version::new(newer.major, newer.minor, newer.patch + 1).to_string();
        let Response::Retiring { stow_version, .. } =
            status_from(&daemon, &newer, executable()).await
        else {
            panic!("a newer stow is given way to");
        };
        assert_eq!(stow_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            daemon.retirement.pending().expect("retiring").successor,
            std::path::PathBuf::from(
                crate::daemon::session::os_bytes::decode(&executable()).expect("decode")
            )
        );
    }

    #[tokio::test]
    async fn a_client_whose_version_is_not_a_version_is_refused() {
        let sessions = tempfile::tempdir().expect("sessions");
        let daemon = daemon(sessions.path());
        let Response::Rejected { reason } = status_from(&daemon, "next", executable()).await else {
            panic!("an unparsable version is refused");
        };
        assert!(reason.contains("next"), "{reason}");
        assert!(daemon.retirement.pending().is_none());
    }

    /// The daemon's executable is replaced by an install: the next request
    /// that opens a session gives way to the file now at its path.
    #[tokio::test]
    async fn an_install_over_the_daemons_executable_is_given_way_to() {
        let sessions = tempfile::tempdir().expect("sessions");
        let installed = tempfile::tempdir().expect("install");
        let path = installed.path().join("stow");
        std::fs::copy(std::env::current_exe().expect("exe"), &path).expect("copy");
        let daemon = Daemon {
            installed: Arc::new(Installed::of(path.clone()).expect("record")),
            ..daemon(sessions.path())
        };
        assert!(matches!(
            status_from(&daemon, env!("CARGO_PKG_VERSION"), b"/stow".to_vec()).await,
            Response::Status { .. }
        ));
        let next = installed.path().join("next");
        std::fs::copy(std::env::current_exe().expect("exe"), &next).expect("copy");
        std::fs::rename(&next, &path).expect("replace");
        assert!(matches!(
            status_from(&daemon, env!("CARGO_PKG_VERSION"), b"/stow".to_vec()).await,
            Response::Retiring { .. }
        ));
        assert_eq!(
            daemon.retirement.pending().expect("retiring").successor,
            path
        );
    }

    /// A cargo whose first wrapper arrives at a daemon that must give way
    /// is told so before anything of its request is acted on.
    #[tokio::test]
    async fn a_cargo_with_no_session_is_given_way_for_through_its_wrapper() {
        let sessions = tempfile::tempdir().expect("sessions");
        let target = tempfile::tempdir().expect("target");
        let daemon = daemon(sessions.path());
        let newer = semver::Version::parse(env!("CARGO_PKG_VERSION")).expect("version");
        let newer = semver::Version::new(newer.major, newer.minor, newer.patch + 1).to_string();
        daemon.processes.start(70, 7);
        let (mut wrapper, _task) = connect_from(&daemon, Some(70));
        let hello = Hello {
            stow_version: newer,
            executable: executable(),
            ..hello(Role::Wrapper {
                session: SessionRef::Cargo {
                    cargo: None,
                    rust_log: None,
                },
            })
        };
        send(&mut wrapper, &hello).await;
        send(&mut wrapper, &unit_request(target.path()).await).await;
        assert!(matches!(
            receive(&mut wrapper).await,
            Response::Retiring { .. }
        ));
        assert_eq!(
            std::fs::read_dir(sessions.path())
                .expect("sessions")
                .count(),
            0,
            "no session was opened"
        );
    }

    #[tokio::test]
    async fn a_hello_whose_frame_is_stamped_with_another_protocol_is_refused() {
        let sessions = tempfile::tempdir().expect("sessions");
        let (mut client, _task) = connect(&daemon(sessions.path()));
        client
            .write_all(&encode_at(PROTOCOL + 1, &hello(Role::Control)).expect("encode"))
            .await
            .expect("write");
        let (_, Response::Rejected { reason }) = receive_stamped(&mut client).await else {
            panic!("a disagreeing stamp must be rejected");
        };
        assert!(reason.contains("stamped"), "{reason}");
    }

    /// Every frame of a connection is stamped with the protocol its client
    /// said hello with, so a client of an older protocol in the daemon's
    /// range could read its replies.
    #[tokio::test]
    async fn every_reply_carries_the_protocol_the_connection_negotiated() {
        let sessions = tempfile::tempdir().expect("sessions");
        let (mut client, _task) = connect(&daemon(sessions.path()));
        send(&mut client, &hello(Role::Control)).await;
        send(&mut client, &ControlRequest::Status).await;
        assert_eq!(receive_stamped(&mut client).await.0, PROTOCOL);
        send(&mut client, &ControlRequest::EndSession).await;
        let (stamp, response) = receive_stamped(&mut client).await;
        assert_eq!(stamp, PROTOCOL);
        assert!(
            matches!(response, Response::Rejected { .. }),
            "{response:?}"
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
            &hello(Role::Wrapper {
                session: SessionRef::Cargo {
                    cargo: None,
                    rust_log: None,
                },
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
            &hello(Role::Wrapper {
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
            &hello(Role::Wrapper {
                session: SessionRef::Cargo {
                    cargo: None,
                    rust_log: None,
                },
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
