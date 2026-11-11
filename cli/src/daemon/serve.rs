//! The daemon process: `stow daemon`.
//!
//! It takes `daemon.lock` without blocking, so a second daemon — one the
//! login trigger started beside a client's, say — finds the lock held and
//! exits 0. The holder removes a stale endpoint, binds its own, reports
//! readiness to the client that spawned it (`--ready <endpoint>`) and
//! serves. The lock is a file lock, so a dead daemon releases it and no
//! pid file is needed.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use stow_types::error::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinSet;
use tracing_subscriber::EnvFilter;

use super::log::LogWriter;
use super::notify::{self, Notification};
use super::protocol::{
    Frame, Hello, PROTOCOL, Request, Response, read_frame_async, write_frame_async,
};
use super::{RunDir, Settings};
use crate::file_lock::FileLock;

#[cfg(unix)]
type Listener = tokio::net::UnixListener;

#[cfg(windows)]
struct Listener {
    name: PathBuf,
    server: tokio::net::windows::named_pipe::NamedPipeServer,
}

/// Run the daemon until it fails. Returns `Ok` only when another daemon
/// already holds the lock.
pub async fn run(ready: Option<PathBuf>) -> Result<()> {
    let run_dir = blocking(|| {
        let run_dir = RunDir::prepare(RunDir::locate()?)?;
        install_logging(&run_dir)?;
        Ok(run_dir)
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
    let endpoint = run_dir.endpoint();
    let listener = bind(&endpoint).await?;
    tracing::info!(
        pid = std::process::id(),
        endpoint = %endpoint.display(),
        "stow daemon serving"
    );
    notify_ready(ready, Notification::Ready).await?;
    accept_loop(listener).await
}

/// Run `work` off the executor: it does file work.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .wrap_err("run the daemon's blocking work")?
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
/// the null device, so nothing it says would otherwise be kept.
fn install_logging(run_dir: &RunDir) -> Result<()> {
    let writer = LogWriter::open(&run_dir.log(), Settings::from_env()?.log_bytes)?;
    // The daemon's environment is cleared, so `RUST_LOG` only reaches it
    // when started by hand; the default is what a log of a long-lived
    // process should carry.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .with_env_filter(filter)
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
async fn accept_loop(listener: Listener) -> Result<()> {
    let mut connections = JoinSet::new();
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .wrap_err("accept a daemon connection")?;
        connections.spawn(serve_connection(stream));
        reap(&mut connections);
    }
}

#[cfg(windows)]
async fn accept_loop(mut listener: Listener) -> Result<()> {
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
        connections.spawn(serve_connection(connected));
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

/// One client: its `Hello`, then its requests until it hangs up.
async fn serve_connection<S: AsyncRead + AsyncWrite + Unpin + Send>(mut stream: S) -> Result<()> {
    let Some(first) = read_frame_async(&mut stream).await? else {
        return Ok(());
    };
    if let Err(reason) = check_hello(&first) {
        tracing::warn!(%reason, "daemon connection refused");
        return reject(&mut stream, reason).await;
    }
    while let Some(frame) = read_frame_async(&mut stream).await? {
        if frame.protocol != PROTOCOL {
            return reject(&mut stream, protocol_mismatch(frame.protocol)).await;
        }
        match frame.decode::<Request>() {
            Ok(Request::Status) => {
                write_frame_async(
                    &mut stream,
                    &Response::Status {
                        stow_version: env!("CARGO_PKG_VERSION").to_owned(),
                        protocol: PROTOCOL,
                    },
                )
                .await?;
            }
            Err(error) => return reject(&mut stream, error.to_string()).await,
        }
    }
    Ok(())
}

fn check_hello(first: &Frame) -> std::result::Result<(), String> {
    if first.protocol != PROTOCOL {
        return Err(protocol_mismatch(first.protocol));
    }
    let hello = first
        .decode::<Hello>()
        .map_err(|error| format!("the first frame must be a Hello: {error}"))?;
    if hello.protocol != PROTOCOL {
        return Err(protocol_mismatch(hello.protocol));
    }
    tracing::debug!(client_version = %hello.stow_version, "daemon client connected");
    Ok(())
}

fn protocol_mismatch(peer: u16) -> String {
    format!("the client speaks protocol {peer}, this daemon speaks {PROTOCOL}")
}

async fn reject<S: AsyncWrite + Unpin + Send>(stream: &mut S, reason: String) -> Result<()> {
    write_frame_async(stream, &Response::Rejected { reason }).await
}

#[cfg(all(test, unix))]
mod tests {
    use tokio::io::AsyncWriteExt as _;

    use super::serve_connection;
    use crate::daemon::protocol::{Hello, PROTOCOL, Request, Response, encode, read_frame_async};

    async fn answer(wire: Vec<u8>) -> Vec<Response> {
        let (mut client, daemon_end) = tokio::io::duplex(4096);
        let task = tokio::spawn(serve_connection(daemon_end));
        client.write_all(&wire).await.expect("write");
        client.shutdown().await.expect("shutdown");
        let mut responses = Vec::new();
        while let Some(frame) = read_frame_async(&mut client).await.expect("read") {
            responses.push(frame.decode::<Response>().expect("response"));
        }
        task.await.expect("join").expect("served");
        responses
    }

    #[tokio::test]
    async fn status_after_hello_reports_version_and_protocol() {
        let mut wire = encode(&Hello::current()).expect("hello");
        wire.extend(encode(&Request::Status).expect("status"));
        assert_eq!(
            answer(wire).await,
            vec![Response::Status {
                stow_version: env!("CARGO_PKG_VERSION").to_owned(),
                protocol: PROTOCOL,
            }]
        );
    }

    #[tokio::test]
    async fn a_first_frame_that_is_not_a_hello_is_rejected() {
        let wire = encode(&Request::Status).expect("status");
        let responses = answer(wire).await;
        assert!(matches!(responses.as_slice(), [Response::Rejected { .. }]));
    }

    #[tokio::test]
    async fn a_hello_for_another_protocol_is_rejected() {
        let wire = encode(&Hello {
            protocol: PROTOCOL + 1,
            stow_version: "9.9.9".to_owned(),
        })
        .expect("hello");
        let responses = answer(wire).await;
        assert!(
            matches!(responses.as_slice(), [Response::Rejected { reason }] if reason.contains("protocol")),
            "{responses:?}"
        );
    }
}
