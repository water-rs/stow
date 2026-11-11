//! The one path every client takes to reach the daemon.
//!
//! Connect; when nothing listens, take `start.lock`, connect again, and
//! otherwise spawn the daemon detached, wait for its readiness
//! notification within the configured bound, and connect. A daemon that
//! does not come up is an error naming the daemon: there is no fallback.
//! The path never asks a service manager anything.
//!
//! The whole path is synchronous and std-only: no async runtime and no
//! configuration load, because the clients that call it run once per
//! compiled unit.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use stow_types::error::{Context, Result};

use super::notify::{Notification, ReadyListener};
use super::protocol::{self, Hello, PROTOCOL, Request, Response};
use super::{RunDir, STOW_DAEMON_DIR_ENV, Settings};
use crate::file_lock::FileLock;

#[cfg(unix)]
type Stream = std::os::unix::net::UnixStream;
#[cfg(windows)]
type Stream = std::fs::File;

/// The first pause between connection attempts to a daemon that holds the
/// lock but is not listening yet. A daemon binds within milliseconds of
/// taking the lock, so the first retry is short.
const FIRST_RECONNECT_PAUSE: Duration = Duration::from_millis(5);
/// The longest pause between those attempts: the pause doubles up to here,
/// which keeps a slow starter from being polled hard.
const LONGEST_RECONNECT_PAUSE: Duration = Duration::from_millis(200);

/// What a daemon reports about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReply {
    /// The daemon's stow version.
    pub stow_version: String,
    /// The protocol number the daemon speaks.
    pub protocol: u16,
}

/// A connection to the daemon that has not yet said hello.
#[derive(Debug)]
pub struct Connection {
    stream: Stream,
    answer: Duration,
}

impl Connection {
    /// Say hello and ask for the daemon's status, in one write.
    ///
    /// # Errors
    ///
    /// The daemon does not answer within the answer bound, answers
    /// something else, or refuses the connection.
    pub fn status(self) -> Result<StatusReply> {
        let answer = self.answer;
        #[cfg(unix)]
        let reply = exchange(self.stream);
        #[cfg(windows)]
        let reply = with_deadline(answer, move || exchange(self.stream));
        reply.wrap_err_with(|| {
            format!(
                "the stow daemon did not complete a status exchange within {} s",
                answer.as_secs()
            )
        })
    }
}

fn exchange<S: Read + Write>(mut stream: S) -> Result<StatusReply> {
    let mut request = protocol::encode(&Hello::current())?;
    request.extend(protocol::encode(&Request::Status)?);
    stream
        .write_all(&request)
        .and_then(|()| stream.flush())
        .wrap_err("send Hello and Status to the daemon")?;
    let frame = protocol::read_frame(&mut stream)?;
    if frame.protocol != PROTOCOL {
        return Err(stow_types::stow_error!(
            "the daemon speaks protocol {}, this stow speaks {PROTOCOL}",
            frame.protocol
        ));
    }
    match frame.decode::<Response>()? {
        Response::Status {
            stow_version,
            protocol,
        } => Ok(StatusReply {
            stow_version,
            protocol,
        }),
        Response::Rejected { reason } => Err(stow_types::stow_error!(
            "the daemon refused the connection: {reason}"
        )),
    }
}

/// A named pipe has no read timeout, so the exchange runs on a thread the
/// caller stops waiting for.
#[cfg(windows)]
fn with_deadline<T: Send + 'static>(
    bound: Duration,
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("stow-daemon-exchange".to_owned())
        .spawn(move || {
            let _ = sender.send(work());
        })
        .wrap_err("spawn the daemon exchange thread")?;
    receiver
        .recv_timeout(bound)
        .map_err(|_| stow_types::stow_error!("no answer within {} s", bound.as_secs()))?
}

enum Attempt {
    Connected(Stream),
    Down,
}

/// Connect once. A missing endpoint or a refused connection means the
/// daemon is down; any other failure is an error.
#[cfg(unix)]
fn try_connect(endpoint: &Path, answer: Duration) -> Result<Attempt> {
    use std::io::ErrorKind;
    match Stream::connect(endpoint) {
        Ok(stream) => {
            stream
                .set_read_timeout(Some(answer))
                .and_then(|()| stream.set_write_timeout(Some(answer)))
                .wrap_err("bound the daemon connection")?;
            Ok(Attempt::Connected(stream))
        }
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::NotFound | ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(Attempt::Down)
        }
        Err(error) => Err(error)
            .wrap_err_with(|| format!("connect to the stow daemon at {}", endpoint.display())),
    }
}

/// Connect once. A missing pipe means the daemon is down; a pipe whose
/// instances are all busy is retried within the answer bound.
#[cfg(windows)]
fn try_connect(endpoint: &Path, answer: Duration) -> Result<Attempt> {
    /// `ERROR_PIPE_BUSY`: every instance of the pipe is serving a client.
    const PIPE_BUSY: i32 = 231;
    /// The pause before asking a busy pipe again.
    const BUSY_PAUSE: Duration = Duration::from_millis(10);
    let deadline = Instant::now() + answer;
    loop {
        match OpenOptions::new().read(true).write(true).open(endpoint) {
            Ok(pipe) => return Ok(Attempt::Connected(pipe)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Attempt::Down),
            Err(error) if error.raw_os_error() == Some(PIPE_BUSY) && Instant::now() < deadline => {
                std::thread::sleep(BUSY_PAUSE);
            }
            Err(error) => {
                return Err(error).wrap_err_with(|| {
                    format!("connect to the stow daemon at {}", endpoint.display())
                });
            }
        }
    }
}

/// Reach the daemon, starting it when it is down.
///
/// `exe` is the executable the daemon is started from: the stow runtime
/// executable, never a wrapper shim.
///
/// # Errors
///
/// The daemon cannot be started, does not report ready within
/// [`Settings::start`], or does not accept the connection.
pub fn connect_or_start(exe: &Path, settings: Settings) -> Result<Connection> {
    let run_dir = RunDir::prepare(RunDir::locate()?)?;
    let endpoint = run_dir.endpoint();
    let connected = |stream| Connection {
        stream,
        answer: settings.answer,
    };
    if let Attempt::Connected(stream) = try_connect(&endpoint, settings.answer)? {
        return Ok(connected(stream));
    }
    // One client starts the daemon at a time; the rest wait here and find
    // it running when they get the lock.
    let start_lock =
        FileLock::exclusive(open_lock(&run_dir.start_lock())?).wrap_err("lock the daemon start")?;
    if let Attempt::Connected(stream) = try_connect(&endpoint, settings.answer)? {
        return Ok(connected(stream));
    }
    let started = Instant::now();
    #[cfg(unix)]
    let listener = ReadyListener::bind(&run_dir)?;
    #[cfg(windows)]
    let listener = ReadyListener::bind()?;
    let mut child = spawn_daemon(exe, &run_dir, listener.endpoint())?;
    let log = run_dir.log();
    let notification = listener.wait(settings.start, || {
        let exited = child.try_wait().wrap_err("watch the stow daemon")?;
        exited.map_or(Ok(()), |status| {
            Err(stow_types::stow_error!(
                "the stow daemon exited with {status} before it was ready; its log is {}",
                log.display()
            ))
        })
    });
    let notification = match notification {
        Ok(notification) => notification,
        Err(error) => {
            // The daemon this path started never reported ready: it does
            // not outlive the failure.
            let _ = child.kill();
            let _ = child.wait();
            return Err(error.wrap_err(format!(
                "start the stow daemon (start bound {} s, log {})",
                settings.start.as_secs(),
                log.display()
            )));
        }
    };
    let stream = match notification {
        Notification::Ready => match try_connect(&endpoint, settings.answer)? {
            Attempt::Connected(stream) => stream,
            Attempt::Down => {
                return Err(stow_types::stow_error!(
                    "the stow daemon reported ready but nothing listens at {}",
                    endpoint.display()
                ));
            }
        },
        Notification::LockHeld => {
            // The daemon this path spawned found another one holding the
            // lock and exits; reap it, and wait for the holder to listen.
            let _ = child.wait();
            reconnect(&endpoint, settings, started)?
        }
    };
    drop(start_lock);
    Ok(connected(stream))
}

/// Connect to a daemon that holds the lock but is not listening yet,
/// backing off until the start bound, counted from `started`, runs out.
fn reconnect(endpoint: &Path, settings: Settings, started: Instant) -> Result<Stream> {
    let deadline = started + settings.start;
    let mut pause = FIRST_RECONNECT_PAUSE;
    loop {
        if let Attempt::Connected(stream) = try_connect(endpoint, settings.answer)? {
            return Ok(stream);
        }
        if Instant::now() + pause > deadline {
            return Err(stow_types::stow_error!(
                "another stow daemon holds the lock but does not listen at {} within {} s",
                endpoint.display(),
                settings.start.as_secs()
            ));
        }
        std::thread::sleep(pause);
        pause = (pause * 2).min(LONGEST_RECONNECT_PAUSE);
    }
}

fn open_lock(path: &Path) -> Result<std::fs::File> {
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .wrap_err_with(|| format!("open {}", path.display()))
}

/// Spawn the daemon so that it keeps nothing of this process: its own
/// session, a cleared environment, null stdio, no inherited descriptors,
/// and the runtime directory as its working directory.
fn spawn_daemon(exe: &Path, run_dir: &RunDir, notify: &Path) -> Result<Child> {
    let mut command = Command::new(exe);
    command
        .arg("daemon")
        .arg("--ready")
        .arg(notify)
        .env_clear()
        // The daemon is told where its directory is instead of deriving
        // it from an environment it no longer has (`XDG_CACHE_HOME`).
        .env(STOW_DAEMON_DIR_ENV, run_dir.path())
        .current_dir(run_dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;

        use super::descriptors;
        // What a daemon needs to find the user's directories and nothing
        // else of the starter's.
        // and the one setting the daemon itself reads.
        for key in [
            "HOME",
            "USER",
            "LOGNAME",
            "TMPDIR",
            super::STOW_DAEMON_LOG_BYTES_ENV,
        ] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let inherited = descriptors::open_from(descriptors::FIRST_INHERITED)
            .wrap_err("list the descriptors this process holds")?;
        // SAFETY: the hook calls only `setsid` and `fcntl`, both
        // async-signal-safe, and reads a list built before the fork.
        unsafe {
            command.pre_exec(move || {
                // A session of its own: a signal aimed at the caller's
                // process group never reaches the daemon.
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                descriptors::mark_close_on_exec(&inherited)
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        /// `DETACHED_PROCESS`: no console of the caller's.
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        /// `CREATE_NEW_PROCESS_GROUP`: a Ctrl-C aimed at the caller's
        /// group never reaches the daemon.
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        /// `CREATE_NO_WINDOW`: no console window opens for it.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
        // Winsock refuses to start in a process whose environment lacks
        // the system root, so that one variable is the system's own and
        // is kept.
        if let Some(root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", root);
        }
    }
    command
        .spawn()
        .wrap_err_with(|| format!("spawn the stow daemon {}", exe.display()))
}
