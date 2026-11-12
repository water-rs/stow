//! The one path every client takes to reach the daemon.
//!
//! Connect; when nothing listens, take `start.lock`, connect again, and
//! otherwise start the daemon, wait for its readiness notification within
//! the configured bound, and connect. A daemon that does not come up is an
//! error naming the daemon: there is no fallback.
//!
//! On Unix the path spawns the daemon detached and never asks a service
//! manager anything. On Windows it asks the Task Scheduler to run the
//! per-user task `stow setup` registered (`scheduled_task`): a
//! process the path itself spawned would stay in the job object of the
//! cargo whose wrapper called it, and end with that cargo.
//!
//! The whole path is synchronous and std-only: no async runtime and no
//! configuration load, because the clients that call it run once per
//! compiled unit.

#[cfg(unix)]
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use stow_types::error::{Context, Result};

#[cfg(unix)]
use super::STOW_DAEMON_DIR_ENV;
#[cfg(unix)]
use super::detached::{self, Detached};
use super::notify::{Notification, ReadyListener};
use super::protocol::{self, ControlRequest, Hello, PROTOCOL, PROTOCOL_FLOOR, Response, Role};
use super::{RunDir, Settings};
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
    /// The daemon's log, which an error names with the daemon's pid.
    log: PathBuf,
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
        let log = self.log;
        #[cfg(unix)]
        let reply = exchange(self.stream);
        #[cfg(windows)]
        let reply = with_deadline(answer, move || exchange(self.stream));
        reply.wrap_err_with(|| {
            format!(
                "the running stow daemon ({}) did not complete a status exchange within {} s",
                describe_daemon(&log),
                answer.as_secs()
            )
        })
    }
}

/// Which daemon a failure is about: its pid, from the line it logged when
/// it bound the endpoint, and its log.
#[must_use]
pub fn describe_daemon(log: &Path) -> String {
    let pid = std::fs::read_to_string(log).ok().and_then(|text| {
        text.lines()
            .rev()
            .find(|line| line.contains("stow daemon serving"))
            .and_then(|line| line.split("pid=").nth(1))
            .and_then(|rest| rest.split_whitespace().next().map(str::to_owned))
    });
    let pid = pid.unwrap_or_else(|| "unknown".to_owned());
    format!("pid {pid}, log {}", log.display())
}

fn exchange<S: Read + Write>(mut stream: S) -> Result<StatusReply> {
    let mut request = protocol::encode(&Hello::new(Role::Control))?;
    request.extend(protocol::encode(&ControlRequest::Status)?);
    stream
        .write_all(&request)
        .and_then(|()| stream.flush())
        .wrap_err("send Hello and Status to the daemon")?;
    let frame = protocol::read_frame(&mut stream)?;
    if !protocol::speaks(frame.protocol) {
        return Err(stow_types::stow_error!(
            "the daemon speaks protocol {}, this stow speaks {PROTOCOL_FLOOR} through {PROTOCOL}",
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
        other => Err(stow_types::stow_error!(
            "the daemon answered a status request with {other:?}"
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
        log: run_dir.log(),
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
    let listener = ReadyListener::bind(&run_dir)?;
    let mut child = Started::begin(exe, &run_dir, &listener)?;
    let log = run_dir.log();
    let notification = listener.wait(settings.start, || child.check(&log));
    let notification = match notification {
        Ok(notification) => notification,
        Err(error) => {
            // The daemon this path started never reported ready: it does
            // not outlive the failure.
            child.abandon();
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
            child.reap();
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

/// The daemon this path started, as far as the path watches it.
///
/// On Unix it is the child the path spawned. On Windows it is the run of
/// the scheduled task (`scheduled_task`) the path asked for: the
/// Task Scheduler owns the process, so there is no child to watch, and a
/// daemon that fails to come up is noticed at the start bound.
#[cfg(unix)]
struct Started(detached::Child);

#[cfg(unix)]
impl Started {
    /// Spawn the daemon with the readiness endpoint of `listener`.
    fn begin(exe: &Path, run_dir: &RunDir, listener: &ReadyListener) -> Result<Self> {
        spawn_daemon(exe, run_dir, listener.endpoint()).map(Self)
    }

    /// Fails once the daemon has exited.
    fn check(&mut self, log: &Path) -> Result<()> {
        let exited = self.0.try_wait().wrap_err("watch the stow daemon")?;
        exited.map_or(Ok(()), |status| {
            Err(stow_types::stow_error!(
                "the stow daemon exited with {status} before it was ready; its log is {}",
                log.display()
            ))
        })
    }

    /// End a daemon that never reported ready.
    fn abandon(mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }

    /// Collect a daemon that exited because another one holds the lock.
    fn reap(mut self) {
        let _ = self.0.wait();
    }
}

#[cfg(windows)]
struct Started {
    run_dir: std::path::PathBuf,
}

#[cfg(windows)]
impl Started {
    /// Ask the Task Scheduler to run the task that starts the daemon for
    /// `run_dir`. The daemon finds the address of `listener` in the run
    /// directory ([`ReadyListener::bind`] published it). There is no
    /// fallback: without the task registered the build fails naming `stow
    /// setup`.
    fn begin(_exe: &Path, run_dir: &RunDir, _listener: &ReadyListener) -> Result<Self> {
        super::scheduled_task::run(run_dir.path())
            .wrap_err("start the stow daemon through the Task Scheduler")?;
        Ok(Self {
            run_dir: run_dir.path().to_owned(),
        })
    }

    /// The scheduler's process is not this path's to watch.
    #[allow(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        reason = "the one interface of the start path on both platforms"
    )]
    fn check(&mut self, _log: &Path) -> Result<()> {
        Ok(())
    }

    /// Stop the task's run: the daemon did not report ready.
    fn abandon(self) {
        let _ = super::scheduled_task::end(&self.run_dir);
    }

    /// Nothing of the scheduler's process to collect.
    #[allow(
        clippy::unused_self,
        reason = "the one interface of the start path on both platforms"
    )]
    fn reap(self) {}
}

/// What a daemon keeps of its starter's environment: what it needs to find
/// the user's directories and nothing else of the starter's.
#[cfg(unix)]
const KEPT_ENVIRONMENT: [&str; 4] = ["HOME", "USER", "LOGNAME", "TMPDIR"];

/// Spawn the daemon detached so that it keeps nothing of this process
/// ([`super::detached`]): a cleared environment, null stdio, no inherited
/// descriptor or handle, and the runtime directory as its working
/// directory.
#[cfg(unix)]
fn spawn_daemon(exe: &Path, run_dir: &RunDir, notify: &Path) -> Result<detached::Child> {
    let kept = KEPT_ENVIRONMENT
        .into_iter()
        // The settings the daemon itself reads.
        .chain([
            super::STOW_DAEMON_LOG_BYTES_ENV,
            super::STOW_DAEMON_ANSWER_SECS_ENV,
        ])
        .filter_map(|key| std::env::var_os(key).map(|value| (OsString::from(key), value)));
    Detached::new(exe)
        .arg("daemon")
        .arg("--ready")
        .arg(notify)
        .envs(kept)
        // The daemon is told where its directory is instead of deriving
        // it from an environment it no longer has (`XDG_CACHE_HOME`).
        .env(STOW_DAEMON_DIR_ENV, run_dir.path())
        .current_dir(run_dir.path())
        .spawn()
        .wrap_err_with(|| format!("spawn the stow daemon {}", exe.display()))
}
