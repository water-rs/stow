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
use super::protocol::{self, ControlRequest, Hello, Response, Role};
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
    /// The newest protocol number the daemon speaks.
    pub protocol: u16,
    /// The oldest protocol number the daemon speaks.
    pub floor: u16,
}

/// A connection to the daemon that has not yet said hello.
#[derive(Debug)]
pub struct Connection {
    stream: Stream,
    answer: Duration,
    /// The daemon's log, which an error names with the daemon's pid.
    log: PathBuf,
    /// The stow runtime executable the hello names.
    exe: PathBuf,
}

/// What a daemon answered to a request that would open a session.
#[derive(Debug, PartialEq, Eq)]
enum Reply {
    Status(StatusReply),
    /// The daemon gives way to another stow and acted on nothing.
    Retiring {
        stow_version: String,
        until: Duration,
    },
}

/// Waiting for the successor of a daemon that answered
/// [`Response::Retiring`]: the pauses between replays and the bound on
/// them.
///
/// The bound counts from the first answer: the time the daemon said it had
/// left to drain, then a start and an answer. A second daemon that gives
/// way, and is older than this stow, means the replacement did not run this
/// stow.
#[derive(Debug)]
pub struct Succession {
    /// What the successor is given after the drain ends: to start, and to
    /// answer.
    after_drain: Duration,
    exe: PathBuf,
    first: Option<(Instant, Instant)>,
    until: Option<Duration>,
    pause: Duration,
}

impl Succession {
    /// A client running `exe` that waits as `settings` bound.
    #[must_use]
    pub fn new(settings: Settings, exe: &Path) -> Self {
        Self {
            after_drain: settings.start + settings.answer,
            exe: exe.to_owned(),
            first: None,
            until: None,
            pause: FIRST_RECONNECT_PAUSE,
        }
    }

    /// Account for a daemon of stow `stow_version` that answered `now` that
    /// it retires within `until`, and return how long to wait before
    /// replaying the request.
    ///
    /// # Errors
    ///
    /// The bound ran out, or the replacement is still older than this stow.
    pub fn retiring(
        &mut self,
        now: Instant,
        stow_version: &str,
        until: Duration,
    ) -> Result<Duration> {
        let (began, deadline) = *self
            .first
            .get_or_insert_with(|| (now, now + until + self.after_drain));
        // A drain that begins later than another's ends is a daemon
        // that took over and gave way again.
        let renewed = self.until.is_some_and(|before| until > before);
        self.until = Some(until);
        let own = env!("CARGO_PKG_VERSION");
        if renewed && super::retire::is_newer(stow_version, own).unwrap_or(false) {
            return Err(stow_types::stow_error!(
                "the stow daemon was replaced and still runs stow {stow_version}, older than this stow {own} ({}); the executable that starts the daemon is not this stow's{}",
                self.exe.display(),
                if cfg!(windows) {
                    ": run `stow setup` from this stow to register its task"
                } else {
                    ""
                }
            ));
        }
        if now >= deadline {
            return Err(stow_types::stow_error!(
                "the stow daemon (stow {stow_version}) did not hand over to its successor within {} s of its first answer that it is retiring",
                (now - began).as_secs()
            ));
        }
        let pause = self.pause;
        self.pause = (pause * 2).min(LONGEST_RECONNECT_PAUSE);
        Ok(pause.min(deadline - now))
    }
}

impl Connection {
    /// Say hello and ask for the daemon's status, in one write.
    ///
    /// # Errors
    ///
    /// The daemon does not answer within the answer bound, answers
    /// something else, or refuses the connection.
    fn status_once(self) -> Result<Reply> {
        let answer = self.answer;
        let log = self.log;
        #[cfg(unix)]
        let reply = exchange(self.stream, &self.exe);
        #[cfg(windows)]
        let reply = with_deadline(answer, move || exchange(self.stream, &self.exe));
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

/// Report the daemon's status, replaying the request while the daemon
/// gives way to a successor: a daemon that answers
/// [`Response::Retiring`] acted on nothing, so the request is made again to
/// whichever daemon serves next.
///
/// # Errors
///
/// The daemon cannot be started or does not answer, refuses this stow, or
/// does not hand over within the bound ([`Succession`]).
pub fn status_of(exe: &Path, settings: Settings) -> Result<StatusReply> {
    let mut succession = Succession::new(settings, exe);
    loop {
        match connect_or_start(exe, settings)?.status_once()? {
            Reply::Status(status) => return Ok(status),
            Reply::Retiring {
                stow_version,
                until,
            } => {
                let pause = succession.retiring(Instant::now(), &stow_version, until)?;
                std::thread::sleep(pause);
            }
        }
    }
}

fn exchange<S: Read + Write>(mut stream: S, exe: &Path) -> Result<Reply> {
    let mut request = protocol::encode(&Hello::new(Role::Control, exe))?;
    request.extend(protocol::encode(&ControlRequest::Status)?);
    stream
        .write_all(&request)
        .and_then(|()| stream.flush())
        .wrap_err("send Hello and Status to the daemon")?;
    let frame = protocol::read_frame(&mut stream)?;
    match protocol::read_response(&frame)? {
        Response::Status {
            stow_version,
            protocol,
            floor,
        } => Ok(Reply::Status(StatusReply {
            stow_version,
            protocol,
            floor,
        })),
        Response::Retiring {
            stow_version,
            until_millis,
        } => Ok(Reply::Retiring {
            stow_version,
            until: Duration::from_millis(until_millis),
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
        exe: exe.to_owned(),
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
    let notification = listener.wait(
        settings.start,
        || child.check(&log),
        || Started::serving(&endpoint, settings.answer),
    );
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
/// daemon that fails to come up is noticed at the start bound. The run
/// may also not be this path's: the task queues a request made while a
/// run is live, so the path never ends the run.
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

    /// Whether a daemon already answers: never asked on Unix, where the
    /// daemon this path spawned is the one that notifies it.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "the one interface of the start path on both platforms"
    )]
    const fn serving(_endpoint: &Path, _answer: Duration) -> Result<bool> {
        Ok(false)
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
struct Started;

#[cfg(windows)]
impl Started {
    /// Ask the Task Scheduler to run the task that starts the daemon for
    /// `run_dir`. The daemon finds the address of `listener` in the run
    /// directory ([`ReadyListener::bind`] published it). There is no
    /// fallback: without the task registered the build fails naming `stow
    /// setup`.
    ///
    /// The task's instance policy queues a run requested while one is
    /// live, and the queued run exits at once on the daemon's lock, so a
    /// daemon already starting (the logon trigger's, say) never hears of
    /// this client. The wait therefore also asks the endpoint
    /// ([`Started::serving`]). A daemon that is retiring is such a run: it
    /// has released the pipe and exits, and the queued run is its
    /// successor.
    fn begin(_exe: &Path, run_dir: &RunDir, _listener: &ReadyListener) -> Result<Self> {
        super::scheduled_task::run(run_dir.path())
            .wrap_err("start the stow daemon through the Task Scheduler")?;
        Ok(Self)
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

    /// Whether a daemon answers at `endpoint`: it has bound its pipe,
    /// whichever start brought it up and whether or not it knew this
    /// client was waiting.
    fn serving(endpoint: &Path, answer: Duration) -> Result<bool> {
        Ok(matches!(
            try_connect(endpoint, answer)?,
            Attempt::Connected(_)
        ))
    }

    /// The daemon did not report ready within the bound. The run is left
    /// alone: the task is shared by every client and the logon trigger, so
    /// a run this path cannot tell from another's may be a daemon another
    /// client is waiting for, and a daemon that cannot come up exits and
    /// releases the task by itself. The failure names the daemon's log.
    #[allow(
        clippy::unused_self,
        reason = "the one interface of the start path on both platforms"
    )]
    fn abandon(self) {}

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
            super::STOW_DAEMON_DRAIN_SECS_ENV,
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

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::{Duration, Instant};

    use super::{LONGEST_RECONNECT_PAUSE, Settings, Succession};

    fn settings() -> Settings {
        Settings {
            answer: Duration::from_secs(2),
            start: Duration::from_secs(8),
            log_bytes: 1 << 20,
            drain: Duration::from_secs(5),
        }
    }

    fn succession() -> Succession {
        Succession::new(settings(), Path::new("/stow"))
    }

    #[test]
    fn replays_back_off_from_the_first_pause_to_the_longest() {
        let (mut succession, now) = (succession(), Instant::now());
        let pauses: Vec<Duration> = (0..8)
            .map(|_| {
                succession
                    .retiring(now, "0.1.0", Duration::from_secs(5))
                    .expect("within the bound")
            })
            .collect();
        assert_eq!(
            pauses,
            [5, 10, 20, 40, 80, 160, 200, 200].map(Duration::from_millis)
        );
        assert_eq!(pauses[7], LONGEST_RECONNECT_PAUSE);
    }

    #[test]
    fn the_bound_is_the_drain_then_a_start_and_an_answer_from_the_first_answer() {
        let (mut succession, began) = (succession(), Instant::now());
        succession
            .retiring(began, "0.1.0", Duration::from_secs(5))
            .expect("the first answer");
        // 5 s of drain, 8 s to start and 2 s to answer.
        succession
            .retiring(
                began + Duration::from_secs(14),
                "0.1.0",
                Duration::from_secs(1),
            )
            .expect("inside the bound");
        let error = succession
            .retiring(
                began + Duration::from_secs(15),
                "0.1.0",
                Duration::from_secs(1),
            )
            .expect_err("the bound ran out");
        assert!(error.to_string().contains("did not hand over"), "{error}");
    }

    #[test]
    fn a_pause_never_outlasts_the_bound() {
        let (mut succession, began) = (succession(), Instant::now());
        succession
            .retiring(began, "0.1.0", Duration::from_secs(5))
            .expect("the first answer");
        let pause = succession
            .retiring(
                began + Duration::from_millis(14_999),
                "0.1.0",
                Duration::from_secs(1),
            )
            .expect("inside the bound");
        assert_eq!(pause, Duration::from_millis(1));
    }

    #[test]
    fn a_replacement_that_is_still_older_is_named() {
        let (mut succession, began) = (succession(), Instant::now());
        succession
            .retiring(began, "0.1.0", Duration::from_secs(1))
            .expect("the first answer");
        let error = succession
            .retiring(
                began + Duration::from_secs(1),
                "0.1.0",
                Duration::from_secs(5),
            )
            .expect_err("a new drain began under an older stow");
        let error = error.to_string();
        assert!(
            error.contains("0.1.0") && error.contains(env!("CARGO_PKG_VERSION")),
            "{error}"
        );
        assert!(error.contains("/stow"), "{error}");
    }

    #[test]
    fn the_time_left_shrinking_is_the_same_daemon_draining() {
        let (mut succession, began) = (succession(), Instant::now());
        for left in [5, 4, 3] {
            succession
                .retiring(began, "0.1.0", Duration::from_secs(left))
                .expect("one daemon draining");
        }
    }
}
