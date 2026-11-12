//! The readiness notification: how a daemon a client just spawned tells
//! that client it is serving, or that another daemon already is.
//!
//! The client binds the notification endpoint before it starts the
//! daemon; the daemon connects and writes one line. On Unix the client
//! spawns the daemon and hands it the address (`--ready <endpoint>`), a
//! Unix socket in the runtime directory. On Windows the Task Scheduler
//! starts the daemon from a command line fixed at registration, so the
//! client publishes the address of its endpoint, a loopback TCP port (std
//! has no named-pipe server), in `ready.addr` in the runtime directory and
//! the daemon reads it when it reports. The endpoint only carries the one
//! line, and a forged `ready` costs the client a failed connect to the
//! real endpoint, whose access is restricted.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use stow_types::error::{Context, Result};

#[cfg(unix)]
use std::os::unix::net::{UnixListener as Listener, UnixStream as Stream};

#[cfg(windows)]
use std::net::{TcpListener as Listener, TcpStream as Stream};

use super::RunDir;

/// How often a waiting client looks at its child, and asks whether a daemon
/// already answers, between notifications. A daemon that died before
/// notifying, or one that came up without notifying, is noticed within
/// this, rather than at the start bound; the notification itself is
/// delivered at once.
const CHILD_CHECK_INTERVAL: Duration = Duration::from_millis(100);

/// The longest line a notification may be: far above `lock-held\n`.
const MAX_LINE_BYTES: u64 = 64;

/// What the spawned daemon reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notification {
    /// The daemon holds the lock and is serving.
    Ready,
    /// Another daemon holds the lock; this one is exiting.
    LockHeld,
}

impl Notification {
    const fn line(self) -> &'static str {
        match self {
            Self::Ready => "ready\n",
            Self::LockHeld => "lock-held\n",
        }
    }

    fn parse(line: &str) -> Result<Self> {
        [Self::Ready, Self::LockHeld]
            .into_iter()
            .find(|notification| notification.line() == line)
            .ok_or_else(|| {
                stow_types::stow_error!("unknown daemon notification `{}`", line.trim_end())
            })
    }
}

/// The client's end: bound before the daemon is spawned.
#[derive(Debug)]
pub struct ReadyListener {
    listener: Listener,
    endpoint: PathBuf,
    /// The file the address is published in.
    #[cfg(windows)]
    published: PathBuf,
}

impl ReadyListener {
    /// Bind the notification endpoint. The caller holds `start.lock`, so
    /// any socket file already at the address is a dead client's.
    ///
    /// # Errors
    ///
    /// The endpoint cannot be bound.
    #[cfg(unix)]
    pub fn bind(run_dir: &RunDir) -> Result<Self> {
        let endpoint = run_dir.notify_endpoint();
        match std::fs::remove_file(&endpoint) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .wrap_err_with(|| format!("remove the stale {}", endpoint.display()));
            }
        }
        let listener = Listener::bind(&endpoint).wrap_err_with(|| {
            format!("bind the daemon readiness endpoint {}", endpoint.display())
        })?;
        Ok(Self { listener, endpoint })
    }

    /// Bind the notification endpoint on a loopback port and publish its
    /// address in the run directory, where the daemon the Task Scheduler
    /// starts looks for it. The caller holds `start.lock`, so any address
    /// already published is a dead client's.
    ///
    /// # Errors
    ///
    /// The endpoint cannot be bound or its address cannot be written.
    #[cfg(windows)]
    pub fn bind(run_dir: &RunDir) -> Result<Self> {
        let listener =
            Listener::bind(("127.0.0.1", 0)).wrap_err("bind the daemon readiness endpoint")?;
        let endpoint = PathBuf::from(
            listener
                .local_addr()
                .wrap_err("read the daemon readiness endpoint")?
                .to_string(),
        );
        let file = run_dir.notify_address_file();
        std::fs::write(&file, endpoint.as_os_str().as_encoded_bytes())
            .wrap_err_with(|| format!("publish the readiness address in {}", file.display()))?;
        Ok(Self {
            listener,
            endpoint,
            published: file,
        })
    }

    /// The address the daemon is told to notify.
    #[cfg(unix)]
    #[must_use]
    pub fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    /// Wait up to `bound` for the daemon's notification, calling `alive`
    /// and `serving` between short intervals so a daemon that died first
    /// ends the wait.
    ///
    /// `serving` says whether a daemon already answers at its endpoint,
    /// which ends the wait as [`Notification::Ready`]: a daemon that began
    /// starting before this client published its address never notifies
    /// it, and the start the client asked for is then ignored.
    ///
    /// # Errors
    ///
    /// `alive` or `serving` failed, the bound passed, or the notification
    /// was malformed.
    pub fn wait(
        self,
        bound: Duration,
        mut alive: impl FnMut() -> Result<()>,
        mut serving: impl FnMut() -> Result<bool>,
    ) -> Result<Notification> {
        let Self {
            listener,
            endpoint,
            #[cfg(windows)]
            published,
        } = self;
        let (sender, receiver) = mpsc::channel();
        // `accept` cannot be given a deadline through std, so it runs on
        // a thread of its own. It is not joined: its one read is of a
        // daemon this process spawned, and a thread left blocked by a peer
        // that never writes ends with the process that is about to fail.
        std::thread::Builder::new()
            .name("stow-daemon-ready".to_owned())
            .spawn(move || {
                let _ = sender.send(accept_one(&listener));
            })
            .wrap_err("spawn the readiness listener thread")?;
        let deadline = Instant::now() + bound;
        let outcome = loop {
            match receiver.recv_timeout(CHILD_CHECK_INTERVAL) {
                Ok(delivered) => break delivered,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // A daemon that notifies and then answers is seen at
                    // its notification first: look for it before probing.
                    if let Ok(delivered) = receiver.try_recv() {
                        break delivered;
                    }
                    match serving() {
                        Ok(true) => break Ok(Notification::Ready),
                        Ok(false) => {}
                        Err(error) => break Err(error),
                    }
                    if let Err(error) = alive() {
                        // A daemon that notifies and exits at once — one
                        // that found the lock held — can be seen dead
                        // before its line is delivered: look once more.
                        break receiver
                            .recv_timeout(CHILD_CHECK_INTERVAL)
                            .unwrap_or(Err(error));
                    }
                    if Instant::now() >= deadline {
                        break Err(stow_types::stow_error!(
                            "no readiness notification within {} s",
                            bound.as_secs()
                        ));
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break Err(stow_types::stow_error!(
                        "the readiness listener thread ended"
                    ));
                }
            }
        };
        // Wake a thread still blocked in `accept` by connecting to it
        // ourselves. After a notification the thread has already returned
        // and this connect finds nothing listening.
        drop(connect(&endpoint));
        #[cfg(unix)]
        let _ = std::fs::remove_file(&endpoint);
        // The address is no one's once the wait is over: a daemon the
        // scheduler starts later must not find a dead client's.
        #[cfg(windows)]
        let _ = std::fs::remove_file(&published);
        outcome
    }
}

fn accept_one(listener: &Listener) -> Result<Notification> {
    let (stream, _) = listener
        .accept()
        .wrap_err("accept the daemon notification")?;
    let mut line = String::new();
    BufReader::new(stream.take(MAX_LINE_BYTES))
        .read_line(&mut line)
        .wrap_err("read the daemon notification")?;
    Notification::parse(&line)
}

fn connect(endpoint: &Path) -> std::io::Result<Stream> {
    #[cfg(unix)]
    {
        Stream::connect(endpoint)
    }
    #[cfg(windows)]
    {
        Stream::connect(endpoint.to_string_lossy().as_ref())
    }
}

/// The address a waiting client published for the daemon the Task Scheduler
/// started, if one did.
#[cfg(windows)]
pub fn published_address(run_dir: &RunDir) -> Option<PathBuf> {
    let text = std::fs::read_to_string(run_dir.notify_address_file()).ok()?;
    Some(PathBuf::from(text.trim()))
}

/// The daemon's end: report `notification` to the client that spawned it.
///
/// # Errors
///
/// The client's endpoint is gone or the write fails.
pub fn send(endpoint: &Path, notification: Notification) -> Result<()> {
    let mut stream = connect(endpoint)
        .wrap_err_with(|| format!("connect to the readiness endpoint {}", endpoint.display()))?;
    stream
        .write_all(notification.line().as_bytes())
        .and_then(|()| stream.flush())
        .wrap_err("write the daemon notification")
}

#[cfg(all(test, unix))]
mod tests {
    use std::time::Duration;

    use super::{Notification, ReadyListener, send};
    use crate::daemon::RunDir;

    #[test]
    fn a_notification_reaches_the_waiting_client() {
        for notification in [Notification::Ready, Notification::LockHeld] {
            let dir = tempfile::tempdir().expect("tempdir");
            let run_dir = RunDir::prepare(dir.path().join("run")).expect("run dir");
            let listener = ReadyListener::bind(&run_dir).expect("bind");
            let endpoint = listener.endpoint().to_owned();
            let sender = std::thread::spawn(move || send(&endpoint, notification));
            let received = listener
                .wait(Duration::from_secs(5), || Ok(()), || Ok(false))
                .expect("notification");
            sender.join().expect("join").expect("send");
            assert_eq!(received, notification);
        }
    }

    #[test]
    fn a_dead_child_ends_the_wait_before_the_bound() {
        let dir = tempfile::tempdir().expect("tempdir");
        let run_dir = RunDir::prepare(dir.path().join("run")).expect("run dir");
        let listener = ReadyListener::bind(&run_dir).expect("bind");
        let error = listener
            .wait(
                Duration::from_secs(60),
                || Err(stow_types::stow_error!("the daemon exited")),
                || Ok(false),
            )
            .expect_err("the child is gone");
        assert!(error.to_string().contains("exited"), "{error}");
    }

    /// A daemon that began starting before the client published its address
    /// never notifies it: the client still learns it is serving, long
    /// before the bound.
    #[test]
    fn a_daemon_that_answers_without_notifying_ends_the_wait() {
        let dir = tempfile::tempdir().expect("tempdir");
        let run_dir = RunDir::prepare(dir.path().join("run")).expect("run dir");
        let listener = ReadyListener::bind(&run_dir).expect("bind");
        let started = std::time::Instant::now();
        let mut probes = 0_u32;
        let received = listener
            .wait(
                Duration::from_secs(60),
                || Ok(()),
                || {
                    probes += 1;
                    Ok(probes >= 3)
                },
            )
            .expect("the daemon answers");
        assert_eq!(received, Notification::Ready);
        assert_eq!(probes, 3);
        assert!(started.elapsed() < Duration::from_secs(30));
    }

    /// A probe that fails ends the wait with its error instead of waiting
    /// out the bound.
    #[test]
    fn a_failing_probe_ends_the_wait() {
        let dir = tempfile::tempdir().expect("tempdir");
        let run_dir = RunDir::prepare(dir.path().join("run")).expect("run dir");
        let listener = ReadyListener::bind(&run_dir).expect("bind");
        let error = listener
            .wait(
                Duration::from_secs(60),
                || Ok(()),
                || Err(stow_types::stow_error!("the endpoint is unusable")),
            )
            .expect_err("the probe failed");
        assert!(error.to_string().contains("unusable"), "{error}");
    }

    /// A notification already delivered wins over a probe that would also
    /// say ready: the daemon's own word is what the client acts on.
    #[test]
    fn a_delivered_notification_is_taken_before_the_probe() {
        let dir = tempfile::tempdir().expect("tempdir");
        let run_dir = RunDir::prepare(dir.path().join("run")).expect("run dir");
        let listener = ReadyListener::bind(&run_dir).expect("bind");
        let endpoint = listener.endpoint().to_owned();
        send(&endpoint, Notification::LockHeld).expect("send");
        let received = listener
            .wait(Duration::from_secs(5), || Ok(()), || Ok(true))
            .expect("notification");
        assert_eq!(received, Notification::LockHeld);
    }
}
