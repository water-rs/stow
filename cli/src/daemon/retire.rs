//! A daemon giving way to another stow.
//!
//! A [`Retirement`] begins when the daemon learns that another stow must
//! serve from here on: it then answers every request that would open a
//! session with [`Response::Retiring`] — acting on none of it, so the
//! client replays it — and keeps serving what is already under way. A
//! daemon is *busy* ([`Busy`]) while it holds a build's session, a
//! connection that has not been answered yet, or a probe; the drain ends
//! when it is idle or when the bound runs out, whichever is first. At the
//! bound the sessions of drivers are cut: their control connections are
//! refused naming the restart. A cargo's session is not cut; its owner
//! record survives the restart and the successor refuses the cargo's
//! wrappers from then on, naming the restart.
//!
//! On Unix the daemon then replaces its own image ([`exec_into`]): the pid,
//! the lock and the listening socket carry over, so the endpoint never
//! stops existing. On Windows it releases the pipe and the lock and exits,
//! and the Task Scheduler's task starts the successor.

#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

use super::protocol::Response;

/// What a daemon has under way that an exit would cut.
#[derive(Debug, Clone, Copy)]
enum Work {
    /// A connection that has been accepted but whose first request has not
    /// been handled, or a probe's conversation.
    Request,
    /// A driver's session, held by its control connection.
    Driver,
    /// A cargo's session, from its opening until its end has concluded.
    Cargo,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Counts {
    requests: usize,
    drivers: usize,
    cargos: usize,
}

impl Counts {
    const fn slot(&mut self, work: Work) -> &mut usize {
        match work {
            Work::Request => &mut self.requests,
            Work::Driver => &mut self.drivers,
            Work::Cargo => &mut self.cargos,
        }
    }

    const fn idle(self) -> bool {
        self.requests == 0 && self.drivers == 0 && self.cargos == 0
    }

    /// Nothing that must finish after the drivers were cut is left.
    const fn settled(self) -> bool {
        self.requests == 0 && self.drivers == 0
    }
}

/// What the daemon holds that a restart would cut. Clones share the count.
#[derive(Debug, Clone)]
pub struct Busy(Arc<watch::Sender<Counts>>);

impl Default for Busy {
    fn default() -> Self {
        Self(Arc::new(watch::channel(Counts::default()).0))
    }
}

/// One unit of [`Busy`] work, released when dropped.
#[derive(Debug)]
pub struct Held {
    counts: Arc<watch::Sender<Counts>>,
    work: Work,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.counts
            .send_modify(|counts| *counts.slot(self.work) -= 1);
    }
}

impl Busy {
    fn hold(&self, work: Work) -> Held {
        self.0.send_modify(|counts| *counts.slot(work) += 1);
        Held {
            counts: Arc::clone(&self.0),
            work,
        }
    }

    /// A connection that has to be answered, or a probe.
    #[must_use]
    pub fn request(&self) -> Held {
        self.hold(Work::Request)
    }

    /// A driver's session.
    #[must_use]
    pub fn driver(&self) -> Held {
        self.hold(Work::Driver)
    }

    /// A cargo's session.
    #[must_use]
    pub fn cargo(&self) -> Held {
        self.hold(Work::Cargo)
    }

    async fn until(&self, done: fn(&Counts) -> bool) {
        let mut counts = self.0.subscribe();
        counts
            .wait_for(done)
            .await
            .expect("the sender lives as long as the busy handle");
    }

    /// Resolves when nothing is held.
    pub async fn idle(&self) {
        self.until(|counts| counts.idle()).await;
    }

    /// Resolves when no request and no driver's session is held: what must
    /// still finish once the drivers have been cut.
    async fn settled(&self) {
        self.until(|counts| counts.settled()).await;
    }
}

/// A retirement under way: onto what, and by when the drain ends.
#[derive(Debug, Clone)]
pub struct Pending {
    /// The executable that serves from here on.
    pub successor: PathBuf,
    /// When the drain ends and the open builds are cut.
    pub deadline: Instant,
}

impl Pending {
    /// The time left before the drain ends.
    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

/// Whether, and onto what, this daemon is retiring. Clones share the state.
#[derive(Debug, Clone)]
pub struct Retirement {
    state: Arc<watch::Sender<Option<Pending>>>,
    /// How long a drain lasts.
    drain: Duration,
}

impl Retirement {
    /// A daemon that is not retiring, whose drains last `drain`.
    #[must_use]
    pub fn new(drain: Duration) -> Self {
        Self {
            state: Arc::new(watch::channel(None).0),
            drain,
        }
    }

    /// Begin retiring onto `successor`, unless a retirement is under way:
    /// the first one's successor and deadline stand. Returns what stands.
    pub fn begin(&self, successor: PathBuf) -> Pending {
        let deadline = Instant::now() + self.drain;
        let mut began = false;
        self.state.send_if_modified(|state| {
            began = state.is_none();
            if began {
                *state = Some(Pending {
                    successor,
                    deadline,
                });
            }
            began
        });
        let pending = self.pending().expect("a retirement stands once begun");
        if began {
            tracing::info!(
                successor = %pending.successor.display(),
                drain_secs = self.drain.as_secs(),
                "retiring: draining before the successor takes over"
            );
        }
        pending
    }

    /// The retirement under way, if any.
    #[must_use]
    pub fn pending(&self) -> Option<Pending> {
        self.state.borrow().clone()
    }

    /// The answer to a request that would open a session, when the daemon
    /// is retiring: nothing of the request was acted on.
    #[must_use]
    pub fn reply(&self) -> Option<Response> {
        self.pending().map(|pending| Response::Retiring {
            stow_version: env!("CARGO_PKG_VERSION").to_owned(),
            until_millis: u64::try_from(pending.remaining().as_millis()).unwrap_or(u64::MAX),
        })
    }

    /// Resolves, with what stands, once a retirement has begun.
    pub async fn begun(&self) -> Pending {
        let mut state = self.state.subscribe();
        let pending = state
            .wait_for(Option::is_some)
            .await
            .expect("the sender lives as long as the retirement handle")
            .clone();
        pending.expect("waited for a retirement")
    }

    /// Resolves when a retirement's drain bound has run out.
    pub async fn cut(&self) {
        let pending = self.begun().await;
        tokio::time::sleep_until(pending.deadline).await;
    }

    /// Resolves, with what stands, when a retirement has begun and the
    /// daemon is done: nothing is left to wait for, or the drain bound ran
    /// out and the builds it cut have finished within `answer`.
    pub async fn drained(&self, busy: &Busy, answer: Duration) -> Pending {
        let pending = self.begun().await;
        tokio::select! {
            () = busy.idle() => tracing::info!("drained: no build is open"),
            () = tokio::time::sleep_until(pending.deadline) => {
                tracing::warn!("the drain bound ran out with builds open; cutting them");
                if tokio::time::timeout(answer, busy.settled()).await.is_err() {
                    tracing::warn!("a request or driver's session outlasted its cut");
                }
            }
        }
        pending
    }
}

/// Replace this process's image with `successor`'s, keeping the lock and
/// the listening socket: the successor adopts both as `--inherit-lock` and
/// `--inherit-listener`. Returns only when the exec failed.
///
/// A multi-threaded process replaces every thread, and nothing is dropped,
/// so the lock is never released.
#[cfg(unix)]
pub fn exec_into(
    successor: &Path,
    run_dir: &Path,
    lock: std::os::fd::RawFd,
    listener: std::os::fd::RawFd,
) -> std::io::Error {
    use std::os::unix::process::CommandExt as _;

    if let Err(error) = super::descriptors::clear_close_on_exec(&[lock, listener]) {
        return error;
    }
    std::process::Command::new(successor)
        .arg("daemon")
        .arg(crate::cli_args::RUN_DIR_FLAG)
        .arg(run_dir)
        .arg(crate::cli_args::INHERIT_LOCK_FLAG)
        .arg(lock.to_string())
        .arg(crate::cli_args::INHERIT_LISTENER_FLAG)
        .arg(listener.to_string())
        .exec()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{Busy, Retirement};
    use crate::daemon::protocol::Response;

    const DRAIN: Duration = Duration::from_secs(10);

    #[tokio::test(start_paused = true)]
    async fn a_daemon_that_is_not_retiring_answers_nothing_special() {
        let retirement = Retirement::new(DRAIN);
        assert!(retirement.pending().is_none() && retirement.reply().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_retirement_stands() {
        let retirement = Retirement::new(DRAIN);
        let first = retirement.begin(PathBuf::from("/first"));
        tokio::time::advance(Duration::from_secs(4)).await;
        let second = retirement.begin(PathBuf::from("/second"));
        assert_eq!(second.successor, PathBuf::from("/first"));
        assert_eq!(second.deadline, first.deadline);
        let Some(Response::Retiring { until_millis, .. }) = retirement.reply() else {
            panic!("a retiring daemon says so");
        };
        assert_eq!(until_millis, 6_000, "the time left, not the whole bound");
    }

    #[tokio::test(start_paused = true)]
    async fn the_drain_ends_when_the_last_build_ends() {
        let (retirement, busy) = (Retirement::new(DRAIN), Busy::default());
        let driver = busy.driver();
        let cargo = busy.cargo();
        retirement.begin(PathBuf::from("/next"));
        let drained = retirement.drained(&busy, Duration::from_secs(1));
        tokio::pin!(drained);
        tokio::time::advance(Duration::from_secs(3)).await;
        assert!(futures_util::poll!(&mut drained).is_pending());
        drop(driver);
        tokio::time::advance(Duration::from_secs(3)).await;
        assert!(
            futures_util::poll!(&mut drained).is_pending(),
            "a cargo's session is open"
        );
        drop(cargo);
        let started = tokio::time::Instant::now();
        let pending = drained.await;
        assert_eq!(pending.successor, PathBuf::from("/next"));
        assert_eq!(
            started,
            tokio::time::Instant::now(),
            "it ended with the build, not at the bound"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_drain_is_cut_at_the_bound_and_waits_for_the_drivers_it_cut() {
        let (retirement, busy) = (Retirement::new(DRAIN), Busy::default());
        let _cargo = busy.cargo();
        let driver = busy.driver();
        retirement.begin(PathBuf::from("/next"));
        let began = tokio::time::Instant::now();
        // What a driver's session does: it ends when the bound runs out.
        let cut = retirement.clone();
        let session = tokio::spawn(async move {
            cut.cut().await;
            drop(driver);
        });
        let pending = retirement.drained(&busy, Duration::from_secs(1)).await;
        session.await.expect("the driver's session");
        assert_eq!(tokio::time::Instant::now() - began, DRAIN);
        assert_eq!(pending.successor, PathBuf::from("/next"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_stuck_request_does_not_hold_the_restart_past_the_answer_bound() {
        let (retirement, busy) = (Retirement::new(DRAIN), Busy::default());
        let _stuck = busy.request();
        retirement.begin(PathBuf::from("/next"));
        let began = tokio::time::Instant::now();
        retirement.drained(&busy, Duration::from_secs(2)).await;
        assert_eq!(
            tokio::time::Instant::now() - began,
            DRAIN + Duration::from_secs(2)
        );
    }
}
