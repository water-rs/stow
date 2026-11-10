//! The local CI's runner pool.
//!
//! On GitHub Actions every job runs on a machine of its own, with a cargo
//! home of its own. Here the jobs share one machine, and cargo takes its
//! package-cache lock exclusively around every resolve and download, so
//! tasks sharing one `CARGO_HOME` queue on that lock. A [`Runner`] is the
//! stand-in for one machine: it owns a cargo home no other runner touches,
//! and the pool lends each runner to one task at a time.

use std::ops::Deref;
use std::path::{Path, PathBuf};

use smol::channel::{Receiver, Sender};

/// One runner: the cargo home its task's cargo invocations use.
#[derive(Debug)]
pub struct Runner {
    cargo_home: PathBuf,
}

impl Runner {
    pub const fn new(cargo_home: PathBuf) -> Self {
        Self { cargo_home }
    }

    /// The runner's own `CARGO_HOME`.
    pub fn cargo_home(&self) -> &Path {
        &self.cargo_home
    }
}

/// The idle runners, handed out through a channel: a task takes the next
/// idle runner, waiting when all are held, and its lease returns the runner
/// when dropped.
#[derive(Clone, Debug)]
pub struct RunnerPool {
    release: Sender<Runner>,
    idle: Receiver<Runner>,
}

impl RunnerPool {
    /// A pool over `runners`, all idle.
    pub fn new(runners: Vec<Runner>) -> Self {
        let (release, idle) = smol::channel::bounded(runners.len());
        for runner in runners {
            release
                .try_send(runner)
                .expect("the pool's channel holds every runner it was sized for");
        }
        Self { release, idle }
    }

    /// A pool of `size` runners whose cargo homes are
    /// `<root>/<n>/cargo-home`, created here.
    ///
    /// # Errors
    ///
    /// Whatever creating a runner's directory fails with.
    pub fn create(root: &Path, size: usize) -> stow_types::error::Result<Self> {
        let runners = (0..size)
            .map(|index| {
                let cargo_home = root.join(index.to_string()).join("cargo-home");
                std::fs::create_dir_all(&cargo_home)?;
                Ok(Runner::new(cargo_home))
            })
            .collect::<stow_types::error::Result<Vec<_>>>()?;
        Ok(Self::new(runners))
    }

    /// The next idle runner, waiting while every runner is held.
    pub async fn acquire(&self) -> RunnerLease {
        let runner = self
            .idle
            .recv()
            .await
            .expect("the pool holds its own sender, so the channel is never closed");
        RunnerLease {
            runner: Some(runner),
            release: self.release.clone(),
        }
    }
}

/// A runner held by one task; dropping it returns the runner to the pool.
#[derive(Debug)]
pub struct RunnerLease {
    runner: Option<Runner>,
    release: Sender<Runner>,
}

impl Deref for RunnerLease {
    type Target = Runner;

    fn deref(&self) -> &Runner {
        self.runner
            .as_ref()
            .expect("a lease holds its runner until it is dropped")
    }
}

impl Drop for RunnerLease {
    fn drop(&mut self) {
        let runner = self
            .runner
            .take()
            .expect("a lease holds its runner until it is dropped");
        self.release
            .try_send(runner)
            .expect("the pool's channel has room for every runner it lent");
    }
}

#[cfg(test)]
mod tests {
    use super::RunnerPool;

    #[tokio::test]
    async fn concurrently_held_runners_have_distinct_cargo_homes() {
        let root = tempfile::tempdir().unwrap();
        let pool = RunnerPool::create(root.path(), 3).unwrap();
        let first = pool.acquire().await;
        let second = pool.acquire().await;
        let third = pool.acquire().await;
        let homes = [first.cargo_home(), second.cargo_home(), third.cargo_home()];
        for (index, home) in homes.iter().enumerate() {
            assert!(home.is_dir(), "{} was created", home.display());
            assert!(
                homes[index + 1..].iter().all(|other| other != home),
                "{} is held twice",
                home.display()
            );
        }
    }

    #[tokio::test]
    async fn a_released_runner_is_handed_out_again() {
        let root = tempfile::tempdir().unwrap();
        let pool = RunnerPool::create(root.path(), 1).unwrap();
        let held = pool.acquire().await;
        let home = held.cargo_home().to_path_buf();
        // With the only runner held, the next acquire cannot complete.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), pool.acquire())
                .await
                .is_err()
        );
        drop(held);
        assert_eq!(pool.acquire().await.cargo_home(), home);
    }
}
