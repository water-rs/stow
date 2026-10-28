//! Advisory file locks held as guards that release on drop (stow#1003).
//!
//! A lock released by closing its file is released only once no other
//! descriptor refers to that open file: on Unix every child the process
//! spawns starts with a copy of each descriptor — close-on-exec ones
//! included — and holds it until its exec, so a lock released by close
//! outlives its holder for as long as a spawn on any other thread takes
//! to exec, and a try-lock in that window, in this process or another,
//! finds it held. [`FileLock`] unlocks before the file closes, which
//! releases the lock for every copy at once.

use std::fs::{File, TryLockError};
use std::sync::atomic::{AtomicBool, Ordering};

/// A lock on a file, held from construction until [`FileLock::release`]
/// or the drop, whichever comes first.
#[derive(Debug)]
pub struct FileLock {
    file: File,
    held: AtomicBool,
}

impl FileLock {
    /// Lock `file` exclusively, blocking until every other holder
    /// releases it.
    pub fn exclusive(file: File) -> std::io::Result<Self> {
        file.lock()?;
        Ok(Self::held(file))
    }

    /// Lock `file` shared, blocking while an exclusive holder has it.
    pub fn shared(file: File) -> std::io::Result<Self> {
        file.lock_shared()?;
        Ok(Self::held(file))
    }

    /// Lock `file` exclusively if no one else holds it; `None` when
    /// another holder does.
    pub fn try_exclusive(file: File) -> std::io::Result<Option<Self>> {
        match file.try_lock() {
            Ok(()) => Ok(Some(Self::held(file))),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(error)) => Err(error),
        }
    }

    const fn held(file: File) -> Self {
        Self {
            file,
            held: AtomicBool::new(true),
        }
    }

    /// Release the lock now, for a holder that outlives its claim. Later
    /// calls and the drop do nothing.
    pub fn release(&self) {
        if self.held.swap(false, Ordering::AcqRel) {
            unlock(&self.file);
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        if *self.held.get_mut() {
            unlock(&self.file);
        }
    }
}

/// Unlocking a lock this handle holds has no failure mode but a broken
/// handle, which is a bug.
fn unlock(file: &File) {
    file.unlock().expect("release a held file lock");
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::os::unix::process::CommandExt as _;

    use super::FileLock;

    /// A child stopped between its fork and its exec: it holds a copy of
    /// every descriptor the process had open when it forked, until
    /// [`SuspendedChild::finish`] lets it exec.
    struct SuspendedChild {
        release: std::io::PipeWriter,
        spawner: std::thread::JoinHandle<std::process::Child>,
    }

    impl SuspendedChild {
        fn fork() -> Self {
            let (mut forked_reader, forked_writer) = std::io::pipe().expect("pipe");
            let (release_reader, release_writer) = std::io::pipe().expect("pipe");
            // `spawn` returns only once the child has exec'd, so it runs on
            // its own thread while the test acts inside the window.
            let spawner = std::thread::spawn(move || {
                let mut command = std::process::Command::new("/usr/bin/true");
                // SAFETY: the hook only writes and reads pipes it owns,
                // both async-signal-safe.
                unsafe {
                    command.pre_exec(move || {
                        (&forked_writer).write_all(b"f")?;
                        (&release_reader).read_exact(&mut [0])
                    });
                }
                command.spawn().expect("spawn the suspended child")
            });
            forked_reader
                .read_exact(&mut [0])
                .expect("the child forked");
            Self {
                release: release_writer,
                spawner,
            }
        }

        fn finish(mut self) {
            self.release.write_all(b"r").expect("let the child exec");
            let status = self
                .spawner
                .join()
                .expect("join the spawner")
                .wait()
                .expect("reap the child");
            assert!(status.success());
        }
    }

    /// stow#1003: a guard's drop frees the lock while a child spawned
    /// during the hold still has the file open, for both modes and for
    /// an early release.
    #[test]
    fn a_lock_is_free_once_released_while_a_spawned_child_shares_its_file() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("held.lock");
        let open = || {
            std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(&path)
                .expect("open the lock file")
        };
        let probe = open();

        let exclusive = FileLock::exclusive(open()).expect("lock exclusive");
        let child = SuspendedChild::fork();
        drop(exclusive);
        let freed = FileLock::try_exclusive(probe.try_clone().expect("clone the probe"));
        child.finish();
        assert!(
            freed.expect("probe").is_some(),
            "an exclusive lock is free once its guard drops"
        );

        let shared = FileLock::shared(open()).expect("lock shared");
        let child = SuspendedChild::fork();
        shared.release();
        let freed = FileLock::try_exclusive(probe.try_clone().expect("clone the probe"));
        drop(shared);
        child.finish();
        assert!(
            freed.expect("probe").is_some(),
            "a shared lock is free once released"
        );
    }
}
