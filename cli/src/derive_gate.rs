//! The package-cache-lock gate (stow#667).
//!
//! Cargo holds its package-cache lock — one per cargo home — for the
//! whole of a resolution, so a miss drain's detached `cargo
//! --unit-graph` re-derivation can make the user's next command print
//! `Blocking waiting for file lock on package cache`. Both sides
//! coordinate under one directory per cargo home, `<cargo home>/stow`:
//!
//! - `foreground.lock` — a stow command that will run cargo holds it
//!   shared from its start until its cargo's resolution is over; a
//!   drain probes it (`try_lock_exclusive`, released at once) and a
//!   failed probe means such a command is present.
//! - `derive/<pid>` — one pointer file per drain that may be deriving,
//!   holding the encoded [`Endpoint`] of that drain's stop listener.
//!
//! The stop protocol carries no frames: a connection to a drain's
//! listener *is* the stop request, and the drain's closing it is the
//! acknowledgement — it closes only after its cargo child is killed and
//! reaped, so a released command never queues behind a drain cargo that
//! still holds the lock.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fs2::FileExt as _;

use crate::supervisor::{self, Endpoint, Listener, Stream};

/// `<gate_dir>/foreground.lock` — see the module docs.
const FOREGROUND_LOCK: &str = "foreground.lock";

/// `<gate_dir>/derive`, holding one pointer file per drain that may be
/// deriving — see the module docs.
const DERIVE_DIR: &str = "derive";

/// The bound one stop exchange may take: a drain that accepts and never
/// closes cannot hold a command's start past it.
const STOP_DEADLINE: Duration = Duration::from_secs(2);

/// A stow command's claim on the package-cache lock's next holder:
/// while it is held, no miss drain starts a cargo of its own
/// (stow#667).
#[derive(Debug, Clone)]
pub struct ForegroundHold(Option<Arc<std::fs::File>>);

impl ForegroundHold {
    /// Take the hold in `gate_dir`, then make every derivation in
    /// progress there stop.
    ///
    /// # Errors
    ///
    /// The gate directory or its `foreground.lock` cannot be created,
    /// or the shared lock cannot be taken.
    pub async fn enter(gate_dir: &Path) -> stow_types::error::Result<Self> {
        let dir = gate_dir.to_path_buf();
        let file = tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(&dir)
                .map_err(|error| stow_types::stow_error!("create {}: {error}", dir.display()))?;
            let path = dir.join(FOREGROUND_LOCK);
            let file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(&path)
                .map_err(|error| stow_types::stow_error!("open {}: {error}", path.display()))?;
            // The only other locker is a drain's instant try-lock
            // probe, so this shared take never waits on a command.
            file.lock_shared().map_err(|error| {
                stow_types::stow_error!("lock {} shared: {error}", path.display())
            })?;
            Ok::<_, stow_types::error::Error>(file)
        })
        .await
        .map_err(|error| stow_types::stow_error!("take the foreground hold: {error}"))??;
        stop_derivations(gate_dir).await;
        Ok(Self(Some(Arc::new(file))))
    }

    /// Give the hold up. Idempotent; also happens when the last clone
    /// drops.
    pub fn release(&self) {
        if let Some(file) = &self.0 {
            let _ = file.unlock();
        }
    }

    /// A hold over nothing, for a `ProjectContext` a test builds by
    /// hand.
    #[cfg(test)]
    pub const fn detached() -> Self {
        Self(None)
    }
}

/// Connect to every drain `gate_dir` lists and wait for each one's
/// close — the stop protocol's whole exchange.
async fn stop_derivations(gate_dir: &Path) {
    let pointers = match list_pointers(gate_dir).await {
        Ok(pointers) => pointers,
        Err(error) => {
            tracing::warn!(
                %error,
                gate = %gate_dir.display(),
                "could not list in-progress derivations; drains keep running"
            );
            return;
        }
    };
    // One exchange per pointer, all at once: the count is bounded by
    // the number of live drains.
    futures_util::future::join_all(pointers.into_iter().map(|pointer| async move {
        if tokio::time::timeout(STOP_DEADLINE, stop_derivation(&pointer))
            .await
            .is_err()
        {
            tracing::warn!(
                pointer = %pointer.display(),
                "a miss drain did not acknowledge a stop inside the deadline"
            );
        }
    }))
    .await;
}

/// The pointer files `gate_dir`'s `derive` directory holds. A missing
/// directory is "no derivations"; names starting with `.` are the
/// half-written tmp files a drain has not renamed into place yet.
async fn list_pointers(gate_dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let dir = gate_dir.join(DERIVE_DIR);
    tokio::task::spawn_blocking(move || {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        Ok(entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                !path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with('.'))
            })
            .collect())
    })
    .await
    .unwrap_or_else(|error| Err(std::io::Error::other(error.to_string())))
}

/// One stop exchange: read the pointer, connect — the connection
/// itself is the stop request — and read until the drain closes,
/// which it does only after its cargo child is dead and reaped. A
/// pointer whose drain is gone, that cannot be read or parsed, or
/// whose endpoint refuses the connection belongs to a dead drain:
/// remove it and move on.
async fn stop_derivation(pointer: &Path) {
    // The pointer is named after its drain's pid. A dead drain is never
    // connected to: where the endpoint is a port, whoever listens there
    // now is a stranger that would hold this command for the deadline.
    let drain_alive = pointer
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.parse::<u32>().ok())
        .is_some_and(crate::miss_journal::process_alive);
    if !drain_alive {
        remove_pointer(pointer).await;
        return;
    }
    let Some(endpoint) = read_pointer(pointer).await else {
        return;
    };
    let Ok(mut stream) = supervisor::connect(&endpoint).await else {
        remove_pointer(pointer).await;
        return;
    };
    read_until_close(&mut stream).await;
}

/// The endpoint `pointer` names. A pointer that cannot be read or
/// parsed belongs to a dead drain and is removed.
async fn read_pointer(pointer: &Path) -> Option<Endpoint> {
    let path = pointer.to_path_buf();
    let raw = tokio::task::spawn_blocking(move || std::fs::read_to_string(&path))
        .await
        .ok()
        .and_then(Result::ok);
    let Some(endpoint) = raw.and_then(|raw| Endpoint::parse(raw.trim()).ok()) else {
        remove_pointer(pointer).await;
        return None;
    };
    Some(endpoint)
}

/// Remove a dead drain's pointer; a removal error is ignored — the
/// next command's sweep tries again.
async fn remove_pointer(pointer: &Path) {
    let path = pointer.to_path_buf();
    let _ = tokio::task::spawn_blocking(move || std::fs::remove_file(&path)).await;
}

/// Read the drain's stream until it closes — the acknowledgement. A
/// reset counts as closed.
async fn read_until_close(stream: &mut Stream) {
    use tokio::io::AsyncReadExt as _;
    let mut sink = Vec::new();
    let _closed = match stream {
        #[cfg(unix)]
        Stream::Unix(stream) => stream.read_to_end(&mut sink).await,
        Stream::Loopback(stream) => stream.read_to_end(&mut sink).await,
    };
}

/// A drain's standing to run a cargo of its own.
pub enum DerivationGate {
    /// Not asked yet.
    Unopened(PathBuf),
    /// Open: this drain may derive, and a stow command can make it
    /// stop.
    Open(DerivationSlot),
    /// A stow command is present or has asked for a stop: no
    /// derivation for the rest of this drain.
    Shut,
}

impl DerivationGate {
    /// A gate not yet consulted, over `gate_dir` (`<cargo home>/stow`).
    pub const fn unopened(gate_dir: PathBuf) -> Self {
        Self::Unopened(gate_dir)
    }

    /// This drain's derivation slot: `Some` while no stow command is
    /// present, `None` once the gate is shut.
    ///
    /// Opening publishes the stop-listener's pointer *before* probing
    /// `foreground.lock`: a command that takes its hold after the
    /// probe always finds the pointer, and one that took it before
    /// makes the probe fail — there is no window in which a
    /// derivation starts unseen.
    pub async fn slot(&mut self) -> Option<&mut DerivationSlot> {
        if let Self::Unopened(gate_dir) = self {
            let gate_dir = gate_dir.clone();
            *self = open_slot(&gate_dir)
                .await
                .map_or_else(|| Self::Shut, Self::Open);
        }
        match self {
            Self::Open(slot) => Some(slot),
            Self::Unopened(_) | Self::Shut => None,
        }
    }

    /// Shut the gate for the rest of this drain: drop the listener and
    /// the parked stop connection — its drop is the close that releases
    /// the requester — then remove the pointer. Idempotent.
    pub async fn shut(&mut self) {
        let Self::Open(slot) = std::mem::replace(self, Self::Shut) else {
            return;
        };
        let DerivationSlot { pointer, stop, .. } = slot;
        drop(stop);
        let _ = tokio::task::spawn_blocking(move || std::fs::remove_file(&pointer)).await;
    }
}

/// The open gate: this drain's stop listener, the endpoint its pointer
/// advertises, and the pointer's path.
pub struct DerivationSlot {
    listener: Listener,
    endpoint: Endpoint,
    pointer: PathBuf,
    /// The accepted stop request, held so the requester stays parked
    /// on its read until this slot drops it — which happens only after
    /// the derivation's cargo is dead and reaped (stow#667).
    stop: Option<Stream>,
}

impl DerivationSlot {
    /// Resolve when a stow command connects — the connection is the
    /// stop request, and it is kept inside the slot so the requester
    /// stays parked until the slot drops it.
    pub async fn stop_requested(&mut self) {
        let accepted = match &self.listener {
            #[cfg(unix)]
            Listener::Unix(listener, _) => listener
                .accept()
                .await
                .map(|(stream, _)| Stream::Unix(stream)),
            #[cfg(not(unix))]
            Listener::Loopback(listener) => listener
                .accept()
                .await
                .map(|(stream, _)| Stream::Loopback(stream)),
        };
        match accepted {
            Ok(stream) => self.stop = Some(stream),
            // The only peer that ever connects is a command asking the
            // drain to stop; if accepting it fails the drain cannot
            // hear the request at all, so resolve the same way.
            Err(error) => tracing::warn!(
                %error,
                endpoint = %self.endpoint.encode(),
                "miss drain could not accept a stop request"
            ),
        }
    }
}

/// The outcome of a drain's slot setup.
enum OpenAttempt {
    /// Listener bound, pointer written, probe clear.
    Ready(DerivationSlot),
    /// A stow command holds `foreground.lock` right now; the pointer
    /// is already removed.
    Contended,
}

/// The whole of [`DerivationGate::slot`]'s first open, on a blocking
/// thread — the directory create, the bind, the pointer's tmp-then-
/// rename write, and the lock probe.
fn open_slot_blocking(gate_dir: &Path) -> Result<OpenAttempt, String> {
    let derive = gate_dir.join(DERIVE_DIR);
    std::fs::create_dir_all(&derive)
        .map_err(|error| format!("create {}: {error}", derive.display()))?;
    let (listener, endpoint) = supervisor::bind("stow-derive-")?;
    let pid = std::process::id();
    let pointer = derive.join(pid.to_string());
    // The pointer lands by rename: a reader either sees the finished
    // file or nothing, never a half-written one.
    let tmp = derive.join(format!(".{pid}.tmp"));
    if let Err(error) =
        std::fs::write(&tmp, endpoint.encode()).and_then(|()| std::fs::rename(&tmp, &pointer))
    {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("write {}: {error}", pointer.display()));
    }
    let lock_path = gate_dir.join(FOREGROUND_LOCK);
    let probe = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .and_then(|file| {
            file.try_lock_exclusive()?;
            file.unlock()
        });
    match probe {
        Ok(()) => Ok(OpenAttempt::Ready(DerivationSlot {
            listener,
            endpoint,
            pointer,
            stop: None,
        })),
        Err(error) if crate::artifact_cache::is_lock_contended(&error) => {
            let _ = std::fs::remove_file(&pointer);
            Ok(OpenAttempt::Contended)
        }
        Err(error) => {
            let _ = std::fs::remove_file(&pointer);
            Err(format!("probe {}: {error}", lock_path.display()))
        }
    }
}

/// Open this drain's slot — see [`DerivationGate::slot`] for the
/// ordering contract. `None` shuts the gate: a contended probe, or any
/// setup error a warning already named; the units stay journaled and a
/// later drain tries again.
async fn open_slot(gate_dir: &Path) -> Option<DerivationSlot> {
    let dir = gate_dir.to_path_buf();
    match tokio::task::spawn_blocking(move || open_slot_blocking(&dir)).await {
        Ok(Ok(OpenAttempt::Ready(slot))) => Some(slot),
        Ok(Ok(OpenAttempt::Contended)) => None,
        Ok(Err(error)) => {
            tracing::warn!(
                %error,
                gate = %gate_dir.display(),
                "miss drain could not open its derivation slot; its units stay journaled"
            );
            None
        }
        Err(error) => {
            tracing::warn!(
                %error,
                gate = %gate_dir.display(),
                "miss drain's derivation-slot setup failed; its units stay journaled"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A command holding `foreground.lock` makes a drain's probe fail:
    /// the slot never opens and its pointer never survives.
    #[tokio::test]
    async fn a_present_command_shuts_the_gate() {
        let dir = tempfile::tempdir().expect("temp dir");
        let gate_dir = dir.path().join("gate");
        let hold = ForegroundHold::enter(&gate_dir).await.expect("enter");

        let mut gate = DerivationGate::unopened(gate_dir.clone());
        assert!(gate.slot().await.is_none(), "a held gate opens no slot");
        assert!(matches!(gate, DerivationGate::Shut));
        assert_eq!(
            std::fs::read_dir(gate_dir.join(DERIVE_DIR))
                .expect("derive dir")
                .count(),
            0,
            "a contended probe removes the pointer it just wrote"
        );
        hold.release();
    }

    /// The hold is what shuts the gate: once released, the next probe
    /// passes.
    #[tokio::test]
    async fn a_released_hold_opens_the_gate() {
        let dir = tempfile::tempdir().expect("temp dir");
        let gate_dir = dir.path().join("gate");
        let hold = ForegroundHold::enter(&gate_dir).await.expect("enter");
        hold.release();

        let mut gate = DerivationGate::unopened(gate_dir);
        assert!(
            gate.slot().await.is_some(),
            "the gate opens once the hold is gone"
        );
    }

    /// The connection is the request and its close is the answer: the
    /// command stays parked on it until the drain shuts the gate.
    #[tokio::test]
    async fn a_command_waits_for_the_slot_to_close() {
        let dir = tempfile::tempdir().expect("temp dir");
        let gate_dir = dir.path().join("gate");
        let mut gate = DerivationGate::unopened(gate_dir.clone());
        let enter = {
            let slot = gate
                .slot()
                .await
                .expect("the gate opens with no command present");
            let enter = tokio::spawn({
                let gate_dir = gate_dir.clone();
                async move { ForegroundHold::enter(&gate_dir).await }
            });
            // Entering reached this drain — the connection it just
            // made is the stop request.
            slot.stop_requested().await;
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            assert!(
                !enter.is_finished(),
                "the command is still waiting on the open stop connection"
            );
            enter
        };
        // Shutting drops the listener and the parked connection — that
        // close is the acknowledgement the command waits on.
        gate.shut().await;
        let hold = enter.await.expect("enter task").expect("enter");
        hold.release();
        assert_eq!(
            std::fs::read_dir(gate_dir.join(DERIVE_DIR))
                .expect("derive dir")
                .count(),
            0,
            "shut removes the pointer"
        );
    }

    /// A pointer whose endpoint refuses the connection names a dead
    /// drain: the sweep removes it and the command is not delayed.
    #[tokio::test]
    async fn a_dead_drains_pointer_is_removed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let gate_dir = dir.path().join("gate");
        let derive = gate_dir.join(DERIVE_DIR);
        std::fs::create_dir_all(&derive).expect("derive dir");
        // An endpoint nobody listens on, under the pid of a process
        // that is alive — this one: the listener is dropped as soon as
        // the pointer is written.
        let (listener, endpoint) = supervisor::bind("stow-derive-").expect("bind");
        let pointer = derive.join(std::process::id().to_string());
        std::fs::write(&pointer, endpoint.encode()).expect("write pointer");
        drop(listener);

        let hold = ForegroundHold::enter(&gate_dir).await.expect("enter");
        assert!(
            !pointer.exists(),
            "a dead drain's pointer is removed by the sweep"
        );
        hold.release();
    }

    /// A pointer left by a drain that no longer runs is removed
    /// without a connection: whoever listens on its endpoint now is
    /// not that drain.
    #[tokio::test]
    async fn a_gone_drains_endpoint_is_never_connected_to() {
        let dir = tempfile::tempdir().expect("temp dir");
        let gate_dir = dir.path().join("gate");
        let derive = gate_dir.join(DERIVE_DIR);
        std::fs::create_dir_all(&derive).expect("derive dir");
        // A listener that would hold a connection for the whole
        // deadline, under the pid of a process that has exited.
        let (_listener, endpoint) = supervisor::bind("stow-derive-").expect("bind");
        let pointer = derive.join(crate::miss_journal::dead_pid().to_string());
        std::fs::write(&pointer, endpoint.encode()).expect("write pointer");

        let started = std::time::Instant::now();
        let hold = ForegroundHold::enter(&gate_dir).await.expect("enter");
        assert!(
            started.elapsed() < STOP_DEADLINE,
            "a gone drain's endpoint was waited on"
        );
        assert!(!pointer.exists(), "a gone drain's pointer is removed");
        hold.release();
    }

    /// A drain that accepts and never answers cannot hold a command's
    /// start past the exchange deadline.
    #[tokio::test(start_paused = true)]
    async fn a_silent_listener_costs_at_most_the_deadline() {
        let dir = tempfile::tempdir().expect("temp dir");
        let gate_dir = dir.path().join("gate");
        let derive = gate_dir.join(DERIVE_DIR);
        std::fs::create_dir_all(&derive).expect("derive dir");
        let (listener, endpoint) = supervisor::bind("stow-derive-").expect("bind");
        std::fs::write(
            derive.join(std::process::id().to_string()),
            endpoint.encode(),
        )
        .expect("write pointer");
        let _serving = tokio::spawn(async move {
            let accepted = match &listener {
                #[cfg(unix)]
                Listener::Unix(listener, _) => listener
                    .accept()
                    .await
                    .map(|(stream, _)| Stream::Unix(stream)),
                #[cfg(not(unix))]
                Listener::Loopback(listener) => listener
                    .accept()
                    .await
                    .map(|(stream, _)| Stream::Loopback(stream)),
            };
            if let Ok(_stream) = accepted {
                std::future::pending::<()>().await;
            }
        });

        let started = tokio::time::Instant::now();
        let hold = ForegroundHold::enter(&gate_dir).await.expect("enter");
        assert!(
            started.elapsed() >= STOP_DEADLINE,
            "the silent listener cost the whole deadline, no more"
        );
        hold.release();
    }
}
