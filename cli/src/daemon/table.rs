//! The daemon's session table and its per-cache-directory resources.
//!
//! One task owns both: the table of open sessions — a driver's by id, a
//! cargo's by the process that owns it — and the [`Resources`] every
//! session on one cache directory shares — the state database handles and
//! the verified index slices — which outlive any one build. Everything
//! else reaches it over a channel, so no lock guards either.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use tokio::sync::{OnceCell, mpsc, oneshot};

use super::owner::CargoOwner;
use super::session::{CacheDirHandles, Cargo, Resources, Session, SessionId};

/// What a remembered `rustc -vV` answer is keyed by: the rustc file and
/// the time it was last modified, so a toolchain that was updated in place
/// is probed again.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ToolchainKey {
    file: Arc<same_file::Handle>,
    modified: SystemTime,
}

impl ToolchainKey {
    /// The key of the rustc `file` last modified at `modified`.
    #[must_use]
    pub fn new(file: same_file::Handle, modified: SystemTime) -> Self {
        Self {
            file: Arc::new(file),
            modified,
        }
    }
}

/// The session of one cargo: empty until the cargo's first wrapper that
/// has to describe the build opens it.
#[derive(Debug, Default)]
pub struct CargoSlot {
    session: OnceCell<Arc<Session<Cargo>>>,
    /// The cargo outlived the daemon that held its session: what that
    /// session knew is gone, so this cargo's wrappers are refused.
    outlived_daemon: bool,
}

impl CargoSlot {
    /// The slot of a cargo that outlived the daemon that held its session.
    fn outlived_daemon() -> Self {
        Self {
            session: OnceCell::new(),
            outlived_daemon: true,
        }
    }

    /// Whether the cargo outlived the daemon that held its session.
    #[must_use]
    pub const fn is_outlived_daemon(&self) -> bool {
        self.outlived_daemon
    }

    /// The cargo's session, when it is open.
    #[must_use]
    pub fn session(&self) -> Option<Arc<Session<Cargo>>> {
        self.session.get().cloned()
    }

    /// The cargo's session, opened by `open` unless a wrapper already
    /// opened it or is opening it now, in which case this waits for that.
    /// A failed open leaves the slot empty.
    ///
    /// # Errors
    ///
    /// What `open` failed with.
    pub async fn open_with<Open, Opened>(&self, open: Open) -> Result<Arc<Session<Cargo>>, String>
    where
        Open: FnOnce() -> Opened,
        Opened: std::future::Future<Output = Result<Arc<Session<Cargo>>, String>>,
    {
        self.session.get_or_try_init(open).await.cloned()
    }
}

enum Command {
    Handles {
        cache_dir: PathBuf,
        reply: oneshot::Sender<CacheDirHandles>,
    },
    Insert(Arc<Session>),
    Join {
        id: SessionId,
        reply: oneshot::Sender<Option<Arc<Session>>>,
    },
    Remove(SessionId),
    CargoSlot {
        owner: CargoOwner,
        reply: oneshot::Sender<Arc<CargoSlot>>,
    },
    RemoveCargo(CargoOwner),
    OutlivedDaemon(CargoOwner),
    ToolchainProbe {
        key: ToolchainKey,
        reply: oneshot::Sender<Option<Arc<String>>>,
    },
    RememberToolchainProbe(ToolchainKey, Arc<String>),
}

/// A handle on the table's task. Clones share it; the task ends when the
/// last one is dropped.
#[derive(Debug, Clone)]
pub struct SessionTable {
    commands: mpsc::UnboundedSender<Command>,
}

impl SessionTable {
    /// Start the table's task on the current runtime.
    #[must_use]
    pub fn start() -> Self {
        let (commands, mut inbox) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut resources = Resources::default();
            let mut sessions: HashMap<SessionId, Arc<Session>> = HashMap::new();
            let mut cargos: HashMap<CargoOwner, Arc<CargoSlot>> = HashMap::new();
            let mut probes: HashMap<ToolchainKey, Arc<String>> = HashMap::new();
            while let Some(command) = inbox.recv().await {
                match command {
                    Command::Handles { cache_dir, reply } => {
                        // A requester that gave up needs no answer.
                        let _ = reply.send(resources.handles_for(&cache_dir));
                    }
                    Command::Insert(session) => {
                        sessions.insert(session.id(), session);
                    }
                    Command::Join { id, reply } => {
                        let _ = reply.send(sessions.get(&id).cloned());
                    }
                    Command::Remove(id) => {
                        sessions.remove(&id);
                    }
                    Command::CargoSlot { owner, reply } => {
                        let _ = reply.send(Arc::clone(cargos.entry(owner).or_default()));
                    }
                    Command::RemoveCargo(owner) => {
                        cargos.remove(&owner);
                    }
                    Command::OutlivedDaemon(owner) => {
                        cargos.insert(owner, Arc::new(CargoSlot::outlived_daemon()));
                    }
                    Command::ToolchainProbe { key, reply } => {
                        let _ = reply.send(probes.get(&key).cloned());
                    }
                    Command::RememberToolchainProbe(key, vv) => {
                        probes.insert(key, vv);
                    }
                }
            }
        });
        Self { commands }
    }

    /// The handles of `cache_dir`, created the first time it is asked for.
    pub async fn handles_for(&self, cache_dir: PathBuf) -> CacheDirHandles {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Handles { cache_dir, reply });
        answer
            .await
            .expect("the session table answers every request")
    }

    /// Make `session` joinable by its id.
    pub fn insert(&self, session: Arc<Session>) {
        self.send(Command::Insert(session));
    }

    /// The open session `id` names, if there is one.
    pub async fn join(&self, id: SessionId) -> Option<Arc<Session>> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Join { id, reply });
        answer
            .await
            .expect("the session table answers every request")
    }

    /// Stop `id` from being joinable.
    pub fn remove(&self, id: SessionId) {
        self.send(Command::Remove(id));
    }

    /// The slot of the cargo `owner`'s session, created empty the first
    /// time it is asked for.
    pub async fn cargo_slot(&self, owner: CargoOwner) -> Arc<CargoSlot> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::CargoSlot { owner, reply });
        answer
            .await
            .expect("the session table answers every request")
    }

    /// Forget the cargo `owner`: a wrapper that finds its cargo from here
    /// on opens a session of its own.
    pub fn remove_cargo(&self, owner: CargoOwner) {
        self.send(Command::RemoveCargo(owner));
    }

    /// Record that the cargo `owner` outlived the daemon that held its
    /// session, so its wrappers are refused until [`Self::remove_cargo`].
    pub fn outlived_daemon(&self, owner: CargoOwner) {
        self.send(Command::OutlivedDaemon(owner));
    }

    /// The `rustc -vV` answer remembered for `key`.
    pub async fn toolchain_probe(&self, key: ToolchainKey) -> Option<Arc<String>> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::ToolchainProbe { key, reply });
        answer
            .await
            .expect("the session table answers every request")
    }

    /// Remember the `rustc -vV` answer for `key`.
    pub fn remember_toolchain_probe(&self, key: ToolchainKey, vv: Arc<String>) {
        self.send(Command::RememberToolchainProbe(key, vv));
    }

    fn send(&self, command: Command) {
        assert!(
            self.commands.send(command).is_ok(),
            "the session table's task lives as long as its handles"
        );
    }
}
