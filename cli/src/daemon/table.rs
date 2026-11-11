//! The daemon's session table and its per-cache-directory resources.
//!
//! One task owns both: the table of open sessions by id, and the
//! [`Resources`] every session on one cache directory shares — the state
//! database handles and the verified index slices — which outlive any one
//! build. Everything else reaches it over a channel, so no lock guards
//! either.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

use super::session::{CacheDirHandles, Resources, Session, SessionId};

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

    fn send(&self, command: Command) {
        assert!(
            self.commands.send(command).is_ok(),
            "the session table's task lives as long as its handles"
        );
    }
}
