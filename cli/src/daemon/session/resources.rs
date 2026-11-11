//! What sessions on one cache directory share, and what outlives a build.
//!
//! A config that crossed a process boundary carries none of the handles an
//! opened one holds (they are not data), so the process that runs the
//! session hands it its own. One set per cache directory: the state
//! database is one pool per directory, and two sessions with different
//! cache directories must never share a pool. The verified index slices a
//! session fetched are held here too, so the next build on the directory
//! does not read them again.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::OnceCell;

use crate::config::StowConfig;
use crate::index::{HeldSlices, SliceFetches};
use crate::state_db::StateDb;

/// The handles of one cache directory.
#[derive(Debug, Clone, Default)]
pub struct CacheDirHandles {
    state_db: StateDb,
    trust_material: Arc<OnceCell<Arc<crate::verify::TrustMaterial>>>,
    registry_http: Arc<OnceCell<stow_oci::RegistryHttp>>,
    slices: HeldSlices,
}

impl CacheDirHandles {
    /// Give `config` these handles in place of its own.
    pub fn install(&self, config: &mut StowConfig) {
        config.state_db = self.state_db.clone();
        config.trust_material = Arc::clone(&self.trust_material);
        config.registry_http = Arc::clone(&self.registry_http);
    }

    /// A slice memo for one build, backed by the slices this directory's
    /// earlier builds fetched.
    #[must_use]
    pub fn slice_fetches(&self) -> SliceFetches {
        SliceFetches::backed_by(self.slices.clone())
    }
}

/// Every cache directory's handles, created on first use. Owned by one
/// task, which hands each opening session a clone of its directory's
/// handles.
#[derive(Debug, Default)]
pub struct Resources {
    by_cache_dir: HashMap<PathBuf, CacheDirHandles>,
}

impl Resources {
    /// The handles of `cache_dir`, created the first time it is asked for.
    pub fn handles_for(&mut self, cache_dir: &Path) -> CacheDirHandles {
        self.by_cache_dir
            .entry(cache_dir.to_owned())
            .or_default()
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::Resources;

    /// Two cache directories get two pools, and one directory always gets
    /// the same one: a database is opened for the first directory a handle
    /// is asked about and reused for whatever directory is passed after.
    #[tokio::test]
    async fn two_cache_dirs_open_their_own_state_databases() {
        let first = tempfile::tempdir().expect("first cache dir");
        let second = tempfile::tempdir().expect("second cache dir");
        let mut resources = Resources::default();
        let first_handles = resources.handles_for(first.path());
        let second_handles = resources.handles_for(second.path());
        first_handles
            .state_db
            .pool(first.path())
            .await
            .expect("open the first database");
        second_handles
            .state_db
            .pool(second.path())
            .await
            .expect("open the second database");
        assert!(crate::state_db::state_db_path(first.path()).is_file());
        assert!(crate::state_db::state_db_path(second.path()).is_file());
        // The same directory again is the same handle: it opens nothing.
        let again = resources.handles_for(first.path());
        let pool = again
            .state_db
            .pool(first.path())
            .await
            .expect("reuse the first database");
        pool.acquire().await.expect("the shared pool is open");
        first_handles.state_db.close().await;
        second_handles.state_db.close().await;
    }
}
