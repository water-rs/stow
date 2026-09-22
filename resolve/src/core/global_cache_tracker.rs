//! Last-use tracking for cache files, adapted from cargo's
//! `core/global_cache_tracker.rs`.
//!
//! Cargo persists this bookkeeping in a sqlite database under the cargo
//! home so that `cargo clean`/`gc` can expire stale caches. Sqlite cannot
//! be carried to `wasm32-unknown-unknown`, and cache-GC bookkeeping has no
//! bearing on resolution output, so this keeps cargo's in-memory
//! [`DeferredGlobalLastUse`] accumulation semantics (the same marker types
//! and method names) without the database layer.

use crate::util::interning::InternedString;
use std::collections::HashMap;
use std::time::SystemTime;

/// The key for a registry index entry stored in the database.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct RegistryIndex {
    /// A unique name of the registry source.
    pub encoded_registry_name: InternedString,
}

/// The key for a registry `.crate` entry stored in the database.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct RegistryCrate {
    /// A unique name of the registry source.
    pub encoded_registry_name: InternedString,
    /// The filename of the compressed crate, like `foo-1.2.3.crate`.
    pub crate_filename: InternedString,
    /// The size of the `.crate` file.
    pub size: u64,
}

/// The key for a registry src directory entry stored in the database.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct RegistrySrc {
    /// A unique name of the registry source.
    pub encoded_registry_name: InternedString,
    /// The directory name of the extracted source, like `foo-1.2.3`.
    pub package_dir: InternedString,
    /// Total size of the src directory in bytes.
    pub size: Option<u64>,
}

/// The key for a git db entry stored in the database.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct GitDb {
    /// A unique name of the git database.
    pub encoded_git_name: InternedString,
}

/// The key for a git checkout entry stored in the database.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct GitCheckout {
    /// A unique name of the git database.
    pub encoded_git_name: InternedString,
    /// A unique name of the checkout without the database.
    pub short_name: InternedString,
    /// Total size of the checkout directory.
    pub size: Option<u64>,
}

type Timestamp = SystemTime;

/// Accumulates last-use markers during a resolve, identical in shape to
/// cargo's deferred buffer (its `save` flushes to sqlite; ours drops at the
/// end of the resolve since there is no long-lived cargo home).
pub struct DeferredGlobalLastUse {
    /// New registry index entries to insert.
    registry_index_timestamps: HashMap<RegistryIndex, Timestamp>,
    /// New registry `.crate` entries to insert.
    registry_crate_timestamps: HashMap<RegistryCrate, Timestamp>,
    /// New registry src directory entries to insert.
    registry_src_timestamps: HashMap<RegistrySrc, Timestamp>,
    /// New git db entries to insert.
    git_db_timestamps: HashMap<GitDb, Timestamp>,
    /// New git checkout entries to insert.
    git_checkout_timestamps: HashMap<GitCheckout, Timestamp>,
    /// The current time, used to improve performance.
    now: Timestamp,
}

impl DeferredGlobalLastUse {
    pub fn new() -> DeferredGlobalLastUse {
        DeferredGlobalLastUse {
            registry_index_timestamps: HashMap::new(),
            registry_crate_timestamps: HashMap::new(),
            registry_src_timestamps: HashMap::new(),
            git_db_timestamps: HashMap::new(),
            git_checkout_timestamps: HashMap::new(),
            now: SystemTime::now(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.registry_index_timestamps.is_empty()
            && self.registry_crate_timestamps.is_empty()
            && self.registry_src_timestamps.is_empty()
            && self.git_db_timestamps.is_empty()
            && self.git_checkout_timestamps.is_empty()
    }

    /// No-op in stow-resolve: there is no global cache database, so there is
    /// nothing to persist; the deferred records are dropped with the resolve.
    /// (Upstream cargo writes these to `<cargo_home>/global-cache.sqlite`.)
    pub fn save_no_error(&mut self, _gctx: &crate::util::GlobalContext) {
        self.clear();
    }

    pub fn clear(&mut self) {
        self.registry_index_timestamps.clear();
        self.registry_crate_timestamps.clear();
        self.registry_src_timestamps.clear();
        self.git_db_timestamps.clear();
        self.git_checkout_timestamps.clear();
    }

    /// Indicates the given [`RegistryIndex`] has been used right now.
    pub fn mark_registry_index_used(&mut self, registry_index: RegistryIndex) {
        self.registry_index_timestamps
            .insert(registry_index, self.now);
    }

    /// Indicates the given [`RegistryCrate`] has been used right now.
    ///
    /// Also implicitly marks the index used, too.
    pub fn mark_registry_crate_used(&mut self, registry_crate: RegistryCrate) {
        self.registry_index_timestamps.insert(
            RegistryIndex {
                encoded_registry_name: registry_crate.encoded_registry_name,
            },
            self.now,
        );
        self.registry_crate_timestamps
            .insert(registry_crate, self.now);
    }

    /// Indicates the given [`RegistrySrc`] has been used right now.
    ///
    /// Also implicitly marks the index used, too.
    pub fn mark_registry_src_used(&mut self, registry_src: RegistrySrc) {
        self.registry_index_timestamps.insert(
            RegistryIndex {
                encoded_registry_name: registry_src.encoded_registry_name,
            },
            self.now,
        );
        self.registry_src_timestamps.insert(registry_src, self.now);
    }

    /// Indicates the given [`GitDb`] has been used right now.
    pub fn mark_git_db_used(&mut self, git_db: GitDb) {
        self.git_db_timestamps.insert(git_db, self.now);
    }

    /// Indicates the given [`GitCheckout`] has been used right now.
    pub fn mark_git_checkout_used(&mut self, git_checkout: GitCheckout) {
        self.git_db_timestamps.insert(
            GitDb {
                encoded_git_name: git_checkout.encoded_git_name,
            },
            self.now,
        );
        self.git_checkout_timestamps.insert(git_checkout, self.now);
    }
}
