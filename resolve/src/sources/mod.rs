//! The trait for sources of Cargo packages and its built-in implementations.
//!
//! Mirror of `cargo::sources`: `Source`/`SourceMap`, `SourceConfigMap`
//! (`[source.*]` config), `PathSource`/`RecursivePathSource` (project
//! workspaces and path deps), `DirectorySource` (vendored dirs),
//! `RegistrySource` (sparse index), `ReplacedSource` (source replacement),
//! and `GitTreeSource`.
//!
//! `GitTreeSource` drives every https git remote — codeload tarballs on
//! github.com, shallow smart-HTTP fetches elsewhere — and runs on wasm32,
//! so worker and hosts share one git code path. cargo's libgit2-backed
//! `GitSource` is not carried here.

pub use self::config::SourceConfigMap;
pub use self::directory::DirectorySource;
pub use self::git::GitTreeSource;
pub use self::path::{PathEntry, PathSource, RecursivePathSource};
pub use self::registry::{
    CRATES_IO_DOMAIN, CRATES_IO_INDEX, CRATES_IO_REGISTRY, IndexSummary, RegistrySource,
};
pub use self::replaced::ReplacedSource;

pub mod config;
pub mod directory;
// Stow adaptation: `git::tree` runs on wasm32, so the module itself is
// no longer gated; the libgit2 submodules gate individually inside.
pub mod git;
pub mod overlay;
pub mod path;
pub mod registry;
pub mod replaced;
pub mod source;
