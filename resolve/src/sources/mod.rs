//! The trait for sources of Cargo packages and its built-in implementations.
//!
//! Mirror of `cargo::sources`: `Source`/`SourceMap`, `SourceConfigMap`
//! (`[source.*]` config), `PathSource`/`RecursivePathSource` (project
//! workspaces and path deps), `DirectorySource` (vendored dirs),
//! `RegistrySource` (sparse index), `ReplacedSource` (source replacement),
//! and `GitSource`.
//!
//! `GitSource` is host-only: it drives libgit2 checkouts, which cannot exist
//! on wasm32-unknown-unknown. Loading a git dependency on wasm is a truthful
//! error, not a fallback.

pub use self::config::SourceConfigMap;
pub use self::directory::DirectorySource;
#[cfg(not(target_family = "wasm"))]
pub use self::git::GitSource;
pub use self::path::{PathEntry, PathSource, RecursivePathSource};
pub use self::registry::{
    CRATES_IO_DOMAIN, CRATES_IO_INDEX, CRATES_IO_REGISTRY, IndexSummary, RegistrySource,
};
pub use self::replaced::ReplacedSource;

pub mod config;
pub mod directory;
#[cfg(not(target_family = "wasm"))]
pub mod git;
pub mod overlay;
pub mod path;
pub mod registry;
pub mod replaced;
pub mod source;
