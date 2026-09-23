//! `stow-resolve` — cargo's dependency resolver, carried from cargo `0.99.0`
//! (rust-lang/cargo@`797e8a9bca276c1c9f9f738d2a20f484fa4eea9d`) into a crate
//! that compiles on host targets and `wasm32-unknown-unknown`.
//!
//! The resolver pipeline is carried verbatim: `ops::output_metadata` →
//! `build_resolve_graph` → `resolve_ws_with_opts` → `resolver::resolve` →
//! `FeatureResolver` per spec, reproducing `cargo metadata
//! --filter-platform <triple>`. Synchronous filesystem/network APIs inside
//! cargo were made `async` at their existing seams rather than reimplemented.
//!
//! Adaptation layer (documented in the PR design note):
//! - `util::context::GlobalContext` — slimmed to what resolution reads.
//! - `util::{fs,paths,flock}` — virtual filesystem; `MemoryFilesystem` for wasm.
//! - `util::network::http_async` — the async HTTP client boundary; host uses a
//!   real client, wasm uses `fetch`.
//! - `util::process`, `util::auth`, `util::credential` — removed entirely;
//!   cargo only ever spawns processes to probe `rustc`/`rustdoc` (the caller
//!   injects that data) and registry credentials are unreachable. With them
//!   went `TargetInfo::new`/`RustcTargetData::new` (probe constructors — the
//!   `*_injected` variants are used), `Rustc::new`/`cached_output`, the
//!   `output_filename`/`FileType`/`rustc_outputs` machinery, `jobserver`,
//!   `apply_env_config`, `CompileKind::add_target_arg`,
//!   `Edition::{cmd_edition_arg,force_warn_arg}`, `fetch_with_cli`
//!   (`net.git-fetch-with-cli`), `ops::output_metadata` (the probing wrapper;
//!   `output_metadata_with` remains), and `util::process`'s `ProcessBuilder`.
//! - `util::counter` — kept: `MetricsCounter` throttles git-fetch progress
//!   reporting in `sources::git::{utils,oxide}` (host-only path).
//! - `sources::git` — host-only (libgit2 cannot run on wasm); loading a git
//!   source on wasm is a truthful error.
//! - `util::shell` — cargo's `Shell` semantics without a tty.

#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(clippy::nursery)]
#![allow(clippy::cargo)]
#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::private_intra_doc_links)]
#![allow(dead_code)]
// Cargo's internals are `pub` but largely undocumented; these lints would
// fire on every vendored item.
#![allow(missing_docs)]
#![allow(missing_debug_implementations)]

#[macro_use]
mod macros;

pub mod api;
pub mod core;
pub mod diagnostics;
pub mod git_proto;
pub mod github_tree;
pub mod ops;
pub mod rustc_data;
pub mod sources;
pub mod testing;
pub mod util;
pub mod version;

pub use crate::util::errors::{AlreadyPrintedError, InternalError, VerboseError};
pub use crate::util::{CargoResult, CliError, CliResult, GlobalContext, indented_lines};
pub use crate::version::version;

/// Name of the environment variable that is used to find the `cargo` executable.
///
/// Set by cargo when running tests/benchmarks so child processes can find cargo.
pub const CARGO_ENV: &str = "CARGO";
