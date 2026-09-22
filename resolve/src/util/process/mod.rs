//! Process spawning, ported from `cargo-util/src/process_builder.rs`.
//!
//! On host targets the vendored implementation is used verbatim. On
//! `wasm32` there is no operating system to spawn processes into, so the
//! exec entry points return `ProcessError::could_not_execute` — the same
//! error cargo surfaces when a binary cannot be spawned. The vendored
//! resolver never reaches those entry points on wasm because rustc/target
//! information is injected rather than probed, but the builder API must
//! still exist for the code that constructs probe commands.

mod error;

#[cfg(not(target_family = "wasm"))]
mod imp;
#[cfg(not(target_family = "wasm"))]
mod read2;

pub use error::{ProcessError, exit_status_to_string};
#[cfg(not(target_family = "wasm"))]
pub use imp::*;

#[cfg(target_family = "wasm")]
mod wasm;
#[cfg(target_family = "wasm")]
pub use wasm::*;
