//! `cargo::core::compiler::build_context` holds `BuildContext` — the build
//! runner's scheduling context — alongside `TargetInfo`/`RustcTargetData`.
//! Resolution only needs the latter pair, so `BuildContext` (and the
//! `FileType`/`FileFlavor`/`DepKindSet` machinery that hangs off it) is not
//! ported.

pub(crate) mod target_info;

pub use target_info::{RustcTargetData, TargetInfo};
