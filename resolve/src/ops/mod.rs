//! Ops entry points — mirror of `cargo::ops` limited to the resolve pipeline:
//! `output_metadata` (the `cargo metadata` printer), `resolve_ws*` (the
//! resolver driver), `lockfile` (Cargo.lock read/write), `read_package`
//! (manifest loading), and `cargo_compile::Packages` (spec parsing used by
//! the metadata default).

pub mod cargo_compile;
pub mod cargo_output_metadata;
mod cargo_read_manifest;
mod cargo_update;
pub mod lockfile;
mod resolve;

pub use self::cargo_compile::Packages;
pub use self::cargo_output_metadata::{ExportInfo, OutputMetadataOptions};
pub use self::cargo_read_manifest::read_package;
pub use self::cargo_update::print_lockfile_changes;
pub use self::lockfile::{LOCKFILE_NAME, load_pkg_lockfile, resolve_to_string, write_pkg_lockfile};
pub use self::resolve::{
    WorkspaceResolve, add_overrides, get_resolved_packages, resolve_with_previous, resolve_ws,
    resolve_ws_with_opts,
};
