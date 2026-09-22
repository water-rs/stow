//! Compiler-facing types needed by the resolver's metadata pipeline.
//!
//! `cargo::core::compiler` is the build-execution engine; resolution only
//! touches a thin slice of it: `CompileKind`/`CompileTarget`/`CrateType`
//! (vendored), `TargetInfo`/`RustcTargetData` (the `cargo metadata
//! --filter-platform` evaluation input), `CompileMode`/`UserIntent`,
//! the `Unit`/`UnitDep`/`IsArtifact` identity types, `BuildOutput` (target
//! config `links` overrides), `RustdocScrapeExamples`, and
//! `apply_env_config`. Everything else (BuildRunner, fingerprints, job
//! scheduling) is deliberately absent — no build ever runs here.

pub mod artifact;
mod build_config;
pub(crate) mod build_context;
mod compile_kind;
mod crate_type;
pub(crate) mod custom_build;
pub mod rustdoc;
mod unit;
pub mod unit_dependencies;

pub use self::build_config::{CompileMode, UserIntent};
pub use self::build_context::{RustcTargetData, TargetInfo};
pub use self::compile_kind::{CompileKind, CompileKindFallback, CompileTarget};
pub use self::crate_type::CrateType;
pub use self::custom_build::LinkArgTarget;
pub use self::custom_build::{BuildOutput, LibraryPath};
pub use self::rustdoc::RustdocScrapeExamples;
pub use self::unit::{Unit, UnitIndex};

use crate::util::ProcessBuilder;
use crate::util::errors::CargoResult;

/// Apply the `[env]` config-table vars to `cmd` (carried verbatim).
pub(crate) fn apply_env_config(
    gctx: &crate::GlobalContext,
    cmd: &mut ProcessBuilder,
) -> CargoResult<()> {
    for (key, value) in gctx.env_config()?.iter() {
        // never override a value that has already been set by cargo
        if cmd.get_envs().contains_key(key) {
            continue;
        }
        cmd.env(key, value);
    }
    Ok(())
}
