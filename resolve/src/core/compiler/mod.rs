//! Compiler-facing types needed by the resolver's metadata pipeline.
//!
//! `cargo::core::compiler` is the build-execution engine; resolution only
//! touches a thin slice of it: `CompileKind`/`CompileTarget`/`CrateType`
//! (vendored), `TargetInfo`/`RustcTargetData` (the `cargo metadata
//! --filter-platform` evaluation input), `CompileMode`/`UserIntent`,
//! `BuildOutput` (target config `links` overrides), `RustdocScrapeExamples`,
//! and `apply_env_config`. Everything else (BuildRunner, fingerprints, job
//! scheduling) is deliberately absent — no build ever runs here.

pub mod artifact;
mod build_config;
pub(crate) mod build_context;
mod compile_kind;
mod crate_type;
pub(crate) mod custom_build;
pub mod rustdoc;

pub use self::build_config::{CompileMode, UserIntent};
pub use self::build_context::{RustcTargetData, TargetInfo};
pub use self::compile_kind::{CompileKind, CompileKindFallback, CompileTarget};
pub use self::crate_type::CrateType;
pub use self::custom_build::LinkArgTarget;
pub use self::custom_build::{BuildOutput, LibraryPath};
pub use self::rustdoc::RustdocScrapeExamples;
