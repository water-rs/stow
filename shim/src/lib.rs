//! Cross-crate utilities for stow.
//!
//! * Wrapper-shim materialization (used by both the cli and the trusted CI
//!   runner; both processes need a stable filesystem path that resolves to
//!   the current stow binary so cargo can be told `RUSTC_WRAPPER` once).
//!   Native targets only.
//! * Shared D1 / `SQLite` schema constants (used by edge and mock-registry).
//! * Shared zstd compression level (used by ci and mock-registry; gated
//!   behind the `zstd` feature).

pub mod schema;

/// Default zstd compression level for stow OCI layers. Used by ci's upload
/// path and the mock registry so they produce identically-shaped layers.
#[cfg(feature = "zstd")]
pub const STOW_ZSTD_COMPRESSION_LEVEL: i32 = zstd::DEFAULT_COMPRESSION_LEVEL;

// Wrapper-shim materialization is meaningless on wasm32 (the edge worker
// target) — no filesystem, no rustc to wrap. Gate everything below so the
// crate compiles cleanly when only the schema/zstd helpers are needed.
#[cfg(not(target_arch = "wasm32"))]
mod wrapper;

#[cfg(not(target_arch = "wasm32"))]
pub use wrapper::{
    CAPTURE_DIR_ENV, REAL_CC_ENV, REAL_CXX_ENV, RESOLVE_CC, RESOLVE_CXX, WrapperRole,
    WrapperShimPaths, capture_executable_beside, materialize_wrapper_shims,
    runtime_executable_beside, tools_dir,
};
