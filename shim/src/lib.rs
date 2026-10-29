//! Cross-crate utilities for stow.
//!
//! * Wrapper-shim materialization (used by both the cli and the trusted CI
//!   runner; both processes need a stable filesystem path that resolves to
//!   the current stow binary so cargo can be told `RUSTC_WRAPPER` once).
//!   Native targets only.
//! * The bundle pack format and the zstd settings every producer shares
//!   (gated behind the `zstd` feature).

#[cfg(feature = "zstd")]
pub mod pack;

#[cfg(feature = "zstd")]
pub use pack::{
    STOW_ZSTD_COMPRESSION_LEVEL, STOW_ZSTD_JOB_SIZE, STOW_ZSTD_OVERLAP_LOG, STOW_ZSTD_WINDOW_LOG,
    compress, decompress, encode_index, pack, unpack,
};

// Wrapper-shim materialization is meaningless on wasm32 (the edge worker
// target) — no filesystem, no rustc to wrap. Gate everything below so the
// crate compiles cleanly when only the schema/zstd helpers are needed.
#[cfg(not(target_arch = "wasm32"))]
mod wrapper;

#[cfg(not(target_arch = "wasm32"))]
pub use wrapper::{
    CAPTURE_DIR_ENV, REAL_CC_ENV, REAL_CXX_ENV, RESOLVE_CC, RESOLVE_CXX, WrapperRole,
    WrapperShimPaths, capture_executable_beside, materialize_wrapper_shims, tools_dir,
    tools_dir_in,
};
