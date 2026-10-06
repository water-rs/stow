//! `stow-resolver` — the native graph resolver (#427): the published
//! `cargo` crate as a library, running on GitHub Actions runners (and
//! here, `stow-admin`'s preheat lanes) instead of inside the Worker.
//!
//! A [`Resolver`] session materializes a fetched project tree or a
//! `.crate` on disk in a temp dir, points cargo at it under an isolated
//! `CARGO_HOME`, selects versions once (the dropped-lockfile semantics:
//! registry pins to the yanked whitelist, git pins to `register_lock`),
//! and projects the selection onto each requested target via cargo's
//! own `FeatureResolver` — the same per-target [`StowUnit`]s the
//! vendored `stow-resolve` emitted, plus the [`enqueue`] conversion to
//! `EnqueueRequest`s both admin and (#429) the edge share.

#![forbid(unsafe_code)]

mod edges;
mod emit;
pub mod enqueue;
pub mod fetch;
mod lockfile;
pub mod prepare;
mod select;
mod session;
pub mod shim;
mod units;

pub use enqueue::{
    RequestPlanParts, TaskGraph, TaskNode, enqueue_requests_from_output, enqueue_requests_inner,
    request_plan_parts,
};
pub use prepare::{
    GitCommit, PreparedSourceTree, RelativeSourcePath, SourcePreparation, project_fetch_ref,
};
pub use session::{ResolveOptions, Resolver, SourceResolve};
pub use units::{
    SpecsAndResolvedFeatures, StowDep, StowResolveOutput, StowSide, StowUnit, StowUnitKey,
    StowUnitKind,
};
