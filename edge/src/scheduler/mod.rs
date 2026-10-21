//! Durable Object build scheduler.
//!
//! `queue` holds the backend-abstracted queue state machine and compiles on
//! every target so its logic is host-testable; `dispatch` keeps the same
//! split inside itself — the `BuildRuns` contract and every pure helper
//! host-test while the `CfFetch` plumbing stays `wasm32`-only — and
//! `object` is the Durable Object glue.

/// The hourly demand feed's durable hour/page state machine —
/// backend-abstracted like `queue` so it host-tests on every target.
pub mod feed;
pub mod meter;
pub mod queue;
/// The exact `value`/`dispatch_key` rank — one shared Rust derivation
/// every queue writer binds from (stow#524).
pub mod rank;

/// The production-shaped fixture: host tests and the workerd budget
/// probe both seed it, so the module builds on both targets.
#[cfg(any(test, target_arch = "wasm32"))]
pub mod fixture;

/// The route list both cost gates drive — the host test and the workerd
/// probe share it so a route cannot be measured in one and skipped in
/// the other.
#[cfg(any(test, target_arch = "wasm32"))]
pub mod drives;

#[cfg(all(test, not(target_arch = "wasm32")))]
pub mod test_db;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod cost_gate;

/// The workerd budget table — data only, compiled wherever either the
/// probe or the host drift test needs it.
#[cfg(any(test, target_arch = "wasm32"))]
pub mod do_budgets;

/// §1.2 batch formation — the pure packer the batched claim pass
/// drives (stow#833).
pub mod batching;

#[cfg(target_arch = "wasm32")]
pub mod budget;
pub mod dispatch;
#[cfg(target_arch = "wasm32")]
pub mod object;
