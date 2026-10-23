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
/// The in-memory dependency graph the flat store persists (stow#878):
/// nodes, edges, per-node state and the ready set, interned — merged
/// by task id, gated by published-shape masks, dispatching in rank
/// order. Not yet part of the wasm32 build: stage 4 wires the submit
/// routes and `object.rs`'s dispatch pass into it and drops this cfg —
/// until then a wasm32 reference would be dead code, not wiring.
#[cfg(not(target_arch = "wasm32"))]
pub mod graph;
pub mod meter;
pub mod queue;
/// The exact `value`/`dispatch_key` rank — one shared Rust derivation
/// every queue writer binds from (stow#524).
pub mod rank;
/// The flat persistence substrate — `event_log`, chunked
/// `snapshot_chunks`, `store_meta` — plus the wake/replay half and the
/// in-memory billed-row counting. Same staging as `graph`: stage 4's
/// `object.rs` constructor calls `ensure_schema`, its submit and
/// delivery routes call `append_events`, and its wake calls `load` +
/// `apply_events`; this cfg drops with that wiring.
#[cfg(not(target_arch = "wasm32"))]
pub mod store;

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

#[cfg(target_arch = "wasm32")]
pub mod budget;
pub mod dispatch;
#[cfg(target_arch = "wasm32")]
pub mod object;
