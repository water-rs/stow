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
/// order. `object.rs`'s submit routes, delivery routes and dispatch
/// pass consume it (stow#878 stage 4–6).
pub mod graph;
pub mod meter;
pub mod queue;
/// The graph-and-store cores of the routes, shared by the Durable
/// Object handlers and the cost harness.
pub mod routes;
/// The flat persistence substrate — `event_log`, chunked
/// `snapshot_chunks`, `store_meta` — plus the wake/replay half and the
/// in-memory billed-row counting. `object.rs` calls `ensure_schema` at
/// construction, `append_events` per accepted event, and `load` +
/// `apply_events` on wake (stow#878 stage 4–6).
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

#[cfg(target_arch = "wasm32")]
pub mod budget;
pub mod dispatch;
#[cfg(target_arch = "wasm32")]
pub mod object;
