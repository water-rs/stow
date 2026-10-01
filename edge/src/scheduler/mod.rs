//! Durable Object build scheduler.
//!
//! `queue` holds the backend-abstracted queue state machine and compiles on
//! every target so its logic is host-testable; `dispatch` and `object` are the
//! Cloudflare-bound dispatch and Durable Object glue.

pub mod meter;
pub mod queue;

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
#[cfg(target_arch = "wasm32")]
pub mod dispatch;
#[cfg(target_arch = "wasm32")]
pub(crate) mod object;
