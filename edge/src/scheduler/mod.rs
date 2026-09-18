//! Durable Object build scheduler.
//!
//! `queue` holds the backend-abstracted queue state machine and compiles on
//! every target so its logic is host-testable; `dispatch` and `object` are the
//! Cloudflare-bound dispatch and Durable Object glue.

pub mod queue;

#[cfg(all(test, not(target_arch = "wasm32")))]
pub mod test_db;

#[cfg(target_arch = "wasm32")]
pub mod dispatch;
#[cfg(target_arch = "wasm32")]
mod object;
