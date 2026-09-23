//! Clock access for the vendored tree.
//!
//! `std::time::Instant::now` and `std::time::SystemTime::now` panic on
//! `wasm32-unknown-unknown` (`sys/time/unsupported.rs` — there is no OS
//! clock), so the vendored sources take `Instant` through this re-export and
//! read the wall clock through [`system_time_now`].
//!
//! On wasm the readings come from `web_time` (`performance.now` /
//! `Date.now` under the JS host); on hosts they are the plain `std::time`
//! items, so the types below are `std::time::Instant` /
//! `std::time::SystemTime` there exactly.

#[cfg(not(target_family = "wasm"))]
pub use std::time::Instant;
#[cfg(target_family = "wasm")]
pub use web_time::Instant;

/// `SystemTime::now`, portable.
///
/// The `SystemTime` type itself is `std`'s on every target: on wasm the
/// `web_time` reading is folded through `UNIX_EPOCH + duration`, which is
/// value arithmetic and needs no clock support.
pub fn system_time_now() -> std::time::SystemTime {
    #[cfg(not(target_family = "wasm"))]
    {
        std::time::SystemTime::now()
    }
    #[cfg(target_family = "wasm")]
    {
        std::time::SystemTime::UNIX_EPOCH
            + web_time::SystemTime::now()
                .duration_since(web_time::SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
    }
}
