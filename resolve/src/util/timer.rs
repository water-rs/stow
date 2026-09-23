//! `Delay` abstraction mirroring `futures_timer::Delay`.
//!
//! On host targets this is `futures_timer::Delay` itself; on wasm32 there is
//! no timer thread, so it delegates to `gloo_timers`' `TimeoutFuture` which
//! calls `setTimeout` in the host runtime.

#[cfg(not(target_family = "wasm"))]
pub use futures_timer::Delay;

#[cfg(target_family = "wasm")]
pub use wasm_delay::Delay;

#[cfg(target_family = "wasm")]
mod wasm_delay {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    /// A future that resolves after `dur`, backed by `gloo_timers`.
    pub struct Delay {
        inner: gloo_timers::future::TimeoutFuture,
    }

    impl Delay {
        /// Create a new future which will fire at `dur` milliseconds into the
        /// future (like `futures_timer::Delay::new`).
        pub fn new(dur: Duration) -> Delay {
            Delay {
                inner: gloo_timers::future::TimeoutFuture::new(dur.as_millis() as u32),
            }
        }
    }

    impl Future for Delay {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            Pin::new(&mut self.inner).poll(cx)
        }
    }
}
