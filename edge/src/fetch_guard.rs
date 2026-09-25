//! Outbound-fetch hygiene for the Workers stalled-response heuristic.
//!
//! The runtime lets an invocation hold only a bounded number of outgoing
//! connections at once; a `fetch()` whose response headers arrived but
//! whose body is never read or cancelled keeps its slot until the runtime
//! cancels it as "stalled" — the warn that preceded the 2026-09-24 hang,
//! where stalled slots plus queued subrequests deadlocked the request.
//!
//! [`GuardedResponse`] makes that leak unreachable: `Drop` cancels the
//! body stream, so early returns and status-only branches free the
//! connection exactly like a full read. [`outbound_slot`] keeps the
//! resolve path's fetch fan-out inside the same budget.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use stow_resolve::util::network::http_async::BodyStream;

/// A fetched body that can be actively released without reading it.
///
/// `worker::Response` bodies handed to `bytes()`/`stream()` end on their
/// own (EOF or cancel-on-drop), so only responses that were never
/// touched need this.
pub trait CancellableBody {
    /// Cancel the body stream, releasing the underlying connection.
    fn cancel_body(self);
}

/// The surface a guarded fetch needs: status + one header for branch
/// decisions, plus a body the caller takes to its terminal state.
#[allow(async_fn_in_trait)]
pub trait FetchedResponse: CancellableBody {
    /// HTTP status code.
    fn status_code(&self) -> u16;
    /// Value of one response header, if present.
    fn header(&self, name: &str) -> Option<String>;
    /// Read the body to completion as UTF-8 text.
    async fn text(self) -> Result<String, String>;
}

/// `worker::Response`'s stream body cancels through the platform API;
/// `SendWrapper` delegates so wasm call sites can keep their `Send`
/// future bound. Both impls exist only where the `worker` crate does.
#[cfg(target_arch = "wasm32")]
mod platform {
    use skyzen_cloudflare::worker;
    use skyzen_cloudflare::worker::send::SendWrapper;

    use super::{CancellableBody, FetchedResponse};

    impl CancellableBody for worker::Response {
        /// `ReadableStream.cancel()` frees the connection now; the promise
        /// it returns settles on its own.
        fn cancel_body(self) {
            if let worker::ResponseBody::Stream(stream) = self.body() {
                let _ = stream.cancel();
            }
        }
    }

    impl FetchedResponse for worker::Response {
        fn status_code(&self) -> u16 {
            Self::status_code(self)
        }

        fn header(&self, name: &str) -> Option<String> {
            self.headers().get(name).ok().flatten()
        }

        async fn text(mut self) -> Result<String, String> {
            use skyzen_cloudflare::worker::send::IntoSendFuture as _;

            Self::text(&mut self)
                .into_send()
                .await
                .map_err(|error| error.to_string())
        }
    }

    impl<T: CancellableBody> CancellableBody for SendWrapper<T> {
        fn cancel_body(self) {
            self.0.cancel_body();
        }
    }

    impl<T: FetchedResponse> FetchedResponse for SendWrapper<T> {
        fn status_code(&self) -> u16 {
            self.0.status_code()
        }

        fn header(&self, name: &str) -> Option<String> {
            self.0.header(name)
        }

        async fn text(self) -> Result<String, String> {
            self.0.text().await
        }
    }
}

/// A fetched response that cannot leak its connection: `Drop` cancels
/// the body when it was never handed off for consumption.
///
/// Inspect status/headers through [`GuardedResponse::get_ref`]; move the
/// body to a consumer (`text()`, `bytes()`, `stream()`) with
/// [`GuardedResponse::into_inner`], which disarms the drop-cancel.
pub struct GuardedResponse<B: CancellableBody> {
    inner: Option<B>,
}

impl<B: CancellableBody> GuardedResponse<B> {
    /// Wrap a response fresh off the wire.
    pub const fn new(inner: B) -> Self {
        Self { inner: Some(inner) }
    }

    /// Borrow the response for status/headers — never consumes the body.
    pub const fn get_ref(&self) -> &B {
        self.inner.as_ref().expect("guarded body present")
    }

    /// Move the body out for a read path — the consumer owns its
    /// terminal state from here (EOF or cancel-on-drop).
    pub fn into_inner(mut self) -> B {
        self.inner.take().expect("guarded body present")
    }
}

impl<B: CancellableBody> Drop for GuardedResponse<B> {
    fn drop(&mut self) {
        if let Some(body) = self.inner.take() {
            body.cancel_body();
        }
    }
}

/// Simultaneous outbound fetches the resolve path may hold open: the
/// Workers platform limits one invocation to six simultaneous outgoing
/// connections, and this invocation's budget is shared with the trust
/// probes and scheduler calls on the same request — four keeps resolve
/// fan-out under the documented ceiling with headroom for the rest.
pub const MAX_OUTBOUND_INFLIGHT: usize = 4;

thread_local! {
    static OUTBOUND_INFLIGHT: Cell<usize> = const { Cell::new(0) };
    static OUTBOUND_WAITERS: RefCell<VecDeque<Waker>> = const { RefCell::new(VecDeque::new()) };
}

/// RAII permit for one outbound connection slot — released when the
/// fetch's body reaches its terminal state.
pub struct OutboundPermit {
    _private: (),
}

impl Drop for OutboundPermit {
    fn drop(&mut self) {
        OUTBOUND_INFLIGHT.with(|inflight| inflight.set(inflight.get() - 1));
        // Wake every waiter: a dropped request future leaves a dead
        // waker, and popping only it would strand the live queue behind
        // it — the same failure shape the resolve permit fixed.
        OUTBOUND_WAITERS.with(|queue| {
            for waker in queue.borrow_mut().drain(..) {
                waker.wake();
            }
        });
    }
}

/// Wait for an outbound connection slot under
/// [`MAX_OUTBOUND_INFLIGHT`]. Futures queue here instead of inside the
/// runtime, where an in-flight slot held by a stalled response would
/// deadlock them.
pub fn outbound_slot() -> impl std::future::Future<Output = OutboundPermit> {
    std::future::poll_fn(|cx: &mut Context<'_>| {
        if OUTBOUND_INFLIGHT.with(|inflight| inflight.get() < MAX_OUTBOUND_INFLIGHT) {
            OUTBOUND_INFLIGHT.with(|inflight| inflight.set(inflight.get() + 1));
            Poll::Ready(OutboundPermit { _private: () })
        } else {
            OUTBOUND_WAITERS.with(|queue| queue.borrow_mut().push_back(cx.waker().clone()));
            Poll::Pending
        }
    })
}

/// Bind an [`OutboundPermit`] to a body stream: the slot frees when the
/// stream is consumed or dropped, never earlier.
pub fn slotted(stream: BodyStream, permit: OutboundPermit) -> BodyStream {
    Box::pin(SlottedStream {
        _permit: permit,
        inner: stream,
    })
}

struct SlottedStream {
    _permit: OutboundPermit,
    inner: BodyStream,
}

impl futures_util::Stream for SlottedStream {
    type Item = stow_resolve::util::CargoResult<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

/// Test double for [`FetchedResponse`]: records which terminal path the
/// body took so host tests can prove a branch consumed or cancelled it.
#[cfg(test)]
pub mod stub {
    use super::{CancellableBody, FetchedResponse};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A canned response whose body reports how it ended.
    pub struct StubResponse {
        /// HTTP status code.
        pub status: u16,
        /// Response headers.
        pub headers: Vec<(String, String)>,
        /// Body returned by `text()`.
        pub body: String,
        /// Set when `cancel_body` ran.
        pub cancelled: Arc<AtomicBool>,
        /// Set when `text` ran.
        pub consumed: Arc<AtomicBool>,
    }

    impl StubResponse {
        /// A stub at `status` with no headers or body, plus its flags.
        pub fn new(status: u16) -> (Self, Arc<AtomicBool>, Arc<AtomicBool>) {
            let cancelled = Arc::new(AtomicBool::new(false));
            let consumed = Arc::new(AtomicBool::new(false));
            (
                Self {
                    status,
                    headers: Vec::new(),
                    body: String::new(),
                    cancelled: cancelled.clone(),
                    consumed: consumed.clone(),
                },
                cancelled,
                consumed,
            )
        }

        /// Attach one header value.
        pub fn with_header(mut self, name: &str, value: &str) -> Self {
            self.headers.push((name.to_owned(), value.to_owned()));
            self
        }
    }

    impl CancellableBody for StubResponse {
        fn cancel_body(self) {
            self.cancelled.store(true, Ordering::SeqCst);
        }
    }

    impl FetchedResponse for StubResponse {
        fn status_code(&self) -> u16 {
            self.status
        }

        fn header(&self, name: &str) -> Option<String> {
            self.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.clone())
        }

        fn text(self) -> impl std::future::Future<Output = Result<String, String>> {
            self.consumed.store(true, Ordering::SeqCst);
            std::future::ready(Ok(self.body))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::stub::StubResponse;
    use super::{GuardedResponse, MAX_OUTBOUND_INFLIGHT, outbound_slot};
    use std::task::{Context, Poll, Waker};

    /// A response dropped without a read cancels the body instead of
    /// stalling the connection — the branch that used to leak.
    #[test]
    fn drop_cancels_an_unread_body() {
        use std::sync::atomic::Ordering;

        let (response, cancelled, consumed) = StubResponse::new(404);
        drop(GuardedResponse::new(response));
        assert!(
            cancelled.load(Ordering::SeqCst),
            "unread drop must cancel the body"
        );
        assert!(!consumed.load(Ordering::SeqCst));
    }

    /// Handing the body to a consumer disarms the guard — the read path
    /// owns the terminal state, so no double-cancel.
    #[test]
    fn into_inner_disarms_the_drop() {
        use std::sync::atomic::Ordering;

        let (response, cancelled, _) = StubResponse::new(200);
        let response = GuardedResponse::new(response);
        let body = response.into_inner();
        drop(body);
        assert!(
            !cancelled.load(Ordering::SeqCst),
            "consumed bodies must not be cancelled"
        );
    }

    /// The N+1th fetch queues until a slot frees — and a dead waker in
    /// the queue must not strand the waiters behind it, same contract as
    /// `resolve_permit`.
    #[test]
    fn outbound_slot_bounds_inflight_and_wakes_past_dead_waiters() {
        struct Flag(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl std::task::Wake for Flag {
            fn wake(self: std::sync::Arc<Self>) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            fn wake_by_ref(self: &std::sync::Arc<Self>) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let noop = futures_util::task::noop_waker();
        let mut noop_cx = Context::from_waker(&noop);

        let mut held = Vec::new();
        for _ in 0..MAX_OUTBOUND_INFLIGHT {
            let mut acquire = Box::pin(outbound_slot());
            match acquire.as_mut().poll(&mut noop_cx) {
                Poll::Ready(permit) => held.push(permit),
                Poll::Pending => panic!("slot must be free below the cap"),
            }
        }

        let mut queued = Box::pin(outbound_slot());
        assert!(
            queued.as_mut().poll(&mut noop_cx).is_pending(),
            "fetch at the cap must queue"
        );

        // A dead waiter between the permit and the live queue.
        let mut dead = Box::pin(outbound_slot());
        assert!(dead.as_mut().poll(&mut noop_cx).is_pending());
        drop(dead);

        let woke = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waker = Waker::from(std::sync::Arc::new(Flag(woke.clone())));
        let mut cx = Context::from_waker(&waker);
        let mut live = Box::pin(outbound_slot());
        assert!(live.as_mut().poll(&mut cx).is_pending());

        drop(held.pop().expect("held slot"));
        assert!(
            woke.load(std::sync::atomic::Ordering::SeqCst),
            "a live waiter behind a dead waker must still be woken"
        );
        assert!(live.as_mut().poll(&mut cx).is_ready());
    }
}
