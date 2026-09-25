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
//! connection exactly like a full read. [`OutboundPool`] keeps the
//! resolve path's fetch fan-out inside the same budget.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use async_lock::{Semaphore, SemaphoreGuardArc};

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

/// One invocation's bound on the Workers outgoing-connection budget.
///
/// The platform caps the connections a single request or DO fetch may
/// hold at once, so the pool is a value owned by the invocation — built
/// where the request (or DO fetch) is handled and passed to the fetch
/// clients that run inside it — never ambient state. An isolate-wide
/// pool would let one request's slow `.crate` download hold slots a
/// concurrent invocation needs, recreating the deadlock the bound
/// exists to prevent. Cloning the pool shares the budget, which is how
/// the several clients inside one invocation stay under the same bound.
#[derive(Debug, Clone)]
pub struct OutboundPool {
    semaphore: Arc<Semaphore>,
    stats: Arc<PoolStats>,
}

/// The running counts the transport's trace events carry: how many of
/// this invocation's fetches hold a connection slot and how many are
/// queued for one — the two numbers a hang diagnosis needs.
#[derive(Debug, Default)]
struct PoolStats {
    held: AtomicUsize,
    waiting: AtomicUsize,
}

/// Counts an in-flight `slot()` acquisition: dropping the acquire future
/// (a cancelled request never polls again) backs the counter back out.
struct WaitingOn(Arc<PoolStats>);

impl WaitingOn {
    fn new(stats: Arc<PoolStats>) -> Self {
        stats.waiting.fetch_add(1, Ordering::SeqCst);
        Self(stats)
    }
}

impl Drop for WaitingOn {
    fn drop(&mut self) {
        self.0.waiting.fetch_sub(1, Ordering::SeqCst);
    }
}

impl OutboundPool {
    /// A fresh pool with every slot free — one per invocation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(MAX_OUTBOUND_INFLIGHT)),
            stats: Arc::new(PoolStats::default()),
        }
    }

    /// `(held, waiting)` — live connection slots and queued acquirers.
    pub fn stats(&self) -> (usize, usize) {
        (
            self.stats.held.load(Ordering::SeqCst),
            self.stats.waiting.load(Ordering::SeqCst),
        )
    }

    /// Wait for an outbound connection slot under
    /// [`MAX_OUTBOUND_INFLIGHT`]. Futures queue inside the semaphore
    /// instead of inside the runtime, where an in-flight slot held by a
    /// stalled response would deadlock them.
    pub fn slot(&self) -> impl std::future::Future<Output = OutboundPermit> + use<> {
        let semaphore = self.semaphore.clone();
        let stats = self.stats.clone();
        async move {
            let wait = WaitingOn::new(stats.clone());
            let guard = semaphore.acquire_arc().await;
            drop(wait);
            stats.held.fetch_add(1, Ordering::SeqCst);
            OutboundPermit {
                _guard: guard,
                stats,
            }
        }
    }
}

impl Default for OutboundPool {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII permit for one outbound connection slot — released when the
/// fetch's body reaches its terminal state.
///
/// The permit is the semaphore's owned guard, not a hand-rolled counter:
/// a waker list drained by `Drop` can still hold a waker for the task
/// that is *currently being polled* — a task's earlier wait leaves a
/// stale waker behind even after the task has re-polled — and waking a
/// running task is what panicked the single-threaded
/// `js_sys::futures` executor (`Task::run` holds its `inner` `RefCell`
/// across the poll; waking it re-queues the task and a re-entrant `run`
/// hits `RefCell already borrowed` at `task/singlethread.rs`). An
/// event-listener semaphore cannot do that: a listener exists only
/// inside a poll that returned `Pending`, so `notify` can only ever
/// wake a task that is asleep.
pub struct OutboundPermit {
    _guard: SemaphoreGuardArc,
    stats: Arc<PoolStats>,
}

impl Drop for OutboundPermit {
    fn drop(&mut self) {
        self.stats.held.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Bind an [`OutboundPermit`] to a body stream: the slot frees when the
/// stream is consumed or dropped, never earlier. The trace events mark
/// which of the two happened — a stream dropped before `finished` is
/// the parked-body pattern the hang hunt is after.
pub fn slotted(stream: BodyStream, permit: OutboundPermit, url: String) -> BodyStream {
    Box::pin(SlottedStream {
        _permit: permit,
        inner: stream,
        url,
        finished: false,
    })
}

struct SlottedStream {
    _permit: OutboundPermit,
    inner: BodyStream,
    url: String,
    finished: bool,
}

impl futures_util::Stream for SlottedStream {
    type Item = stow_resolve::util::CargoResult<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let poll = self.inner.as_mut().poll_next(cx);
        if matches!(poll, Poll::Ready(None)) {
            self.finished = true;
            tracing::info!(url = %self.url, "fetch: stream finished");
        }
        poll
    }
}

impl Drop for SlottedStream {
    fn drop(&mut self) {
        if !self.finished {
            tracing::info!(url = %self.url, "fetch: stream dropped mid-body");
        }
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
    use super::{GuardedResponse, MAX_OUTBOUND_INFLIGHT, OutboundPool};
    use std::pin::Pin;
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

    /// The N+1th fetch queues until a slot frees — and a waiter whose
    /// future was dropped before its wake must not strand the waiters
    /// behind it, same contract as `resolve_permit`.
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
        let pool = OutboundPool::new();

        let mut held = Vec::new();
        for _ in 0..MAX_OUTBOUND_INFLIGHT {
            let mut acquire = Box::pin(pool.slot());
            match acquire.as_mut().poll(&mut noop_cx) {
                Poll::Ready(permit) => held.push(permit),
                Poll::Pending => panic!("slot must be free below the cap"),
            }
        }

        // A dead waiter at the head of the queue — its listener
        // unregisters with the dropped future.
        let mut dead = Box::pin(pool.slot());
        assert!(dead.as_mut().poll(&mut noop_cx).is_pending());
        drop(dead);

        let woke = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waker = Waker::from(std::sync::Arc::new(Flag(woke.clone())));
        let mut cx = Context::from_waker(&waker);
        let mut live = Box::pin(pool.slot());
        assert!(live.as_mut().poll(&mut cx).is_pending());

        drop(held.pop().expect("held slot"));
        assert!(
            woke.load(std::sync::atomic::Ordering::SeqCst),
            "a live waiter behind a dead waker must still be woken"
        );
        assert!(live.as_mut().poll(&mut cx).is_ready());
    }

    /// The budget is per pool, not ambient: a second invocation's pool
    /// acquires freely while the first holds every slot, and a clone of
    /// the busy pool — a second client in the same invocation — shares
    /// its bound.
    #[test]
    fn pools_bound_each_invocation_independently() {
        let noop = futures_util::task::noop_waker();
        let mut noop_cx = Context::from_waker(&noop);
        let busy = OutboundPool::new();

        let mut held = Vec::new();
        for _ in 0..MAX_OUTBOUND_INFLIGHT {
            let mut acquire = Box::pin(busy.slot());
            match acquire.as_mut().poll(&mut noop_cx) {
                Poll::Ready(permit) => held.push(permit),
                Poll::Pending => panic!("slot must be free below the cap"),
            }
        }
        assert_eq!(held.len(), MAX_OUTBOUND_INFLIGHT);
        // `held` keeps the permits alive — dropping any would free a slot.
        // A clone is the same invocation's pool — it sees the cap.
        let same_invocation = busy.clone();
        let mut shared = Box::pin(same_invocation.slot());
        assert!(
            shared.as_mut().poll(&mut noop_cx).is_pending(),
            "clients sharing a pool share its bound"
        );

        // A fresh pool is a different invocation — its slots are free.
        let other_invocation = OutboundPool::new();
        let mut independent = Box::pin(other_invocation.slot());
        assert!(
            independent.as_mut().poll(&mut noop_cx).is_ready(),
            "another invocation's pool must not queue behind this one"
        );

        // Once the held permits drop, this invocation's pool frees again.
        drop(shared);
        drop(held);
        let mut freed = Box::pin(busy.slot());
        assert!(freed.as_mut().poll(&mut noop_cx).is_ready());
    }

    /// A permit dropped *inside the poll of the task holding it* — the
    /// drop path that panicked the singlethreaded executor when the
    /// drain-all queue woke the running task. The semaphore's notify can
    /// only reach listeners, and a listener exists only behind a
    /// `Pending` poll, so the running task's own waker is never invoked.
    #[test]
    fn release_inside_the_holders_poll_still_wakes_waiters() {
        use std::future::Future;

        /// A future that drops its held permit while it is being polled.
        struct ReleaseInsidePoll {
            permit: Option<super::OutboundPermit>,
        }
        impl Future for ReleaseInsidePoll {
            type Output = ();
            fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                drop(self.permit.take());
                Poll::Ready(())
            }
        }

        struct Flag(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl std::task::Wake for Flag {
            fn wake(self: std::sync::Arc<Self>) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let noop = futures_util::task::noop_waker();
        let mut noop_cx = Context::from_waker(&noop);
        let pool = OutboundPool::new();

        let mut held = Vec::new();
        for _ in 0..MAX_OUTBOUND_INFLIGHT {
            let mut acquire = Box::pin(pool.slot());
            match acquire.as_mut().poll(&mut noop_cx) {
                Poll::Ready(permit) => held.push(permit),
                Poll::Pending => panic!("slot must be free below the cap"),
            }
        }

        let woke = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waker = Waker::from(std::sync::Arc::new(Flag(woke.clone())));
        let mut cx = Context::from_waker(&waker);
        let mut queued = Box::pin(pool.slot());
        assert!(queued.as_mut().poll(&mut cx).is_pending());

        // The holder releases mid-poll — the waiter is woken, never run inline.
        let mut release = Box::pin(ReleaseInsidePoll { permit: held.pop() });
        assert!(release.as_mut().poll(&mut noop_cx).is_ready());
        assert!(
            woke.load(std::sync::atomic::Ordering::SeqCst),
            "the freed slot must reach the waiter"
        );
        assert!(queued.as_mut().poll(&mut cx).is_ready());
    }

    /// A permit dropped *inside a waiting task's poll*: the waiter
    /// registers on a full semaphore and releases its other permit in the
    /// same poll — the freed slot must flow to the next waiter, proving
    /// release-in-poll composes with the queue instead of re-entering it.
    #[test]
    fn release_inside_a_waiters_poll_passes_the_permit() {
        use std::future::Future;

        /// A waiter that drops a second held permit while its acquire
        /// poll is outstanding.
        struct WaitAndRelease {
            acquire: Pin<Box<dyn Future<Output = super::OutboundPermit>>>,
            held: Option<super::OutboundPermit>,
        }
        impl Future for WaitAndRelease {
            type Output = super::OutboundPermit;
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let poll = self.acquire.as_mut().poll(cx);
                drop(self.held.take());
                poll
            }
        }

        let noop = futures_util::task::noop_waker();
        let mut noop_cx = Context::from_waker(&noop);
        let pool = OutboundPool::new();

        let mut held = Vec::new();
        for _ in 0..MAX_OUTBOUND_INFLIGHT {
            let mut acquire = Box::pin(pool.slot());
            match acquire.as_mut().poll(&mut noop_cx) {
                Poll::Ready(permit) => held.push(permit),
                Poll::Pending => panic!("slot must be free below the cap"),
            }
        }

        let mut front = Box::pin(WaitAndRelease {
            acquire: Box::pin(pool.slot()),
            held: held.pop(),
        });
        // Pool is full: the acquire half pends — but the poll also
        // released the permit this future was holding.
        assert!(front.as_mut().poll(&mut noop_cx).is_pending());

        // That release wakes the front waiter itself — its own listener
        // is the only one, and the next poll completes the acquire. The
        // permit must be kept, or its drop frees another slot.
        let _front_permit = match front.as_mut().poll(&mut noop_cx) {
            Poll::Ready(permit) => permit,
            Poll::Pending => panic!("the waiter's own release must wake it"),
        };

        // And with the pool again full, a fresh waiter queues — nothing
        // was stranded by the mid-poll release.
        let mut tail = Box::pin(pool.slot());
        assert!(tail.as_mut().poll(&mut noop_cx).is_pending());
        drop(held.pop());
        assert!(tail.as_mut().poll(&mut noop_cx).is_ready());
    }
}
