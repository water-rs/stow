//! Debug-build resolve-state registry.
//!
//! The edge worker's resolve watchdog polls [`snapshot`] every 500ms and
//! prints one line when the state changed — the answer to "what is this
//! invocation waiting on" when the runtime reports the request hung.
//! Everything lives in a thread-local because the worker isolate is
//! single-threaded and the resolve interleaves futures on it.

use std::cell::RefCell;
use std::collections::BTreeMap;

/// One index-file load: whether the owning future still lives, and how
/// many dedup waiters queue on its result. `owner_alive == false` with
/// waiters left is the orphan signature — the owner was dropped without
/// completing and its waiters are never woken.
#[derive(Debug, Clone)]
pub struct IndexLoad {
    /// `true` while the future doing the fetch still exists.
    pub owner_alive: bool,
    /// Futures parked on `rx.await` for this name.
    pub waiters: usize,
}

/// The watchdog's view of resolve internals at one instant.
#[derive(Debug, Default, Clone)]
pub struct Trace {
    /// Index loads in flight, by crate name.
    pub index_loads: BTreeMap<String, IndexLoad>,
    /// `get_package` futures not yet resolved in the download queue.
    pub downloads_queue: usize,
    /// `.crate` fetches currently on the wire.
    pub downloads_pending: u64,
    /// `.crate` fetches completed.
    pub downloads_done: u64,
}

thread_local! {
    static TRACE: RefCell<Trace> = RefCell::new(Trace::default());
}

/// A point-in-time copy of the registry, for the watchdog's line.
pub fn snapshot() -> Trace {
    TRACE.with(|trace| trace.borrow().clone())
}

/// RAII mark for a `load_summaries` owner: `owner_alive` clears when the
/// owner's future finishes *or* is dropped mid-await — the latter is the
/// poll-and-discard/cancel case whose waiters are never woken.
pub struct IndexOwner(String);

impl IndexOwner {
    /// `load_summaries` accepted the owner role for `name`.
    pub fn begin(name: &str) -> Self {
        TRACE.with(|trace| {
            trace.borrow_mut().index_loads.insert(
                name.to_string(),
                IndexLoad {
                    owner_alive: true,
                    waiters: 0,
                },
            );
        });
        Self(name.to_string())
    }
}

impl Drop for IndexOwner {
    fn drop(&mut self) {
        index_owner_end(&self.0);
    }
}

/// `load_summaries` parked a dedup waiter on `name`.
pub fn index_waiter_add(name: &str) {
    TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        trace
            .index_loads
            .entry(name.to_string())
            .or_insert(IndexLoad {
                owner_alive: false,
                waiters: 0,
            })
            .waiters += 1;
    });
}

/// A waiter's channel resolved (or was dropped) — one fewer parked.
pub fn index_waiter_remove(name: &str) {
    TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        if let Some(load) = trace.index_loads.get_mut(name) {
            load.waiters = load.waiters.saturating_sub(1);
            if load.waiters == 0 && !load.owner_alive {
                trace.index_loads.remove(name);
            }
        }
    });
}

/// Owner for `name` finished or was dropped — waiters already sent, or
/// orphaned (which is the state the watchdog exists to surface).
pub fn index_owner_end(name: &str) {
    TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        if let Some(load) = trace.index_loads.get_mut(name) {
            load.owner_alive = false;
            if load.waiters == 0 {
                trace.index_loads.remove(name);
            }
        }
    });
}

/// Mirror the download queue's counters (called at queue begin, each
/// 200ms tick, and each crate fetch boundary).
pub fn downloads_queue(queue: usize) {
    TRACE.with(|trace| trace.borrow_mut().downloads_queue = queue);
}

/// `.crate` fetches currently on the wire.
pub fn downloads_pending(pending: u64) {
    TRACE.with(|trace| trace.borrow_mut().downloads_pending = pending);
}

/// `.crate` fetches completed.
pub fn downloads_done(done: u64) {
    TRACE.with(|trace| trace.borrow_mut().downloads_done = done);
}
