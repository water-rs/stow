//! Mock-only union of scheduler request and alarm processing intervals.
//! This observes handler wall time, not production billable duration.

#[derive(Debug, Default)]
pub(super) struct Activity {
    finished_ms: u64,
    busy: Option<Busy>,
}

#[derive(Debug)]
struct Busy {
    started_ms: i64,
    invocations: std::num::NonZeroU32,
}

impl Activity {
    #[cfg(any(test, target_arch = "wasm32"))]
    pub(super) const fn begin(&mut self, now: i64) {
        match &mut self.busy {
            Some(busy) => {
                busy.invocations = busy
                    .invocations
                    .checked_add(1)
                    .expect("invocations fit u32");
            }
            None => {
                self.busy = Some(Busy {
                    started_ms: now,
                    invocations: std::num::NonZeroU32::MIN,
                });
            }
        }
    }

    #[cfg(any(test, target_arch = "wasm32"))]
    pub(super) fn end(&mut self, now: i64) {
        let busy = self.busy.as_mut().expect("invocation was started");
        if let Some(remaining) = std::num::NonZeroU32::new(busy.invocations.get() - 1) {
            busy.invocations = remaining;
        } else {
            self.finished_ms +=
                u64::try_from(now - busy.started_ms).expect("clock moved backwards");
            self.busy = None;
        }
    }

    pub(super) fn read(&self, now: i64) -> u64 {
        self.finished_ms
            + self.busy.as_ref().map_or(0, |busy| {
                u64::try_from(now - busy.started_ms).expect("clock moved backwards")
            })
    }
}

/// Balanced even when a handler returns an error or its future is dropped.
#[cfg(any(test, target_arch = "wasm32"))]
pub(super) struct Invocation<'a, C: Fn() -> i64> {
    activity: &'a std::sync::Mutex<Activity>,
    clock: C,
}

#[cfg(any(test, target_arch = "wasm32"))]
impl<'a, C: Fn() -> i64> Invocation<'a, C> {
    pub(super) fn start(activity: &'a std::sync::Mutex<Activity>, clock: C) -> Self {
        activity
            .lock()
            .expect("activity counter poisoned")
            .begin(clock());
        Self { activity, clock }
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
impl<C: Fn() -> i64> Drop for Invocation<'_, C> {
    fn drop(&mut self) {
        self.activity
            .lock()
            .expect("activity counter poisoned")
            .end((self.clock)());
    }
}

#[cfg(test)]
mod tests {
    use super::Activity;

    #[test]
    fn error_returns_and_cancelled_futures_finish_the_interval() {
        use futures_util::FutureExt as _;
        let activity = std::sync::Mutex::new(Activity::default());
        let time = std::cell::Cell::new(10);
        let failed = || -> Result<(), &'static str> {
            let _invocation = super::Invocation::start(&activity, || time.get());
            time.set(20);
            Err("handler failed")
        };
        assert_eq!(failed(), Err("handler failed"));
        assert_eq!(activity.lock().unwrap().read(100), 10);
        time.set(200);
        let cancelled = async {
            let _invocation = super::Invocation::start(&activity, || time.get());
            time.set(225);
            std::future::pending::<()>().await;
        };
        assert!(cancelled.now_or_never().is_none());
        assert_eq!(activity.lock().unwrap().read(500), 35);
    }

    #[test]
    fn overlapping_requests_and_alarms_count_one_interval_and_exclude_idle() {
        let mut counter = Activity::default();
        counter.begin(10);
        counter.begin(15);
        assert_eq!(counter.read(20), 10);
        counter.end(25);
        assert_eq!(counter.read(30), 20);
        counter.end(40);
        assert_eq!(counter.read(80), 30);
        counter.begin(100);
        counter.end(110);
        assert_eq!(counter.read(200), 40);
    }
}
