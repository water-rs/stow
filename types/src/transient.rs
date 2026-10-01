//! The transient-failure policy every stow HTTP client shares: which
//! answers are worth another attempt, how long to wait before it, and
//! when to give up.
//!
//! A long run (a preheat wave, an index export, a mold install on a
//! flaky link) issues enough requests that one of these lands somewhere
//! in it, and the request that met it is worth another attempt — on
//! 2026-09-21 one `Invalid redirect URL` on `lock_api` ended a whole
//! target's crates.io lane, on 2026-09-29 one HTTP/2 transport error on
//! a GitHub runs poll ended a manual preheat wave, and on 2026-10-01 one
//! `http2 error` on the mold release download failed `stow setup`.

use std::time::Duration;

/// Statuses worth a retry: request timeout, rate limiting, and every
/// server-side failure.
#[must_use]
pub const fn is_transient_status(status: u16) -> bool {
    status == 408 || status == 429 || status >= 500
}

/// How many times one request is attempted before the caller fails —
/// the first try plus the retries [`Backoff::next_wait`] hands out.
const ATTEMPTS: u32 = 4;

/// Delay before the second attempt; doubles for each one after it, then
/// lengthens — never shortens — to the `Retry-After` hint when an answer
/// carries one.
const RETRY_DELAY: Duration = Duration::from_millis(500);

/// Ceiling on the backoff a `Retry-After` hint can push to — a bounded
/// wait that still honors the servers' real answers (they send seconds).
const RETRY_AFTER_MAX: Duration = Duration::from_mins(5);

/// One request's remaining retry budget.
#[derive(Debug)]
pub struct Backoff {
    retries_left: u32,
    delay: Duration,
}

impl Backoff {
    /// A fresh budget: [`ATTEMPTS`] attempts in all.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            retries_left: ATTEMPTS - 1,
            delay: RETRY_DELAY,
        }
    }

    /// The wait before retrying a transient failure, honoring its
    /// `Retry-After` hint — `None` once every attempt is spent, and the
    /// failure is final.
    pub fn next_wait(&mut self, retry_after: Option<Duration>) -> Option<Duration> {
        if self.retries_left == 0 {
            return None;
        }
        self.retries_left -= 1;
        let wait = retry_after.map_or(self.delay, |hint| hint.max(self.delay).min(RETRY_AFTER_MAX));
        self.delay = self.delay.saturating_mul(2);
        Some(wait)
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

/// The `Retry-After` hint a refused answer carries, as a duration; only
/// the delta-seconds form is honored.
#[must_use]
pub fn retry_after_hint(headers: &http::HeaderMap) -> Option<Duration> {
    headers
        .get(http::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{ATTEMPTS, Backoff, RETRY_AFTER_MAX, RETRY_DELAY, is_transient_status};

    #[test]
    fn timeouts_rate_limits_and_server_errors_are_transient() {
        for status in [408, 429, 500, 502, 503, 504] {
            assert!(is_transient_status(status), "{status}");
        }
        for status in [200, 301, 400, 401, 403, 404, 409, 422] {
            assert!(!is_transient_status(status), "{status}");
        }
    }

    /// The budget allows `ATTEMPTS - 1` retries, doubling from
    /// `RETRY_DELAY`, and a `Retry-After` hint only ever lengthens the
    /// wait, up to the ceiling.
    #[test]
    fn backoff_doubles_honors_hints_and_runs_out() {
        let mut backoff = Backoff::new();
        assert_eq!(backoff.next_wait(None), Some(RETRY_DELAY));
        assert_eq!(
            backoff.next_wait(Some(Duration::from_secs(3))),
            Some(Duration::from_secs(3))
        );
        assert_eq!(
            backoff.next_wait(Some(Duration::from_hours(1))),
            Some(RETRY_AFTER_MAX)
        );
        assert_eq!(ATTEMPTS, 4);
        assert_eq!(backoff.next_wait(None), None);
    }
}
