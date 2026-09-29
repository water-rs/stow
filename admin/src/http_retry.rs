//! The retry policy every `stow-admin` HTTP client shares: which answers
//! are transient, how long to wait before the next attempt, and when to
//! give up. A wave or a lane issues hundreds of requests over tens of
//! minutes, so one transient answer is likely somewhere in every run —
//! on 2026-09-21 one `Invalid redirect URL` on `lock_api` ended a whole
//! target's crates.io lane, and on 2026-09-29 one HTTP/2 transport error
//! on a GitHub runs poll ended a manual preheat wave.

use std::time::Duration;

/// How many times one request is attempted before the command fails.
const ATTEMPTS: u32 = 4;
/// Delay before the second attempt; doubles for each one after it, then
/// lengthens — never shortens — to the `Retry-After` hint when an answer
/// carries one.
const RETRY_DELAY: Duration = Duration::from_millis(500);
/// Ceiling on the backoff a `Retry-After` hint can push to — a bounded
/// wait that still honors the servers' real answers (they send seconds).
const RETRY_AFTER_MAX: Duration = Duration::from_mins(5);

/// One request's remaining retry budget.
pub struct Backoff {
    retries_left: u32,
    delay: Duration,
}

impl Backoff {
    /// A fresh budget: [`ATTEMPTS`] attempts in all.
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

/// Whether `status` is transient — the set every stow client shares.
pub const fn is_retryable(status: zenwave::StatusCode) -> bool {
    stow_types::transient::is_transient_status(status.as_u16())
}

/// `Retry-After` as a duration; only the delta-seconds form is honored.
pub fn retry_after_hint(response: &zenwave::Response) -> Option<Duration> {
    response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{ATTEMPTS, Backoff, RETRY_AFTER_MAX, RETRY_DELAY};

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
