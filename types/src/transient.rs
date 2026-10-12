//! The transient-failure policy every stow HTTP client shares: which
//! answers are worth another attempt, how long to wait before it, and
//! when to give up.
//!
//! A long run (a preheat wave, an index export, a mold install on a
//! flaky link) issues enough requests that one of these lands somewhere
//! in it, and the request that met it is worth another attempt — on
//! 2026-09-21 one `Invalid redirect URL` on `lock_api` ended a whole
//! target's crates.io lane, on 2026-09-29 one HTTP/2 transport error on
//! a GitHub runs poll ended a manual preheat wave, on 2026-10-01 one
//! `http2 error` on the mold release download failed `stow setup`,
//! and on 2026-10-12 a 502 burst during a GitHub incident ended a wave
//! three times.

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

/// Per-wait ceiling under [`Backoff::outage`]: one minute, so a
/// recovered API is noticed at the next attempt rather than slept
/// through — doubling unbounded would leave a recovered GitHub
/// unpolled for longer than the incident that raised the waits.
const OUTAGE_DELAY_MAX: Duration = Duration::from_mins(1);

/// Total wait one [`Backoff::outage`] read hands out before giving up:
/// an hour is longer than the incidents GitHub's status page records
/// for Actions, and it is cheap against a wave's own two-day deadline —
/// a waiting wave holds no runner, so the only thing the bound spends
/// is the wave's clock.
const OUTAGE_BOUND: Duration = Duration::from_hours(1);

/// One request's remaining retry budget.
#[derive(Debug)]
pub struct Backoff {
    /// The wait the next retry takes absent a hint — doubles each retry.
    delay: Duration,
    /// The ceiling on the doubling delay — [`OUTAGE_DELAY_MAX`] when the
    /// budget counts time, none below [`RETRY_AFTER_MAX`] when it counts
    /// attempts. A `Retry-After` hint is the server's own answer and may
    /// lengthen a wait past it, up to [`RETRY_AFTER_MAX`].
    delay_max: Duration,
    /// What the budget spends down.
    budget: Budget,
}

/// How a [`Backoff`] measures what is left. The budget is counted in
/// what has been handed out — attempts, or summed waits — never read
/// from a clock, so it stays deterministic and this module compiles for
/// `wasm32`.
#[derive(Debug)]
enum Budget {
    /// Retries remaining under [`Backoff::new`].
    Retries(u32),
    /// Waits already handed out under [`Backoff::outage`], summed; a
    /// wait that would carry the sum past [`OUTAGE_BOUND`] is never
    /// handed out.
    Waited(Duration),
}

impl Backoff {
    /// A fresh budget: [`ATTEMPTS`] attempts in all.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            delay: RETRY_DELAY,
            delay_max: RETRY_AFTER_MAX,
            budget: Budget::Retries(ATTEMPTS - 1),
        }
    }

    /// An outage-sized budget: the same doubling from [`RETRY_DELAY`],
    /// the delay capped at [`OUTAGE_DELAY_MAX`], until the waits already
    /// handed out reach [`OUTAGE_BOUND`] — for a reader that can wait an
    /// incident out, like a wave driver holding no runner.
    #[must_use]
    pub const fn outage() -> Self {
        Self {
            delay: RETRY_DELAY,
            delay_max: OUTAGE_DELAY_MAX,
            budget: Budget::Waited(Duration::ZERO),
        }
    }

    /// The wait before retrying a transient failure, honoring its
    /// `Retry-After` hint — `None` once the budget is spent (every
    /// attempt under [`Backoff::new`], the summed waits reaching
    /// [`OUTAGE_BOUND`] under [`Backoff::outage`]), and the failure is
    /// final.
    pub fn next_wait(&mut self, retry_after: Option<Duration>) -> Option<Duration> {
        let delay = self.delay.min(self.delay_max);
        let wait = retry_after.map_or(delay, |hint| hint.max(delay).min(RETRY_AFTER_MAX));
        match &mut self.budget {
            Budget::Retries(retries_left) => {
                if *retries_left == 0 {
                    return None;
                }
                *retries_left -= 1;
            }
            Budget::Waited(waited) => {
                if wait > OUTAGE_BOUND.saturating_sub(*waited) {
                    return None;
                }
                *waited += wait;
            }
        }
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

    use super::{
        ATTEMPTS, Backoff, OUTAGE_BOUND, OUTAGE_DELAY_MAX, RETRY_AFTER_MAX, RETRY_DELAY,
        is_transient_status,
    };

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

    /// The outage budget doubles from `RETRY_DELAY` until the waits cap
    /// at `OUTAGE_DELAY_MAX`, and stops handing out waits exactly when
    /// the next one would carry their sum past `OUTAGE_BOUND`.
    #[test]
    fn outage_waits_cap_and_stop_at_the_bound() {
        let mut backoff = Backoff::outage();
        let mut waits = Vec::new();
        let mut sum = Duration::ZERO;
        while let Some(wait) = backoff.next_wait(None) {
            assert!(wait <= OUTAGE_DELAY_MAX, "{wait:?} over the cap");
            waits.push(wait);
            sum += wait;
            assert!(sum <= OUTAGE_BOUND, "the sum passed the bound");
        }
        assert_eq!(
            waits[..7],
            [
                Duration::from_millis(500),
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                Duration::from_secs(16),
                Duration::from_secs(32),
            ]
        );
        assert!(waits[7..].iter().all(|wait| *wait == OUTAGE_DELAY_MAX));
        // Seven doubling waits sum to 63.5 s; 58 capped waits reach
        // 3543.5 s — the 66th's 60 s would pass the bound, so the budget
        // stops within one `OUTAGE_DELAY_MAX` of it.
        assert_eq!(waits.len(), 65);
        assert_eq!(sum, Duration::from_millis(3_543_500));
        assert!(OUTAGE_BOUND.saturating_sub(sum) < OUTAGE_DELAY_MAX);
    }

    /// A `Retry-After` hint is the server's own answer: it lengthens an
    /// outage wait past the delay cap, up to [`RETRY_AFTER_MAX`], and
    /// what it was handed counts toward the bound — a hinted read gives
    /// up after fewer attempts, exactly as the attempt budget treats
    /// hints.
    #[test]
    fn an_outage_hint_lengthens_and_spends_the_bound() {
        let hint = Duration::from_mins(2);
        assert!(hint > OUTAGE_DELAY_MAX && hint < RETRY_AFTER_MAX);
        let mut backoff = Backoff::outage();
        let mut spent = Duration::ZERO;
        let mut handed = 0u32;
        while let Some(wait) = backoff.next_wait(Some(hint)) {
            assert_eq!(wait, hint);
            spent += wait;
            handed += 1;
        }
        assert_eq!(handed, 30);
        assert_eq!(spent, OUTAGE_BOUND);
        assert_eq!(
            Backoff::outage().next_wait(Some(Duration::from_hours(1))),
            Some(RETRY_AFTER_MAX)
        );
    }
}
