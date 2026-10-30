//! The process-wide bound on registry writes.
//!
//! GHCR caps writes — `POST`, `PUT` and `PATCH` — at 2000 per minute per
//! namespace and answers the excess `429 TOOMANYREQUESTS`; reads are not
//! capped. A process that fans publishes out (the repack sweep runs tens
//! of tasks at once) reaches that cap on its own, and every request it
//! sends past it is a refusal the client has to wait out. [`WriteBudget`]
//! keeps the process below an operator-set rate instead: each write waits
//! for a token before it is dispatched, retries included, since GHCR
//! counts a refused write as a write.

use std::num::NonZeroU32;
use std::sync::Arc;

use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};

/// The operator setting that sets the rate, in writes per minute.
const WRITES_PER_MINUTE_ENV: &str = "STOW_GHCR_WRITES_PER_MINUTE";

/// The rate when [`WRITES_PER_MINUTE_ENV`] is unset: three quarters of
/// GHCR's 2000-per-minute namespace cap, leaving 500 writes a minute to the
/// build publishes and index publishes that write into the same namespace
/// while a sweep runs.
const DEFAULT_WRITES_PER_MINUTE: NonZeroU32 = NonZeroU32::new(1500).expect("non-zero");

/// One process's registry write budget — a token bucket refilled at the
/// configured rate, holding at most one second of it.
///
/// A burst of a full minute would let the first second spend the whole
/// minute's allowance and the next fifty-nine refill it, putting up to
/// twice the rate into one minute of GHCR's window; a one-second bucket
/// keeps every sixty-second span within the rate plus one second of it.
///
/// Clones share the bucket. Build it once per process and hand it to
/// every push session the process opens.
#[derive(Debug, Clone)]
pub struct WriteBudget {
    limiter: Arc<DefaultDirectRateLimiter>,
    per_minute: NonZeroU32,
}

impl WriteBudget {
    /// A budget of `per_minute` writes a minute.
    #[must_use]
    pub fn per_minute(per_minute: NonZeroU32) -> Self {
        let burst = NonZeroU32::new(per_minute.get() / 60).unwrap_or(NonZeroU32::MIN);
        Self {
            limiter: Arc::new(RateLimiter::direct(
                Quota::per_minute(per_minute).allow_burst(burst),
            )),
            per_minute,
        }
    }

    /// The budget `STOW_GHCR_WRITES_PER_MINUTE` sets, else 1500 writes a
    /// minute.
    ///
    /// # Errors
    ///
    /// The variable is set to anything but a positive whole number.
    pub fn from_env() -> stow_types::error::Result<Self> {
        let per_minute = match std::env::var(WRITES_PER_MINUTE_ENV) {
            Ok(value) => value.trim().parse::<NonZeroU32>().map_err(|error| {
                stow_types::stow_error!(
                    "{WRITES_PER_MINUTE_ENV}={value:?} is not a positive number of writes per minute: {error}"
                )
            })?,
            Err(std::env::VarError::NotPresent) => DEFAULT_WRITES_PER_MINUTE,
            Err(std::env::VarError::NotUnicode(value)) => {
                return Err(stow_types::stow_error!(
                    "{WRITES_PER_MINUTE_ENV}={value:?} is not Unicode"
                ));
            }
        };
        Ok(Self::per_minute(per_minute))
    }

    /// The configured rate.
    #[must_use]
    pub const fn writes_per_minute(&self) -> NonZeroU32 {
        self.per_minute
    }

    /// Wait for one write's token.
    pub(crate) async fn acquire(&self) {
        self.limiter.until_ready().await;
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::time::{Duration, Instant};

    use super::{WRITES_PER_MINUTE_ENV, WriteBudget};

    /// The bucket holds one second of the rate: that many writes go at
    /// once, and the next waits for the refill. Each assertion holds
    /// however slowly the test runs — a refusal is only demanded while no
    /// refill interval has passed.
    #[tokio::test]
    async fn the_bucket_holds_one_second_of_the_rate() {
        let budget = WriteBudget::per_minute(NonZeroU32::new(600).expect("rate"));
        let start = Instant::now();
        for _ in 0..10 {
            assert!(budget.limiter.check().is_ok(), "the burst is free");
        }
        assert!(
            budget.limiter.check().is_err() || start.elapsed() >= Duration::from_millis(100),
            "the eleventh write is held for a refill interval"
        );
        budget.acquire().await;
        assert!(
            start.elapsed() >= Duration::from_millis(90),
            "the next write waited for the refill: {:?}",
            start.elapsed()
        );
    }

    /// A rate under one write a second still admits one write at a time.
    #[test]
    fn a_slow_rate_keeps_a_burst_of_one() {
        let budget = WriteBudget::per_minute(NonZeroU32::new(30).expect("rate"));
        let start = Instant::now();
        assert!(budget.limiter.check().is_ok());
        assert!(
            budget.limiter.check().is_err() || start.elapsed() >= Duration::from_secs(2),
            "a second write waits two seconds"
        );
    }

    #[test]
    #[serial_test::serial]
    fn the_rate_is_an_operator_setting() {
        // SAFETY: serialized against every other env-mutating test.
        unsafe { std::env::remove_var(WRITES_PER_MINUTE_ENV) };
        assert_eq!(
            WriteBudget::from_env()
                .expect("default")
                .writes_per_minute()
                .get(),
            1500
        );
        // SAFETY: as above.
        unsafe { std::env::set_var(WRITES_PER_MINUTE_ENV, "120000") };
        assert_eq!(
            WriteBudget::from_env()
                .expect("set")
                .writes_per_minute()
                .get(),
            120_000
        );
        for invalid in ["0", "-1", "fast"] {
            // SAFETY: as above.
            unsafe { std::env::set_var(WRITES_PER_MINUTE_ENV, invalid) };
            let error = WriteBudget::from_env().expect_err("invalid rate");
            assert!(error.to_string().contains(WRITES_PER_MINUTE_ENV), "{error}");
        }
        // SAFETY: as above.
        unsafe { std::env::remove_var(WRITES_PER_MINUTE_ENV) };
    }
}
