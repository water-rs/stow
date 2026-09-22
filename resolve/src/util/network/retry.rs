//! Utilities for retrying a network operation.
//!
//! Some network errors are considered "spurious", meaning it is not a real
//! error (such as a 404 not found) and is likely a transient error (like a
//! bad network connection) that we can hope will resolve itself shortly. The
//! [`Retry`] type offers a way to repeatedly perform some kind of network
//! operation with a delay if it detects one of these possibly transient
//! errors.
//!
//! This supports errors from [`git2`], [`gix`], [`curl`], and
//! [`HttpNotSuccessful`] 5xx HTTP errors.
//!
//! The number of retries can be configured by the user via the `net.retry`
//! config option. This indicates the number of times to retry the operation
//! (default 3 times for a total of 4 attempts).
//!
//! There are hard-coded constants that indicate how long to sleep between
//! retries. The constants are tuned to balance a few factors, such as the
//! responsiveness to the user (we don't want cargo to hang for too long
//! retrying things), and accommodating things like Cloudfront's default
//! negative TTL of 10 seconds (if Cloudfront gets a 5xx error for whatever
//! reason it won't try to fetch again for 10 seconds).
//!
//! The timeout also implements a primitive form of random jitter. This is so
//! that if multiple requests fail at the same time that they don't all flood
//! the server at the same time when they are retried. This jitter still has
//! some clumping behavior, but should be good enough.
//!
//! [`Retry`] is the core type for implementing retry logic. The
//! [`Retry::try`] method can be called with a callback, and it will
//! indicate if it needs to be called again sometime in the future if there
//! was a possibly transient error. The caller is responsible for sleeping the
//! appropriate amount of time and then calling [`Retry::try`] again.
//!
//! [`with_retry`] is a convenience function that will create a [`Retry`] and
//! handle repeatedly running a callback until it succeeds, or it runs out of
//! retries.
//!
//! Some interesting resources about retries:
//! - <https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/>
//! - <https://en.wikipedia.org/wiki/Exponential_backoff>
//! - <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After>

use crate::util::errors::HttpNotSuccessful;
use crate::util::network::http_async;
use crate::{CargoResult, GlobalContext};
use anyhow::Error;

use std::cmp::min;

/// State for managing retrying a network operation.
pub struct Retry<'a> {
    gctx: &'a GlobalContext,
    /// The number of failed attempts that have been done so far.
    ///
    /// Starts at 0, and increases by one each time an attempt fails.
    retries: u64,
    /// The maximum number of times the operation should be retried.
    ///
    /// 0 means it should never retry.
    max_retries: u64,
}

/// The result of attempting some operation via [`Retry::try`].
pub enum RetryResult<T> {
    /// The operation was successful.
    ///
    /// The wrapped value is the return value of the callback function.
    Success(T),
    /// The operation was an error, and it should not be tried again.
    Err(anyhow::Error),
    /// The operation failed, and should be tried again in the future.
    ///
    /// The wrapped value is the number of milliseconds to wait before trying
    /// again. The caller is responsible for waiting this long and then
    /// calling [`Retry::try`] again.
    Retry(u64),
}

/// Maximum amount of time a single retry can be delayed (milliseconds).
const MAX_RETRY_SLEEP_MS: u64 = 10 * 1000;
/// The minimum initial amount of time a retry will be delayed (milliseconds).
///
/// The actual amount of time will be a random value above this.
const INITIAL_RETRY_SLEEP_BASE_MS: u64 = 500;
/// The maximum amount of additional time the initial retry will take (milliseconds).
///
/// The initial delay will be [`INITIAL_RETRY_SLEEP_BASE_MS`] plus a random range
/// from 0 to this value.
const INITIAL_RETRY_JITTER_MS: u64 = 1000;

impl<'a> Retry<'a> {
    pub fn new(gctx: &'a GlobalContext) -> CargoResult<Retry<'a>> {
        Ok(Retry {
            gctx,
            retries: 0,
            max_retries: gctx.net_config()?.retry.unwrap_or(3) as u64,
        })
    }

    /// Calls the given callback, and returns a [`RetryResult`] which
    /// indicates whether or not this needs to be called again at some point
    /// in the future to retry the operation if it failed.
    pub fn r#try<T>(&mut self, f: impl FnOnce() -> CargoResult<T>) -> RetryResult<T> {
        match f() {
            Err(ref e) if maybe_spurious(e) && self.retries < self.max_retries => {
                let err = e.downcast_ref::<HttpNotSuccessful>();
                let err_msg = err
                    .map(|http_err| http_err.display_short())
                    .unwrap_or_else(|| e.root_cause().to_string());
                let left_retries = self.max_retries - self.retries;
                let msg = format!(
                    "spurious network error ({} {} remaining): {err_msg}",
                    left_retries,
                    if left_retries != 1 { "tries" } else { "try" }
                );
                if let Err(e) = self.gctx.shell().warn(msg) {
                    return RetryResult::Err(e);
                }
                self.retries += 1;
                let sleep = err
                    .and_then(|v| Self::parse_retry_after(v, &jiff::Timestamp::now()))
                    // Limit the Retry-After to a maximum value to avoid waiting too long.
                    .map(|retry_after| retry_after.min(MAX_RETRY_SLEEP_MS))
                    .unwrap_or_else(|| self.next_sleep_ms());
                RetryResult::Retry(sleep)
            }
            Err(e) => RetryResult::Err(e),
            Ok(r) => RetryResult::Success(r),
        }
    }

    /// Gets the next sleep duration in milliseconds.
    fn next_sleep_ms(&self) -> u64 {
        if let Ok(sleep) = self.gctx.get_env("__CARGO_TEST_FIXED_RETRY_SLEEP_MS") {
            return sleep.parse().expect("a u64");
        }

        if self.retries == 1 {
            let mut rng = crate::util::rand::rng();
            INITIAL_RETRY_SLEEP_BASE_MS + rng.random_range(0..INITIAL_RETRY_JITTER_MS)
        } else {
            min(
                ((self.retries - 1) * 3) * 1000 + INITIAL_RETRY_SLEEP_BASE_MS,
                MAX_RETRY_SLEEP_MS,
            )
        }
    }

    /// Parse the HTTP `Retry-After` header.
    /// Returns the number of milliseconds to wait before retrying according to the header.
    fn parse_retry_after(response: &HttpNotSuccessful, now: &jiff::Timestamp) -> Option<u64> {
        // Only applies to HTTP 429 (too many requests) and 503 (service unavailable).
        if !matches!(response.code, 429 | 503) {
            return None;
        }

        // Extract the Retry-After header value.
        let retry_after = response
            .headers
            .iter()
            .filter_map(|h| h.split_once(':'))
            .map(|(k, v)| (k.trim(), v.trim()))
            .find(|(k, _)| k.eq_ignore_ascii_case("retry-after"))?
            .1;

        // First option: Retry-After is a positive integer of seconds to wait.
        if let Ok(delay_secs) = retry_after.parse::<u32>() {
            return Some(delay_secs as u64 * 1000);
        }

        // Second option: Retry-After is a future HTTP date string that tells us when to retry.
        if let Ok(retry_time) = jiff::fmt::rfc2822::parse(retry_after) {
            let diff_ms = now
                .until(&retry_time)
                .unwrap()
                .total(jiff::Unit::Millisecond)
                .unwrap();
            if diff_ms > 0.0 {
                return Some(diff_ms as u64);
            }
        }
        None
    }
}

fn maybe_spurious(err: &Error) -> bool {
    if let Some(async_http_error) = err.downcast_ref::<http_async::Error>() {
        match async_http_error {
            http_async::Error::Spurious(_) => return true,
            http_async::Error::TooSlow(_) => return true,
            http_async::Error::BadHeader(_) => {}
            http_async::Error::Other(_) => {}
        }
    }
    if let Some(not_200) = err.downcast_ref::<HttpNotSuccessful>() {
        if 500 <= not_200.code && not_200.code < 600 || not_200.code == 429 {
            return true;
        }
    }

    false
}

/// Wrapper method for network call retry logic.
///
/// Retry counts provided by Config object `net.retry`. Config shell outputs
/// a warning on per retry.
///
/// Closure must return a `CargoResult`.
#[cfg(not(target_family = "wasm"))]
pub fn with_retry<T, F>(gctx: &GlobalContext, mut callback: F) -> CargoResult<T>
where
    F: FnMut() -> CargoResult<T>,
{
    let mut retry = Retry::new(gctx)?;
    loop {
        match retry.r#try(&mut callback) {
            RetryResult::Success(r) => return Ok(r),
            RetryResult::Err(e) => return Err(e),
            RetryResult::Retry(sleep) => {
                std::thread::sleep(std::time::Duration::from_millis(sleep))
            }
        }
    }
}
