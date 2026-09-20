//! Bounded retries with exponential backoff for transient outbound failures.

use std::fmt::Display;
use std::future::Future;
use std::time::Duration;

/// Run `operation` until it succeeds, `max_attempts` is reached, or
/// `should_retry` rejects the error.
///
/// Every failed attempt is logged with its attempt number and the error. A
/// retryable failure sleeps `initial_delay * 2^(attempt - 1)` before the
/// next attempt, so `initial_delay = 1s` yields 1s, 2s, 4s, 8s, … The final
/// error is returned to the caller, which owns wrapping it in the context a
/// generic loop cannot know (the URL, the operation subject).
pub async fn retry_with_backoff<F, Fut, T, E>(
    operation: &'static str,
    max_attempts: u32,
    initial_delay: Duration,
    mut attempt_operation: F,
    should_retry: impl Fn(&E) -> bool,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: Display,
{
    let mut attempt = 0_u32;
    loop {
        attempt += 1;
        let error = match attempt_operation().await {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };
        if attempt >= max_attempts || !should_retry(&error) {
            tracing::warn!(
                operation,
                attempt,
                max_attempts,
                error = %error,
                "attempt failed; not retrying"
            );
            return Err(error);
        }
        let multiplier = 1_u32.checked_shl(attempt - 1).unwrap_or(u32::MAX);
        let delay = initial_delay.saturating_mul(multiplier);
        tracing::warn!(
            operation,
            attempt,
            max_attempts,
            retry_in_ms = delay.as_millis(),
            error = %error,
            "attempt failed; retrying"
        );
        smol::Timer::after(delay).await;
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::time::Duration;

    use super::retry_with_backoff;

    #[test]
    fn retries_retryable_failures_until_success() {
        smol::block_on(async {
            let attempts = Cell::new(0_u32);
            let result = retry_with_backoff(
                "test",
                5,
                Duration::ZERO,
                || {
                    let attempt = attempts.get() + 1;
                    attempts.set(attempt);
                    async move {
                        if attempt < 3 {
                            Err("transient")
                        } else {
                            Ok(42)
                        }
                    }
                },
                |_| true,
            )
            .await;
            assert_eq!(result, Ok(42));
            assert_eq!(attempts.get(), 3);
        });
    }

    #[test]
    fn does_not_retry_when_decision_rejects_error() {
        smol::block_on(async {
            let attempts = Cell::new(0_u32);
            let result: Result<(), &'static str> = retry_with_backoff(
                "test",
                5,
                Duration::ZERO,
                || {
                    attempts.set(attempts.get() + 1);
                    async { Err("permanent") }
                },
                |_| false,
            )
            .await;
            assert_eq!(result, Err("permanent"));
            assert_eq!(attempts.get(), 1);
        });
    }

    #[test]
    fn gives_up_after_max_attempts() {
        smol::block_on(async {
            let attempts = Cell::new(0_u32);
            let result: Result<(), u32> = retry_with_backoff(
                "test",
                3,
                Duration::ZERO,
                || {
                    let attempt = attempts.get() + 1;
                    attempts.set(attempt);
                    async move { Err(attempt) }
                },
                |_| true,
            )
            .await;
            assert_eq!(result, Err(3));
            assert_eq!(attempts.get(), 3);
        });
    }
}
