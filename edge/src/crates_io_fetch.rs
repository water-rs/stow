//! crates.io fetch retry and status classification — the branching half of
//! [`crate::crates_io`]'s GET loop, kept host-side so the branches that used
//! to drop a response body unread stay unit-testable. [`decide`] takes a
//! [`GuardedResponse`]: every non-2xx arm returns without reading the body
//! and the guard cancels it on drop — only the 2xx arm consumes.

use crate::errors::ResolverError;
use crate::fetch_guard::{FetchedResponse, GuardedResponse};

/// What one fetch attempt produced: a usable body, a failure worth
/// retrying (with the delay to wait first), or a final answer.
pub enum FetchOutcome {
    /// The response body, read to completion.
    Body(String),
    /// A transient failure worth retrying after `delay_ms`.
    Retryable {
        /// The error to surface if the retries run out.
        error: ResolverError,
        /// Milliseconds to wait before the next attempt.
        delay_ms: u64,
    },
    /// A final answer — success shape or failure — no retry.
    Fatal(ResolverError),
}

const RETRY_BASE_DELAY_MS: u64 = 250;
const RETRY_MAX_DELAY_MS: u64 = 8_000;

/// Classify one fetched response into the retry loop's next step. Status
/// checks inspect `response` through the guard; the 2xx arm hands the
/// body to `text()`, every other arm drops the guard and cancels the
/// unread body — nothing here may leave a body open.
pub async fn decide<B: FetchedResponse>(
    response: GuardedResponse<B>,
    url: &str,
    missing: &(impl Fn() -> ResolverError + Sync),
    attempt: u32,
) -> FetchOutcome {
    let status = response.get_ref().status_code();
    if status == 404 {
        return FetchOutcome::Fatal(missing());
    }
    if !(200..300).contains(&status) {
        let error = ResolverError::CratesIo(format!("crates.io {url} returned HTTP {status}"));
        if is_retryable_status(status) {
            return FetchOutcome::Retryable {
                error,
                delay_ms: retry_delay(attempt, retry_after_ms(response.get_ref())),
            };
        }
        return FetchOutcome::Fatal(error);
    }
    match response.into_inner().text().await {
        Ok(body) => FetchOutcome::Body(body),
        Err(error) => FetchOutcome::Retryable {
            error: ResolverError::CratesIo(format!("read crates.io {url}: {error}")),
            delay_ms: retry_delay(attempt, None),
        },
    }
}

/// Statuses worth a retry: rate limiting, gateway timeouts, and every
/// server-side failure the index CDN might transiently produce.
const fn is_retryable_status(status: u16) -> bool {
    status == 408 || status == 429 || status >= 500
}

/// `Retry-After` as milliseconds; only the delta-seconds form is honored.
fn retry_after_ms(response: &impl FetchedResponse) -> Option<u64> {
    response
        .header("retry-after")
        .and_then(|value| value.parse::<u64>().ok())
        .map(|seconds| seconds.saturating_mul(1000))
}

/// Backoff for retry number `attempt` (0-based): 250 ms doubling to an
/// 8 s ceiling, lengthened — never shortened — by a `Retry-After` hint.
pub fn retry_delay(attempt: u32, retry_after_ms: Option<u64>) -> u64 {
    let backoff = RETRY_BASE_DELAY_MS
        .saturating_mul(1u64.checked_shl(attempt).unwrap_or(u64::MAX))
        .min(RETRY_MAX_DELAY_MS);
    retry_after_ms.map_or(backoff, |hint| hint.max(backoff).min(RETRY_MAX_DELAY_MS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch_guard::stub::StubResponse;

    fn missing() -> ResolverError {
        ResolverError::CrateNotPublished {
            crate_name: "unpublished".to_owned(),
        }
    }

    /// A 404 answers fatally and the body is cancelled, not left open —
    /// the branch that stalled a connection slot per missing crate.
    #[tokio::test]
    async fn decide_404_cancels_the_body() {
        let (response, cancelled, _) = StubResponse::new(404);
        let outcome = decide(
            GuardedResponse::new(response),
            "https://index/b/at/bat",
            &missing,
            0,
        )
        .await;
        assert!(matches!(
            outcome,
            FetchOutcome::Fatal(ResolverError::CrateNotPublished { .. })
        ));
        assert!(
            cancelled.load(std::sync::atomic::Ordering::SeqCst),
            "404 must cancel the unread body"
        );
    }

    /// A retryable status cancels the body the same way — retries used
    /// to stack one stalled response per attempt.
    #[tokio::test]
    async fn decide_429_cancels_the_body() {
        let (response, cancelled, _) = StubResponse::new(429);
        let outcome = decide(
            GuardedResponse::new(response),
            "https://index/b/at/bat",
            &missing,
            0,
        )
        .await;
        assert!(matches!(outcome, FetchOutcome::Retryable { .. }));
        assert!(
            cancelled.load(std::sync::atomic::Ordering::SeqCst),
            "retryable status must cancel the unread body"
        );
    }

    /// A non-retryable non-2xx fails fatally and still frees the slot.
    #[tokio::test]
    async fn decide_5xx_is_retryable_and_cancelled() {
        let (response, cancelled, _) = StubResponse::new(503);
        let outcome = decide(
            GuardedResponse::new(response),
            "https://index/b/at/bat",
            &missing,
            3,
        )
        .await;
        assert!(matches!(outcome, FetchOutcome::Retryable { .. }));
        assert!(cancelled.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// The 2xx arm consumes the body — the only terminal state a guard
    /// never has to manufacture.
    #[tokio::test]
    async fn decide_200_reads_the_body() {
        let (response, cancelled, consumed) = StubResponse::new(200);
        let outcome = decide(
            GuardedResponse::new(response),
            "https://index/b/at/bat",
            &missing,
            0,
        )
        .await;
        assert!(matches!(outcome, FetchOutcome::Body(_)));
        assert!(
            consumed.load(std::sync::atomic::Ordering::SeqCst),
            "2xx must read the body"
        );
        assert!(
            !cancelled.load(std::sync::atomic::Ordering::SeqCst),
            "consumed bodies must not be cancelled"
        );
    }
}
