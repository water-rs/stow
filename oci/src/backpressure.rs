//! Retrying the registry round-trips GHCR answers with backpressure.
//!
//! GHCR caps a namespace at 2000 requests per minute and answers everything
//! over the line with `429 TOOMANYREQUESTS`. A preheat wave is the shape that
//! reaches that cap: tens of build jobs publish concurrently, each pushing a
//! config blob, a layer and a bundle per artifact, so the limit is a property
//! of the fleet rather than of any one job. Without a retry the first job to
//! arrive one request over the line fails its whole publish stage — 142 of the
//! 206 failed scheduler tasks on 2026-09-21 were this one response — and every
//! artifact it compiled is thrown away.
//!
//! `oci-client` surfaces the refusal as `ServerError { code: 429, .. }` and
//! gives no access to the response headers, so the wait comes from the body
//! GHCR puts in the message (`retry-after: 6.565868ms`). That number is the
//! floor, not the answer: it describes when *this* request could have been
//! admitted, while the budget it names is shared with every other job in the
//! wave, so retrying at 6ms lands back on the cap. The wait is therefore the
//! larger of the server's number and a doubling local delay.

use std::time::Duration;

use oci_client::errors::OciDistributionError;

/// How many times a rate-limited round trip is re-attempted before the
/// publish fails. The delays double from [`BASE_DELAY`], so the last
/// attempt starts about 6 seconds after the first.
const MAX_RETRIES: u32 = 5;

/// First local delay after a `429`; doubles per attempt.
const BASE_DELAY: Duration = Duration::from_millis(200);

/// Run `operation` until it succeeds, fails for a reason other than the
/// registry's rate limit, or runs out of attempts.
///
/// `what` names the round trip in the retry log line.
///
/// # Errors
///
/// Returns the operation's own error. A rate-limit refusal is returned only
/// after [`MAX_RETRIES`] attempts have been refused.
pub async fn retrying_rate_limits<T, F, Fut>(
    what: &str,
    mut operation: F,
) -> Result<T, OciDistributionError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, OciDistributionError>>,
{
    let mut local_delay = BASE_DELAY;
    for attempt in 1..=MAX_RETRIES {
        let error = match operation().await {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };
        let Some(server_delay) = rate_limit_delay(&error) else {
            return Err(error);
        };
        let delay = server_delay.max(local_delay);
        tracing::warn!(
            what,
            attempt,
            delay_ms = delay.as_millis(),
            "registry refused the request as rate limited; retrying"
        );
        smol::Timer::after(delay).await;
        local_delay = local_delay.saturating_mul(2);
    }
    operation().await
}

/// The wait a rate-limit refusal asks for, or `None` when `error` is not a
/// rate-limit refusal.
fn rate_limit_delay(error: &OciDistributionError) -> Option<Duration> {
    let OciDistributionError::ServerError { code, message, .. } = error else {
        return None;
    };
    if *code != 429 {
        return None;
    }
    Some(parse_retry_after(message).unwrap_or(Duration::ZERO))
}

/// The `retry-after: <duration>` GHCR writes into the refusal body, as a
/// duration. `None` when the body carries no such value or spells it in a
/// unit we do not know.
fn parse_retry_after(message: &str) -> Option<Duration> {
    let rest = message.split("retry-after:").nth(1)?.trim_start();
    let digits = rest
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .map_or(rest, |end| &rest[..end]);
    let value: f64 = digits.parse().ok()?;
    let unit = rest[digits.len()..].trim_start();
    let seconds = if unit.starts_with("ns") {
        value / 1e9
    } else if unit.starts_with("us") || unit.starts_with("µs") {
        value / 1e6
    } else if unit.starts_with("ms") {
        value / 1e3
    } else if unit.starts_with('s') {
        value
    } else {
        return None;
    };
    Duration::try_from_secs_f64(seconds).ok()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use oci_client::errors::OciDistributionError;

    use super::{parse_retry_after, rate_limit_delay};

    /// The body GHCR actually returned when the 2026-09-21 preheat wave
    /// crossed the namespace's 2000/minute budget.
    const GHCR_429: &str = r#"{"errors":[{"code":"TOOMANYREQUESTS","message":"retry-after: 6.565868ms, allowed: 2000/minute"}]}"#;

    #[test]
    fn ghcr_spells_its_wait_in_milliseconds() {
        assert_eq!(
            parse_retry_after(GHCR_429),
            Some(Duration::from_secs_f64(0.006_565_868))
        );
    }

    #[test]
    fn whole_seconds_are_understood_too() {
        assert_eq!(
            parse_retry_after("retry-after: 30s"),
            Some(Duration::from_secs(30))
        );
    }

    /// A refusal with no parseable wait still counts as a rate limit — the
    /// local delay then decides how long to wait.
    #[test]
    fn a_rate_limit_without_a_wait_is_still_a_rate_limit() {
        let error = OciDistributionError::ServerError {
            code: 429,
            url: "https://ghcr.io/v2/water-rs/stow-cache/blobs/uploads/".to_owned(),
            message: "too many requests".to_owned(),
        };
        assert_eq!(rate_limit_delay(&error), Some(Duration::ZERO));
    }

    /// Everything else is a real failure and must not be retried: a 401 is
    /// not going to become a 200.
    #[test]
    fn other_server_errors_are_not_retried() {
        let error = OciDistributionError::ServerError {
            code: 401,
            url: "https://ghcr.io/v2/water-rs/stow-cache/blobs/uploads/".to_owned(),
            message: "unauthorized".to_owned(),
        };
        assert!(rate_limit_delay(&error).is_none());
    }
}
