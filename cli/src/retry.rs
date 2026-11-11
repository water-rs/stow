//! The one retry loop every CLI download shares: attempts spaced by the
//! [`stow_types::transient::Backoff`] budget, each classified by its
//! caller as done, worth another try, or final.

use std::future::Future;
use std::time::Duration;

/// What one attempt produced, classified by the caller: the value, a
/// failure another attempt can change — with the `Retry-After` hint the
/// answer carried — or a failure no retry changes.
pub enum Attempt<T, E> {
    Done(T),
    Transient {
        error: E,
        retry_after: Option<Duration>,
    },
    Final(E),
}

/// Run `attempt` until it is done or final, or until the shared backoff
/// budget is spent — the last transient error is then what the caller
/// gets. `what` names the request in the per-attempt log line.
pub async fn with_backoff<T, E, Fut>(what: &str, mut attempt: impl FnMut() -> Fut) -> Result<T, E>
where
    E: std::fmt::Display,
    Fut: Future<Output = Attempt<T, E>>,
{
    let mut backoff = stow_types::transient::Backoff::new();
    loop {
        let wait = match attempt().await {
            Attempt::Done(value) => return Ok(value),
            Attempt::Transient { error, retry_after } => {
                let Some(wait) = backoff.next_wait(retry_after) else {
                    return Err(error);
                };
                // Per attempt: the exhausted retry's error is what the
                // caller surfaces (stow#633).
                tracing::debug!(what, %error, "download failed; retrying");
                wait
            }
            Attempt::Final(error) => return Err(error),
        };
        tokio::time::sleep(wait).await;
    }
}
