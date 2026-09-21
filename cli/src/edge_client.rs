//! The `zenwave` client every edge request goes through, so request
//! identity and the analytics opt-out live in exactly one place.
//!
//! Every request carries `User-Agent: stow-cli/<version> (<os>)` — the edge
//! parses it into the anonymous `cli_version`/`os_family` usage-stat
//! dimensions. When `STOW_NO_ANALYTICS=1` the client additionally sends
//! `x-stow-no-analytics: 1`, which suppresses every analytics write and the
//! install hash for that request.

use std::convert::Infallible;

use zenwave::middleware::MiddlewareError;
use zenwave::{Client, Endpoint, Middleware, Request, Response, header};

use crate::config::StowConfig;

/// The environment variable that opts the CLI out of usage analytics.
pub const NO_ANALYTICS_ENV: &str = "STOW_NO_ANALYTICS";

/// Header the edge's consent extractor honours — sent as `1` when
/// [`NO_ANALYTICS_ENV`] is `1`.
const NO_ANALYTICS_HEADER: &str = "x-stow-no-analytics";

/// Build the edge HTTP client: configured request timeout plus the
/// [`EdgeHeaders`] middleware that stamps identity and opt-out headers on
/// every request.
pub fn client(config: &StowConfig) -> impl Client {
    zenwave::client()
        .timeout(config.request_timeout)
        .with(EdgeHeaders::new())
}

/// Whether `STOW_NO_ANALYTICS` is set to `1`.
#[must_use]
pub fn analytics_opted_out() -> bool {
    std::env::var(NO_ANALYTICS_ENV).ok().as_deref() == Some("1")
}

/// Per-request header middleware: the `stow-cli/<version> (<os>)` user
/// agent, and the opt-out header when `STOW_NO_ANALYTICS=1`. Infallible —
/// it only writes headers.
#[derive(Debug)]
struct EdgeHeaders {
    user_agent: String,
    no_analytics: bool,
}

impl EdgeHeaders {
    fn new() -> Self {
        Self {
            user_agent: format!(
                "stow-cli/{} ({})",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS
            ),
            no_analytics: analytics_opted_out(),
        }
    }
}

impl Middleware for EdgeHeaders {
    type Error = Infallible;

    async fn handle<E: Endpoint>(
        &mut self,
        request: &mut Request,
        mut next: E,
    ) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
        let headers = request.headers_mut();
        headers.insert(
            header::USER_AGENT,
            self.user_agent
                .parse()
                .expect("the stow-cli user agent contains no invalid header bytes"),
        );
        if self.no_analytics {
            headers.insert(
                NO_ANALYTICS_HEADER,
                "1".parse().expect("valid header value"),
            );
        }
        next.respond(request)
            .await
            .map_err(MiddlewareError::Endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::analytics_opted_out;

    #[test]
    fn opt_out_reflects_the_environment_variable() {
        let expected = std::env::var("STOW_NO_ANALYTICS").ok().as_deref() == Some("1");
        assert_eq!(analytics_opted_out(), expected);
    }
}
