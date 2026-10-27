//! The `zenwave` client every edge request goes through, so request
//! identity and the analytics opt-out live in exactly one place.
//!
//! Every request carries `User-Agent: stow-cli/<version> (<os>)` — the edge
//! parses it into the anonymous `cli_version`/`os_family` usage-stat
//! dimensions. When `STOW_NO_ANALYTICS=1` the client additionally sends
//! `x-stow-no-analytics: 1`, which suppresses every analytics write for that
//! request.

use std::convert::Infallible;

use zenwave::middleware::MiddlewareError;
use zenwave::{Client, Endpoint, Middleware, Request, Response, header};

use crate::config::StowConfig;

/// The environment variable that opts the CLI out of usage analytics.
pub const NO_ANALYTICS_ENV: &str = "STOW_NO_ANALYTICS";

/// Header the edge's consent extractor honours — sent as `1` when
/// [`NO_ANALYTICS_ENV`] is `1`.
const NO_ANALYTICS_HEADER: &str = "x-stow-no-analytics";

/// Header the edge's telemetry extractor reads into the `environment`
/// usage dimension — sent as `1` when `CI` is set in the environment.
const CI_HEADER: &str = "x-stow-ci";

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
    analytics_opted_out_in(|key| std::env::var(key).ok())
}

/// [`analytics_opted_out`] with the environment injected, so a caller —
/// or a test — answers `STOW_NO_ANALYTICS` from its own lookup instead
/// of the process's.
fn analytics_opted_out_in(env: impl Fn(&str) -> Option<String>) -> bool {
    env(NO_ANALYTICS_ENV).as_deref() == Some("1")
}

/// Per-request header middleware: the `stow-cli/<version> (<os>)` user
/// agent, and the opt-out header when `STOW_NO_ANALYTICS=1`. Infallible —
/// it only writes headers.
#[derive(Debug)]
struct EdgeHeaders {
    user_agent: String,
    no_analytics: bool,
    ci: bool,
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
            ci: std::env::var_os("CI").is_some(),
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
        if self.ci {
            headers.insert(CI_HEADER, "1".parse().expect("valid header value"));
        }
        next.respond(request)
            .await
            .map_err(MiddlewareError::Endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::{NO_ANALYTICS_ENV, analytics_opted_out_in};

    /// An environment lookup over `values` — the test answers
    /// `STOW_NO_ANALYTICS` itself rather than reading whatever the
    /// developer's shell exported (stow#800).
    fn env<'a>(values: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + use<'a> {
        move |key| {
            values
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn opt_out_reflects_the_environment_variable() {
        assert!(analytics_opted_out_in(env(&[(NO_ANALYTICS_ENV, "1")])));
        assert!(!analytics_opted_out_in(env(&[(NO_ANALYTICS_ENV, "0")])));
        assert!(!analytics_opted_out_in(env(&[])));
        assert!(!analytics_opted_out_in(env(&[("OTHER", "1")])));
    }
}
