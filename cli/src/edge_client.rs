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

use crate::config::{StowConfig, Switches};

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
/// every request. Refuses a cache mode that does not reach the network.
pub fn client(config: &StowConfig) -> stow_types::error::Result<impl Client> {
    config.require_network("an edge request")?;
    Ok(zenwave::client()
        .timeout(config.request_timeout)
        .with(EdgeHeaders::new(&config.switches)))
}

/// Per-request header middleware: the `stow-cli/<version> (<os>)` user
/// agent, and the opt-out header when the config's switches say
/// `STOW_NO_ANALYTICS=1`. Infallible — it only writes headers.
#[derive(Debug)]
struct EdgeHeaders {
    user_agent: String,
    no_analytics: bool,
    ci: bool,
}

impl EdgeHeaders {
    fn new(switches: &Switches) -> Self {
        Self {
            user_agent: format!(
                "stow-cli/{} ({})",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS
            ),
            no_analytics: switches.no_analytics,
            ci: switches.ci,
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
    use super::NO_ANALYTICS_ENV;
    use crate::config::Switches;

    /// The switches of an environment of exactly `values` — the test
    /// answers `STOW_NO_ANALYTICS` itself rather than reading whatever the
    /// developer's shell exported (stow#800).
    fn switches(values: &[(&str, &str)]) -> Switches {
        Switches::of_environ(
            &values
                .iter()
                .map(|(name, value)| ((*name).into(), (*value).into()))
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn opt_out_reflects_the_environment_variable() {
        assert!(switches(&[(NO_ANALYTICS_ENV, "1")]).no_analytics);
        assert!(!switches(&[(NO_ANALYTICS_ENV, "0")]).no_analytics);
        assert!(!switches(&[]).no_analytics);
        assert!(!switches(&[("OTHER", "1")]).no_analytics);
    }

    #[test]
    fn ci_and_the_identity_trace_come_from_the_given_environment() {
        let switches = switches(&[("CI", ""), ("STOW_IDENTITY_TRACE", "/trace")]);
        assert!(switches.ci);
        assert_eq!(
            switches.identity_trace.as_deref(),
            Some(std::path::Path::new("/trace"))
        );
        assert!(!self::switches(&[]).ci);
    }
}
