//! The HTTP answers every stow client treats as transient.
//!
//! A long run (a preheat wave, an index export, a CLI fetch on a flaky
//! link) issues enough requests that one of these lands somewhere in it,
//! and the request that met it is worth another attempt.

/// Statuses worth a retry: request timeout, rate limiting, and every
/// server-side failure.
#[must_use]
pub const fn is_transient_status(status: u16) -> bool {
    status == 408 || status == 429 || status >= 500
}

#[cfg(test)]
mod tests {
    use super::is_transient_status;

    #[test]
    fn timeouts_rate_limits_and_server_errors_are_transient() {
        for status in [408, 429, 500, 502, 503, 504] {
            assert!(is_transient_status(status), "{status}");
        }
        for status in [200, 301, 400, 401, 403, 404, 409, 422] {
            assert!(!is_transient_status(status), "{status}");
        }
    }
}
