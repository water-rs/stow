//! Where a facade reaches its supervisor: the endpoint env pair every
//! supervised build sets for its compiler wrappers.

use std::path::PathBuf;

/// Endpoint the facade connects to, as spelled in [`ENDPOINT_ENV`].
pub const ENDPOINT_ENV: &str = "STOW_SUPERVISOR_ENDPOINT";

/// Shared secret every frame carries, as spelled in [`TOKEN_ENV`].
///
/// A Unix socket is already protected by its owner-only mode; the token is
/// what makes the loopback listener Windows needs safe on a shared
/// machine.
pub const TOKEN_ENV: &str = "STOW_SUPERVISOR_TOKEN";

/// Where a facade reaches its supervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// A Unix domain socket at this path, created with mode 0600.
    #[cfg(unix)]
    Unix(PathBuf),
    /// A loopback TCP listener on this port — the Windows transport.
    Loopback(u16),
}

impl Endpoint {
    /// The `STOW_SUPERVISOR_ENDPOINT` spelling of this endpoint.
    #[must_use]
    pub fn encode(&self) -> String {
        match self {
            #[cfg(unix)]
            Self::Unix(path) => format!("unix:{}", path.display()),
            Self::Loopback(port) => format!("tcp:{port}"),
        }
    }

    /// Parse the `STOW_SUPERVISOR_ENDPOINT` spelling.
    ///
    /// # Errors
    ///
    /// An unknown scheme, or a `tcp:` endpoint whose port is not a number.
    pub fn parse(raw: &str) -> Result<Self, String> {
        if let Some(port) = raw.strip_prefix("tcp:") {
            return port
                .parse::<u16>()
                .map(Self::Loopback)
                .map_err(|error| format!("supervisor endpoint port {port:?}: {error}"));
        }
        #[cfg(unix)]
        if let Some(path) = raw.strip_prefix("unix:") {
            return Ok(Self::Unix(PathBuf::from(path)));
        }
        Err(format!("unrecognised supervisor endpoint {raw:?}"))
    }
}

/// The endpoint and token this process was handed, when it is running
/// under a supervisor.
///
/// `None` means there is no supervisor to talk to — the wrapper is running
/// under a plain `cargo build` through the `RUSTC_WRAPPER` that `stow
/// setup` writes, which is a supported configuration, not a failure.
///
/// # Errors
///
/// An endpoint that does not parse, or an endpoint without its token: both
/// mean the environment says there is a supervisor and the facade cannot
/// reach it, which fails the build rather than silently compiling without
/// the cache.
pub fn from_env() -> Result<Option<(Endpoint, String)>, String> {
    let Some(raw) = std::env::var_os(ENDPOINT_ENV) else {
        return Ok(None);
    };
    let raw = raw
        .to_str()
        .ok_or_else(|| format!("{ENDPOINT_ENV} is not valid Unicode"))?;
    if raw.is_empty() {
        return Ok(None);
    }
    let endpoint = Endpoint::parse(raw)?;
    let token = std::env::var(TOKEN_ENV)
        .map_err(|_| format!("{ENDPOINT_ENV} is set but {TOKEN_ENV} is not"))?;
    Ok(Some((endpoint, token)))
}

#[cfg(test)]
mod tests {
    use super::Endpoint;

    #[test]
    fn a_loopback_endpoint_round_trips() {
        let endpoint = Endpoint::Loopback(54321);
        assert_eq!(endpoint.encode(), "tcp:54321");
        assert_eq!(Endpoint::parse("tcp:54321").expect("parse"), endpoint);
    }

    #[cfg(unix)]
    #[test]
    fn a_unix_endpoint_round_trips() {
        let endpoint = Endpoint::Unix(std::path::PathBuf::from("/tmp/stow-build/sock"));
        assert_eq!(endpoint.encode(), "unix:/tmp/stow-build/sock");
        assert_eq!(
            Endpoint::parse("unix:/tmp/stow-build/sock").expect("parse"),
            endpoint
        );
    }

    #[test]
    fn an_unknown_scheme_is_refused() {
        let error = Endpoint::parse("http://localhost:1").expect_err("unknown scheme");
        assert!(error.contains("unrecognised"), "{error}");
    }
}
