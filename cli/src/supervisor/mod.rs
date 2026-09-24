//! The per-build supervisor, and the facade that talks to it.
//!
//! One rustc invocation used to be one `stow` process that loaded the
//! config, opened the state database, read the verified index slice and
//! built its own HTTP transport. The transport is the expensive part:
//! zenwave pools connections and shares one QUIC endpoint per *process*,
//! so a build of 39 units opened up to 39 connections and HTTP/3's
//! multiplexing had nothing to multiplex over.
//!
//! So the wrapper is a facade. It parses its command line, asks the
//! supervisor what to do with the invocation, and either exits or execs
//! the real rustc. Everything else — config, index, local cache, network,
//! statistics, admissions — belongs to the supervisor, which lives for the
//! whole build and holds one connection to the edge.
//!
//! The supervisor is `stow check|build|test` itself: that process already
//! spans the build, so supervision costs no extra process.
//!
//! The facade half — endpoint env, the wire protocol, and the synchronous
//! connection — lives in `stow_facade`, the crate the tiny `stow-facade`
//! binary the wrapper shims exec is built on; this module re-exports it so
//! the driver side keeps one spelling.

pub mod client;
pub mod server;

pub mod protocol {
    pub use stow_facade::protocol::*;
}

/// Endpoint the facade connects to, as spelled in [`ENDPOINT_ENV`].
pub const ENDPOINT_ENV: &str = stow_facade::endpoint::ENDPOINT_ENV;

/// Shared secret every frame carries, as spelled in [`TOKEN_ENV`].
pub const TOKEN_ENV: &str = stow_facade::endpoint::TOKEN_ENV;

pub use stow_facade::endpoint::{Endpoint, from_env};

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
