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

pub mod client;
pub mod os_bytes;
pub mod protocol;
pub mod server;

#[cfg(unix)]
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

/// The socket's file name inside its directory.
#[cfg(unix)]
const SOCKET_NAME: &str = "sock";

/// A listener [`bind`] produced: the Unix socket with the temp
/// directory that owns it, or the loopback TCP listener with its port.
pub enum Listener {
    /// The socket inside `dir` — the directory's removal takes the
    /// socket with it.
    #[cfg(unix)]
    Unix {
        /// The bound socket.
        listener: tokio::net::UnixListener,
        /// The directory holding it.
        dir: tempfile::TempDir,
    },
    /// A loopback TCP listener — the transport every non-Unix platform
    /// binds.
    #[cfg(not(unix))]
    Loopback {
        /// The bound listener.
        listener: tokio::net::TcpListener,
        /// The kernel-picked port it listens on.
        port: u16,
    },
}

impl Listener {
    /// The endpoint that reaches this listener.
    #[must_use]
    pub fn endpoint(&self) -> Endpoint {
        match self {
            #[cfg(unix)]
            Self::Unix { dir, .. } => Endpoint::Unix(dir.path().join(SOCKET_NAME)),
            #[cfg(not(unix))]
            Self::Loopback { port, .. } => Endpoint::Loopback(*port),
        }
    }

    /// Accept one connection.
    ///
    /// # Errors
    ///
    /// The listener's accept error.
    pub async fn accept(&self) -> std::io::Result<Stream> {
        match self {
            #[cfg(unix)]
            Self::Unix { listener, .. } => listener
                .accept()
                .await
                .map(|(stream, _)| Stream::Unix(stream)),
            #[cfg(not(unix))]
            Self::Loopback { listener, .. } => listener
                .accept()
                .await
                .map(|(stream, _)| Stream::Loopback(stream)),
        }
    }
}

/// The connected half of the [`Endpoint`] transport — what [`connect`]
/// hands a client of a listener [`bind`] produced.
pub enum Stream {
    /// A connected Unix socket.
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    /// A connected loopback TCP stream.
    Loopback(tokio::net::TcpStream),
}

/// Bind a listener: on Unix a socket inside a fresh `dir_prefix` temp directory,
/// restricted to the owner; elsewhere a loopback TCP listener on a
/// kernel-picked port. `dir_prefix` spells `stow-<what>-`, and `<what>`
/// is the subject the error text names.
///
/// # Errors
///
/// A socket directory that cannot be created, a socket that cannot be
/// bound or restricted, a loopback listener that cannot be bound or
/// adopted.
pub fn bind(dir_prefix: &str) -> Result<Listener, String> {
    let subject = dir_prefix
        .strip_prefix("stow-")
        .and_then(|rest| rest.strip_suffix('-'))
        .unwrap_or(dir_prefix);
    #[cfg(unix)]
    {
        let socket_dir = tempfile::Builder::new()
            .prefix(dir_prefix)
            .tempdir()
            .map_err(|error| format!("create {subject} socket directory: {error}"))?;
        let path = socket_dir.path().join(SOCKET_NAME);
        let listener = tokio::net::UnixListener::bind(&path)
            .map_err(|error| format!("bind {subject} socket {}: {error}", path.display()))?;
        restrict_socket(&path, subject)?;
        Ok(Listener::Unix {
            listener,
            dir: socket_dir,
        })
    }
    #[cfg(not(unix))]
    {
        // Bound through the std listener so binding needs no runtime of
        // its own: the supervisor is started from ordinary code, and the
        // accept loop is what belongs on the runtime.
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .map_err(|error| format!("bind {subject} loopback listener: {error}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("set the {subject} listener non-blocking: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| format!("read {subject} listener port: {error}"))?
            .port();
        let listener = tokio::net::TcpListener::from_std(listener)
            .map_err(|error| format!("adopt the {subject} listener: {error}"))?;
        Ok(Listener::Loopback { listener, port })
    }
}

#[cfg(unix)]
fn restrict_socket(path: &std::path::Path, subject: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("restrict {subject} socket {}: {error}", path.display()))
}

/// Connect to `endpoint`.
///
/// # Errors
///
/// Any connection failure.
pub async fn connect(endpoint: &Endpoint) -> Result<Stream, String> {
    match endpoint {
        #[cfg(unix)]
        Endpoint::Unix(path) => tokio::net::UnixStream::connect(path)
            .await
            .map(Stream::Unix)
            .map_err(|error| format!("connect to supervisor at {}: {error}", path.display())),
        Endpoint::Loopback(port) => tokio::net::TcpStream::connect(("127.0.0.1", *port))
            .await
            .map(Stream::Loopback)
            .map_err(|error| format!("connect to supervisor on port {port}: {error}")),
    }
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
