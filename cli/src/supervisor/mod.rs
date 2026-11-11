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
pub mod invocation;
pub mod ipc;
pub mod os_bytes;
pub mod protocol;
pub mod server;

use std::path::Path;

use stow_types::error::Context;

use crate::local_socket::Endpoint;

/// Endpoint the facade connects to, as spelled in [`ENDPOINT_ENV`].
pub const ENDPOINT_ENV: &str = "STOW_SUPERVISOR_ENDPOINT";

/// Shared secret every frame carries, as spelled in [`TOKEN_ENV`].
///
/// A Unix socket is already protected by its owner-only mode; the token is
/// what makes the loopback listener Windows needs safe on a shared
/// machine.
pub const TOKEN_ENV: &str = "STOW_SUPERVISOR_TOKEN";

/// The supervising build's binary identity, as spelled in [`BINARY_ENV`].
///
/// A facade checks it against its own binary's identity before a frame is
/// sent: a wrapper whose shim resolves to a different build of stow —
/// the binary at the path replaced mid-build — must refuse the
/// supervisor rather than speak a protocol its shape may differ from
/// (stow#645).
pub const BINARY_ENV: &str = "STOW_SUPERVISOR_BINARY";

/// What tells one build of the stow binary from another at the same path.
///
/// A Unix shim is a symlink, so replacing the binary it resolves to
/// mid-build hands the next facade cargo spawns to the new binary while
/// the running build's supervisor stays the old one — the pair this
/// compares apart. Length and modification time are what `fs::metadata`
/// reports: a hard-linked wrapper shares them by construction, and a
/// copied one is stamped with them when it is placed (stow#645).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryIdentity {
    len: u64,
    modified_nanos: u128,
}

impl BinaryIdentity {
    /// The identity of the file `executable` names — a symlink's target,
    /// since `fs::metadata` follows it.
    ///
    /// # Errors
    ///
    /// Whatever `fs::metadata` fails with, or a modification time before
    /// the Unix epoch.
    pub fn of(executable: &Path) -> stow_types::error::Result<Self> {
        let metadata = std::fs::metadata(executable)
            .wrap_err_with(|| format!("stat {}", executable.display()))?;
        let modified = metadata
            .modified()
            .wrap_err_with(|| format!("read modification time of {}", executable.display()))?
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| {
                stow_types::stow_error!(
                    "modification time of {} predates the Unix epoch: {error}",
                    executable.display()
                )
            })?;
        Ok(Self {
            len: metadata.len(),
            modified_nanos: modified.as_nanos(),
        })
    }

    /// The `STOW_SUPERVISOR_BINARY` spelling: `<len>:<modified-nanos>`.
    #[must_use]
    pub fn encode(&self) -> String {
        format!("{}:{}", self.len, self.modified_nanos)
    }

    /// Parse the `STOW_SUPERVISOR_BINARY` spelling.
    ///
    /// # Errors
    ///
    /// A value that is not `<len>:<modified-nanos>`.
    pub fn parse(raw: &str) -> stow_types::error::Result<Self> {
        let (len, nanos) = raw.split_once(':').ok_or_else(|| {
            stow_types::stow_error!("{BINARY_ENV} value {raw:?} is not <len>:<modified-nanos>")
        })?;
        let len = len
            .parse::<u64>()
            .map_err(|error| stow_types::stow_error!("{BINARY_ENV} length {len:?}: {error}"))?;
        let modified_nanos = nanos.parse::<u128>().map_err(|error| {
            stow_types::stow_error!("{BINARY_ENV} modified time {nanos:?}: {error}")
        })?;
        Ok(Self {
            len,
            modified_nanos,
        })
    }
}

/// Refuse a supervisor another build of stow owns — the check
/// [`from_env`] runs once it knows there is one, before a facade sends or
/// reads a frame. `exported` is the raw `STOW_SUPERVISOR_BINARY` the
/// parent wired: it must be present, parse, and equal `own`.
fn same_build(
    own_executable: &Path,
    own: &BinaryIdentity,
    exported: Option<&str>,
) -> stow_types::error::Result<()> {
    let exported = BinaryIdentity::parse(exported.ok_or_else(|| {
        stow_types::stow_error!("{ENDPOINT_ENV} is set but {BINARY_ENV} is not")
    })?)?;
    if exported != *own {
        return Err(stow_types::stow_error!(
            "this wrapper is {}, but cargo was started by a different build of stow at the same path: the stow binary was replaced while the build was running. Run the build again.",
            own_executable.display()
        ));
    }
    Ok(())
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
/// An endpoint that does not parse, an endpoint without its token, or a
/// supervisor that belongs to a different build of the stow binary: each
/// means the environment says there is a supervisor and the facade must
/// not use it, which fails the build rather than silently compiling
/// without the cache.
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
    // The shim resolves to whatever binary sits at its path now — the
    // stow a build was started under is not necessarily it. Check before
    // anything is sent or read: a different build's supervisor speaks a
    // protocol this process may frame differently (stow#645).
    let own_executable = std::env::current_exe()
        .map_err(|error| format!("resolve this wrapper's own executable: {error}"))?;
    let own = BinaryIdentity::of(&own_executable).map_err(|error| error.to_string())?;
    same_build(
        &own_executable,
        &own,
        std::env::var(BINARY_ENV).ok().as_deref(),
    )
    .map_err(|error| error.to_string())?;
    Ok(Some((endpoint, token)))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{BINARY_ENV, BinaryIdentity, same_build};

    fn identity(len: u64, nanos: u128) -> BinaryIdentity {
        BinaryIdentity {
            len,
            modified_nanos: nanos,
        }
    }

    #[test]
    fn a_binary_identity_round_trips() {
        let identity = identity(123_456, 987_654_321_000);
        assert_eq!(identity.encode(), "123456:987654321000");
        assert_eq!(
            BinaryIdentity::parse(&identity.encode()).expect("parse"),
            identity
        );
    }

    #[test]
    fn the_wrapper_accepts_its_own_build() {
        assert!(same_build(Path::new("/x/stow-cli"), &identity(1, 2), Some("1:2")).is_ok());
    }

    #[test]
    fn the_wrapper_refuses_another_builds_supervisor() {
        // A different length and a different modification time are each
        // another build — both carry the rebuild instruction.
        for exported in ["2:2", "1:3"] {
            let error = same_build(Path::new("/x/stow-cli"), &identity(1, 2), Some(exported))
                .expect_err("a different build must be refused");
            assert!(
                error
                    .to_string()
                    .contains("replaced while the build was running"),
                "{error}"
            );
        }
    }

    #[test]
    fn the_wrapper_refuses_a_missing_binary_identity() {
        for exported in [None, Some("not-an-identity")] {
            let error = same_build(Path::new("/x/stow-cli"), &identity(1, 2), exported)
                .expect_err("an unusable STOW_SUPERVISOR_BINARY must be refused");
            assert!(error.to_string().contains(BINARY_ENV), "{error}");
        }
    }

    /// `fs::metadata` follows the shim's symlink, so a wrapper stats the
    /// binary it resolves to — exactly the file the supervisor's exported
    /// identity was taken from (stow#645).
    #[cfg(unix)]
    #[test]
    fn a_shim_symlink_stats_the_binary_it_resolves_to() {
        let base = std::env::temp_dir().join(format!("stow-shim-id-{}", std::process::id()));
        std::fs::create_dir_all(&base).expect("create the test dir");
        let runtime = base.join("runtime");
        let capture = base.join("capture");
        std::fs::write(&runtime, b"runtime").expect("write the runtime");
        std::fs::write(&capture, b"capture").expect("write the capture");
        let paths = stow_shim::materialize_wrapper_shims(&base, &runtime, &capture)
            .expect("materialize the shims");
        assert_eq!(
            BinaryIdentity::of(&paths.rustc_wrapper).expect("shim identity"),
            BinaryIdentity::of(&runtime).expect("runtime identity"),
        );
        std::fs::remove_dir_all(&base).expect("remove the test dir");
    }
}
