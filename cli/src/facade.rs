//! The rustc facade's uncovered-unit fast path.
//!
//! `stow build` writes the serve map before cargo starts, so the one
//! question a rustc invocation can ask — could anything serve this unit
//! — already has its answer when the facade starts. The map lives in a
//! per-build file named by `STOW_SERVE_MAP_FILE`: the `(crate, version)`
//! pairs this build's cached index slice and local artifacts cover,
//! plus the crate names a semver-compatible upgrade could serve when
//! semantic fallback is on. The driver atomically replaces it once the
//! fresh index slice and the exact dependency graph land — work that
//! now runs while cargo builds rather than before it — so units that
//! compile after the upgrade see the richer map (stow#347). A unit the
//! map does not cover compiles: the facade marks it locally built, runs
//! rustc, and reports the outcome. The mark still lands before rustc
//! starts, so the ordering cargo's dependency pipeline relies on is
//! intact — what is gone is the plan round trip the decision used to
//! cost.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};

use stow_types::error::Context;
use stow_types::public_cache::{canonical_crate_name, detect_registry_crate_version};
use stow_types::rustc::ParsedRustcArgs;

use crate::rustc_args;
use crate::supervisor::protocol::{Observed, Request};
use crate::supervisor::{self, Endpoint};

/// The `stow build` wiring carrying the serve-map file path to every
/// facade.
pub const STOW_SERVE_MAP_FILE_ENV: &str = "STOW_SERVE_MAP_FILE";

/// The version slot a wildcard entry holds instead of one version.
const WILDCARD: &str = "*";

/// The bound on a facade's wait for a pending serve map: long enough for
/// the driver's fresh slice fetch to land, short enough that a stuck
/// fetch cannot stall the build's unit queue past it (stow#347).
const SERVE_MAP_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The serve decision, distilled to what a facade can look up before its
/// runtime exists: which `(crate, version)` pairs this build could serve,
/// per side of the unit graph, plus `("name", "*")` entries meaning any
/// semver-compatible upgrade of that crate could serve.
///
/// Covering a unit that cannot actually serve only costs a plan round
/// trip; the map errs on that side. What it must never do is fail to
/// cover a unit that could serve — the facade that misses the map would
/// compile it.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServeMap {
    /// Units invoked with `--target`: the consumer side of the graph.
    pub target: Vec<(String, String)>,
    /// Units invoked without one — host dependencies, and every unit on a
    /// native build.
    pub host: Vec<(String, String)>,
    /// The map may still grow: the driver wrote it from its cached slices
    /// alone because the fresh index fetch could not finish before cargo
    /// started (stow#347). A facade the map cannot cover waits on the
    /// readiness gate this flag announces rather than compiling a unit
    /// the fetch may be about to cover; the driver's full analysis lands
    /// by rewriting this file with `pending` cleared.
    #[serde(default)]
    pub pending: bool,
}

impl ServeMap {
    /// The map this build's driver wrote. `None` means the environment
    /// carries no map path — this invocation is not under a supervised
    /// build — so the facade takes the plan path like it always has. A
    /// path that names no file yet reads as an empty map: nothing has
    /// been proven servable, so every unit compiles — the same answer a
    /// completed map gives on an all-miss build.
    ///
    /// # Errors
    ///
    /// A present-but-unreadable or malformed file is a wiring bug and
    /// fails loudly; the driver writes the file atomically, so a facade
    /// either sees a whole map or sees none.
    fn from_env() -> stow_types::error::Result<Option<(PathBuf, Self)>> {
        let Some(path) = std::env::var_os(STOW_SERVE_MAP_FILE_ENV) else {
            return Ok(None);
        };
        let path = PathBuf::from(path);
        Self::read(&path).map(|map| Some((path, map)))
    }

    /// Read one serve map file; `NotFound` reads as the empty map a cold
    /// start means, matching `from_env`'s contract.
    fn read(path: &Path) -> stow_types::error::Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).wrap_err_with(|| {
                format!("{} is not a serve map", path.display())
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(stow_types::stow_error!(
                "read serve map {}: {error}",
                path.display()
            )),
        }
    }

    /// Any coverage at all, exact or wildcard: the empty map is the
    /// build that provably has nothing to serve yet — nothing local, no
    /// cached slice — so a `pending` empty map waits on nothing
    /// (stow#347).
    pub fn is_empty(&self) -> bool {
        self.target.is_empty() && self.host.is_empty()
    }

    /// Whether anything in the build could serve `name` at `version` on
    /// this side of the graph: an exact pair, or a wildcard when the
    /// build's semantic fallback is on.
    fn covers(&self, spelled_target: bool, canonical_name: &str, version: &str) -> bool {
        let entries = if spelled_target {
            &self.target
        } else {
            &self.host
        };
        entries.iter().any(|(entry_name, entry_version)| {
            entry_name == canonical_name && (entry_version == version || entry_version == WILDCARD)
        })
    }
}

/// What the facade settled before the runtime starts.
pub enum FastPath {
    /// The invocation was handled; the process exits with this status.
    Handled(i32),
    /// The fast path could not answer — the invocation continues down the
    /// plan path unchanged.
    Defer,
}

/// The uncovered-unit fast path: when the build's serve map is present
/// and does not cover this invocation, the plan's answer was already
/// "compile". The facade marks the unit, runs rustc, reports the outcome
/// over two one-way frames, and exits — no runtime, no plan round trip.
///
/// Anything the map cannot answer for — a unit stow might serve, an argv
/// stow cannot model, a supervisor that is not there — takes the plan
/// path, which is also what a plain `cargo build` through `stow setup`'s
/// wiring gets (no supervisor env at all).
///
/// # Errors
///
/// The transport contract is unchanged: a supervisor that is reachable in
/// principle but not in fact fails the build rather than silently
/// compiling without it.
pub fn try_invocation() -> stow_types::error::Result<FastPath> {
    let args = crate::process_args();
    if args.get(1).and_then(|arg| arg.to_str()) != Some("rustc") {
        return Ok(FastPath::Defer);
    }
    let Some(executable) = args.get(2).cloned() else {
        return Ok(FastPath::Defer);
    };
    let Some((map_path, mut map)) = ServeMap::from_env()? else {
        return Ok(FastPath::Defer);
    };
    let (endpoint, token) = match supervisor::from_env() {
        Ok(Some(pair)) => pair,
        Ok(None) => return Ok(FastPath::Defer),
        Err(error) => return Err(stow_types::stow_error!("{error}")),
    };
    // The debugging paths want the spans and traces the plan path emits.
    if std::env::var_os(crate::STOW_TRACE_WRAPPED_COMPILERS_ENV).is_some()
        || std::env::var_os("STOW_IDENTITY_TRACE").is_some()
    {
        return Ok(FastPath::Defer);
    }
    let mut wrapped_args = args.get(3..).map(<[_]>::to_vec).unwrap_or_default();
    if let Some(encoded) = std::env::var_os(rustc_args::STOW_RUSTC_EXTRA_ARGS_ENV)
        .and_then(|value| value.into_string().ok())
    {
        wrapped_args.extend(
            encoded
                .split('\x1f')
                .filter(|arg| !arg.is_empty())
                .map(OsString::from),
        );
    }
    let Ok(parsed) = ParsedRustcArgs::parse(&wrapped_args) else {
        return Ok(FastPath::Defer);
    };
    let Some((crate_name, version)) = detect_registry_crate_version(&parsed).unwrap_or(None) else {
        return Ok(FastPath::Defer);
    };
    let Ok(version) = semver::Version::parse(&version) else {
        return Ok(FastPath::Defer);
    };
    let invocation_covers = |map: &ServeMap| {
        map.covers(
            parsed.target.is_some(),
            &canonical_crate_name(&crate_name),
            version.to_string().as_str(),
        )
    };
    if invocation_covers(&map) {
        return Ok(FastPath::Defer);
    }
    // A pending map's "not covered" is provisional — but only when the
    // build provably has coverage the fetch may add to. An empty map
    // means nothing local and no cached slice: the fetch is a lottery,
    // and stalling every unit on it is exactly the slowdown the map
    // exists to remove, so the facade compiles and units arriving after
    // the final write still defer on it (stow#347).
    if map.pending && !map.is_empty() {
        wait_for_serve_map(&map_path);
        map = ServeMap::read(&map_path)?;
        if invocation_covers(&map) {
            return Ok(FastPath::Defer);
        }
    }
    Ok(FastPath::Handled(run_uncovered(
        &endpoint,
        &token,
        &executable,
        &wrapped_args,
    )?))
}

/// Mark the unit, run rustc, report the outcome: the build's bookkeeping
/// for a compile the map already ruled out, at the cost of two frame
/// writes and no round trips.
fn run_uncovered(
    endpoint: &Endpoint,
    token: &str,
    executable: &OsString,
    wrapped_args: &[OsString],
) -> stow_types::error::Result<i32> {
    let out_dir = std::env::var_os("OUT_DIR");
    let mut wire = connect(endpoint).map_err(|error| stow_types::stow_error!("{error}"))?;
    // The mark a `Compile` decision writes before rustc runs: dependents
    // plan only after this unit's metadata lands, so the file is on disk
    // before the frame that could consult it. (stow's own identity is
    // insensitive to provenance; an artifact compiled against CI's copy of
    // a locally-built crate links against the wrong copy.)
    write_observed(
        &mut wire,
        token,
        executable,
        wrapped_args,
        out_dir.as_deref(),
        None,
    )
    .map_err(|error| stow_types::stow_error!("{error}"))?;
    let status = std::process::Command::new(executable)
        .args(wrapped_args)
        .status()
        .wrap_err("failed to spawn wrapped compiler")?;
    let success = status.success();
    write_observed(
        &mut wire,
        token,
        executable,
        wrapped_args,
        out_dir.as_deref(),
        Some(success),
    )
    .map_err(|error| stow_types::stow_error!("{error}"))?;
    Ok(status.code().unwrap_or(1))
}

/// The path the driver's readiness gate binds for `map_path`:
/// `<map>.wait`, the socket whose close tells every waiting facade the
/// map is final.
#[cfg(unix)]
fn wait_socket_path(map_path: &Path) -> PathBuf {
    let mut name = map_path
        .file_name()
        .map(OsStr::to_os_string)
        .unwrap_or_default();
    name.push(".wait");
    map_path.with_file_name(name)
}

/// Wait on the gate a `pending` serve map announced: connect to its
/// socket and block until the driver closes it — the final map has
/// landed — or the bounded timeout expires. A gate that is absent (the
/// driver never bound one, or its process already went away) reads as
/// "decide on the map as it stands". Non-unix platforms have no gate:
/// they decide on the map immediately (stow#347).
#[cfg(unix)]
fn wait_for_serve_map(map_path: &Path) {
    use std::io::Read as _;

    let Ok(stream) = std::os::unix::net::UnixStream::connect(wait_socket_path(map_path)) else {
        return;
    };
    let _ = stream.set_read_timeout(Some(SERVE_MAP_WAIT_TIMEOUT));
    let mut byte = [0_u8; 1];
    let _ = (&stream).read(&mut byte);
}

/// Non-unix builds have no gate to wait on; a pending map decides as-is.
#[cfg(not(unix))]
fn wait_for_serve_map(_map_path: &Path) {}

/// The readiness gate a pending serve map leaves open, on unix the bound
/// `<map>.wait` listener: every facade blocked on it wakes when this is
/// dropped — after the driver's final map write, on error, or on process
/// exit, so a waiter can never hang past the driver's lifetime. Other
/// platforms carry no gate (stow#347).
#[cfg(unix)]
pub struct ServeMapGate {
    /// Held only to be dropped; closing the socket is the signal, so the
    /// listener is never read back.
    #[allow(dead_code)]
    listener: std::os::unix::net::UnixListener,
}

#[cfg(unix)]
impl ServeMapGate {
    /// Bind `<map>.wait`; `None` when the socket cannot be created — a
    /// facade then finds no gate and decides on the map it has.
    pub fn bind(map_path: &Path) -> Option<Self> {
        std::os::unix::net::UnixListener::bind(wait_socket_path(map_path))
            .ok()
            .map(|listener| Self { listener })
    }
}

/// The readiness gate a pending serve map leaves open: absent on
/// non-unix builds, whose facades decide on the map as it stands.
#[cfg(not(unix))]
pub struct ServeMapGate;

#[cfg(not(unix))]
impl ServeMapGate {
    /// No gate exists to bind on this platform.
    pub fn bind(_map_path: &Path) -> Option<Self> {
        None
    }
}

/// A blocking connection to the supervisor — two frame writes on the
/// fast path's behalf, no runtime and no round trip.
fn connect(endpoint: &Endpoint) -> std::io::Result<Box<dyn Write>> {
    match endpoint {
        #[cfg(unix)]
        Endpoint::Unix(path) => std::os::unix::net::UnixStream::connect(Path::new(path))
            .map(|stream| Box::new(stream) as Box<dyn Write>),
        Endpoint::Loopback(port) => std::net::TcpStream::connect(("127.0.0.1", *port))
            .map(|stream| Box::new(stream) as Box<dyn Write>),
    }
}

/// One one-way `Observed` frame: length prefix plus JSON body, the same
/// wire `client::Connection` speaks.
fn write_observed(
    wire: &mut dyn Write,
    token: &str,
    executable: &OsString,
    wrapped_args: &[OsString],
    out_dir: Option<&std::ffi::OsStr>,
    success: Option<bool>,
) -> std::io::Result<()> {
    let request = Request::Observed(Observed::new(
        token.to_owned(),
        executable,
        wrapped_args,
        out_dir,
        success,
    ));
    let body = serde_json::to_vec(&request).expect("an Observed frame always serializes");
    let length = u32::try_from(body.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "frame exceeds the wire limit",
        )
    })?;
    wire.write_all(&length.to_le_bytes())?;
    wire.write_all(&body)?;
    wire.flush()
}

#[cfg(test)]
mod tests {
    use super::{ServeMap, WILDCARD};

    fn map(target: &[(&str, &str)], host: &[(&str, &str)]) -> ServeMap {
        ServeMap {
            target: target
                .iter()
                .map(|(name, version)| ((*name).to_owned(), (*version).to_owned()))
                .collect(),
            host: host
                .iter()
                .map(|(name, version)| ((*name).to_owned(), (*version).to_owned()))
                .collect(),
            pending: false,
        }
    }

    /// An exact pair covers the unit; a different version and a different
    /// crate do not.
    #[test]
    fn a_pair_covers_exactly_its_version() {
        let map = map(&[("serde", "1.0.219")], &[]);
        assert!(map.covers(true, "serde", "1.0.219"));
        assert!(!map.covers(true, "serde", "1.0.220"));
        assert!(!map.covers(true, "serde_json", "1.0.219"));
    }

    /// A wildcard covers every version of its crate — the semantic-fallback
    /// shape — and nothing else.
    #[test]
    fn a_wildcard_covers_every_version() {
        let map = map(&[("serde", WILDCARD)], &[]);
        assert!(map.covers(true, "serde", "0.9.0"));
        assert!(!map.covers(true, "serde_json", "1.0.219"));
    }

    /// The two sides answer from their own sets: a consumer-covered crate
    /// does not cover a host-side unit.
    #[test]
    fn each_side_reads_its_own_coverage() {
        let map = map(&[("serde", "1.0.219")], &[("proc_macro2", "1.0.101")]);
        assert!(!map.covers(false, "serde", "1.0.219"));
        assert!(map.covers(false, "proc_macro2", "1.0.101"));
    }

    /// The wire shape round-trips, so the driver's serialization parses
    /// back into the map the facade answers from.
    #[test]
    fn the_env_shape_round_trips() {
        let map = map(
            &[("serde", "1.0.219"), ("libc", WILDCARD)],
            &[("log", "0.4.27")],
        );
        let encoded = serde_json::to_string(&map).expect("serialize");
        let decoded: ServeMap = serde_json::from_str(&encoded).expect("parse");
        assert!(decoded.covers(true, "serde", "1.0.219"));
        assert!(decoded.covers(true, "libc", "0.2.177"));
        assert!(decoded.covers(false, "log", "0.4.27"));
        assert!(!decoded.covers(true, "log", "0.4.27"));
    }

    /// A map file written before the field existed — a complete map by
    /// an older driver — parses as final, not pending (stow#347).
    #[test]
    fn a_map_without_the_flag_is_not_pending() {
        let decoded: ServeMap =
            serde_json::from_str(r#"{"target":[],"host":[]}"#).expect("parse");
        assert!(!decoded.pending);
        let decoded: ServeMap = serde_json::from_str(
            r#"{"target":[],"host":[],"pending":true}"#,
        )
        .expect("parse");
        assert!(decoded.pending);
    }

    /// Dropping the gate wakes the facade blocked on it, so a pending
    /// map's wait ends when the driver's final map lands (stow#347).
    #[cfg(unix)]
    #[test]
    fn the_gate_releases_its_waiters_when_dropped() {
        use std::time::{Duration, Instant};

        let dir = std::env::temp_dir().join(format!("stow-gate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create gate dir");
        let map_path = dir.join("serve-map.json");
        let gate = super::ServeMapGate::bind(&map_path).expect("bind the gate");
        let waiter = std::thread::spawn(move || {
            super::wait_for_serve_map(&map_path);
            Instant::now()
        });
        // Give the waiter its moment to block, then close the gate.
        std::thread::sleep(Duration::from_millis(50));
        let released = Instant::now();
        drop(gate);
        let woke = waiter.join().expect("waiter returns");
        assert!(woke - released < Duration::from_secs(5));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A facade that finds no gate decides immediately — the driver may
    /// have finished before this unit ever ran (stow#347).
    #[cfg(unix)]
    #[test]
    fn a_missing_gate_never_blocks() {
        use std::time::{Duration, Instant};

        let map_path =
            std::env::temp_dir().join(format!("stow-gate-absent-{}.json", std::process::id()));
        let started = Instant::now();
        super::wait_for_serve_map(&map_path);
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
