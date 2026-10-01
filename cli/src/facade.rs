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

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use stow_types::error::Context;
use stow_types::public_cache::{canonical_crate_name, detect_registry_crate_version};
use stow_types::rustc::ParsedRustcArgs;

use crate::rustc_args;
use crate::supervisor::protocol::{Answer, AwaitServeMap, Observed, Request};
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
    /// started (stow#347). A facade whose crate the map names but whose
    /// unit it does not cover asks the supervisor — `AwaitServeMap` over
    /// the build's existing transport — to hold it until the driver's
    /// full analysis rewrites this file with `pending` cleared, rather
    /// than compiling a unit the fetch may be about to cover.
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
            Ok(bytes) => serde_json::from_slice(&bytes)
                .wrap_err_with(|| format!("{} is not a serve map", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(stow_types::stow_error!(
                "read serve map {}: {error}",
                path.display()
            )),
        }
    }

    /// Any coverage at all, exact or wildcard: the empty map is the
    /// build that provably has nothing to serve yet — nothing local, no
    /// cached slice — so a `pending` map names nothing to wait on
    /// (stow#347).
    pub const fn is_empty(&self) -> bool {
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

    /// Whether the build ever covered `name`: any version, either side.
    /// A pending map's wait applies only to a crate this could still
    /// gain coverage for — the local artifacts or a previous slice
    /// already know it, so the fresh fetch plausibly adds the shape
    /// this unit needs; a crate nobody covered waits on a lottery, and
    /// stalling every first-wave unit on that measured about 0.8 s over
    /// cargo's own noise (stow#347).
    fn names(&self, canonical_name: &str) -> bool {
        self.target
            .iter()
            .chain(&self.host)
            .any(|(entry_name, _)| entry_name == canonical_name)
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
    // A pending map's "not covered" is provisional — but only for a
    // crate the build already covers at some shape. A crate the local
    // artifacts and the cached slices never covered waits on a
    // lottery, and measured against cargo that stall is above noise, so
    // the facade compiles and units arriving after the final write
    // still defer on it (stow#347).
    if map.pending && map.names(&canonical_crate_name(&crate_name)) {
        await_serve_map(&endpoint, &token)?;
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

/// Ask the supervisor to hold this facade until the pending serve map
/// is final: one `AwaitServeMap` frame, one `ServeMapReady` answer. The
/// wait rides the transport every platform already speaks — unix socket
/// or loopback TCP — so nothing here is unix-only anymore (stow#347).
///
/// The supervisor lives in the `stow` process that spawned cargo, so
/// anything that says it is gone mid-build is a defect and fails the
/// build loudly, naming the endpoint: a refused connect, a failed write,
/// a closed or reset stream, a refused request, a malformed frame. The
/// one quiet ending is the bounded read timeout — a driver that is alive
/// but stuck — which leaves the facade deciding on the map it has, since
/// the map file is re-read either way.
fn await_serve_map(endpoint: &Endpoint, token: &str) -> stow_types::error::Result<()> {
    await_serve_map_within(endpoint, token, SERVE_MAP_WAIT_TIMEOUT)
}

/// [`await_serve_map`] with the read bound as a parameter, so a test
/// does not have to wait the full timeout to see the quiet ending.
fn await_serve_map_within(
    endpoint: &Endpoint,
    token: &str,
    timeout: std::time::Duration,
) -> stow_types::error::Result<()> {
    let mut wire = connect(endpoint).map_err(|error| {
        stow_types::stow_error!(
            "the serve-map wait could not reach the supervisor at {endpoint:?}: {error}"
        )
    })?;
    wire.set_read_timeout(Some(timeout)).map_err(|error| {
        stow_types::stow_error!("bound the serve-map wait's read at {endpoint:?}: {error}")
    })?;
    let request = Request::AwaitServeMap(AwaitServeMap {
        token: token.to_owned(),
    });
    write_request(&mut wire, &request).map_err(|error| {
        stow_types::stow_error!(
            "the serve-map wait could not ask the supervisor at {endpoint:?}: {error}"
        )
    })?;
    match read_answer(&mut wire) {
        Ok(Some(Answer::ServeMapReady)) => Ok(()),
        Ok(None) => Err(stow_types::stow_error!(
            "the supervisor at {endpoint:?} closed the serve-map wait unanswered"
        )),
        Err(FrameError::Io(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Ok(())
        }
        Err(FrameError::Io(error)) => Err(stow_types::stow_error!(
            "the supervisor at {endpoint:?} dropped the serve-map wait: {error}"
        )),
        Ok(Some(Answer::Failed { message })) => Err(stow_types::stow_error!(
            "the supervisor at {endpoint:?} refused the serve-map wait: {message}"
        )),
        Ok(Some(answer)) => Err(stow_types::stow_error!(
            "the supervisor at {endpoint:?} answered the serve-map wait with {answer:?}"
        )),
        Err(FrameError::Malformed(message)) => Err(stow_types::stow_error!(
            "the serve-map wait at {endpoint:?} read a malformed frame: {message}"
        )),
    }
}

/// The build's "the serve map is final" signal, spoken over the
/// supervisor transport as `AwaitServeMap`: the enrichment completes it
/// once the pending map's final write lands, and the waiters' guard
/// completes it on drop, so a failed or cancelled analysis still
/// releases every facade it held. The whole signal dying — supervisor
/// included — drops the waiter's connection the same way (stow#347).
#[derive(Debug)]
pub struct ServeMapSignal {
    ready: tokio::sync::watch::Sender<bool>,
}

impl ServeMapSignal {
    /// A signal that has not yet seen the final write.
    #[must_use]
    pub fn pending() -> Self {
        Self {
            ready: tokio::sync::watch::channel(false).0,
        }
    }

    /// A signal already final — the at-once answer a supervisor with no
    /// pending map to wait on gives.
    #[must_use]
    pub fn settled() -> Self {
        Self {
            ready: tokio::sync::watch::channel(true).0,
        }
    }

    /// The final map has landed: release every waiter.
    pub fn complete(&self) {
        let _ = self.ready.send(true);
    }

    /// Wait for [`Self::complete`], or for the signal's own end: a
    /// sender that is gone resolves the same wait a completed one does.
    pub async fn wait(&self) {
        let mut receiver = self.ready.subscribe();
        if !*receiver.borrow() {
            let _ = receiver.changed().await;
        }
    }
}

impl Default for ServeMapSignal {
    /// A context nobody armed has no pending map: the answer is at once.
    fn default() -> Self {
        Self::settled()
    }
}

/// The completion side of a pending map's signal: dropping it — the
/// successful write, a failed fetch, a cancelled task — completes the
/// signal, so a facade's wait can never outlive the analysis it waits
/// on (stow#347).
#[derive(Debug)]
pub struct ServeMapWaiters(std::sync::Arc<ServeMapSignal>);

impl ServeMapWaiters {
    /// Arm `signal` for this build's pending map.
    pub const fn new(signal: std::sync::Arc<ServeMapSignal>) -> Self {
        Self(signal)
    }
}

impl Drop for ServeMapWaiters {
    fn drop(&mut self) {
        self.0.complete();
    }
}

/// The stream a facade opens to its supervisor — unix socket on unix,
/// loopback TCP elsewhere: the transport the Windows build's facades
/// already speak (stow#347).
enum FacadeStream {
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
    Tcp(std::net::TcpStream),
}

impl FacadeStream {
    /// Bound the wait's read: the `ServeMapReady` answer cannot stall a
    /// unit queue past it.
    fn set_read_timeout(&self, duration: Option<std::time::Duration>) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Unix(stream) => stream.set_read_timeout(duration),
            Self::Tcp(stream) => stream.set_read_timeout(duration),
        }
    }
}

impl Read for FacadeStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(unix)]
            Self::Unix(stream) => stream.read(buffer),
            Self::Tcp(stream) => stream.read(buffer),
        }
    }
}

impl Write for FacadeStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(unix)]
            Self::Unix(stream) => stream.write(buffer),
            Self::Tcp(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Unix(stream) => stream.flush(),
            Self::Tcp(stream) => stream.flush(),
        }
    }
}

/// A blocking connection to the supervisor — frame writes and the
/// serve-map wait on the fast path's behalf, no runtime.
fn connect(endpoint: &Endpoint) -> std::io::Result<FacadeStream> {
    match endpoint {
        #[cfg(unix)]
        Endpoint::Unix(path) => {
            std::os::unix::net::UnixStream::connect(Path::new(path)).map(FacadeStream::Unix)
        }
        Endpoint::Loopback(port) => {
            std::net::TcpStream::connect(("127.0.0.1", *port)).map(FacadeStream::Tcp)
        }
    }
}

/// One length-prefixed request frame: the same wire
/// `client::Connection` speaks, minus the runtime.
fn write_request(wire: &mut FacadeStream, request: &Request) -> std::io::Result<()> {
    let body = serde_json::to_vec(request).expect("a request frame always serializes");
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

/// Why a blocking read of one answer frame failed: the transport broke
/// or did not answer — driver death, the wait's own bound — or the
/// frame did not parse. `Io` carries the error so the caller can tell
/// the bounded timeout apart from a dropped connection.
enum FrameError {
    Io(std::io::Error),
    Malformed(String),
}

/// Read one answer frame, blocking. `Ok(None)` is a clean end of
/// stream — the driver closed between frames — the same semantic the
/// async `read_frame` gives the supervisor.
fn read_answer(wire: &mut FacadeStream) -> Result<Option<Answer>, FrameError> {
    let mut length_bytes = [0_u8; 4];
    match wire.read_exact(&mut length_bytes) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(FrameError::Io(error)),
    }
    let length = u32::from_le_bytes(length_bytes);
    if length > 4 * 1024 * 1024 {
        return Err(FrameError::Malformed(format!(
            "peer announced a {length}-byte frame"
        )));
    }
    let mut body = vec![0_u8; length as usize];
    wire.read_exact(&mut body).map_err(FrameError::Io)?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|error| FrameError::Malformed(format!("decode frame: {error}")))
}

/// One one-way `Observed` frame: mark or report, on the same wire
/// `client::Connection` speaks.
fn write_observed(
    wire: &mut FacadeStream,
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
    write_request(wire, &request)
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};

    use super::{ServeMap, WILDCARD};
    use crate::supervisor::Endpoint;

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
        let decoded: ServeMap = serde_json::from_str(r#"{"target":[],"host":[]}"#).expect("parse");
        assert!(!decoded.pending);
        let decoded: ServeMap =
            serde_json::from_str(r#"{"target":[],"host":[],"pending":true}"#).expect("parse");
        assert!(decoded.pending);
    }

    /// Accept one `AwaitServeMap` frame on a loopback listener and
    /// answer it with `answer` — after `hold`, so the test can see the
    /// wait actually waited. Returns the port the facade connects to
    /// and the frame the peer read.
    fn serve_one_await(
        hold: std::time::Duration,
        answer: &super::Answer,
    ) -> (u16, std::thread::JoinHandle<super::Request>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        let answer = answer.clone();
        let server = std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept the facade");
            let mut length_bytes = [0_u8; 4];
            peer.read_exact(&mut length_bytes).expect("read length");
            let mut body = vec![0_u8; u32::from_le_bytes(length_bytes) as usize];
            peer.read_exact(&mut body).expect("read body");
            let request: super::Request = serde_json::from_slice(&body).expect("request frame");
            std::thread::sleep(hold);
            let encoded = serde_json::to_vec(&answer).expect("answer frame");
            peer.write_all(
                &u32::try_from(encoded.len())
                    .expect("frame length fits u32")
                    .to_le_bytes(),
            )
            .expect("write length");
            peer.write_all(&encoded).expect("write body");
            peer.flush().expect("flush");
            request
        });
        (port, server)
    }

    /// The serve-map wait rides the supervisor transport the Windows
    /// build uses: a loopback peer that answers once the final map
    /// lands releases the facade — the wait is the peer's word, not a
    /// unix socket's close (stow#347).
    #[test]
    fn the_wait_rides_the_loopback_transport() {
        use std::time::{Duration, Instant};

        let (port, server) =
            serve_one_await(Duration::from_millis(80), &super::Answer::ServeMapReady);
        let started = Instant::now();
        super::await_serve_map(&Endpoint::Loopback(port), "the-token").expect("the wait");
        let waited = started.elapsed();
        let request = server.join().expect("server thread");
        assert_eq!(
            request,
            super::Request::AwaitServeMap(super::AwaitServeMap {
                token: "the-token".to_owned()
            })
        );
        assert!(waited >= Duration::from_millis(80), "{waited:?}");
        assert!(waited < super::SERVE_MAP_WAIT_TIMEOUT, "{waited:?}");
    }

    /// A driver that dies mid-wait drops the connection — the
    /// supervisor lives in the `stow` process that spawned cargo, so
    /// that is a defect the build fails on, named by its endpoint, not
    /// a signal the facade decides around (stow#347).
    #[test]
    fn a_driver_that_dies_fails_the_wait_loudly() {
        use std::time::{Duration, Instant};

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        let server = std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept the facade");
            let mut length_bytes = [0_u8; 4];
            peer.read_exact(&mut length_bytes).expect("read length");
            let mut body = vec![0_u8; u32::from_le_bytes(length_bytes) as usize];
            peer.read_exact(&mut body).expect("read body");
            drop(peer);
        });
        let started = Instant::now();
        let error = super::await_serve_map(&Endpoint::Loopback(port), "the-token")
            .expect_err("a dropped supervisor must fail the build");
        server.join().expect("server thread");
        assert!(
            error.to_string().contains(&port.to_string()),
            "the error must name the endpoint: {error}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// A supervisor that is not there at all is a driver gone before
    /// the wait even began — the same defect, failing loudly with its
    /// endpoint named (stow#347).
    #[test]
    fn a_dead_endpoint_fails_the_wait_loudly() {
        use std::time::{Duration, Instant};

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        let started = Instant::now();
        let error = super::await_serve_map(&Endpoint::Loopback(port), "the-token")
            .expect_err("a refused connect must fail the build");
        assert!(
            error.to_string().contains(&port.to_string()),
            "the error must name the endpoint: {error}"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// A driver that is alive but never answers — the one quiet ending:
    /// the read bound trips and the facade decides on the map it has
    /// (stow#347).
    #[test]
    fn the_read_timeout_decides_on_the_map_as_it_stands() {
        use std::time::{Duration, Instant};

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        let server = std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept the facade");
            let mut length_bytes = [0_u8; 4];
            peer.read_exact(&mut length_bytes).expect("read length");
            let mut body = vec![0_u8; u32::from_le_bytes(length_bytes) as usize];
            peer.read_exact(&mut body).expect("read body");
            std::thread::sleep(Duration::from_secs(2));
        });
        let started = Instant::now();
        super::await_serve_map_within(
            &Endpoint::Loopback(port),
            "the-token",
            Duration::from_millis(50),
        )
        .expect("the bounded timeout ends the wait quietly");
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(50) && waited < Duration::from_secs(2),
            "the wait ended on its own bound, not the peer's: {waited:?}"
        );
        server.join().expect("server thread");
    }

    /// A supervisor that refuses the wait — the wrong-token answer — is
    /// a protocol bug the facade surfaces, not a release (stow#347).
    #[test]
    fn a_refused_wait_fails_loudly() {
        use std::time::Duration;

        let (port, server) = serve_one_await(
            Duration::ZERO,
            &super::Answer::Failed {
                message: "supervisor token mismatch".to_owned(),
            },
        );
        let error = super::await_serve_map(&Endpoint::Loopback(port), "the-token")
            .expect_err("a refused wait must not pass");
        server.join().expect("server thread");
        assert!(
            error.to_string().contains("supervisor token mismatch"),
            "{error}"
        );
    }
}
