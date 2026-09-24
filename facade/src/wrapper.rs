//! The facade's fast paths: answer the serve question from the build's
//! once-per-build map, run the compiler, and owe the supervisor only the
//! frames that keep its bookkeeping honest.
//!
//! Everything here is synchronous and self-contained — no runtime, no
//! config load, no index — because it runs once per compiler invocation,
//! hundreds of times per build (stow#347).

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use stow_types::error::Context;
use stow_types::rustc::ParsedRustcArgs;

use crate::cc;
use crate::client::SyncConnection;
use crate::endpoint;
use crate::journal;
use crate::servable::{self, ServableUnits};

/// Env override for the runtime executable a facade delegates to.
///
/// The supervising build sets it to its own `current_exe`, which is
/// always the runtime that spawned cargo.
pub const STOW_CLI_BINARY_ENV: &str = "STOW_CLI_BINARY";

/// Env channel carrying rustc arguments a `stow` build appends per unit.
///
/// The workspace path remap plus any flags the run itself selected,
/// `\x1f`-joined like `CARGO_ENCODED_RUSTFLAGS`. A private channel rather
/// than `RUSTFLAGS`, because env rustflags replace the user's configured
/// rustflags outright: assigning `RUSTFLAGS` would make cargo ignore
/// `.cargo/config.toml` `target.*.rustflags` — the usual way
/// `-C link-arg=-fuse-ld=mold` is enabled — for the whole build.
pub const STOW_RUSTC_EXTRA_ARGS_ENV: &str = "STOW_RUSTC_EXTRA_ARGS";

/// The serve question, answered from the map the supervising build
/// computed: `(crate_name, version)` pairs it can serve, plus
/// `crate_name → *` wildcard entries a semantic fallback may cover.
///
/// Every unit outside the map compiles — no plan round trip asks again
/// (stow#347). Returns `None` when the fast path does not apply and the
/// invocation should take the ordinary wrapper path.
///
/// `args` is the expanded wrapper command line — `[program, role, ...]`:
/// `rustc <rustc> <args…>` or `cc <compiler> <args…>`, the same shape
/// `stow-cli`'s own dispatcher parses.
///
/// # Errors
///
/// Env or supervisor-connect failures, and the wrapped compiler failing
/// to spawn.
pub fn try_fast_wrapper_path(args: &[OsString]) -> stow_types::error::Result<Option<i32>> {
    match args.get(1).map(OsString::as_os_str) {
        Some(arg) if arg == OsStr::new("cc") => return try_fast_cc_path(args),
        Some(arg) if arg == OsStr::new("rustc") => {}
        _ => return Ok(None),
    }
    // Both envs must be live: the supervisor endpoint (set by every
    // supervised run) and the servable map (set only by a run that
    // computed it). Without the map this is an older supervisor — the
    // ordinary path keeps working.
    let Some((endpoint, token)) =
        endpoint::from_env().map_err(|error| stow_types::stow_error!("{error}"))?
    else {
        return Ok(None);
    };
    let Some(units) = servable::serve_map().and_then(|raw| ServableUnits::parse(&raw)) else {
        return Ok(None);
    };
    let Some(executable) = args.get(2).cloned() else {
        return Ok(None);
    };
    let mut wrapped_args: Vec<OsString> = args.get(3..).unwrap_or_default().to_vec();
    // The supervising run's extra rustc arguments arrive appended, the
    // same merge the ordinary wrapper performs before planning.
    if let Some(encoded) =
        std::env::var_os(STOW_RUSTC_EXTRA_ARGS_ENV).and_then(|encoded| encoded.into_string().ok())
    {
        wrapped_args.extend(
            encoded
                .split('\x1f')
                .filter(|arg| !arg.is_empty())
                .map(OsString::from),
        );
    }
    let mut connection = SyncConnection::open(&endpoint, token)
        .map_err(|error| stow_types::stow_error!("{error}"))?;
    let parsed = ParsedRustcArgs::parse(&wrapped_args).ok();
    let servable = parsed.as_ref().is_some_and(|parsed| {
        let detected_version = stow_types::public_cache::detect_registry_crate_version(parsed)
            .ok()
            .flatten()
            .map(|(_, version)| version);
        units.covers(&parsed.crate_name, detected_version.as_deref())
    });
    if parsed.is_none() || servable {
        // A serve is possible, or the invocation is not a unit at all
        // (a probe): the plan round trip decides — the only frame that
        // may block rustc's start, and only where it can pay (stow#347).
        return run_planned_invocation(connection, &executable, &wrapped_args).map(Some);
    }

    // Nothing in this build can serve this unit: compile it here and
    // report the outcome so the supervisor's bookkeeping still lands —
    // the provenance mark before rustc starts, the rest off the wire.
    connection
        .mark(&executable, &wrapped_args)
        .map_err(|error| stow_types::stow_error!("{error}"))?;
    let status = std::process::Command::new(&executable)
        .args(&wrapped_args)
        .status()
        .wrap_err("failed to spawn wrapped compiler")?;
    connection
        .report_observed(&executable, &wrapped_args, status.success())
        .map_err(|error| stow_types::stow_error!("{error}"))?;
    Ok(Some(status.code().unwrap_or(1)))
}

/// `stow cc` on a cold local object cache: the once-per-build state
/// already answered the only question the cc pipeline asks here (nothing
/// cached can serve this compile), so the compiler just runs and the
/// content-keyed store is journaled for the build's drain — no runtime,
/// no config load, no `cc -E`, no sqlite on the facade (stow#347).
///
/// The env carrying the journal path is only set by a supervised build
/// that checked the store's emptiness once; without it the ordinary
/// lookup path runs.
///
/// # Errors
///
/// The wrapped compiler failing to spawn.
fn try_fast_cc_path(args: &[OsString]) -> stow_types::error::Result<Option<i32>> {
    let Some(journal_path) = std::env::var_os(journal::CC_PENDING_ENV).map(PathBuf::from) else {
        return Ok(None);
    };
    let Some(executable) = args.get(2) else {
        return Ok(None);
    };
    #[cfg(not(windows))]
    let compiler = resolve_cc_compiler(executable);
    #[cfg(windows)]
    let compiler = resolve_cc_compiler(executable)?;
    let wrapped: &[OsString] = args.get(3..).unwrap_or_default();
    let status = std::process::Command::new(&compiler.program)
        .args(wrapped)
        .envs(compiler.env.iter().cloned())
        .status()
        .wrap_err("failed to spawn wrapped C/C++ compiler")?;
    if let Err(error) =
        journal::append_cc_pending(&journal_path, &compiler, wrapped, status.success())
    {
        eprintln!("stow: failed to journal a deferred C/C++ compile: {error}");
    }
    Ok(Some(status.code().unwrap_or(1)))
}

/// The plan half of the facade, synchronous: ask the supervisor what to
/// do, run rustc only when nothing serves it, then report — the same
/// exchange the ordinary path runs over the async transport.
///
/// # Errors
///
/// Plan/report round-trip failures, and rustc failing to spawn.
fn run_planned_invocation(
    mut connection: SyncConnection,
    executable: &OsString,
    args: &[OsString],
) -> stow_types::error::Result<i32> {
    let decision = connection
        .plan(executable, args)
        .map_err(|error| stow_types::stow_error!("{error}"))?;
    let ticket = match decision {
        crate::client::Decision::Served => return Ok(0),
        crate::client::Decision::Compile(ticket) => ticket,
    };
    let status = std::process::Command::new(executable)
        .args(args)
        .status()
        .wrap_err("failed to spawn wrapped compiler")?;
    connection
        .report(&ticket, status.success())
        .map_err(|error| stow_types::stow_error!("{error}"))?;
    Ok(status.code().unwrap_or(1))
}

/// What `stow cc`'s executable argument asks for: an explicitly recorded
/// compiler execed verbatim, or the platform toolchain resolved per
/// invocation for the compilation's `TARGET`.
#[derive(Debug)]
pub(crate) enum CcResolutionKind {
    /// Exec this program verbatim.
    Explicit(OsString),
    /// Resolve the platform toolchain for this language.
    Resolve(cc::CcKind),
}

/// Classify `stow cc`'s executable argument. The compiler shims emit the
/// resolve markers when no `STOW_REAL_CC`/`STOW_REAL_CXX` was recorded.
/// A bare `cl`/`clang-cl` also resolves rather than execing verbatim: the
/// `CMake` launcher role hands the compiler cmake picked as argv[1], and
/// `cl.exe` cannot run without the toolchain env `find_msvc_tools`
/// computes.
fn classify_cc_executable(executable: &OsString, target: Option<&str>) -> CcResolutionKind {
    let msvc_target = target.map_or(cfg!(all(windows, target_env = "msvc")), |t| {
        t.contains("msvc")
    });
    let stem = || {
        Path::new(executable)
            .file_stem()
            .and_then(std::ffi::OsStr::to_str)
    };
    match executable.to_str() {
        Some(stow_shim::RESOLVE_CC) => CcResolutionKind::Resolve(cc::CcKind::C),
        Some(stow_shim::RESOLVE_CXX) => CcResolutionKind::Resolve(cc::CcKind::Cxx),
        _ if msvc_target
            && stem().is_some_and(|stem| {
                stem.eq_ignore_ascii_case("cl") || stem.contains("clang-cl")
            }) =>
        {
            CcResolutionKind::Resolve(cc::CcKind::C)
        }
        _ => CcResolutionKind::Explicit(executable.clone()),
    }
}

/// The compiler a `stow cc` invocation execs — see
/// [`classify_cc_executable`] and [`cc::resolve_compiler`]. The ordinary
/// `stow cc` path resolves the same way.
///
/// # Errors
///
/// See [`cc::resolve_compiler`]: an msvc target with no toolchain found.
#[cfg(windows)]
pub fn resolve_cc_compiler(
    executable: &OsString,
) -> stow_types::error::Result<cc::ResolvedCompiler> {
    let target = std::env::var("TARGET").ok();
    match classify_cc_executable(executable, target.as_deref()) {
        CcResolutionKind::Resolve(kind) => cc::resolve_compiler(kind, target.as_deref()),
        CcResolutionKind::Explicit(program) => Ok(cc::ResolvedCompiler::explicit(program)),
    }
}

/// The POSIX form: infallible, because resolution is always the
/// `cc`/`c++` driver name.
#[cfg(not(windows))]
#[must_use]
pub fn resolve_cc_compiler(executable: &OsString) -> cc::ResolvedCompiler {
    match classify_cc_executable(executable, std::env::var("TARGET").ok().as_deref()) {
        CcResolutionKind::Resolve(kind) => cc::resolve_compiler(kind, None),
        CcResolutionKind::Explicit(program) => cc::ResolvedCompiler::explicit(program),
    }
}
