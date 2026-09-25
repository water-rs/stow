//! Which real compiler a `stow cc` facade execs.
//!
//! Resolved per invocation the way the `cc` crate resolves it inside
//! every build script, rather than snapshotted into the cargo
//! configuration, so a toolchain update cannot strand it.

use std::ffi::OsString;

/// Which language the compiler shim was invoked for — the two roles
/// resolve to different POSIX defaults and the same `cl.exe` on Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcKind {
    /// The `stow-cc` shim (`CC`).
    C,
    /// The `stow-cxx` shim (`CXX`).
    Cxx,
}

/// The real compiler a shim invocation execs, plus the environment it needs.
///
/// The environment is empty on POSIX; the MSVC toolchain's `PATH`/`LIB`/
/// `INCLUDE` for an msvc target, where `cl.exe` finds nothing on its own.
/// It is resolved per invocation (the way the `cc` crate resolves it
/// inside every build script) rather than snapshotted into the cargo
/// configuration, so a Visual Studio update cannot strand it.
#[derive(Debug, Clone)]
pub struct ResolvedCompiler {
    /// The compiler program to spawn or exec.
    pub program: OsString,
    /// Environment overrides the compiler needs to run.
    pub env: Vec<(OsString, OsString)>,
}

impl ResolvedCompiler {
    /// An explicitly recorded compiler: used verbatim with no toolchain
    /// env.
    #[must_use]
    pub const fn explicit(program: OsString) -> Self {
        Self {
            program,
            env: Vec::new(),
        }
    }
}

/// Resolve the compiler an invocation with no recorded toolchain runs.
///
/// `target` is the `TARGET` variable cargo sets for a build script —
/// the compilation's real destination, so an x64→aarch64 cross build
/// gets the right `cl.exe`/`LIB`/`INCLUDE`; when it is absent (a manual
/// shim call outside a build) the host applies.
///
/// On an msvc target it is the `cl.exe` `find_msvc_tools` locates (the
/// same lookup `cc` performs), carrying that tool's environment; any
/// other Windows target keeps the `cc`/`c++` names.
///
/// # Errors
/// Fails when the target is msvc but no MSVC toolchain can be found —
/// wiring a bare `cl` would produce a spawn error with no hint of the
/// cause.
#[cfg(windows)]
pub fn resolve_compiler(
    kind: CcKind,
    target: Option<&str>,
) -> stow_types::error::Result<ResolvedCompiler> {
    if let Some(target) = target_for_resolution(target) {
        let tool = find_msvc_tools::find_tool(target.as_str(), "cl.exe").ok_or_else(|| {
            stow_types::stow_error!(
                "no MSVC toolchain found for target {target} — install \
                 Visual Studio Build Tools, or set STOW_REAL_CC to a compiler"
            )
        })?;
        return Ok(ResolvedCompiler {
            program: tool.path().as_os_str().to_owned(),
            env: tool
                .env()
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect(),
        });
    }
    Ok(platform_driver(kind))
}

/// The POSIX form of [`resolve_compiler`]: infallible, because the
/// `cc`/`c++` driver names always resolve — `TARGET` is accepted for
/// signature parity and ignored.
#[cfg(not(windows))]
#[must_use]
pub fn resolve_compiler(kind: CcKind, _target: Option<&str>) -> ResolvedCompiler {
    platform_driver(kind)
}

/// `cc`/`c++`, the compiler driver the `cc` crate execs on every
/// non-msvc resolution.
fn platform_driver(kind: CcKind) -> ResolvedCompiler {
    ResolvedCompiler::explicit(OsString::from(match kind {
        CcKind::C => "cc",
        CcKind::Cxx => "c++",
    }))
}

/// The `TARGET`-or-host triple an msvc lookup applies, or `None` when
/// the compilation is not for an msvc target (`*-windows-gnu`, `wasm32`,
/// …). `find_tool` needs the host architecture when `TARGET` is absent —
/// cargo sets the variable only for build scripts, not for a shim a user
/// invokes by hand.
#[cfg(windows)]
fn target_for_resolution(target: Option<&str>) -> Option<String> {
    target.map_or_else(
        || Some(format!("{}-pc-windows-msvc", std::env::consts::ARCH)),
        |triple| triple.contains("msvc").then(|| triple.to_owned()),
    )
}

#[cfg(all(test, windows))]
mod tests {
    /// The msvc lookup keys on `TARGET`, not the machine: an
    /// `aarch64-pc-windows-msvc` target resolves for aarch64, a `*-gnu`
    /// target or wasm skips the MSVC path entirely.
    #[test]
    fn target_for_resolution_follows_the_build_target() {
        assert_eq!(
            super::target_for_resolution(Some("aarch64-pc-windows-msvc")).as_deref(),
            Some("aarch64-pc-windows-msvc")
        );
        assert_eq!(
            super::target_for_resolution(Some("x86_64-pc-windows-msvc")).as_deref(),
            Some("x86_64-pc-windows-msvc")
        );
        assert_eq!(
            super::target_for_resolution(Some("x86_64-pc-windows-gnu")),
            None
        );
        assert_eq!(
            super::target_for_resolution(Some("wasm32-unknown-unknown")),
            None
        );
        // No TARGET (a manual shim call) resolves for the host arch.
        assert_eq!(
            super::target_for_resolution(None).as_deref(),
            Some(format!("{}-pc-windows-msvc", std::env::consts::ARCH)).as_deref()
        );
    }
}
