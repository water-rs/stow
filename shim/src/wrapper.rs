//! Wrapper-shim materialization for native targets.
//!
//! A wrapper is the runtime executable itself under a wrapper name: a
//! symlink on Unix, a copy on Windows, where an `AppContainer` (the trusted
//! build sandbox) refuses to run batch files and `cmd.exe`'s re-tokenization
//! of `%*` is unsafe for rustc argument lists anyway. Either way the runtime
//! recovers its role from the file stem it was started under
//! ([`WrapperRole`]) and, for the rustc role under a capture build, hands the
//! invocation to the `stow-capture` executable placed beside it.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use stow_types::error::Context;

const RUSTC_WRAPPER_PATH: &str = "stow-rustc-wrapper";
const CC_LAUNCHER_PATH: &str = "stow-cc-launcher";
const CC_COMPILER_PATH: &str = "stow-cc";
const CXX_COMPILER_PATH: &str = "stow-cxx";
const RUNTIME_LINK_PATH: &str = "stow-runtime";
const CAPTURE_LINK_PATH: &str = "stow-capture";

/// Environment variable the trusted build stage sets inside its sandbox. When
/// present, the rustc wrapper routes every invocation to the capture
/// executable instead of the runtime.
pub const CAPTURE_DIR_ENV: &str = "STOW_BUILD_RUSTC_CAPTURE_DIR";
/// Real C compiler the compiler-shaped `cc` shim invokes; recorded by the
/// driver before it overwrites `CC`.
pub const REAL_CC_ENV: &str = "STOW_REAL_CC";
/// Real C++ compiler the compiler-shaped `cxx` shim invokes; recorded by the
/// driver before it overwrites `CXX`.
pub const REAL_CXX_ENV: &str = "STOW_REAL_CXX";
/// Marker a compiler-shaped shim emits as `stow cc`'s executable when no
/// real compiler was recorded — [`REAL_CC_ENV`] unset.
///
/// The runtime resolves the platform's toolchain per invocation the way
/// the `cc` crate does, rather than wiring a snapshot resolved at setup
/// time.
pub const RESOLVE_CC: &str = "stow-resolve-cc";
/// [`RESOLVE_CC`] for the `cxx` role.
pub const RESOLVE_CXX: &str = "stow-resolve-cxx";

/// The job a wrapper executable performs, recovered from its file stem.
///
/// Each variant corresponds to one of the materialized wrapper names, so a
/// runtime binary copied under that name knows which subcommand the caller
/// meant without any argument marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapperRole {
    /// `RUSTC_WRAPPER`: argv is `<rustc> <rustc args…>`.
    Rustc,
    /// `CMAKE_*_COMPILER_LAUNCHER`: argv is `<compiler> <compiler args…>`.
    CcLauncher,
    /// `CC`: argv is `<compiler args…>`; the compiler comes from
    /// [`REAL_CC_ENV`].
    Cc,
    /// `CXX`: argv is `<compiler args…>`; the compiler comes from
    /// [`REAL_CXX_ENV`].
    Cxx,
}

impl WrapperRole {
    /// The role `program` (argv\[0\]) plays, or `None` when it is not one of
    /// the wrapper names.
    #[must_use]
    pub fn from_program(program: &Path) -> Option<Self> {
        match program.file_stem()?.to_str()? {
            RUSTC_WRAPPER_PATH => Some(Self::Rustc),
            CC_LAUNCHER_PATH => Some(Self::CcLauncher),
            CC_COMPILER_PATH => Some(Self::Cc),
            CXX_COMPILER_PATH => Some(Self::Cxx),
            _ => None,
        }
    }

    /// The runtime subcommand line this role stands for: the arguments a
    /// runtime binary parses in place of `wrapped` when it was started under
    /// this role's name.
    #[must_use]
    pub fn runtime_args(self, wrapped: &[OsString]) -> Vec<OsString> {
        let mut args: Vec<OsString> = match self {
            Self::Rustc => vec![OsString::from("rustc")],
            Self::CcLauncher => vec![OsString::from("cc")],
            Self::Cc => vec![
                OsString::from("cc"),
                std::env::var_os(REAL_CC_ENV).unwrap_or_else(|| OsString::from(RESOLVE_CC)),
            ],
            Self::Cxx => vec![
                OsString::from("cc"),
                std::env::var_os(REAL_CXX_ENV).unwrap_or_else(|| OsString::from(RESOLVE_CXX)),
            ],
        };
        args.extend(wrapped.iter().cloned());
        args
    }

    /// Whether this invocation belongs to the capture executable: the rustc
    /// role inside a trusted build sandbox, signalled by [`CAPTURE_DIR_ENV`].
    #[must_use]
    pub fn delegates_to_capture(self) -> bool {
        self == Self::Rustc
            && std::env::var_os(CAPTURE_DIR_ENV).is_some_and(|value| !value.is_empty())
    }
}

/// The capture executable materialized beside a wrapper: `stow-capture` (with
/// the platform executable suffix) in the wrapper's directory.
#[must_use]
pub fn capture_executable_beside(program: &Path) -> PathBuf {
    let dir = program.parent().unwrap_or_else(|| Path::new(""));
    dir.join(executable_file_name(CAPTURE_LINK_PATH))
}

fn executable_file_name(base: &str) -> String {
    format!("{base}{}", std::env::consts::EXE_SUFFIX)
}

/// Filesystem paths to the materialized rustc / cc wrappers.
///
/// `cc_launcher` and `cc_compiler` differ by calling convention, and using one
/// where the other belongs breaks every C build. `RUSTC_WRAPPER` and
/// `CMAKE_*_COMPILER_LAUNCHER` are *launchers*: the program to run arrives as
/// the first argument. `CC` and `CXX` are not — they are invoked with compiler
/// arguments only, so a launcher-shaped shim tries to execute the first flag.
#[derive(Debug)]
pub struct WrapperShimPaths {
    /// Path to the rustc wrapper.
    pub rustc_wrapper: PathBuf,
    /// Launcher-shaped cc shim, for `CMAKE_*_COMPILER_LAUNCHER`.
    pub cc_launcher: PathBuf,
    /// Compiler-shaped cc shim, for `CC`.
    pub cc_compiler: PathBuf,
    /// Compiler-shaped c++ shim, for `CXX`.
    pub cxx_compiler: PathBuf,
}

/// The durable per-user directory the wrapper tools are installed into.
///
/// Resolves to `dirs::data_local_dir()/stow/tools`:
/// `~/Library/Application Support/stow/tools` on macOS,
/// `~/.local/share/stow/tools` on Linux, `%LOCALAPPDATA%\stow\tools` on
/// Windows.
///
/// The tools dir must outlive a reboot: `stow setup` writes its paths into
/// `.cargo/config.toml` and the job environment, and a base under the system
/// temp directory is purged by the OS, leaving every cargo invocation
/// pointing at a wrapper that no longer exists.
///
/// # Errors
/// Returns an error when the platform has no per-user local data directory.
pub fn tools_dir() -> stow_types::error::Result<PathBuf> {
    let base = dirs::data_local_dir().ok_or_else(|| {
        stow_types::stow_error!("resolve per-user local data directory for stow tools")
    })?;
    Ok(base.join("stow").join("tools"))
}

/// Idempotently materialize the rustc / cc wrappers under `tools_dir` (see
/// [`tools_dir`] for the standard location), and point them at the supplied
/// runtime / capture executables.
///
/// Every replacement is a temp-file-plus-rename, so a wrapper that cargo is
/// executing concurrently resolves to either the old or the new runtime,
/// never to a partially written one.
///
/// # Errors
/// Returns an error when the tool directory cannot be created, or a link or
/// executable cannot be written or renamed into place.
pub fn materialize_wrapper_shims(
    tools_dir: &Path,
    runtime_executable: &Path,
    capture_executable: &Path,
) -> stow_types::error::Result<WrapperShimPaths> {
    fs::create_dir_all(tools_dir)
        .wrap_err_with(|| format!("create wrapper tool dir {}", tools_dir.display()))?;

    materialize_in(tools_dir, runtime_executable, capture_executable)
}

/// Unix: symlinks to the runtime under each wrapper name, exactly as
/// Windows places copies of it.
///
/// These wrappers run once per compiler invocation — hundreds of times in a
/// build — so anything they do is multiplied by the unit count. An `sh`
/// script cost a whole extra fork and exec of a shell for each one: 28.4ms
/// per rustc invocation against 23.7ms through a symlink, measured as the
/// median of 40 `rustc -vV` runs on an M-series Mac. The runtime recovers
/// its role from the name it was started under ([`WrapperRole`]) and
/// handles the capture-sandbox branch the script used to test for, so the
/// shell bought nothing.
#[cfg(unix)]
fn materialize_in(
    base: &Path,
    runtime_executable: &Path,
    capture_executable: &Path,
) -> stow_types::error::Result<WrapperShimPaths> {
    replace_link_atomic(&base.join(RUNTIME_LINK_PATH), runtime_executable)?;
    replace_link_atomic(&base.join(CAPTURE_LINK_PATH), capture_executable)?;

    let wrapper_link = |name: &str| -> stow_types::error::Result<PathBuf> {
        let path = base.join(name);
        replace_link_atomic(&path, runtime_executable)?;
        Ok(path)
    };
    Ok(WrapperShimPaths {
        rustc_wrapper: wrapper_link(RUSTC_WRAPPER_PATH)?,
        cc_launcher: wrapper_link(CC_LAUNCHER_PATH)?,
        cc_compiler: wrapper_link(CC_COMPILER_PATH)?,
        cxx_compiler: wrapper_link(CXX_COMPILER_PATH)?,
    })
}

/// Windows: the executables themselves, placed under the wrapper names.
///
/// `stow-runtime.exe` and `stow-capture.exe` mirror the Unix symlinks; the
/// four wrappers are the runtime under its role names (see [`WrapperRole`]).
/// A copy is a hard link when the tool directory shares a volume with the
/// executable and a byte copy otherwise; either way the file is staged and
/// renamed into place so a wrapper cargo is executing is never half-written.
#[cfg(windows)]
fn materialize_in(
    base: &Path,
    runtime_executable: &Path,
    capture_executable: &Path,
) -> stow_types::error::Result<WrapperShimPaths> {
    place_executable(base, RUNTIME_LINK_PATH, runtime_executable)?;
    place_executable(base, CAPTURE_LINK_PATH, capture_executable)?;
    Ok(WrapperShimPaths {
        rustc_wrapper: place_executable(base, RUSTC_WRAPPER_PATH, runtime_executable)?,
        cc_launcher: place_executable(base, CC_LAUNCHER_PATH, runtime_executable)?,
        cc_compiler: place_executable(base, CC_COMPILER_PATH, runtime_executable)?,
        cxx_compiler: place_executable(base, CXX_COMPILER_PATH, runtime_executable)?,
    })
}

/// Put `executable` at `<base>/<name>.exe`, leaving an identical file alone.
#[cfg(windows)]
fn place_executable(
    base: &Path,
    name: &str,
    executable: &Path,
) -> stow_types::error::Result<PathBuf> {
    let destination = base.join(executable_file_name(name));
    if same_contents(&destination, executable)? {
        return Ok(destination);
    }
    let temp_path = staging_path(&destination)?;
    if let Err(link_error) = fs::hard_link(executable, &temp_path) {
        fs::copy(executable, &temp_path).wrap_err_with(|| {
            format!(
                "copy {} to {} (hard link failed: {link_error})",
                executable.display(),
                temp_path.display()
            )
        })?;
    }
    fs::rename(&temp_path, &destination).map_err(|error| {
        let _ = fs::remove_file(&temp_path);
        stow_types::stow_error!(
            "atomically replace wrapper executable {}: {error}",
            destination.display()
        )
    })?;
    Ok(destination)
}

/// Whether `destination` already holds the bytes of `source`. A missing
/// destination is simply not identical.
#[cfg(windows)]
fn same_contents(destination: &Path, source: &Path) -> stow_types::error::Result<bool> {
    let Ok(destination_meta) = fs::metadata(destination) else {
        return Ok(false);
    };
    let source_meta = fs::metadata(source)
        .wrap_err_with(|| format!("stat wrapper executable source {}", source.display()))?;
    if destination_meta.len() != source_meta.len() {
        return Ok(false);
    }
    let destination_bytes = fs::read(destination)
        .wrap_err_with(|| format!("read wrapper executable {}", destination.display()))?;
    let source_bytes = fs::read(source)
        .wrap_err_with(|| format!("read wrapper executable source {}", source.display()))?;
    Ok(destination_bytes == source_bytes)
}

#[cfg(unix)]
fn replace_link_atomic(link_path: &Path, target: &Path) -> stow_types::error::Result<()> {
    let temp_path = staging_path(link_path)?;
    std::os::unix::fs::symlink(target, &temp_path).wrap_err_with(|| {
        format!(
            "create temporary wrapper tool link {} -> {}",
            temp_path.display(),
            target.display()
        )
    })?;
    fs::rename(&temp_path, link_path).map_err(|error| {
        let _ = fs::remove_file(&temp_path);
        stow_types::stow_error!(
            "atomically replace wrapper tool link {} -> {}: {error}",
            link_path.display(),
            target.display()
        )
    })
}

/// A per-process staging name next to `path`, so concurrent `stow setup`
/// runs never write the same temp file and the final rename is atomic.
fn staging_path(path: &Path) -> stow_types::error::Result<PathBuf> {
    let parent = path.parent().ok_or_else(|| {
        stow_types::stow_error!("wrapper path {} has no parent directory", path.display())
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            stow_types::stow_error!(
                "wrapper path {} has invalid UTF-8 file name",
                path.display()
            )
        })?;
    let temp_path = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    // A crashed earlier run under a reused pid may have left its staging file.
    if fs::symlink_metadata(&temp_path).is_ok() {
        fs::remove_file(&temp_path)
            .wrap_err_with(|| format!("remove stale staging file {}", temp_path.display()))?;
    }
    Ok(temp_path)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::Path;

    use super::{
        REAL_CC_ENV, REAL_CXX_ENV, RESOLVE_CC, RESOLVE_CXX, WrapperRole, capture_executable_beside,
    };

    /// Every wrapper resolves to the runtime executable itself, so starting
    /// one costs exactly one process. The `sh` scripts this replaced cost a
    /// shell as well, on every compiler invocation in the build.
    #[cfg(unix)]
    #[test]
    fn unix_wrappers_are_the_runtime_under_another_name() {
        let base = std::env::temp_dir().join(format!("stow-shim-test-{}", std::process::id()));
        std::fs::create_dir_all(&base).expect("create the test tool dir");
        let runtime = base.join("runtime-executable");
        let capture = base.join("capture-executable");
        std::fs::write(&runtime, b"runtime").expect("write the runtime executable");
        std::fs::write(&capture, b"capture").expect("write the capture executable");

        let paths = super::materialize_wrapper_shims(&base, &runtime, &capture)
            .expect("materialize the wrapper shims");
        for wrapper in [
            &paths.rustc_wrapper,
            &paths.cc_launcher,
            &paths.cc_compiler,
            &paths.cxx_compiler,
        ] {
            assert_eq!(
                std::fs::read_link(wrapper).expect("wrapper is a link"),
                runtime,
                "{} does not resolve to the runtime",
                wrapper.display()
            );
            assert!(
                WrapperRole::from_program(wrapper).is_some(),
                "{} carries no role",
                wrapper.display()
            );
        }
        assert_eq!(
            std::fs::read_link(capture_executable_beside(&paths.rustc_wrapper))
                .expect("capture is a link"),
            capture
        );

        // Materialization is idempotent: a second run replaces the links in
        // place rather than failing on the existing ones.
        super::materialize_wrapper_shims(&base, &runtime, &capture)
            .expect("re-materialize the wrapper shims");
        std::fs::remove_dir_all(&base).expect("remove the test tool dir");
    }

    fn args(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    #[test]
    fn roles_are_recovered_from_wrapper_file_stems() {
        assert_eq!(
            WrapperRole::from_program(Path::new(
                "C:/Users/ci/AppData/Local/stow/tools/stow-rustc-wrapper.exe"
            )),
            Some(WrapperRole::Rustc)
        );
        assert_eq!(
            WrapperRole::from_program(Path::new(
                "/home/ci/.local/share/stow/tools/stow-cc-launcher"
            )),
            Some(WrapperRole::CcLauncher)
        );
        assert_eq!(
            WrapperRole::from_program(Path::new("stow-cc.exe")),
            Some(WrapperRole::Cc)
        );
        assert_eq!(
            WrapperRole::from_program(Path::new("stow-cxx")),
            Some(WrapperRole::Cxx)
        );
        assert_eq!(WrapperRole::from_program(Path::new("stow-cli.exe")), None);
        assert_eq!(WrapperRole::from_program(Path::new("cargo-stow")), None);
    }

    #[test]
    fn launcher_roles_prepend_only_the_subcommand() {
        assert_eq!(
            WrapperRole::Rustc.runtime_args(&args(&["/toolchain/bin/rustc", "-vV"])),
            args(&["rustc", "/toolchain/bin/rustc", "-vV"])
        );
        assert_eq!(
            WrapperRole::CcLauncher.runtime_args(&args(&["clang", "-c", "a.c"])),
            args(&["cc", "clang", "-c", "a.c"])
        );
    }

    #[test]
    fn compiler_roles_emit_the_resolve_marker_without_a_recorded_compiler() {
        // Safe here because nextest runs each test in its own process.
        unsafe {
            std::env::remove_var(REAL_CC_ENV);
            std::env::remove_var(REAL_CXX_ENV);
        }
        assert_eq!(
            WrapperRole::Cc.runtime_args(&args(&["-c", "a.c"])),
            args(&["cc", RESOLVE_CC, "-c", "a.c"])
        );
        assert_eq!(
            WrapperRole::Cxx.runtime_args(&args(&["-c", "a.cc"])),
            args(&["cc", RESOLVE_CXX, "-c", "a.cc"])
        );
    }

    #[test]
    fn capture_executable_sits_beside_the_wrapper() {
        let tools = Path::new("/home/ci/.local/share/stow/tools");
        let capture = capture_executable_beside(&tools.join("stow-rustc-wrapper"));
        assert_eq!(
            capture,
            tools.join(format!("stow-capture{}", std::env::consts::EXE_SUFFIX))
        );
    }
}
