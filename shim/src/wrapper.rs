//! Wrapper-shim materialization for native targets.

use std::fs;
use std::path::{Path, PathBuf};

use stow_types::error::Context;

const MACOS_TOOLS_BASE: &str = "/private/tmp/stow-tools";
const UNIX_TOOLS_BASE: &str = "/tmp/stow-tools";
const WINDOWS_TOOLS_BASE: &str = "C:\\stow-tools";
const RUSTC_WRAPPER_PATH: &str = "stow-rustc-wrapper";
const CC_LAUNCHER_PATH: &str = "stow-cc-launcher";
const CC_COMPILER_PATH: &str = "stow-cc";
const CXX_COMPILER_PATH: &str = "stow-cxx";
const RUNTIME_LINK_PATH: &str = "stow-runtime";
const CAPTURE_LINK_PATH: &str = "stow-capture";

/// Filesystem paths to the materialized rustc / cc wrapper scripts.
///
/// `cc_launcher` and `cc_compiler` differ by calling convention, and using one
/// where the other belongs breaks every C build. `RUSTC_WRAPPER` and
/// `CMAKE_*_COMPILER_LAUNCHER` are *launchers*: the program to run arrives as
/// the first argument. `CC` and `CXX` are not — they are invoked with compiler
/// arguments only, so a launcher-shaped shim tries to execute the first flag.
#[derive(Debug)]
pub struct WrapperShimPaths {
    /// Path to the rustc wrapper script.
    pub rustc_wrapper: PathBuf,
    /// Launcher-shaped cc shim, for `CMAKE_*_COMPILER_LAUNCHER`.
    pub cc_launcher: PathBuf,
    /// Compiler-shaped cc shim, for `CC`.
    pub cc_compiler: PathBuf,
    /// Compiler-shaped c++ shim, for `CXX`.
    pub cxx_compiler: PathBuf,
}

/// Idempotently materialize the rustc / cc wrapper scripts under
/// `/tmp/stow-tools/` (or platform equivalent), and point them at the
/// supplied runtime / capture executables.
///
/// Every replacement is a temp-file-plus-rename, so a wrapper that cargo is
/// executing concurrently sees either the old or the new script, never a
/// partially written one.
///
/// # Errors
/// Returns an error when the tool directory cannot be created, a link or
/// script cannot be written or renamed into place, or a wrapper path is not
/// valid UTF-8.
pub fn materialize_wrapper_shims(
    runtime_executable: &Path,
    capture_executable: &Path,
) -> stow_types::error::Result<WrapperShimPaths> {
    let base = tools_base();
    fs::create_dir_all(&base)
        .wrap_err_with(|| format!("create wrapper tool base {}", base.display()))?;

    let rustc_wrapper_path = base.join(wrapper_file_name(RUSTC_WRAPPER_PATH));
    let cc_launcher_path = base.join(wrapper_file_name(CC_LAUNCHER_PATH));
    let cc_compiler_path = base.join(wrapper_file_name(CC_COMPILER_PATH));
    let cxx_compiler_path = base.join(wrapper_file_name(CXX_COMPILER_PATH));

    let runtime_link = executable_reference(&base, RUNTIME_LINK_PATH, runtime_executable)?;
    let capture_link = executable_reference(&base, CAPTURE_LINK_PATH, capture_executable)?;
    write_wrapper_script(&rustc_wrapper_path, &runtime_link, &capture_link, "rustc")?;
    write_wrapper_script(
        &cc_launcher_path,
        &runtime_link,
        &capture_link,
        "cc-launcher",
    )?;
    write_wrapper_script(&cc_compiler_path, &runtime_link, &capture_link, "cc")?;
    write_wrapper_script(&cxx_compiler_path, &runtime_link, &capture_link, "cxx")?;

    Ok(WrapperShimPaths {
        rustc_wrapper: rustc_wrapper_path,
        cc_launcher: cc_launcher_path,
        cc_compiler: cc_compiler_path,
        cxx_compiler: cxx_compiler_path,
    })
}

fn write_wrapper_script(
    wrapper_path: &Path,
    runtime_link: &Path,
    capture_link: &Path,
    subcommand: &str,
) -> stow_types::error::Result<()> {
    let contents = wrapper_script_contents(runtime_link, capture_link, subcommand)?;
    if wrapper_path.exists() {
        let existing = fs::read_to_string(wrapper_path)
            .wrap_err_with(|| format!("read wrapper shim {}", wrapper_path.display()))?;
        if existing == contents {
            return Ok(());
        }
    }
    let temp_path = staging_path(wrapper_path)?;
    fs::write(&temp_path, contents)
        .wrap_err_with(|| format!("write wrapper shim {}", temp_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&temp_path)
            .wrap_err_with(|| format!("stat wrapper shim {}", temp_path.display()))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&temp_path, perms)
            .wrap_err_with(|| format!("chmod wrapper shim {}", temp_path.display()))?;
    }
    fs::rename(&temp_path, wrapper_path).map_err(|error| {
        let _ = fs::remove_file(&temp_path);
        stow_types::stow_error!(
            "atomically replace wrapper shim {}: {error}",
            wrapper_path.display()
        )
    })
}

/// The wrapper scripts reach the executables through a symlink, so the
/// scripts (whose paths cargo fingerprints) stay byte-identical when stow is
/// upgraded or relocated.
#[cfg(unix)]
fn executable_reference(
    base: &Path,
    link_name: &str,
    executable: &Path,
) -> stow_types::error::Result<PathBuf> {
    let link_path = base.join(link_name);
    replace_link_atomic(&link_path, executable)?;
    Ok(link_path)
}

/// Windows symlinks need a privilege ordinary accounts lack, and `cmd` only
/// executes files carrying an executable extension, so the batch scripts name
/// the executable directly; the script is rewritten in place when it moves.
#[cfg(windows)]
fn executable_reference(
    _base: &Path,
    _link_name: &str,
    executable: &Path,
) -> stow_types::error::Result<PathBuf> {
    Ok(executable.to_path_buf())
}

#[cfg(unix)]
fn wrapper_script_contents(
    runtime_link: &Path,
    capture_link: &Path,
    subcommand: &str,
) -> stow_types::error::Result<String> {
    let runtime = runtime_link.to_str().ok_or_else(|| {
        stow_types::stow_error!(
            "wrapper runtime path {} is not UTF-8",
            runtime_link.display()
        )
    })?;
    let capture = capture_link.to_str().ok_or_else(|| {
        stow_types::stow_error!(
            "wrapper capture path {} is not UTF-8",
            capture_link.display()
        )
    })?;
    Ok(match subcommand {
        "rustc" => format!(
            "#!/bin/sh\nif [ -n \"$STOW_BUILD_RUSTC_CAPTURE_DIR\" ]; then\n  exec \"{capture}\" rustc \"$@\"\nfi\nexec \"{runtime}\" rustc \"$@\"\n"
        ),
        // Launcher form: cargo/cmake pass the real compiler as argv[1].
        "cc-launcher" => format!("#!/bin/sh\nexec \"{runtime}\" cc \"$@\"\n"),
        // Compiler form: nothing supplies the executable, so the shim does.
        // `STOW_REAL_CC` / `STOW_REAL_CXX` carry whatever the caller had set
        // before stow overwrote CC/CXX, so an explicit toolchain survives.
        "cc" => format!("#!/bin/sh\nexec \"{runtime}\" cc \"${{STOW_REAL_CC:-cc}}\" \"$@\"\n"),
        "cxx" => format!("#!/bin/sh\nexec \"{runtime}\" cc \"${{STOW_REAL_CXX:-c++}}\" \"$@\"\n"),
        other => {
            return Err(stow_types::stow_error!(
                "unsupported wrapper shim subcommand {other}"
            ));
        }
    })
}

#[cfg(windows)]
fn wrapper_script_contents(
    runtime_link: &Path,
    capture_link: &Path,
    subcommand: &str,
) -> stow_types::error::Result<String> {
    let runtime = runtime_link.to_str().ok_or_else(|| {
        stow_types::stow_error!(
            "wrapper runtime path {} is not UTF-8",
            runtime_link.display()
        )
    })?;
    let capture = capture_link.to_str().ok_or_else(|| {
        stow_types::stow_error!(
            "wrapper capture path {} is not UTF-8",
            capture_link.display()
        )
    })?;
    Ok(match subcommand {
        "rustc" => format!(
            "@echo off\r\nif not \"%STOW_BUILD_RUSTC_CAPTURE_DIR%\"==\"\" (\r\n  \"{capture}\" rustc %*\r\n  exit /b %ERRORLEVEL%\r\n)\r\n\"{runtime}\" rustc %*\r\n"
        ),
        "cc-launcher" => format!("@echo off\r\n\"{runtime}\" cc %*\r\n"),
        "cc" => format!(
            "@echo off\r\nif \"%STOW_REAL_CC%\"==\"\" (set STOW_REAL_CC=cc)\r\n\"{runtime}\" cc \"%STOW_REAL_CC%\" %*\r\n"
        ),
        "cxx" => format!(
            "@echo off\r\nif \"%STOW_REAL_CXX%\"==\"\" (set STOW_REAL_CXX=c++)\r\n\"{runtime}\" cc \"%STOW_REAL_CXX%\" %*\r\n"
        ),
        other => {
            return Err(stow_types::stow_error!(
                "unsupported wrapper shim subcommand {other}"
            ));
        }
    })
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

fn tools_base() -> PathBuf {
    if cfg!(target_os = "macos") {
        return PathBuf::from(MACOS_TOOLS_BASE);
    }
    if cfg!(windows) {
        return PathBuf::from(WINDOWS_TOOLS_BASE);
    }
    PathBuf::from(UNIX_TOOLS_BASE)
}

fn wrapper_file_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.cmd")
    } else {
        base.to_owned()
    }
}
