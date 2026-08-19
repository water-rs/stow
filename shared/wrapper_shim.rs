use std::fs;
use std::path::{Path, PathBuf};

use eyre::Context;

const MACOS_TOOLS_BASE: &str = "/private/tmp/stow-tools";
const UNIX_TOOLS_BASE: &str = "/tmp/stow-tools";
const WINDOWS_TOOLS_BASE: &str = "C:\\stow-tools";
const RUSTC_WRAPPER_PATH: &str = "stow-rustc-wrapper";
const CC_LAUNCHER_PATH: &str = "stow-cc-launcher";
const CC_COMPILER_PATH: &str = "stow-cc";
const CXX_COMPILER_PATH: &str = "stow-cxx";
const RUNTIME_LINK_PATH: &str = "stow-runtime";
const CAPTURE_LINK_PATH: &str = "stow-capture";

// Shared between the CLI and the CI builder, which use different subsets.
#[allow(dead_code)]
pub struct WrapperShimPaths {
    /// `RUSTC_WRAPPER`: invoked as `<shim> <rustc> <args...>`.
    pub rustc_wrapper: PathBuf,
    /// `CMAKE_*_COMPILER_LAUNCHER`: invoked as `<shim> <compiler> <args...>`.
    pub cc_launcher: PathBuf,
    /// `CC`: invoked as `<shim> <args...>`, standing in for the C compiler.
    pub cc_compiler: PathBuf,
    /// `CXX`: invoked as `<shim> <args...>`, standing in for the C++ compiler.
    pub cxx_compiler: PathBuf,
}

/// Env var naming the real C compiler the `CC` shim delegates to.
pub const STOW_REAL_CC_ENV: &str = "STOW_REAL_CC";
/// Env var naming the real C++ compiler the `CXX` shim delegates to.
pub const STOW_REAL_CXX_ENV: &str = "STOW_REAL_CXX";

pub fn materialize_wrapper_shims(
    runtime_executable: &Path,
    capture_executable: &Path,
) -> eyre::Result<WrapperShimPaths> {
    let base = tools_base();
    fs::create_dir_all(&base)
        .wrap_err_with(|| format!("create wrapper tool base {}", base.display()))?;

    let runtime_link = base.join(RUNTIME_LINK_PATH);
    let capture_link = base.join(CAPTURE_LINK_PATH);
    let rustc_wrapper_path = base.join(wrapper_file_name(RUSTC_WRAPPER_PATH));
    let cc_launcher_path = base.join(wrapper_file_name(CC_LAUNCHER_PATH));
    let cc_compiler_path = base.join(wrapper_file_name(CC_COMPILER_PATH));
    let cxx_compiler_path = base.join(wrapper_file_name(CXX_COMPILER_PATH));

    replace_link(&runtime_link, runtime_executable)?;
    replace_link(&capture_link, capture_executable)?;
    write_wrapper_script(&rustc_wrapper_path, &runtime_link, &capture_link, "rustc")?;
    write_wrapper_script(&cc_launcher_path, &runtime_link, &capture_link, "cc-launcher")?;
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
) -> eyre::Result<()> {
    let contents = wrapper_script_contents(runtime_link, capture_link, subcommand)?;
    if wrapper_path.exists() {
        let existing = fs::read_to_string(wrapper_path)
            .wrap_err_with(|| format!("read wrapper shim {}", wrapper_path.display()))?;
        if existing == contents {
            return Ok(());
        }
    }
    fs::write(wrapper_path, contents)
        .wrap_err_with(|| format!("write wrapper shim {}", wrapper_path.display()))?;
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(wrapper_path)
            .wrap_err_with(|| format!("stat wrapper shim {}", wrapper_path.display()))?
            .permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o755);
        fs::set_permissions(wrapper_path, perms)
            .wrap_err_with(|| format!("chmod wrapper shim {}", wrapper_path.display()))?;
    }
    Ok(())
}

fn wrapper_script_contents(
    runtime_link: &Path,
    capture_link: &Path,
    subcommand: &str,
) -> eyre::Result<String> {
    #[cfg(unix)]
    {
        let runtime = runtime_link.to_str().ok_or_else(|| {
            eyre::eyre!(
                "wrapper runtime path {} is not UTF-8",
                runtime_link.display()
            )
        })?;
        let capture = capture_link.to_str().ok_or_else(|| {
            eyre::eyre!(
                "wrapper capture path {} is not UTF-8",
                capture_link.display()
            )
        })?;
        return Ok(match subcommand {
            "rustc" => format!(
                "#!/bin/sh\nif [ -n \"$STOW_BUILD_RUSTC_CAPTURE_DIR\" ]; then\n  exec \"{capture}\" rustc \"$@\"\nfi\nexec \"{runtime}\" rustc \"$@\"\n"
            ),
            // Compiler-launcher contract: the compiler to run is argv[1].
            "cc-launcher" => format!("#!/bin/sh\nexec \"{runtime}\" cc \"$@\"\n"),
            // Compiler contract: `CC`/`CXX` are invoked with compiler
            // arguments only, so the shim supplies the real compiler itself.
            "cc" => format!(
                "#!/bin/sh\nexec \"{runtime}\" cc \"${{{STOW_REAL_CC_ENV}:-cc}}\" \"$@\"\n"
            ),
            "cxx" => format!(
                "#!/bin/sh\nexec \"{runtime}\" cc \"${{{STOW_REAL_CXX_ENV}:-c++}}\" \"$@\"\n"
            ),
            other => {
                return Err(eyre::eyre!("unsupported wrapper shim subcommand {other}"));
            }
        });
    }
    #[cfg(windows)]
    {
        let runtime = runtime_link.to_str().ok_or_else(|| {
            eyre::eyre!(
                "wrapper runtime path {} is not UTF-8",
                runtime_link.display()
            )
        })?;
        let capture = capture_link.to_str().ok_or_else(|| {
            eyre::eyre!(
                "wrapper capture path {} is not UTF-8",
                capture_link.display()
            )
        })?;
        return Ok(match subcommand {
            "rustc" => format!(
                "@echo off\r\nif not \"%STOW_BUILD_RUSTC_CAPTURE_DIR%\"==\"\" (\r\n  \"{capture}\" rustc %*\r\n  exit /b %ERRORLEVEL%\r\n)\r\n\"{runtime}\" rustc %*\r\n"
            ),
            "cc-launcher" => format!("@echo off\r\n\"{runtime}\" cc %*\r\n"),
            "cc" => format!(
                "@echo off\r\nset \"STOW_CC={STOW_REAL_CC_ENV_VALUE}\"\r\nif \"%STOW_CC%\"==\"\" set \"STOW_CC=cc\"\r\n\"{runtime}\" cc \"%STOW_CC%\" %*\r\n",
                STOW_REAL_CC_ENV_VALUE = format!("%{STOW_REAL_CC_ENV}%")
            ),
            "cxx" => format!(
                "@echo off\r\nset \"STOW_CXX={STOW_REAL_CXX_ENV_VALUE}\"\r\nif \"%STOW_CXX%\"==\"\" set \"STOW_CXX=c++\"\r\n\"{runtime}\" cc \"%STOW_CXX%\" %*\r\n",
                STOW_REAL_CXX_ENV_VALUE = format!("%{STOW_REAL_CXX_ENV}%")
            ),
            other => {
                return Err(eyre::eyre!("unsupported wrapper shim subcommand {other}"));
            }
        });
    }
}

fn replace_link(link_path: &Path, target: &Path) -> eyre::Result<()> {
    if link_path.exists() || link_path.is_symlink() {
        remove_existing_path(link_path)?;
    }
    create_link(target, link_path).wrap_err_with(|| {
        format!(
            "create wrapper tool link {} -> {}",
            link_path.display(),
            target.display()
        )
    })
}

fn remove_existing_path(path: &Path) -> eyre::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("stat existing wrapper path {}", path.display()))?;
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)
            .wrap_err_with(|| format!("remove existing wrapper dir {}", path.display()))
    } else {
        fs::remove_file(path)
            .wrap_err_with(|| format!("remove existing wrapper file {}", path.display()))
    }
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

#[cfg(unix)]
fn create_link(target: &Path, link_path: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link_path)
}

#[cfg(windows)]
fn create_link(target: &Path, link_path: &Path) -> std::io::Result<()> {
    let metadata = fs::metadata(target)?;
    if metadata.is_dir() {
        std::os::windows::fs::symlink_dir(target, link_path)
    } else {
        std::os::windows::fs::symlink_file(target, link_path)
    }
}
