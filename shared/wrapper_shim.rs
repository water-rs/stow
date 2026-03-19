use std::fs;
use std::path::{Path, PathBuf};

use eyre::Context;

const MACOS_TOOLS_BASE: &str = "/private/tmp/stow-tools";
const UNIX_TOOLS_BASE: &str = "/tmp/stow-tools";
const WINDOWS_TOOLS_BASE: &str = "C:\\stow-tools";
const RUSTC_WRAPPER_PATH: &str = "stow-rustc-wrapper";
const CC_WRAPPER_PATH: &str = "stow-cc-wrapper";
const RUNTIME_LINK_PATH: &str = "stow-runtime";
const CAPTURE_LINK_PATH: &str = "stow-capture";

pub struct WrapperShimPaths {
    pub rustc_wrapper: PathBuf,
    pub cc_wrapper: PathBuf,
}

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
    let cc_wrapper_path = base.join(wrapper_file_name(CC_WRAPPER_PATH));

    replace_link(&runtime_link, runtime_executable)?;
    replace_link(&capture_link, capture_executable)?;
    write_wrapper_script(&rustc_wrapper_path, &runtime_link, &capture_link, "rustc")?;
    write_wrapper_script(&cc_wrapper_path, &runtime_link, &capture_link, "cc")?;

    Ok(WrapperShimPaths {
        rustc_wrapper: rustc_wrapper_path,
        cc_wrapper: cc_wrapper_path,
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
            "cc" => format!("#!/bin/sh\nexec \"{runtime}\" cc \"$@\"\n"),
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
            "cc" => format!("@echo off\r\n\"{runtime}\" cc %*\r\n"),
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
