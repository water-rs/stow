use std::ffi::{OsStr, OsString};
use std::path::Path;

use async_process::Command;
use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Shared};
use tracing::Instrument as _;

pub use stow_types::rustc::ParsedRustcArgs;

pub const STOW_PUBLIC_CACHE_RUSTC_VERSION_ENV: &str = "STOW_PUBLIC_CACHE_RUSTC_VERSION";
pub const STOW_PUBLIC_CACHE_TARGET_ENV: &str = "STOW_PUBLIC_CACHE_TARGET";

/// Env channel carrying the rustc argument a `stow`-supervised cargo run
/// appends to every unit — the workspace path remap. It names a JSON
/// `Vec<String>` build file rather than carrying the list itself — the
/// same file-table channel the build's other generated payloads use
/// (stow#625). A private channel
/// rather than `RUSTFLAGS`, because env rustflags replace the user's
/// configured rustflags outright: assigning `RUSTFLAGS` would make cargo
/// ignore `.cargo/config.toml` `target.*.rustflags` — the usual way
/// `-C link-arg=-fuse-ld=mold` is enabled — for the whole build.
pub const STOW_RUSTC_EXTRA_ARGS_FILE_ENV: &str = "STOW_RUSTC_EXTRA_ARGS_FILE";

/// The extra rustc arguments the driver named on the environment —
/// empty when the variable is unset.
///
/// # Errors
///
/// A set variable whose file is missing or malformed is a wiring bug and
/// fails loudly, naming the path — the same contract the build's other
/// table files follow (stow#625).
pub fn extra_args_from_env() -> stow_types::error::Result<Vec<std::ffi::OsString>> {
    let Some(path) = std::env::var_os(STOW_RUSTC_EXTRA_ARGS_FILE_ENV) else {
        return Ok(Vec::new());
    };
    let path = std::path::PathBuf::from(path);
    let args = crate::read_build_json_table::<Vec<String>>(&path, STOW_RUSTC_EXTRA_ARGS_FILE_ENV)?;
    Ok(args.into_iter().map(std::ffi::OsString::from).collect())
}
#[tracing::instrument(name = "stow.rustc.probe.version", skip_all, fields(env_cache_hit))]
pub async fn detect_rustc_version(rustc: &std::ffi::OsStr) -> Result<String, String> {
    if let Some(version) = configured_public_cache_rustc_version() {
        tracing::Span::current().record("env_cache_hit", true);
        return Ok(version);
    }
    tracing::Span::current().record("env_cache_hit", false);

    let output = Command::new(rustc)
        .arg("--version")
        .output()
        .await
        .map_err(|error| format!("spawn rustc --version: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "rustc --version failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("rustc --version output is not UTF-8: {error}"))?;
    stdout
        .split_whitespace()
        .nth(1)
        .map(str::to_owned)
        .ok_or_else(|| "rustc --version output missing semantic version".to_owned())
}

#[tracing::instrument(name = "stow.rustc.probe.host", skip_all, fields(env_cache_hit))]
pub async fn detect_rustc_host_target(rustc: &std::ffi::OsStr) -> Result<String, String> {
    if let Some(target) = configured_public_cache_target() {
        tracing::Span::current().record("env_cache_hit", true);
        return Ok(target);
    }
    tracing::Span::current().record("env_cache_hit", false);

    rustc_host_target(rustc).await
}

/// The compiling rustc's own `host:` triple — a real `-vV` probe, never
/// the `STOW_PUBLIC_CACHE_TARGET` shortcut. The env carries the build's
/// *consumer* target, which is a different platform than the host a
/// unit without `--target` links for under a `--target` build (stow#317).
pub async fn rustc_host_target(rustc: &std::ffi::OsStr) -> Result<String, String> {
    vv_host(&rustc_vv(rustc).await?)
}

/// The raw stdout of one `rustc -vV` — the one probe every rustc-facts
/// consumer shares (stow#608): the host probe, the version probe and the
/// supervisor base's facts all come out of this output, so pre-cargo
/// rustc spawns about rustc itself are exactly `-vV` and `--print
/// sysroot`, run concurrently.
pub async fn rustc_vv(rustc: &std::ffi::OsStr) -> Result<String, String> {
    let output = Command::new(rustc)
        .arg("-vV")
        .output()
        .await
        .map_err(|error| format!("spawn rustc -vV: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "rustc -vV failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| format!("rustc -vV output is not UTF-8: {error}"))
}

/// The `host:` triple out of `rustc -vV` output.
pub fn vv_host(vv: &str) -> Result<String, String> {
    vv.lines()
        .find_map(|line| line.strip_prefix("host: ").map(str::to_owned))
        .ok_or_else(|| "rustc -vV output missing host target".to_owned())
}

/// The `release:` version out of `rustc -vV` output — the same string
/// `rustc --version` reports as its second word, so sharing `-vV`
/// retires the separate `--version` spawn (stow#608).
pub fn vv_release(vv: &str) -> Result<String, String> {
    vv.lines()
        .find_map(|line| line.strip_prefix("release: ").map(str::to_owned))
        .ok_or_else(|| "rustc -vV output missing release".to_owned())
}

/// The rustc a build compiles with, as cargo resolves it: the
/// configured `RUSTC`/`build.rustc` when one is set — cargo hands its
/// rustc wrapper that spelling verbatim — else the toolchain's own
/// `rustc` (stow#608).
#[derive(Debug, Clone)]
pub enum BuildRustc {
    /// No `RUSTC`/`build.rustc` configured: the toolchain's own `rustc`
    /// — the bare name cargo resolves, through the rustup shim when one
    /// proxies it.
    ToolchainDefault,
    /// `RUSTC`/`build.rustc` set: the spelling cargo hands its rustc
    /// wrapper and the toolchain probes verbatim.
    Configured(OsString),
}

impl BuildRustc {
    /// The build's rustc as a loaded cargo config chain resolves it —
    /// `build.rustc` covers the `RUSTC`/`CARGO_BUILD_RUSTC` environment
    /// and the config files alike.
    pub fn from_cargo_config(config: &cargo_config2::Config) -> Self {
        config
            .build
            .rustc
            .clone()
            .map_or(Self::ToolchainDefault, |rustc| {
                Self::Configured(rustc.into_os_string())
            })
    }

    /// The executable to spawn when this rustc is asked anything — a
    /// `-vV`, a `--print` query: the configured spelling, or the bare
    /// name the toolchain resolves.
    pub fn executable(&self) -> &OsStr {
        match self {
            Self::ToolchainDefault => OsStr::new("rustc"),
            Self::Configured(rustc) => rustc,
        }
    }

    /// The spelling the build's facades report for this rustc: the
    /// configured one verbatim, or the toolchain's
    /// `<sysroot>/bin/rustc` — the path cargo hands its wrapper when it
    /// asks the rustup shim for the real rustc.
    pub async fn facade_spelling(&self) -> Result<OsString, String> {
        match self {
            Self::Configured(rustc) => Ok(rustc.clone()),
            Self::ToolchainDefault => sysroot_rustc_executable(self.executable()).await,
        }
    }
}

/// The toolchain's own `rustc`, `<sysroot>/bin/rustc` — the string cargo
/// hands the build's rustc wrapper when neither `RUSTC` nor `build.rustc`
/// is set: cargo asks the rustup shim for its real rustc rather than
/// passing the bare name, and `rustc --print sysroot` answers the same
/// directory. `rustc` is the executable the probe runs — the build
/// rustc's [`BuildRustc::executable`].
async fn sysroot_rustc_executable(rustc: &OsStr) -> Result<OsString, String> {
    let output = Command::new(rustc)
        .arg("--print")
        .arg("sysroot")
        .output()
        .await
        .map_err(|error| format!("spawn rustc --print sysroot: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "rustc --print sysroot failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let sysroot = String::from_utf8(output.stdout)
        .map_err(|error| format!("rustc --print sysroot output is not UTF-8: {error}"))?;
    Ok(Path::new(sysroot.trim())
        .join("bin")
        .join(format!("rustc{}", std::env::consts::EXE_SUFFIX))
        .into_os_string())
}

/// One `rustc -vV` shared by every consumer — the project context's
/// target and version facts, the supervisor base's facts, and the link
/// resolution's key — so the probe spawns once.
pub type SharedRustcVv = Shared<BoxFuture<'static, Result<std::sync::Arc<String>, String>>>;

/// The one constructor every `SharedRustcVv` comes from: spawn the
/// `-vV` probe now, share the pending result. `rustc` is the build's
/// rustc — the configured one when `RUSTC` / `build.rustc` names one,
/// else the toolchain default (stow#608).
pub fn shared_rustc_vv(rustc: std::ffi::OsString) -> SharedRustcVv {
    let probe = tokio::spawn(
        async move { rustc_vv(&rustc).await }
            .instrument(tracing::debug_span!("stow.precargo.rustc_vv_probe")),
    );
    async move {
        match probe.await {
            Ok(result) => result.map(std::sync::Arc::new),
            Err(error) => Err(format!("join rustc -vV probe task: {error}")),
        }
    }
    .boxed()
    .shared()
}

pub fn configured_public_cache_rustc_version() -> Option<String> {
    std::env::var(STOW_PUBLIC_CACHE_RUSTC_VERSION_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

pub fn configured_public_cache_target() -> Option<String> {
    std::env::var(STOW_PUBLIC_CACHE_TARGET_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
}
