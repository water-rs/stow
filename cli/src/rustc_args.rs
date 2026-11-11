use std::ffi::{OsStr, OsString};
use std::path::Path;

use async_process::Command;
use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Shared};
use tracing::Instrument as _;

use crate::session_env::SessionEnv;

pub use stow_types::rustc::ParsedRustcArgs;

pub const STOW_PUBLIC_CACHE_RUSTC_VERSION_ENV: &str = "STOW_PUBLIC_CACHE_RUSTC_VERSION";
pub const STOW_PUBLIC_CACHE_TARGET_ENV: &str = "STOW_PUBLIC_CACHE_TARGET";

#[tracing::instrument(name = "stow.rustc.probe.version", skip_all, fields(env_cache_hit))]
pub async fn detect_rustc_version(
    rustc: &std::ffi::OsStr,
    env: &SessionEnv,
) -> Result<String, String> {
    if let Some(version) = configured_public_cache_rustc_version(env) {
        tracing::Span::current().record("env_cache_hit", true);
        return Ok(version);
    }
    tracing::Span::current().record("env_cache_hit", false);

    let output = probe_command(rustc, env)?
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
pub async fn detect_rustc_host_target(
    rustc: &std::ffi::OsStr,
    env: &SessionEnv,
) -> Result<String, String> {
    if let Some(target) = configured_public_cache_target(env) {
        tracing::Span::current().record("env_cache_hit", true);
        return Ok(target);
    }
    tracing::Span::current().record("env_cache_hit", false);

    rustc_host_target(rustc, env).await
}

/// A command running the rustc `rustc` names in `env`: resolved through
/// its `PATH`, started with exactly its variables, in its working
/// directory. Probes of a build's rustc run in the build's environment —
/// under rustup `RUSTUP_TOOLCHAIN` and `PATH` pick the toolchain — never
/// in the probing process's own.
fn probe_command(rustc: &OsStr, env: &SessionEnv) -> Result<Command, String> {
    env.command(rustc)
        .map_err(|error| format!("{}: {error}", Path::new(rustc).display()))
}

/// The compiling rustc's own `host:` triple — a real `-vV` probe, never
/// the `STOW_PUBLIC_CACHE_TARGET` shortcut. The env carries the build's
/// *consumer* target, which is a different platform than the host a
/// unit without `--target` links for under a `--target` build (stow#317).
pub async fn rustc_host_target(
    rustc: &std::ffi::OsStr,
    env: &SessionEnv,
) -> Result<String, String> {
    vv_host(&rustc_vv(rustc, env).await?)
}

/// The raw stdout of one `rustc -vV` — the one probe every rustc-facts
/// consumer shares (stow#608): the host probe, the version probe and the
/// session base's facts all come out of this output, so pre-cargo
/// rustc spawns about rustc itself are exactly `-vV` and `--print
/// sysroot`, run concurrently.
pub async fn rustc_vv(rustc: &std::ffi::OsStr, env: &SessionEnv) -> Result<String, String> {
    let output = probe_command(rustc, env)?
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
    pub async fn facade_spelling(&self, env: &SessionEnv) -> Result<OsString, String> {
        match self {
            Self::Configured(rustc) => Ok(rustc.clone()),
            Self::ToolchainDefault => sysroot_rustc_executable(self.executable(), env).await,
        }
    }
}

/// The toolchain's own `rustc`, `<sysroot>/bin/rustc` — the string cargo
/// hands the build's rustc wrapper when neither `RUSTC` nor `build.rustc`
/// is set: cargo asks the rustup shim for its real rustc rather than
/// passing the bare name, and `rustc --print sysroot` answers the same
/// directory. `rustc` is the executable the probe runs — the build
/// rustc's [`BuildRustc::executable`].
async fn sysroot_rustc_executable(rustc: &OsStr, env: &SessionEnv) -> Result<OsString, String> {
    let output = probe_command(rustc, env)?
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
/// target and version facts, the session base's facts, and the link
/// resolution's key — so the probe spawns once.
pub type SharedRustcVv = Shared<BoxFuture<'static, Result<std::sync::Arc<String>, String>>>;

/// The one constructor every `SharedRustcVv` comes from: spawn the
/// `-vV` probe now, share the pending result. `rustc` is the build's
/// rustc — the configured one when `RUSTC` / `build.rustc` names one,
/// else the toolchain default (stow#608). The probe runs in `env`, the
/// build's environment.
pub fn shared_rustc_vv(rustc: std::ffi::OsString, env: SessionEnv) -> SharedRustcVv {
    let probe = tokio::spawn(
        async move { rustc_vv(&rustc, &env).await }
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

pub fn configured_public_cache_rustc_version(env: &SessionEnv) -> Option<String> {
    configured_text(env, STOW_PUBLIC_CACHE_RUSTC_VERSION_ENV)
}

pub fn configured_public_cache_target(env: &SessionEnv) -> Option<String> {
    configured_text(env, STOW_PUBLIC_CACHE_TARGET_ENV)
}

/// The non-blank Unicode value of `key` in `env`.
fn configured_text(env: &SessionEnv, key: &str) -> Option<String> {
    env.var_os(key)
        .and_then(OsStr::to_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
}

#[cfg(all(test, unix))]
mod tests {
    use std::ffi::OsStr;
    use std::os::unix::fs::PermissionsExt as _;

    use super::{
        STOW_PUBLIC_CACHE_TARGET_ENV, configured_public_cache_target, detect_rustc_host_target,
    };
    use crate::session_env::SessionEnv;

    /// The probe runs the `rustc` the build's `PATH` names, with the
    /// build's variables: a stub on a `PATH` only the environment holds
    /// answers `-vV`, and records what it saw.
    #[tokio::test]
    async fn the_rustc_probe_runs_in_the_builds_environment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let seen = dir.path().join("seen");
        let stub = dir.path().join("rustc");
        std::fs::write(
            &stub,
            "#!/bin/sh\necho \"$STOW_PROBE_MARK $1\" > \"$STOW_PROBE_SEEN\"\necho 'rustc 9.9.9 (stub)'\necho 'host: stub-host-triple'\necho 'release: 9.9.9'\n",
        )
        .expect("write the stub rustc");
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
            .expect("make the stub executable");
        let env = SessionEnv::for_tests([
            ("PATH", dir.path().as_os_str()),
            ("STOW_PROBE_MARK", OsStr::new("the-builds-variable")),
            ("STOW_PROBE_SEEN", seen.as_os_str()),
        ]);

        let vv = super::rustc_vv(OsStr::new("rustc"), &env)
            .await
            .expect("the stub answers -vV");
        assert_eq!(super::vv_host(&vv).as_deref(), Ok("stub-host-triple"));
        assert_eq!(
            std::fs::read_to_string(&seen).expect("the stub recorded its run"),
            "the-builds-variable -vV\n"
        );
        assert_eq!(
            detect_rustc_host_target(OsStr::new("rustc"), &env)
                .await
                .as_deref(),
            Ok("stub-host-triple")
        );
    }

    /// The public-cache target override is the environment's own.
    #[tokio::test]
    async fn the_public_cache_target_is_read_from_the_given_environment() {
        let env = SessionEnv::for_tests([(
            STOW_PUBLIC_CACHE_TARGET_ENV,
            OsStr::new("x86_64-unknown-linux-gnu"),
        )]);
        assert_eq!(
            configured_public_cache_target(&env).as_deref(),
            Some("x86_64-unknown-linux-gnu")
        );
        // The override short-circuits the probe: no rustc is on this
        // environment's (empty) `PATH`.
        assert_eq!(
            detect_rustc_host_target(OsStr::new("rustc"), &env)
                .await
                .as_deref(),
            Ok("x86_64-unknown-linux-gnu")
        );
        assert_eq!(
            configured_public_cache_target(&SessionEnv::for_tests([])),
            None
        );
    }
}
