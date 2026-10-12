use async_process::Command;
use futures_util::future::{BoxFuture, Shared};

pub use stow_types::rustc::ParsedRustcArgs;

pub const STOW_PUBLIC_CACHE_RUSTC_VERSION_ENV: &str = "STOW_PUBLIC_CACHE_RUSTC_VERSION";
pub const STOW_PUBLIC_CACHE_TARGET_ENV: &str = "STOW_PUBLIC_CACHE_TARGET";

/// Env channel carrying the rustc arguments a `stow`-supervised cargo run
/// appends to every unit — the workspace path remap plus any flags the run
/// itself selected — `\x1f`-joined like `CARGO_ENCODED_RUSTFLAGS`. A private
/// channel rather than `RUSTFLAGS`, because env rustflags replace the
/// user's configured rustflags outright: assigning `RUSTFLAGS` would make
/// cargo ignore `.cargo/config.toml` `target.*.rustflags` — the usual way
/// `-C link-arg=-fuse-ld=mold` is enabled — for the whole build.
pub const STOW_RUSTC_EXTRA_ARGS_ENV: &str = "STOW_RUSTC_EXTRA_ARGS";
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

    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("rustc -vV output is not UTF-8: {error}"))?;
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("host: ").map(str::to_owned))
        .ok_or_else(|| "rustc -vV output missing host target".to_owned())
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

/// One `rustc -vV` shared by every consumer — the project context's
/// target and version facts, the supervisor base's facts, and the link
/// resolution's key — so the probe spawns once.
pub type SharedRustcVv = Shared<BoxFuture<'static, Result<std::sync::Arc<String>, String>>>;

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
