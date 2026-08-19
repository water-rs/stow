use async_process::Command;

pub use stow_types::rustc::ParsedRustcArgs;

pub const STOW_PUBLIC_CACHE_RUSTC_VERSION_ENV: &str = "STOW_PUBLIC_CACHE_RUSTC_VERSION";
pub const STOW_PUBLIC_CACHE_TARGET_ENV: &str = "STOW_PUBLIC_CACHE_TARGET";

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

fn configured_public_cache_rustc_version() -> Option<String> {
    std::env::var(STOW_PUBLIC_CACHE_RUSTC_VERSION_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn configured_public_cache_target() -> Option<String> {
    std::env::var(STOW_PUBLIC_CACHE_TARGET_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
}
