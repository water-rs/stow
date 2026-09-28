//! The stable rustc a lane builds against, read straight from the Rust
//! release channel manifest — the same `channel-rust-stable.toml` lookup
//! the preheat workflows used to leave to the edge's scheduler-cached
//! copy. `pkg.rustc.version` parses to the numeric portion only
//! (`"1.98.1 (hash date)"` → `1.98.1`).

use stow_types::error::Context as _;
use stow_types::identity::WireRustcVersion;
use stow_types::stow_error;
use zenwave::{Client as _, ResponseExt as _};

/// Manifest endpoint for the stable channel.
const CHANNEL_MANIFEST_URL: &str = "https://static.rust-lang.org/dist/channel-rust-stable.toml";

/// `GET channel-rust-stable.toml` → the stable rustc version.
///
/// # Errors
/// Transport, status, or manifest-shape failures.
pub async fn stable_rustc_version() -> stow_types::error::Result<WireRustcVersion> {
    let mut client = zenwave::client();
    let manifest = client
        .get(CHANNEL_MANIFEST_URL)
        .map_err(|error| stow_error!("GET {CHANNEL_MANIFEST_URL}: {error}"))?
        .await
        .map_err(|error| stow_error!("GET {CHANNEL_MANIFEST_URL}: {error}"))?;
    let text = manifest
        .error_for_status()
        .await
        .map_err(|error| stow_error!("GET {CHANNEL_MANIFEST_URL}: {error}"))?
        .into_string()
        .await
        .map_err(|error| stow_error!("read {CHANNEL_MANIFEST_URL}: {error}"))?;
    parse_channel_rustc_version(&text)
}

/// `[pkg.rustc].version`'s leading semver out of the manifest text.
fn parse_channel_rustc_version(manifest: &str) -> stow_types::error::Result<WireRustcVersion> {
    let document: toml::Table =
        toml::from_str(manifest).wrap_err("channel-rust-stable.toml is not TOML")?;
    let raw = document
        .get("pkg")
        .and_then(|pkg| pkg.get("rustc"))
        .and_then(|rustc| rustc.get("version"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| stow_error!("channel manifest has no pkg.rustc.version"))?;
    let numeric = raw
        .split_whitespace()
        .next()
        .ok_or_else(|| stow_error!("channel manifest rustc version is empty"))?;
    WireRustcVersion::parse(numeric.to_owned())
        .wrap_err_with(|| format!("channel manifest rustc version `{numeric}`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_decorated_version() {
        let manifest = "[pkg.rustc]\nversion = \"1.98.1 (04b871bb4 2026-01-01)\"\n";
        assert_eq!(
            parse_channel_rustc_version(manifest).unwrap().as_str(),
            "1.98.1"
        );
    }

    #[test]
    fn missing_version_is_an_error() {
        assert!(parse_channel_rustc_version("[pkg.rustc]\n").is_err());
    }
}
