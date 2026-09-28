//! The stable rustc a lane builds against, read straight from the Rust
//! release channel manifest — the same `channel-rust-stable.toml` lookup
//! the preheat workflows used to leave to the edge's scheduler-cached
//! copy. `pkg.rustc.version` parses to the numeric portion only
//! (`"1.98.1 (hash date)"` → `1.98.1`).

use stow_types::identity::{WireRustcVersion, parse_channel_rustc_version};
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
