//! The stable rustc a lane builds against, read straight from the Rust
//! release channel manifest — the same `channel-rust-stable.toml` lookup
//! the preheat workflows used to leave to the edge's scheduler-cached
//! copy. `pkg.rustc.version` parses to the numeric portion only
//! (`"1.98.1 (hash date)"` → `1.98.1`). The release history the launch
//! model's stable-release cadence counts is read from here too.

use stow_types::identity::{WireRustcVersion, parse_channel_rustc_version};
use stow_types::stow_error;
use zenwave::{Client as _, ResponseExt as _};

/// Manifest endpoint for the stable channel.
const CHANNEL_MANIFEST_URL: &str = "https://static.rust-lang.org/dist/channel-rust-stable.toml";

/// Rust's published release notes — one `Version X.Y.Z (YYYY-MM-DD)`
/// heading per stable release, point releases included.
const RELEASE_NOTES_URL: &str =
    "https://raw.githubusercontent.com/rust-lang/rust/master/RELEASES.md";

/// `GET url` → the response body.
async fn get_text(url: &str) -> stow_types::error::Result<String> {
    let mut client = zenwave::client();
    let response = client
        .get(url)
        .map_err(|error| stow_error!("GET {url}: {error}"))?
        .await
        .map_err(|error| stow_error!("GET {url}: {error}"))?;
    response
        .error_for_status()
        .await
        .map_err(|error| stow_error!("GET {url}: {error}"))?
        .into_string()
        .await
        .map(|body| body.to_string())
        .map_err(|error| stow_error!("read {url}: {error}"))
}

/// `GET channel-rust-stable.toml` → the stable rustc version.
///
/// # Errors
/// Transport, status, or manifest-shape failures.
pub async fn stable_rustc_version() -> stow_types::error::Result<WireRustcVersion> {
    parse_channel_rustc_version(&get_text(CHANNEL_MANIFEST_URL).await?)
}

/// `GET RELEASES.md` → Rust's release history, newest first.
///
/// # Errors
/// Transport or status failures.
pub async fn release_notes() -> stow_types::error::Result<String> {
    get_text(RELEASE_NOTES_URL).await
}
