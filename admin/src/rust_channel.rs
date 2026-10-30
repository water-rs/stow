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

/// The list of every channel manifest ever published, one
/// `static.rust-lang.org/dist/<date>/channel-rust-<name>.toml` line each.
const MANIFESTS_URL: &str = "https://static.rust-lang.org/manifests.txt";

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

/// `GET manifests.txt` → every stable rustc release, oldest first.
///
/// # Errors
/// Transport or status failures, or a manifest list of an unknown shape.
pub async fn stable_releases() -> stow_types::error::Result<Vec<WireRustcVersion>> {
    parse_stable_releases(&get_text(MANIFESTS_URL).await?)
}

/// The stable releases `manifests.txt` lists: the
/// `channel-rust-<major>.<minor>.<patch>.toml` entries, once each however
/// often a release was re-published. The `channel-rust-stable.toml`,
/// `-beta`, `-nightly`, `<major>.<minor>` and pre-release entries are not
/// releases. Every line must be a `channel-rust-*.toml` path, so a reply
/// of another shape fails instead of reading as "no releases".
fn parse_stable_releases(text: &str) -> stow_types::error::Result<Vec<WireRustcVersion>> {
    let mut releases = std::collections::BTreeSet::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let name = line
            .rsplit('/')
            .next()
            .and_then(|file| file.strip_prefix("channel-rust-"))
            .and_then(|file| file.strip_suffix(".toml"))
            .ok_or_else(|| stow_error!("manifests.txt line `{line}` is not a channel manifest"))?;
        if let Ok(version) = semver::Version::parse(name)
            && version.pre.is_empty()
            && version.build.is_empty()
        {
            releases.insert(version);
        }
    }
    if releases.is_empty() {
        return Err(stow_error!("manifests.txt lists no stable release"));
    }
    releases
        .into_iter()
        .map(|version| {
            WireRustcVersion::parse(version.to_string())
                .map_err(|error| stow_error!("release {version}: {error}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_stable_releases;

    const SAMPLE: &str = "\
static.rust-lang.org/dist/2016-03-08/channel-rust-nightly.toml
static.rust-lang.org/dist/2016-04-12/channel-rust-1.8.0.toml
static.rust-lang.org/dist/2016-04-14/channel-rust-1.8.0.toml
static.rust-lang.org/dist/2016-05-24/channel-rust-1.9.0.toml
static.rust-lang.org/dist/2026-10-01/channel-rust-1.99.0.toml
static.rust-lang.org/dist/2026-10-01/channel-rust-1.99.toml
static.rust-lang.org/dist/2026-10-01/channel-rust-stable.toml
static.rust-lang.org/dist/2026-10-15/channel-rust-1.99.1.toml
static.rust-lang.org/dist/2026-10-10/channel-rust-1.100.0-beta.2.toml
static.rust-lang.org/dist/2026-10-10/channel-rust-beta.toml
static.rust-lang.org/dist/2026-10-10/channel-rust-1.10.0.toml

";

    #[test]
    fn keeps_each_stable_release_once_in_version_order() {
        let releases = parse_stable_releases(SAMPLE).expect("parse");
        let names: Vec<String> = releases.iter().map(ToString::to_string).collect();
        assert_eq!(names, ["1.8.0", "1.9.0", "1.10.0", "1.99.0", "1.99.1"]);
    }

    #[test]
    fn a_reply_of_another_shape_fails() {
        for text in [
            "<html>moved</html>",
            "static.rust-lang.org/dist/2016-04-12/channel-rust-1.8.0.toml\nnot a path",
            "static.rust-lang.org/dist/2016-03-08/channel-rust-nightly.toml\n",
            "",
        ] {
            assert!(parse_stable_releases(text).is_err(), "{text:?}");
        }
    }
}
