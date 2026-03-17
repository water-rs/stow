use skyzen_services::Kv;
use zenwave::Client;

const RUST_STABLE_CHANNEL_URL: &str = "https://static.rust-lang.org/dist/channel-rust-stable.toml";
const RUST_STABLE_STATE_KEY: &str = "rustc-stable-version";
const RUST_CHANNEL_USER_AGENT: &str = "stow-watcher";

pub async fn detect_new_stable(state_kv: &Kv) -> Result<Option<String>, String> {
    let latest_version = fetch_stable_rust_version().await?;
    let previous_version = state_kv
        .get_text(RUST_STABLE_STATE_KEY)
        .await
        .map_err(|error| format!("read rustc stable watcher state: {error}"))?;

    if previous_version.as_deref() == Some(latest_version.as_str()) {
        return Ok(None);
    }

    tracing::info!(
        previous_version = ?previous_version,
        latest_version = %latest_version,
        "detected new rust stable release"
    );

    state_kv
        .put(RUST_STABLE_STATE_KEY, latest_version.as_bytes())
        .await
        .map_err(|error| format!("persist rustc stable watcher state: {error}"))?;

    Ok(Some(latest_version))
}

async fn fetch_stable_rust_version() -> Result<String, String> {
    let mut client = zenwave::client();
    let manifest = client
        .get(RUST_STABLE_CHANNEL_URL)
        .header("User-Agent", RUST_CHANNEL_USER_AGENT)
        .string()
        .await
        .map_err(|error| format!("fetch rust stable channel manifest: {error}"))?;

    let manifest: StableChannelManifest = toml::from_str(manifest.as_ref())
        .map_err(|error| format!("parse rust stable channel manifest: {error}"))?;

    manifest
        .pkg
        .rust
        .version
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| "stable channel manifest did not contain rust version".to_owned())
}

#[derive(Debug, serde::Deserialize)]
struct StableChannelManifest {
    pkg: StablePackages,
}

#[derive(Debug, serde::Deserialize)]
struct StablePackages {
    rust: StableRustPackage,
}

#[derive(Debug, serde::Deserialize)]
struct StableRustPackage {
    version: String,
}
