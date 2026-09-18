use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::rustc_args::ParsedRustcArgs;

const STOW_CACHE_POLICY_PATH_ENV: &str = "STOW_CACHE_POLICY_PATH";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CachePolicyEntry {
    pub target: String,
    pub crate_name: String,
}

pub async fn write_policy(
    config: &crate::config::StowConfig,
    entries: &[CachePolicyEntry],
) -> stow_types::error::Result<PathBuf> {
    async_fs::create_dir_all(config.graph_plan_dir())
        .await
        .map_err(|error| {
            stow_types::stow_error!(
                "create cache policy dir {}: {error}",
                config.graph_plan_dir().display()
            )
        })?;

    let dir = config.graph_plan_dir().join(format!(
        "cache-policy-{}-{}",
        std::process::id(),
        crate::state_db::now_millis()
    ));
    async_fs::create_dir_all(&dir).await.map_err(|error| {
        stow_types::stow_error!("create cache policy dir {}: {error}", dir.display())
    })?;

    for entry in entries {
        let file_path = allow_marker_path(&dir, entry.target.as_str(), entry.crate_name.as_str());
        if let Some(parent) = file_path.parent() {
            async_fs::create_dir_all(parent).await.map_err(|error| {
                stow_types::stow_error!(
                    "create cache policy target dir {}: {error}",
                    parent.display()
                )
            })?;
        }
        async_fs::write(&file_path, []).await.map_err(|error| {
            stow_types::stow_error!("write cache policy marker {}: {error}", file_path.display())
        })?;
    }

    Ok(dir)
}

/// Cheap pre-identity gate: with a policy dir present, only crates the graph
/// analysis marked as cached are worth the identity computation + network
/// round trip. Keyed by canonical crate name — the only identity component
/// that is free to read from the rustc args and stable across cargo's
/// ephemeral metadata. A stale allow (name cached, variant missing) costs
/// one 404; a deny costs nothing.
///
/// `None` means "no policy configured" (standalone wrapper use) and the
/// caller treats it as allowed.
pub fn public_cache_allowed(parsed: &ParsedRustcArgs) -> Option<bool> {
    let path = std::env::var_os(STOW_CACHE_POLICY_PATH_ENV)?;
    let target = parsed
        .target
        .clone()
        .or_else(|| std::env::var("STOW_PUBLIC_CACHE_TARGET").ok())?;

    let dir = PathBuf::from(path);
    let marker = allow_marker_path(&dir, &target, &parsed.crate_name);
    Some(marker.exists())
}

pub fn cache_policy_env(path: &Path) -> (String, OsString) {
    (
        STOW_CACHE_POLICY_PATH_ENV.to_owned(),
        path.as_os_str().to_owned(),
    )
}

fn allow_marker_path(policy_dir: &Path, target: &str, crate_name: &str) -> PathBuf {
    policy_dir
        .join("allow")
        .join(target)
        .join(crate_name.replace('-', "_"))
}
