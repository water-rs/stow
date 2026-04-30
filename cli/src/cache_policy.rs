use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::rustc_args::ParsedRustcArgs;
use async_fs;

const STOW_CACHE_POLICY_PATH_ENV: &str = "STOW_CACHE_POLICY_PATH";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CachePolicyEntry {
    pub target: String,
    pub c_metadata: String,
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
        let file_path = allow_marker_path(&dir, entry.target.as_str(), entry.c_metadata.as_str());
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

pub async fn public_cache_allowed(
    parsed: &ParsedRustcArgs,
) -> stow_types::error::Result<Option<bool>> {
    let Some(path) = std::env::var_os(STOW_CACHE_POLICY_PATH_ENV) else {
        return Ok(None);
    };
    let Some(target) = parsed.target.as_deref() else {
        return Ok(None);
    };
    let Some(c_metadata) = parsed.c_metadata.as_deref() else {
        return Ok(None);
    };

    let dir = PathBuf::from(path);
    let marker = allow_marker_path(&dir, target, c_metadata);
    Ok(marker.exists().then_some(true))
}

pub fn cache_policy_env(path: &Path) -> (String, OsString) {
    (
        STOW_CACHE_POLICY_PATH_ENV.to_owned(),
        path.as_os_str().to_owned(),
    )
}

fn allow_marker_path(policy_dir: &Path, target: &str, c_metadata: &str) -> PathBuf {
    policy_dir.join("allow").join(target).join(c_metadata)
}
