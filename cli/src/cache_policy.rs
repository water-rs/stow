use std::ffi::OsString;
use std::path::PathBuf;

use crate::rustc_args::ParsedRustcArgs;
use async_fs;

const STOW_CACHE_POLICY_PATH_ENV: &str = "STOW_CACHE_POLICY_PATH";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CachePolicyEntry {
    pub target: String,
    pub c_metadata: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CachePolicyFile {
    entries: Vec<CachePolicyEntry>,
}

pub async fn write_policy(
    config: &crate::config::StowConfig,
    entries: &[CachePolicyEntry],
) -> eyre::Result<PathBuf> {
    async_fs::create_dir_all(config.graph_plan_dir())
        .await
        .map_err(|error| {
            eyre::eyre!(
                "create cache policy dir {}: {error}",
                config.graph_plan_dir().display()
            )
        })?;
    let file = CachePolicyFile {
        entries: entries.to_vec(),
    };
    let path = config.graph_plan_dir().join(format!(
        "cache-policy-{}-{}.json",
        std::process::id(),
        crate::state_file::now_millis()
    ));
    let bytes = serde_json::to_vec(&file)
        .map_err(|error| eyre::eyre!("serialize cache policy: {error}"))?;
    async_fs::write(&path, bytes)
        .await
        .map_err(|error| eyre::eyre!("write cache policy {}: {error}", path.display()))?;
    Ok(path)
}

pub async fn public_cache_allowed(parsed: &ParsedRustcArgs) -> eyre::Result<Option<bool>> {
    let Some(path) = std::env::var_os(STOW_CACHE_POLICY_PATH_ENV) else {
        return Ok(None);
    };
    let Some(target) = parsed.target.as_deref() else {
        return Ok(None);
    };
    let Some(c_metadata) = parsed.c_metadata.as_deref() else {
        return Ok(None);
    };

    let bytes = async_fs::read(&path).await.map_err(|error| {
        eyre::eyre!(
            "read cache policy {}: {error}",
            PathBuf::from(&path).display()
        )
    })?;
    let policy = serde_json::from_slice::<CachePolicyFile>(&bytes).map_err(|error| {
        eyre::eyre!(
            "parse cache policy {}: {error}",
            PathBuf::from(&path).display()
        )
    })?;

    let matches = policy
        .entries
        .iter()
        .filter(|entry| entry.target == target && entry.c_metadata == c_metadata)
        .count();
    match matches {
        0 => Ok(Some(false)),
        1 => Ok(Some(true)),
        _ => Err(eyre::eyre!(
            "cache policy produced multiple matches for target {} and c_metadata {}",
            target,
            c_metadata
        )),
    }
}

pub fn cache_policy_env(path: &std::path::Path) -> (String, OsString) {
    (
        STOW_CACHE_POLICY_PATH_ENV.to_owned(),
        path.as_os_str().to_owned(),
    )
}
