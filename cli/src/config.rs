use std::path::PathBuf;
use std::time::Duration;

use eyre::Context;

const STOW_EDGE_URL_ENV: &str = "STOW_EDGE_URL";
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 2;
const DEFAULT_NEGATIVE_CACHE_TTL_SECS: u64 = 300;
const DEFAULT_CIRCUIT_RESET_SECS: u64 = 60;
const DEFAULT_CIRCUIT_TRIP_THRESHOLD: u32 = 5;

#[derive(Debug, Clone)]
pub struct StowConfig {
    pub edge_url: String,
    pub cache_dir: PathBuf,
    pub request_timeout: Duration,
    pub negative_cache_ttl: Duration,
    pub circuit_reset_after: Duration,
    pub circuit_trip_threshold: u32,
}

impl StowConfig {
    pub fn load() -> eyre::Result<Self> {
        let file_config = load_user_config()?;
        let edge_url = std::env::var(STOW_EDGE_URL_ENV)
            .ok()
            .or(file_config.as_ref().and_then(|config| config.edge_url.clone()))
            .ok_or_else(|| {
                eyre::eyre!(
                    "missing edge URL; set {STOW_EDGE_URL_ENV} or ~/.config/stow/config.toml"
                )
            })?;
        let local_cache_dir = cache_dir()?;

        Ok(Self {
            edge_url,
            cache_dir: local_cache_dir,
            request_timeout: Duration::from_secs(
                file_config
                    .as_ref()
                    .and_then(|config| config.request_timeout_secs)
                    .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS),
            ),
            negative_cache_ttl: Duration::from_secs(
                file_config
                    .as_ref()
                    .and_then(|config| config.negative_cache_ttl_secs)
                    .unwrap_or(DEFAULT_NEGATIVE_CACHE_TTL_SECS),
            ),
            circuit_reset_after: Duration::from_secs(
                file_config
                    .as_ref()
                    .and_then(|config| config.circuit_reset_secs)
                    .unwrap_or(DEFAULT_CIRCUIT_RESET_SECS),
            ),
            circuit_trip_threshold: file_config
                .as_ref()
                .and_then(|config| config.circuit_trip_threshold)
                .unwrap_or(DEFAULT_CIRCUIT_TRIP_THRESHOLD),
        })
    }

    pub fn load_local() -> eyre::Result<Self> {
        let file_config = load_user_config()?;
        Ok(Self {
            edge_url: std::env::var(STOW_EDGE_URL_ENV)
                .ok()
                .or(file_config.as_ref().and_then(|config| config.edge_url.clone()))
                .unwrap_or_default(),
            cache_dir: cache_dir()?,
            request_timeout: Duration::from_secs(
                file_config
                    .as_ref()
                    .and_then(|config| config.request_timeout_secs)
                    .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS),
            ),
            negative_cache_ttl: Duration::from_secs(
                file_config
                    .as_ref()
                    .and_then(|config| config.negative_cache_ttl_secs)
                    .unwrap_or(DEFAULT_NEGATIVE_CACHE_TTL_SECS),
            ),
            circuit_reset_after: Duration::from_secs(
                file_config
                    .as_ref()
                    .and_then(|config| config.circuit_reset_secs)
                    .unwrap_or(DEFAULT_CIRCUIT_RESET_SECS),
            ),
            circuit_trip_threshold: file_config
                .as_ref()
                .and_then(|config| config.circuit_trip_threshold)
                .unwrap_or(DEFAULT_CIRCUIT_TRIP_THRESHOLD),
        })
    }

    pub async fn ensure_dirs(&self) -> eyre::Result<()> {
        async_fs::create_dir_all(&self.cache_dir)
            .await
            .wrap_err_with(|| format!("create cache directory {}", self.cache_dir.display()))
    }

    pub fn circuit_path(&self) -> PathBuf {
        self.cache_dir.join("circuit.json")
    }

    pub fn negative_cache_path(&self) -> PathBuf {
        self.cache_dir.join("negative.json")
    }

    pub fn stats_path(&self) -> PathBuf {
        self.cache_dir.join("stats.json")
    }
}

pub fn config_file_path() -> eyre::Result<PathBuf> {
    let config_dir = dirs::config_dir().ok_or_else(|| eyre::eyre!("resolve config directory"))?;
    Ok(config_dir.join("stow").join("config.toml"))
}

pub fn cache_dir() -> eyre::Result<PathBuf> {
    let cache_dir = dirs::cache_dir().ok_or_else(|| eyre::eyre!("resolve cache directory"))?;
    Ok(cache_dir.join("stow"))
}

fn load_user_config() -> eyre::Result<Option<StowUserConfig>> {
    let config_path = config_file_path()?;
    if !config_path.exists() {
        return Ok(None);
    }

    let contents = std::fs::read_to_string(&config_path)
        .wrap_err_with(|| format!("read {}", config_path.display()))?;
    let config =
        toml::from_str::<StowUserConfig>(&contents).wrap_err("parse stow config TOML")?;
    Ok(Some(config))
}

#[derive(Debug, Clone, serde::Deserialize)]
struct StowUserConfig {
    edge_url: Option<String>,
    request_timeout_secs: Option<u64>,
    negative_cache_ttl_secs: Option<u64>,
    circuit_reset_secs: Option<u64>,
    circuit_trip_threshold: Option<u32>,
}
