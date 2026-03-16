use std::path::PathBuf;
use std::time::Duration;

use eyre::Context;

const STOW_EDGE_URL_ENV: &str = "STOW_EDGE_URL";
const STOW_VERIFY_MODE_ENV: &str = "STOW_VERIFY_MODE";
const STOW_MOCK_PUBLIC_KEY_PATH_ENV: &str = "STOW_MOCK_PUBLIC_KEY_PATH";
const STOW_ARTIFACT_CACHE_MAX_BYTES_ENV: &str = "STOW_ARTIFACT_CACHE_MAX_BYTES";
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 2;
const DEFAULT_NEGATIVE_CACHE_TTL_SECS: u64 = 300;
const DEFAULT_GRAPH_CACHE_TTL_SECS: u64 = 300;
const DEFAULT_CIRCUIT_RESET_SECS: u64 = 60;
const DEFAULT_CIRCUIT_TRIP_THRESHOLD: u32 = 5;
const DEFAULT_ARTIFACT_CACHE_MAX_BYTES: u64 = 20 * 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct StowConfig {
    pub edge_url: String,
    pub cache_dir: PathBuf,
    pub request_timeout: Duration,
    pub negative_cache_ttl: Duration,
    pub graph_cache_ttl: Duration,
    pub circuit_reset_after: Duration,
    pub circuit_trip_threshold: u32,
    pub artifact_cache_max_bytes: u64,
    pub verify_mode: VerifyMode,
    pub mock_public_key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    GithubCi,
    MockKey,
}

impl VerifyMode {
    fn parse(raw: &str) -> eyre::Result<Self> {
        match raw {
            "github-ci" => Ok(Self::GithubCi),
            "mock-key" => Ok(Self::MockKey),
            other => Err(eyre::eyre!(
                "unsupported verify mode `{other}`; expected `github-ci` or `mock-key`"
            )),
        }
    }
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
        let verify_mode = load_verify_mode(file_config.as_ref())?;
        let mock_public_key_path = load_mock_public_key_path(file_config.as_ref());
        if verify_mode == VerifyMode::MockKey && mock_public_key_path.is_none() {
            return Err(eyre::eyre!(
                "verify mode `mock-key` requires {STOW_MOCK_PUBLIC_KEY_PATH_ENV} or mock_public_key_path in config"
            ));
        }

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
            graph_cache_ttl: Duration::from_secs(
                file_config
                    .as_ref()
                    .and_then(|config| config.graph_cache_ttl_secs)
                    .unwrap_or(DEFAULT_GRAPH_CACHE_TTL_SECS),
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
            artifact_cache_max_bytes: load_artifact_cache_max_bytes(file_config.as_ref())?,
            verify_mode,
            mock_public_key_path,
        })
    }

    pub fn load_local() -> eyre::Result<Self> {
        let file_config = load_user_config()?;
        let verify_mode = load_verify_mode(file_config.as_ref())?;
        let mock_public_key_path = load_mock_public_key_path(file_config.as_ref());
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
            graph_cache_ttl: Duration::from_secs(
                file_config
                    .as_ref()
                    .and_then(|config| config.graph_cache_ttl_secs)
                    .unwrap_or(DEFAULT_GRAPH_CACHE_TTL_SECS),
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
            artifact_cache_max_bytes: load_artifact_cache_max_bytes(file_config.as_ref())?,
            verify_mode,
            mock_public_key_path,
        })
    }

    pub async fn ensure_dirs(&self) -> eyre::Result<()> {
        async_fs::create_dir_all(&self.cache_dir)
            .await
            .wrap_err_with(|| format!("create cache directory {}", self.cache_dir.display()))
    }

    pub fn artifact_cache_root(&self) -> PathBuf {
        self.cache_dir.join("cache")
    }

    pub fn artifact_cache_version_dir(&self, rustc_version: &str) -> PathBuf {
        self.artifact_cache_root().join(rustc_version)
    }

    pub fn artifact_cache_index_path(&self, rustc_version: &str) -> PathBuf {
        self.artifact_cache_version_dir(rustc_version).join("index.json")
    }

    pub fn artifact_cache_purge_root(&self) -> PathBuf {
        self.cache_dir.join("purge")
    }

    pub fn circuit_path(&self) -> PathBuf {
        self.cache_dir.join("circuit.json")
    }

    pub fn negative_cache_path(&self) -> PathBuf {
        self.cache_dir.join("negative.json")
    }

    pub fn graph_cache_path(&self) -> PathBuf {
        self.cache_dir.join("graph-cache.json")
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
    let home_dir = dirs::home_dir().ok_or_else(|| eyre::eyre!("resolve home directory"))?;
    Ok(home_dir.join(".stow"))
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
    graph_cache_ttl_secs: Option<u64>,
    circuit_reset_secs: Option<u64>,
    circuit_trip_threshold: Option<u32>,
    artifact_cache_max_bytes: Option<u64>,
    verify_mode: Option<String>,
    mock_public_key_path: Option<String>,
}

fn load_verify_mode(file_config: Option<&StowUserConfig>) -> eyre::Result<VerifyMode> {
    let raw = std::env::var(STOW_VERIFY_MODE_ENV)
        .ok()
        .or_else(|| file_config.and_then(|config| config.verify_mode.clone()))
        .unwrap_or_else(|| "github-ci".to_owned());
    VerifyMode::parse(&raw)
}

fn load_mock_public_key_path(file_config: Option<&StowUserConfig>) -> Option<PathBuf> {
    std::env::var(STOW_MOCK_PUBLIC_KEY_PATH_ENV)
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            file_config
                .and_then(|config| config.mock_public_key_path.as_ref())
                .map(PathBuf::from)
        })
}

fn load_artifact_cache_max_bytes(file_config: Option<&StowUserConfig>) -> eyre::Result<u64> {
    let raw = std::env::var(STOW_ARTIFACT_CACHE_MAX_BYTES_ENV)
        .ok()
        .or_else(|| {
            file_config
                .and_then(|config| config.artifact_cache_max_bytes)
                .map(|value| value.to_string())
        });
    let value = match raw {
        Some(raw) => raw.parse::<u64>().map_err(|error| {
            eyre::eyre!(
                "parse {STOW_ARTIFACT_CACHE_MAX_BYTES_ENV} as u64 bytes: {error}"
            )
        })?,
        None => DEFAULT_ARTIFACT_CACHE_MAX_BYTES,
    };
    if value == 0 {
        return Err(eyre::eyre!(
            "{STOW_ARTIFACT_CACHE_MAX_BYTES_ENV} must be greater than zero"
        ));
    }
    Ok(value)
}
