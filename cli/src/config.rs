use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use stow_types::error::Context;
use tokio::sync::OnceCell;

use crate::wrapper_shim;

const STOW_EDGE_URL_ENV: &str = "STOW_EDGE_URL";
/// The production edge. `STOW_EDGE_URL` or `edge_url` in the config file
/// override it for mock and staging runs.
pub const DEFAULT_EDGE_URL: &str = "https://stow.waterui.dev";
const STOW_VERIFY_MODE_ENV: &str = "STOW_VERIFY_MODE";
const STOW_MOCK_PUBLIC_KEY_PATH_ENV: &str = "STOW_MOCK_PUBLIC_KEY_PATH";
const STOW_CACHE_DIR_ENV: &str = "STOW_CACHE_DIR";
const STOW_ARTIFACT_CACHE_MAX_BYTES_ENV: &str = "STOW_ARTIFACT_CACHE_MAX_BYTES";
const STOW_ADMISSION_DRAIN_TIMEOUT_MS_ENV: &str = "STOW_ADMISSION_DRAIN_TIMEOUT_MS";
/// Carries the parent `stow check` driver's already-resolved `StowConfig` to
/// every rustc-wrapper subprocess as a JSON blob, so the wrapper does not
/// re-read `~/.config/stow/config.toml` on each rustc invocation.
pub const STOW_CONFIG_BLOB_ENV: &str = "STOW_CONFIG_BLOB";
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 300;
const DEFAULT_NEGATIVE_CACHE_TTL_SECS: u64 = 300;
const DEFAULT_GRAPH_CACHE_TTL_SECS: u64 = 300;
const DEFAULT_CIRCUIT_RESET_SECS: u64 = 60;
const DEFAULT_CIRCUIT_TRIP_THRESHOLD: u32 = 5;
const DEFAULT_ARTIFACT_CACHE_MAX_BYTES: u64 = 20 * 1024 * 1024 * 1024;
/// Fallback admission-drain deadline when neither
/// `STOW_ADMISSION_DRAIN_TIMEOUT_MS` nor a config value applies. Also the
/// ceiling a completed `stow check`/`build` run will wait for in-flight
/// enqueue redemptions before abandoning them.
pub const DEFAULT_ADMISSION_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Deadline for redeeming queued miss admissions once the build
    /// finishes — the driver abandons whatever is unsolved/unposted at the
    /// deadline. `STOW_ADMISSION_DRAIN_TIMEOUT_MS` overrides the default.
    pub admission_drain_timeout: Duration,
    /// Process-scoped lazy cache for the state `SQLite` pool. Reused across
    /// every `artifact_cache` / `graph_cache` / circuit / stats call, so the
    /// rustc-wrapper hot path does not pay the `SqliteConnectOptions` /
    /// schema-migration cost on each invocation. Tests/fixtures should
    /// initialize via [`StowConfig::default_state_db_pool`].
    #[serde(skip, default = "Arc::default")]
    pub state_db_pool: Arc<OnceCell<SqlitePool>>,
}

impl StowConfig {
    /// Get (lazily initializing) the shared `SQLite` pool for this config.
    pub async fn state_db_pool(&self) -> stow_types::error::Result<SqlitePool> {
        let pool = self
            .state_db_pool
            .get_or_try_init(|| crate::state_db::connect_pool(&self.cache_dir))
            .await?;
        Ok(pool.clone())
    }

    /// Build a fresh, uninitialized lazy cache for the state SQLite pool.
    /// Tests/fixtures use this when constructing a `StowConfig` literal.
    #[cfg(test)]
    #[must_use]
    pub fn default_state_db_pool() -> Arc<OnceCell<SqlitePool>> {
        Arc::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyMode {
    GithubCi,
    MockKey,
}

impl VerifyMode {
    /// The wire string `STOW_VERIFY_MODE` accepts; the inverse of
    /// [`Self::parse`].
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GithubCi => "github-ci",
            Self::MockKey => "mock-key",
        }
    }

    fn parse(raw: &str) -> stow_types::error::Result<Self> {
        match raw {
            "github-ci" => Ok(Self::GithubCi),
            "mock-key" => Ok(Self::MockKey),
            other => Err(stow_types::stow_error!(
                "unsupported verify mode `{other}`; expected `github-ci` or `mock-key`"
            )),
        }
    }
}

impl StowConfig {
    /// Encode the resolved config as a JSON blob suitable for passing to a
    /// child process via `STOW_CONFIG_BLOB` env. Used by `stow check` to skip
    /// re-parsing the user config inside every rustc wrapper invocation.
    pub fn to_env_blob(&self) -> stow_types::error::Result<String> {
        serde_json::to_string(self).wrap_err("serialize STOW_CONFIG_BLOB")
    }

    /// Decode a previously-encoded `STOW_CONFIG_BLOB`, returning `None` when
    /// the env var is unset.
    fn from_env_blob() -> stow_types::error::Result<Option<Self>> {
        let Some(raw) = std::env::var_os(STOW_CONFIG_BLOB_ENV) else {
            return Ok(None);
        };
        let raw = raw
            .into_string()
            .map_err(|_| stow_types::stow_error!("{STOW_CONFIG_BLOB_ENV} must be valid UTF-8"))?;
        let config: Self = serde_json::from_str(&raw)
            .wrap_err_with(|| format!("parse {STOW_CONFIG_BLOB_ENV} as JSON"))?;
        Ok(Some(config))
    }

    #[tracing::instrument(name = "stow.config.load", skip_all)]
    pub fn load() -> stow_types::error::Result<Self> {
        if let Some(config) = Self::from_env_blob()? {
            tracing::Span::current().record("source", "env_blob");
            return Ok(config);
        }
        let file_config = load_user_config()?;
        let edge_url = resolve_edge_url(file_config.as_ref());
        let local_cache_dir = resolve_cache_dir(file_config.as_ref())?;
        let verify_mode = load_verify_mode(file_config.as_ref())?;
        let mock_public_key_path = load_mock_public_key_path(file_config.as_ref());
        if verify_mode == VerifyMode::MockKey && mock_public_key_path.is_none() {
            return Err(stow_types::stow_error!(
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
            admission_drain_timeout: load_admission_drain_timeout()?,
            state_db_pool: Arc::default(),
        })
    }

    pub fn load_local() -> stow_types::error::Result<Self> {
        if let Some(config) = Self::from_env_blob()? {
            return Ok(config);
        }
        let file_config = load_user_config()?;
        let verify_mode = load_verify_mode(file_config.as_ref())?;
        let mock_public_key_path = load_mock_public_key_path(file_config.as_ref());
        Ok(Self {
            edge_url: resolve_edge_url(file_config.as_ref()),
            cache_dir: resolve_cache_dir(file_config.as_ref())?,
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
            admission_drain_timeout: load_admission_drain_timeout()?,
            state_db_pool: Arc::default(),
        })
    }

    pub async fn ensure_dirs(&self) -> stow_types::error::Result<()> {
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

    pub fn artifact_cache_purge_root(&self) -> PathBuf {
        self.cache_dir.join("purge")
    }

    pub fn graph_plan_dir(&self) -> PathBuf {
        self.cache_dir.join("graph-plans")
    }
}

pub fn config_file_path() -> stow_types::error::Result<PathBuf> {
    let config_dir =
        dirs::config_dir().ok_or_else(|| stow_types::stow_error!("resolve config directory"))?;
    Ok(config_dir.join("stow").join("config.toml"))
}

pub fn cache_dir() -> stow_types::error::Result<PathBuf> {
    let file_config = load_user_config()?;
    resolve_cache_dir(file_config.as_ref())
}

/// The per-user directory `stow setup` installs the rustc/cc wrapper shims
/// into (`~/Library/Application Support/stow/tools` on macOS,
/// `~/.local/share/stow/tools` on Linux, `%LOCALAPPDATA%\stow\tools` on
/// Windows). Unlike the previous `/tmp` location it survives a reboot, so
/// the `rustc-wrapper` path written into `.cargo/config.toml` keeps
/// resolving.
pub fn tools_dir() -> stow_types::error::Result<PathBuf> {
    wrapper_shim::tools_dir()
}

fn resolve_cache_dir(file_config: Option<&StowUserConfig>) -> stow_types::error::Result<PathBuf> {
    if let Some(value) = std::env::var_os(STOW_CACHE_DIR_ENV) {
        if value.is_empty() {
            return Err(stow_types::stow_error!(
                "{STOW_CACHE_DIR_ENV} must not be empty"
            ));
        }
        return Ok(PathBuf::from(value));
    }

    if let Some(value) = file_config.and_then(|config| config.cache_dir.as_ref()) {
        if value.trim().is_empty() {
            return Err(stow_types::stow_error!(
                "cache_dir in stow config must not be empty"
            ));
        }
        return Ok(PathBuf::from(value));
    }

    let home_dir =
        dirs::home_dir().ok_or_else(|| stow_types::stow_error!("resolve home directory"))?;
    Ok(home_dir.join(".stow"))
}

fn resolve_edge_url(file_config: Option<&StowUserConfig>) -> String {
    std::env::var(STOW_EDGE_URL_ENV)
        .ok()
        .or_else(|| file_config.and_then(|config| config.edge_url.clone()))
        .unwrap_or_else(|| DEFAULT_EDGE_URL.to_owned())
}

fn load_user_config() -> stow_types::error::Result<Option<StowUserConfig>> {
    let config_path = config_file_path()?;
    if !config_path.exists() {
        return Ok(None);
    }

    let contents = std::fs::read_to_string(&config_path)
        .wrap_err_with(|| format!("read {}", config_path.display()))?;
    let config = toml::from_str::<StowUserConfig>(&contents).wrap_err("parse stow config TOML")?;
    Ok(Some(config))
}

#[derive(Debug, Clone, serde::Deserialize)]
struct StowUserConfig {
    edge_url: Option<String>,
    cache_dir: Option<String>,
    request_timeout_secs: Option<u64>,
    negative_cache_ttl_secs: Option<u64>,
    graph_cache_ttl_secs: Option<u64>,
    circuit_reset_secs: Option<u64>,
    circuit_trip_threshold: Option<u32>,
    artifact_cache_max_bytes: Option<u64>,
    verify_mode: Option<String>,
    mock_public_key_path: Option<String>,
}

fn load_verify_mode(file_config: Option<&StowUserConfig>) -> stow_types::error::Result<VerifyMode> {
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

fn load_admission_drain_timeout() -> stow_types::error::Result<Duration> {
    let Some(raw) = std::env::var(STOW_ADMISSION_DRAIN_TIMEOUT_MS_ENV).ok() else {
        return Ok(DEFAULT_ADMISSION_DRAIN_TIMEOUT);
    };
    let millis = raw.parse::<u64>().map_err(|error| {
        stow_types::stow_error!(
            "parse {STOW_ADMISSION_DRAIN_TIMEOUT_MS_ENV} as u64 milliseconds: {error}"
        )
    })?;
    Ok(Duration::from_millis(millis))
}

fn load_artifact_cache_max_bytes(
    file_config: Option<&StowUserConfig>,
) -> stow_types::error::Result<u64> {
    let raw = std::env::var(STOW_ARTIFACT_CACHE_MAX_BYTES_ENV)
        .ok()
        .or_else(|| {
            file_config
                .and_then(|config| config.artifact_cache_max_bytes)
                .map(|value| value.to_string())
        });
    let value = match raw {
        Some(raw) => raw.parse::<u64>().map_err(|error| {
            stow_types::stow_error!(
                "parse {STOW_ARTIFACT_CACHE_MAX_BYTES_ENV} as u64 bytes: {error}"
            )
        })?,
        None => DEFAULT_ARTIFACT_CACHE_MAX_BYTES,
    };
    if value == 0 {
        return Err(stow_types::stow_error!(
            "{STOW_ARTIFACT_CACHE_MAX_BYTES_ENV} must be greater than zero"
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[test]
    fn tools_dir_is_absolute_and_outside_the_system_temp_dir() {
        let dir = super::tools_dir().expect("resolve tools dir");
        assert!(
            dir.is_absolute(),
            "tools dir {} is not absolute",
            dir.display()
        );
        assert!(
            !dir.starts_with(std::env::temp_dir()),
            "tools dir {} lives under the system temp dir",
            dir.display()
        );
        assert_eq!(
            dir.file_name().and_then(std::ffi::OsStr::to_str),
            Some("tools")
        );
        assert_eq!(
            dir.parent()
                .and_then(Path::file_name)
                .and_then(std::ffi::OsStr::to_str),
            Some("stow")
        );
    }
}
