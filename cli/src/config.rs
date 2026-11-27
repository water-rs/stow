use std::path::{Path, PathBuf};

#[cfg(feature = "mock-verify")]
use sha2::Digest as _;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use stow_types::error::Context;
use tokio::sync::OnceCell;

use stow_types::public_cache::UnitSource;

use crate::artifact_cache::ArtifactProvenance;
use crate::session_env::SessionEnv;
use crate::state_db::{CacheTier, StateDb};
use crate::wrapper_shim;

const STOW_EDGE_URL_ENV: &str = "STOW_EDGE_URL";
/// The production edge. `STOW_EDGE_URL` or `edge_url` in the config file
/// override it for mock and staging runs.
pub const DEFAULT_EDGE_URL: &str = "https://stow.waterui.dev";
const STOW_VERIFY_MODE_ENV: &str = "STOW_VERIFY_MODE";
#[cfg(feature = "mock-verify")]
const STOW_MOCK_PUBLIC_KEY_PATH_ENV: &str = "STOW_MOCK_PUBLIC_KEY_PATH";
const STOW_CACHE_DIR_ENV: &str = "STOW_CACHE_DIR";
const STOW_REGISTRY_BASE_URL_ENV: &str = "STOW_REGISTRY_BASE_URL";
const STOW_INDEX_REFRESH_SECS_ENV: &str = "STOW_INDEX_REFRESH_SECS";
const STOW_ARTIFACT_CACHE_MAX_BYTES_ENV: &str = "STOW_ARTIFACT_CACHE_MAX_BYTES";
const STOW_BUILD_DIR_MAX_BYTES_ENV: &str = "STOW_BUILD_DIR_MAX_BYTES";
const STOW_BUILD_DIR_MIN_FREE_BYTES_ENV: &str = "STOW_BUILD_DIR_MIN_FREE_BYTES";
const STOW_BUILD_DIR_IDLE_SECS_ENV: &str = "STOW_BUILD_DIR_IDLE_SECS";
const STOW_BUCKET_ENV: &str = "STOW_BUCKET";
const STOW_BUCKET_ENDPOINT_ENV: &str = "STOW_BUCKET_ENDPOINT";
const STOW_BUCKET_REGION_ENV: &str = "STOW_BUCKET_REGION";
const STOW_BUCKET_PREFIX_ENV: &str = "STOW_BUCKET_PREFIX";
const STOW_BUCKET_READ_ONLY_ENV: &str = "STOW_BUCKET_READ_ONLY";
const STOW_BUCKET_LOCAL_CRATES_IO_ENV: &str = "STOW_BUCKET_LOCAL_CRATES_IO";
const STOW_BUCKET_FORCE_PATH_STYLE_ENV: &str = "STOW_BUCKET_FORCE_PATH_STYLE";
const AWS_ACCESS_KEY_ID_ENV: &str = "AWS_ACCESS_KEY_ID";
const AWS_SECRET_ACCESS_KEY_ENV: &str = "AWS_SECRET_ACCESS_KEY";
const AWS_SESSION_TOKEN_ENV: &str = "AWS_SESSION_TOKEN";
pub const DEFAULT_BUCKET_REGION: &str = "auto";
pub const DEFAULT_BUCKET_PREFIX: &str = "stow/";
/// Short default timeouts for optional L2 bucket operations so an unreachable
/// or stalled S3-compatible endpoint degrades quickly to local compilation.
pub const DEFAULT_BUCKET_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
pub const DEFAULT_BUCKET_READ_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_BUCKET_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const STOW_FUSE_ENV: &str = "STOW_FUSE";
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 300;
const DEFAULT_NEGATIVE_CACHE_TTL_SECS: u64 = 300;
const DEFAULT_CIRCUIT_RESET_SECS: u64 = 60;
const DEFAULT_CIRCUIT_TRIP_THRESHOLD: u32 = 5;
pub const DEFAULT_ARTIFACT_CACHE_MAX_BYTES: u64 = 20 * 1024 * 1024 * 1024;
/// How long a verified index slice's pointer stays fresh before the next
/// read re-checks the tag — `STOW_INDEX_REFRESH_SECS`, config
/// `index_refresh_secs`, default ten minutes.
const DEFAULT_INDEX_REFRESH_SECS: u64 = 600;
/// How long a build directory stow placed may go unbuilt before the
/// daemon collects it — config `build_dir_idle_secs` or
/// `STOW_BUILD_DIR_IDLE_SECS`, default 30 days (stow#1540). A workspace left
/// alone for a month is rebuilt from the cache in one serve.
pub const DEFAULT_BUILD_DIR_IDLE: Duration = Duration::from_hours(24 * 30);
/// Default cap on private (non-CoW-shared) bytes across `<cache_dir>/build-dir/`
/// before unlocked idle build directories are evicted LRU: 64 GiB.
pub const DEFAULT_BUILD_DIR_MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;
/// Default free-space floor on `<cache_dir>`'s filesystem below which unlocked
/// idle build directories are evicted LRU: 20 GiB.
pub const DEFAULT_BUILD_DIR_MIN_FREE_BYTES: u64 = 20 * 1024 * 1024 * 1024;

const fn default_build_dir_max_bytes() -> u64 {
    DEFAULT_BUILD_DIR_MAX_BYTES
}

const fn default_build_dir_min_free_bytes() -> u64 {
    DEFAULT_BUILD_DIR_MIN_FREE_BYTES
}
/// The consumer's registry connect bound: an unreachable registry
/// answers in seconds, and its connect/DNS failure never joins the
/// retry sweep — the build's circuit carries the outage instead of
/// eight stalled attempts (stow#977). Publishing keeps
/// [`stow_oci::TransportPolicy::PATIENT`].
const REGISTRY_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Which cache layers a stow process may use (stow#1007): the `[cache]` table
/// of the global config, read by every stow process, with a flag on each
/// cargo-running command overriding it for one run. The layers are
/// independent of the build isolation level: a build with every layer off
/// still runs its build scripts and proc macros at the configured level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheLayers {
    /// The remote cache: every edge and registry request, the miss journal,
    /// the inexact reports, and the entries downloaded from the remote
    /// earlier. Off, no remote-built artifact takes part in the build and
    /// nothing about its graph leaves the machine.
    pub remote: bool,
    /// Lookup and store of locally built crates.io units.
    pub local_crates_io: bool,
    /// Lookup and store of locally built git units.
    pub local_git: bool,
}

impl Default for CacheLayers {
    fn default() -> Self {
        Self {
            remote: true,
            local_crates_io: true,
            local_git: true,
        }
    }
}

impl CacheLayers {
    /// Whether stow may reach the index registry and the edge: the one
    /// predicate every network call site is gated on.
    pub const fn reaches_network(self) -> bool {
        self.remote
    }

    /// Whether locally built units of this source are looked up and stored.
    pub const fn local(self, source: &UnitSource) -> bool {
        match source {
            UnitSource::CratesIo { .. } => self.local_crates_io,
            UnitSource::Git { .. } => self.local_git,
        }
    }

    /// Whether an entry of this provenance may serve a unit of this source:
    /// a downloaded entry belongs to the remote layer, a self-built one to
    /// the local layer of its source.
    pub const fn serves(self, provenance: ArtifactProvenance, source: &UnitSource) -> bool {
        match provenance {
            ArtifactProvenance::Remote => self.remote,
            ArtifactProvenance::Local => self.local(source),
        }
    }

    /// Every layer is off: nothing is looked up, recorded or stored.
    pub const fn is_off(self) -> bool {
        !self.remote && !self.local_crates_io && !self.local_git
    }

    /// Whether the C/C++ object cache is used: it has no source kind, so it
    /// stays on while any local layer is.
    pub const fn uses_cc_cache(self) -> bool {
        self.local_crates_io || self.local_git
    }
}

/// Static S3 credentials resolved from a build's [`SessionEnv`]
/// (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN`).
///
/// Never read from or serialized into `config.toml`; [`std::fmt::Debug`]
/// redacts every field so credentials never appear in logs or diagnostics.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BucketCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

impl BucketCredentials {
    /// Convert into [`skyzen_s3::S3Credentials`] for explicit per-session auth.
    #[must_use]
    pub fn into_s3_credentials(self) -> skyzen_s3::S3Credentials {
        let credentials = skyzen_s3::S3Credentials::new(self.access_key_id, self.secret_access_key);
        match self.session_token {
            Some(token) => credentials.with_session_token(token),
            None => credentials,
        }
    }
}

impl std::fmt::Debug for BucketCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BucketCredentials")
            .field("access_key_id", &"<redacted>")
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Optional S3-compatible remote bucket backing stow's local cache tiers
/// (`local/`, including `local/cc/`, and optionally `local-crates-io/`).
///
/// Configured via `[cache.bucket]` in `config.toml` and/or `STOW_BUCKET*`
/// variables in [`SessionEnv`]; works independently of `[cache] remote`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BucketCacheConfig {
    pub bucket: String,
    pub endpoint: Option<String>,
    pub region: String,
    pub prefix: String,
    pub read_only: bool,
    pub local_crates_io: bool,
    pub force_path_style: Option<bool>,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub operation_timeout: Duration,
    #[serde(skip)]
    pub credentials: Option<BucketCredentials>,
}

impl BucketCacheConfig {
    /// Build a configuration for `bucket` with default region, prefix, flags,
    /// and timeouts.
    #[must_use]
    pub fn for_bucket(bucket: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            endpoint: None,
            region: DEFAULT_BUCKET_REGION.to_owned(),
            prefix: DEFAULT_BUCKET_PREFIX.to_owned(),
            read_only: false,
            local_crates_io: true,
            force_path_style: None,
            connect_timeout: DEFAULT_BUCKET_CONNECT_TIMEOUT,
            read_timeout: DEFAULT_BUCKET_READ_TIMEOUT,
            operation_timeout: DEFAULT_BUCKET_OPERATION_TIMEOUT,
            credentials: None,
        }
    }

    /// Timeout configuration passed to [`skyzen_s3::S3StorageBuilder::timeouts`].
    #[must_use]
    pub const fn s3_timeouts(&self) -> skyzen_s3::S3Timeouts {
        skyzen_s3::S3Timeouts {
            connect: Some(self.connect_timeout),
            read: Some(self.read_timeout),
            operation_attempt: None,
            operation: Some(self.operation_timeout),
        }
    }
}

/// Normalize a bucket key prefix: strip leading slashes and ensure a trailing
/// slash when non-empty.
#[must_use]
pub fn normalize_bucket_prefix(raw: &str) -> String {
    let trimmed = raw.trim_start_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else if trimmed.ends_with('/') {
        trimmed.to_owned()
    } else {
        format!("{trimmed}/")
    }
}

/// The environment switches that shape what a command sends and writes
/// rather than what it builds: resolved once with the config, so the
/// process answering for a build reads them from the build's environment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Switches {
    /// `STOW_NO_ANALYTICS=1`: requests carry the opt-out header and no
    /// usage report is sent.
    pub no_analytics: bool,
    /// `CI` is set: requests carry the CI environment header.
    pub ci: bool,
    /// `STOW_IDENTITY_TRACE`: the directory the identity-input probe writes
    /// to, when set.
    pub identity_trace: Option<PathBuf>,
}

impl Switches {
    /// The switches in `environ`.
    #[must_use]
    pub fn of_environ(environ: &[(std::ffi::OsString, std::ffi::OsString)]) -> Self {
        let var = |key: &str| {
            environ
                .iter()
                .find(|(name, _)| stow_types::env_name::eq(name, key))
                .map(|(_, value)| value)
        };
        Self {
            no_analytics: var(crate::edge_client::NO_ANALYTICS_ENV)
                .is_some_and(|value| value == "1"),
            ci: var("CI").is_some(),
            identity_trace: var("STOW_IDENTITY_TRACE").map(PathBuf::from),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StowConfig {
    /// Analytics, CI and trace switches of the environment this config was
    /// resolved in.
    pub switches: Switches,
    /// The resolved cache layers: the global config's `[cache]` table, then
    /// the run's flags. Every network request goes through
    /// [`Self::registry_http`] or [`crate::edge_client::client`], which both
    /// refuse a config whose remote layer is off.
    #[serde(default)]
    pub cache: CacheLayers,
    /// Optional S3-compatible remote bucket backing local cache tiers
    /// (`[cache.bucket]` / `STOW_BUCKET*`). Independent of `cache.remote`.
    #[serde(default)]
    pub bucket: Option<Box<BucketCacheConfig>>,
    pub edge_url: String,
    /// OCI registry root every index/artifact pull hits, in
    /// `scheme://host[:port]` form — the pull appends `/v2/<repository>`
    /// for the rustc's own package. `STOW_REGISTRY_BASE_URL` or
    /// `registry_base_url` redirect it — the mock e2e serves the same
    /// paths over plain HTTP; production is GHCR.
    pub registry_base_url: String,
    pub cache_dir: PathBuf,
    pub request_timeout: Duration,
    pub negative_cache_ttl: Duration,
    pub circuit_reset_after: Duration,
    pub circuit_trip_threshold: u32,
    pub artifact_cache_max_bytes: u64,
    /// Freshness window for a cached index slice: within it reads serve
    /// the verified blob without touching the registry; past it one
    /// manifest request re-validates the digest and re-downloads only on
    /// change. `STOW_INDEX_REFRESH_SECS` or `index_refresh_secs`.
    pub index_refresh_interval: Duration,
    /// Age past which a build directory under `<cache_dir>/build-dir/`
    /// that has not been built is collected. `build_dir_idle_secs` or
    /// `STOW_BUILD_DIR_IDLE_SECS`.
    pub build_dir_idle: Duration,
    /// Soft cap on private reclaimable bytes across `<cache_dir>/build-dir/`
    /// before unlocked idle build directories are evicted LRU.
    /// `build_dir_max_bytes` or `STOW_BUILD_DIR_MAX_BYTES`.
    #[serde(default = "default_build_dir_max_bytes")]
    pub build_dir_max_bytes: u64,
    /// Minimum free bytes on `<cache_dir>`'s filesystem below which unlocked
    /// idle build directories are evicted LRU. `build_dir_min_free_bytes` or
    /// `STOW_BUILD_DIR_MIN_FREE_BYTES`.
    #[serde(default = "default_build_dir_min_free_bytes")]
    pub build_dir_min_free_bytes: u64,
    /// Linux FUSE virtual copy-on-write layer over `<cache_dir>/build-dir/`
    /// for non-copy-on-write filesystems such as ext4 (stow#1704). Defaults to
    /// `true` on Linux (opt out via `fuse = false` or `STOW_FUSE=0`), `false`
    /// elsewhere; automatically skipped on native `CoW` filesystems (`btrfs`,
    /// `xfs`) and falls back to byte copies when `/dev/fuse` or `fusermount` is
    /// unavailable.
    #[serde(default = "default_fuse")]
    pub fuse: bool,
    pub verify_mode: VerifyMode,
    /// The process's handle on the state database, shared by every config
    /// the process loads: the command entry point creates it, hands it to
    /// each load, and closes it when the command ends (stow#682). Every
    /// `artifact_cache` / circuit / stats call draws the one pool from
    /// it, so the rustc-wrapper hot path does not pay the
    /// `SqliteConnectOptions` / schema-identity check on each invocation.
    /// Never serialised — a config a session receives from its driver
    /// takes the daemon's handle.
    #[serde(skip, default)]
    pub state_db: StateDb,
    /// Lazily loaded Sigstore trust root, shared by every verification
    /// this process performs. Loading it costs well over a second; one
    /// signature check against it costs milliseconds, so rebuilding it per
    /// artifact made verification the whole cost of a cold prefetch.
    #[serde(skip, default = "Arc::default")]
    pub trust_material: Arc<OnceCell<Arc<crate::verify::TrustMaterial>>>,
    /// Lazily built registry HTTP client, shared by every registry
    /// session this process opens. Building one loads the platform trust
    /// store — hundreds of certificate files on Linux — so a client per
    /// session made each index fetch pay that scan again (stow#624).
    #[serde(skip, default = "Arc::default")]
    pub registry_http: Arc<OnceCell<stow_oci::RegistryHttp>>,
    /// Per-tier, per-rustc artifact cache staging directories shared across a
    /// daemon's sessions, created lazily and re-acquired automatically if an
    /// idle version directory was purged or cleaned.
    #[serde(skip, default = "default_tier_staging")]
    pub artifact_cache_staging: TierStaging,
    /// Daemon-shared weak table of active per-`(tier, rustc_version)` shared
    /// lease locks so concurrent sessions on the same rustc hold one lock FD
    /// per tier instead of one per session (stow#1690).
    #[serde(skip, default)]
    pub version_leases: crate::artifact_cache::SharedVersionLeases,
    /// Daemon-shared remote bucket clients, circuit breakers, and bounded
    /// write-behind uploader for this cache directory (stow#1700).
    #[serde(skip, default)]
    pub bucket_handles: crate::bucket_cache::BucketCacheHandles,
}

pub type TierStaging = Arc<
    [tokio::sync::Mutex<std::collections::BTreeMap<String, Arc<crate::artifact_cache::StagingDir>>>;
        3],
>;

pub const fn default_fuse() -> bool {
    cfg!(target_os = "linux")
}

pub fn default_tier_staging() -> TierStaging {
    Arc::default()
}

impl StowConfig {
    /// Get (lazily opening) the process's host `SQLite` pool for this config.
    ///
    /// # Errors
    ///
    /// Whatever opening the database fails with, and any use after the
    /// process closed its handle.
    pub async fn state_db_pool(&self) -> stow_types::error::Result<SqlitePool> {
        self.state_db.pool(&self.cache_dir).await
    }

    /// Get (lazily opening or creating) `tier`'s self-contained catalog pool.
    ///
    /// # Errors
    ///
    /// Whatever opening the catalog fails with, and any use after the
    /// process closed its handle.
    pub async fn tier_db_pool(&self, tier: CacheTier) -> stow_types::error::Result<SqlitePool> {
        self.state_db.tier_pool(&self.cache_dir, tier).await
    }

    /// Open `tier`'s catalog pool only when its file already exists on disk.
    ///
    /// # Errors
    ///
    /// Stat/open failures, schema mismatches, and any use after close.
    pub async fn existing_tier_db_pool(
        &self,
        tier: CacheTier,
    ) -> stow_types::error::Result<Option<SqlitePool>> {
        self.state_db
            .existing_tier_pool(&self.cache_dir, tier)
            .await
    }

    /// Get (lazily loading) the Sigstore trust root for this config.
    ///
    /// # Errors
    ///
    /// Whatever loading the trust root fails with.
    pub async fn trust_material(
        &self,
    ) -> stow_types::error::Result<Arc<crate::verify::TrustMaterial>> {
        let material = self
            .trust_material
            .get_or_try_init(|| async {
                crate::verify::load_trust_material(&self.cache_dir)
                    .await
                    .map(Arc::new)
            })
            .await?;
        Ok(Arc::clone(material))
    }

    /// Refuse a network request while the remote cache is off. Callers gate
    /// on [`CacheLayers::reaches_network`] first, so the failure is a wiring
    /// bug, never a path a build takes.
    ///
    /// # Errors
    ///
    /// The remote cache layer is off.
    pub fn require_network(&self, what: &str) -> stow_types::error::Result<()> {
        if self.cache.reaches_network() {
            return Ok(());
        }
        Err(stow_types::stow_error!(
            "{what} needs the network, but the remote cache is off; set `remote = true` in the `[cache]` table of the stow config and drop `--no-remote-cache` to allow it"
        ))
    }

    /// Get (lazily building) the registry HTTP client for this config.
    ///
    /// # Errors
    ///
    /// The cache mode does not reach the network, or whatever building the
    /// client fails with.
    pub async fn registry_http(&self) -> stow_types::error::Result<stow_oci::RegistryHttp> {
        self.require_network("a registry request")?;
        let http = self
            .registry_http
            .get_or_try_init(|| {
                stow_oci::RegistryHttp::new(stow_oci::TransportPolicy {
                    connect_timeout: Some(REGISTRY_CONNECT_TIMEOUT),
                    retry_connect_failures: false,
                })
            })
            .await?;
        Ok(http.clone())
    }

    /// Get (lazily creating) this process's staging directory inside
    /// `tier`'s `rustc_version` artifact cache: `<tier>/<version>/staging/<name>/`,
    /// with its `<name>.lock` held until the handle drops.
    ///
    /// # Errors
    ///
    /// Whatever creating or locking the staging directory fails with.
    pub async fn artifact_cache_staging_dir(
        &self,
        tier: CacheTier,
        rustc_version: &str,
    ) -> stow_types::error::Result<Arc<crate::artifact_cache::StagingDir>> {
        let mut by_version = self.artifact_cache_staging[tier.index()].lock().await;
        if let Some(existing) = by_version.get(rustc_version)
            && existing.rustc_version() == rustc_version
            && existing.is_live_on_disk()
        {
            return Ok(Arc::clone(existing));
        }
        let staging_root = self
            .tier_version_dir(tier, rustc_version)
            .join(crate::artifact_cache::STAGING_DIR);
        let version = rustc_version.to_owned();
        let staging = tokio::task::spawn_blocking(move || {
            crate::artifact_cache::StagingDir::acquire(&staging_root, &version)
        })
        .await
        .wrap_err("join artifact cache staging task")??;
        let staging = Arc::new(staging);
        by_version.insert(rustc_version.to_owned(), Arc::clone(&staging));
        drop(by_version);
        Ok(staging)
    }

    /// Release cached [`crate::artifact_cache::StagingDir`] handles in `tier`
    /// for every rustc version other than `keep_version` that holds no active
    /// version lease and has no in-flight store reference, so Windows can
    /// rename idle `<tier>/<stale_version>` directories into `.purge/`.
    pub async fn release_idle_artifact_cache_staging(&self, tier: CacheTier, keep_version: &str) {
        let mut by_version = self.artifact_cache_staging[tier.index()].lock().await;
        let evicted: Vec<Arc<crate::artifact_cache::StagingDir>> = by_version
            .extract_if(.., |version, staging| {
                version != keep_version
                    && !self.version_leases.is_held(tier, version)
                    && Arc::strong_count(staging) == 1
            })
            .map(|(_, staging)| staging)
            .collect();
        drop(by_version);
        if !evicted.is_empty() {
            let _ = tokio::task::spawn_blocking(move || drop(evicted)).await;
        }
    }
}

/// How downloaded bundles are verified. The mock variant exists only in a
/// build with the `mock-verify` feature, so a release binary cannot be
/// switched to a local key by environment or config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyMode {
    GithubCi,
    #[cfg(feature = "mock-verify")]
    MockKey {
        /// PEM public key every bundle signature must verify against.
        public_key_path: PathBuf,
        /// SHA-256 of the PEM bytes, read once at load; names the trust
        /// policy in cached-bundle trust markers.
        public_key_sha256: String,
    },
}

impl VerifyMode {
    /// The wire string `STOW_VERIFY_MODE` accepts.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::GithubCi => "github-ci",
            #[cfg(feature = "mock-verify")]
            Self::MockKey { .. } => "mock-key",
        }
    }
}

impl StowConfig {
    /// The config of this process's own environment.
    ///
    /// # Errors
    ///
    /// As [`Self::load_in`], and the working directory cannot be read.
    #[tracing::instrument(name = "stow.config.load", skip_all)]
    pub fn load(state_db: StateDb) -> stow_types::error::Result<Self> {
        Self::load_in(&SessionEnv::of_this_process()?, state_db)
    }

    /// The config `env` names: its variables, its home directory and the
    /// config file under it decide every value, never the loading
    /// process's own environment.
    ///
    /// # Errors
    ///
    /// A config file that cannot be read or parsed, or a value that does
    /// not parse.
    pub fn load_in(env: &SessionEnv, state_db: StateDb) -> stow_types::error::Result<Self> {
        let file_config = load_user_config(env)?;
        let verify_mode = load_verify_mode(env, file_config.as_ref())?;
        let cache = file_config
            .as_ref()
            .and_then(|config| config.cache.as_ref())
            .map_or_default(CacheUserConfig::layers);
        let bucket = resolve_bucket_config(env, file_config.as_ref())?.map(Box::new);
        Ok(Self {
            switches: Switches::of_environ(env.environ()),
            cache,
            bucket,
            edge_url: resolve_edge_url(env, file_config.as_ref()),
            registry_base_url: resolve_registry_base_url(env, file_config.as_ref()),
            cache_dir: resolve_cache_dir(env, file_config.as_ref())?,
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
            artifact_cache_max_bytes: load_artifact_cache_max_bytes(env, file_config.as_ref())?,
            index_refresh_interval: load_index_refresh_interval(env, file_config.as_ref())?,
            build_dir_idle: load_build_dir_idle(env, file_config.as_ref())?,
            build_dir_max_bytes: load_u64_setting(
                env,
                STOW_BUILD_DIR_MAX_BYTES_ENV,
                file_config
                    .as_ref()
                    .and_then(|config| config.build_dir_max_bytes),
                DEFAULT_BUILD_DIR_MAX_BYTES,
            )?,
            build_dir_min_free_bytes: load_u64_setting(
                env,
                STOW_BUILD_DIR_MIN_FREE_BYTES_ENV,
                file_config
                    .as_ref()
                    .and_then(|config| config.build_dir_min_free_bytes),
                DEFAULT_BUILD_DIR_MIN_FREE_BYTES,
            )?,
            fuse: load_fuse(env, file_config.as_ref())?,
            verify_mode,
            state_db,
            trust_material: Arc::default(),
            registry_http: Arc::default(),
            artifact_cache_staging: default_tier_staging(),
            version_leases: crate::artifact_cache::SharedVersionLeases::default(),
            bucket_handles: crate::bucket_cache::BucketCacheHandles::default(),
        })
    }

    /// Whether the configured remote bucket backs `tier`.
    ///
    /// Never true for [`CacheTier::CratesIo`], which belongs to the signed
    /// public cache alone.
    #[must_use]
    pub fn bucket_syncs_tier(&self, tier: CacheTier) -> bool {
        let Some(bucket) = self.bucket.as_deref() else {
            return false;
        };
        match tier {
            CacheTier::CratesIo => false,
            CacheTier::LocalCratesIo => self.cache.local_crates_io && bucket.local_crates_io,
            CacheTier::Local => self.cache.local_crates_io || self.cache.local_git,
        }
    }

    /// Whether the configured remote bucket syncs `local-crates-io/`.
    #[must_use]
    pub fn bucket_syncs_local_crates_io(&self) -> bool {
        self.bucket_syncs_tier(CacheTier::LocalCratesIo)
    }

    pub async fn ensure_dirs(&self) -> stow_types::error::Result<()> {
        async_fs::create_dir_all(&self.cache_dir)
            .await
            .wrap_err_with(|| format!("create cache directory {}", self.cache_dir.display()))
    }

    #[must_use]
    pub fn tier_dir(&self, tier: CacheTier) -> PathBuf {
        crate::state_db::tier_dir(&self.cache_dir, tier)
    }

    #[must_use]
    pub fn tier_version_dir(&self, tier: CacheTier, rustc_version: &str) -> PathBuf {
        self.tier_dir(tier).join(rustc_version)
    }

    pub fn artifact_cache_purge_root(&self) -> PathBuf {
        self.cache_dir.join("purge")
    }

    /// The directory the C/C++ object cache lives in — `<key>.o` files
    /// under `~/.stow/local/cc/`, each with a `cc_cache_entries` row in
    /// `local/`'s self-contained catalog.
    pub fn cc_cache_dir(&self) -> PathBuf {
        self.tier_dir(CacheTier::Local).join("cc")
    }
}

/// The stow config file `env` names.
///
/// # Errors
///
/// No per-user config directory can be resolved for `env`.
pub fn config_file_path(env: &SessionEnv) -> stow_types::error::Result<PathBuf> {
    let config_dir =
        config_dir_in(env).ok_or_else(|| stow_types::stow_error!("resolve config directory"))?;
    Ok(config_dir.join("stow").join("config.toml"))
}

/// The per-user config directory in `env`, by the rule the `dirs` crate
/// applies to the process's own environment: `$XDG_CONFIG_HOME` when it
/// is absolute, else `~/.config` on Linux and the other Unixes;
/// `~/Library/Application Support` on macOS; the known folder on Windows,
/// which no variable decides.
fn config_dir_in(env: &SessionEnv) -> Option<PathBuf> {
    if cfg!(windows) {
        return dirs::config_dir();
    }
    if cfg!(target_os = "macos") {
        return env
            .home_dir()
            .map(|home| home.join("Library").join("Application Support"));
    }
    env.var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
        .or_else(|| env.home_dir().map(|home| home.join(".config")))
}

/// The `[isolation]` table of the global config, the defaults when the file
/// or the table is absent.
///
/// Read on its own rather than through [`StowConfig`], so a config that cannot
/// be parsed fails the build instead of leaving it to run at a level the user
/// did not choose.
///
/// # Errors
///
/// A config file that exists and cannot be read or parsed.
pub fn load_isolation_config(
    env: &SessionEnv,
) -> stow_types::error::Result<crate::isolation::IsolationConfig> {
    Ok(load_user_config(env)?
        .and_then(|config| config.isolation)
        .unwrap_or_default())
}

/// The directory the isolation audit logs are written to: the per-user data
/// directory, apart from the artifact cache, since an audit trail is written
/// at every cache mode.
///
/// # Errors
///
/// No per-user data directory on this platform.
pub fn audit_dir() -> stow_types::error::Result<PathBuf> {
    let data_dir = dirs::data_local_dir()
        .ok_or_else(|| stow_types::stow_error!("resolve the per-user data directory"))?;
    Ok(data_dir.join("stow").join("audit"))
}

/// The artifact cache directory `env` names.
///
/// # Errors
///
/// A config file that cannot be read or parsed, an empty override, or no
/// home directory.
pub fn cache_dir(env: &SessionEnv) -> stow_types::error::Result<PathBuf> {
    let file_config = load_user_config(env)?;
    resolve_cache_dir(env, file_config.as_ref())
}

/// The per-user tools directory (`~/Library/Application Support/stow/tools`
/// on macOS, `~/.local/share/stow/tools` on Linux, `%LOCALAPPDATA%\stow\tools`
/// on Windows). The managed mold install lives under it; the wrapper shims
/// moved to [`shims_dir`] — one directory per cargo home and stow binary —
/// because one shared directory let any stow re-point every other's shims
/// (stow#645).
pub fn tools_dir() -> stow_types::error::Result<PathBuf> {
    wrapper_shim::tools_dir()
}

/// The directory the rustc/cc wrapper shims are materialized into:
/// `<cargo home>/stow/shims/<key>/`, where `<key>` is the first 16 hex
/// characters of the blake3 of `runtime_executable`'s path bytes — the
/// path exactly as the caller resolved it, not canonicalized.
///
/// One directory per (cargo home, stow binary) is what makes the shims
/// safe to share a filesystem (stow#645):
///
/// - The path is stable across builds of the same binary in the same
///   cargo home, so cargo's `target/.rustc_info.json` probe cache — which
///   hashes the `RUSTC_WRAPPER` path into its key — holds. A per-build
///   directory would re-run cargo's rustc probes on every build.
/// - Two stow binaries never share a directory, so nothing re-points
///   another binary's shims at itself mid-build.
/// - A test that isolates `CARGO_HOME` isolates its shims with no further
///   knob.
pub fn shims_dir(cargo_home: &Path, runtime_executable: &Path) -> PathBuf {
    let key = blake3::hash(runtime_executable.as_os_str().as_encoded_bytes()).to_hex();
    cargo_home.join("stow").join("shims").join(&key[..16])
}

/// The directory cargo reads its user-level `config.toml` from: `$CARGO_HOME`
/// when set, else `~/.cargo` — the same resolution cargo performs. `None`
/// when neither source can produce a path.
pub fn cargo_home() -> Option<PathBuf> {
    cargo_home_with(|key| std::env::var_os(key))
}

/// [`cargo_home`] or the error every caller that cannot proceed without a
/// cargo home reports.
///
/// # Errors
///
/// `None` from [`cargo_home`] — neither `CARGO_HOME` nor a home directory
/// is available.
pub fn require_cargo_home() -> stow_types::error::Result<PathBuf> {
    cargo_home().ok_or_else(|| {
        stow_types::stow_error!(
            "resolve the cargo home — neither $CARGO_HOME nor a home directory is available"
        )
    })
}

/// [`cargo_home`] with the environment injected, so a caller — or a test —
/// answers `CARGO_HOME`, and the home directory it falls back to, from its
/// own lookup instead of the process's.
pub fn cargo_home_with(env: impl Fn(&str) -> Option<std::ffi::OsString>) -> Option<PathBuf> {
    env("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| home_dir_with(env).map(|home| home.join(".cargo")))
}

/// The home directory the environment `env` reads names, as cargo's
/// `home` crate resolves it: the variable it reads first (`HOME`, or
/// `USERPROFILE` on Windows) when set and non-empty, else the account's
/// own home directory.
pub fn home_dir_with(env: impl Fn(&str) -> Option<std::ffi::OsString>) -> Option<PathBuf> {
    let variable = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    env(variable)
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
}

fn resolve_cache_dir(
    env: &SessionEnv,
    file_config: Option<&StowUserConfig>,
) -> stow_types::error::Result<PathBuf> {
    if let Some(value) = env.var_os(STOW_CACHE_DIR_ENV) {
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

    let home_dir = env
        .home_dir()
        .ok_or_else(|| stow_types::stow_error!("resolve home directory"))?;
    Ok(home_dir.join(".stow"))
}

/// The value of `key` in `env` as text; a value that is not Unicode is
/// absent, as `std::env::var(..).ok()` reads it.
fn text_var(env: &SessionEnv, key: &str) -> Option<String> {
    env.var_os(key)
        .and_then(std::ffi::OsStr::to_str)
        .map(str::to_owned)
}

fn resolve_edge_url(env: &SessionEnv, file_config: Option<&StowUserConfig>) -> String {
    text_var(env, STOW_EDGE_URL_ENV)
        .or_else(|| file_config.and_then(|config| config.edge_url.clone()))
        .unwrap_or_else(|| DEFAULT_EDGE_URL.to_owned())
}

fn resolve_registry_base_url(env: &SessionEnv, file_config: Option<&StowUserConfig>) -> String {
    text_var(env, STOW_REGISTRY_BASE_URL_ENV)
        .or_else(|| file_config.and_then(|config| config.registry_base_url.clone()))
        .unwrap_or_else(|| stow_types::registry::GHCR_REGISTRY_URL.to_owned())
}

fn load_index_refresh_interval(
    env: &SessionEnv,
    file_config: Option<&StowUserConfig>,
) -> stow_types::error::Result<Duration> {
    let raw = text_var(env, STOW_INDEX_REFRESH_SECS_ENV).or_else(|| {
        file_config
            .and_then(|config| config.index_refresh_secs)
            .map(|value| value.to_string())
    });
    let value = match raw {
        Some(raw) => raw.parse::<u64>().map_err(|error| {
            stow_types::stow_error!("parse {STOW_INDEX_REFRESH_SECS_ENV} as u64 seconds: {error}")
        })?,
        None => DEFAULT_INDEX_REFRESH_SECS,
    };
    Ok(Duration::from_secs(value))
}

fn load_user_config(env: &SessionEnv) -> stow_types::error::Result<Option<StowUserConfig>> {
    let config_path = config_file_path(env)?;
    if !config_path.exists() {
        return Ok(None);
    }

    let contents = std::fs::read_to_string(&config_path)
        .wrap_err_with(|| format!("read {}", config_path.display()))?;
    let config = toml::from_str::<StowUserConfig>(&contents).wrap_err("parse stow config TOML")?;
    Ok(Some(config))
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CacheUserConfig {
    remote: bool,
    local_crates_io: bool,
    local_git: bool,
    bucket: Option<BucketCacheFileConfig>,
}

impl Default for CacheUserConfig {
    fn default() -> Self {
        let defaults = CacheLayers::default();
        Self {
            remote: defaults.remote,
            local_crates_io: defaults.local_crates_io,
            local_git: defaults.local_git,
            bucket: None,
        }
    }
}

impl CacheUserConfig {
    const fn layers(&self) -> CacheLayers {
        CacheLayers {
            remote: self.remote,
            local_crates_io: self.local_crates_io,
            local_git: self.local_git,
        }
    }
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct BucketCacheFileConfig {
    bucket: Option<String>,
    endpoint: Option<String>,
    region: Option<String>,
    prefix: Option<String>,
    read_only: Option<bool>,
    local_crates_io: Option<bool>,
    force_path_style: Option<bool>,
    connect_timeout_secs: Option<u64>,
    read_timeout_secs: Option<u64>,
    operation_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StowUserConfig {
    cache: Option<CacheUserConfig>,
    edge_url: Option<String>,
    registry_base_url: Option<String>,
    cache_dir: Option<String>,
    request_timeout_secs: Option<u64>,
    negative_cache_ttl_secs: Option<u64>,
    circuit_reset_secs: Option<u64>,
    circuit_trip_threshold: Option<u32>,
    artifact_cache_max_bytes: Option<u64>,
    index_refresh_secs: Option<u64>,
    build_dir_idle_secs: Option<u64>,
    build_dir_max_bytes: Option<u64>,
    build_dir_min_free_bytes: Option<u64>,
    fuse: Option<bool>,
    verify_mode: Option<String>,
    isolation: Option<crate::isolation::IsolationConfig>,
    #[cfg(feature = "mock-verify")]
    mock_public_key_path: Option<String>,
}

fn parse_bool_env(env: &SessionEnv, key: &str) -> stow_types::error::Result<Option<bool>> {
    let Some(raw) = text_var(env, key) else {
        return Ok(None);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(Some(true)),
        "0" | "false" | "no" => Ok(Some(false)),
        other => Err(stow_types::stow_error!(
            "parse {key} as boolean (`true`/`false`/`1`/`0`): got `{other}`"
        )),
    }
}

fn positive_timeout_secs(
    value: Option<u64>,
    field: &str,
    default: Duration,
) -> stow_types::error::Result<Duration> {
    match value {
        Some(0) => Err(stow_types::stow_error!(
            "[cache.bucket] {field} must be greater than zero"
        )),
        Some(secs) => Ok(Duration::from_secs(secs)),
        None => Ok(default),
    }
}

fn resolve_bucket_credentials(
    env: &SessionEnv,
) -> stow_types::error::Result<Option<BucketCredentials>> {
    let access_key = text_var(env, AWS_ACCESS_KEY_ID_ENV).filter(|value| !value.is_empty());
    let secret_key = text_var(env, AWS_SECRET_ACCESS_KEY_ENV).filter(|value| !value.is_empty());
    let session_token = text_var(env, AWS_SESSION_TOKEN_ENV).filter(|value| !value.is_empty());
    match (access_key, secret_key) {
        (Some(access_key_id), Some(secret_access_key)) => Ok(Some(BucketCredentials {
            access_key_id,
            secret_access_key,
            session_token,
        })),
        (Some(_), None) => Err(stow_types::stow_error!(
            "{AWS_ACCESS_KEY_ID_ENV} is set without {AWS_SECRET_ACCESS_KEY_ENV}"
        )),
        (None, Some(_)) => Err(stow_types::stow_error!(
            "{AWS_SECRET_ACCESS_KEY_ENV} is set without {AWS_ACCESS_KEY_ID_ENV}"
        )),
        (None, None) => Ok(None),
    }
}

fn resolve_bucket_config(
    env: &SessionEnv,
    file_config: Option<&StowUserConfig>,
) -> stow_types::error::Result<Option<BucketCacheConfig>> {
    let file_bucket = file_config
        .and_then(|config| config.cache.as_ref())
        .and_then(|cache| cache.bucket.as_ref());

    let bucket = match text_var(env, STOW_BUCKET_ENV) {
        Some(raw) if raw.trim().is_empty() => return Ok(None),
        Some(raw) => raw.trim().to_owned(),
        None => match file_bucket {
            None => return Ok(None),
            Some(file) => match file.bucket.as_deref().map(str::trim) {
                Some(name) if !name.is_empty() => name.to_owned(),
                _ => {
                    return Err(stow_types::stow_error!(
                        "[cache.bucket] requires a non-empty `bucket` name (or {STOW_BUCKET_ENV})"
                    ));
                }
            },
        },
    };

    let endpoint = match text_var(env, STOW_BUCKET_ENDPOINT_ENV) {
        Some(raw) if raw.trim().is_empty() => None,
        Some(raw) => Some(raw.trim().to_owned()),
        None => file_bucket
            .and_then(|file| file.endpoint.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
    };

    let region = text_var(env, STOW_BUCKET_REGION_ENV)
        .or_else(|| file_bucket.and_then(|file| file.region.clone()))
        .unwrap_or_else(|| DEFAULT_BUCKET_REGION.to_owned());
    let region = region.trim().to_owned();
    if region.is_empty() {
        return Err(stow_types::stow_error!(
            "bucket region ({STOW_BUCKET_REGION_ENV} or [cache.bucket] region) must not be empty"
        ));
    }

    let raw_prefix = text_var(env, STOW_BUCKET_PREFIX_ENV)
        .or_else(|| file_bucket.and_then(|file| file.prefix.clone()))
        .unwrap_or_else(|| DEFAULT_BUCKET_PREFIX.to_owned());
    let prefix = normalize_bucket_prefix(&raw_prefix);

    let read_only = parse_bool_env(env, STOW_BUCKET_READ_ONLY_ENV)?
        .or_else(|| file_bucket.and_then(|file| file.read_only))
        .unwrap_or(false);
    let local_crates_io = parse_bool_env(env, STOW_BUCKET_LOCAL_CRATES_IO_ENV)?
        .or_else(|| file_bucket.and_then(|file| file.local_crates_io))
        .unwrap_or(true);
    let force_path_style = parse_bool_env(env, STOW_BUCKET_FORCE_PATH_STYLE_ENV)?
        .or_else(|| file_bucket.and_then(|file| file.force_path_style));

    let connect_timeout = positive_timeout_secs(
        file_bucket.and_then(|file| file.connect_timeout_secs),
        "connect_timeout_secs",
        DEFAULT_BUCKET_CONNECT_TIMEOUT,
    )?;
    let read_timeout = positive_timeout_secs(
        file_bucket.and_then(|file| file.read_timeout_secs),
        "read_timeout_secs",
        DEFAULT_BUCKET_READ_TIMEOUT,
    )?;
    let operation_timeout = positive_timeout_secs(
        file_bucket.and_then(|file| file.operation_timeout_secs),
        "operation_timeout_secs",
        DEFAULT_BUCKET_OPERATION_TIMEOUT,
    )?;

    let credentials = resolve_bucket_credentials(env)?;

    Ok(Some(BucketCacheConfig {
        bucket,
        endpoint,
        region,
        prefix,
        read_only,
        local_crates_io,
        force_path_style,
        connect_timeout,
        read_timeout,
        operation_timeout,
        credentials,
    }))
}

fn load_verify_mode(
    env: &SessionEnv,
    file_config: Option<&StowUserConfig>,
) -> stow_types::error::Result<VerifyMode> {
    let raw = text_var(env, STOW_VERIFY_MODE_ENV)
        .or_else(|| file_config.and_then(|config| config.verify_mode.clone()))
        .unwrap_or_else(|| "github-ci".to_owned());
    match raw.as_str() {
        "github-ci" => Ok(VerifyMode::GithubCi),
        #[cfg(feature = "mock-verify")]
        "mock-key" => {
            let public_key_path = text_var(env, STOW_MOCK_PUBLIC_KEY_PATH_ENV)
                .map(PathBuf::from)
                .or_else(|| {
                    file_config
                        .and_then(|config| config.mock_public_key_path.as_ref())
                        .map(PathBuf::from)
                })
                .ok_or_else(|| {
                    stow_types::stow_error!(
                        "verify mode `mock-key` requires {STOW_MOCK_PUBLIC_KEY_PATH_ENV} or mock_public_key_path in config"
                    )
                })?;
            let public_key = std::fs::read(&public_key_path).map_err(|error| {
                stow_types::stow_error!(
                    "read mock public key {}: {error}",
                    public_key_path.display()
                )
            })?;
            let public_key_sha256 = hex::encode(sha2::Sha256::digest(public_key));
            Ok(VerifyMode::MockKey {
                public_key_path,
                public_key_sha256,
            })
        }
        #[cfg(not(feature = "mock-verify"))]
        "mock-key" => Err(stow_types::stow_error!(
            "verify mode `mock-key` is only available in a stow-cli built with the `mock-verify` cargo feature; this binary verifies against GitHub CI only"
        )),
        other => Err(stow_types::stow_error!(
            "unsupported verify mode `{other}`; expected `github-ci` or `mock-key`"
        )),
    }
}

fn load_artifact_cache_max_bytes(
    env: &SessionEnv,
    file_config: Option<&StowUserConfig>,
) -> stow_types::error::Result<u64> {
    let raw = text_var(env, STOW_ARTIFACT_CACHE_MAX_BYTES_ENV).or_else(|| {
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

fn load_u64_setting(
    env: &SessionEnv,
    env_key: &str,
    file_value: Option<u64>,
    default: u64,
) -> stow_types::error::Result<u64> {
    text_var(env, env_key).map_or_else(
        || Ok(file_value.unwrap_or(default)),
        |raw| {
            raw.parse::<u64>()
                .map_err(|error| stow_types::stow_error!("parse {env_key} as u64: {error}"))
        },
    )
}

fn load_build_dir_idle(
    env: &SessionEnv,
    file_config: Option<&StowUserConfig>,
) -> stow_types::error::Result<Duration> {
    text_var(env, STOW_BUILD_DIR_IDLE_SECS_ENV).map_or_else(
        || {
            Ok(file_config
                .and_then(|config| config.build_dir_idle_secs)
                .map_or(DEFAULT_BUILD_DIR_IDLE, Duration::from_secs))
        },
        |raw| {
            raw.parse::<u64>()
                .map(Duration::from_secs)
                .map_err(|error| {
                    stow_types::stow_error!(
                        "parse {STOW_BUILD_DIR_IDLE_SECS_ENV} as u64 seconds: {error}"
                    )
                })
        },
    )
}

fn load_fuse(
    env: &SessionEnv,
    file_config: Option<&StowUserConfig>,
) -> stow_types::error::Result<bool> {
    if let Some(raw) = text_var(env, STOW_FUSE_ENV) {
        return match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" => Ok(true),
            "0" | "false" => Ok(false),
            other => Err(stow_types::stow_error!(
                "parse {STOW_FUSE_ENV} as boolean (`1`/`true`/`0`/`false`), got `{other}`"
            )),
        };
    }
    Ok(file_config
        .and_then(|config| config.fuse)
        .unwrap_or_else(default_fuse))
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_layer_serves_only_the_entries_it_owns() {
        use super::{ArtifactProvenance as Provenance, CacheLayers, UnitSource};
        let crates_io = UnitSource::CratesIo {
            package: "demo".to_owned(),
            version: "1.0.0".to_owned(),
        };
        let git = UnitSource::Git {
            commit: "0".repeat(40),
            manifest_path_in_repo: String::new(),
        };
        for bits in 0..8u8 {
            let layers = CacheLayers {
                remote: bits & 1 != 0,
                local_crates_io: bits & 2 != 0,
                local_git: bits & 4 != 0,
            };
            // A downloaded entry belongs to the remote layer whatever its
            // source; a self-built one to the local layer of its source.
            for source in [&crates_io, &git] {
                assert_eq!(layers.serves(Provenance::Remote, source), layers.remote);
            }
            assert_eq!(
                layers.serves(Provenance::Local, &crates_io),
                layers.local_crates_io
            );
            assert_eq!(layers.serves(Provenance::Local, &git), layers.local_git);
            assert_eq!(layers.local(&crates_io), layers.local_crates_io);
            assert_eq!(layers.local(&git), layers.local_git);
            assert_eq!(layers.reaches_network(), layers.remote);
            assert_eq!(layers.is_off(), bits == 0);
            assert_eq!(layers.uses_cc_cache(), bits & 6 != 0);
        }
    }

    use std::path::Path;

    /// Every value a config carries comes from the environment it is
    /// loaded in — the variables, the home directory the config file is
    /// found under — never from the loading process's own. Windows finds
    /// the config directory through a known folder no variable decides, so
    /// the file half of the check is a Unix one.
    #[cfg(unix)]
    #[test]
    fn a_config_resolves_from_the_given_environment_alone() {
        use std::ffi::OsStr;

        use crate::session_env::SessionEnv;
        use crate::state_db::StateDb;

        let home = tempfile::tempdir().expect("home");
        let cache = home.path().join("elsewhere");
        let bare = SessionEnv::for_tests([("HOME", home.path().as_os_str())]);
        let file = super::config_file_path(&bare).expect("the config file's path");
        assert!(
            file.starts_with(home.path()),
            "{} is not under the environment's home {}",
            file.display(),
            home.path().display()
        );
        std::fs::create_dir_all(file.parent().expect("the config directory"))
            .expect("create the config directory");
        std::fs::write(
            &file,
            "registry_base_url = \"http://from-the-file.invalid\"\n",
        )
        .expect("write the config file");

        let env = SessionEnv::for_tests([
            ("HOME", home.path().as_os_str()),
            ("STOW_CACHE_DIR", cache.as_os_str()),
            ("STOW_EDGE_URL", OsStr::new("http://from-the-env.invalid")),
        ]);
        let config = super::StowConfig::load_in(&env, StateDb::closed()).expect("load the config");
        assert_eq!(config.cache_dir, cache);
        assert_eq!(config.edge_url, "http://from-the-env.invalid");
        assert_eq!(config.registry_base_url, "http://from-the-file.invalid");
        assert_eq!(
            super::cache_dir(&bare).expect("the default cache directory"),
            home.path().join(".stow")
        );
        assert_eq!(
            config.fuse,
            cfg!(target_os = "linux"),
            "fuse defaults on for Linux and off elsewhere"
        );
    }

    #[cfg(unix)]
    #[test]
    fn fuse_config_defaults_on_linux_and_honors_file_and_env() {
        use std::ffi::OsStr;

        use crate::session_env::SessionEnv;
        use crate::state_db::StateDb;

        let home = tempfile::tempdir().expect("home");
        let bare = SessionEnv::for_tests([("HOME", home.path().as_os_str())]);
        let default_cfg =
            super::StowConfig::load_in(&bare, StateDb::closed()).expect("default config");
        assert_eq!(default_cfg.fuse, cfg!(target_os = "linux"));

        let file = super::config_file_path(&bare).expect("config path");
        std::fs::create_dir_all(file.parent().expect("parent")).expect("mkdir");
        std::fs::write(&file, "fuse = false\n").expect("write config false");
        let from_file_off =
            super::StowConfig::load_in(&bare, StateDb::closed()).expect("file config off");
        assert!(!from_file_off.fuse);

        let env_on = SessionEnv::for_tests([
            ("HOME", home.path().as_os_str()),
            ("STOW_FUSE", OsStr::new("1")),
        ]);
        let overridden_on = super::StowConfig::load_in(&env_on, StateDb::closed()).expect("env on");
        assert!(overridden_on.fuse);

        std::fs::write(&file, "fuse = true\n").expect("write config true");
        let from_file = super::StowConfig::load_in(&bare, StateDb::closed()).expect("file config");
        assert!(from_file.fuse);

        let env_off = SessionEnv::for_tests([
            ("HOME", home.path().as_os_str()),
            ("STOW_FUSE", OsStr::new("0")),
        ]);
        let overridden_off =
            super::StowConfig::load_in(&env_off, StateDb::closed()).expect("env off");
        assert!(!overridden_off.fuse);

        let env_bad = SessionEnv::for_tests([
            ("HOME", home.path().as_os_str()),
            ("STOW_FUSE", OsStr::new("maybe")),
        ]);
        assert!(super::StowConfig::load_in(&env_bad, StateDb::closed()).is_err());
    }

    #[test]
    fn shims_dir_is_a_16_hex_key_under_the_cargo_home() {
        let cargo_home = Path::new("/cargo/home");
        let dir = super::shims_dir(cargo_home, Path::new("/usr/local/bin/stow-cli"));
        assert_eq!(
            dir.parent().expect("shims dir has a parent"),
            cargo_home.join("stow").join("shims")
        );
        let key = dir
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .expect("shims dir has a name");
        assert_eq!(key.len(), 16);
        assert!(
            key.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "key {key} is not 16 lowercase hex characters"
        );
    }

    #[test]
    fn shims_dir_keys_the_executable_path() {
        let cargo_home = Path::new("/cargo/home");
        let one = super::shims_dir(cargo_home, Path::new("/a/stow-cli"));
        let other = super::shims_dir(cargo_home, Path::new("/b/stow-cli"));
        assert_ne!(one, other, "two binaries must not share a shim dir");
        assert_eq!(
            one,
            super::shims_dir(cargo_home, Path::new("/a/stow-cli")),
            "the same binary must land on the same shim dir"
        );
    }

    /// The tools dir's contract, exercised against an injected data dir —
    /// calling `tools_dir` itself would resolve through the developer's
    /// home (stow#800).
    #[test]
    fn tools_dir_is_absolute_and_nested_under_the_data_dir() {
        let data_local = tempfile::tempdir().expect("data-local dir");
        let dir = crate::wrapper_shim::tools_dir_in(data_local.path());
        assert!(
            dir.is_absolute(),
            "tools dir {} is not absolute",
            dir.display()
        );
        assert!(
            dir.starts_with(data_local.path()),
            "tools dir {} is not under the data dir {}",
            dir.display(),
            data_local.path().display()
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

    #[cfg(unix)]
    #[test]
    fn bucket_config_parses_toml_file_with_remote_off() {
        use std::time::Duration;

        use crate::session_env::SessionEnv;
        use crate::state_db::{CacheTier, StateDb};

        let home = tempfile::tempdir().expect("home");
        let bare = SessionEnv::for_tests([("HOME", home.path().as_os_str())]);
        let file = super::config_file_path(&bare).expect("config path");
        std::fs::create_dir_all(file.parent().expect("config parent")).expect("mkdir");
        std::fs::write(
            &file,
            r#"
[cache]
remote = false

[cache.bucket]
bucket = "team-cache"
endpoint = "https://r2.example.invalid"
region = "wnam"
prefix = "/ci/stow"
read_only = true
local_crates_io = false
force_path_style = true
connect_timeout_secs = 4
read_timeout_secs = 12
operation_timeout_secs = 45
"#,
        )
        .expect("write config");

        let from_file =
            super::StowConfig::load_in(&bare, StateDb::closed()).expect("load file config");
        assert!(!from_file.cache.remote);
        assert!(!from_file.cache.reaches_network());
        let bucket = from_file.bucket.as_deref().expect("bucket enabled");
        assert_eq!(bucket.bucket, "team-cache");
        assert_eq!(
            bucket.endpoint.as_deref(),
            Some("https://r2.example.invalid")
        );
        assert_eq!(bucket.region, "wnam");
        assert_eq!(bucket.prefix, "ci/stow/");
        assert!(bucket.read_only);
        assert!(!bucket.local_crates_io);
        assert_eq!(bucket.force_path_style, Some(true));
        assert_eq!(bucket.connect_timeout, Duration::from_secs(4));
        assert_eq!(bucket.read_timeout, Duration::from_secs(12));
        assert_eq!(bucket.operation_timeout, Duration::from_secs(45));
        assert!(bucket.credentials.is_none());
        assert!(from_file.bucket_syncs_tier(CacheTier::Local));
        assert!(!from_file.bucket_syncs_local_crates_io());
        assert!(!from_file.bucket_syncs_tier(CacheTier::CratesIo));
    }

    #[cfg(unix)]
    #[test]
    fn bucket_config_applies_session_env_overrides_and_redacts_credentials() {
        use std::ffi::OsStr;

        use crate::session_env::SessionEnv;
        use crate::state_db::StateDb;

        let home = tempfile::tempdir().expect("home");
        let bare = SessionEnv::for_tests([("HOME", home.path().as_os_str())]);
        let file = super::config_file_path(&bare).expect("config path");
        std::fs::create_dir_all(file.parent().expect("config parent")).expect("mkdir");
        std::fs::write(&file, "[cache.bucket]\nbucket = \"team-cache\"\n").expect("write config");

        let env = SessionEnv::for_tests([
            ("HOME", home.path().as_os_str()),
            ("STOW_BUCKET", OsStr::new("override-bucket")),
            (
                "STOW_BUCKET_ENDPOINT",
                OsStr::new("https://override.example.invalid"),
            ),
            ("STOW_BUCKET_REGION", OsStr::new("us-east-1")),
            ("STOW_BUCKET_PREFIX", OsStr::new("dev")),
            ("STOW_BUCKET_READ_ONLY", OsStr::new("false")),
            ("STOW_BUCKET_LOCAL_CRATES_IO", OsStr::new("1")),
            ("STOW_BUCKET_FORCE_PATH_STYLE", OsStr::new("0")),
            ("AWS_ACCESS_KEY_ID", OsStr::new("AKIAEXAMPLE123")),
            ("AWS_SECRET_ACCESS_KEY", OsStr::new("super-secret-value")),
            ("AWS_SESSION_TOKEN", OsStr::new("temp-session-token")),
        ]);
        let overridden =
            super::StowConfig::load_in(&env, StateDb::closed()).expect("load overridden config");
        let bucket = overridden.bucket.as_deref().expect("bucket enabled");
        assert_eq!(bucket.bucket, "override-bucket");
        assert_eq!(
            bucket.endpoint.as_deref(),
            Some("https://override.example.invalid")
        );
        assert_eq!(bucket.region, "us-east-1");
        assert_eq!(bucket.prefix, "dev/");
        assert!(!bucket.read_only);
        assert!(bucket.local_crates_io);
        assert_eq!(bucket.force_path_style, Some(false));
        assert!(overridden.bucket_syncs_local_crates_io());
        let creds = bucket.credentials.as_ref().expect("session credentials");
        assert_eq!(creds.access_key_id, "AKIAEXAMPLE123");
        assert_eq!(creds.secret_access_key, "super-secret-value");
        assert_eq!(creds.session_token.as_deref(), Some("temp-session-token"));
        let debug = format!("{bucket:?}");
        assert!(
            !debug.contains("AKIAEXAMPLE123"),
            "debug leaked key id: {debug}"
        );
        assert!(
            !debug.contains("super-secret-value"),
            "debug leaked secret: {debug}"
        );
        assert!(
            !debug.contains("temp-session-token"),
            "debug leaked session token: {debug}"
        );

        let disabled_env = SessionEnv::for_tests([
            ("HOME", home.path().as_os_str()),
            ("STOW_BUCKET", OsStr::new("")),
        ]);
        let disabled = super::StowConfig::load_in(&disabled_env, StateDb::closed())
            .expect("load disabled config");
        assert!(disabled.bucket.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn bucket_config_rejects_partial_credentials_and_toml_secrets() {
        use std::ffi::OsStr;

        use crate::session_env::SessionEnv;
        use crate::state_db::StateDb;

        let home = tempfile::tempdir().expect("home");
        let partial = SessionEnv::for_tests([
            ("HOME", home.path().as_os_str()),
            ("STOW_BUCKET", OsStr::new("my-bucket")),
            ("AWS_ACCESS_KEY_ID", OsStr::new("AKIAONLY")),
        ]);
        let err = super::StowConfig::load_in(&partial, StateDb::closed())
            .expect_err("partial credentials must fail");
        assert!(err.to_string().contains("AWS_SECRET_ACCESS_KEY"), "{err}");

        let invalid_bool = SessionEnv::for_tests([
            ("HOME", home.path().as_os_str()),
            ("STOW_BUCKET", OsStr::new("my-bucket")),
            ("STOW_BUCKET_READ_ONLY", OsStr::new("maybe")),
        ]);
        assert!(super::StowConfig::load_in(&invalid_bool, StateDb::closed()).is_err());

        // Credentials are never accepted in config.toml (`deny_unknown_fields`).
        let bare = SessionEnv::for_tests([("HOME", home.path().as_os_str())]);
        let file = super::config_file_path(&bare).expect("config path");
        std::fs::create_dir_all(file.parent().expect("config parent")).expect("mkdir");
        std::fs::write(
            &file,
            "[cache.bucket]\nbucket = \"b\"\naccess_key_id = \"nope\"\n",
        )
        .expect("write config");
        assert!(super::StowConfig::load_in(&bare, StateDb::closed()).is_err());
    }
}
