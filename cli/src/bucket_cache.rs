//! Optional S3-compatible remote bucket L2 backing stow's local cache tiers
//! (`local/`, including `local/cc/`, and optionally `local-crates-io/`).
//!
//! Reads hydrate the local L1 cache on a miss (verifying every Rust output's
//! SHA-256 and installing atomically into the tier directory and catalog before
//! returning a [`CachedArtifactBundle`] so existing closure / SVH checks still
//! apply). Writes happen asynchronously in the background after L1 lands,
//! bounded in concurrency, deduplicated by object key, and drained on daemon
//! shutdown.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::io::{Read as _, Write as _};
use std::num::NonZeroUsize;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use skyzen_s3::S3Storage;
use skyzen_services::Storage;
use skyzen_services::storage::{PutOptions, StorageError};
use stow_types::artifact::{ArtifactKind, RustCrateType};
use stow_types::bundle::ArtifactBundleFile;
use stow_types::error::Context as _;
use stow_types::platform::Profile;
use stow_types::public_cache::{Reach, UnitSource};

use crate::artifact_cache::{
    ArtifactProvenance, BucketInstallInput, CachedArtifactBundle, install_staged_bucket_entry,
    load_cached_bundle_in_tier,
};
use crate::config::{BucketCacheConfig, StowConfig};
use crate::fetch::FetchRequest;
use crate::state_db::{CacheTier, now_millis};

/// Current manifest schema version stored inside `<entry_key>.tar.zst`.
const BUCKET_MANIFEST_SCHEMA_VERSION: u32 = 1;
/// Manifest file name inside every Rust archive.
const BUCKET_MANIFEST_PATH: &str = "manifest.json";
/// Subdirectory holding artifact output files inside every Rust archive.
const BUCKET_FILES_DIR: &str = "files";
/// Fast zstd compression level for local write-behind uploads: trades a small
/// amount of compression ratio relative to level 19 for fast packing on
/// developer machines.
const BUCKET_ZSTD_COMPRESSION_LEVEL: i32 = 3;
/// Content type recorded on every zstd-compressed bucket object.
const ZSTD_CONTENT_TYPE: &str = "application/zstd";
/// Maximum S3 retry attempts per bucket operation: 2 keeps transient blips
/// recoverable while letting outages trip the circuit quickly.
const BUCKET_MAX_ATTEMPTS: u32 = 2;

/// Isolated in-memory circuit breaker for remote bucket operations.
///
/// Separate from the public-cache circuit breaker in `state_db`: a bucket
/// outage degrades bucket reads/writes to local compilation without affecting
/// the public cache, and vice versa. Trips only on backend/IO/throttled/auth
/// errors — never on `None` (not found) or [`StorageError::Conflict`].
#[derive(Debug)]
pub struct BucketCircuit {
    trip_threshold: u32,
    reset_after: Duration,
    state: Mutex<BucketCircuitState>,
}

#[derive(Debug, Default)]
struct BucketCircuitState {
    consecutive_failures: u32,
    tripped_at: Option<Instant>,
}

impl BucketCircuit {
    /// Create a new circuit breaker with the given consecutive-failure trip
    /// threshold and reset cooldown.
    #[must_use]
    pub fn new(trip_threshold: u32, reset_after: Duration) -> Self {
        Self {
            trip_threshold: trip_threshold.max(1),
            reset_after,
            state: Mutex::new(BucketCircuitState::default()),
        }
    }

    /// Whether the breaker is currently open (tripped and within its cooldown).
    #[must_use]
    pub fn is_tripped(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(tripped_at) = state.tripped_at else {
            return false;
        };
        if tripped_at.elapsed() < self.reset_after {
            return true;
        }
        state.consecutive_failures = 0;
        state.tripped_at = None;
        false
    }

    /// Reset consecutive failures after a healthy bucket response.
    pub fn record_success(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.consecutive_failures = 0;
        state.tripped_at = None;
    }

    /// Count a backend failure and return `true` when this failure transitions
    /// the breaker into the open state.
    pub fn record_failure(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        let tripped =
            if state.consecutive_failures >= self.trip_threshold && state.tripped_at.is_none() {
                state.tripped_at = Some(Instant::now());
                true
            } else {
                false
            };
        drop(state);
        tripped
    }
}

/// Whether a [`StorageError`] counts as a bucket outage / auth failure for the
/// circuit breaker.
///
/// [`StorageError::Conflict`] means the object already exists under
/// `If-None-Match: *` and is never an error.
const fn is_circuit_error(error: &StorageError) -> bool {
    matches!(
        error,
        StorageError::Backend { .. }
            | StorageError::Io(_)
            | StorageError::Throttled { .. }
            | StorageError::Unauthorized
    )
}

/// Bounded-concurrency, key-deduplicated background uploader shared across all
/// sessions of one cache directory.
#[derive(Debug, Clone)]
pub struct BucketUploader {
    inner: Arc<UploaderInner>,
}

#[derive(Debug)]
struct UploaderInner {
    semaphore: Arc<tokio::sync::Semaphore>,
    state: Mutex<UploaderState>,
    idle: tokio::sync::Notify,
}

#[derive(Debug, Default)]
struct UploaderState {
    in_flight: HashSet<String>,
    pending: usize,
    closing: bool,
}

struct UploadGuard {
    inner: Arc<UploaderInner>,
    dedup_key: String,
}

impl Drop for UploadGuard {
    fn drop(&mut self) {
        let done = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.in_flight.remove(&self.dedup_key);
            state.pending = state.pending.saturating_sub(1);
            state.pending == 0
        };
        if done {
            self.inner.idle.notify_waiters();
        }
    }
}

impl Default for BucketUploader {
    fn default() -> Self {
        let concurrency = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
        Self::with_concurrency(concurrency)
    }
}

impl BucketUploader {
    /// Create an uploader with an explicit concurrency bound (clamped to >= 1).
    #[must_use]
    pub fn with_concurrency(max_concurrent: usize) -> Self {
        Self {
            inner: Arc::new(UploaderInner {
                semaphore: Arc::new(tokio::sync::Semaphore::new(max_concurrent.max(1))),
                state: Mutex::new(UploaderState::default()),
                idle: tokio::sync::Notify::new(),
            }),
        }
    }

    /// Enqueue a background upload task keyed by `dedup_key`.
    ///
    /// Returns `false` if an upload for `dedup_key` is already queued/running,
    /// if the uploader is draining for shutdown, or if no tokio runtime is
    /// active.
    pub fn enqueue<F>(&self, dedup_key: String, task: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return false;
        };
        {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.closing || !state.in_flight.insert(dedup_key.clone()) {
                return false;
            }
            state.pending = state.pending.saturating_add(1);
        }
        let inner = Arc::clone(&self.inner);
        handle.spawn(async move {
            let _guard = UploadGuard {
                inner: Arc::clone(&inner),
                dedup_key,
            };
            let Ok(_permit) = inner.semaphore.acquire().await else {
                return;
            };
            task.await;
        });
        true
    }

    /// Wait for every currently queued/running upload to complete without
    /// rejecting future uploads.
    pub async fn flush(&self) {
        self.wait_until_idle(false).await;
    }

    /// Reject new uploads and wait for every queued/running upload to finish
    /// before returning (called during `stow daemon stop`).
    pub async fn drain(&self) {
        self.wait_until_idle(true).await;
    }

    async fn wait_until_idle(&self, close: bool) {
        loop {
            let notified = self.inner.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = self
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if close {
                    state.closing = true;
                }
                if state.pending == 0 {
                    return;
                }
            }
            notified.await;
        }
    }
}

/// Live client and isolated circuit breaker for one bucket configuration.
pub struct BucketClient {
    storage: Storage,
    circuit: Arc<BucketCircuit>,
}

impl fmt::Debug for BucketClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BucketClient")
            .field("circuit", &self.circuit)
            .finish_non_exhaustive()
    }
}

impl BucketClient {
    /// Wrap any [`Storage`] backend with a fresh circuit breaker.
    #[must_use]
    pub const fn from_storage(storage: Storage, circuit: Arc<BucketCircuit>) -> Self {
        Self { storage, circuit }
    }

    /// Build a production [`S3Storage`]-backed client from `bucket` config.
    pub async fn connect(
        bucket: &BucketCacheConfig,
        circuit_trip_threshold: u32,
        circuit_reset_after: Duration,
    ) -> Self {
        let mut builder = S3Storage::builder(&bucket.bucket)
            .region(&bucket.region)
            .timeouts(bucket.s3_timeouts())
            .max_attempts(BUCKET_MAX_ATTEMPTS);
        if let Some(endpoint) = &bucket.endpoint {
            builder = builder.endpoint_url(endpoint);
        }
        if let Some(force_path_style) = bucket.force_path_style {
            builder = builder.force_path_style(force_path_style);
        }
        if let Some(credentials) = bucket.credentials.clone() {
            builder = builder.credentials(credentials.into_s3_credentials());
        }
        let storage = Storage::new(builder.build().await);
        let circuit = Arc::new(BucketCircuit::new(
            circuit_trip_threshold,
            circuit_reset_after,
        ));
        Self { storage, circuit }
    }

    async fn get(&self, key: &str) -> Option<Vec<u8>> {
        if self.circuit.is_tripped() {
            return None;
        }
        match self.storage.get(key).await {
            Ok(Some(object)) => {
                self.circuit.record_success();
                Some(object.body)
            }
            Ok(None) => {
                self.circuit.record_success();
                None
            }
            Err(error) => {
                self.handle_storage_error("get", key, &error);
                None
            }
        }
    }

    async fn put_if_not_exists(&self, key: &str, body: Vec<u8>) -> bool {
        if self.circuit.is_tripped() {
            return false;
        }
        let options = PutOptions::new()
            .with_content_type(ZSTD_CONTENT_TYPE)
            .if_not_exists();
        match self.storage.put_with(key, body, options).await {
            Ok(()) => {
                self.circuit.record_success();
                true
            }
            Err(StorageError::Conflict) => {
                // Object already exists in bucket; treat as already present and
                // never trip the circuit breaker.
                self.circuit.record_success();
                tracing::debug!(key, "remote bucket object already present (conflict)");
                true
            }
            Err(error) => {
                self.handle_storage_error("put", key, &error);
                false
            }
        }
    }

    fn handle_storage_error(&self, op: &str, key: &str, error: &StorageError) {
        if is_circuit_error(error) {
            let tripped = self.circuit.record_failure();
            if tripped {
                tracing::warn!(
                    op,
                    key,
                    error = %error,
                    "remote bucket circuit breaker tripped; degrading to local cache"
                );
            } else {
                tracing::warn!(
                    op,
                    key,
                    error = %error,
                    "remote bucket operation failed; degrading to local cache"
                );
            }
        } else {
            tracing::warn!(
                op,
                key,
                error = %error,
                "remote bucket operation returned non-circuit error"
            );
        }
    }
}

/// Shared remote bucket clients and bounded background uploader held per cache
/// directory by [`crate::daemon::session::CacheDirHandles`] and attached to
/// [`StowConfig`].
#[derive(Debug, Clone, Default)]
pub struct BucketCacheHandles {
    inner: Arc<BucketHandlesInner>,
}

#[derive(Debug, Default)]
struct BucketHandlesInner {
    /// Cached clients keyed by the exact session [`BucketCacheConfig`] so
    /// sessions with distinct buckets or per-session credentials stay isolated.
    clients: tokio::sync::Mutex<HashMap<BucketCacheConfig, Arc<BucketClient>>>,
    /// Optional pre-injected client used by tests (e.g. `InMemoryStorage`).
    override_client: Option<Arc<BucketClient>>,
    uploader: BucketUploader,
}

impl BucketCacheHandles {
    /// Inject a pre-built [`Storage`] backend (for tests using
    /// `skyzen_test::mock::InMemoryStorage`).
    #[cfg(test)]
    #[must_use]
    pub fn with_storage(storage: Storage, trip_threshold: u32, reset_after: Duration) -> Self {
        let circuit = Arc::new(BucketCircuit::new(trip_threshold, reset_after));
        let client = Arc::new(BucketClient::from_storage(storage, circuit));
        Self {
            inner: Arc::new(BucketHandlesInner {
                clients: tokio::sync::Mutex::new(HashMap::new()),
                override_client: Some(client),
                uploader: BucketUploader::default(),
            }),
        }
    }

    /// Inject a pre-built [`Storage`] backend and explicit uploader concurrency
    /// (for tests).
    #[cfg(test)]
    #[must_use]
    pub fn with_storage_and_uploader(
        storage: Storage,
        trip_threshold: u32,
        reset_after: Duration,
        uploader: BucketUploader,
    ) -> Self {
        let circuit = Arc::new(BucketCircuit::new(trip_threshold, reset_after));
        let client = Arc::new(BucketClient::from_storage(storage, circuit));
        Self {
            inner: Arc::new(BucketHandlesInner {
                clients: tokio::sync::Mutex::new(HashMap::new()),
                override_client: Some(client),
                uploader,
            }),
        }
    }

    /// Resolve (lazily connecting) the [`BucketClient`] for `config`.
    pub async fn client_for(&self, config: &StowConfig) -> Option<Arc<BucketClient>> {
        let bucket = config.bucket.as_deref()?;
        if let Some(client) = &self.inner.override_client {
            return Some(Arc::clone(client));
        }
        {
            let guard = self.inner.clients.lock().await;
            if let Some(client) = guard.get(bucket) {
                return Some(Arc::clone(client));
            }
        }
        let built = Arc::new(
            Box::pin(BucketClient::connect(
                bucket,
                config.circuit_trip_threshold,
                config.circuit_reset_after,
            ))
            .await,
        );
        let client = Arc::clone(
            self.inner
                .clients
                .lock()
                .await
                .entry(bucket.clone())
                .or_insert_with(|| Arc::clone(&built)),
        );
        Some(client)
    }

    /// Reference to the shared background uploader.
    #[must_use]
    pub fn uploader(&self) -> &BucketUploader {
        &self.inner.uploader
    }

    /// Wait for currently pending uploads without closing the uploader.
    #[cfg(test)]
    pub async fn flush(&self) {
        self.inner.uploader.flush().await;
    }

    /// Drain all pending uploads and stop accepting new ones (called on daemon
    /// shutdown).
    pub async fn drain(&self) {
        self.inner.uploader.drain().await;
    }
}

/// Metadata stored as `manifest.json` inside every Rust bucket archive
/// (`<prefix>v1/<tier>/<rustc_version>/<target>/<entry_key>.tar.zst`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketArtifactManifest {
    pub schema_version: u32,
    pub rustc_version: String,
    pub target: String,
    pub entry_key: String,
    pub compile_key: String,
    pub crate_name: String,
    pub crate_version: String,
    pub c_metadata: String,
    pub features_json: String,
    pub dependency_c_metadata_json: String,
    pub dependency_compile_keys_json: String,
    pub dependency_instances_json: String,
    pub reach: i64,
    pub compile_millis: u64,
    pub profile: Profile,
    pub emit: Vec<String>,
    pub kind: ArtifactKind,
    pub crate_types: Vec<RustCrateType>,
    pub outputs: Vec<ArtifactBundleFile>,
}

/// Object key for a Rust local-cache archive:
/// `<prefix>v1/<tier>/<rustc_version>/<target>/<entry_key>.tar.zst`.
#[must_use]
pub fn rust_object_key(
    prefix: &str,
    tier: CacheTier,
    rustc_version: &str,
    target: &str,
    entry_key: &str,
) -> String {
    format!(
        "{prefix}v1/{}/{rustc_version}/{target}/{entry_key}.tar.zst",
        tier.dir_name()
    )
}

/// Object key for a C/C++ object:
/// `<prefix>v1/cc/<cache_key>.o.zst`.
#[must_use]
pub fn cc_object_key(prefix: &str, cache_key: &str) -> String {
    format!("{prefix}v1/cc/{cache_key}.o.zst")
}

/// Read-through a Rust artifact from the remote bucket into `tier`'s L1 cache
/// and return the installed [`CachedArtifactBundle`].
///
/// Returns `Ok(None)` when no bucket is configured, the tier/source is not
/// eligible, the bucket circuit is open, the object is absent, or the archive
/// fails integrity/path validation (degrading cleanly to local compilation).
pub async fn pull_rust_artifact(
    config: &StowConfig,
    tier: CacheTier,
    source: &UnitSource,
    request: &FetchRequest<'_>,
) -> stow_types::error::Result<Option<CachedArtifactBundle>> {
    if tier == CacheTier::CratesIo || !config.bucket_syncs_tier(tier) || !config.cache.local(source)
    {
        return Ok(None);
    }
    let Some(bucket) = config.bucket.as_ref() else {
        return Ok(None);
    };
    let Some(client) = config.bucket_handles.client_for(config).await else {
        return Ok(None);
    };
    let key = rust_object_key(
        &bucket.prefix,
        tier,
        request.rustc_version,
        request.target,
        request.c_metadata,
    );
    let Some(archive_bytes) = client.get(&key).await else {
        return Ok(None);
    };

    let staging_dir = config
        .artifact_cache_staging_dir(tier, request.rustc_version)
        .await?;
    let expected_rustc = request.rustc_version.to_owned();
    let expected_target = request.target.to_owned();
    let expected_entry_key = request.c_metadata.to_owned();
    let unpacked = tokio::task::spawn_blocking(move || {
        unpack_rust_entry_blocking(
            staging_dir.path(),
            &archive_bytes,
            &expected_rustc,
            &expected_target,
            &expected_entry_key,
        )
    })
    .await
    .wrap_err("join bucket rust artifact unpack task")?;

    let unpacked = match unpacked {
        Ok(unpacked) => unpacked,
        Err(error) => {
            tracing::warn!(
                key,
                error = %error,
                "discarding invalid or corrupted remote bucket Rust artifact"
            );
            return Ok(None);
        }
    };

    let Some(reach) = Reach::from_int(unpacked.manifest.reach) else {
        tracing::warn!(
            key,
            reach = unpacked.manifest.reach,
            "discarding remote bucket Rust artifact with unknown reach"
        );
        return Ok(None);
    };
    if CacheTier::for_local_reach(reach) != tier {
        tracing::warn!(
            key,
            expected_tier = tier.dir_name(),
            actual_tier = CacheTier::for_local_reach(reach).dir_name(),
            "discarding remote bucket Rust artifact whose reach mismatches its tier"
        );
        return Ok(None);
    }

    let manifest = &unpacked.manifest;
    let input = BucketInstallInput {
        tier,
        rustc_version: &manifest.rustc_version,
        target: &manifest.target,
        entry_key: &manifest.entry_key,
        compile_key: &manifest.compile_key,
        crate_name: &manifest.crate_name,
        crate_version: manifest.crate_version.clone(),
        c_metadata: &manifest.c_metadata,
        features_json: manifest.features_json.clone(),
        dependency_c_metadata_json: manifest.dependency_c_metadata_json.clone(),
        dependency_compile_keys_json: &manifest.dependency_compile_keys_json,
        dependency_instances_json: &manifest.dependency_instances_json,
        reach,
        compile_millis: manifest.compile_millis,
        profile: &manifest.profile,
        emit: &manifest.emit,
        kind: &manifest.kind,
        crate_types: &manifest.crate_types,
        outputs: &manifest.outputs,
        size_bytes: unpacked.size_bytes,
    };

    let installed = install_staged_bucket_entry(config, unpacked.staged, &input).await?;
    if installed.is_some() {
        tracing::debug!(
            key,
            tier = tier.dir_name(),
            crate_name = %manifest.crate_name,
            "hydrated L1 Rust cache entry from remote bucket"
        );
    }
    Ok(installed)
}

/// Enqueue a write-behind upload of a freshly stored, non-`manifest_scoped`
/// local Rust cache entry.
///
/// Never uploads [`CacheTier::CratesIo`] entries, skips when `read_only = true`
/// or when `tier` is not enabled for the bucket.
pub fn enqueue_rust_upload(
    config: &StowConfig,
    tier: CacheTier,
    rustc_version: &str,
    target: &str,
    entry_key: &str,
) {
    if tier == CacheTier::CratesIo || !config.bucket_syncs_tier(tier) {
        return;
    }
    let Some(bucket) = config.bucket.as_ref() else {
        return;
    };
    if bucket.read_only {
        return;
    }
    let object_key = rust_object_key(&bucket.prefix, tier, rustc_version, target, entry_key);
    let dedup_key = format!("{}::{object_key}", bucket.bucket);
    let uploader = config.bucket_handles.uploader().clone();
    let config = config.clone();
    let rustc_version = rustc_version.to_owned();
    let target = target.to_owned();
    let entry_key = entry_key.to_owned();
    uploader.enqueue(dedup_key, async move {
        upload_rust_entry(
            &config,
            tier,
            &rustc_version,
            &target,
            &entry_key,
            &object_key,
        )
        .await;
    });
}

async fn upload_rust_entry(
    config: &StowConfig,
    tier: CacheTier,
    rustc_version: &str,
    target: &str,
    entry_key: &str,
    object_key: &str,
) {
    let Some(client) = config.bucket_handles.client_for(config).await else {
        return;
    };
    if client.circuit.is_tripped() {
        return;
    }
    let bundle = match load_cached_bundle_in_tier(
        config,
        tier,
        &FetchRequest {
            target,
            rustc_version,
            c_metadata: entry_key,
        },
    )
    .await
    {
        Ok(Some(bundle)) => bundle,
        Ok(None) => return,
        Err(error) => {
            tracing::debug!(
                key = object_key,
                error = %error,
                "skipping remote bucket upload: failed to load L1 Rust entry"
            );
            return;
        }
    };
    if bundle.provenance != ArtifactProvenance::Local || bundle.tier == CacheTier::CratesIo {
        return;
    }
    let target_owned = target.to_owned();
    let entry_key_owned = entry_key.to_owned();
    let packed = tokio::task::spawn_blocking(move || {
        let bytes = pack_rust_entry_blocking(&bundle, &target_owned, &entry_key_owned);
        drop(bundle);
        bytes
    })
    .await;

    let archive_bytes = match packed {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(error)) => {
            tracing::warn!(
                key = object_key,
                error = %error,
                "failed to pack L1 Rust cache entry for remote bucket upload"
            );
            return;
        }
        Err(error) => {
            tracing::warn!(
                key = object_key,
                error = %error,
                "bucket Rust archive pack task panicked"
            );
            return;
        }
    };

    if client.put_if_not_exists(object_key, archive_bytes).await {
        tracing::debug!(
            key = object_key,
            "uploaded Rust cache entry to remote bucket"
        );
    }
}

/// Read-through a C/C++ object (`<prefix>v1/cc/<cache_key>.o.zst`) from the
/// remote bucket into `local/cc/<cache_key>.o` + `cc_cache_entries`.
///
/// Returns `Ok(None)` when no bucket is configured, the local C/C++ cache is
/// disabled, the circuit is open, the object is absent, or decompression fails.
pub async fn pull_cc_object(
    config: &StowConfig,
    cache_key: &str,
) -> stow_types::error::Result<Option<PathBuf>> {
    if !config.cache.uses_cc_cache() || !config.bucket_syncs_tier(CacheTier::Local) {
        return Ok(None);
    }
    if !crate::cc::is_cache_key(cache_key) {
        return Ok(None);
    }
    let Some(bucket) = config.bucket.as_ref() else {
        return Ok(None);
    };
    let Some(client) = config.bucket_handles.client_for(config).await else {
        return Ok(None);
    };
    let object_key = cc_object_key(&bucket.prefix, cache_key);
    let Some(compressed) = client.get(&object_key).await else {
        return Ok(None);
    };

    let cache_path = crate::cc::cached_object_path(config, cache_key);
    if let Some(parent) = cache_path.parent() {
        async_fs::create_dir_all(parent)
            .await
            .wrap_err_with(|| format!("create C cache directory {}", parent.display()))?;
    }

    let dest_path = cache_path.clone();
    let written = tokio::task::spawn_blocking(move || {
        decompress_and_install_cc_blocking(&compressed, &dest_path)
    })
    .await
    .wrap_err("join bucket C/C++ object unpack task")?;

    let size_bytes = match written {
        Ok(size) => size,
        Err(error) => {
            tracing::warn!(
                key = object_key,
                error = %error,
                "discarding invalid or corrupted remote bucket C/C++ object"
            );
            return Ok(None);
        }
    };

    let connection = config.tier_db_pool(CacheTier::Local).await?;
    crate::cc::upsert_cc_cache_entry(&connection, cache_key, size_bytes, now_millis()).await?;
    crate::artifact_cache::evict_after_cc_store(config, cache_key).await?;
    tracing::debug!(
        key = object_key,
        cache_key,
        "hydrated L1 C/C++ object from remote bucket"
    );
    Ok(Some(cache_path))
}

/// Enqueue a write-behind upload of a freshly published C/C++ object.
pub fn enqueue_cc_upload(config: &StowConfig, cache_key: &str) {
    if !config.cache.uses_cc_cache() || !config.bucket_syncs_tier(CacheTier::Local) {
        return;
    }
    if !crate::cc::is_cache_key(cache_key) {
        return;
    }
    let Some(bucket) = config.bucket.as_ref() else {
        return;
    };
    if bucket.read_only {
        return;
    }
    let object_key = cc_object_key(&bucket.prefix, cache_key);
    let dedup_key = format!("{}::{object_key}", bucket.bucket);
    let uploader = config.bucket_handles.uploader().clone();
    let config = config.clone();
    let cache_key = cache_key.to_owned();
    uploader.enqueue(dedup_key, async move {
        upload_cc_object(&config, &cache_key, &object_key).await;
    });
}

async fn upload_cc_object(config: &StowConfig, cache_key: &str, object_key: &str) {
    let Some(client) = config.bucket_handles.client_for(config).await else {
        return;
    };
    if client.circuit.is_tripped() {
        return;
    }
    let cache_path = crate::cc::cached_object_path(config, cache_key);
    let compressed =
        tokio::task::spawn_blocking(move || -> stow_types::error::Result<Option<Vec<u8>>> {
            let raw = match std::fs::read(&cache_path) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => {
                    return Err(error)
                        .wrap_err_with(|| format!("read C/C++ object {}", cache_path.display()));
                }
            };
            let encoded =
                compress_zstd(&raw).wrap_err("compress C/C++ object for remote bucket")?;
            Ok(Some(encoded))
        })
        .await;

    let body = match compressed {
        Ok(Ok(Some(body))) => body,
        Ok(Ok(None)) => return,
        Ok(Err(error)) => {
            tracing::warn!(
                key = object_key,
                error = %error,
                "failed to compress C/C++ object for remote bucket upload"
            );
            return;
        }
        Err(error) => {
            tracing::warn!(
                key = object_key,
                error = %error,
                "bucket C/C++ compress task panicked"
            );
            return;
        }
    };

    if client.put_if_not_exists(object_key, body).await {
        tracing::debug!(key = object_key, "uploaded C/C++ object to remote bucket");
    }
}

fn compress_zstd(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), BUCKET_ZSTD_COMPRESSION_LEVEL)?;
    encoder.set_pledged_src_size(Some(bytes.len() as u64))?;
    encoder.write_all(bytes)?;
    encoder.finish()
}

fn decompress_zstd(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut decoder = zstd::stream::Decoder::new(bytes)?;
    decoder.window_log_max(stow_shim::STOW_ZSTD_WINDOW_LOG)?;
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

fn decompress_and_install_cc_blocking(
    compressed: &[u8],
    cache_path: &Path,
) -> stow_types::error::Result<u64> {
    let raw = decompress_zstd(compressed).wrap_err("decompress remote bucket C/C++ object")?;
    let cache_dir = cache_path.parent().ok_or_else(|| {
        stow_types::stow_error!("C object cache path {} has no parent", cache_path.display())
    })?;
    let mut staged = tempfile::Builder::new()
        .prefix(".bucket-cc-")
        .suffix(".o")
        .tempfile_in(cache_dir)
        .wrap_err_with(|| format!("create temp C/C++ object in {}", cache_dir.display()))?;
    staged
        .write_all(&raw)
        .wrap_err("write decompressed C/C++ object")?;
    staged.flush().wrap_err("flush decompressed C/C++ object")?;
    let size_bytes = raw.len() as u64;
    match staged.persist_noclobber(cache_path) {
        Ok(_) => Ok(size_bytes),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(std::fs::metadata(cache_path).map_or(size_bytes, |meta| meta.len()))
        }
        Err(error) => Err(
            stow_types::error::Error::from(error.error).wrap_err(format!(
                "move bucket C/C++ object into cache at {}",
                cache_path.display()
            )),
        ),
    }
}

fn validate_output_file_name(name: &str) -> stow_types::error::Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(stow_types::stow_error!(
            "unsafe output file name `{name}` in remote bucket archive"
        ));
    }
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(stow_types::stow_error!(
            "unsafe output file name `{name}` in remote bucket archive"
        )),
    }
}

enum ArchiveEntryPath {
    Manifest,
    File(String),
}

fn parse_archive_path(path: &Path) -> stow_types::error::Result<ArchiveEntryPath> {
    let raw = path.to_str().ok_or_else(|| {
        stow_types::stow_error!(
            "non-UTF-8 path in remote bucket archive: {}",
            path.display()
        )
    })?;
    if raw.contains('\\') || raw.contains('\0') {
        return Err(stow_types::stow_error!(
            "rejected path `{raw}` in remote bucket archive"
        ));
    }
    let mut components = path.components();
    match (components.next(), components.next(), components.next()) {
        (Some(Component::Normal(first)), None, None) if first == BUCKET_MANIFEST_PATH => {
            Ok(ArchiveEntryPath::Manifest)
        }
        (Some(Component::Normal(first)), Some(Component::Normal(second)), None)
            if first == BUCKET_FILES_DIR =>
        {
            let name = second.to_str().ok_or_else(|| {
                stow_types::stow_error!("non-UTF-8 file name in remote bucket archive")
            })?;
            validate_output_file_name(name)?;
            Ok(ArchiveEntryPath::File(name.to_owned()))
        }
        _ => Err(stow_types::stow_error!(
            "rejected disallowed path `{raw}` in remote bucket archive"
        )),
    }
}

fn append_tar_file(
    tar: &mut tar::Builder<Vec<u8>>,
    path: &str,
    bytes: &[u8],
) -> stow_types::error::Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    tar.append_data(&mut header, path, bytes)
        .wrap_err_with(|| format!("append `{path}` to remote bucket archive"))
}

fn pack_rust_entry_blocking(
    bundle: &CachedArtifactBundle,
    target: &str,
    entry_key: &str,
) -> stow_types::error::Result<Vec<u8>> {
    let manifest = BucketArtifactManifest {
        schema_version: BUCKET_MANIFEST_SCHEMA_VERSION,
        rustc_version: bundle.rustc_version.clone(),
        target: target.to_owned(),
        entry_key: entry_key.to_owned(),
        compile_key: bundle.compile_key.clone(),
        crate_name: bundle.crate_name.clone(),
        crate_version: bundle.crate_version.clone(),
        c_metadata: bundle.c_metadata.clone(),
        features_json: bundle.features_json.clone(),
        dependency_c_metadata_json: bundle.dependency_c_metadata_json.clone(),
        dependency_compile_keys_json: bundle.dependency_compile_keys_json.clone(),
        dependency_instances_json: bundle.dependency_instances_json.clone(),
        reach: bundle.reach.to_int(),
        compile_millis: bundle.compile_millis,
        profile: bundle.profile.clone(),
        emit: bundle.emit.clone(),
        kind: bundle.kind.clone(),
        crate_types: bundle.crate_types.clone(),
        outputs: bundle.outputs.clone(),
    };
    let manifest_bytes =
        serde_json::to_vec(&manifest).wrap_err("serialize remote bucket artifact manifest")?;

    let mut tar = tar::Builder::new(Vec::new());
    append_tar_file(&mut tar, BUCKET_MANIFEST_PATH, &manifest_bytes)?;
    for output in &bundle.outputs {
        validate_output_file_name(&output.file_name)?;
        let source_path = bundle.output_source_path(output);
        let bytes = std::fs::read(&source_path).wrap_err_with(|| {
            format!("read L1 output {} for bucket pack", source_path.display())
        })?;
        let archive_path = format!("{BUCKET_FILES_DIR}/{}", output.file_name);
        append_tar_file(&mut tar, &archive_path, &bytes)?;
    }
    let tar_bytes = tar
        .into_inner()
        .wrap_err("finish remote bucket artifact tar")?;
    compress_zstd(&tar_bytes).wrap_err("compress remote bucket artifact archive")
}

struct UnpackedBucketEntry {
    staged: tempfile::TempDir,
    manifest: BucketArtifactManifest,
    size_bytes: u64,
}

fn unpack_rust_entry_blocking(
    staging_dir: &Path,
    archive_bytes: &[u8],
    expected_rustc_version: &str,
    expected_target: &str,
    expected_entry_key: &str,
) -> stow_types::error::Result<UnpackedBucketEntry> {
    let mut decoder =
        zstd::stream::Decoder::new(archive_bytes).wrap_err("open remote bucket zstd stream")?;
    decoder
        .window_log_max(stow_shim::STOW_ZSTD_WINDOW_LOG)
        .wrap_err("bound remote bucket zstd decoder window")?;
    let mut archive = tar::Archive::new(decoder);

    let staged = tempfile::Builder::new()
        .prefix(&format!("{expected_entry_key}-"))
        .tempdir_in(staging_dir)
        .wrap_err_with(|| format!("create bucket staging dir in {}", staging_dir.display()))?;
    let files_dir = staged.path().join(BUCKET_FILES_DIR);
    std::fs::create_dir_all(&files_dir)
        .wrap_err_with(|| format!("create bucket staging files dir {}", files_dir.display()))?;

    let mut manifest: Option<BucketArtifactManifest> = None;
    let mut extracted_files: BTreeMap<String, (String, u64)> = BTreeMap::new();
    let mut copy_buf = vec![0u8; 64 * 1024];

    for entry in archive
        .entries()
        .wrap_err("read remote bucket tar entries")?
    {
        let mut entry = entry.wrap_err("read remote bucket tar entry")?;
        if !entry.header().entry_type().is_file() {
            return Err(stow_types::stow_error!(
                "remote bucket archive contains non-regular entry `{}`",
                entry
                    .path()
                    .map_or_else(|_| "<invalid>".to_owned(), |p| p.display().to_string())
            ));
        }
        let path = entry.path().wrap_err("read remote bucket tar entry path")?;
        match parse_archive_path(&path)? {
            ArchiveEntryPath::Manifest => {
                if manifest.is_some() {
                    return Err(stow_types::stow_error!(
                        "remote bucket archive contains duplicate manifest.json"
                    ));
                }
                let mut bytes = Vec::new();
                entry
                    .read_to_end(&mut bytes)
                    .wrap_err("read manifest.json from remote bucket archive")?;
                manifest = Some(
                    serde_json::from_slice(&bytes)
                        .wrap_err("parse manifest.json from remote bucket archive")?,
                );
            }
            ArchiveEntryPath::File(file_name) => {
                if extracted_files.contains_key(&file_name) {
                    return Err(stow_types::stow_error!(
                        "remote bucket archive contains duplicate file `{file_name}`"
                    ));
                }
                let digest_and_len = extract_and_hash_entry(
                    &mut entry,
                    &files_dir.join(&file_name),
                    &file_name,
                    &mut copy_buf,
                )?;
                extracted_files.insert(file_name, digest_and_len);
            }
        }
    }

    let manifest = manifest
        .ok_or_else(|| stow_types::stow_error!("remote bucket archive is missing manifest.json"))?;
    let size_bytes = verify_unpacked_manifest(
        &manifest,
        &extracted_files,
        expected_rustc_version,
        expected_target,
        expected_entry_key,
    )?;

    Ok(UnpackedBucketEntry {
        staged,
        manifest,
        size_bytes,
    })
}

fn extract_and_hash_entry<R: std::io::Read>(
    entry: &mut R,
    dest_path: &Path,
    file_name: &str,
    buffer: &mut [u8],
) -> stow_types::error::Result<(String, u64)> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest_path)
        .wrap_err_with(|| format!("create staged bucket output {}", dest_path.display()))?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    loop {
        let read = entry
            .read(buffer)
            .wrap_err_with(|| format!("read `{file_name}` from bucket archive"))?;
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];
        file.write_all(chunk)
            .wrap_err_with(|| format!("write staged bucket output {}", dest_path.display()))?;
        hasher.update(chunk);
        total = total.saturating_add(read as u64);
    }
    file.flush()
        .wrap_err_with(|| format!("flush staged bucket output {}", dest_path.display()))?;
    Ok((hex::encode(hasher.finalize()), total))
}

fn verify_unpacked_manifest(
    manifest: &BucketArtifactManifest,
    extracted_files: &BTreeMap<String, (String, u64)>,
    expected_rustc_version: &str,
    expected_target: &str,
    expected_entry_key: &str,
) -> stow_types::error::Result<u64> {
    if manifest.schema_version != BUCKET_MANIFEST_SCHEMA_VERSION {
        return Err(stow_types::stow_error!(
            "unsupported remote bucket manifest schema version {}",
            manifest.schema_version
        ));
    }
    if manifest.rustc_version != expected_rustc_version
        || manifest.target != expected_target
        || manifest.entry_key != expected_entry_key
        || manifest.c_metadata != expected_entry_key
    {
        return Err(stow_types::stow_error!(
            "remote bucket manifest identity ({}/{}/{}) does not match requested ({expected_rustc_version}/{expected_target}/{expected_entry_key})",
            manifest.rustc_version,
            manifest.target,
            manifest.entry_key
        ));
    }
    if manifest.outputs.is_empty() {
        return Err(stow_types::stow_error!(
            "remote bucket manifest declares no outputs"
        ));
    }
    if manifest.outputs.len() != extracted_files.len() {
        return Err(stow_types::stow_error!(
            "remote bucket archive file count ({}) does not match manifest outputs ({})",
            extracted_files.len(),
            manifest.outputs.len()
        ));
    }

    let mut size_bytes = 0u64;
    for output in &manifest.outputs {
        validate_output_file_name(&output.file_name)?;
        let Some((actual_sha256, len)) = extracted_files.get(&output.file_name) else {
            return Err(stow_types::stow_error!(
                "remote bucket archive is missing declared output `{}`",
                output.file_name
            ));
        };
        if actual_sha256 != &output.sha256 {
            return Err(stow_types::stow_error!(
                "remote bucket output `{}` sha256 mismatch: expected {}, got {actual_sha256}",
                output.file_name,
                output.sha256
            ));
        }
        size_bytes = size_bytes.saturating_add(*len);
    }
    Ok(size_bytes)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use skyzen_services::Storage;
    use skyzen_services::storage::ListOptions;
    use skyzen_test::mock::InMemoryStorage;
    use stow_types::public_cache::{Reach, StableUnitIdentity, UnitSource};

    use super::*;
    use crate::artifact_cache::{
        LocalBuildArtifact, LocalEntryKey, MaterializedDependency, ResolvedDependencies,
        hash_local_build_outputs_sync, local_build_output_specs, prepare_local_cache,
        record_materialized_local_build_outputs, store_local_build_outputs,
    };
    use crate::config::{BucketCacheConfig, CacheLayers, StowConfig, Switches, VerifyMode};
    use crate::daemon::session::Resources;
    use crate::daemon::wrapper::InvocationEnv;
    use crate::rustc_args::ParsedRustcArgs;
    use crate::state_db::StateDb;
    use stow_types::rustc::ParsedExternCrate;

    const TEST_RUSTC: &str = "1.91.1";
    const TEST_TARGET: &str = "aarch64-apple-darwin";

    fn machine_config(
        cache_dir: &Path,
        storage: &InMemoryStorage,
        bucket: BucketCacheConfig,
        trip_threshold: u32,
        reset_after: Duration,
    ) -> StowConfig {
        StowConfig {
            switches: Switches::default(),
            cache: CacheLayers {
                // Public cache OFF to prove private bucket works independently.
                remote: false,
                local_crates_io: true,
                local_git: true,
            },
            bucket: Some(Box::new(bucket)),
            edge_url: "http://127.0.0.1:9".to_owned(),
            registry_base_url: "http://127.0.0.1:9".to_owned(),
            cache_dir: cache_dir.to_path_buf(),
            request_timeout: Duration::from_secs(5),
            negative_cache_ttl: Duration::from_secs(60),
            circuit_reset_after: reset_after,
            circuit_trip_threshold: trip_threshold,
            artifact_cache_max_bytes: 512 * 1024 * 1024,
            index_refresh_interval: Duration::from_secs(60),
            build_dir_idle: crate::config::DEFAULT_BUILD_DIR_IDLE,
            verify_mode: VerifyMode::GithubCi,
            state_db: StateDb::default(),
            trust_material: Arc::default(),
            registry_http: Arc::default(),
            artifact_cache_staging: crate::config::default_tier_staging(),
            version_leases: crate::artifact_cache::SharedVersionLeases::default(),
            bucket_handles: BucketCacheHandles::with_storage(
                Storage::new(storage.clone()),
                trip_threshold,
                reset_after,
            ),
        }
    }

    fn git_source() -> UnitSource {
        UnitSource::Git {
            commit: "a".repeat(40),
            manifest_path_in_repo: String::new(),
        }
    }

    fn crates_io_source(name: &str) -> UnitSource {
        UnitSource::CratesIo {
            package: name.to_owned(),
            version: "1.0.0".to_owned(),
        }
    }

    fn make_parsed_rlib(
        crate_name: &str,
        cargo_c_metadata: &str,
        out_dir: &Path,
        extern_crates: Vec<ParsedExternCrate>,
    ) -> ParsedRustcArgs {
        ParsedRustcArgs {
            crate_name: crate_name.to_owned(),
            crate_types: vec!["rlib".to_owned()],
            features: BTreeSet::default(),
            cfgs: BTreeSet::default(),
            cfg_args: Vec::new(),
            emit: ["dep-info", "metadata", "link"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            json: BTreeSet::default(),
            input_path: Some(out_dir.join(format!("{crate_name}.rs"))),
            target: Some(TEST_TARGET.to_owned()),
            c_metadata: Some(cargo_c_metadata.to_owned()),
            out_dir: Some(out_dir.to_path_buf()),
            extra_filename: format!("-{cargo_c_metadata}"),
            opt_level: Some("0".to_owned()),
            debuginfo: Some("0".to_owned()),
            panic_strategy: None,
            debug_assertions: Some(true),
            overflow_checks: Some(true),
            strip: None,
            native_search_paths: Vec::new(),
            build_script_out_dir: None,
            cargo_bin_name: false,
            extern_crates,
            embed_metadata: None,
            embed_bitcode: false,
            extra_codegen: Vec::new(),
            link_options: Vec::new(),
        }
    }

    fn write_and_build_artifact(
        parsed: &ParsedRustcArgs,
        stable_c_metadata: &str,
        source: UnitSource,
        reach: Reach,
        rlib_bytes: &[u8],
        rmeta_bytes: &[u8],
        dependencies: ResolvedDependencies,
    ) -> LocalBuildArtifact {
        let rlib = parsed.output_rlib_path().expect("rlib path");
        let rmeta = parsed.output_rmeta_path().expect("rmeta path");
        let dep_info = parsed.output_dep_info_path().expect("dep-info path");
        std::fs::create_dir_all(rlib.parent().expect("parent")).expect("mkdir");
        std::fs::write(&rlib, rlib_bytes).expect("write rlib");
        std::fs::write(&rmeta, rmeta_bytes).expect("write rmeta");
        std::fs::write(&dep_info, format!("{}: src/lib.rs\n", rlib.display()))
            .expect("write dep-info");

        let identity = StableUnitIdentity {
            compile_key: format!("{stable_c_metadata}{stable_c_metadata}"),
            c_metadata: stable_c_metadata.to_owned(),
            extra_filename: format!("-{stable_c_metadata}"),
            crate_name: parsed.crate_name.clone(),
            version: "1.0.0".to_owned(),
            source,
            reach,
        };
        let stable_parsed = crate::inject::parsed_with_stable_identity(
            parsed,
            &identity.c_metadata,
            &identity.extra_filename,
        );
        let mut outputs =
            local_build_output_specs(parsed, &stable_parsed, TEST_TARGET).expect("output specs");
        hash_local_build_outputs_sync(&mut outputs).expect("hash outputs");
        LocalBuildArtifact {
            target: TEST_TARGET.to_owned(),
            rustc_version: TEST_RUSTC.to_owned(),
            identity,
            reach,
            features_json: "[]".to_owned(),
            dependencies,
            outputs,
            compile_millis: 42,
        }
    }

    fn empty_deps(reach: Reach) -> ResolvedDependencies {
        ResolvedDependencies {
            c_metadata_json: "[]".to_owned(),
            externs: Vec::new(),
            reach,
        }
    }

    #[tokio::test]
    async fn cross_machine_local_git_rust_dep_sharing_with_public_cache_off() {
        let storage = InMemoryStorage::new();
        let dir_a = tempfile::tempdir().expect("dir_a");
        let dir_b = tempfile::tempdir().expect("dir_b");
        let cfg_a = machine_config(
            dir_a.path(),
            &storage,
            BucketCacheConfig::for_bucket("shared"),
            3,
            Duration::from_secs(60),
        );
        let cfg_b = machine_config(
            dir_b.path(),
            &storage,
            BucketCacheConfig::for_bucket("shared"),
            3,
            Duration::from_secs(60),
        );
        let _lease_a = prepare_local_cache(&cfg_a, TEST_RUSTC)
            .await
            .expect("prep a");
        let _lease_b = prepare_local_cache(&cfg_b, TEST_RUSTC)
            .await
            .expect("prep b");

        let out_a = dir_a.path().join("target/deps");
        let parsed_a = make_parsed_rlib("gitdep", "cargo111111111111", &out_a, Vec::new());
        let stable = "aaaa111122223333";
        let build_a = write_and_build_artifact(
            &parsed_a,
            stable,
            git_source(),
            Reach::LocalOnly,
            b"git-rlib-payload",
            b"git-rmeta-payload",
            empty_deps(Reach::LocalOnly),
        );
        let env_a = InvocationEnv::for_tests();
        crate::store_local_build(&cfg_a, &parsed_a, &build_a, &env_a, TEST_TARGET)
            .await
            .expect("store local build on machine A");
        cfg_a.bucket_handles.flush().await;

        let expected_key =
            rust_object_key("stow/", CacheTier::Local, TEST_RUSTC, TEST_TARGET, stable);
        assert!(
            Storage::new(storage.clone())
                .head(&expected_key)
                .await
                .expect("head")
                .is_some(),
            "expected object at {expected_key}"
        );

        // Machine B has an empty L1 cache and pulls from the shared bucket.
        let out_b = dir_b.path().join("target/deps");
        std::fs::create_dir_all(&out_b).expect("mkdir out_b");
        let parsed_b = make_parsed_rlib("gitdep", "cargo999999999999", &out_b, Vec::new());
        let request = FetchRequest {
            target: TEST_TARGET,
            rustc_version: TEST_RUSTC,
            c_metadata: stable,
        };
        let pulled = pull_rust_artifact(&cfg_b, CacheTier::Local, &git_source(), &request)
            .await
            .expect("pull from bucket")
            .expect("bucket hit on machine B");
        assert_eq!(pulled.compile_millis, 42);
        assert_eq!(pulled.reach, Reach::LocalOnly);

        let mut tally = crate::LookupTally::default();
        let served = crate::try_serve_loaded_local_cached_bundle(
            &cfg_b,
            &parsed_b,
            &git_source(),
            &request,
            crate::EntryOrigin::ExactKey,
            pulled,
            &mut tally,
        )
        .await;
        assert!(served.is_some(), "machine B must serve hydrated bundle");
        assert_eq!(
            std::fs::read(parsed_b.output_rlib_path().expect("rlib")).expect("read rlib"),
            b"git-rlib-payload"
        );
        assert_eq!(
            std::fs::read(parsed_b.output_rmeta_path().expect("rmeta")).expect("read rmeta"),
            b"git-rmeta-payload"
        );
        // Subsequent lookup on Machine B hits L1 directly.
        assert!(
            load_cached_bundle_in_tier(&cfg_b, CacheTier::Local, &request)
                .await
                .expect("load L1")
                .is_some()
        );
    }

    #[tokio::test]
    async fn cross_machine_local_crates_io_sharing_and_opt_out() {
        let storage = InMemoryStorage::new();
        let dir_a = tempfile::tempdir().expect("dir_a");
        let dir_b = tempfile::tempdir().expect("dir_b");
        let dir_c = tempfile::tempdir().expect("dir_c");
        let cfg_a = machine_config(
            dir_a.path(),
            &storage,
            BucketCacheConfig::for_bucket("shared"),
            3,
            Duration::from_secs(60),
        );
        let cfg_b = machine_config(
            dir_b.path(),
            &storage,
            BucketCacheConfig::for_bucket("shared"),
            3,
            Duration::from_secs(60),
        );
        let mut no_crates_io_bucket = BucketCacheConfig::for_bucket("shared");
        no_crates_io_bucket.local_crates_io = false;
        let cfg_c = machine_config(
            dir_c.path(),
            &storage,
            no_crates_io_bucket,
            3,
            Duration::from_secs(60),
        );
        let _la = prepare_local_cache(&cfg_a, TEST_RUSTC)
            .await
            .expect("prep a");
        let _lb = prepare_local_cache(&cfg_b, TEST_RUSTC)
            .await
            .expect("prep b");
        let _lc = prepare_local_cache(&cfg_c, TEST_RUSTC)
            .await
            .expect("prep c");

        let out_a = dir_a.path().join("target/deps");
        let parsed_a = make_parsed_rlib("uncovered", "cargo222222222222", &out_a, Vec::new());
        let stable = "bbbb111122223333";
        let source = crates_io_source("uncovered");
        let build_a = write_and_build_artifact(
            &parsed_a,
            stable,
            source.clone(),
            Reach::Public,
            b"crates-io-rlib",
            b"crates-io-rmeta",
            empty_deps(Reach::Public),
        );
        crate::store_local_build(
            &cfg_a,
            &parsed_a,
            &build_a,
            &InvocationEnv::for_tests(),
            TEST_TARGET,
        )
        .await
        .expect("store on A");
        cfg_a.bucket_handles.flush().await;

        let expected_key = rust_object_key(
            "stow/",
            CacheTier::LocalCratesIo,
            TEST_RUSTC,
            TEST_TARGET,
            stable,
        );
        assert!(
            Storage::new(storage.clone())
                .head(&expected_key)
                .await
                .expect("head")
                .is_some()
        );

        let request = FetchRequest {
            target: TEST_TARGET,
            rustc_version: TEST_RUSTC,
            c_metadata: stable,
        };
        // Machine C has local_crates_io = false on its bucket config: skips pull.
        assert!(
            pull_rust_artifact(&cfg_c, CacheTier::LocalCratesIo, &source, &request)
                .await
                .expect("pull C")
                .is_none()
        );

        // Machine B pulls and serves it cleanly.
        let pulled = pull_rust_artifact(&cfg_b, CacheTier::LocalCratesIo, &source, &request)
            .await
            .expect("pull B")
            .expect("bucket hit on B");
        assert_eq!(pulled.tier, CacheTier::LocalCratesIo);
        assert_eq!(pulled.reach, Reach::Public);
    }

    #[tokio::test]
    async fn crates_io_tier_is_never_uploaded_or_pulled() {
        let storage = InMemoryStorage::new();
        let dir = tempfile::tempdir().expect("dir");
        let cfg = machine_config(
            dir.path(),
            &storage,
            BucketCacheConfig::for_bucket("shared"),
            3,
            Duration::from_secs(60),
        );
        enqueue_rust_upload(
            &cfg,
            CacheTier::CratesIo,
            TEST_RUSTC,
            TEST_TARGET,
            "abcd1234abcd1234",
        );
        cfg.bucket_handles.flush().await;
        let listed = Storage::new(storage.clone())
            .list(ListOptions::default())
            .await
            .expect("list");
        assert!(listed.objects.is_empty());

        let request = FetchRequest {
            target: TEST_TARGET,
            rustc_version: TEST_RUSTC,
            c_metadata: "abcd1234abcd1234",
        };
        assert!(
            pull_rust_artifact(&cfg, CacheTier::CratesIo, &crates_io_source("x"), &request)
                .await
                .expect("pull")
                .is_none()
        );
    }

    #[tokio::test]
    async fn cross_machine_cc_object_sharing() {
        let storage = InMemoryStorage::new();
        let dir_a = tempfile::tempdir().expect("dir_a");
        let dir_b = tempfile::tempdir().expect("dir_b");
        let cfg_a = machine_config(
            dir_a.path(),
            &storage,
            BucketCacheConfig::for_bucket("shared"),
            3,
            Duration::from_secs(60),
        );
        let cfg_b = machine_config(
            dir_b.path(),
            &storage,
            BucketCacheConfig::for_bucket("shared"),
            3,
            Duration::from_secs(60),
        );

        let cache_key = "a".repeat(64);
        let cc_dir_a = cfg_a.cc_cache_dir();
        std::fs::create_dir_all(&cc_dir_a).expect("mkdir cc_dir_a");
        let src_path = dir_a.path().join("foo.o");
        let obj_bytes = b"\x7fELF-fake-object-bytes-0123456789";
        std::fs::write(&src_path, obj_bytes).expect("write foo.o");
        let src_file = std::fs::File::open(&src_path).expect("open foo.o");
        let cache_path_a = crate::cc::cached_object_path(&cfg_a, &cache_key);
        let staged = crate::cc::stage_opened_object(&cache_path_a, src_file, &src_path)
            .await
            .expect("stage cc object");
        crate::cc::write_record(
            &cfg_a,
            crate::cc::CcRecord::Compiled {
                cache_key: cache_key.clone(),
                staged: Some(staged),
            },
        )
        .await;
        cfg_a.bucket_handles.flush().await;

        let expected_key = cc_object_key("stow/", &cache_key);
        assert!(
            Storage::new(storage.clone())
                .head(&expected_key)
                .await
                .expect("head cc")
                .is_some()
        );

        // Machine B misses locally, then pulls via bucket read-through.
        assert!(
            crate::cc::locate_cached_object(&cfg_b, &cache_key)
                .await
                .expect("locate local B")
                .is_none()
        );
        let hydrated = pull_cc_object(&cfg_b, &cache_key)
            .await
            .expect("pull cc")
            .expect("cc bucket hit");
        assert_eq!(std::fs::read(&hydrated).expect("read hydrated"), obj_bytes);

        // Verify cc_cache_entries catalog row exists on Machine B.
        let pool_b = cfg_b.tier_db_pool(CacheTier::Local).await.expect("pool b");
        let row_size: Option<i64> =
            sqlx::query_scalar("SELECT size_bytes FROM cc_cache_entries WHERE cache_key = ?")
                .bind(&cache_key)
                .fetch_optional(&pool_b)
                .await
                .expect("query cc_cache_entries");
        assert_eq!(row_size, Some(i64::try_from(obj_bytes.len()).expect("len")));
    }

    async fn store_cc_fixture(cfg: &StowConfig, dir: &Path, cache_key: &str, bytes: &[u8]) {
        std::fs::create_dir_all(cfg.cc_cache_dir()).expect("mkdir cc");
        let src_o = dir.join("fixture.o");
        std::fs::write(&src_o, bytes).expect("write fixture.o");
        let staged = crate::cc::stage_opened_object(
            &crate::cc::cached_object_path(cfg, cache_key),
            std::fs::File::open(&src_o).expect("open"),
            &src_o,
        )
        .await
        .expect("stage");
        crate::cc::write_record(
            cfg,
            crate::cc::CcRecord::Compiled {
                cache_key: cache_key.to_owned(),
                staged: Some(staged),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn read_only_mode_reads_without_uploading() {
        let storage = InMemoryStorage::new();
        let readonly_dir = tempfile::tempdir().expect("readonly_dir");
        let writable_dir = tempfile::tempdir().expect("writable_dir");
        let mut ro_bucket = BucketCacheConfig::for_bucket("shared");
        ro_bucket.read_only = true;
        let readonly_cfg = machine_config(
            readonly_dir.path(),
            &storage,
            ro_bucket,
            3,
            Duration::from_secs(60),
        );
        let writable_cfg = machine_config(
            writable_dir.path(),
            &storage,
            BucketCacheConfig::for_bucket("shared"),
            3,
            Duration::from_secs(60),
        );
        let _lro = prepare_local_cache(&readonly_cfg, TEST_RUSTC)
            .await
            .expect("prep ro");
        let _lrw = prepare_local_cache(&writable_cfg, TEST_RUSTC)
            .await
            .expect("prep rw");

        let readonly_out = readonly_dir.path().join("target/deps");
        let readonly_parsed =
            make_parsed_rlib("ro_crate", "cargo333333333333", &readonly_out, Vec::new());
        let readonly_build = write_and_build_artifact(
            &readonly_parsed,
            "cccc111122223333",
            git_source(),
            Reach::LocalOnly,
            b"ro-rlib",
            b"ro-rmeta",
            empty_deps(Reach::LocalOnly),
        );
        crate::store_local_build(
            &readonly_cfg,
            &readonly_parsed,
            &readonly_build,
            &InvocationEnv::for_tests(),
            TEST_TARGET,
        )
        .await
        .expect("store ro");
        store_cc_fixture(
            &readonly_cfg,
            readonly_dir.path(),
            &"b".repeat(64),
            b"ro-obj",
        )
        .await;
        readonly_cfg.bucket_handles.flush().await;
        assert!(
            Storage::new(storage.clone())
                .list(ListOptions::default())
                .await
                .expect("list")
                .objects
                .is_empty(),
            "read_only machine must never upload"
        );

        let writable_out = writable_dir.path().join("target/deps");
        let writable_parsed =
            make_parsed_rlib("rw_crate", "cargo444444444444", &writable_out, Vec::new());
        let stable_rw = "dddd111122223333";
        let writable_build = write_and_build_artifact(
            &writable_parsed,
            stable_rw,
            git_source(),
            Reach::LocalOnly,
            b"rw-rlib",
            b"rw-rmeta",
            empty_deps(Reach::LocalOnly),
        );
        crate::store_local_build(
            &writable_cfg,
            &writable_parsed,
            &writable_build,
            &InvocationEnv::for_tests(),
            TEST_TARGET,
        )
        .await
        .expect("store rw");
        writable_cfg.bucket_handles.flush().await;

        let request = FetchRequest {
            target: TEST_TARGET,
            rustc_version: TEST_RUSTC,
            c_metadata: stable_rw,
        };
        assert!(
            pull_rust_artifact(&readonly_cfg, CacheTier::Local, &git_source(), &request)
                .await
                .expect("pull ro")
                .is_some(),
            "read_only machine must still read from bucket"
        );
    }

    #[tokio::test]
    async fn conflict_on_conditional_put_does_not_overwrite_or_trip_circuit() {
        let storage = InMemoryStorage::new();
        let circuit = Arc::new(BucketCircuit::new(1, Duration::from_secs(60)));
        let client =
            BucketClient::from_storage(Storage::new(storage.clone()), Arc::clone(&circuit));

        assert!(
            client
                .put_if_not_exists("stow/v1/cc/test.o.zst", b"first".to_vec())
                .await
        );
        // Second put hits StorageError::Conflict -> treated as already present, circuit stays closed.
        assert!(
            client
                .put_if_not_exists("stow/v1/cc/test.o.zst", b"second".to_vec())
                .await
        );
        assert!(!circuit.is_tripped());
        assert_eq!(
            client.get("stow/v1/cc/test.o.zst").await.as_deref(),
            Some(b"first".as_slice())
        );
    }

    fn manifest_from_loaded(
        loaded: &CachedArtifactBundle,
        entry_key: &str,
    ) -> BucketArtifactManifest {
        BucketArtifactManifest {
            schema_version: BUCKET_MANIFEST_SCHEMA_VERSION,
            rustc_version: TEST_RUSTC.to_owned(),
            target: TEST_TARGET.to_owned(),
            entry_key: entry_key.to_owned(),
            compile_key: loaded.compile_key.clone(),
            crate_name: loaded.crate_name.clone(),
            crate_version: loaded.crate_version.clone(),
            c_metadata: loaded.c_metadata.clone(),
            features_json: loaded.features_json.clone(),
            dependency_c_metadata_json: loaded.dependency_c_metadata_json.clone(),
            dependency_compile_keys_json: loaded.dependency_compile_keys_json.clone(),
            dependency_instances_json: loaded.dependency_instances_json.clone(),
            reach: loaded.reach.to_int(),
            compile_millis: loaded.compile_millis,
            profile: loaded.profile.clone(),
            emit: loaded.emit.clone(),
            kind: loaded.kind.clone(),
            crate_types: loaded.crate_types.clone(),
            outputs: loaded.outputs.clone(),
        }
    }

    #[tokio::test]
    async fn sha256_corruption_archive_is_rejected() {
        let storage = InMemoryStorage::new();
        let dir_a = tempfile::tempdir().expect("dir_a");
        let dir_b = tempfile::tempdir().expect("dir_b");
        let cfg_a = machine_config(
            dir_a.path(),
            &storage,
            BucketCacheConfig::for_bucket("shared"),
            3,
            Duration::from_secs(60),
        );
        let cfg_b = machine_config(
            dir_b.path(),
            &storage,
            BucketCacheConfig::for_bucket("shared"),
            3,
            Duration::from_secs(60),
        );
        let _la = prepare_local_cache(&cfg_a, TEST_RUSTC)
            .await
            .expect("prep a");
        let _lb = prepare_local_cache(&cfg_b, TEST_RUSTC)
            .await
            .expect("prep b");

        let out_a = dir_a.path().join("target/deps");
        let parsed = make_parsed_rlib("corrupt", "cargo555555555555", &out_a, Vec::new());
        let stable = "eeee111122223333";
        let build = write_and_build_artifact(
            &parsed,
            stable,
            git_source(),
            Reach::LocalOnly,
            b"good-rlib",
            b"good-rmeta",
            empty_deps(Reach::LocalOnly),
        );
        store_local_build_outputs(
            &cfg_a,
            &parsed,
            &build,
            TEST_TARGET,
            &LocalEntryKey::plain(stable),
        )
        .await
        .expect("store");
        let request = FetchRequest {
            target: TEST_TARGET,
            rustc_version: TEST_RUSTC,
            c_metadata: stable,
        };
        let loaded = load_cached_bundle_in_tier(&cfg_a, CacheTier::Local, &request)
            .await
            .expect("load")
            .expect("present");
        let manifest_bytes =
            serde_json::to_vec(&manifest_from_loaded(&loaded, stable)).expect("manifest json");
        let mut tar = tar::Builder::new(Vec::new());
        append_tar_file(&mut tar, BUCKET_MANIFEST_PATH, &manifest_bytes).expect("append manifest");
        for output in &loaded.outputs {
            append_tar_file(
                &mut tar,
                &format!("{BUCKET_FILES_DIR}/{}", output.file_name),
                b"TAMPERED-BYTES",
            )
            .expect("append tampered");
        }
        let corrupt_zst = compress_zstd(&tar.into_inner().expect("tar")).expect("zst");
        let key = rust_object_key("stow/", CacheTier::Local, TEST_RUSTC, TEST_TARGET, stable);
        Storage::new(storage.clone())
            .put(&key, corrupt_zst)
            .await
            .expect("put corrupt");

        assert!(
            pull_rust_artifact(&cfg_b, CacheTier::Local, &git_source(), &request)
                .await
                .expect("pull corrupt")
                .is_none(),
            "corrupted archive must be discarded"
        );
        assert!(
            load_cached_bundle_in_tier(&cfg_b, CacheTier::Local, &request)
                .await
                .expect("load L1 B")
                .is_none(),
            "corrupted archive must never poison L1"
        );
    }

    #[tokio::test]
    async fn path_traversal_archive_is_rejected() {
        let storage = InMemoryStorage::new();
        let dir_b = tempfile::tempdir().expect("dir_b");
        let cfg_b = machine_config(
            dir_b.path(),
            &storage,
            BucketCacheConfig::for_bucket("shared"),
            3,
            Duration::from_secs(60),
        );
        let _lb = prepare_local_cache(&cfg_b, TEST_RUSTC)
            .await
            .expect("prep b");

        let mut raw_header = tar::Header::new_gnu();
        raw_header.set_entry_type(tar::EntryType::Regular);
        raw_header.set_size(4);
        raw_header.set_mode(0o644);
        let name_bytes = b"../evil.rlib";
        raw_header.as_gnu_mut().expect("gnu").name[..name_bytes.len()].copy_from_slice(name_bytes);
        raw_header.set_cksum();

        let mut raw_tar = Vec::new();
        raw_tar.extend_from_slice(raw_header.as_bytes());
        raw_tar.extend_from_slice(b"evil");
        raw_tar.resize(raw_tar.len() + (512 - 4) + 1024, 0);
        let traversal_zst = compress_zstd(&raw_tar).expect("zst traversal");

        let stable = "ffff111122223333";
        let trav_key = rust_object_key("stow/", CacheTier::Local, TEST_RUSTC, TEST_TARGET, stable);
        Storage::new(storage.clone())
            .put(&trav_key, traversal_zst)
            .await
            .expect("put traversal");
        assert!(
            pull_rust_artifact(
                &cfg_b,
                CacheTier::Local,
                &git_source(),
                &FetchRequest {
                    target: TEST_TARGET,
                    rustc_version: TEST_RUSTC,
                    c_metadata: stable,
                },
            )
            .await
            .expect("pull traversal")
            .is_none(),
            "path-traversal archive must be rejected"
        );
    }

    async fn publish_dep_and_consumer_on_machine_a(
        storage: &InMemoryStorage,
        stable_dep: &str,
        stable_consumer: &str,
    ) {
        let dir_a = tempfile::tempdir().expect("dir_a");
        let cfg_a = machine_config(
            dir_a.path(),
            storage,
            BucketCacheConfig::for_bucket("shared"),
            3,
            Duration::from_secs(60),
        );
        let _la = prepare_local_cache(&cfg_a, TEST_RUSTC)
            .await
            .expect("prep a");
        let out_a = dir_a.path().join("target/deps");
        let parsed_dep_a = make_parsed_rlib("dep_a", "cargo_dep_a", &out_a, Vec::new());
        let build_dep_a = write_and_build_artifact(
            &parsed_dep_a,
            stable_dep,
            git_source(),
            Reach::LocalOnly,
            b"dep-a-v1-rlib",
            b"dep-a-v1-rmeta",
            empty_deps(Reach::LocalOnly),
        );
        record_materialized_local_build_outputs(&cfg_a, &parsed_dep_a, &build_dep_a, TEST_TARGET)
            .await
            .expect("record dep_a on A");
        crate::store_local_build(
            &cfg_a,
            &parsed_dep_a,
            &build_dep_a,
            &InvocationEnv::for_tests(),
            TEST_TARGET,
        )
        .await
        .expect("store dep_a on A");

        let parsed_consumer_a = make_parsed_rlib(
            "dep_b",
            "cargo_dep_b",
            &out_a,
            vec![ParsedExternCrate {
                crate_name: "dep_a".to_owned(),
                path: parsed_dep_a.output_rlib_path().expect("dep_a rlib"),
            }],
        );
        let deps_a = ResolvedDependencies {
            c_metadata_json: serde_json::json!([{"crate_name": "dep_a", "c_metadata": stable_dep}])
                .to_string(),
            externs: vec![MaterializedDependency {
                crate_name: "dep_a".to_owned(),
                c_metadata: stable_dep.to_owned(),
                instance: build_dep_a.instance(),
            }],
            reach: Reach::LocalOnly,
        };
        let build_consumer_a = write_and_build_artifact(
            &parsed_consumer_a,
            stable_consumer,
            git_source(),
            Reach::LocalOnly,
            b"dep-b-rlib",
            b"dep-b-rmeta",
            deps_a,
        );
        crate::store_local_build(
            &cfg_a,
            &parsed_consumer_a,
            &build_consumer_a,
            &InvocationEnv::for_tests(),
            TEST_TARGET,
        )
        .await
        .expect("store dep_b on A");
        cfg_a.bucket_handles.flush().await;
    }

    #[tokio::test]
    async fn dependency_instances_svh_mismatch_rejects_bucket_entry_on_serve() {
        let storage = InMemoryStorage::new();
        let stable_dep = "1111aaaa2222bbbb";
        let stable_consumer = "3333cccc4444dddd";
        publish_dep_and_consumer_on_machine_a(&storage, stable_dep, stable_consumer).await;

        let req_consumer = FetchRequest {
            target: TEST_TARGET,
            rustc_version: TEST_RUSTC,
            c_metadata: stable_consumer,
        };

        // Machine B compiled dep_a locally with DIFFERENT bytes (v2 -> different SVH).
        let dir_b = tempfile::tempdir().expect("dir_b");
        let cfg_b = machine_config(
            dir_b.path(),
            &storage,
            BucketCacheConfig::for_bucket("shared"),
            3,
            Duration::from_secs(60),
        );
        let _lb = prepare_local_cache(&cfg_b, TEST_RUSTC)
            .await
            .expect("prep b");
        let out_b = dir_b.path().join("target/deps");
        let parsed_dep_b = make_parsed_rlib("dep_a", "cargo_dep_b_local", &out_b, Vec::new());
        let build_dep_b = write_and_build_artifact(
            &parsed_dep_b,
            stable_dep,
            git_source(),
            Reach::LocalOnly,
            b"dep-a-v2-DIFFERENT-SVH-rlib",
            b"dep-a-v2-DIFFERENT-SVH-rmeta",
            empty_deps(Reach::LocalOnly),
        );
        record_materialized_local_build_outputs(&cfg_b, &parsed_dep_b, &build_dep_b, TEST_TARGET)
            .await
            .expect("record dep_a v2 on B");
        store_local_build_outputs(
            &cfg_b,
            &parsed_dep_b,
            &build_dep_b,
            TEST_TARGET,
            &LocalEntryKey::plain(stable_dep),
        )
        .await
        .expect("store dep_a v2 on B");

        let parsed_consumer_b = make_parsed_rlib(
            "dep_b",
            "cargo_consumer_b",
            &out_b,
            vec![ParsedExternCrate {
                crate_name: "dep_a".to_owned(),
                path: parsed_dep_b.output_rlib_path().expect("dep_a rlib on B"),
            }],
        );
        let pulled_b = pull_rust_artifact(&cfg_b, CacheTier::Local, &git_source(), &req_consumer)
            .await
            .expect("pull dep_b on B")
            .expect("bucket has dep_b");
        let mut tally_b = crate::LookupTally::default();
        assert!(
            crate::try_serve_loaded_local_cached_bundle(
                &cfg_b,
                &parsed_consumer_b,
                &git_source(),
                &req_consumer,
                crate::EntryOrigin::ExactKey,
                pulled_b,
                &mut tally_b,
            )
            .await
            .is_none(),
            "SVH mismatch must refuse serve"
        );
        assert!(
            load_cached_bundle_in_tier(&cfg_b, CacheTier::Local, &req_consumer)
                .await
                .expect("check L1 B")
                .is_none(),
            "rejected mismatched entry must be evicted from L1"
        );
    }

    #[tokio::test]
    async fn dependency_instances_svh_match_serves_bucket_entry() {
        let storage = InMemoryStorage::new();
        let stable_dep = "1111aaaa2222bbbb";
        let stable_consumer = "3333cccc4444dddd";
        publish_dep_and_consumer_on_machine_a(&storage, stable_dep, stable_consumer).await;

        let req_dep = FetchRequest {
            target: TEST_TARGET,
            rustc_version: TEST_RUSTC,
            c_metadata: stable_dep,
        };
        let req_consumer = FetchRequest {
            target: TEST_TARGET,
            rustc_version: TEST_RUSTC,
            c_metadata: stable_consumer,
        };

        let dir_c = tempfile::tempdir().expect("dir_c");
        let cfg_c = machine_config(
            dir_c.path(),
            &storage,
            BucketCacheConfig::for_bucket("shared"),
            3,
            Duration::from_secs(60),
        );
        let _lc = prepare_local_cache(&cfg_c, TEST_RUSTC)
            .await
            .expect("prep c");
        let out_c = dir_c.path().join("target/deps");
        std::fs::create_dir_all(&out_c).expect("mkdir out_c");
        let parsed_dep_c = make_parsed_rlib("dep_a", "cargo_dep_c", &out_c, Vec::new());
        let pulled_dep_c = pull_rust_artifact(&cfg_c, CacheTier::Local, &git_source(), &req_dep)
            .await
            .expect("pull dep_a on C")
            .expect("bucket has dep_a");
        let mut tally_c = crate::LookupTally::default();
        assert!(
            crate::try_serve_loaded_local_cached_bundle(
                &cfg_c,
                &parsed_dep_c,
                &git_source(),
                &req_dep,
                crate::EntryOrigin::ExactKey,
                pulled_dep_c,
                &mut tally_c,
            )
            .await
            .is_some()
        );
        let parsed_consumer_c = make_parsed_rlib(
            "dep_b",
            "cargo_consumer_c",
            &out_c,
            vec![ParsedExternCrate {
                crate_name: "dep_a".to_owned(),
                path: parsed_dep_c.output_rlib_path().expect("dep_a rlib on C"),
            }],
        );
        let pulled_consumer_c =
            pull_rust_artifact(&cfg_c, CacheTier::Local, &git_source(), &req_consumer)
                .await
                .expect("pull dep_b on C")
                .expect("bucket has dep_b");
        assert!(
            crate::try_serve_loaded_local_cached_bundle(
                &cfg_c,
                &parsed_consumer_c,
                &git_source(),
                &req_consumer,
                crate::EntryOrigin::ExactKey,
                pulled_consumer_c,
                &mut tally_c,
            )
            .await
            .is_some(),
            "matching dependency_instances from bucket must serve cleanly on Machine C"
        );
    }

    #[tokio::test]
    async fn manifest_scoped_entries_are_excluded_from_bucket_uploads() {
        let storage = InMemoryStorage::new();
        let dir = tempfile::tempdir().expect("dir");
        let cfg = machine_config(
            dir.path(),
            &storage,
            BucketCacheConfig::for_bucket("shared"),
            3,
            Duration::from_secs(60),
        );
        let _lease = prepare_local_cache(&cfg, TEST_RUSTC).await.expect("prep");

        let out_dir = dir.path().join("target/deps");
        let mut parsed = make_parsed_rlib("my_macro", "cargo_macro", &out_dir, Vec::new());
        parsed.crate_types = vec!["proc-macro".to_owned()];
        parsed.emit = ["dep-info", "link"]
            .into_iter()
            .map(str::to_owned)
            .collect();

        let linked = parsed
            .output_linked_image_path(TEST_TARGET)
            .expect("linked path")
            .expect("some linked path");
        let dep_info = parsed.output_dep_info_path().expect("dep-info");
        std::fs::create_dir_all(linked.parent().expect("parent")).expect("mkdir");
        std::fs::write(&linked, b"fake-proc-macro-dylib").expect("write dylib");
        // Mark CARGO_MANIFEST_DIR as read by the proc macro -> manifest_scoped!
        std::fs::write(
            &dep_info,
            format!(
                "{}: src/lib.rs\n# env-dep:CARGO_MANIFEST_DIR=/tmp/machine-a\n",
                linked.display()
            ),
        )
        .expect("write dep-info");

        let stable = "9999aaaa8888bbbb";
        let identity = StableUnitIdentity {
            compile_key: format!("{stable}{stable}"),
            c_metadata: stable.to_owned(),
            extra_filename: format!("-{stable}"),
            crate_name: "my_macro".to_owned(),
            version: "1.0.0".to_owned(),
            source: git_source(),
            reach: Reach::LocalOnly,
        };
        let stable_parsed = crate::inject::parsed_with_stable_identity(
            &parsed,
            &identity.c_metadata,
            &identity.extra_filename,
        );
        let mut outputs =
            local_build_output_specs(&parsed, &stable_parsed, TEST_TARGET).expect("specs");
        hash_local_build_outputs_sync(&mut outputs).expect("hash");
        let build = LocalBuildArtifact {
            target: TEST_TARGET.to_owned(),
            rustc_version: TEST_RUSTC.to_owned(),
            identity,
            reach: Reach::LocalOnly,
            features_json: "[]".to_owned(),
            dependencies: empty_deps(Reach::LocalOnly),
            outputs,
            compile_millis: 10,
        };

        let mut env = InvocationEnv::for_tests();
        env.manifest_dir = Some(b"/tmp/machine-a".to_vec());
        crate::store_local_build(&cfg, &parsed, &build, &env, TEST_TARGET)
            .await
            .expect("store manifest_scoped entry");
        cfg.bucket_handles.flush().await;

        // Stored in L1 under manifest_scoped key, but NEVER uploaded to bucket!
        let scoped = LocalEntryKey::manifest_scoped(stable, b"/tmp/machine-a");
        assert!(scoped.is_manifest_scoped());
        assert!(
            load_cached_bundle_in_tier(
                &cfg,
                CacheTier::Local,
                &FetchRequest {
                    target: TEST_TARGET,
                    rustc_version: TEST_RUSTC,
                    c_metadata: scoped.as_str(),
                },
            )
            .await
            .expect("load scoped L1")
            .is_some(),
            "manifest_scoped entry must still exist in L1"
        );
        assert!(
            Storage::new(storage.clone())
                .list(ListOptions::default())
                .await
                .expect("list")
                .objects
                .is_empty(),
            "manifest_scoped entry must NEVER be uploaded to remote bucket"
        );
    }

    #[tokio::test]
    async fn circuit_breaker_trips_on_backend_failure_and_ignores_not_found() {
        let storage = InMemoryStorage::new();
        let dir = tempfile::tempdir().expect("dir");
        let cfg = machine_config(
            dir.path(),
            &storage,
            BucketCacheConfig::for_bucket("shared"),
            1,
            Duration::from_secs(60),
        );
        let _lease = prepare_local_cache(&cfg, TEST_RUSTC).await.expect("prep");

        let request = FetchRequest {
            target: TEST_TARGET,
            rustc_version: TEST_RUSTC,
            c_metadata: "0000111122223333",
        };
        // `None` (not found) never trips the circuit breaker.
        assert!(
            pull_rust_artifact(&cfg, CacheTier::Local, &git_source(), &request)
                .await
                .expect("miss 1")
                .is_none()
        );
        assert!(
            pull_rust_artifact(&cfg, CacheTier::Local, &git_source(), &request)
                .await
                .expect("miss 2")
                .is_none()
        );
        let client = cfg.bucket_handles.client_for(&cfg).await.expect("client");
        assert!(!client.circuit.is_tripped());

        // Inject backend failure -> degrades cleanly to Ok(None) and trips breaker.
        storage.fail_next_with("simulated S3 outage");
        assert!(
            pull_rust_artifact(&cfg, CacheTier::Local, &git_source(), &request)
                .await
                .expect("outage degrades cleanly")
                .is_none()
        );
        assert!(
            client.circuit.is_tripped(),
            "backend failure must trip BucketCircuit"
        );

        // Even with an object now present in storage, circuit open short-circuits.
        let cc_key = "c".repeat(64);
        Storage::new(storage.clone())
            .put(
                &cc_object_key("stow/", &cc_key),
                compress_zstd(b"hello-obj").expect("compress"),
            )
            .await
            .expect("put");
        assert!(
            pull_cc_object(&cfg, &cc_key)
                .await
                .expect("short-circuit")
                .is_none(),
            "tripped circuit must skip bucket fetches"
        );
    }

    #[tokio::test]
    async fn uploader_deduplicates_keys_and_drains_on_shutdown() {
        let uploader = BucketUploader::with_concurrency(2);
        let runs = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Notify::new());

        let runs_first = Arc::clone(&runs);
        let gate_first = Arc::clone(&gate);
        assert!(uploader.enqueue("bucket::k1".to_owned(), async move {
            runs_first.fetch_add(1, Ordering::SeqCst);
            gate_first.notified().await;
        }));
        // Duplicate key while k1 is still in flight is deduplicated.
        let runs_dup = Arc::clone(&runs);
        assert!(!uploader.enqueue("bucket::k1".to_owned(), async move {
            runs_dup.fetch_add(1, Ordering::SeqCst);
        }));

        // Start drain before releasing gate; drain must wait until k1 finishes.
        let drain_uploader = uploader.clone();
        let drain_task = tokio::spawn(async move {
            drain_uploader.drain().await;
        });
        tokio::task::yield_now().await;
        assert!(
            !drain_task.is_finished(),
            "drain must wait for in-flight upload"
        );

        gate.notify_one();
        drain_task.await.expect("drain completed");
        assert_eq!(runs.load(Ordering::SeqCst), 1);

        // After drain, new uploads are rejected.
        assert!(!uploader.enqueue("bucket::k2".to_owned(), async {}));
    }

    #[tokio::test]
    async fn resources_checkpoint_and_close_drains_in_flight_bucket_uploads() {
        let storage = InMemoryStorage::new();
        let dir = tempfile::tempdir().expect("dir");
        let mut resources = Resources::default();
        let handles = resources.handles_for(dir.path());

        let mut cfg = machine_config(
            dir.path(),
            &storage,
            BucketCacheConfig::for_bucket("shared"),
            3,
            Duration::from_secs(60),
        );
        handles.install(&mut cfg);

        let gate = Arc::new(tokio::sync::Notify::new());
        let gate_task = Arc::clone(&gate);
        let storage_task = Storage::new(storage.clone());
        assert!(cfg.bucket_handles.uploader().enqueue(
            "shared::stow/v1/cc/drain-test.o.zst".to_owned(),
            async move {
                gate_task.notified().await;
                storage_task
                    .put(
                        "stow/v1/cc/drain-test.o.zst",
                        b"uploaded-before-stop".to_vec(),
                    )
                    .await
                    .expect("put during drain");
            },
        ));

        let shutdown = tokio::spawn(async move {
            resources.checkpoint_and_close_all().await;
        });
        tokio::task::yield_now().await;
        assert!(
            !shutdown.is_finished(),
            "checkpoint_and_close_all must wait for pending bucket uploads"
        );
        gate.notify_one();
        shutdown.await.expect("checkpoint_and_close_all finished");

        let stored = Storage::new(storage.clone())
            .get("stow/v1/cc/drain-test.o.zst")
            .await
            .expect("get")
            .expect("upload finished before daemon shutdown");
        assert_eq!(stored.body, b"uploaded-before-stop");
    }
}
