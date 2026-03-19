use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use eyre::Context;
use fs2::FileExt;
use sqlx::FromRow;
use stow_types::artifact::{NativeArtifacts, NativeLib, OutDirFile};
use stow_types::bundle::{ArtifactBundleFile, SigstoreSignature};

use crate::config::StowConfig;
use crate::fetch::{ArtifactBundle, FetchRequest, bundle_file_path, decode_bundle_output_bytes};
use crate::state_db::{connect, now_millis};

const BUNDLES_DIR: &str = "bundles";
const NATIVE_DIR: &str = "native";
const NATIVE_OUT_DIR: &str = "native/out";
const VERSION_LEASES_DIR: &str = "leases";
const ARTIFACT_CACHE_LAYOUT_VERSION: &str = "v3";

#[derive(Debug)]
pub struct RustcVersionLease {
    _file: File,
}

#[derive(Debug)]
pub struct CachedArtifactBundle {
    pub oci_reference: String,
    pub oci_digest: String,
    pub outputs: Vec<ArtifactBundleFile>,
    pub native: Option<NativeArtifacts>,
    pub sigstore_signatures: Vec<SigstoreSignature>,
    pub(crate) entry_dir: PathBuf,
    pub(crate) rustc_version: String,
    pub(crate) cache_key: String,
    pub(crate) verified_marker_version: Option<u8>,
    pub(crate) verified_marker_policy: Option<String>,
    pub(crate) _lease_lock: File,
}

impl CachedArtifactBundle {
    pub fn output_source_path(&self, file: &ArtifactBundleFile) -> PathBuf {
        self.entry_dir.join(bundle_file_path(&file.file_name))
    }

    pub fn native_output_source_path(&self, relative_path: &str) -> PathBuf {
        self.entry_dir.join(NATIVE_OUT_DIR).join(relative_path)
    }
}

pub async fn prepare_local_cache(
    config: &StowConfig,
    rustc_version: &str,
) -> eyre::Result<RustcVersionLease> {
    let artifact_cache_root = config.artifact_cache_root();
    let purge_root = config.artifact_cache_purge_root();
    let rustc_version = rustc_version.to_owned();
    let connection = connect(&config.cache_dir).await?;
    let active_rustc_version = sqlx::query_scalar::<_, String>(
        "SELECT value FROM metadata_values WHERE key = 'active_rustc_version'",
    )
    .fetch_optional(&connection)
    .await?;
    let active_version_matches = active_rustc_version.as_deref() == Some(rustc_version.as_str());
    let rustc_version_for_prepare = rustc_version.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        prepare_local_cache_blocking(
            &artifact_cache_root,
            &purge_root,
            &rustc_version_for_prepare,
            active_version_matches,
        )
    })
    .await
    .wrap_err("join prepare_local_cache blocking task")??;
    if !active_version_matches {
        sqlx::query(
            "INSERT INTO metadata_values (key, value) VALUES ('active_rustc_version', ?) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(&rustc_version)
        .execute(&connection)
        .await?;
    }
    let stale_dirs = prepared.stale_dirs;
    if !stale_dirs.is_empty() {
        spawn_purge_worker(stale_dirs)?;
    }
    Ok(prepared.version_lease)
}

pub async fn load_cached_bundle(
    config: &StowConfig,
    request: &FetchRequest<'_>,
) -> eyre::Result<Option<CachedArtifactBundle>> {
    let version_dir = config.artifact_cache_version_dir(request.rustc_version);
    let entry_relative_dir = entry_relative_dir(request);
    let cache_key = cache_key(request);
    let rustc_version = request.rustc_version.to_owned();
    let entry_dir = version_dir.join(&entry_relative_dir);
    if !entry_dir.exists() {
        return Ok(None);
    }
    let lease_lock = tokio::task::spawn_blocking({
        let version_dir = version_dir.clone();
        let cache_key = cache_key.clone();
        move || acquire_entry_shared_lock(&version_dir, &cache_key)
    })
    .await
    .wrap_err("join load_cached_bundle lock task")??;
    if !entry_dir.exists() {
        return Ok(None);
    }

    let connection = connect(&config.cache_dir).await?;
    touch_artifact_cache_entry(&connection, &rustc_version, &cache_key, now_millis()).await?;
    let entry = load_artifact_cache_entry(&connection, &rustc_version, &cache_key)
        .await?
        .ok_or_else(|| {
            eyre::eyre!(
                "artifact cache entry {cache_key} for rustc {rustc_version} is missing from the state database"
            )
        })?;
    let outputs = load_artifact_outputs(&connection, &rustc_version, &cache_key).await?;
    let sigstore_signatures =
        load_sigstore_signatures(&connection, &rustc_version, &cache_key).await?;
    let native = load_native_artifacts(&connection, &rustc_version, &cache_key).await?;
    Ok(Some(CachedArtifactBundle {
        oci_reference: entry.oci_reference,
        oci_digest: entry.oci_digest,
        outputs,
        native,
        sigstore_signatures,
        entry_dir,
        rustc_version,
        cache_key,
        verified_marker_version: entry.verified_marker_version.and_then(|value| u8::try_from(value).ok()),
        verified_marker_policy: entry.verified_marker_policy,
        _lease_lock: lease_lock,
    }))
}

pub async fn store_downloaded_bundle(
    config: &StowConfig,
    request: &FetchRequest<'_>,
    bundle: &ArtifactBundle,
) -> eyre::Result<CachedArtifactBundle> {
    let request = OwnedFetchRequest::from(request);
    let bundle = bundle.clone();
    let version_dir = config.artifact_cache_version_dir(&request.rustc_version);
    let bundles_dir = version_dir.join(BUNDLES_DIR);
    async_fs::create_dir_all(&bundles_dir)
        .await
        .wrap_err_with(|| format!("create bundle cache directory {}", bundles_dir.display()))?;

    let entry_relative_dir = entry_relative_dir_owned(&request);
    let entry_dir = version_dir.join(&entry_relative_dir);
    let entry_parent = entry_dir.parent().ok_or_else(|| {
        eyre::eyre!(
            "artifact cache entry dir {} has no parent",
            entry_dir.display()
        )
    })?;
    async_fs::create_dir_all(entry_parent)
        .await
        .wrap_err_with(|| format!("create artifact cache parent {}", entry_parent.display()))?;
    let cache_key = cache_key_owned(&request);
    let size_bytes = tokio::task::spawn_blocking({
        let entry_parent = entry_parent.to_path_buf();
        let entry_dir = entry_dir.clone();
        let bundle = bundle.clone();
        let c_metadata = request.c_metadata.clone();
        move || write_bundle_entry_blocking(&entry_parent, &entry_dir, &bundle, &c_metadata)
    })
    .await
    .wrap_err("join store_downloaded_bundle file task")??;

    let connection = connect(&config.cache_dir).await?;
    replace_artifact_cache_metadata(
        &connection,
        &request.rustc_version,
        &cache_key,
        &path_to_string(&entry_relative_dir)?,
        size_bytes,
        now_millis(),
        &bundle,
    )
    .await?;
    evict_entries(
        &connection,
        &request.rustc_version,
        &version_dir,
        config.artifact_cache_max_bytes,
        &cache_key,
    )
    .await?;
    let lease_lock = tokio::task::spawn_blocking({
        let version_dir = version_dir.clone();
        let cache_key = cache_key.clone();
        move || acquire_entry_shared_lock(&version_dir, &cache_key)
    })
    .await
    .wrap_err("join store_downloaded_bundle lock task")??;
    Ok(CachedArtifactBundle {
        oci_reference: bundle.manifest.oci_reference.clone(),
        oci_digest: bundle.manifest.oci_digest.clone(),
        outputs: bundle.manifest.config.outputs.clone(),
        native: bundle.manifest.config.native.clone(),
        sigstore_signatures: bundle.manifest.sigstore_signatures.clone(),
        entry_dir,
        rustc_version: request.rustc_version,
        cache_key,
        verified_marker_version: None,
        verified_marker_policy: None,
        _lease_lock: lease_lock,
    })
}

pub async fn remove_cached_bundle(
    config: &StowConfig,
    request: &FetchRequest<'_>,
) -> eyre::Result<()> {
    let version_dir = config.artifact_cache_version_dir(request.rustc_version);
    let cache_key = cache_key(request);
    let rustc_version = request.rustc_version.to_owned();
    let connection = connect(&config.cache_dir).await?;
    remove_cached_bundle_locked(&connection, &version_dir, &rustc_version, &cache_key).await
}

fn prepare_local_cache_blocking(
    artifact_cache_root: &Path,
    purge_root: &Path,
    rustc_version: &str,
    active_version_matches: bool,
) -> eyre::Result<PreparedLocalCache> {
    std::fs::create_dir_all(artifact_cache_root).wrap_err_with(|| {
        format!(
            "create artifact cache root {}",
            artifact_cache_root.display()
        )
    })?;
    std::fs::create_dir_all(purge_root)
        .wrap_err_with(|| format!("create artifact purge root {}", purge_root.display()))?;
    let leases_root = artifact_cache_root.join(VERSION_LEASES_DIR);
    std::fs::create_dir_all(&leases_root)
        .wrap_err_with(|| format!("create artifact lease root {}", leases_root.display()))?;

    let version_dir = artifact_cache_root.join(rustc_version);
    std::fs::create_dir_all(version_dir.join(BUNDLES_DIR)).wrap_err_with(|| {
        format!(
            "create rustc artifact cache directory {}",
            version_dir.display()
        )
    })?;
    std::fs::create_dir_all(version_dir.join("locks")).wrap_err_with(|| {
        format!(
            "create rustc artifact cache lock directory {}",
            version_dir.display()
        )
    })?;
    let version_lease = RustcVersionLease {
        _file: acquire_version_shared_lock(&leases_root, rustc_version)?,
    };

    if active_version_matches {
        return Ok(PreparedLocalCache {
            stale_dirs: Vec::new(),
            version_lease,
        });
    }

    let mut stale_dirs = Vec::new();
    for entry in std::fs::read_dir(artifact_cache_root).wrap_err_with(|| {
        format!("read artifact cache root {}", artifact_cache_root.display())
    })? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let file_name = entry.file_name();
        if file_name == rustc_version || file_name == VERSION_LEASES_DIR {
            continue;
        }
        let stale_path = entry.path();
        let stale_version = file_name.to_string_lossy().to_string();
        let Some(_stale_lease) = try_acquire_version_exclusive_lock(&leases_root, &stale_version)?
        else {
            continue;
        };
        let purge_path =
            purge_root.join(format!("{}-{}", file_name.to_string_lossy(), now_millis()));
        std::fs::rename(&stale_path, &purge_path).wrap_err_with(|| {
            format!(
                "move stale rustc cache directory {} to {}",
                stale_path.display(),
                purge_path.display()
            )
        })?;
        stale_dirs.push(purge_path);
    }

    Ok(PreparedLocalCache {
        stale_dirs,
        version_lease,
    })
}

fn write_bundle_entry_blocking(
    entry_parent: &Path,
    entry_dir: &Path,
    bundle: &ArtifactBundle,
    c_metadata: &str,
) -> eyre::Result<u64> {
    let tempdir = tempfile::Builder::new()
        .prefix(&format!("{c_metadata}-"))
        .tempdir_in(entry_parent)
        .wrap_err_with(|| format!("create temp cache directory for {}", entry_dir.display()))?;
    let size_bytes = write_downloaded_bundle_to_entry(tempdir.path(), bundle)?;
    if !entry_dir.exists() {
        if let Some(parent) = entry_dir.parent() {
            std::fs::create_dir_all(parent)
                .wrap_err_with(|| format!("create artifact cache parent {}", parent.display()))?;
        }
        std::fs::rename(tempdir.path(), entry_dir).wrap_err_with(|| {
            format!(
                "move artifact cache entry {} into place at {}",
                tempdir.path().display(),
                entry_dir.display()
            )
        })?;
    }
    Ok(size_bytes)
}

async fn remove_cached_bundle_locked(
    connection: &sqlx::SqlitePool,
    version_dir: &Path,
    rustc_version: &str,
    cache_key: &str,
) -> eyre::Result<()> {
    let Some(entry) = load_artifact_cache_entry(connection, rustc_version, cache_key).await? else {
        return Ok(());
    };
    delete_artifact_cache_entry(connection, rustc_version, cache_key).await?;
    let entry_dir = version_dir.join(&entry.relative_dir);
    let Some(eviction_lock) = tokio::task::spawn_blocking({
        let version_dir = version_dir.to_path_buf();
        let cache_key = cache_key.to_owned();
        move || try_acquire_entry_exclusive_lock(&version_dir, &cache_key)
    })
    .await
    .wrap_err("join remove_cached_bundle lock task")?? else {
        sqlx::query(
            "INSERT INTO artifact_cache_entries \
             (rustc_version, cache_key, relative_dir, size_bytes, last_accessed_ms, oci_reference, oci_digest, verified_marker_version, verified_marker_policy) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(rustc_version)
        .bind(cache_key)
        .bind(&entry.relative_dir)
        .bind(entry.size_bytes as i64)
        .bind(entry.last_accessed_ms as i64)
        .bind(&entry.oci_reference)
        .bind(&entry.oci_digest)
        .bind(entry.verified_marker_version.map(i64::from))
        .bind(entry.verified_marker_policy.as_deref())
        .execute(connection)
        .await?;
        return Err(eyre::eyre!(
            "artifact cache entry {cache_key} is in use by another stow process"
        ));
    };
    if entry_dir.exists() {
        tokio::task::spawn_blocking({
            let entry_dir = entry_dir.clone();
            move || {
                std::fs::remove_dir_all(&entry_dir)
                    .wrap_err_with(|| format!("remove cached artifact entry {}", entry_dir.display()))
            }
        })
        .await
        .wrap_err("join remove_cached_bundle remove_dir task")??;
    }
    drop(eviction_lock);
    Ok(())
}

async fn evict_entries(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    version_dir: &Path,
    max_bytes: u64,
    protected_key: &str,
) -> eyre::Result<()> {
    let mut entries = list_artifact_cache_entries(connection, rustc_version).await?;
    let mut total_bytes = entries
        .values()
        .fold(0u64, |sum, entry| sum.saturating_add(entry.size_bytes));
    if total_bytes <= max_bytes {
        return Ok(());
    }

    let mut eviction_order = entries
        .iter()
        .filter(|(key, _)| key.as_str() != protected_key)
        .map(|(key, entry)| (key.clone(), entry.last_accessed_ms))
        .collect::<Vec<_>>();
    eviction_order.sort_by(|left, right| left.1.cmp(&right.1).then(left.0.cmp(&right.0)));

    for (cache_key, _) in eviction_order {
        let Some(entry) = entries.remove(&cache_key) else {
            continue;
        };
        let Some(eviction_lock) = tokio::task::spawn_blocking({
            let version_dir = version_dir.to_path_buf();
            let cache_key = cache_key.clone();
            move || try_acquire_entry_exclusive_lock(&version_dir, &cache_key)
        })
        .await
        .wrap_err("join evict_entries lock task")?? else {
            continue;
        };
        delete_artifact_cache_entry(connection, rustc_version, &cache_key).await?;
        let entry_dir = version_dir.join(&entry.relative_dir);
        if entry_dir.exists() {
            tokio::task::spawn_blocking({
                let entry_dir = entry_dir.clone();
                move || {
                    std::fs::remove_dir_all(&entry_dir)
                        .wrap_err_with(|| format!("evict artifact cache entry {}", entry_dir.display()))
                }
            })
            .await
            .wrap_err("join evict_entries remove_dir task")??;
        }
        drop(eviction_lock);
        total_bytes = total_bytes.saturating_sub(entry.size_bytes);
        if total_bytes <= max_bytes {
            return Ok(());
        }
    }

    if total_bytes > max_bytes {
        if let Some(entry) = entries.remove(protected_key) {
            let Some(eviction_lock) = tokio::task::spawn_blocking({
                let version_dir = version_dir.to_path_buf();
                let protected_key = protected_key.to_owned();
                move || try_acquire_entry_exclusive_lock(&version_dir, &protected_key)
            })
            .await
            .wrap_err("join evict_entries protected lock task")?? else {
                return Err(eyre::eyre!(
                    "artifact cache is full and the protected entry {protected_key} is in use by another stow process"
                ));
            };
            delete_artifact_cache_entry(connection, rustc_version, protected_key).await?;
            let entry_dir = version_dir.join(&entry.relative_dir);
            if entry_dir.exists() {
                tokio::task::spawn_blocking({
                    let entry_dir = entry_dir.clone();
                    move || {
                        std::fs::remove_dir_all(&entry_dir).wrap_err_with(|| {
                            format!(
                                "evict oversized protected artifact cache entry {}",
                                entry_dir.display()
                            )
                        })
                    }
                })
                .await
                .wrap_err("join evict_entries protected remove_dir task")??;
            }
            drop(eviction_lock);
            return Err(eyre::eyre!(
                "artifact cache entry {protected_key} exceeds max local cache size {} bytes",
                max_bytes
            ));
        }
    }

    Err(eyre::eyre!(
        "artifact cache is full but all eviction candidates are currently in use by other stow processes"
    ))
}

fn write_downloaded_bundle_to_entry(
    entry_dir: &Path,
    bundle: &ArtifactBundle,
) -> eyre::Result<u64> {
    let mut total_bytes = 0u64;
    let output_files = bundle
        .manifest
        .config
        .outputs
        .iter()
        .map(|file| (bundle_file_path(&file.file_name), file))
        .collect::<BTreeMap<_, _>>();
    for (relative_path, contents) in &bundle.files {
        let path = join_relative_path(entry_dir, relative_path)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .wrap_err_with(|| format!("create cache parent {}", parent.display()))?;
        }
        let decoded = match output_files.get(relative_path) {
            Some(file) => decode_bundle_output_bytes(file, contents)?,
            None => contents.clone(),
        };
        std::fs::write(&path, &decoded)
            .wrap_err_with(|| format!("write cached bundle file {}", path.display()))?;
        total_bytes = total_bytes.saturating_add(decoded.len() as u64);
    }

    if let Some(native) = bundle.manifest.config.native.as_ref() {
        total_bytes = total_bytes.saturating_add(write_native_cache_entry(entry_dir, native)?);
    }

    Ok(total_bytes)
}

fn write_native_cache_entry(entry_dir: &Path, native: &NativeArtifacts) -> eyre::Result<u64> {
    let native_root = entry_dir.join(NATIVE_DIR);
    std::fs::create_dir_all(native_root.join("out"))
        .wrap_err_with(|| format!("create native cache root {}", native_root.display()))?;

    let mut total_bytes = 0u64;
    for file in &native.out_dir_files {
        let path = join_relative_path(&native_root.join("out"), &file.relative_path)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .wrap_err_with(|| format!("create native cache parent {}", parent.display()))?;
        }
        std::fs::write(&path, &file.contents)
            .wrap_err_with(|| format!("write native cache file {}", path.display()))?;
        total_bytes = total_bytes.saturating_add(file.contents.len() as u64);
    }

    Ok(total_bytes)
}

fn join_relative_path(root: &Path, relative_path: &str) -> eyre::Result<PathBuf> {
    let path = PathBuf::from(relative_path);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(eyre::eyre!("invalid relative cache path {relative_path}"));
    }
    Ok(root.join(path))
}

fn cache_key(request: &FetchRequest<'_>) -> String {
    format!(
        "{}/{}/{}",
        ARTIFACT_CACHE_LAYOUT_VERSION, request.target, request.c_metadata
    )
}

fn cache_key_owned(request: &OwnedFetchRequest) -> String {
    format!(
        "{}/{}/{}",
        ARTIFACT_CACHE_LAYOUT_VERSION, request.target, request.c_metadata
    )
}

fn entry_relative_dir(request: &FetchRequest<'_>) -> PathBuf {
    PathBuf::from(BUNDLES_DIR)
        .join(ARTIFACT_CACHE_LAYOUT_VERSION)
        .join(request.target)
        .join(request.c_metadata)
}

fn entry_relative_dir_owned(request: &OwnedFetchRequest) -> PathBuf {
    PathBuf::from(BUNDLES_DIR)
        .join(ARTIFACT_CACHE_LAYOUT_VERSION)
        .join(&request.target)
        .join(&request.c_metadata)
}

fn path_to_string(path: &Path) -> eyre::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| eyre::eyre!("path {} is not UTF-8", path.display()))
}

fn acquire_version_shared_lock(leases_root: &Path, rustc_version: &str) -> eyre::Result<File> {
    let lock_path = version_lease_path(leases_root, rustc_version);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .wrap_err_with(|| format!("open version lease {}", lock_path.display()))?;
    file.lock_shared()
        .wrap_err_with(|| format!("lock version lease {}", lock_path.display()))?;
    Ok(file)
}

fn try_acquire_version_exclusive_lock(
    leases_root: &Path,
    rustc_version: &str,
) -> eyre::Result<Option<File>> {
    let lock_path = version_lease_path(leases_root, rustc_version);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .wrap_err_with(|| format!("open stale version lease {}", lock_path.display()))?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(eyre::eyre!(
            "lock stale version lease {}: {error}",
            lock_path.display()
        )),
    }
}

fn version_lease_path(leases_root: &Path, rustc_version: &str) -> PathBuf {
    leases_root.join(format!("{rustc_version}.lock"))
}

fn acquire_entry_shared_lock(version_dir: &Path, cache_key: &str) -> eyre::Result<File> {
    let lock_path = entry_lock_path(version_dir, cache_key);
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)
            .wrap_err_with(|| format!("create cache lock parent {}", parent.display()))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .wrap_err_with(|| format!("open cache lease lock {}", lock_path.display()))?;
    file.lock_shared()
        .wrap_err_with(|| format!("lock cache lease {}", lock_path.display()))?;
    Ok(file)
}

fn try_acquire_entry_exclusive_lock(
    version_dir: &Path,
    cache_key: &str,
) -> eyre::Result<Option<File>> {
    let lock_path = entry_lock_path(version_dir, cache_key);
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)
            .wrap_err_with(|| format!("create cache lock parent {}", parent.display()))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .wrap_err_with(|| format!("open cache eviction lock {}", lock_path.display()))?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(eyre::eyre!(
            "lock cache eviction {}: {error}",
            lock_path.display()
        )),
    }
}

fn entry_lock_path(version_dir: &Path, cache_key: &str) -> PathBuf {
    let mut path = version_dir.join("locks").join(cache_key);
    path.set_extension("lock");
    path
}

fn spawn_purge_worker(paths: Vec<PathBuf>) -> eyre::Result<()> {
    let current_exe = std::env::current_exe().wrap_err("resolve current stow executable")?;
    let mut command = std::process::Command::new(current_exe);
    command
        .arg("__purge-cache-dir")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for path in paths {
        command.arg(path);
    }
    command
        .spawn()
        .wrap_err("spawn detached artifact cache purge worker")?;
    Ok(())
}

#[derive(Debug, Clone)]
struct OwnedFetchRequest {
    target: String,
    rustc_version: String,
    c_metadata: String,
}

impl From<&FetchRequest<'_>> for OwnedFetchRequest {
    fn from(value: &FetchRequest<'_>) -> Self {
        Self {
            target: value.target.to_owned(),
            rustc_version: value.rustc_version.to_owned(),
            c_metadata: value.c_metadata.to_owned(),
        }
    }
}

#[derive(Debug, Clone)]
struct ArtifactCacheIndexEntry {
    relative_dir: String,
    size_bytes: u64,
    last_accessed_ms: u64,
}

#[derive(Debug)]
struct PreparedLocalCache {
    stale_dirs: Vec<PathBuf>,
    version_lease: RustcVersionLease,
}

#[derive(Debug, Clone, FromRow)]
struct ArtifactCacheEntryRow {
    relative_dir: String,
    size_bytes: i64,
    last_accessed_ms: i64,
    oci_reference: String,
    oci_digest: String,
    verified_marker_version: Option<i64>,
    verified_marker_policy: Option<String>,
}

#[derive(Debug, Clone, FromRow)]
struct OutputRow {
    file_name: String,
    media_type: String,
    sha256: String,
}

#[derive(Debug, Clone, FromRow)]
struct SigstoreSignatureRow {
    payload_path: String,
    signature: String,
    certificate_pem: String,
    rekor_bundle_json: Option<String>,
}

#[derive(Debug, Clone, FromRow)]
struct NativeStaticLibRow {
    lib_name: String,
    bytes_sha256: String,
}

#[derive(Debug, Clone, FromRow)]
struct NativeDirectiveRow {
    directive: String,
}

#[derive(Debug, Clone, FromRow)]
struct NativeDepEnvVarRow {
    env_key: String,
    env_value: String,
}

#[derive(Debug, Clone, FromRow)]
struct NativeOutDirFileRow {
    relative_path: String,
}

async fn load_artifact_cache_entry(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
) -> eyre::Result<Option<ArtifactCacheEntryRow>> {
    sqlx::query_as::<_, ArtifactCacheEntryRow>(
        "SELECT relative_dir, size_bytes, last_accessed_ms, oci_reference, oci_digest, \
                verified_marker_version, verified_marker_policy \
         FROM artifact_cache_entries \
         WHERE rustc_version = ? AND cache_key = ?",
    )
    .bind(rustc_version)
    .bind(cache_key)
    .fetch_optional(connection)
    .await
    .map_err(Into::into)
}

async fn list_artifact_cache_entries(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
) -> eyre::Result<BTreeMap<String, ArtifactCacheIndexEntry>> {
    let rows = sqlx::query_as::<_, (String, String, i64, i64)>(
        "SELECT cache_key, relative_dir, size_bytes, last_accessed_ms \
         FROM artifact_cache_entries \
         WHERE rustc_version = ?",
    )
    .bind(rustc_version)
    .fetch_all(connection)
    .await?;
    let mut entries = BTreeMap::new();
    for (cache_key, relative_dir, size_bytes, last_accessed_ms) in rows {
        entries.insert(
            cache_key,
            ArtifactCacheIndexEntry {
                relative_dir,
                size_bytes: size_bytes as u64,
                last_accessed_ms: last_accessed_ms as u64,
            },
        );
    }
    Ok(entries)
}

async fn load_artifact_outputs(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
) -> eyre::Result<Vec<ArtifactBundleFile>> {
    let rows = sqlx::query_as::<_, OutputRow>(
        "SELECT file_name, media_type, sha256 \
         FROM artifact_cache_outputs \
         WHERE rustc_version = ? AND cache_key = ? \
         ORDER BY ordinal",
    )
    .bind(rustc_version)
    .bind(cache_key)
    .fetch_all(connection)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ArtifactBundleFile {
            file_name: row.file_name,
            media_type: row.media_type,
            sha256: row.sha256,
        })
        .collect())
}

async fn load_sigstore_signatures(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
) -> eyre::Result<Vec<SigstoreSignature>> {
    let rows = sqlx::query_as::<_, SigstoreSignatureRow>(
        "SELECT payload_path, signature, certificate_pem, rekor_bundle_json \
         FROM artifact_cache_sigstore_signatures \
         WHERE rustc_version = ? AND cache_key = ? \
         ORDER BY ordinal",
    )
    .bind(rustc_version)
    .bind(cache_key)
    .fetch_all(connection)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| SigstoreSignature {
            payload_path: row.payload_path,
            signature: row.signature,
            certificate_pem: row.certificate_pem,
            rekor_bundle_json: row.rekor_bundle_json,
        })
        .collect())
}

async fn load_native_artifacts(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
) -> eyre::Result<Option<NativeArtifacts>> {
    let static_lib_rows = sqlx::query_as::<_, NativeStaticLibRow>(
        "SELECT lib_name, bytes_sha256 \
         FROM artifact_cache_native_static_libs \
         WHERE rustc_version = ? AND cache_key = ? \
         ORDER BY ordinal",
    )
    .bind(rustc_version)
    .bind(cache_key)
    .fetch_all(connection)
    .await?;
    let directive_rows = sqlx::query_as::<_, NativeDirectiveRow>(
        "SELECT directive \
         FROM artifact_cache_native_directives \
         WHERE rustc_version = ? AND cache_key = ? \
         ORDER BY ordinal",
    )
    .bind(rustc_version)
    .bind(cache_key)
    .fetch_all(connection)
    .await?;
    let dep_env_rows = sqlx::query_as::<_, NativeDepEnvVarRow>(
        "SELECT env_key, env_value \
         FROM artifact_cache_native_dep_env_vars \
         WHERE rustc_version = ? AND cache_key = ? \
         ORDER BY env_key",
    )
    .bind(rustc_version)
    .bind(cache_key)
    .fetch_all(connection)
    .await?;
    let out_dir_rows = sqlx::query_as::<_, NativeOutDirFileRow>(
        "SELECT relative_path \
         FROM artifact_cache_native_out_dir_files \
         WHERE rustc_version = ? AND cache_key = ? \
         ORDER BY ordinal",
    )
    .bind(rustc_version)
    .bind(cache_key)
    .fetch_all(connection)
    .await?;

    if static_lib_rows.is_empty()
        && directive_rows.is_empty()
        && dep_env_rows.is_empty()
        && out_dir_rows.is_empty()
    {
        return Ok(None);
    }

    Ok(Some(NativeArtifacts {
        static_libs: static_lib_rows
            .into_iter()
            .map(|row| NativeLib {
                name: row.lib_name,
                bytes_sha256: row.bytes_sha256,
            })
            .collect(),
        cargo_directives: directive_rows.into_iter().map(|row| row.directive).collect(),
        dep_env_vars: dep_env_rows
            .into_iter()
            .map(|row| (row.env_key, row.env_value))
            .collect(),
        out_dir_files: out_dir_rows
            .into_iter()
            .map(|row| OutDirFile {
                relative_path: row.relative_path,
                contents: Vec::new(),
            })
            .collect(),
    }))
}

async fn replace_artifact_cache_metadata(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
    relative_dir: &str,
    size_bytes: u64,
    last_accessed_ms: u64,
    bundle: &ArtifactBundle,
) -> eyre::Result<()> {
    sqlx::query(
        "INSERT INTO artifact_cache_entries \
         (rustc_version, cache_key, relative_dir, size_bytes, last_accessed_ms, oci_reference, oci_digest, verified_marker_version, verified_marker_policy) \
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL) \
         ON CONFLICT(rustc_version, cache_key) DO UPDATE SET \
             relative_dir = excluded.relative_dir, \
             size_bytes = excluded.size_bytes, \
             last_accessed_ms = excluded.last_accessed_ms, \
             oci_reference = excluded.oci_reference, \
             oci_digest = excluded.oci_digest, \
             verified_marker_version = NULL, \
             verified_marker_policy = NULL",
    )
    .bind(rustc_version)
    .bind(cache_key)
    .bind(relative_dir)
    .bind(size_bytes as i64)
    .bind(last_accessed_ms as i64)
    .bind(&bundle.manifest.oci_reference)
    .bind(&bundle.manifest.oci_digest)
    .execute(connection)
    .await?;

    delete_artifact_cache_children(connection, rustc_version, cache_key).await?;

    for (ordinal, file) in bundle.manifest.config.outputs.iter().enumerate() {
        sqlx::query(
            "INSERT INTO artifact_cache_outputs \
             (rustc_version, cache_key, ordinal, file_name, media_type, sha256) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(rustc_version)
        .bind(cache_key)
        .bind(ordinal as i64)
        .bind(&file.file_name)
        .bind(&file.media_type)
        .bind(&file.sha256)
        .execute(connection)
        .await?;
    }

    for (ordinal, material) in bundle.manifest.sigstore_signatures.iter().enumerate() {
        sqlx::query(
            "INSERT INTO artifact_cache_sigstore_signatures \
             (rustc_version, cache_key, ordinal, payload_path, signature, certificate_pem, rekor_bundle_json) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(rustc_version)
        .bind(cache_key)
        .bind(ordinal as i64)
        .bind(&material.payload_path)
        .bind(&material.signature)
        .bind(&material.certificate_pem)
        .bind(material.rekor_bundle_json.as_deref())
        .execute(connection)
        .await?;
    }

    if let Some(native) = bundle.manifest.config.native.as_ref() {
        for (ordinal, lib) in native.static_libs.iter().enumerate() {
            sqlx::query(
                "INSERT INTO artifact_cache_native_static_libs \
                 (rustc_version, cache_key, ordinal, lib_name, bytes_sha256) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(rustc_version)
            .bind(cache_key)
            .bind(ordinal as i64)
            .bind(&lib.name)
            .bind(&lib.bytes_sha256)
            .execute(connection)
            .await?;
        }
        for (ordinal, directive) in native.cargo_directives.iter().enumerate() {
            sqlx::query(
                "INSERT INTO artifact_cache_native_directives \
                 (rustc_version, cache_key, ordinal, directive) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(rustc_version)
            .bind(cache_key)
            .bind(ordinal as i64)
            .bind(directive)
            .execute(connection)
            .await?;
        }
        for (env_key, env_value) in &native.dep_env_vars {
            sqlx::query(
                "INSERT INTO artifact_cache_native_dep_env_vars \
                 (rustc_version, cache_key, env_key, env_value) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(rustc_version)
            .bind(cache_key)
            .bind(env_key)
            .bind(env_value)
            .execute(connection)
            .await?;
        }
        for (ordinal, file) in native.out_dir_files.iter().enumerate() {
            sqlx::query(
                "INSERT INTO artifact_cache_native_out_dir_files \
                 (rustc_version, cache_key, ordinal, relative_path) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(rustc_version)
            .bind(cache_key)
            .bind(ordinal as i64)
            .bind(&file.relative_path)
            .execute(connection)
            .await?;
        }
    }
    Ok(())
}

async fn delete_artifact_cache_children(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
) -> eyre::Result<()> {
    for table in [
        "artifact_cache_outputs",
        "artifact_cache_sigstore_signatures",
        "artifact_cache_native_static_libs",
        "artifact_cache_native_directives",
        "artifact_cache_native_dep_env_vars",
        "artifact_cache_native_out_dir_files",
    ] {
        sqlx::query(&format!(
            "DELETE FROM {table} WHERE rustc_version = ? AND cache_key = ?"
        ))
        .bind(rustc_version)
        .bind(cache_key)
        .execute(connection)
        .await?;
    }
    Ok(())
}

async fn touch_artifact_cache_entry(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
    last_accessed_ms: u64,
) -> eyre::Result<()> {
    let result = sqlx::query(
        "UPDATE artifact_cache_entries \
         SET last_accessed_ms = ? \
         WHERE rustc_version = ? AND cache_key = ?",
    )
    .bind(last_accessed_ms as i64)
    .bind(rustc_version)
    .bind(cache_key)
    .execute(connection)
    .await?;
    if result.rows_affected() != 1 {
        return Err(eyre::eyre!(
            "artifact cache entry {cache_key} for rustc {rustc_version} is missing from the state database"
        ));
    }
    Ok(())
}

pub async fn persist_cached_bundle_trust_marker(
    config: &StowConfig,
    bundle: &CachedArtifactBundle,
    marker_version: u8,
    marker_policy: &str,
) -> eyre::Result<()> {
    let connection = connect(&config.cache_dir).await?;
    let result = sqlx::query(
        "UPDATE artifact_cache_entries \
         SET verified_marker_version = ?, verified_marker_policy = ? \
         WHERE rustc_version = ? AND cache_key = ?",
    )
    .bind(i64::from(marker_version))
    .bind(marker_policy)
    .bind(&bundle.rustc_version)
    .bind(&bundle.cache_key)
    .execute(&connection)
    .await?;
    if result.rows_affected() != 1 {
        return Err(eyre::eyre!(
            "artifact cache trust marker update did not match exactly one entry"
        ));
    }
    Ok(())
}

async fn delete_artifact_cache_entry(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
) -> eyre::Result<()> {
    sqlx::query(
        "DELETE FROM artifact_cache_entries WHERE rustc_version = ? AND cache_key = ?",
    )
    .bind(rustc_version)
    .bind(cache_key)
    .execute(connection)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use sha2::Digest;
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::bundle::{ArtifactBlobConfig, ArtifactBundleFile, ArtifactBundleManifest, SigstoreSignature};

    use super::{
        cache_key, list_artifact_cache_entries, prepare_local_cache, prepare_local_cache_blocking,
        touch_artifact_cache_entry, write_downloaded_bundle_to_entry,
    };
    use crate::config::{StowConfig, VerifyMode};
    use crate::fetch::{ArtifactBundle, FetchRequest, bundle_file_path};
    use crate::state_db::connect;

    #[test]
    fn prepare_local_cache_only_purges_on_version_change() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        std::fs::create_dir_all(config.artifact_cache_root().join("1.90.0"))
            .expect("create stale dir");
        std::fs::write(
            config.artifact_cache_root().join("1.90.0").join("stale.txt"),
            b"stale",
        )
        .expect("write stale file");

        run_async(async {
            let lease = prepare_local_cache(&config, "1.91.1").await.expect("prepare cache");
            drop(lease);
            assert!(config.artifact_cache_root().join("1.91.1").exists());
            assert!(!config.artifact_cache_root().join("1.90.0").exists());

            let pool = connect(&config.cache_dir).await.expect("connect state db");
            let active = sqlx::query_scalar::<_, String>(
                "SELECT value FROM metadata_values WHERE key = 'active_rustc_version'",
            )
            .fetch_optional(&pool)
            .await
            .expect("load active rustc version");
            assert_eq!(active.as_deref(), Some("1.91.1"));
        });
    }

    #[test]
    fn busy_old_rustc_version_is_not_purged() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let artifact_root = tempdir.path().join("cache");
        let purge_root = tempdir.path().join("purge");

        let first = prepare_local_cache_blocking(&artifact_root, &purge_root, "1.90.0", false)
            .expect("prepare old rustc cache");
        std::fs::write(artifact_root.join("1.90.0").join("busy.txt"), b"busy")
            .expect("write busy marker");

        let switched = prepare_local_cache_blocking(&artifact_root, &purge_root, "1.91.1", false)
            .expect("prepare new rustc cache");
        assert!(switched.stale_dirs.is_empty());
        assert!(artifact_root.join("1.90.0").exists());
        assert!(artifact_root.join("1.91.1").exists());

        drop(first.version_lease);
    }

    #[test]
    fn store_and_load_cached_bundle_round_trip() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let request = fetch_request("round-trip");
        let bundle = sample_bundle("round-trip", "libdemo-round-trip.rmeta");

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            let stored = super::store_downloaded_bundle(&config, &request, &bundle)
                .await
                .expect("store bundle");
            assert!(stored.entry_dir.exists());

            let loaded = super::load_cached_bundle(&config, &request)
                .await
                .expect("load bundle")
                .expect("cached bundle");
            assert_eq!(loaded.oci_reference, bundle.manifest.oci_reference);
            assert_eq!(loaded.oci_digest, bundle.manifest.oci_digest);
            assert_eq!(loaded.outputs.len(), 1);
            assert_eq!(loaded.outputs[0].file_name, "libdemo-round-trip.rmeta");
            assert_eq!(loaded.sigstore_signatures.len(), 1);
        });
    }

    #[test]
    fn store_downloaded_bundle_evicts_least_recently_used_entry() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let mut config = test_config(tempdir.path());
        let first_request = fetch_request("aaaa");
        let second_request = fetch_request("bbbb");
        let first_bundle = sample_bundle("aaaa", "libdemo-aaaa.rmeta");
        let second_bundle = sample_bundle("bbbb", "libdemo-bbbb.rmeta");
        let second_size = write_downloaded_bundle_to_entry(
            &tempdir.path().join("scratch-second"),
            &second_bundle,
        )
        .expect("measure second bundle size");

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            let first_cached = super::store_downloaded_bundle(&config, &first_request, &first_bundle)
                .await
                .expect("store first bundle");
            let first_entry_dir = first_cached.entry_dir.clone();
            let first_index = list_artifact_cache_entries(
                &connect(&config.cache_dir).await.expect("connect state db"),
                "1.91.1",
            )
            .await
            .expect("list entries");
            let first_size = first_index
                .get(&cache_key(&first_request))
                .expect("first entry")
                .size_bytes;
            config.artifact_cache_max_bytes = first_size + second_size - 1;
            drop(first_cached);

            super::store_downloaded_bundle(&config, &second_request, &second_bundle)
                .await
                .expect("store second bundle");

            let index = list_artifact_cache_entries(
                &connect(&config.cache_dir).await.expect("connect state db"),
                "1.91.1",
            )
            .await
            .expect("list entries");
            assert!(index.contains_key(&cache_key(&second_request)));
            assert!(!index.contains_key(&cache_key(&first_request)));
            assert!(!first_entry_dir.exists());
        });
    }

    #[test]
    fn load_cached_bundle_updates_lru_timestamp() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let request = fetch_request("touch-me");
        let bundle = sample_bundle("touch-me", "libdemo-touch-me.rmeta");

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            let cached = super::store_downloaded_bundle(&config, &request, &bundle)
                .await
                .expect("store bundle");
            drop(cached);

            let pool = connect(&config.cache_dir).await.expect("connect state db");
            touch_artifact_cache_entry(&pool, "1.91.1", &cache_key(&request), 1)
                .await
                .expect("set stale lru timestamp");

            let loaded = super::load_cached_bundle(&config, &request)
                .await
                .expect("load bundle")
                .expect("cached bundle");
            drop(loaded);

            let updated = list_artifact_cache_entries(&pool, "1.91.1")
                .await
                .expect("list entries")
                .get(&cache_key(&request))
                .expect("cache entry")
                .last_accessed_ms;
            assert!(updated > 1);
        });
    }

    #[test]
    fn remove_cached_bundle_drops_entry_and_files() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let request = fetch_request("remove-me");
        let bundle = sample_bundle("remove-me", "libdemo-remove-me.rmeta");

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            let cached = super::store_downloaded_bundle(&config, &request, &bundle)
                .await
                .expect("store bundle");
            let entry_dir = cached.entry_dir.clone();
            drop(cached);

            super::remove_cached_bundle(&config, &request)
                .await
                .expect("remove cached bundle");

            let index = list_artifact_cache_entries(
                &connect(&config.cache_dir).await.expect("connect state db"),
                "1.91.1",
            )
            .await
            .expect("list entries");
            assert!(!index.contains_key(&cache_key(&request)));
            assert!(!entry_dir.exists());
        });
    }

    fn test_config(root: &std::path::Path) -> StowConfig {
        StowConfig {
            edge_url: "http://127.0.0.1:8787".to_owned(),
            cache_dir: root.join(".stow"),
            request_timeout: Duration::from_secs(1),
            negative_cache_ttl: Duration::from_secs(60),
            graph_cache_ttl: Duration::from_secs(60),
            circuit_reset_after: Duration::from_secs(60),
            circuit_trip_threshold: 5,
            artifact_cache_max_bytes: u64::MAX,
            verify_mode: VerifyMode::GithubCi,
            mock_public_key_path: None,
        }
    }

    fn fetch_request(c_metadata: &str) -> FetchRequest<'_> {
        FetchRequest {
            target: "aarch64-apple-darwin",
            rustc_version: "1.91.1",
            c_metadata,
            crate_name: "demo",
        }
    }

    fn sample_bundle(c_metadata: &str, file_name: &str) -> ArtifactBundle {
        let file_contents = b"demo-artifact".to_vec();
        let compression_level = *zstd::compression_level_range().end();
        let stored_contents = zstd::bulk::compress(&file_contents, compression_level)
            .expect("compress sample artifact bundle output");
        ArtifactBundle {
            manifest: ArtifactBundleManifest {
                oci_reference: "ghcr.io/stow-rs/cache/demo:test".to_owned(),
                oci_digest: "sha256:test".to_owned(),
                config: ArtifactBlobConfig {
                    crate_name: "demo".to_owned(),
                    crate_version: "1.0.0".to_owned(),
                    c_metadata: c_metadata.to_owned(),
                    target: "aarch64-apple-darwin".to_owned(),
                    rustc_version: "1.91.1".to_owned(),
                    features_json: "[]".to_owned(),
                    artifact_size: file_contents.len() as u64,
                    kind: ArtifactKind::Rlib,
                    crate_types: vec![RustCrateType::Lib],
                    outputs: vec![ArtifactBundleFile {
                        file_name: file_name.to_owned(),
                        media_type: stow_types::bundle::STOW_RMETA_MEDIA_TYPE.to_owned(),
                        sha256: hex::encode(sha2::Sha256::digest(&file_contents)),
                    }],
                    native: None,
                },
                sigstore_signatures: vec![SigstoreSignature {
                    payload_path: "sigstore/payload.json".to_owned(),
                    signature: "MEUCIQDUMMY".to_owned(),
                    certificate_pem: "mock-local".to_owned(),
                    rekor_bundle_json: None,
                }],
            },
            files: BTreeMap::from([
                (bundle_file_path(file_name), stored_contents),
                (
                    "sigstore/payload.json".to_owned(),
                    serde_json::to_vec(&serde_json::json!({
                        "critical": {
                            "identity": {
                                "docker-reference": "ghcr.io/stow-rs/cache/demo:test"
                            },
                            "image": {
                                "docker-manifest-digest": "sha256:test"
                            },
                            "type": "cosign container image signature"
                        },
                        "optional": null
                    }))
                    .expect("serialize sample sigstore payload"),
                ),
            ]),
        }
    }

    fn run_async(future: impl std::future::Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime")
            .block_on(future);
    }
}
