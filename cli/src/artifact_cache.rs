use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use eyre::Context;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use stow_types::artifact::NativeArtifacts;
use stow_types::bundle::{ArtifactBundleFile, ArtifactBundleManifest};

use crate::config::StowConfig;
use crate::fetch::{ArtifactBundle, FetchRequest, bundle_file_path, decode_bundle_output_bytes};
use crate::state_file::{now_millis, with_locked_json_file};

const BUNDLES_DIR: &str = "bundles";
const NATIVE_DIR: &str = "native";
const NATIVE_OUT_DIR: &str = "native/out";
const VERSION_LEASES_DIR: &str = "leases";

#[derive(Debug)]
pub struct RustcVersionLease {
    _file: File,
}

#[derive(Debug)]
pub struct CachedArtifactBundle {
    pub manifest: ArtifactBundleManifest,
    pub(crate) entry_dir: PathBuf,
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
    let prepared = smol::unblock(move || {
        prepare_local_cache_blocking(&artifact_cache_root, &purge_root, &rustc_version)
    })
    .await?;
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
    let index_path = config.artifact_cache_index_path(request.rustc_version);
    let cache_key = cache_key(request);
    let entry_relative_dir = entry_relative_dir(request);
    smol::unblock(move || {
        with_locked_json_file::<ArtifactCacheIndex, Option<CachedArtifactBundle>>(
            &index_path,
            |index| load_cached_bundle_locked(index, &version_dir, &cache_key, &entry_relative_dir),
        )
    })
    .await
}

pub async fn store_downloaded_bundle(
    config: &StowConfig,
    request: &FetchRequest<'_>,
    bundle: &ArtifactBundle,
) -> eyre::Result<CachedArtifactBundle> {
    let config = config.clone();
    let request = OwnedFetchRequest::from(request);
    let bundle = bundle.clone();
    smol::unblock(move || store_downloaded_bundle_blocking(&config, &request, &bundle)).await
}

pub async fn remove_cached_bundle(
    config: &StowConfig,
    request: &FetchRequest<'_>,
) -> eyre::Result<()> {
    let version_dir = config.artifact_cache_version_dir(request.rustc_version);
    let index_path = config.artifact_cache_index_path(request.rustc_version);
    let cache_key = cache_key(request);
    smol::unblock(move || {
        with_locked_json_file::<ArtifactCacheIndex, ()>(&index_path, |index| {
            remove_cached_bundle_locked(index, &version_dir, &cache_key)
        })
    })
    .await
}

fn prepare_local_cache_blocking(
    artifact_cache_root: &Path,
    purge_root: &Path,
    rustc_version: &str,
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

    let active_state_path = artifact_cache_root.join("active-rustc-version.json");
    with_locked_json_file::<ActiveRustcVersionState, PreparedLocalCache>(
        &active_state_path,
        |state| {
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

            if state.current_version.as_deref() == Some(rustc_version) {
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
                let Some(_stale_lease) =
                    try_acquire_version_exclusive_lock(&leases_root, &stale_version)?
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

            state.current_version = Some(rustc_version.to_owned());
            Ok(PreparedLocalCache {
                stale_dirs,
                version_lease,
            })
        },
    )
}

fn load_cached_bundle_locked(
    index: &mut ArtifactCacheIndex,
    version_dir: &Path,
    cache_key: &str,
    entry_relative_dir: &Path,
) -> eyre::Result<Option<CachedArtifactBundle>> {
    let Some(entry) = index.entries.get_mut(cache_key) else {
        return Ok(None);
    };

    let expected_entry_dir = version_dir.join(entry_relative_dir);
    let indexed_entry_dir = version_dir.join(&entry.relative_dir);
    if expected_entry_dir != indexed_entry_dir {
        return Err(eyre::eyre!(
            "artifact cache index mismatch for {cache_key}: expected {}, got {}",
            expected_entry_dir.display(),
            indexed_entry_dir.display()
        ));
    }
    if !indexed_entry_dir.exists() {
        index.entries.remove(cache_key);
        return Ok(None);
    }

    let manifest = read_manifest(&indexed_entry_dir)?;
    let lease_lock = acquire_entry_shared_lock(version_dir, cache_key)?;
    entry.last_accessed_ms = now_millis();
    Ok(Some(CachedArtifactBundle {
        manifest,
        entry_dir: indexed_entry_dir,
        _lease_lock: lease_lock,
    }))
}

fn store_downloaded_bundle_blocking(
    config: &StowConfig,
    request: &OwnedFetchRequest,
    bundle: &ArtifactBundle,
) -> eyre::Result<CachedArtifactBundle> {
    let version_dir = config.artifact_cache_version_dir(&request.rustc_version);
    let bundles_dir = version_dir.join(BUNDLES_DIR);
    std::fs::create_dir_all(&bundles_dir)
        .wrap_err_with(|| format!("create bundle cache directory {}", bundles_dir.display()))?;

    let entry_relative_dir = entry_relative_dir_owned(request);
    let entry_dir = version_dir.join(&entry_relative_dir);
    let entry_parent = entry_dir.parent().ok_or_else(|| {
        eyre::eyre!(
            "artifact cache entry dir {} has no parent",
            entry_dir.display()
        )
    })?;
    std::fs::create_dir_all(entry_parent)
        .wrap_err_with(|| format!("create artifact cache parent {}", entry_parent.display()))?;
    let cache_key = cache_key_owned(request);
    let tempdir = tempfile::Builder::new()
        .prefix(&format!("{}-", request.c_metadata))
        .tempdir_in(entry_parent)
        .wrap_err_with(|| format!("create temp cache directory for {}", entry_dir.display()))?;
    let size_bytes = write_downloaded_bundle_to_entry(tempdir.path(), bundle)?;

    let index_path = config.artifact_cache_index_path(&request.rustc_version);
    let cache_key_for_lock = cache_key.clone();
    let entry_relative_dir_for_lock = entry_relative_dir.clone();
    let max_bytes = config.artifact_cache_max_bytes;
    let final_bundle =
        with_locked_json_file::<ArtifactCacheIndex, CachedArtifactBundle>(&index_path, |index| {
            let now_ms = now_millis();
            if !entry_dir.exists() {
                if let Some(parent) = entry_dir.parent() {
                    std::fs::create_dir_all(parent).wrap_err_with(|| {
                        format!("create artifact cache parent {}", parent.display())
                    })?;
                }
                std::fs::rename(tempdir.path(), &entry_dir).wrap_err_with(|| {
                    format!(
                        "move artifact cache entry {} into place at {}",
                        tempdir.path().display(),
                        entry_dir.display()
                    )
                })?;
            }

            index.entries.insert(
                cache_key_for_lock.clone(),
                ArtifactCacheIndexEntry {
                    relative_dir: path_to_string(&entry_relative_dir_for_lock)?,
                    size_bytes,
                    last_accessed_ms: now_ms,
                },
            );

            evict_entries(index, &version_dir, max_bytes, &cache_key_for_lock)?;
            let manifest = read_manifest(&entry_dir)?;
            let lease_lock = acquire_entry_shared_lock(&version_dir, &cache_key_for_lock)?;
            Ok(CachedArtifactBundle {
                manifest,
                entry_dir: entry_dir.clone(),
                _lease_lock: lease_lock,
            })
        })?;

    Ok(final_bundle)
}

fn remove_cached_bundle_locked(
    index: &mut ArtifactCacheIndex,
    version_dir: &Path,
    cache_key: &str,
) -> eyre::Result<()> {
    let Some(entry) = index.entries.remove(cache_key) else {
        return Ok(());
    };
    let entry_dir = version_dir.join(&entry.relative_dir);
    let Some(eviction_lock) = try_acquire_entry_exclusive_lock(version_dir, cache_key)? else {
        index.entries.insert(cache_key.to_owned(), entry);
        return Err(eyre::eyre!(
            "artifact cache entry {cache_key} is in use by another stow process"
        ));
    };
    if entry_dir.exists() {
        std::fs::remove_dir_all(&entry_dir)
            .wrap_err_with(|| format!("remove cached artifact entry {}", entry_dir.display()))?;
    }
    drop(eviction_lock);
    Ok(())
}

fn evict_entries(
    index: &mut ArtifactCacheIndex,
    version_dir: &Path,
    max_bytes: u64,
    protected_key: &str,
) -> eyre::Result<()> {
    let mut total_bytes = index
        .entries
        .values()
        .fold(0u64, |sum, entry| sum.saturating_add(entry.size_bytes));
    if total_bytes <= max_bytes {
        return Ok(());
    }

    let mut eviction_order = index
        .entries
        .iter()
        .filter(|(key, _)| key.as_str() != protected_key)
        .map(|(key, entry)| (key.clone(), entry.last_accessed_ms))
        .collect::<Vec<_>>();
    eviction_order.sort_by(|left, right| left.1.cmp(&right.1).then(left.0.cmp(&right.0)));

    for (cache_key, _) in eviction_order {
        let Some(entry) = index.entries.remove(&cache_key) else {
            continue;
        };
        let entry_dir = version_dir.join(&entry.relative_dir);
        let Some(eviction_lock) = try_acquire_entry_exclusive_lock(version_dir, &cache_key)? else {
            index.entries.insert(cache_key.clone(), entry);
            continue;
        };
        if entry_dir.exists() {
            std::fs::remove_dir_all(&entry_dir)
                .wrap_err_with(|| format!("evict artifact cache entry {}", entry_dir.display()))?;
        }
        drop(eviction_lock);
        total_bytes = total_bytes.saturating_sub(entry.size_bytes);
        if total_bytes <= max_bytes {
            return Ok(());
        }
    }

    if total_bytes > max_bytes {
        if let Some(entry) = index.entries.remove(protected_key) {
            let entry_dir = version_dir.join(&entry.relative_dir);
            if let Some(eviction_lock) =
                try_acquire_entry_exclusive_lock(version_dir, protected_key)?
            {
                if entry_dir.exists() {
                    std::fs::remove_dir_all(&entry_dir).wrap_err_with(|| {
                        format!(
                            "evict oversized protected artifact cache entry {}",
                            entry_dir.display()
                        )
                    })?;
                }
                drop(eviction_lock);
            } else {
                index.entries.insert(protected_key.to_owned(), entry);
                return Err(eyre::eyre!(
                    "artifact cache is full and the protected entry {protected_key} is in use by another stow process"
                ));
            }
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

    let manifest_path = entry_dir.join(stow_types::bundle::STOW_BUNDLE_MANIFEST_PATH);
    let manifest_bytes = serde_json::to_vec(&bundle.manifest)
        .wrap_err("serialize artifact bundle manifest for local cache")?;
    std::fs::write(&manifest_path, &manifest_bytes)
        .wrap_err_with(|| format!("write cached bundle manifest {}", manifest_path.display()))?;
    total_bytes = total_bytes.saturating_add(manifest_bytes.len() as u64);

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

fn read_manifest(entry_dir: &Path) -> eyre::Result<ArtifactBundleManifest> {
    let manifest_path = entry_dir.join(stow_types::bundle::STOW_BUNDLE_MANIFEST_PATH);
    let manifest_bytes = std::fs::read(&manifest_path)
        .wrap_err_with(|| format!("read cached bundle manifest {}", manifest_path.display()))?;
    serde_json::from_slice(&manifest_bytes)
        .wrap_err_with(|| format!("parse cached bundle manifest {}", manifest_path.display()))
}

fn cache_key(request: &FetchRequest<'_>) -> String {
    format!("{}/{}", request.target, request.c_metadata)
}

fn cache_key_owned(request: &OwnedFetchRequest) -> String {
    format!("{}/{}", request.target, request.c_metadata)
}

fn entry_relative_dir(request: &FetchRequest<'_>) -> PathBuf {
    PathBuf::from(BUNDLES_DIR)
        .join(request.target)
        .join(request.c_metadata)
}

fn entry_relative_dir_owned(request: &OwnedFetchRequest) -> PathBuf {
    PathBuf::from(BUNDLES_DIR)
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

#[derive(Debug, Default, Serialize, Deserialize)]
struct ArtifactCacheIndex {
    entries: BTreeMap<String, ArtifactCacheIndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArtifactCacheIndexEntry {
    relative_dir: String,
    size_bytes: u64,
    last_accessed_ms: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ActiveRustcVersionState {
    current_version: Option<String>,
}

#[derive(Debug)]
struct PreparedLocalCache {
    stale_dirs: Vec<PathBuf>,
    version_lease: RustcVersionLease,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use sha2::Digest;
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::bundle::{ArtifactBlobConfig, ArtifactBundleFile, ArtifactBundleManifest};

    use super::{
        ActiveRustcVersionState, ArtifactCacheIndex, prepare_local_cache_blocking, read_manifest,
        remove_cached_bundle_locked, store_downloaded_bundle_blocking,
        write_downloaded_bundle_to_entry,
    };
    use crate::config::{StowConfig, VerifyMode};
    use crate::fetch::{ArtifactBundle, FetchRequest, bundle_file_path};

    #[test]
    fn prepare_local_cache_only_purges_on_version_change() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let artifact_root = tempdir.path().join("cache");
        let purge_root = tempdir.path().join("purge");
        std::fs::create_dir_all(artifact_root.join("1.90.0")).expect("create stale dir");
        std::fs::write(artifact_root.join("1.90.0").join("stale.txt"), b"stale")
            .expect("write stale file");

        let stale = prepare_local_cache_blocking(&artifact_root, &purge_root, "1.91.1")
            .expect("prepare cache");
        assert_eq!(stale.stale_dirs.len(), 1);
        assert!(artifact_root.join("1.91.1").exists());
        assert!(!artifact_root.join("1.90.0").exists());
        assert!(stale.stale_dirs[0].exists());

        let state = serde_json::from_slice::<ActiveRustcVersionState>(
            &std::fs::read(artifact_root.join("active-rustc-version.json")).expect("read state"),
        )
        .expect("parse state");
        assert_eq!(state.current_version.as_deref(), Some("1.91.1"));

        let second = prepare_local_cache_blocking(&artifact_root, &purge_root, "1.91.1")
            .expect("prepare same version");
        assert!(second.stale_dirs.is_empty());
    }

    #[test]
    fn busy_old_rustc_version_is_not_purged() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let artifact_root = tempdir.path().join("cache");
        let purge_root = tempdir.path().join("purge");

        let first = prepare_local_cache_blocking(&artifact_root, &purge_root, "1.90.0")
            .expect("prepare old rustc cache");
        std::fs::write(artifact_root.join("1.90.0").join("busy.txt"), b"busy")
            .expect("write busy marker");

        let switched = prepare_local_cache_blocking(&artifact_root, &purge_root, "1.91.1")
            .expect("prepare new rustc cache");
        assert!(switched.stale_dirs.is_empty());
        assert!(artifact_root.join("1.90.0").exists());
        assert!(artifact_root.join("1.91.1").exists());

        drop(first.version_lease);
    }

    #[test]
    fn store_downloaded_bundle_evicts_least_recently_used_entry() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let mut config = test_config(tempdir.path());
        prepare_local_cache_blocking(
            &config.artifact_cache_root(),
            &config.artifact_cache_purge_root(),
            "1.91.1",
        )
        .expect("prepare cache");

        let first_request = owned_request("aarch64-apple-darwin", "1.91.1", "aaaa");
        let first_bundle = sample_bundle("aaaa", "libdemo-aaaa.rmeta");
        let first_cached = store_downloaded_bundle_blocking(&config, &first_request, &first_bundle)
            .expect("store first bundle");
        let first_index = serde_json::from_slice::<ArtifactCacheIndex>(
            &std::fs::read(config.artifact_cache_index_path("1.91.1")).expect("read first index"),
        )
        .expect("parse first index");
        let first_size = first_index
            .entries
            .get("aarch64-apple-darwin/aaaa")
            .expect("first entry")
            .size_bytes;
        assert_eq!(
            read_manifest(&first_cached.entry_dir)
                .expect("read manifest")
                .config
                .c_metadata,
            "aaaa"
        );
        let first_entry_dir = first_cached.entry_dir.clone();

        let second_request = owned_request("aarch64-apple-darwin", "1.91.1", "bbbb");
        let second_bundle = sample_bundle("bbbb", "libdemo-bbbb.rmeta");
        let second_size = write_downloaded_bundle_to_entry(
            &tempdir.path().join("scratch-second"),
            &second_bundle,
        )
        .expect("measure second bundle size");
        config.artifact_cache_max_bytes = first_size + second_size - 1;
        drop(first_cached);
        let second_cached =
            store_downloaded_bundle_blocking(&config, &second_request, &second_bundle)
                .expect("store second bundle");

        let index = serde_json::from_slice::<ArtifactCacheIndex>(
            &std::fs::read(config.artifact_cache_index_path("1.91.1")).expect("read index"),
        )
        .expect("parse index");
        assert!(index.entries.contains_key("aarch64-apple-darwin/bbbb"));
        assert!(!index.entries.contains_key("aarch64-apple-darwin/aaaa"));
        assert!(!first_entry_dir.exists());
        assert!(second_cached.entry_dir.exists());
    }

    #[test]
    fn in_use_entry_blocks_lru_eviction() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let mut config = test_config(tempdir.path());
        prepare_local_cache_blocking(
            &config.artifact_cache_root(),
            &config.artifact_cache_purge_root(),
            "1.91.1",
        )
        .expect("prepare cache");

        let first_request = owned_request("aarch64-apple-darwin", "1.91.1", "lock-a");
        let first_bundle = sample_bundle("lock-a", "libdemo-lock-a.rmeta");
        let first_cached = store_downloaded_bundle_blocking(&config, &first_request, &first_bundle)
            .expect("store first bundle");
        let first_index = serde_json::from_slice::<ArtifactCacheIndex>(
            &std::fs::read(config.artifact_cache_index_path("1.91.1")).expect("read first index"),
        )
        .expect("parse first index");
        let first_size = first_index
            .entries
            .get("aarch64-apple-darwin/lock-a")
            .expect("first entry")
            .size_bytes;

        let second_request = owned_request("aarch64-apple-darwin", "1.91.1", "lock-b");
        let second_bundle = sample_bundle("lock-b", "libdemo-lock-b.rmeta");
        let second_size = write_downloaded_bundle_to_entry(
            &tempdir.path().join("scratch-lock-second"),
            &second_bundle,
        )
        .expect("measure second bundle size");
        config.artifact_cache_max_bytes = first_size + second_size - 1;

        let _ = store_downloaded_bundle_blocking(&config, &second_request, &second_bundle)
            .expect_err("busy entry must block eviction");
        assert!(first_cached.entry_dir.exists());
    }

    #[test]
    fn remove_cached_bundle_drops_entry_and_files() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        prepare_local_cache_blocking(
            &config.artifact_cache_root(),
            &config.artifact_cache_purge_root(),
            "1.91.1",
        )
        .expect("prepare cache");

        let request = owned_request("aarch64-apple-darwin", "1.91.1", "remove-me");
        let bundle = sample_bundle("remove-me", "libdemo-remove-me.rmeta");
        let cached =
            store_downloaded_bundle_blocking(&config, &request, &bundle).expect("store bundle");
        let entry_dir = cached.entry_dir.clone();
        drop(cached);

        let index_path = config.artifact_cache_index_path("1.91.1");
        let version_dir = config.artifact_cache_version_dir("1.91.1");
        super::with_locked_json_file::<ArtifactCacheIndex, ()>(&index_path, |index| {
            remove_cached_bundle_locked(index, &version_dir, "aarch64-apple-darwin/remove-me")
        })
        .expect("remove cached bundle");

        let index = serde_json::from_slice::<ArtifactCacheIndex>(
            &std::fs::read(index_path).expect("read index"),
        )
        .expect("parse index");
        assert!(!index.entries.contains_key("aarch64-apple-darwin/remove-me"));
        assert!(!entry_dir.exists());
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

    fn owned_request<'a>(
        target: &'a str,
        rustc_version: &'a str,
        c_metadata: &'a str,
    ) -> super::OwnedFetchRequest {
        super::OwnedFetchRequest::from(&FetchRequest {
            target,
            rustc_version,
            c_metadata,
            crate_name: "demo",
        })
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
                sigstore_signatures: Vec::new(),
            },
            files: BTreeMap::from([(bundle_file_path(file_name), stored_contents)]),
        }
    }
}
