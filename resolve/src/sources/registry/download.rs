//! Shared download logic between [`HttpRegistry`] and [`RemoteRegistry`].
//!
//! [`HttpRegistry`]: super::http_remote::HttpRegistry
//! [`RemoteRegistry`]: super::remote::RemoteRegistry

use crate::util::interning::InternedString;
use crate::util::registry::crate_url;
use crate::util::sha256::Sha256;

use crate::core::PackageId;
use crate::core::global_cache_tracker;
use crate::sources::registry::MaybeLock;
use crate::sources::registry::RegistryConfig;
use crate::util::cache_lock::CacheLockMode;
use crate::util::errors::CargoResult;
use crate::util::fs::File;
use crate::util::paths;
use crate::util::{Filesystem, GlobalContext};

use std::str;

/// Checks if `pkg` is downloaded and ready under the directory at `cache_path`.
/// If not, returns a URL to download it from.
///
/// This is primarily called by [`RegistryData::download`](super::RegistryData::download).
pub(super) fn download(
    cache_path: &Filesystem,
    src_dir: &Filesystem,
    gctx: &GlobalContext,
    encoded_registry_name: InternedString,
    pkg: PackageId,
    checksum: &str,
    registry_config: RegistryConfig,
) -> CargoResult<MaybeLock> {
    let path = cache_path.join(&pkg.tarball_name());
    let path = gctx.assert_package_cache_locked(CacheLockMode::DownloadExclusive, &path);

    // Memory-capped targets keep the downloaded `.crate` in a detached file
    // and drop it after unpacking, so a prior resolve in the same request
    // leaves no tarball — but its `.cargo-ok` marks the unpack done.
    // `get_pkg`'s `unpack_package` fast-paths on the marker before it ever
    // reads the file, so any open handle satisfies the `Ready` shape; open
    // the marker itself.
    let dst = src_dir.join(format!("{}-{}", pkg.name(), pkg.version()));
    let ok_path = dst.join(super::PACKAGE_SOURCE_LOCK);
    let ok_path = gctx.assert_package_cache_locked(CacheLockMode::DownloadExclusive, &ok_path);
    if matches!(
        crate::util::fs::read_to_string(ok_path)
            .ok()
            .and_then(|ok| serde_json::from_str::<super::LockMetadata>(&ok).ok()),
        Some(meta) if meta.v == 1
    ) {
        return Ok(MaybeLock::Ready(paths::open(ok_path)?));
    }

    // Attempt to open a read-only copy first to avoid an exclusive write
    // lock and also work with read-only filesystems. Note that we check the
    // length of the file like below to handle interrupted downloads.
    //
    // If this fails then we fall through to the exclusive path where we may
    // have to redownload the file.
    if let Ok(dst) = paths::open(path) {
        let meta = dst.metadata()?;
        if meta.len() > 0 {
            gctx.deferred_global_last_use()?.mark_registry_crate_used(
                global_cache_tracker::RegistryCrate {
                    encoded_registry_name,
                    crate_filename: pkg.tarball_name().into(),
                    size: meta.len(),
                },
            );
            return Ok(MaybeLock::Ready(dst));
        }
    }

    let url = crate_url(
        &registry_config.dl,
        &*pkg.name(),
        &pkg.version().to_string(),
        checksum,
    );

    Ok(MaybeLock::Download {
        url,
        descriptor: pkg.to_string(),
        authorization: None,
    })
}

/// Verifies the integrity of `data` with `checksum` and prepares a file for
/// unpacking, persisting the bytes under `cache_path` on the host.
///
/// This is primarily called by [`RegistryData::finish_download`](super::RegistryData::finish_download).
pub(super) fn finish_download(
    cache_path: &Filesystem,
    gctx: &GlobalContext,
    encoded_registry_name: InternedString,
    pkg: PackageId,
    checksum: &str,
    data: Vec<u8>,
) -> CargoResult<File> {
    // Verify what we just downloaded
    let actual = Sha256::new().update(&data).finish_hex();
    if actual != checksum {
        anyhow::bail!("failed to verify the checksum of `{}`", pkg)
    }
    gctx.deferred_global_last_use()?.mark_registry_crate_used(
        global_cache_tracker::RegistryCrate {
            encoded_registry_name,
            crate_filename: pkg.tarball_name().into(),
            size: data.len() as u64,
        },
    );

    #[cfg(target_family = "wasm")]
    {
        let path = cache_path.join(&pkg.tarball_name()).into_path_unlocked();
        return Ok(File::detached(path, data));
    }

    #[cfg(not(target_family = "wasm"))]
    {
        cache_path.create_dir()?;
        let path = cache_path.join(&pkg.tarball_name());
        let path = gctx.assert_package_cache_locked(CacheLockMode::DownloadExclusive, &path);
        if let Ok(meta) = paths::metadata(path) {
            if meta.len() > 0 {
                return paths::open(path);
            }
        }

        paths::write(path, &data)?;
        paths::open(path)
    }
}

/// Checks if a tarball of `pkg` has been already downloaded under the
/// directory at `cache_path`. On memory-capped filesystems the `.crate`
/// is deleted once its contents land in `src_dir`, so a completed
/// `.cargo-ok` there also answers downloaded — a later per-target resolve that would
/// otherwise re-download every package in the request.
///
/// This is primarily called by [`RegistryData::is_crate_downloaded`](super::RegistryData::is_crate_downloaded).
pub(super) fn is_crate_downloaded(
    cache_path: &Filesystem,
    src_dir: &Filesystem,
    gctx: &GlobalContext,
    pkg: PackageId,
) -> bool {
    let path = cache_path.join(pkg.tarball_name());
    let path = gctx.assert_package_cache_locked(CacheLockMode::DownloadExclusive, &path);
    if let Ok(meta) = paths::metadata(path) {
        if meta.len() > 0 {
            return true;
        }
    }
    let dst = src_dir.join(format!("{}-{}", pkg.name(), pkg.version()));
    let ok_path = dst.join(super::PACKAGE_SOURCE_LOCK);
    let ok_path = gctx.assert_package_cache_locked(CacheLockMode::DownloadExclusive, &ok_path);
    matches!(
        crate::util::fs::read_to_string(ok_path)
            .ok()
            .and_then(|ok| serde_json::from_str::<super::LockMetadata>(&ok).ok()),
        Some(meta) if meta.v == 1
    )
}
