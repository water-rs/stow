use std::path::PathBuf;

use stow_shim::STOW_ZSTD_COMPRESSION_LEVEL;

/// Asynchronously compress `bytes` with the workspace-wide stow zstd level
/// using smol's blocking-task pool.
pub async fn compress(bytes: Vec<u8>, path: PathBuf) -> stow_types::error::Result<Vec<u8>> {
    smol::unblock(move || {
        zstd::bulk::compress(&bytes, STOW_ZSTD_COMPRESSION_LEVEL).map_err(|error| {
            stow_types::stow_error!(
                "zstd compress {} at level {}: {error}",
                path.display(),
                STOW_ZSTD_COMPRESSION_LEVEL
            )
        })
    })
    .await
}
