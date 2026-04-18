use std::path::PathBuf;

/// Use zstd's balanced default so large native artifacts do not stall CI while
/// preserving the same zstd-compressed OCI layer format.
pub const STOW_ZSTD_COMPRESSION_LEVEL: i32 = zstd::DEFAULT_COMPRESSION_LEVEL;

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
