//! The bundle pack format and the zstd settings every producer shares.
//!
//! A bundle's files travel as one OCI layer: a deterministic tar of the
//! node's outputs, compressed as a single zstd stream so redundancy across
//! files (an rlib embeds the metadata its rmeta carries) is paid for once.
//! Compression runs once at publish time on every core of the machine;
//! decompression speed does not depend on the level, so readers pay the
//! same at any setting.

use std::io::{Read as _, Write as _};

use sha2::{Digest as _, Sha256};
use stow_types::bundle::ArtifactBundleFile;
use stow_types::error::{Context as _, Result};
use stow_types::index::{ArtifactIndex, IndexError};

/// zstd level of every bundle pack and index slice. Decompression runs at
/// the same speed whatever the level, so the cost is the publisher's, once.
pub const STOW_ZSTD_COMPRESSION_LEVEL: i32 = 19;

/// `log2` of the zstd window. Bundle packs enable long-distance matching
/// with it, and every reader allows exactly this window — the memory a
/// decoder commits is bounded by `2^27` bytes (128 MiB).
pub const STOW_ZSTD_WINDOW_LOG: u32 = 27;

/// Bytes of input each multithreading job of [`compress`] takes. At level
/// 19 zstd's default overlap is the whole window, which forces every job to
/// span a full window and leaves all but the largest inputs on one worker;
/// 32 MiB jobs with [`STOW_ZSTD_OVERLAP_LOG`] split a large node across the
/// cores for about 1% of ratio, and an input under 32 MiB stays one job, so
/// its bytes are those of a single-threaded run.
pub const STOW_ZSTD_JOB_SIZE: u32 = 32 << 20;

/// zstd `overlapLog` of [`compress`]: each job is primed with the last
/// `window >> (9 - 8)` bytes of the one before it, which keeps the
/// cross-job matches that long-distance matching finds.
pub const STOW_ZSTD_OVERLAP_LOG: u32 = 8;

/// Compress `bytes` as one zstd stream at [`STOW_ZSTD_COMPRESSION_LEVEL`]
/// with long-distance matching and a [`STOW_ZSTD_WINDOW_LOG`] window, on
/// every core of the machine.
///
/// The frame records the content size, so the window a decoder commits is
/// never larger than the content.
///
/// # Errors
///
/// Returns the encoder's error.
pub fn compress(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    let workers = std::thread::available_parallelism()
        .map_or(1, |cores| u32::try_from(cores.get()).unwrap_or(u32::MAX));
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), STOW_ZSTD_COMPRESSION_LEVEL)?;
    encoder.set_pledged_src_size(Some(bytes.len() as u64))?;
    encoder.long_distance_matching(true)?;
    encoder.window_log(STOW_ZSTD_WINDOW_LOG)?;
    encoder.multithread(workers)?;
    encoder.set_parameter(zstd::zstd_safe::CParameter::JobSize(STOW_ZSTD_JOB_SIZE))?;
    encoder.set_parameter(zstd::zstd_safe::CParameter::OverlapSizeLog(
        STOW_ZSTD_OVERLAP_LOG,
    ))?;
    encoder.write_all(bytes)?;
    encoder.finish()
}

/// Decompress one zstd stream, allowing the [`STOW_ZSTD_WINDOW_LOG`]
/// window [`compress`] writes and no larger.
///
/// # Errors
///
/// Returns the decoder's error: not a zstd stream, or a window past the
/// bound.
pub fn decompress(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut decoder = zstd::stream::Decoder::new(bytes)?;
    decoder.window_log_max(STOW_ZSTD_WINDOW_LOG)?;
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

/// Serialize `index` and compress it with [`compress`] — the bytes an
/// index slice's OCI layer carries.
///
/// # Errors
///
/// [`IndexError::Serialize`] or [`IndexError::Compress`].
pub fn encode_index(index: &ArtifactIndex) -> std::result::Result<Vec<u8>, IndexError> {
    stow_types::index::encode(index, compress)
}

/// Pack `files` — `(name, bytes)` in the order given — into one layer:
/// a tar every reader can reproduce byte for byte (regular files, mode
/// `0644`, owner `0:0`, mtime `0`), compressed with [`compress`].
///
/// # Errors
///
/// Returns an error when a tar entry or the compression fails.
pub fn pack(files: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    let mut tar = tar::Builder::new(Vec::new());
    for (name, bytes) in files {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        tar.append_data(&mut header, name, *bytes)
            .wrap_err_with(|| format!("append {name} to the pack"))?;
    }
    let tar = tar.into_inner().wrap_err("finish the pack tar")?;
    compress(&tar).wrap_err("compress the pack")
}

/// Unpack a layer [`pack`] wrote and verify it against `expected`: the
/// tar must hold exactly those files, in that order, and each file's
/// SHA-256 must be the one the signed config records.
///
/// Returns every file's bytes in `expected` order.
///
/// # Errors
///
/// Returns an error when the layer is not a zstd stream within the window
/// bound, holds other entries than `expected` names, or a file's hash
/// differs.
pub fn unpack(pack: &[u8], expected: &[&ArtifactBundleFile]) -> Result<Vec<Vec<u8>>> {
    let mut decoder = zstd::stream::Decoder::new(pack).wrap_err("open the pack stream")?;
    decoder
        .window_log_max(STOW_ZSTD_WINDOW_LOG)
        .wrap_err("bound the pack window")?;
    let mut archive = tar::Archive::new(decoder);
    let mut entries = archive.entries().wrap_err("read the pack tar")?;
    let mut files = Vec::with_capacity(expected.len());
    for file in expected {
        let mut entry = entries
            .next()
            .ok_or_else(|| stow_types::stow_error!("the pack lacks {}", file.file_name))?
            .wrap_err("read a pack entry")?;
        let name = entry.path().wrap_err("read a pack entry path")?;
        if name.to_str() != Some(file.file_name.as_str()) || !entry.header().entry_type().is_file()
        {
            return Err(stow_types::stow_error!(
                "the pack holds {} where {} is declared",
                name.display(),
                file.file_name
            ));
        }
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .wrap_err_with(|| format!("read {} from the pack", file.file_name))?;
        let actual = hex::encode(Sha256::digest(&bytes));
        if actual != file.sha256 {
            return Err(stow_types::stow_error!(
                "{} in the pack hashes to {actual}, the config records {}",
                file.file_name,
                file.sha256
            ));
        }
        files.push(bytes);
    }
    if let Some(extra) = entries.next() {
        let extra = extra.wrap_err("read a pack entry")?;
        return Err(stow_types::stow_error!(
            "the pack holds undeclared entry {}",
            extra.path().wrap_err("read a pack entry path")?.display()
        ));
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declared(name: &str, bytes: &[u8]) -> ArtifactBundleFile {
        ArtifactBundleFile {
            file_name: name.to_owned(),
            media_type: "application/vnd.stow.rlib.v1".to_owned(),
            sha256: hex::encode(Sha256::digest(bytes)),
        }
    }

    #[test]
    fn packing_is_deterministic_and_round_trips() {
        let rlib = b"rlib bytes".repeat(1000);
        let rmeta = b"rmeta".to_vec();
        let files: [(&str, &[u8]); 2] = [("liba.rlib", &rlib), ("liba.rmeta", &rmeta)];
        let first = pack(&files).expect("pack");
        assert_eq!(first, pack(&files).expect("pack again"));

        let rlib_file = declared("liba.rlib", &rlib);
        let rmeta_file = declared("liba.rmeta", &rmeta);
        let unpacked = unpack(&first, &[&rlib_file, &rmeta_file]).expect("unpack");
        assert_eq!(unpacked, vec![rlib, rmeta]);
    }

    #[test]
    fn unpack_refuses_a_hash_a_name_and_an_extra_entry() {
        let a = b"first".to_vec();
        let b = b"second".to_vec();
        let packed = pack(&[("a.rlib", &a), ("b.rmeta", &b)]).expect("pack");

        let mut wrong_hash = declared("a.rlib", &a);
        wrong_hash.sha256 = hex::encode(Sha256::digest(b"other"));
        let b_file = declared("b.rmeta", &b);
        let error = unpack(&packed, &[&wrong_hash, &b_file]).unwrap_err();
        assert!(error.to_string().contains("hashes to"), "{error}");

        let a_file = declared("a.rlib", &a);
        let renamed = declared("c.rmeta", &b);
        let error = unpack(&packed, &[&a_file, &renamed]).unwrap_err();
        assert!(
            error.to_string().contains("where c.rmeta is declared"),
            "{error}"
        );

        let error = unpack(&packed, &[&a_file]).unwrap_err();
        assert!(
            error.to_string().contains("undeclared entry b.rmeta"),
            "{error}"
        );

        let c_file = declared("c.rmeta", b"x");
        let error = unpack(&packed, &[&a_file, &b_file, &c_file]).unwrap_err();
        assert!(error.to_string().contains("lacks c.rmeta"), "{error}");
    }

    #[test]
    fn compress_round_trips_and_pins_the_window() {
        let bytes = b"stow ".repeat(100_000);
        let compressed = compress(&bytes).expect("compress");
        assert!(compressed.len() < bytes.len() / 50);
        assert_eq!(decompress(&compressed).expect("decompress"), bytes);
    }

    #[test]
    fn an_input_past_one_job_round_trips() {
        let bytes: Vec<u8> = (0..(STOW_ZSTD_JOB_SIZE as usize + (1 << 20)))
            .map(|i| (i % 251) as u8 ^ (i / 4099) as u8)
            .collect();
        let compressed = compress(&bytes).expect("compress");
        assert_eq!(decompress(&compressed).expect("decompress"), bytes);
    }
}
