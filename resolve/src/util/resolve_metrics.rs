//! Per-request counters for the resolve's memory profile — debug builds
//! only. Isolate-wide statics; [`reset`] runs at each resolve start.

use std::sync::atomic::{AtomicU64, Ordering};

/// Index file bodies fetched (sparse protocol `LoadResponse::Data`).
pub static INDEX_FETCHES: AtomicU64 = AtomicU64::new(0);
/// Raw bytes of those index bodies.
pub static INDEX_BYTES: AtomicU64 = AtomicU64::new(0);
/// `.crate` downloads completed through `RegistryData::finish_download`.
pub static DOWNLOADS_DONE: AtomicU64 = AtomicU64::new(0);
/// Compressed bytes of those downloads.
pub static DOWNLOAD_BYTES: AtomicU64 = AtomicU64::new(0);

pub fn index_fetched(bytes: u64) {
    INDEX_FETCHES.fetch_add(1, Ordering::Relaxed);
    INDEX_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

pub fn download_finished(compressed: u64) {
    DOWNLOADS_DONE.fetch_add(1, Ordering::Relaxed);
    DOWNLOAD_BYTES.fetch_add(compressed, Ordering::Relaxed);
}

/// (index fetches, index bytes, downloads done, download bytes).
pub fn snapshot() -> (u64, u64, u64, u64) {
    (
        INDEX_FETCHES.load(Ordering::Relaxed),
        INDEX_BYTES.load(Ordering::Relaxed),
        DOWNLOADS_DONE.load(Ordering::Relaxed),
        DOWNLOAD_BYTES.load(Ordering::Relaxed),
    )
}

pub fn reset() {
    for c in [
        &INDEX_FETCHES,
        &INDEX_BYTES,
        &DOWNLOADS_DONE,
        &DOWNLOAD_BYTES,
    ] {
        c.store(0, Ordering::Relaxed);
    }
}
