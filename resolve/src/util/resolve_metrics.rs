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
/// Version lines seen across all fetched index files.
pub static INDEX_VERSION_LINES: AtomicU64 = AtomicU64::new(0);
/// Query-matched version lines (occurrences — a name queried twice
/// counts twice).
pub static INDEX_LINES_MATCHED: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// Distinct (name, version) pairs any query matched and parsed.
    static INDEX_MATCHED_PAIRS: std::cell::RefCell<std::collections::BTreeSet<(String, String)>> =
        std::cell::RefCell::new(std::collections::BTreeSet::new());
}

pub fn index_fetched(bytes: u64) {
    INDEX_FETCHES.fetch_add(1, Ordering::Relaxed);
    INDEX_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

pub fn download_finished(compressed: u64) {
    DOWNLOADS_DONE.fetch_add(1, Ordering::Relaxed);
    DOWNLOAD_BYTES.fetch_add(compressed, Ordering::Relaxed);
}

/// `count` more version lines entered a name's `Summaries`.
pub fn index_versions_loaded(count: u64) {
    INDEX_VERSION_LINES.fetch_add(count, Ordering::Relaxed);
}

/// A query matched `name` at `version` — the line a lazy parse would
/// materialize.
pub fn index_line_matched(name: &str, version: &str) {
    INDEX_LINES_MATCHED.fetch_add(1, Ordering::Relaxed);
    INDEX_MATCHED_PAIRS.with(|s| {
        s.borrow_mut()
            .insert((name.to_string(), version.to_string()));
    });
}

/// Distinct (name, version) pairs matched so far.
pub fn matched_pairs_count() -> u64 {
    INDEX_MATCHED_PAIRS.with(|s| s.borrow().len() as u64)
}

/// (index fetches, index bytes, downloads done, download bytes,
/// version lines, matched occurrences, matched distinct pairs).
pub fn snapshot() -> (u64, u64, u64, u64, u64, u64, u64) {
    (
        INDEX_FETCHES.load(Ordering::Relaxed),
        INDEX_BYTES.load(Ordering::Relaxed),
        DOWNLOADS_DONE.load(Ordering::Relaxed),
        DOWNLOAD_BYTES.load(Ordering::Relaxed),
        INDEX_VERSION_LINES.load(Ordering::Relaxed),
        INDEX_LINES_MATCHED.load(Ordering::Relaxed),
        matched_pairs_count(),
    )
}

pub fn reset() {
    for c in [
        &INDEX_FETCHES,
        &INDEX_BYTES,
        &DOWNLOADS_DONE,
        &DOWNLOAD_BYTES,
        &INDEX_VERSION_LINES,
        &INDEX_LINES_MATCHED,
    ] {
        c.store(0, Ordering::Relaxed);
    }
    INDEX_MATCHED_PAIRS.with(|s| s.borrow_mut().clear());
}
