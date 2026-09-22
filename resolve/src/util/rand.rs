//! Minimal PRNG used by `network::retry` for jitter.
//!
//! `rand::rng()` needs OS entropy (and `getrandom` is not available on
//! wasm32-unknown-unknown without a JS shim), so this is a seeded xorshift64*
//! with the same `random_range` shape the vendored retry code uses. Jitter
//! only needs to decorrelate concurrent callers — the seed mixes the
//! invocation instant and process id.

use std::ops::Range;
use std::time::{SystemTime, UNIX_EPOCH};

/// xorshift64* generator.
pub struct Rng {
    state: u64,
}

/// A process-wide RNG seeded at first use.
pub fn rng() -> Rng {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u64> = Cell::new(seed());
    }
    fn seed() -> u64 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9e3779b97f4a7c15);
        // SplitMix64 finalize — decorrelates identical nanos across processes.
        let mut z = nanos
            .wrapping_add(std::process::id() as u64)
            .wrapping_add(0x9e3779b97f4a7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        let z = z ^ (z >> 31);
        z | 1
    }
    Rng { state: STATE.get() }
}

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545f4914f6cdd1d)
    }

    /// Uniform in `range` (mirrors `rand::Rng::random_range`).
    pub fn random_range(&mut self, range: Range<u64>) -> u64 {
        let span = range.end - range.start;
        if span == 0 {
            return range.start;
        }
        range.start + self.next_u64() % span
    }
}
