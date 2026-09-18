//! Shared proof-of-work metric for the enqueue admission flow.
//!
//! Both sides compute the identical digest — the CLI while searching for a
//! nonce and the edge while verifying a ticket — so the function lives here
//! next to the wire types it authenticates.

/// Hard ceiling on the leading-zero-bit requirement an admission may carry.
///
/// The edge never mints a difficulty above this (queue depth is capped), and
/// the CLI refuses to solve anything above it — a larger advertised value
/// would mean unbounded work for a challenge that expires anyway.
pub const MAX_POW_DIFFICULTY: u32 = 24;

/// Count of leading zero bits in `blake3(task_id ‖ challenge ‖ nonce)`.
///
/// `challenge` is the opaque server-issued string from
/// [`crate::api::EnqueueAdmission`]; `nonce` is hashed as its little-endian
/// byte representation so the metric is identical on every platform.
#[must_use]
pub fn enqueue_pow_zero_bits(task_id: &str, challenge: &str, nonce: u64) -> u32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(task_id.as_bytes());
    hasher.update(challenge.as_bytes());
    hasher.update(&nonce.to_le_bytes());
    let digest = hasher.finalize();
    let mut bits = 0;
    for byte in digest.as_bytes() {
        bits += byte.leading_zeros();
        if *byte != 0 {
            break;
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::enqueue_pow_zero_bits;

    #[test]
    fn zero_bits_matches_digest_prefix() {
        let digest = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"task");
            hasher.update(b"challenge");
            hasher.update(&0u64.to_le_bytes());
            *hasher.finalize().as_bytes()
        };
        let expected = digest[0].leading_zeros();
        assert_eq!(enqueue_pow_zero_bits("task", "challenge", 0), expected);
    }

    #[test]
    fn solver_finds_nonce_at_moderate_difficulty() {
        // Difficulty 8 is the order of magnitude a loaded queue demands;
        // a sequential scan must find a nonce quickly.
        let nonce = (0u64..(1 << 24))
            .find(|nonce| enqueue_pow_zero_bits("t", "c", *nonce) >= 8)
            .expect("a nonce always exists for difficulty 8");
        assert!(enqueue_pow_zero_bits("t", "c", nonce) >= 8);
        assert!(nonce < (1 << 16));
    }
}
