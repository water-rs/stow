//! Stateless enqueue-admission primitives: HMAC challenge issue/verify and
//! queue-depth-scaled proof-of-work difficulty.
//!
//! A public cache miss cannot enqueue a build directly — the fetch path
//! returns an [`stow_types::api::EnqueueAdmission`] carrying this module's
//! challenge and difficulty, and `POST /api/v1/enqueue` redeems it. Nothing
//! is persisted per challenge: the HMAC covers `task_id ‖ issue_minute` and
//! is recomputed on verify, so tickets expire on their own about two
//! minutes after issue.
//!
//! Everything here is platform-free so the whole protocol is unit-testable
//! on the host; the wasm handlers feed it wall-clock minutes from
//! `js_sys::Date`.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Hard cap on required leading-zero bits so queue depth cannot push a
/// solve beyond what an honest client computes in seconds.
pub const MAX_POW_DIFFICULTY: u32 = 24;

/// Default for `STOW_POW_DEPTH_PER_BIT` — pending tasks per extra
/// leading-zero bit of required proof-of-work.
pub const DEFAULT_POW_DEPTH_PER_BIT: u32 = 50;

type ChallengeMac = Hmac<Sha256>;

/// Issue the hex-encoded HMAC-SHA256 challenge for `task_id` as of
/// `issue_minute` (unix time / 60).
pub fn issue_challenge(secret: &str, task_id: &str, issue_minute: u64) -> String {
    hex::encode(
        challenge_mac(secret, task_id, issue_minute)
            .finalize()
            .into_bytes(),
    )
}

/// `challenge` is valid when it matches the edge-issued value for the
/// current minute or the one before it — the skew window covers solve
/// latency and nothing more.
#[must_use]
pub fn verify_challenge(secret: &str, task_id: &str, challenge: &str, now_minute: u64) -> bool {
    let Ok(bytes) = hex::decode(challenge) else {
        return false;
    };
    challenge_mac(secret, task_id, now_minute)
        .verify_slice(&bytes)
        .is_ok()
        || challenge_mac(secret, task_id, now_minute.saturating_sub(1))
            .verify_slice(&bytes)
            .is_ok()
}

fn challenge_mac(secret: &str, task_id: &str, issue_minute: u64) -> ChallengeMac {
    let mut mac =
        ChallengeMac::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(task_id.as_bytes());
    mac.update(&issue_minute.to_be_bytes());
    mac
}

/// Required leading-zero bits for a queue `pending` tasks deep: one extra
/// bit per `depth_per_bit` pending tasks, capped at [`MAX_POW_DIFFICULTY`].
/// `depth_per_bit == 0` disables proof-of-work entirely.
#[must_use]
pub fn difficulty_for_depth(pending: u32, depth_per_bit: u32) -> u32 {
    if depth_per_bit == 0 {
        return 0;
    }
    (pending / depth_per_bit).min(MAX_POW_DIFFICULTY)
}

/// Difficulty `/enqueue` enforces: one bit below the current depth-derived
/// value, tolerating queue growth between the miss response and redemption.
#[must_use]
pub fn required_difficulty(pending: u32, depth_per_bit: u32) -> u32 {
    difficulty_for_depth(pending, depth_per_bit).saturating_sub(1)
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_POW_DEPTH_PER_BIT, MAX_POW_DIFFICULTY, difficulty_for_depth, issue_challenge,
        required_difficulty, verify_challenge,
    };

    const SECRET: &str = "test-secret";

    #[test]
    fn issued_challenge_verifies_for_current_and_previous_minute() {
        let challenge = issue_challenge(SECRET, "task-1", 100);
        assert!(verify_challenge(SECRET, "task-1", &challenge, 100));
        assert!(verify_challenge(SECRET, "task-1", &challenge, 101));
        assert!(!verify_challenge(SECRET, "task-1", &challenge, 102));
        assert!(!verify_challenge(SECRET, "task-1", &challenge, 99));
    }

    #[test]
    fn forged_challenges_are_rejected() {
        let challenge = issue_challenge(SECRET, "task-1", 100);
        assert!(!verify_challenge("other-secret", "task-1", &challenge, 100));
        assert!(!verify_challenge(SECRET, "task-2", &challenge, 100));
        assert!(!verify_challenge(SECRET, "task-1", "deadbeef", 100));
        assert!(!verify_challenge(SECRET, "task-1", "not-hex!!", 100));
        // Truncated MAC does not verify.
        assert!(!verify_challenge(SECRET, "task-1", &challenge[..16], 100));
    }

    #[test]
    fn difficulty_scales_with_depth() {
        assert_eq!(difficulty_for_depth(0, DEFAULT_POW_DEPTH_PER_BIT), 0);
        assert_eq!(difficulty_for_depth(49, DEFAULT_POW_DEPTH_PER_BIT), 0);
        assert_eq!(difficulty_for_depth(50, DEFAULT_POW_DEPTH_PER_BIT), 1);
        assert_eq!(difficulty_for_depth(500, DEFAULT_POW_DEPTH_PER_BIT), 10);
        assert_eq!(
            difficulty_for_depth(u32::MAX, DEFAULT_POW_DEPTH_PER_BIT),
            MAX_POW_DIFFICULTY
        );
        assert_eq!(difficulty_for_depth(10_000, 0), 0);
    }

    #[test]
    fn required_difficulty_tolerates_queue_growth() {
        assert_eq!(required_difficulty(50, DEFAULT_POW_DEPTH_PER_BIT), 0);
        assert_eq!(required_difficulty(500, DEFAULT_POW_DEPTH_PER_BIT), 9);
        assert_eq!(required_difficulty(0, DEFAULT_POW_DEPTH_PER_BIT), 0);
    }
}
