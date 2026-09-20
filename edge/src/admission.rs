//! Stateless enqueue-admission primitives: HMAC challenge issue/verify and
//! queue-depth-scaled proof-of-work difficulty.
//!
//! A public cache miss cannot enqueue a build directly — the fetch path
//! returns an [`stow_types::api::EnqueueAdmission`] carrying the canonical
//! [`stow_types::api::EnqueueRequest`], this module's challenge, and a
//! difficulty; `POST /api/v1/enqueue` redeems it by forwarding the carried
//! request to the scheduler. Nothing is persisted per challenge: the HMAC
//! covers `task_id ‖ canonical request JSON ‖ issue_minute` and is
//! recomputed on verify, so tickets expire on their own about two minutes
//! after issue and a forged or tampered request cannot verify.
//!
//! Everything here is platform-free so the whole protocol is unit-testable
//! on the host; the wasm handlers feed it wall-clock minutes from
//! `js_sys::Date` and the canonical JSON from `serde_json::to_vec`.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use stow_types::pow::MAX_POW_DIFFICULTY;

/// Default for `STOW_POW_DEPTH_PER_BIT` — pending tasks per extra
/// leading-zero bit of required proof-of-work.
pub const DEFAULT_POW_DEPTH_PER_BIT: u32 = 50;

/// Default for `STOW_POW_MIN_BITS` — the floor every minted admission and
/// every redeemed ticket is held to, so an enqueue is never free even on
/// an empty queue.
pub const DEFAULT_POW_MIN_BITS: u32 = 12;

type ChallengeMac = Hmac<Sha256>;

/// Issue the hex-encoded HMAC-SHA256 challenge binding `task_id` and
/// `request_json` (the canonical `serde_json::to_vec` of the carried
/// [`stow_types::api::EnqueueRequest`]) as of `issue_minute` (unix time /
/// 60).
pub fn issue_challenge(
    secret: &str,
    task_id: &str,
    request_json: &[u8],
    issue_minute: u64,
) -> String {
    hex::encode(
        challenge_mac(secret, task_id, request_json, issue_minute)
            .finalize()
            .into_bytes(),
    )
}

/// `challenge` is valid when it matches the edge-issued value for
/// `(task_id, request_json)` at the current minute or the one before it —
/// the skew window covers solve latency and nothing more.
#[must_use]
pub fn verify_challenge(
    secret: &str,
    task_id: &str,
    request_json: &[u8],
    challenge: &str,
    now_minute: u64,
) -> bool {
    let Ok(bytes) = hex::decode(challenge) else {
        return false;
    };
    challenge_mac(secret, task_id, request_json, now_minute)
        .verify_slice(&bytes)
        .is_ok()
        || challenge_mac(secret, task_id, request_json, now_minute.saturating_sub(1))
            .verify_slice(&bytes)
            .is_ok()
}

fn challenge_mac(
    secret: &str,
    task_id: &str,
    request_json: &[u8],
    issue_minute: u64,
) -> ChallengeMac {
    let mut mac =
        ChallengeMac::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(task_id.as_bytes());
    mac.update(request_json);
    mac.update(&issue_minute.to_be_bytes());
    mac
}

/// The depth-scaled component of the difficulty: one extra leading-zero
/// bit per `depth_per_bit` pending tasks, capped at
/// [`stow_types::pow::MAX_POW_DIFFICULTY`]. `depth_per_bit == 0` disables
/// the scaling — the `min_bits` floor still applies on top of it.
fn depth_scaled_bits(pending: u32, depth_per_bit: u32) -> u32 {
    if depth_per_bit == 0 {
        return 0;
    }
    (pending / depth_per_bit).min(MAX_POW_DIFFICULTY)
}

/// Required leading-zero bits minted into admissions for a queue `pending`
/// tasks deep: `max(min_bits, depth-scaled bits)`, capped at
/// [`stow_types::pow::MAX_POW_DIFFICULTY`].
#[must_use]
pub fn difficulty_for_depth(pending: u32, depth_per_bit: u32, min_bits: u32) -> u32 {
    depth_scaled_bits(pending, depth_per_bit).max(min_bits.min(MAX_POW_DIFFICULTY))
}

/// Difficulty `/enqueue` enforces: the depth-scaled component drops one
/// bit to tolerate queue growth between the miss response and redemption,
/// while `min_bits` stays a true floor — a redeemed ticket can never pass
/// with fewer bits than the floor.
#[must_use]
pub fn required_difficulty(pending: u32, depth_per_bit: u32, min_bits: u32) -> u32 {
    depth_scaled_bits(pending, depth_per_bit)
        .saturating_sub(1)
        .max(min_bits.min(MAX_POW_DIFFICULTY))
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_POW_DEPTH_PER_BIT, DEFAULT_POW_MIN_BITS, difficulty_for_depth, issue_challenge,
        required_difficulty, verify_challenge,
    };
    use stow_types::pow::MAX_POW_DIFFICULTY;

    const SECRET: &str = "test-secret";
    const REQUEST_JSON: &[u8] = b"{\"crate_name\":\"serde\"}";

    #[test]
    fn issued_challenge_verifies_for_current_and_next_minute() {
        let challenge = issue_challenge(SECRET, "task-1", REQUEST_JSON, 100);
        assert!(verify_challenge(
            SECRET,
            "task-1",
            REQUEST_JSON,
            &challenge,
            100
        ));
        assert!(verify_challenge(
            SECRET,
            "task-1",
            REQUEST_JSON,
            &challenge,
            101
        ));
        assert!(!verify_challenge(
            SECRET,
            "task-1",
            REQUEST_JSON,
            &challenge,
            102
        ));
        assert!(!verify_challenge(
            SECRET,
            "task-1",
            REQUEST_JSON,
            &challenge,
            99
        ));
    }

    #[test]
    fn forged_challenges_are_rejected() {
        let challenge = issue_challenge(SECRET, "task-1", REQUEST_JSON, 100);
        assert!(!verify_challenge(
            "other-secret",
            "task-1",
            REQUEST_JSON,
            &challenge,
            100
        ));
        assert!(!verify_challenge(
            SECRET,
            "task-2",
            REQUEST_JSON,
            &challenge,
            100
        ));
        assert!(!verify_challenge(
            SECRET,
            "task-1",
            REQUEST_JSON,
            "deadbeef",
            100
        ));
        assert!(!verify_challenge(
            SECRET,
            "task-1",
            REQUEST_JSON,
            "not-hex!!",
            100
        ));
        // Truncated MAC does not verify.
        assert!(!verify_challenge(
            SECRET,
            "task-1",
            REQUEST_JSON,
            &challenge[..16],
            100
        ));
    }

    #[test]
    fn challenge_binds_the_request_payload() {
        let challenge = issue_challenge(SECRET, "task-1", REQUEST_JSON, 100);
        // A tampered request cannot redeem the admission's challenge.
        let tampered = b"{\"crate_name\":\"rand\"}";
        assert!(!verify_challenge(
            SECRET, "task-1", tampered, &challenge, 100
        ));
    }

    #[test]
    fn difficulty_scales_with_depth() {
        // A zero floor keeps the pre-floor scaling unchanged.
        assert_eq!(difficulty_for_depth(0, DEFAULT_POW_DEPTH_PER_BIT, 0), 0);
        assert_eq!(difficulty_for_depth(49, DEFAULT_POW_DEPTH_PER_BIT, 0), 0);
        assert_eq!(difficulty_for_depth(50, DEFAULT_POW_DEPTH_PER_BIT, 0), 1);
        assert_eq!(difficulty_for_depth(500, DEFAULT_POW_DEPTH_PER_BIT, 0), 10);
        assert_eq!(
            difficulty_for_depth(u32::MAX, DEFAULT_POW_DEPTH_PER_BIT, 0),
            MAX_POW_DIFFICULTY
        );
        assert_eq!(difficulty_for_depth(10_000, 0, 0), 0);
    }

    #[test]
    fn difficulty_never_drops_below_the_floor() {
        assert_eq!(
            difficulty_for_depth(0, DEFAULT_POW_DEPTH_PER_BIT, DEFAULT_POW_MIN_BITS),
            DEFAULT_POW_MIN_BITS
        );
        // The floor wins while the depth-scaled component is smaller…
        assert_eq!(
            difficulty_for_depth(500, DEFAULT_POW_DEPTH_PER_BIT, DEFAULT_POW_MIN_BITS),
            DEFAULT_POW_MIN_BITS
        );
        // …and hands over once the queue is deep enough to demand more.
        assert_eq!(
            difficulty_for_depth(700, DEFAULT_POW_DEPTH_PER_BIT, DEFAULT_POW_MIN_BITS),
            14
        );
        // Disabling the scaling still leaves the floor: enqueue is never free.
        assert_eq!(difficulty_for_depth(10_000, 0, DEFAULT_POW_MIN_BITS), 12);
        // A floor above the protocol ceiling clamps to the ceiling.
        assert_eq!(difficulty_for_depth(0, DEFAULT_POW_DEPTH_PER_BIT, 100), 24);
    }

    #[test]
    fn required_difficulty_tolerates_queue_growth() {
        // Without a floor the one-bit leniency is unchanged.
        assert_eq!(required_difficulty(50, DEFAULT_POW_DEPTH_PER_BIT, 0), 0);
        assert_eq!(required_difficulty(500, DEFAULT_POW_DEPTH_PER_BIT, 0), 9);
        assert_eq!(required_difficulty(0, DEFAULT_POW_DEPTH_PER_BIT, 0), 0);
        // The floor is a true floor: leniency never dips below it.
        assert_eq!(
            required_difficulty(0, DEFAULT_POW_DEPTH_PER_BIT, DEFAULT_POW_MIN_BITS),
            DEFAULT_POW_MIN_BITS
        );
        assert_eq!(
            required_difficulty(50, DEFAULT_POW_DEPTH_PER_BIT, DEFAULT_POW_MIN_BITS),
            DEFAULT_POW_MIN_BITS
        );
        // Once the queue is deep, leniency applies to the scaled component.
        assert_eq!(
            required_difficulty(700, DEFAULT_POW_DEPTH_PER_BIT, DEFAULT_POW_MIN_BITS),
            13
        );
        assert_eq!(required_difficulty(10_000, 0, DEFAULT_POW_MIN_BITS), 12);
    }
}
