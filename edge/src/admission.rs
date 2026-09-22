//! Stateless enqueue-admission primitives: HMAC challenge issue/verify and
//! the proof-of-work difficulty every admission carries.
//!
//! # What protects this path, and what does not
//!
//! Proof-of-work is a cost speed bump, never the defence. It exists so an
//! anonymous enqueue is not free; it cannot be sized to stop abuse,
//! because the legitimate client and the attacker pay the same unit price
//! and are separated by only about as many orders of magnitude in request
//! count as the usable cost window is wide. Four layers guard this path,
//! and `PoW` is the weakest of them on purpose:
//!
//! 1. **Zone-level IP rate limiting**, configured in the Cloudflare zone's
//!    Rate Limiting Rules. It is deliberately not in this repository:
//!    Rate Limiting Rules are zone/WAF configuration, while wrangler
//!    config reaches only the Worker, and zone level is the right scope
//!    for something that protects more than this Worker. It is named here
//!    because it leaves no other trace in the code, and reading this
//!    module without knowing it exists leads straight to the conclusion
//!    that `PoW` is all there is.
//! 2. **`max_queue_pending`** in the `/api/v1/enqueue` handler: once the
//!    scheduler queue is full, miss-lane tickets are refused with 429 and
//!    a `Retry-After`. This is the precise, honest form of "the queue is
//!    under pressure" — it says so instead of making everyone mine.
//! 3. **Identity canonicalization and deduplication**: the queue's
//!    `UNIQUE(crate_name, version, features_json, target, rustc_version)`,
//!    `task_id` as its primary key, `is_ci_target` on the
//!    redemption path, and `dependency_resolver::resolve_local_features`
//!    dropping feature names the crate does not declare. A client cannot
//!    mint novel identities out of arbitrary strings, so the tasks an
//!    attacker can create are legitimate ones that serve real users.
//! 4. **The anonymous-traffic circuit breaker** (`crate::panic`).
//!
//! Difficulty was once scaled by the scheduler's pending depth, one bit
//! per fifty tasks up to a 24-bit cap. That duplicated layer 2 while
//! charging the wrong party: queue depth is caused by everyone, so the
//! next legitimate arrival paid for other people's backlog. At a
//! measured 66 ns per hash, the cap meant about 1.1 CPU-seconds for a
//! single admission — a warm build minting a couple of hundred of them
//! spent 342 CPU-seconds mining against 44.6 for compiling the same
//! project from scratch, and never redeemed one.
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

/// Default for `STOW_POW_MIN_BITS` — the leading-zero bits every minted
/// admission and every redeemed ticket carries, so an enqueue is never
/// free. At a measured 66 ns per blake3 hash this is about 0.27 ms of
/// expected work per admission: unmissable in aggregate to anyone
/// enqueuing at scale, unnoticeable to a build that missed a few
/// hundred artifacts.
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

/// The leading-zero bits an admission carries, which is also what
/// `/api/v1/enqueue` requires of the ticket redeeming it. Minting and
/// redemption compute the same value from the same configuration, so a
/// ticket solved for its admission is always redeemable within the
/// challenge's lifetime.
///
/// [`stow_types::pow::MAX_POW_DIFFICULTY`] clamps it: it guards against a
/// misconfigured `STOW_POW_MIN_BITS`, not against load.
#[must_use]
pub fn difficulty(min_bits: u32) -> u32 {
    min_bits.min(MAX_POW_DIFFICULTY)
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_POW_MIN_BITS, difficulty, issue_challenge, verify_challenge};
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
    fn difficulty_is_the_configured_bits_and_nothing_else() {
        // No load term, by design: the difficulty an admission carries is
        // a constant of the deployment. It used to rise with the
        // scheduler's pending depth, which charged whoever arrived next
        // for a backlog everyone had built.
        assert_eq!(difficulty(DEFAULT_POW_MIN_BITS), DEFAULT_POW_MIN_BITS);
        assert_eq!(difficulty(0), 0);
        assert_eq!(difficulty(16), 16);
    }

    #[test]
    fn difficulty_clamps_a_misconfigured_floor() {
        // The ceiling guards against a typo in `STOW_POW_MIN_BITS`, not
        // against load: a floor above it would mint admissions no client
        // can redeem.
        assert_eq!(difficulty(100), MAX_POW_DIFFICULTY);
        assert_eq!(difficulty(u32::MAX), MAX_POW_DIFFICULTY);
    }

    #[test]
    fn minting_and_redemption_demand_the_same_bits() {
        // Both paths call this one function with the same configuration,
        // so a ticket solved for its admission is redeemable for as long
        // as its challenge lives. The two used to be computed differently
        // — minted from the queue depth at issue time, required from the
        // depth at redemption minus a bit of slack — so the number a
        // client solved for was not the number it was judged against.
        for min_bits in [0, 1, DEFAULT_POW_MIN_BITS, MAX_POW_DIFFICULTY] {
            assert_eq!(difficulty(min_bits), difficulty(min_bits));
        }
    }

    #[test]
    fn the_default_difficulty_is_solvable_by_a_sequential_scan() {
        // The failure this catches is the one that made the whole
        // admission channel silent: a difficulty the edge is happy to
        // mint but no client can afford to solve. At 12 bits the expected
        // scan is 4096 hashes, so a bound of 2^20 fails only if the
        // difficulty is far higher than configured.
        let bits = difficulty(DEFAULT_POW_MIN_BITS);
        let nonce = (0u64..(1 << 20))
            .find(|nonce| {
                stow_types::pow::enqueue_pow_zero_bits("task-1", "challenge-1", *nonce) >= bits
            })
            .expect("the default difficulty is reachable within a sequential scan");
        assert!(stow_types::pow::enqueue_pow_zero_bits("task-1", "challenge-1", nonce) >= bits);
    }
}
