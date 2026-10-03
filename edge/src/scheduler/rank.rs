//! The scheduler's exact dispatch rank — the one Rust abstraction
//! every `value`/`dispatch_key` writer derives from (stow#524,
//! coordinator value-stack contract).
//!
//! `queue.value` stays the persisted I6 integer: precedence bands
//! over the nonnegative priority plus accumulated demand
//! (`bands × VALUE_BAND + MAX(0, priority) + MAX(0, demand)`, human
//! contributing two bands and Windows one — stow#522). `dispatch_key`
//! orders on the exact rational `value / expected_cost`: the leading
//! field is a lane prefix (`0` human / `1` other — human sorts first
//! under any cost) followed by the fixed-width lowercase hex of
//! `U256::MAX - q`, so ascending text order is descending ratio, then
//! the FIFO tuple `first_requested_at | created_at | task_id`.

use std::num::NonZero;

use crypto_bigint::{NonZero as UintNonZero, U256};
use stow_types::api::RunnerFamily;

use crate::errors::QueueError;

/// The cost a `(crate_name, target)` pair carries while no sample has
/// ever priced it — `1`, so an unmeasured build ranks on its raw
/// value alone. A row's stored median only enters the rank through
/// [`checked_cost`]; a present stat that fails that check is
/// corruption, never silently this constant.
pub const UNMEASURED_COST: NonZero<i64> = NonZero::new(1).unwrap();

/// The positive cost the rank requires, decoded from a stored
/// `median_ms` text: a present stat that is not a positive integer is
/// corruption — fail loudly instead of clamping it toward 1.
pub fn checked_cost(median_ms: &str) -> Result<NonZero<i64>, QueueError> {
    let parsed = median_ms
        .parse::<i64>()
        .map_err(|_| QueueError::Invariant(format!("median_ms {median_ms:?} is not an integer")))?;
    NonZero::new(parsed)
        .filter(|cost| cost.get() > 0)
        .ok_or_else(|| QueueError::Invariant(format!("median_ms {median_ms:?} is not positive")))
}

/// `q = floor((v << 128) / c)` for a nonnegative `i64`-range raw value
/// `v` and a positive `i64`-range cost `c`, computed in U256.
///
/// Exactness, not approximation: two distinct ratios `v1/c1 != v2/c2`
/// differ by at least `1/(c1·c2)`, and `c1·c2 < 2^126` inside the
/// `i64` range, so the gap exceeds `2^-126`. Scaling by `2^128` makes
/// every distinct pair more than `4` apart, so `floor` can never merge
/// them — the quotient preserves the full rational order at every
/// supported magnitude, with no REAL, clamp, ceiling or tie horizon.
/// The numerator is at most `2^191`, safely inside `U256`; equal
/// ratios still yield equal `q` and fall through to the key's FIFO
/// fields. `cost` is `>= 1` by contract, so `NonZero::new` cannot
/// fail.
fn rank_quotient(value: u64, cost: NonZero<i64>) -> U256 {
    let numerator = U256::from_u64(value).shl_vartime(128);
    let divisor =
        UintNonZero::new(U256::from_u64(cost.get().cast_unsigned())).expect("positive cost");
    let (quotient, _remainder) = numerator.div_rem(&divisor);
    quotient
}

/// `queue.value` for one row — the persisted band/priority integer a
/// writer stores alongside the key (stow#442 I6): precedence bands
/// over `MAX(0, priority) + demand`, the raw-value contract every
/// writer shares (stow#522). `family` is the row's `dispatch_family`
/// label; `priority` and `demand` clamp at zero, matching the SQL
/// `MAX(0, …)` operands this replaces (the demand ledger keeps
/// `priority + demand <= PRIORITY_MAX`, so demand can never cross a
/// band). `VALUE_BAND` is wide enough that the largest value
/// (`4 × PRIORITY_MAX + 3`) cannot overflow `i64`.
pub fn raw_value(lane: &str, family: &str, priority: i64, demand: i64) -> i64 {
    let bands = i64::from(lane == "human") * 2 + i64::from(family == "windows");
    bands * super::queue::VALUE_BAND + priority.max(0) + demand.max(0)
}

/// The `dispatch_family` label for a `target` column value — the Rust
/// half of `dispatch_family_sql`'s CASE, for writers that derive the
/// family off-row (the operator backfill, tests).
pub fn dispatch_family(target: &str) -> &'static str {
    for family in RunnerFamily::ALL {
        if family.targets().contains(&target) {
            return match family {
                RunnerFamily::MacOs => "macos",
                RunnerFamily::Windows => "windows",
                RunnerFamily::Linux => "linux",
            };
        }
    }
    "linux"
}

/// The leading score field of a `dispatch_key`: the lane prefix plus
/// the fixed-64-digit lowercase hex of `U256::MAX - q`. Inverting the
/// quotient makes the text sort the numeric `DESC` — ascending key,
/// descending exact ratio — and the fixed width keeps the comparison
/// byte-stable at every magnitude. `U256`'s `LowerHex` pads each of
/// its four `u64` limbs to 16 digits, so the field is always exactly
/// 64 hex characters.
pub fn rank_prefix(lane: &str, value: i64, cost_ms: NonZero<i64>) -> String {
    debug_assert!(
        value >= 0,
        "raw value bands over clamped priority and demand"
    );
    debug_assert!(cost_ms.get() > 0, "invalid costs fail at checked_cost");
    let inverted = U256::MAX.wrapping_sub(&rank_quotient(value.cast_unsigned(), cost_ms));
    let lane_prefix = u8::from(lane != "human");
    format!("{lane_prefix}{inverted:x}")
}

/// The row operands a dispatch key derives from — one value so no
/// caller can silently drop `demand` (stow#522) or misorder the FIFO
/// fields.
pub struct KeyOperands<'a> {
    /// The row's lane — `'human'` or `'miss'`.
    pub lane: &'a str,
    /// The row's `dispatch_family` label.
    pub family: &'a str,
    /// The row's persisted baseline priority.
    pub priority: i64,
    /// The row's accumulated demand — the post-fold value on the
    /// demand path.
    pub demand: i64,
    /// The keyed expected build cost — `UNMEASURED_COST` (1) absent a
    /// stats row.
    pub cost_ms: NonZero<i64>,
    /// FIFO tie-breakers, in stored order.
    pub first_requested_at: &'a str,
    pub created_at: &'a str,
    pub task_id: &'a str,
}

/// The full `dispatch_key` text a writer binds: `[rank_prefix] |
/// first_requested_at | created_at | task_id` — exact ratio descent
/// inside each lane, then the queue's existing FIFO tie-breakers.
pub fn dispatch_key(operands: &KeyOperands<'_>) -> String {
    let prefix = rank_prefix(
        operands.lane,
        raw_value(
            operands.lane,
            operands.family,
            operands.priority,
            operands.demand,
        ),
        operands.cost_ms,
    );
    format!(
        "{prefix}|{}|{}|{}",
        operands.first_requested_at, operands.created_at, operands.task_id
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The contract's exactness check against `u128` cross-products —
    /// `v1·c2` vs `v2·c1` is the exact rational comparison (products of
    /// two `i64`-range nonnegative integers fit `u128`). The key sorts
    /// ascending on the *inverted* quotient, so the ranked order is the
    /// reverse of the exact ascending ratio order; equal ratios share
    /// the prefix and fall through to the key's FIFO fields.
    fn assert_rational_order(pairs: &[(i64, i64)]) {
        for (i, &(v1, c1)) in pairs.iter().enumerate() {
            for &(v2, c2) in &pairs[i + 1..] {
                let exact = (u128::from(v1.cast_unsigned()) * u128::from(c2.cast_unsigned()))
                    .cmp(&(u128::from(v2.cast_unsigned()) * u128::from(c1.cast_unsigned())));
                let cost1 = NonZero::new(c1).expect("positive test cost");
                let cost2 = NonZero::new(c2).expect("positive test cost");
                let ranked = rank_prefix("miss", v1, cost1).cmp(&rank_prefix("miss", v2, cost2));
                assert_eq!(
                    ranked,
                    exact.reverse(),
                    "key order != exact rational order for {v1}/{c1} vs {v2}/{c2}"
                );
            }
        }
    }

    /// Adjacent numerators above `2^53` must not merge — the removed
    /// REAL-and-clamp path collapsed `2^53` and `2^53 + 1` into one
    /// score.
    #[test]
    fn adjacent_numerators_above_f64_precision_stay_distinct() {
        let near = 9_007_199_254_740_992;
        let pairs = [(near, 1_048_576), (near + 1, 1_048_576)];
        assert_ne!(
            rank_prefix("miss", near, NonZero::new(1_048_576).unwrap()),
            rank_prefix("miss", near + 1, NonZero::new(1_048_576).unwrap())
        );
        assert_rational_order(&pairs);
    }

    /// Extreme denominators at both ends of the `i64` range, plus
    /// values across the band magnitudes a real queue carries.
    #[test]
    fn extreme_denominators_preserve_exact_order() {
        let pairs = [
            (1, i64::MAX),
            (1, i64::MAX - 1),
            (i64::MAX, 1),
            (i64::MAX, 2),
            (73_787_148_093_530_007, 3_600_000), // 3 bands + PRIORITY_MAX, an hour
            (73_787_148_093_530_007, 3_600_001),
            (18_446_787_023_382_502, 1),
            (1, 1),
        ];
        assert_rational_order(&pairs);
    }

    /// Equal ratios produce equal quotients — the key falls through
    /// to the FIFO fields byte-for-byte.
    #[test]
    fn equal_fractions_share_the_prefix() {
        assert_eq!(
            rank_prefix("miss", 2, NonZero::new(6).unwrap()),
            rank_prefix(
                "miss",
                1_000_000_000_000_000,
                NonZero::new(3_000_000_000_000_000).unwrap()
            ),
        );
        assert_eq!(
            rank_prefix("miss", 0, UNMEASURED_COST),
            rank_prefix("miss", 0, NonZero::new(i64::MAX).unwrap()),
        );
    }

    /// The human lane sorts before every miss-lane key at any cost
    /// ratio — lane precedence is a literal prefix, not a band the
    /// ratio can cross.
    #[test]
    fn human_lane_prefix_sorts_first() {
        assert!(
            rank_prefix("human", 1, NonZero::new(i64::MAX).unwrap())
                < rank_prefix("miss", i64::MAX, UNMEASURED_COST)
        );
        for key in [
            rank_prefix("human", 0, UNMEASURED_COST),
            rank_prefix("miss", 0, UNMEASURED_COST),
        ] {
            // 1-char lane prefix + 64 lowercase hex digits.
            assert_eq!(key.len(), 65);
            assert!(key[1..].chars().all(|c| c.is_ascii_hexdigit()));
            assert_eq!(key, key.to_lowercase());
        }
    }

    /// With every cost unknown (`1`), the rank reduces to raw `value`
    /// order — the accepted I6 claim order — for a mixed band set.
    #[test]
    fn unmeasured_costs_keep_i6_value_order() {
        let mut keys = Vec::new();
        for lane in ["human", "miss"] {
            for family in ["windows", "linux"] {
                for priority in [0, 5, 500_000] {
                    keys.push((
                        lane,
                        family,
                        priority,
                        rank_prefix(lane, raw_value(lane, family, priority, 0), UNMEASURED_COST),
                    ));
                }
            }
        }
        for (i, &(l1, f1, p1, ref k1)) in keys.iter().enumerate() {
            for &(l2, f2, p2, ref k2) in &keys[i + 1..] {
                let human_order = l1.cmp(l2); // 'human' < 'miss' — lane prefix dominates
                let value_order = raw_value(l1, f1, p1, 0).cmp(&raw_value(l2, f2, p2, 0));
                let expected = if l1 == l2 {
                    // Within a lane the inverted quotient descends with value.
                    value_order.reverse()
                } else {
                    human_order
                };
                assert_eq!(k1.cmp(k2), expected, "{l1}/{f1}/{p1} vs {l2}/{f2}/{p2}");
            }
        }
    }
}
