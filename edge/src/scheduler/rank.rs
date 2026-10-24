//! The scheduler's exact dispatch rank — the one Rust abstraction
//! every node's claim order derives from (stow#524, stow#878).
//!
//! A node's raw value is the precedence bands over the nonnegative
//! priority plus accumulated demand (`bands × VALUE_BAND +
//! MAX(0, priority) + MAX(0, demand)`, human contributing two bands and
//! Windows one — stow#522). The claim order is the exact rational
//! `value / expected_cost` behind a lane precedence (human first under
//! any cost), compared by [`Rank`].

use std::cmp::Ordering;
use std::num::NonZero;

use stow_types::api::RunnerFamily;

/// The cost a `(crate_name, target)` pair carries while no sample has
/// ever priced it — `1`, so an unmeasured build ranks on its raw
/// value alone.
pub const UNMEASURED_COST: NonZero<i64> = NonZero::new(1).unwrap();

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

/// One node's claim rank: its lane and the exact ratio of its raw
/// value to its expected build cost. Ascending order is claim order —
/// the human lane first, then the larger ratio first.
///
/// Exactness, not approximation: ratios compare by cross-multiplying in
/// `u128` (`v1·c2` against `v2·c1`). Both operands are inside the
/// nonnegative `i64` range, so each product is below `2^126`: it cannot
/// overflow, and distinct ratios never compare equal. Equal ratios
/// compare equal and fall through to the caller's FIFO fields.
#[derive(Debug, Clone, Copy)]
pub struct Rank {
    human: bool,
    value: u64,
    cost: NonZero<i64>,
}

impl Rank {
    /// The rank of a node with raw `value` (nonnegative, see
    /// [`raw_value`]) and expected build `cost` in milliseconds.
    pub fn new(human: bool, value: i64, cost: NonZero<i64>) -> Self {
        debug_assert!(
            value >= 0,
            "raw value bands over clamped priority and demand"
        );
        Self {
            human,
            value: value.cast_unsigned(),
            cost,
        }
    }
}

impl Ord for Rank {
    fn cmp(&self, other: &Self) -> Ordering {
        other.human.cmp(&self.human).then_with(|| {
            // self before other when self.value/self.cost is larger:
            // other.value·self.cost compared against self.value·other.cost.
            let mine = u128::from(self.value) * u128::from(other.cost.get().cast_unsigned());
            let theirs = u128::from(other.value) * u128::from(self.cost.get().cast_unsigned());
            theirs.cmp(&mine)
        })
    }
}

impl PartialOrd for Rank {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Rank {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Rank {}

#[cfg(test)]
mod tests {
    use super::*;

    fn rank_key(human: bool, value: i64, cost: NonZero<i64>) -> Rank {
        Rank::new(human, value, cost)
    }

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
                let ranked = rank_key(false, v1, cost1).cmp(&rank_key(false, v2, cost2));
                assert_eq!(
                    ranked,
                    exact.reverse(),
                    "rank order != exact rational order for {v1}/{c1} vs {v2}/{c2}"
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
            rank_key(false, near, NonZero::new(1_048_576).unwrap()),
            rank_key(false, near + 1, NonZero::new(1_048_576).unwrap())
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

    /// Equal ratios compare equal — the order falls through to the
    /// caller's FIFO fields.
    #[test]
    fn equal_fractions_share_the_prefix() {
        assert_eq!(
            rank_key(false, 2, NonZero::new(6).unwrap()),
            rank_key(
                false,
                1_000_000_000_000_000,
                NonZero::new(3_000_000_000_000_000).unwrap()
            ),
        );
        assert_eq!(
            rank_key(false, 0, UNMEASURED_COST),
            rank_key(false, 0, NonZero::new(i64::MAX).unwrap()),
        );
    }

    /// The human lane sorts before every miss-lane key at any cost
    /// ratio — lane precedence is a literal prefix, not a band the
    /// ratio can cross.
    #[test]
    fn human_lane_prefix_sorts_first() {
        assert!(
            rank_key(true, 1, NonZero::new(i64::MAX).unwrap())
                < rank_key(false, i64::MAX, UNMEASURED_COST)
        );
        assert!(
            rank_key(true, 0, UNMEASURED_COST) < rank_key(false, 0, UNMEASURED_COST),
            "the lane prefix decides before the ratio"
        );
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
                        rank_key(
                            lane == "human",
                            raw_value(lane, family, priority, 0),
                            UNMEASURED_COST,
                        ),
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
