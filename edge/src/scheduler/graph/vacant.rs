//! The vacant slots of the state slab, one bit each.
//!
//! A wave that publishes vacates nearly every slot of the slab, so the
//! set costs a bit per slot rather than the four bytes a heap of slot
//! numbers does. The lowest vacant slot is always the one taken next:
//! the `node_digests` rows are keyed by state slot, and a graph rebuilt
//! from a snapshot and the log tail must allocate the slots the live one
//! did.

use fixedbitset::{Block, FixedBitSet};

const BLOCK_BITS: usize = Block::BITS as usize;

/// The set of vacant slots of a slab.
#[derive(Debug, Default)]
pub struct VacantSlots {
    /// A set bit is a vacant slot; slots past its end are not vacant.
    bits: FixedBitSet,
    /// How many bits are set.
    len: usize,
    /// No slot below this one is vacant, so a take scans from here.
    floor: usize,
}

impl VacantSlots {
    /// The vacant slots of a slab of `held.len()` slots, `held` being
    /// the occupied ones.
    pub fn from_held(mut held: FixedBitSet) -> Self {
        held.toggle_range(..);
        Self {
            len: held.count_ones(..),
            floor: held.minimum().unwrap_or(0),
            bits: held,
        }
    }

    /// Mark `slot` vacant.
    ///
    /// # Panics
    /// When `slot` is already vacant: a slot is released once.
    pub fn release(&mut self, slot: u32) {
        let slot = slot as usize;
        self.bits.grow(slot + 1);
        assert!(!self.bits.put(slot), "state slot {slot} released twice");
        self.len += 1;
        self.floor = self.floor.min(slot);
    }

    /// Occupy and return the lowest vacant slot, if any.
    pub fn take_lowest(&mut self) -> Option<u32> {
        if self.len == 0 {
            return None;
        }
        let blocks = self.bits.as_slice();
        let first = self.floor / BLOCK_BITS;
        let (at, block) = blocks
            .iter()
            .enumerate()
            .skip(first)
            .find(|&(_, &block)| block != 0)
            .expect("a nonzero vacant count has a set block at or above the floor");
        let slot = at * BLOCK_BITS + block.trailing_zeros() as usize;
        self.bits.remove(slot);
        self.len -= 1;
        self.floor = slot;
        Some(u32::try_from(slot).expect("state slots fit u32"))
    }

    /// How many slots are vacant.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Heap bytes the set holds.
    pub fn heap_bytes(&self) -> usize {
        size_of_val(self.bits.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// A fixed pseudo-random sequence, so a failure replays.
    fn next(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state >> 33
    }

    #[test]
    fn takes_the_minimum_vacant_slot_across_interleaved_releases() {
        const SLAB: u32 = 700;
        let mut rng = 7u64;
        let mut vacant = VacantSlots::default();
        let mut model = BTreeSet::new();
        let mut held: BTreeSet<u32> = (0..SLAB).collect();
        for step in 0..20_000 {
            let release = next(&mut rng).is_multiple_of(2);
            if release && !held.is_empty() {
                let at = usize::try_from(next(&mut rng)).unwrap() % held.len();
                let slot = *held.iter().nth(at).unwrap();
                held.remove(&slot);
                model.insert(slot);
                vacant.release(slot);
            } else {
                let expected = model.pop_first();
                assert_eq!(vacant.take_lowest(), expected, "step {step}");
                held.extend(expected);
            }
            assert_eq!(vacant.len(), model.len(), "step {step}");
        }
    }

    #[test]
    fn a_set_rebuilt_from_the_held_slots_behaves_as_the_live_one() {
        const SLAB: usize = 300;
        let mut rng = 11u64;
        let mut live = VacantSlots::default();
        let mut held = FixedBitSet::with_capacity(SLAB);
        for slot in 0..SLAB {
            if next(&mut rng).is_multiple_of(3) {
                live.release(u32::try_from(slot).unwrap());
            } else {
                held.insert(slot);
            }
        }
        let mut rebuilt = VacantSlots::from_held(held);
        assert_eq!(rebuilt.len(), live.len());
        for step in 0..200 {
            if next(&mut rng).is_multiple_of(2) {
                let slot = u32::try_from(next(&mut rng) % SLAB as u64).unwrap();
                if !live.bits.contains(slot as usize) {
                    live.release(slot);
                    rebuilt.release(slot);
                }
            } else {
                assert_eq!(rebuilt.take_lowest(), live.take_lowest(), "step {step}");
            }
            assert_eq!(rebuilt.len(), live.len(), "step {step}");
        }
        while let Some(slot) = live.take_lowest() {
            assert_eq!(rebuilt.take_lowest(), Some(slot));
        }
        assert_eq!(rebuilt.take_lowest(), None);
    }
}
