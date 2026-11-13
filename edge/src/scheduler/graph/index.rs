//! The graph's lookup structures: an open-addressing index of `u32`
//! ids and the string interner built on it. Both store ids only — the
//! caller owns the keys and hands the table a hash and an equality, so
//! a key is never held twice (stow#878).

use std::hash::{DefaultHasher, Hash, Hasher};

/// A free slot.
const EMPTY: u32 = u32::MAX;

/// The hash the interner and the identity index probe with.
pub(super) fn hash_of<T: Hash + ?Sized>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// The most slots in use, in eighths of the array.
const LOAD_EIGHTHS: usize = 7;

/// Slots below which a table never shrinks its probe room.
const MIN_SLOTS: usize = 8;

/// The slot count that holds `entries` ids at the full load.
const fn slots_for(entries: usize) -> usize {
    let slots = (entries * 8).div_ceil(LOAD_EIGHTHS);
    if slots < MIN_SLOTS { MIN_SLOTS } else { slots }
}

/// An open-addressing multimap from a hash to `u32` ids: linear
/// probing over a slot array of any length kept at most seven eighths
/// full. A hash maps to its first slot by range reduction (its low 32
/// bits scaled by the length, Lemire's fastrange), so the length is
/// exact rather than a power of two.
///
/// The table holds exactly the ids `0..n`, inserted in order, and the
/// caller can hash any of them again. That makes growth a rebuild from
/// the ids: the old array is freed before the larger one is allocated,
/// so the two are never resident together.
#[derive(Debug, Default)]
pub(super) struct IxTable {
    slots: Vec<u32>,
    used: usize,
}

impl IxTable {
    /// Clear the table and size it exactly for `entries` ids, reusing
    /// the buffer when it is large enough.
    pub(super) fn clear_for(&mut self, entries: usize) {
        let wanted = slots_for(entries);
        if wanted > self.slots.capacity() {
            self.slots = Vec::new();
        }
        self.slots.clear();
        self.slots.resize(wanted, EMPTY);
        self.used = 0;
    }

    /// The ids sharing `hash`'s probe run, in slot order. A caller
    /// keeps the ones whose key it recognises.
    pub(super) fn candidates(&self, hash: u64) -> Candidates<'_> {
        Candidates {
            slots: &self.slots,
            at: probe_start(hash, self.slots.len()),
        }
    }

    /// Insert `id` under `hash`; ids arrive in order, `0, 1, 2, ...`.
    /// `rehash` recomputes the hash of an id already held, for growth.
    pub(super) fn insert(&mut self, hash: u64, id: u32, rehash: impl Fn(u32) -> u64) {
        debug_assert_ne!(id, EMPTY, "the free-slot marker is not an id");
        debug_assert_eq!(id as usize, self.used, "ids are inserted in order");
        if (self.used + 1) * 8 > self.slots.len() * LOAD_EIGHTHS {
            // A quarter more room than the ids held now, so a stream of
            // inserts pays one rebuild per quarter of growth.
            let held = u32::try_from(self.used).expect("held ids fit u32");
            let wanted = slots_for(self.used + 1 + (self.used + 1) / 4);
            self.slots = Vec::new();
            self.slots = vec![EMPTY; wanted];
            self.used = 0;
            for held in 0..held {
                self.place(rehash(held), held);
            }
        }
        self.place(hash, id);
    }

    fn place(&mut self, hash: u64, id: u32) {
        let mut at = probe_start(hash, self.slots.len());
        while self.slots[at] != EMPTY {
            at = next_slot(at, self.slots.len());
        }
        self.slots[at] = id;
        self.used += 1;
    }

    /// Heap bytes the slot array holds.
    pub(super) const fn heap_bytes(&self) -> usize {
        self.slots.capacity() * size_of::<u32>()
    }
}

/// Where a hash's probe run starts in an array of `len` slots (`0` for
/// the empty array): the low 32 bits of the hash scaled into `0..len`.
/// Callers hash to 32 bits at most (an id key's first four bytes), and
/// ids are `u32`, so `len` stays below 2^32 and the product fits.
fn probe_start(hash: u64, len: usize) -> usize {
    let len = u64::try_from(len).expect("slot count fits u64");
    usize::try_from(((hash & u64::from(u32::MAX)) * len) >> 32)
        .expect("a reduced hash is a slot index")
}

/// The slot after `at`, wrapping at the end of the array.
const fn next_slot(at: usize, len: usize) -> usize {
    if at + 1 == len { 0 } else { at + 1 }
}

/// The ids of one probe run.
pub(super) struct Candidates<'a> {
    slots: &'a [u32],
    at: usize,
}

impl Iterator for Candidates<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        let id = *self.slots.get(self.at)?;
        if id == EMPTY {
            return None;
        }
        self.at = next_slot(self.at, self.slots.len());
        Some(id)
    }
}

/// A priority value owned by one graph's priority pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PriorityId(u32);

/// Exact source/operator priorities shared by states in the same rank class.
#[derive(Debug, Default)]
pub(super) struct Priorities {
    values: Vec<i64>,
    table: IxTable,
}

impl Priorities {
    pub(super) const fn len(&self) -> usize {
        self.values.len()
    }

    pub(super) fn at(&self, id: PriorityId) -> i64 {
        self.values[id.0 as usize]
    }

    pub(super) fn intern(&mut self, value: i64) -> PriorityId {
        let hash = hash_of(&value);
        if let Some(id) = self
            .table
            .candidates(hash)
            .find(|&id| self.values[id as usize] == value)
        {
            return PriorityId(id);
        }
        let id =
            u32::try_from(self.values.len()).expect("priority pool holds fewer than 2^32 values");
        self.values.push(value);
        let Self { values, table } = self;
        table.insert(hash, id, |held| hash_of(&values[held as usize]));
        PriorityId(id)
    }

    pub(super) const fn heap_bytes(&self) -> usize {
        self.values.capacity() * size_of::<i64>() + self.table.heap_bytes()
    }
}

/// String interner: every repeated string (crate names, versions,
/// feature lists) is stored once, back to back in one buffer, and
/// referred to by a `u32` everywhere else.
#[derive(Debug, Default)]
pub(super) struct Interner {
    text: String,
    /// End offset of string `id` in `text`; its start is the previous
    /// entry's end.
    ends: Vec<u32>,
    table: IxTable,
}

impl Interner {
    pub(super) const fn len(&self) -> usize {
        self.ends.len()
    }

    pub(super) fn at(&self, id: u32) -> &str {
        slice(&self.text, &self.ends, id)
    }

    pub(super) fn get(&self, value: &str) -> Option<u32> {
        self.table
            .candidates(hash_of(value))
            .find(|&id| self.at(id) == value)
    }

    pub(super) fn intern(&mut self, value: &str) -> u32 {
        if let Some(id) = self.get(value) {
            return id;
        }
        let id = self.push(value);
        let Self { text, ends, table } = self;
        table.insert(hash_of(value), id, |held| hash_of(slice(text, ends, held)));
        id
    }

    fn push(&mut self, value: &str) -> u32 {
        let id = u32::try_from(self.ends.len()).expect("interner holds fewer than 2^32 strings");
        self.text.push_str(value);
        self.ends
            .push(u32::try_from(self.text.len()).expect("interned text fits 4 GiB"));
        id
    }

    /// The strings from `from` on, in id order.
    pub(super) fn iter_from(&self, from: usize) -> impl Iterator<Item = &str> {
        (from..self.ends.len()).map(|id| self.at(u32::try_from(id).expect("interner ids fit u32")))
    }

    /// Load path: append a string without indexing it; [`Self::index`]
    /// builds the table once every string is in.
    pub(super) fn load(&mut self, value: &str) {
        self.push(value);
    }

    /// Size the offset array for `strings` strings.
    pub(super) fn reserve_exact(&mut self, strings: usize) {
        self.ends.reserve_exact(strings);
    }

    /// Build the lookup table over the loaded strings.
    pub(super) fn index(&mut self) {
        self.table.clear_for(self.ends.len());
        let Self { text, ends, table } = self;
        for id in 0..ends.len() {
            let id = u32::try_from(id).expect("interner ids fit u32");
            table.insert(hash_of(slice(text, ends, id)), id, |held| {
                hash_of(slice(text, ends, held))
            });
        }
    }

    /// Heap bytes held: text, offsets and table.
    pub(super) const fn heap_bytes(&self) -> usize {
        self.text.capacity() + self.ends.capacity() * size_of::<u32>() + self.table.heap_bytes()
    }
}

fn slice<'a>(text: &'a str, ends: &[u32], id: u32) -> &'a str {
    let end = ends[id as usize] as usize;
    let start = id
        .checked_sub(1)
        .map_or(0, |prev| ends[prev as usize] as usize);
    &text[start..end]
}

#[cfg(test)]
mod tests {
    use super::{Interner, IxTable, Priorities};

    #[test]
    fn priority_indexes_survive_growth_and_reuse_exact_values() {
        let mut pool = Priorities::default();
        let values = [i64::MIN, i64::MAX, -1, 0, 1];
        let ids: Vec<_> = values.iter().map(|&value| pool.intern(value)).collect();
        for value in 2..1024 {
            pool.intern(value);
        }
        let count = pool.values.len();
        for (&value, &id) in values.iter().zip(&ids) {
            assert_eq!(pool.intern(value), id);
            assert_eq!(pool.at(id), value);
        }
        assert_eq!(pool.values.len(), count);
    }

    #[test]
    fn repeated_index_rebuilds_discard_old_ids_and_preserve_collisions() {
        let mut table = IxTable::default();
        for count in [0u32, 128, 7, 7, 256, 0, 19] {
            let previous = table.slots.as_ptr();
            let capacity = table.slots.capacity();
            table.clear_for(count as usize);
            if table.slots.len() <= capacity {
                assert_eq!(table.slots.as_ptr(), previous);
            }
            // Many identities share each probe hash; rebuilding must both
            // retain every collision and remove the preceding population.
            let hash = |id: u32| u64::from(id % 3);
            for id in 0..count {
                table.insert(hash(id), id, hash);
            }
            for key in 0..3 {
                let mut actual: Vec<_> = table
                    .candidates(key)
                    .filter(|&id| hash(id) == key)
                    .collect();
                actual.sort_unstable();
                let expected: Vec<_> = (0..count).filter(|&id| hash(id) == key).collect();
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn tables_are_sized_exactly_and_grow_by_rebuilding_from_the_ids() {
        let hash = |id: u32| super::hash_of(&id);
        let mut table = IxTable::default();
        table.clear_for(1_000);
        assert_eq!(table.slots.len(), 1_143, "one slot per 7/8 of an entry");
        assert_eq!(table.heap_bytes(), 1_143 * 4);
        let start = table.slots.as_ptr();
        for id in 0..1_000 {
            table.insert(hash(id), id, hash);
        }
        assert_eq!(table.slots.as_ptr(), start, "a sized table never moves");
        // Growth rebuilds from the ids with a quarter more room, and
        // every id stays reachable through its own probe run.
        for id in 1_000..5_000 {
            table.insert(hash(id), id, hash);
            assert!(table.used * 8 <= table.slots.len() * 7);
        }
        assert!(!table.slots.len().is_power_of_two());
        assert_eq!(
            table.heap_bytes(),
            table.slots.len() * 4,
            "no spare capacity"
        );
        for id in 0..5_000 {
            assert!(table.candidates(hash(id)).any(|held| held == id), "id {id}");
        }
    }

    #[test]
    fn interner_reindex_preserves_loaded_and_new_strings() {
        let mut intern = Interner::default();
        for value in ["serde", "1.0.229", "derive", "std"] {
            intern.load(value);
        }
        for value in ["alloc", "serde", "derive"] {
            intern.index();
            intern.intern(value);
            for (id, held) in intern.iter_from(0).enumerate() {
                assert_eq!(intern.get(held), Some(u32::try_from(id).unwrap()));
            }
        }
    }
}
