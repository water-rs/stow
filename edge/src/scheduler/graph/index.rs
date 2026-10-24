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

/// An open-addressing multimap from a hash to `u32` ids: linear
/// probing over a power-of-two slot array kept under 70% full. It
/// never deletes — a stale id is skipped by its caller and a rebuild
/// drops it — so a probe ends at the first free slot.
#[derive(Debug, Default)]
pub(super) struct IxTable {
    slots: Vec<u32>,
    used: usize,
}

impl IxTable {
    /// A table sized so `entries` ids insert without growing.
    pub(super) fn with_entries(entries: usize) -> Self {
        let wanted = (entries * 10 / 7 + 1).next_power_of_two().max(16);
        Self {
            slots: vec![EMPTY; wanted],
            used: 0,
        }
    }

    /// The ids sharing `hash`'s probe run, in slot order. A caller
    /// keeps the ones whose key it recognises.
    pub(super) fn candidates(&self, hash: u64) -> Candidates<'_> {
        Candidates {
            slots: &self.slots,
            at: probe_start(hash, self.slots.len()),
        }
    }

    /// Insert `id` under `hash`; `rehash` recomputes the hash of an id
    /// already held, for the doubling.
    pub(super) fn insert(&mut self, hash: u64, id: u32, rehash: impl Fn(u32) -> u64) {
        debug_assert_ne!(id, EMPTY, "the free-slot marker is not an id");
        if (self.used + 1) * 10 > self.slots.len() * 7 {
            let grown = (self.slots.len() * 2).max(16);
            let old = std::mem::replace(&mut self.slots, vec![EMPTY; grown]);
            self.used = 0;
            for held in old.into_iter().filter(|&held| held != EMPTY) {
                self.place(rehash(held), held);
            }
        }
        self.place(hash, id);
    }

    fn place(&mut self, hash: u64, id: u32) {
        let mask = self.slots.len() - 1;
        let mut at = probe_start(hash, self.slots.len());
        while self.slots[at] != EMPTY {
            at = (at + 1) & mask;
        }
        self.slots[at] = id;
        self.used += 1;
    }

    /// Heap bytes the slot array holds.
    #[cfg(test)]
    pub(super) const fn heap_bytes(&self) -> usize {
        self.slots.len() * size_of::<u32>()
    }
}

/// Where a hash's probe run starts in a power-of-two array of `len`
/// slots (`0` for the empty array).
fn probe_start(hash: u64, len: usize) -> usize {
    let mask = u64::try_from(len.saturating_sub(1)).expect("slot count fits u64");
    usize::try_from(hash & mask).expect("a masked hash is a slot index")
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
        self.at = (self.at + 1) & (self.slots.len() - 1);
        Some(id)
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
        self.table = IxTable::with_entries(self.ends.len());
        let Self { text, ends, table } = self;
        for id in 0..ends.len() {
            let id = u32::try_from(id).expect("interner ids fit u32");
            table.insert(hash_of(slice(text, ends, id)), id, |held| {
                hash_of(slice(text, ends, held))
            });
        }
    }

    /// Heap bytes held: text, offsets and table.
    #[cfg(test)]
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
