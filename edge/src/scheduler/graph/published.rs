//! Published keys live once; both lookup and slice membership hold slot ids.

use std::collections::{HashMap, HashSet};

use orx_split_vec::{Collection, PinnedVec};

use super::arena::Arena;
use super::index::{IxTable, hash_of};
use super::{IdKey, Published, SliceId};

#[derive(Debug, Clone, Copy)]
struct Entry {
    key: IdKey,
    value: Published,
}

#[derive(Debug, Default)]
pub(super) struct PublishedEntries {
    entries: Arena<Entry>,
    index: IxTable,
    slices: HashMap<SliceId, HashSet<u32>>,
    free: Vec<u32>,
}

impl PublishedEntries {
    pub(super) fn len(&self) -> usize {
        self.entries.len() - self.free.len()
    }

    pub(super) fn capacity(&self) -> usize {
        self.entries.capacity()
    }

    /// Snapshot headers size the derived lookup before rows arrive.
    pub(super) fn reserve(&mut self, entries: usize) {
        assert_eq!(self.entries.len(), 0, "reserve precedes snapshot rows");
        self.index.clear_for(entries);
    }

    fn slot(&self, key: &IdKey) -> Option<u32> {
        self.index
            .candidates(hash_of(key))
            .find(|&slot| self.entries[slot as usize].key == *key)
    }

    pub(super) fn get(&self, key: &IdKey) -> Option<&Published> {
        self.slot(key)
            .map(|slot| &self.entries[slot as usize].value)
    }

    pub(super) fn insert(&mut self, key: IdKey, value: Published) {
        if let Some(slot) = self.slot(&key) {
            let held = &mut self.entries[slot as usize];
            if held.value.slice != value.slice {
                assert!(
                    self.slices
                        .get_mut(&held.value.slice)
                        .expect("slice")
                        .remove(&slot)
                );
                self.slices.entry(value.slice).or_default().insert(slot);
            }
            held.value = value;
            return;
        }
        let entry = Entry { key, value };
        let slot = if let Some(slot) = self.free.pop() {
            self.entries[slot as usize] = entry;
            slot
        } else {
            let slot = u32::try_from(self.entries.len()).expect("published slots fit u32");
            self.entries.push(entry);
            slot
        };
        let entries = &self.entries;
        self.index.insert(hash_of(&key), slot, |held| {
            hash_of(&entries[held as usize].key)
        });
        self.slices.entry(value.slice).or_default().insert(slot);
    }

    pub(super) fn remove(&mut self, key: &IdKey) {
        let Some(slot) = self.slot(key) else { return };
        let entries = &self.entries;
        self.index.remove(hash_of(key), slot, |held| {
            hash_of(&entries[held as usize].key)
        });
        let entry = &mut self.entries[slot as usize];
        assert!(
            self.slices
                .get_mut(&entry.value.slice)
                .expect("slice")
                .remove(&slot)
        );
        entry.value.mask = 0;
        self.free.push(slot);
    }

    pub(super) fn members(&self, slice: SliceId) -> impl Iterator<Item = &IdKey> {
        self.slices
            .get(&slice)
            .into_iter()
            .flatten()
            .map(|&slot| &self.entries[slot as usize].key)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (&IdKey, &Published)> {
        self.entries
            .iter()
            .filter(|entry| entry.value.mask != 0)
            .map(|entry| (&entry.key, &entry.value))
    }

    /// Element buffers, excluding hash-map control bytes and arena descriptors.
    pub(super) fn heap_bytes(&self) -> usize {
        self.entries.capacity() * size_of::<Entry>()
            + self.index.heap_bytes()
            + self.free.capacity() * size_of::<u32>()
            + self
                .slices
                .values()
                .map(|members| members.capacity() * size_of::<u32>())
                .sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_moves_deletions_and_slot_reuse_keep_both_indexes() {
        let mut entries = PublishedEntries::default();
        for n in 0u32..4097 {
            let mut key = [0; 16];
            key[..4].copy_from_slice(&n.to_le_bytes());
            entries.insert(
                key,
                Published {
                    mask: 1,
                    slice: (0, 0),
                },
            );
        }
        let allocated = entries.capacity();
        for n in 0u32..4097 {
            let mut key = [0; 16];
            key[..4].copy_from_slice(&n.to_le_bytes());
            if key[0] % 2 == 0 {
                entries.remove(&key);
            } else {
                entries.insert(
                    key,
                    Published {
                        mask: 3,
                        slice: (1, 0),
                    },
                );
            }
        }
        assert_eq!(entries.members((0, 0)).count(), 0);
        assert_eq!(entries.members((1, 0)).count(), 2048);
        for n in 0u32..4097 {
            let mut key = [0; 16];
            key[..4].copy_from_slice(&n.to_le_bytes());
            assert_eq!(
                entries.get(&key).map(|value| value.mask),
                if key[0] % 2 == 0 { None } else { Some(3) }
            );
            entries.insert(
                key,
                Published {
                    mask: 2,
                    slice: (2, 0),
                },
            );
        }
        assert_eq!(entries.len(), 4097);
        assert_eq!(entries.capacity(), allocated);
        assert_eq!(entries.members((1, 0)).count(), 0);
        assert_eq!(entries.members((2, 0)).count(), 4097);
        assert_eq!(entries.iter().count(), entries.len());
    }
}
