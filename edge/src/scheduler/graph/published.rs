//! The published unit-shape masks, which live in storage and never in
//! the graph's memory beyond the changes since the last snapshot.
//!
//! The `published` table (`store.rs`) maps `(slice, key)` to the mask of
//! unit shapes the index serves for that task id, ordered by slice then
//! key. It advances only inside a snapshot's storage turn, so it always
//! equals the state at the snapshot watermark. The graph keeps the
//! changes since then in an [`Overlay`] and rebuilds them by replaying
//! the log tail; a read consults the overlay before the table.
//!
//! The graph never awaits. A caller asks it what a coming operation will
//! read ([`PublishedNeeds`]), reads exactly that from the table, and
//! hands the answer in as a [`PublishedSource`]; the same needs function
//! and the same apply function serve the live path and the replay, so
//! both make the same decisions from the same inputs.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Bound;

use super::digests::DigestSource;
use super::{IdKey, SliceId};
use crate::errors::QueueError;

/// One row of the `published` table: the slice, the task id's key and
/// the mask of unit shapes it serves.
pub type PublishedRow = (SliceId, IdKey, u8);

/// The `slice` column of a slice: its persisted target and rustc ids,
/// target first.
#[must_use]
pub fn slice_column(slice: SliceId) -> i64 {
    i64::from(slice.0) << 8 | i64::from(slice.1)
}

/// The published masks changed since the last snapshot, by key: the
/// slice that reported the key and its current mask, where mask 0 means
/// the key was retired. Cleared once a snapshot has written them to the
/// table.
#[derive(Debug, Default)]
pub(super) struct Overlay {
    changes: BTreeMap<IdKey, (SliceId, u8)>,
}

impl Overlay {
    /// The mask the changes since the snapshot gave `key`, if any.
    pub(super) fn get(&self, key: &IdKey) -> Option<u8> {
        self.changes.get(key).map(|&(_, mask)| mask)
    }

    pub(super) fn set(&mut self, slice: SliceId, key: IdKey, mask: u8) {
        self.changes.insert(key, (slice, mask));
    }

    /// The changed keys of `slice` and their masks.
    pub(super) fn members(&self, slice: SliceId) -> impl Iterator<Item = (&IdKey, u8)> {
        self.changes
            .iter()
            .filter(move |(_, (held, _))| *held == slice)
            .map(|(key, &(_, mask))| (key, mask))
    }

    /// Up to `limit` changed rows after `after`, in key order — the
    /// snapshot writes them page by page without copying the overlay.
    pub(super) fn page(&self, after: Option<&IdKey>, limit: usize) -> Vec<PublishedRow> {
        let start = after.map_or(Bound::Unbounded, Bound::Excluded);
        self.changes
            .range::<IdKey, _>((start, Bound::Unbounded))
            .take(limit)
            .map(|(&key, &(slice, mask))| (slice, key, mask))
            .collect()
    }

    pub(super) fn clear(&mut self) {
        self.changes = BTreeMap::new();
    }

    pub(super) fn len(&self) -> usize {
        self.changes.len()
    }

    /// Every changed row, in key order.
    #[cfg(test)]
    pub(super) fn rows(&self) -> impl Iterator<Item = PublishedRow> {
        self.changes
            .iter()
            .map(|(&key, &(slice, mask))| (slice, key, mask))
    }

    /// The entries' own size, excluding the tree's node overhead.
    pub(super) fn heap_bytes(&self) -> usize {
        self.changes.len() * size_of::<(IdKey, (SliceId, u8))>()
    }
}

/// What a coming graph operation reads from the table: the keys it
/// looks up and the slices it lists in full.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PublishedNeeds {
    /// Each key with the slice it would be filed under, `None` when the
    /// graph has never held that slice's target or rustc — a slice that
    /// was never reported holds no rows.
    keys: BTreeMap<IdKey, Option<SliceId>>,
    slices: BTreeSet<SliceId>,
}

impl PublishedNeeds {
    /// Ask for the mask of `key`.
    pub(super) fn want_key(&mut self, key: IdKey, slice: Option<SliceId>) {
        let held = self.keys.entry(key).or_insert(slice);
        if held.is_none() {
            *held = slice;
        }
    }

    /// Ask for every row of `slice`.
    pub(super) fn want_slice(&mut self, slice: SliceId) {
        self.slices.insert(slice);
    }

    /// The keys asked for, with their slices, ascending.
    pub fn keys(&self) -> impl Iterator<Item = (IdKey, Option<SliceId>)> {
        self.keys.iter().map(|(&key, &slice)| (key, slice))
    }

    /// The slices asked for in full, ascending.
    pub fn slices(&self) -> impl Iterator<Item = SliceId> {
        self.slices.iter().copied()
    }
}

/// Where the graph reads a published mask from when the changes since
/// the last snapshot do not hold it: the table as of the snapshot.
pub trait PublishedSource {
    /// The mask the table holds for `key`; 0 when it holds no row.
    /// `slice` names the slice `key` is filed under, for a source that
    /// only records what is asked.
    ///
    /// # Errors
    /// `QueueError::Invariant` when the source was never given the key:
    /// the caller reads every key the graph will ask for before it
    /// applies, so a missing one is a defect, never a zero.
    fn mask(
        &mut self,
        key: &IdKey,
        slice: impl FnOnce() -> Option<SliceId>,
    ) -> Result<u8, QueueError>;

    /// Every row the table holds under `slice`.
    ///
    /// # Errors
    /// `QueueError::Invariant` when the source was never given the slice.
    fn members(&mut self, slice: SliceId) -> Result<Vec<(IdKey, u8)>, QueueError>;
}

/// A source of everything a read-only graph pass consults in storage: the
/// dependency digests it mints task ids from and the published masks it
/// checks.
pub trait ReadSource: DigestSource + PublishedSource {}

impl<T: DigestSource + PublishedSource> ReadSource for T {}

/// A needs set doubles as the recorder of a read-only pass: it records
/// what is asked and answers zero, so a second pass over the real rows
/// reads exactly what the first named.
impl PublishedSource for PublishedNeeds {
    fn mask(
        &mut self,
        key: &IdKey,
        slice: impl FnOnce() -> Option<SliceId>,
    ) -> Result<u8, QueueError> {
        self.want_key(*key, slice());
        Ok(0)
    }

    fn members(&mut self, slice: SliceId) -> Result<Vec<(IdKey, u8)>, QueueError> {
        self.want_slice(slice);
        Ok(Vec::new())
    }
}

/// Table rows read for a set of [`PublishedNeeds`]. A key the table has
/// no row for is held as mask 0; a key never asked for is absent, and
/// asking for it is a defect.
#[derive(Debug, Default)]
pub struct Fetched {
    masks: HashMap<IdKey, u8>,
    members: HashMap<SliceId, Vec<(IdKey, u8)>>,
}

impl Fetched {
    /// Record that `key` was asked for and the table holds no row for it
    /// unless [`Self::set_mask`] says otherwise.
    pub fn expect(&mut self, key: IdKey) {
        self.masks.entry(key).or_insert(0);
    }

    /// Record the row the table holds for `key`.
    pub fn set_mask(&mut self, key: IdKey, mask: u8) {
        self.masks.insert(key, mask);
    }

    /// Record every row the table holds under `slice`.
    pub fn set_members(&mut self, slice: SliceId, rows: Vec<(IdKey, u8)>) {
        self.members.insert(slice, rows);
    }
}

impl PublishedSource for Fetched {
    fn mask(&mut self, key: &IdKey, _: impl FnOnce() -> Option<SliceId>) -> Result<u8, QueueError> {
        self.masks.get(key).copied().ok_or_else(|| {
            QueueError::Invariant(format!(
                "no published row was read for key {}",
                hex::encode(key)
            ))
        })
    }

    fn members(&mut self, slice: SliceId) -> Result<Vec<(IdKey, u8)>, QueueError> {
        self.members.remove(&slice).ok_or_else(|| {
            QueueError::Invariant(format!(
                "the rows of slice {slice:?} were not read, or were read twice"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> IdKey {
        let mut key = [0; 16];
        key[0] = n;
        key
    }

    #[test]
    fn the_overlay_answers_by_key_pages_in_key_order_and_lists_a_slice() {
        let mut overlay = Overlay::default();
        for n in [5u8, 1, 9, 3] {
            overlay.set((u8::from(n > 4), 0), key(n), n);
        }
        overlay.set((0, 0), key(5), 0);
        assert_eq!(overlay.get(&key(5)), Some(0), "a retired key reads zero");
        assert_eq!(overlay.get(&key(2)), None);
        let first = overlay.page(None, 2);
        assert_eq!(first.iter().map(|row| row.1[0]).collect::<Vec<_>>(), [1, 3]);
        let rest = overlay.page(first.last().map(|row| &row.1), 10);
        assert_eq!(rest.iter().map(|row| row.1[0]).collect::<Vec<_>>(), [5, 9]);
        let mut slice_one: Vec<_> = overlay.members((1, 0)).map(|(key, _)| key[0]).collect();
        slice_one.sort_unstable();
        assert_eq!(slice_one, [9]);
        overlay.clear();
        assert_eq!(overlay.len(), 0);
    }

    #[test]
    fn a_key_never_fetched_is_a_defect_and_an_absent_row_is_zero() {
        let mut fetched = Fetched::default();
        assert!(matches!(
            fetched.mask(&key(1), || None),
            Err(QueueError::Invariant(_))
        ));
        fetched.expect(key(1));
        assert_eq!(fetched.mask(&key(1), || None).expect("expected"), 0);
        fetched.set_mask(key(2), 3);
        assert_eq!(fetched.mask(&key(2), || None).expect("read"), 3);
        assert!(matches!(
            fetched.members((0, 0)),
            Err(QueueError::Invariant(_))
        ));
    }

    #[test]
    fn needs_dedupe_keys_and_prefer_a_known_slice() {
        let mut needs = PublishedNeeds::default();
        needs.want_key(key(1), None);
        needs.want_key(key(1), Some((2, 3)));
        needs.want_key(key(1), None);
        needs.want_slice((4, 5));
        needs.want_slice((4, 5));
        assert_eq!(needs.keys().collect::<Vec<_>>(), [(key(1), Some((2, 3)))]);
        assert_eq!(needs.slices().collect::<Vec<_>>(), [(4, 5)]);
    }
}
