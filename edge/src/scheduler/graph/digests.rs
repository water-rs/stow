//! The dependency digests task ids spell, which live in storage and
//! never in the graph's memory.
//!
//! A node's task id is minted from its interned fields and the 32-byte
//! digest of its resolved dependency subgraph. No scheduling decision
//! reads the digest, so the `node_digests` table holds it, one row per
//! state slot (`store.rs`). A caller that needs a task id reads the rows
//! of exactly the slots it mints from and hands the graph a
//! [`DigestSource`]; the graph itself never awaits.

use std::collections::{BTreeSet, HashMap};

use super::published::{Fetched, PublishedNeeds, PublishedSource};
use super::{IdKey, SliceId};
use crate::errors::QueueError;

/// The dependency digest of one node: the 32 bytes its task id spells as
/// 64 hex digits.
pub type Digest = [u8; 32];

/// A fresh node's digest, by the state slot the merge gave it.
pub type FreshDigest = (u32, Digest);

/// Where the graph reads a dependency digest from while it mints a
/// task id.
pub trait DigestSource {
    /// The digest stored for state slot `slot`.
    ///
    /// # Errors
    /// `QueueError::Invariant` when the source holds none: every live
    /// state slot has a row, so a missing one is a corrupt store.
    fn digest(&mut self, slot: u32) -> Result<Digest, QueueError>;
}

/// Digests read from the `node_digests` rows, by state slot.
#[derive(Debug, Default, Clone)]
pub struct Digests(HashMap<u32, Digest>);

impl Digests {
    pub(crate) fn insert(&mut self, slot: u32, digest: Digest) {
        self.0.insert(slot, digest);
    }

    /// Whether a row was read for `slot`.
    pub(crate) fn holds(&self, slot: u32) -> bool {
        self.0.contains_key(&slot)
    }

    /// The digest read for `slot`, if any.
    #[cfg(test)]
    pub(crate) fn digest_for_test(&self, slot: u32) -> Option<Digest> {
        self.0.get(&slot).copied()
    }
}

impl FromIterator<FreshDigest> for Digests {
    fn from_iter<T: IntoIterator<Item = FreshDigest>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl DigestSource for Digests {
    fn digest(&mut self, slot: u32) -> Result<Digest, QueueError> {
        self.0.get(&slot).copied().ok_or_else(|| {
            QueueError::Invariant(format!("no digest row was read for state slot {slot}"))
        })
    }
}

/// A source that records the rows asked of it and answers with zeros: a
/// read-only graph pass run against it names exactly the digest rows
/// and published rows a second pass, run against the real [`Reads`],
/// consults.
#[derive(Debug, Default)]
pub struct Wanted {
    slots: BTreeSet<u32>,
    published: PublishedNeeds,
}

impl Wanted {
    /// The recorded state slots, ascending.
    pub fn slots(&self) -> Vec<u32> {
        self.slots.iter().copied().collect()
    }

    /// The published rows the pass looked up.
    pub const fn published(&self) -> &PublishedNeeds {
        &self.published
    }
}

impl DigestSource for Wanted {
    fn digest(&mut self, slot: u32) -> Result<Digest, QueueError> {
        self.slots.insert(slot);
        Ok([0; 32])
    }
}

impl PublishedSource for Wanted {
    fn mask(
        &mut self,
        key: &IdKey,
        slice: impl FnOnce() -> Option<SliceId>,
    ) -> Result<u8, QueueError> {
        self.published.mask(key, slice)
    }

    fn members(&mut self, slice: SliceId) -> Result<Vec<(IdKey, u8)>, QueueError> {
        self.published.members(slice)
    }
}

/// The rows a read-only graph pass consults, read from storage: the
/// dependency digests and the published masks.
#[derive(Debug, Default)]
pub struct Reads {
    /// The `node_digests` rows.
    pub digests: Digests,
    /// The `published` rows.
    pub published: Fetched,
}

impl DigestSource for Reads {
    fn digest(&mut self, slot: u32) -> Result<Digest, QueueError> {
        self.digests.digest(slot)
    }
}

impl PublishedSource for Reads {
    fn mask(
        &mut self,
        key: &IdKey,
        slice: impl FnOnce() -> Option<SliceId>,
    ) -> Result<u8, QueueError> {
        self.published.mask(key, slice)
    }

    fn members(&mut self, slice: SliceId) -> Result<Vec<(IdKey, u8)>, QueueError> {
        self.published.members(slice)
    }
}
