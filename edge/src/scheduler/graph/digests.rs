//! The dependency digests task ids spell, which live in storage and
//! never in the graph's memory.
//!
//! A node's task id is minted from its interned fields and the 32-byte
//! digest of its resolved dependency subgraph. No scheduling decision
//! reads the digest, so the `node_digests` table holds it by state slot,
//! [`DIGEST_BLOCK_SLOTS`] slots to a row (`store.rs`). A caller that
//! needs a task id reads the rows its slots fall in and hands the graph
//! a [`DigestSource`]; the graph itself never awaits.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

use crate::errors::QueueError;

/// The dependency digest of one node: the 32 bytes its task id spells as
/// 64 hex digits.
pub type Digest = [u8; 32];

/// Digest slots one `node_digests` row holds.
pub const DIGEST_BLOCK_SLOTS: u32 = 256;

/// A fresh node's digest, by the state slot the merge gave it.
pub type FreshDigest = (u32, Digest);

/// Where the graph reads a dependency digest from while it mints a
/// task id.
pub trait DigestSource: Send + Sync {
    /// The digest stored for state slot `slot`.
    ///
    /// # Errors
    /// `QueueError::Invariant` when the source holds none: every live
    /// state slot has a row, so a missing one is a corrupt store.
    fn digest(&self, slot: u32) -> Result<Digest, QueueError>;
}

/// Digests read from the `node_digests` rows, by state slot.
#[derive(Debug, Default, Clone)]
pub struct Digests(HashMap<u32, Digest>);

impl Digests {
    pub(crate) fn insert(&mut self, slot: u32, digest: Digest) {
        self.0.insert(slot, digest);
    }
}

impl FromIterator<FreshDigest> for Digests {
    fn from_iter<T: IntoIterator<Item = FreshDigest>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl DigestSource for Digests {
    fn digest(&self, slot: u32) -> Result<Digest, QueueError> {
        self.0.get(&slot).copied().ok_or_else(|| {
            QueueError::Invariant(format!("no digest row was read for state slot {slot}"))
        })
    }
}

/// A source that records the slots asked of it and answers with zeros: a
/// read-only graph pass run against it names exactly the rows a second
/// pass, run against the real [`Digests`], will mint from.
#[derive(Debug, Default)]
pub struct Wanted(Mutex<BTreeSet<u32>>);

impl Wanted {
    /// The recorded slots, ascending.
    pub fn slots(&self) -> Vec<u32> {
        self.0
            .lock()
            .expect("wanted digest slots")
            .iter()
            .copied()
            .collect()
    }
}

impl DigestSource for Wanted {
    fn digest(&self, slot: u32) -> Result<Digest, QueueError> {
        self.0.lock().expect("wanted digest slots").insert(slot);
        Ok([0; 32])
    }
}
