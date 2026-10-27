//! Dependency edges as flat `u32` arrays (stow#878): the forward
//! edges of every node sit contiguous in the node's own span, and the
//! reverse index — dependents of a node, for the publish flip and the
//! failure block — is a CSR (offsets plus owners) rebuilt in one
//! counting sort, with the edges added since the last rebuild kept in
//! a small ordered overlay. The overlay merges into the CSR once it
//! outgrows an eighth of it, so a stream of small submissions costs
//! amortised constant work per edge.

use std::collections::BTreeSet;

use crate::errors::QueueError;

/// Bit of an edge's byte that records the edge is met.
const MET: u8 = 1 << 7;

/// Overlay entries below which the CSR is never rebuilt.
const REBUILD_FLOOR: usize = 8_192;

/// The edge arrays: forward spans plus the reverse index.
#[derive(Debug, Default)]
pub(super) struct Edges {
    /// Dep node of each edge.
    dep: Vec<u32>,
    /// The 4-bit mask of unit shapes the edge requires, with
    /// [`MET`] set once the dep's published shapes cover it.
    flags: Vec<u8>,
    /// `offsets[d]..offsets[d + 1]` is dep `d`'s span of `owners`;
    /// nodes past the end have no CSR entries.
    offsets: Vec<u32>,
    /// Owners of the edges onto each dep, grouped by dep.
    owners: Vec<u32>,
    /// `(dep, owner)` of every edge pushed since the last rebuild.
    overlay: BTreeSet<(u32, u32)>,
}

impl Edges {
    pub(super) const fn len(&self) -> usize {
        self.dep.len()
    }

    /// Size the forward arrays for `edges` edges.
    pub(super) fn reserve_exact(&mut self, edges: usize) {
        self.dep.reserve_exact(edges);
        self.flags.reserve_exact(edges);
    }

    /// Append one edge, `owner` onto `dep`; returns its index.
    ///
    /// # Errors
    /// `QueueError::Invariant` when the edge count overflows `u32`.
    pub(super) fn push(
        &mut self,
        owner: u32,
        dep: u32,
        required: u8,
        met: bool,
    ) -> Result<u32, QueueError> {
        let at = u32::try_from(self.dep.len())
            .map_err(|_| QueueError::Invariant("edge count overflows u32".into()))?;
        self.dep.push(dep);
        self.flags.push(required | if met { MET } else { 0 });
        self.overlay.insert((dep, owner));
        Ok(at)
    }

    /// Append an edge from a snapshot row; the reverse index is
    /// rebuilt after the load.
    pub(super) fn load(&mut self, dep: u32, flags: u8) {
        self.dep.push(dep);
        self.flags.push(flags);
    }

    pub(super) fn dep(&self, edge: usize) -> u32 {
        self.dep[edge]
    }

    pub(super) fn required(&self, edge: usize) -> u8 {
        self.flags[edge] & !MET
    }

    pub(super) fn met(&self, edge: usize) -> bool {
        self.flags[edge] & MET != 0
    }

    pub(super) fn set_met(&mut self, edge: usize, met: bool) {
        if met {
            self.flags[edge] |= MET;
        } else {
            self.flags[edge] &= !MET;
        }
    }

    /// The raw flag byte of an edge, for the snapshot.
    pub(super) fn raw_flags(&self, edge: usize) -> u8 {
        self.flags[edge]
    }

    /// The nodes holding an edge onto `dep`, once per edge. A node
    /// that has since been freed still appears until the next rebuild.
    pub(super) fn owners_of(&self, dep: u32) -> Vec<u32> {
        let d = dep as usize;
        let base = match (self.offsets.get(d), self.offsets.get(d + 1)) {
            (Some(&from), Some(&to)) => &self.owners[from as usize..to as usize],
            _ => &[],
        };
        base.iter()
            .copied()
            .chain(
                self.overlay
                    .range((dep, 0)..=(dep, u32::MAX))
                    .map(|&(_, owner)| owner),
            )
            .collect()
    }

    /// Whether the overlay has outgrown its share and the reverse
    /// index should be rebuilt.
    pub(super) fn reverse_stale(&self) -> bool {
        self.overlay.len() >= REBUILD_FLOOR && self.overlay.len() * 8 >= self.owners.len()
    }

    /// Rebuild the reverse index from the forward spans of the live
    /// nodes: `spans` yields `(owner, start, len)`; `nodes` bounds the
    /// dep ids.
    pub(super) fn rebuild_reverse(
        &mut self,
        nodes: usize,
        spans: impl Iterator<Item = (u32, usize, usize)> + Clone,
    ) {
        let mut offsets = vec![0u32; nodes + 1];
        for (_, start, len) in spans.clone() {
            for &dep in &self.dep[start..start + len] {
                offsets[dep as usize + 1] += 1;
            }
        }
        for at in 1..offsets.len() {
            offsets[at] += offsets[at - 1];
        }
        let mut cursor = offsets.clone();
        let mut owners = vec![0u32; offsets[nodes] as usize];
        for (owner, start, len) in spans {
            for &dep in &self.dep[start..start + len] {
                let slot = &mut cursor[dep as usize];
                owners[*slot as usize] = owner;
                *slot += 1;
            }
        }
        self.offsets = offsets;
        self.owners = owners;
        self.overlay.clear();
    }

    /// Drop the forward edges outside the kept spans, in place: each
    /// `(from, len)` span moves down to the running end, in ascending
    /// `from` order, and every dep id is rewritten through `remap`.
    /// The reverse index is invalid afterwards — rebuild it.
    pub(super) fn compact(&mut self, spans: impl Iterator<Item = (usize, usize)>, remap: &[u32]) {
        let mut end = 0;
        for (from, len) in spans {
            assert!(from >= end, "edge spans are ascending and disjoint");
            self.dep.copy_within(from..from + len, end);
            self.flags.copy_within(from..from + len, end);
            end += len;
        }
        self.dep.truncate(end);
        self.flags.truncate(end);
        for dep in &mut self.dep {
            *dep = remap[*dep as usize];
        }
        self.dep.shrink_to_fit();
        self.flags.shrink_to_fit();
        self.offsets = Vec::new();
        self.owners = Vec::new();
        self.overlay.clear();
    }

    /// Heap bytes the arrays hold.
    #[cfg(test)]
    pub(super) fn heap_bytes(&self) -> usize {
        self.dep.capacity() * size_of::<u32>()
            + self.flags.capacity()
            + self.offsets.capacity() * size_of::<u32>()
            + self.owners.capacity() * size_of::<u32>()
            + self.overlay.len() * 2 * size_of::<(u32, u32)>()
    }
}
