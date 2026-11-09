//! Dependency edges as flat `u32` arrays (stow#878): the forward
//! edges of every node occupy one indexed span, and the
//! reverse index — dependents of a node, for the publish flip and the
//! failure block — is a CSR (offsets plus owners) rebuilt in one
//! counting sort, with the edges added since the last rebuild kept in
//! a small ordered overlay. The overlay merges into the CSR once it
//! outgrows an eighth of it, so a stream of small submissions costs
//! amortised constant work per edge.

use std::collections::BTreeSet;

use orx_split_vec::{Collection, PinnedVec};

use super::arena::Arena;
use crate::errors::QueueError;

/// Bit of an edge's byte that records the edge is met.
const MET: u8 = 1 << 7;

/// Overlay entries below which the CSR is never rebuilt.
const REBUILD_FLOOR: usize = 8_192;

/// The edge arrays: forward spans plus the reverse index.
#[derive(Debug, Default)]
pub(super) struct Edges {
    /// Dep node of each edge.
    dep: Arena<u32>,
    /// The 4-bit mask of unit shapes the edge requires, with
    /// [`MET`] set once the dep's published shapes cover it.
    flags: Arena<u8>,
    /// `offsets[d]..offsets[d + 1]` is dep `d`'s span of `owners`;
    /// nodes past the end have no CSR entries.
    offsets: Arena<u32>,
    /// Owners of the edges onto each dep, grouped by dep.
    owners: Arena<u32>,
    /// `(dep, owner)` of every edge pushed since the last rebuild.
    overlay: BTreeSet<(u32, u32)>,
}

impl Edges {
    pub(super) fn len(&self) -> usize {
        self.dep.len()
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
            (Some(&from), Some(&to)) => from as usize..to as usize,
            _ => 0..0,
        };
        self.owners
            .iter_over(base)
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
        self.offsets.resize(nodes + 1, 0);
        for offset in &mut self.offsets {
            *offset = 0;
        }
        for (_, start, len) in spans.clone() {
            for &dep in self.dep.iter_over(start..start + len) {
                self.offsets[dep as usize + 1] += 1;
            }
        }
        for at in 1..self.offsets.len() {
            self.offsets[at] += self.offsets[at - 1];
        }
        self.owners.resize(self.offsets[nodes] as usize, 0);
        for (owner, start, len) in spans {
            for &dep in self.dep.iter_over(start..start + len) {
                let slot = &mut self.offsets[dep as usize];
                self.owners[*slot as usize] = owner;
                *slot += 1;
            }
        }
        // Filling advances each start to its end. The preceding end is
        // the next start, so one shift restores the CSR without a cursor copy.
        for at in (0..nodes).rev() {
            self.offsets[at + 1] = self.offsets[at];
        }
        self.offsets[0] = 0;
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
            for at in 0..len {
                self.dep[end + at] = self.dep[from + at];
                self.flags[end + at] = self.flags[from + at];
            }
            end += len;
        }
        self.dep.truncate(end);
        self.flags.truncate(end);
        for dep in &mut self.dep {
            *dep = remap[*dep as usize];
        }
        self.overlay.clear();
    }

    /// Allocated element storage, excluding fragment descriptors and the overlay.
    pub(super) fn array_bytes(&self) -> usize {
        self.dep.capacity() * size_of::<u32>()
            + self.flags.capacity()
            + self.offsets.capacity() * size_of::<u32>()
            + self.owners.capacity() * size_of::<u32>()
    }

    /// Heap bytes the arrays hold.
    #[cfg(test)]
    pub(super) fn heap_bytes(&self) -> usize {
        self.array_bytes() + self.overlay.len() * 2 * size_of::<(u32, u32)>()
    }
}

#[cfg(test)]
mod tests {
    use orx_split_vec::{Collection, PinnedVec};

    use super::Edges;

    fn assert_reverse(edges: &Edges, nodes: usize, spans: &[(u32, usize, usize)]) {
        for dep in 0..u32::try_from(nodes).expect("test nodes fit") {
            let expected: Vec<_> = spans
                .iter()
                .flat_map(|&(owner, start, len)| {
                    edges
                        .dep
                        .iter_over(start..start + len)
                        .filter(move |&&held| held == dep)
                        .map(move |_| owner)
                })
                .collect();
            assert_eq!(edges.owners_of(dep), expected, "dependency {dep}");
        }
    }

    #[test]
    fn repeated_reverse_rebuilds_preserve_forward_adjacency() {
        let mut edges = Edges::default();
        let mut spans = Vec::new();
        for (owner, deps) in [vec![1, 3, 3], vec![], vec![0, 3], vec![], vec![2], vec![]]
            .into_iter()
            .enumerate()
        {
            let start = edges.len();
            for &dep in &deps {
                edges
                    .push(u32::try_from(owner).expect("test owner"), dep, 1, false)
                    .expect("edge");
            }
            spans.push((u32::try_from(owner).expect("test owner"), start, deps.len()));
        }
        for nodes in [6, 9, 6, 6] {
            edges.rebuild_reverse(nodes, spans.iter().copied());
            assert_reverse(&edges, nodes, &spans);
        }
        let start = edges.len();
        edges.push(5, 1, 1, false).expect("new edge");
        spans[5] = (5, start, 1);
        edges.rebuild_reverse(6, spans.iter().copied());
        assert_reverse(&edges, 6, &spans);
        edges.rebuild_reverse(0, std::iter::empty());
        assert_eq!(edges.owners_of(0), [0u32; 0]);
    }

    #[test]
    fn fragmented_edges_preserve_growth_compaction_and_reload() {
        fn append(edges: &mut Edges, spans: &mut Vec<(u32, usize, usize)>, from: u32, to: u32) {
            for owner in from..to {
                let start = edges.len();
                for (dep, required) in [(owner, 1), ((owner + 1) % to, 2), (owner, 4)] {
                    edges
                        .push(owner, dep, required, owner % 2 == 0)
                        .expect("edge");
                }
                spans.push((owner, start, 3));
            }
        }

        const NODES: u32 = 1031;
        let mut edges = Edges::default();
        let mut spans = Vec::new();
        let starts = |edges: &Edges| {
            (
                &edges.dep[0] as *const u32,
                &edges.flags[0] as *const u8,
                &edges.offsets[0] as *const u32,
                &edges.owners[0] as *const u32,
            )
        };
        append(&mut edges, &mut spans, 0, 256);
        edges.rebuild_reverse(256, spans.iter().copied());
        let before = starts(&edges);
        append(&mut edges, &mut spans, 256, NODES);
        edges.rebuild_reverse(NODES as usize, spans.iter().copied());
        assert_eq!(
            starts(&edges),
            before,
            "growth retains each preceding fragment"
        );
        assert_reverse(&edges, NODES as usize, &spans);

        let remap: Vec<_> = (0..NODES).rev().collect();
        let kept: Vec<_> = spans
            .iter()
            .copied()
            .filter(|(owner, _, _)| owner % 2 == 0)
            .collect();
        let expected: Vec<_> = kept
            .iter()
            .flat_map(|&(_, from, len)| {
                (from..from + len).map(|at| (remap[edges.dep(at) as usize], edges.raw_flags(at)))
            })
            .collect();
        edges.compact(kept.iter().map(|&(_, from, len)| (from, len)), &remap);
        assert_eq!(
            (0..edges.len())
                .map(|at| (edges.dep(at), edges.raw_flags(at)))
                .collect::<Vec<_>>(),
            expected
        );
        let mut start = 0;
        let kept: Vec<_> = kept
            .into_iter()
            .map(|(owner, _, len)| {
                let span = (remap[owner as usize], start, len);
                start += len;
                span
            })
            .collect();
        edges.rebuild_reverse(NODES as usize, kept.iter().copied());
        assert_reverse(&edges, NODES as usize, &kept);

        let mut loaded = Edges::default();
        for (dep, flags) in expected {
            loaded.load(dep, flags);
        }
        loaded.rebuild_reverse(NODES as usize, kept.iter().copied());
        assert_reverse(&loaded, NODES as usize, &kept);
        for at in 0..edges.len() {
            assert_eq!(loaded.raw_flags(at), edges.raw_flags(at));
        }
    }
}
