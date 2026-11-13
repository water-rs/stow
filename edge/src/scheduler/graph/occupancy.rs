//! What the graph holds, by structure: the occupancy line the wake and
//! the budget probe log, and the byte total it accounts for.
//!
//! Counts that the standard library does not expose are estimates from
//! the entry sizes and the B-tree's node layout; every other figure is
//! an allocated capacity. Allocator free space and transient memory
//! stay outside the total, so Wasm linear memory exceeds it by exactly
//! that slack and by the inner strings of the wire records counted
//! inline.

use std::collections::BTreeSet;

use orx_split_vec::{Collection, PinnedVec};

use super::node::{Extra, Node, State, Status};
use super::{FeedSession, Graph, RequestRecord, StagedSlice};

/// Keys a B-tree node holds at most (`2 * B - 1` with `B = 6`).
const BTREE_NODE_KEYS: usize = 11;

/// Keys an average node holds: a tree grown by inserts settles near
/// two thirds full.
const BTREE_NODE_FILL: usize = 7;

/// Heap bytes of a B-tree of `len` entries of `entry` bytes each: the
/// leaves that hold them plus the internal nodes above, an internal
/// node adding one child pointer per slot to a leaf's layout.
pub(super) const fn btree_bytes(len: usize, entry: usize) -> usize {
    // Parent pointer, then the parent index and length in one word.
    let header = 2 * size_of::<usize>();
    let leaf = header + BTREE_NODE_KEYS * entry;
    let internal = leaf + (BTREE_NODE_KEYS + 1) * size_of::<usize>();
    let leaves = len.div_ceil(BTREE_NODE_FILL);
    leaves * leaf + leaves.div_ceil(BTREE_NODE_FILL) * internal
}

/// Heap bytes of a `BTreeSet<T>` of `len` entries.
const fn set_bytes<T>(len: usize) -> usize {
    btree_bytes(len, size_of::<T>())
}

/// Heap bytes of a `BTreeMap<K, V>` of `len` entries.
const fn map_bytes<K, V>(len: usize) -> usize {
    btree_bytes(len, size_of::<K>() + size_of::<V>())
}

/// The ready queues of one runner family: the map over the classes and
/// the set under each.
fn ready_bytes(classes: &super::ReadyClasses) -> usize {
    map_bytes::<super::ReadyClass, BTreeSet<(i64, u32)>>(classes.len())
        + classes
            .values()
            .map(|set| set_bytes::<(i64, u32)>(set.len()))
            .sum::<usize>()
}

/// A feed session's own bytes and its staged pages: each page's
/// entries inline (the inner strings of an entry are not counted) and
/// its hashes.
fn feed_session_bytes(hour: &str, session: &FeedSession) -> usize {
    size_of::<FeedSession>()
        + hour.len()
        + session.state.capacity()
        + session.staged.capacity() * size_of::<Vec<stow_types::api::SchedulerDemandEntry>>()
        + session
            .staged
            .iter()
            .map(|page| page.capacity() * size_of::<stow_types::api::SchedulerDemandEntry>())
            .sum::<usize>()
        + session
            .page_hashes
            .iter()
            .chain(&session.chain_hashes)
            .map(|hash| size_of::<String>() + hash.capacity())
            .sum::<usize>()
}

/// A request record's own bytes and its strings.
fn request_bytes(id: &str, record: &RequestRecord) -> usize {
    let optional = |text: &Option<String>| text.as_ref().map_or(0, String::capacity);
    id.len()
        + size_of::<RequestRecord>()
        + size_of::<stow_types::api::RequestAdmission>()
        + record.admission.request_id.capacity()
        + record.state.capacity()
        + optional(&record.run_id)
        + optional(&record.run_url)
        + optional(&record.outcome_json)
        + optional(&record.error)
}

/// A staged slice report's rows, inline.
fn staged_bytes(staged: &StagedSlice) -> usize {
    size_of::<StagedSlice>()
        + staged.rows.capacity() * size_of::<Vec<stow_types::api::PublishedSliceRow>>()
        + staged
            .rows
            .iter()
            .map(|rows| rows.capacity() * size_of::<stow_types::api::PublishedSliceRow>())
            .sum::<usize>()
}

/// The counts the resident-bytes formula reads: the ones a snapshot
/// head records, the interned text and the ready entries. Every one is
/// held as a count, so a graph's footprint is known in O(1) per event.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::scheduler) struct ResidentCounts {
    /// Node slots, freed ones included until the next compaction.
    pub(in crate::scheduler) nodes: usize,
    /// State slots, vacant ones included.
    pub(in crate::scheduler) states: usize,
    /// Dependency edges.
    pub(in crate::scheduler) edges: usize,
    /// Interned strings.
    pub(in crate::scheduler) strings: usize,
    /// Bytes of interned text.
    pub(in crate::scheduler) text: usize,
    /// Entries of the ready queues.
    pub(in crate::scheduler) ready: usize,
}

/// What a merge adds to the structures [`resident_bytes`] counts,
/// against the graph as it stands.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::scheduler) struct Growth {
    /// Nodes no live node holds the id of.
    pub(in crate::scheduler) nodes: usize,
    /// Of those, the ones that take queue state (the rest are born
    /// published).
    pub(in crate::scheduler) stateful: usize,
    /// Dependency edges of the new nodes.
    pub(in crate::scheduler) edges: usize,
    /// Strings the interner does not hold yet.
    pub(in crate::scheduler) strings: usize,
    /// Bytes of those strings.
    pub(in crate::scheduler) text: usize,
}

impl ResidentCounts {
    /// The bytes these counts hold, by [`resident_bytes`].
    pub(in crate::scheduler) fn bytes(&self) -> u64 {
        u64::try_from(resident_bytes(self)).expect("resident bytes fit u64")
    }

    /// These counts after a merge of `growth`: a new state takes a
    /// vacant slot before it grows the slab, and each stateful node
    /// may enter the ready queue.
    pub(in crate::scheduler) const fn grown(self, growth: Growth, vacant_states: usize) -> Self {
        Self {
            nodes: self.nodes + growth.nodes,
            states: self.states + growth.stateful.saturating_sub(vacant_states),
            edges: self.edges + growth.edges,
            strings: self.strings + growth.strings,
            text: self.text + growth.text,
            ready: self.ready + growth.stateful,
        }
    }
}

/// What a graph of `counts` holds, by formula: every arena, index and
/// queue sized from the counts a snapshot head records, the interned
/// text and the ready entries. It tracks the occupancy line to within
/// a percent at the density production wakes at (the test pins it).
pub(in crate::scheduler) fn resident_bytes(counts: &ResidentCounts) -> usize {
    let ResidentCounts {
        nodes,
        states,
        edges,
        strings,
        text,
        ready,
    } = *counts;
    // An arena allocates whole fragments of 1024 records.
    let arena = |records: usize, record: usize| records.div_ceil(1024) * 1024 * record;
    // An index holds its ids at seven eighths full, sized exactly.
    let table = |entries: usize| (entries * 8).div_ceil(7).max(8) * size_of::<u32>();
    arena(nodes, size_of::<Node>())
        + arena(states, size_of::<State>())
        + states.div_ceil(8)
        // The text grows by doubling, the offsets are sized by the head.
        + text.next_power_of_two()
        + strings * size_of::<u32>()
        + table(strings)
        + 2 * table(nodes)
        + arena(edges, size_of::<u32>())
        + arena(edges, size_of::<u8>())
        + arena(edges, size_of::<u32>())
        + arena(nodes + 1, size_of::<u32>())
        + nodes.div_ceil(8)
        + btree_bytes(ready, size_of::<(i64, u32)>())
}

/// Heap bytes by structure. [`Self::accounted`] is their sum.
#[derive(Debug, Clone, Copy)]
pub(super) struct Occupancy {
    pub(super) node: usize,
    pub(super) state: usize,
    pub(super) free_state: usize,
    pub(super) demand: usize,
    pub(super) intern: usize,
    pub(super) priority: usize,
    pub(super) task_id_index: usize,
    pub(super) identity_index: usize,
    pub(super) edge_array: usize,
    pub(super) edge_overlay: usize,
    pub(super) published_overlay: usize,
    pub(super) extra: usize,
    /// The seven per-status candidate bitsets.
    pub(super) by_status: usize,
    /// Both families' ready queues.
    pub(super) ready: usize,
    /// The pending index: ages, the human lane and the inflight set.
    pub(super) pending_index: usize,
    /// Requests, demand batches, external runs and feed sessions.
    pub(super) side_tables: usize,
    pub(super) staged_slices: usize,
}

impl Occupancy {
    /// Every counted byte.
    pub(super) const fn accounted(&self) -> usize {
        self.node
            + self.state
            + self.free_state
            + self.demand
            + self.intern
            + self.priority
            + self.task_id_index
            + self.identity_index
            + self.edge_array
            + self.edge_overlay
            + self.published_overlay
            + self.extra
            + self.by_status
            + self.ready
            + self.pending_index
            + self.side_tables
            + self.staged_slices
    }
}

impl Graph {
    /// Heap bytes of every structure the graph holds.
    pub(super) fn occupancy(&self) -> Occupancy {
        Occupancy {
            node: self.nodes.capacity() * size_of::<Node>(),
            state: self.states.capacity() * size_of::<State>(),
            free_state: self.free_states.heap_bytes(),
            demand: self.demand.heap_bytes(),
            intern: self.intern.heap_bytes(),
            priority: self.priorities.heap_bytes(),
            task_id_index: self.ids.heap_bytes(),
            identity_index: self.idents.heap_bytes(),
            edge_array: self.edges.array_bytes(),
            edge_overlay: self.edges.overlay_bytes(),
            published_overlay: self.published.heap_bytes(),
            extra: self.extras.capacity() * size_of::<(u32, Extra)>(),
            by_status: self
                .by_status
                .iter()
                .map(|bits| size_of_val(bits.as_slice()))
                .sum(),
            ready: ready_bytes(&self.ready) + ready_bytes(&self.ready_macos),
            pending_index: map_bytes::<i64, u32>(self.pending_ages.len())
                + set_bytes::<u32>(self.human_pending.len())
                + set_bytes::<u32>(self.inflight.len()),
            side_tables: self
                .requests
                .iter()
                .map(|(id, record)| request_bytes(id, record))
                .sum::<usize>()
                + map_bytes::<String, RequestRecord>(self.requests.len())
                + self
                    .demand_batches
                    .iter()
                    .map(|(id, (hash, _))| id.len() + hash.capacity())
                    .sum::<usize>()
                + map_bytes::<String, (String, i64)>(self.demand_batches.len())
                + self
                    .feed_sessions
                    .iter()
                    .map(|(hour, session)| feed_session_bytes(hour, session))
                    .sum::<usize>()
                + map_bytes::<String, FeedSession>(self.feed_sessions.len())
                + self.external_runs.capacity() * size_of::<(u64, u8)>(),
            staged_slices: self.staged_slices.values().map(staged_bytes).sum::<usize>()
                + map_bytes::<super::SliceId, StagedSlice>(self.staged_slices.len()),
        }
    }

    /// The counts [`resident_bytes`] reads, held now. Constant time
    /// but for the ready queues, one per rank-operand class.
    pub(in crate::scheduler) fn resident_counts(&self) -> ResidentCounts {
        ResidentCounts {
            nodes: self.nodes.len(),
            states: self.states.len(),
            edges: self.edges.len(),
            strings: self.intern.len(),
            text: self.intern.text_len(),
            ready: self.ready_sets().map(BTreeSet::len).sum(),
        }
    }

    /// Bytes the graph holds, by [`resident_bytes`].
    pub(in crate::scheduler) fn resident_bytes(&self) -> u64 {
        self.resident_counts().bytes()
    }

    /// Fail unless the graph's resident bytes are within `budget`.
    ///
    /// # Errors
    /// `QueueError::GraphExceedsBudget` past it.
    pub(in crate::scheduler) fn ensure_within(
        &self,
        budget: u64,
    ) -> Result<(), crate::errors::QueueError> {
        let needed = self.resident_bytes();
        if needed > budget {
            return Err(crate::errors::QueueError::GraphExceedsBudget { needed, budget });
        }
        Ok(())
    }

    /// Vacant state slots a new state takes before the slab grows.
    pub(in crate::scheduler) const fn vacant_states(&self) -> usize {
        self.free_states.len()
    }

    /// What merging `validated` would add to the counted structures,
    /// without changing the graph. Nodes the graph already holds cost
    /// nothing: a merge into one only re-ranks it, in place. A new node
    /// costs its record, its slots in the two indexes and its edges
    /// (kept until a compaction even when it is born published and
    /// released at once), a queue state and a ready entry when it is
    /// not published, and the strings the interner does not hold. The
    /// merge's other additions are constants: a priority value in the
    /// pool, a pending-age key per merge instant and a target or rustc
    /// id (at most 256 each), and one B-tree entry per human-lane node.
    ///
    /// # Errors
    /// `QueueError::Invariant` when `base` lacks a row the merge reads.
    pub(in crate::scheduler) fn merge_growth(
        &self,
        validated: &super::ValidatedSubmission<'_>,
        base: &mut impl super::PublishedSource,
    ) -> Result<Growth, crate::errors::QueueError> {
        let super::ValidatedSubmission { tree, ids } = validated;
        let mut growth = Growth::default();
        let mut seen = std::collections::HashSet::new();
        let mut strings = std::collections::HashSet::new();
        for (sub, keys) in tree.nodes.iter().zip(ids) {
            if self.find_key(keys.key).is_some() || !seen.insert(keys.key) {
                continue;
            }
            growth.nodes += 1;
            growth.edges += sub.deps.len();
            let explicit =
                sub.explicit_spelling == stow_types::public_cache::ExplicitSpelling::KeysApart;
            let published = self.published_mask(&keys.key, base, || {
                self.slice_lookup(sub.target.as_str(), sub.rustc_version.as_str())
            })?;
            // A target the graph has not held has no mask yet: assume
            // the node takes a state.
            let own = self.target_lookup(sub.target.as_str()).map(|target| {
                self.targets[usize::from(target)].own_masks[usize::from(sub.host_side)]
                    [usize::from(explicit)]
            });
            if own.is_none_or(|own| published & own != own) {
                growth.stateful += 1;
            }
            let version = sub.version.to_string();
            let features = sub.features_json.raw();
            for text in [sub.crate_name.as_str(), version.as_str(), features.as_str()] {
                if self.intern.get(text).is_none() && strings.insert(text.to_owned()) {
                    growth.strings += 1;
                    growth.text += text.len();
                }
            }
        }
        Ok(growth)
    }

    /// Occupancy and allocated buffer sizes, with the Wasm linear memory
    /// the isolate holds (wasm32 only). `accounted_storage_bytes` sums
    /// every structure's field below, the ready queues, bitsets, pending
    /// index, side tables and staged slices included; what remains of
    /// the linear memory is allocator free space, the wire records'
    /// inner strings and transient memory.
    pub(in crate::scheduler) fn trace_occupancy(&self, drive: &str, phase: &str, boundary: &str) {
        let held = self.occupancy();
        let met_edges = self.edges.met_count();
        let fan_in = self.edges.fan_in();
        tracing::info!(
            drive,
            phase,
            boundary,
            graph_loaded = true,
            retained_nodes = self.nodes.len() - self.counts[Status::Free.index()] as usize,
            node_slots = self.nodes.len(),
            node_capacity = self.nodes.capacity(),
            node_fragments = self.nodes.fragments().len(),
            node_storage_bytes = held.node,
            active_states = self.states.len() - self.free_states.len(),
            state_slots = self.states.len(),
            state_capacity = self.states.capacity(),
            state_fragments = self.states.fragments().len(),
            state_storage_bytes = held.state,
            free_state_slots = self.free_states.len(),
            free_state_storage_bytes = held.free_state,
            demand_storage_bytes = held.demand,
            intern_storage_bytes = held.intern,
            ready_entries = self.ready_sets().map(BTreeSet::len).sum::<usize>(),
            ready_classes = self.ready.len() + self.ready_macos.len(),
            ready_storage_bytes = held.ready,
            by_status_storage_bytes = held.by_status,
            priority_values = self.priorities.len(),
            priority_storage_bytes = held.priority,
            task_id_index_bytes = held.task_id_index,
            identity_index_bytes = held.identity_index,
            dependency_edges = self.edges.len(),
            met_edges,
            fan_in_dependencies = fan_in.dependencies,
            fan_in_max = fan_in.max,
            edge_array_storage_bytes = held.edge_array,
            edge_overlay_bytes = held.edge_overlay,
            published_identities = self.published_ids,
            published_overlay_entries = self.published.len(),
            published_overlay_bytes = held.published_overlay,
            pending_age_entries = self.pending_ages.len(),
            human_pending_entries = self.human_pending.len(),
            inflight_entries = self.inflight.len(),
            pending_index_bytes = held.pending_index,
            extra_entries = self.extras.len(),
            extra_capacity = self.extras.capacity(),
            extra_entry_bytes = size_of::<(u32, Extra)>(),
            extra_storage_bytes = held.extra,
            request_entries = self.requests.len(),
            feed_session_entries = self.feed_sessions.len(),
            staged_slice_entries = self.staged_slices.len(),
            side_table_bytes = held.side_tables,
            staged_slice_bytes = held.staged_slices,
            accounted_storage_bytes = held.accounted(),
            wasm_linear_bytes = super::super::memory::linear_bytes(),
            "budget graph occupancy"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::btree_bytes;

    #[test]
    fn btree_estimate_grows_with_entries_and_vanishes_when_empty() {
        assert_eq!(btree_bytes(0, 16), 0);
        assert!(btree_bytes(7, 16) > 7 * 16, "nodes carry spare slots");
        assert!(btree_bytes(7_000, 16) > 7_000 * 16 * 3 / 2);
        assert!(btree_bytes(7_000, 16) > btree_bytes(6_000, 16));
    }
}
