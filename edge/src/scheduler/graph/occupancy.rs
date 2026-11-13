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
