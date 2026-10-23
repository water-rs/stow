//! The scheduler's in-memory dependency graph (stow#878).
//!
//! Nodes, edges, per-node state and the ready set live here and nowhere
//! else: every accepted event mutates this structure and lands in the
//! flat log before it is acknowledged (`store.rs`); a wake rebuilds the
//! whole structure from a snapshot plus the log tail. Published nodes
//! leave the node arena — the signed index already records them — while
//! a slim published-identity entry survives for dependents' payload
//! rebuilds and is freed when its last unpublished dependent publishes.
//!
//! Layout is sized against the 128 MiB object bound: every string is
//! interned once (task ids, crate names, versions, feature sets,
//! targets, rustc, digests), nodes ride one arena `Vec`, and edges ride
//! one flat `Vec` with per-dep secondary indexes — see
//! `target/878-plan.md` §2 for the byte budget. The derived indexes
//! (`ids`, `by_key`, `dep_index`, `ready`) are rebuilt on load; the
//! snapshot carries only the irreducible state.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use stow_types::api::{
    BuildTaskPayload, PublishedSliceRow, RunnerFamily, SchedulerEvent, SubgraphNode,
    SubmissionNode, SubmissionSource, SubmissionTree, SubmitTaskIdEntry, TaskSubgraph,
    runner_family,
};
use stow_types::public_cache::{ExplicitSpelling, UnitShape};

use crate::errors::QueueError;
use crate::scheduler::{queue, rank};

/// String interner: every repeated string (task ids, crate names,
/// versions, feature sets, dependency digests) is one arena entry and
/// one `u32` everywhere else.
#[derive(Debug, Default)]
struct Interner {
    strings: Vec<Box<str>>,
    index: HashMap<Box<str>, u32>,
}

impl Interner {
    fn intern(&mut self, value: &str) -> u32 {
        if let Some(id) = self.index.get(value) {
            return *id;
        }
        let id = u32::try_from(self.strings.len()).expect("interner capacity");
        self.strings.push(value.into());
        self.index.insert(value.into(), id);
        id
    }

    fn get(&self, value: &str) -> Option<u32> {
        self.index.get(value).copied()
    }

    fn at(&self, id: u32) -> &str {
        &self.strings[id as usize]
    }
}

/// A node's (or an edge's dep's) semantic identity, interned — the same
/// key a published slice row reduces to, so publish membership is a
/// hashmap lookup, not a join.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
struct DepKey {
    crate_name: u32,
    version: u32,
    features: u32,
    target: u32,
    rustc: u32,
    host_side: bool,
    dep_identity: u32,
}

/// One dependency edge: `owner` needs `required` unit shapes of `dep`
/// before it may dispatch. `required` is a 4-bit mask over
/// `(invocation, linked)` pairs — bit `invocation * 2 + linked` — the
/// in-memory form of the retired `dep_invocations`/`dep_shapes` pair.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct Edge {
    owner: u32,
    dep: DepKey,
    required: u8,
    met: bool,
}

/// The edge's required-shape mask, derived exactly like
/// [`queue::dep_edge_requirements`]: host-side deps owe a linked unit
/// under each spelled invocation; target-side deps owe the linked and
/// unlinked unit under each.
fn required_shape_mask(dep_host_side: bool, invocations: i64) -> u8 {
    let mut mask = 0u8;
    for invocation in 0..2i64 {
        if invocations & (1 << invocation) != 0 {
            mask |= 1 << (invocation * 2 + 1);
            if !dep_host_side {
                mask |= 1 << (invocation * 2);
            }
        }
    }
    mask
}

/// One published slice row's contribution to a dep key's shape mask.
const fn shape_bit(shape: UnitShape) -> u8 {
    1 << (shape.invocation.to_int() * 2 + shape.kind.to_int())
}

/// The shapes a node itself must publish before it leaves memory — the
/// same set `required_unit_shapes` computes for the node's own build.
fn node_published_mask(host_side: bool, target: &str, explicit: ExplicitSpelling) -> u8 {
    let invocation = if host_side
        || runner_family(target).is_some_and(|family| family.host_triple() == target)
    {
        stow_types::public_cache::UnitInvocation::Native
    } else {
        stow_types::public_cache::UnitInvocation::Target
    };
    let mut mask = 0u8;
    for shape in stow_types::public_cache::required_unit_shapes(host_side, invocation, explicit) {
        mask |= shape_bit(shape);
    }
    mask
}

/// Queue status — the graph's lifecycle states. `Published` is the
/// tombstone a node retires into; tombstones stay in the arena (stable
/// indexes) but count nowhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Status {
    Pending,
    Dispatched,
    Running,
    Completed,
    Failed,
    Published,
}

/// The entry point a node arrived under — what the rank reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Lane {
    Miss,
    Human,
    Operations,
    Preheat,
}

impl Lane {
    const fn from_source(source: SubmissionSource) -> Self {
        match source {
            SubmissionSource::Operations { .. } => Self::Operations,
            SubmissionSource::HumanRequest => Self::Human,
            SubmissionSource::Preheat => Self::Preheat,
            SubmissionSource::CacheMiss | SubmissionSource::InexactHit => Self::Miss,
        }
    }

    /// The `lane` operand `rank::raw_value` prices — the human lane
    /// keeps its precedence band until #879 rewrites the rank.
    const fn sql_lane(self) -> &'static str {
        match self {
            Self::Human | Self::Operations => "human",
            Self::Miss | Self::Preheat => "miss",
        }
    }
}

/// A verified completion that beat its dispatch response — parked on
/// the task until `bind` lands (the `pending_run_completions` fence,
/// in memory).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ParkedCompletion {
    run_id: u64,
    success: bool,
    cancelled: bool,
    error: Option<String>,
}

/// One graph node: queue identity (interned) plus per-node state.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Node {
    task_id: u32,
    key: DepKey,
    status: Status,
    lane: Lane,
    explicit_spelling: bool,
    preserve_lockfile: bool,
    attempt: u32,
    dispatch_attempts: u32,
    generation: u64,
    run_id: u64,
    claimed_at: i64,
    not_before: i64,
    first_requested: i64,
    priority: i64,
    demand: i64,
    downloads: u64,
    unmet: u32,
    blocked: bool,
    edges_start: u32,
    edges_len: u32,
    error: Option<Box<str>>,
    parked: Option<ParkedCompletion>,
}

/// A dep identity's wire fields — what [`Graph::dep_wire`] returns.
struct DepWire {
    crate_name: String,
    version: String,
    features: String,
    host_side: bool,
    keys_apart: bool,
    deps: Vec<DepKey>,
}

/// A published node's surviving identity — slim, and freed when its
/// last unpublished dependent publishes (stow#878, review Q1). The
/// payload rebuild needs the identity and the dep's own children;
/// nothing else survives.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PublishedIdentity {
    task_id: u32,
    explicit_spelling: bool,
    deps: Vec<DepKey>,
    /// Live nodes still holding an edge on this identity.
    dependents: u32,
}

/// The scheduler's self-counted billed rows (stow#878 review): no
/// `do_meter`/`probe_meter` table counts itself. `store.rs` books every
/// row it reads and writes here; the snapshot carries the counters and
/// replay re-counts the log tail it reads.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Meter {
    /// UTC day (`YYYY-MM-DD`) the counters apply to.
    pub day: String,
    /// Rows the DO read today.
    pub rows_read: u64,
    /// Rows the DO wrote today.
    pub rows_written: u64,
    /// Per-operation ledger for the budget probe — `ops` carries
    /// `(statements, rows_read, rows_written)`.
    #[serde(default)]
    pub ops: BTreeMap<String, (u64, u64, u64)>,
}

impl Meter {
    /// Roll the counters at a UTC-day boundary — the daily budget the
    /// breaker evaluates is per UTC day.
    pub fn roll_to(&mut self, day: &str) {
        if self.day != day {
            day.clone_into(&mut self.day);
            self.rows_read = 0;
            self.rows_written = 0;
        }
    }

    /// Book one statement's billed rows under an operation.
    pub fn record(&mut self, op: &str, rows_read: u64, rows_written: u64) {
        self.rows_read += rows_read;
        self.rows_written += rows_written;
        if let Some(slot) = self.ops.get_mut(op) {
            slot.0 += 1;
            slot.1 += rows_read;
            slot.2 += rows_written;
        }
    }
}

/// The whole in-memory graph. Nothing here serializes whole: the
/// snapshot walks [`Self::snapshot_chunk`]s, each a bounded section
/// slice — serialization never assembles the graph's image in memory
/// (stow#878 review).
#[derive(Debug, Default)]
pub struct Graph {
    intern: Interner,
    /// `task_id` intern-id → node index; published nodes keep their
    /// tombstone entry so id lookups still resolve.
    ids: HashMap<u32, u32>,
    /// `DepKey` → node index, live nodes only (tombstones removed).
    by_key: HashMap<DepKey, u32>,
    nodes: Vec<Node>,
    /// Flat edge list; `node.edges_start..+edges_len` is the owner's
    /// contiguous span.
    edges: Vec<Edge>,
    /// dep → edge indexes — the publish-flip index (rebuilt on load).
    dep_index: HashMap<DepKey, Vec<u32>>,
    /// dep → published unit-shape mask.
    published: HashMap<DepKey, u8>,
    /// Slim identities of published nodes still referenced.
    published_idents: HashMap<DepKey, PublishedIdentity>,
    /// Ready set: dispatchable pending nodes ordered
    /// `(rank descending, first_requested, task_id)` — the in-memory
    /// form of `dispatch_key`'s ordering (rebuilt on load).
    ready: BTreeSet<(i64, i64, u32)>,
    /// External `build-crate.yml` runs (stow#877): run id → family bit.
    external_runs: HashMap<u64, u8>,
    /// The dispatch freeze record while engaged.
    freeze: Option<stow_types::api::DispatchFreezeRecord>,
    /// The admission floor (`min_dispatch_value`).
    floor: i64,
    /// Per-(crate, target) expected build cost samples (stow#524).
    build_stats: HashMap<(u32, u32), Vec<i64>>,
    /// The next claim generation — monotonic, snapshot-carried.
    next_generation: u64,
    /// The in-memory billed-row counters.
    pub meter: Meter,
}

/// One serialized snapshot section — a `snapshot_chunks` row's tag and
/// payload. A part stays under the row-size bound by construction:
/// each section serializes at most `*_PART` items.
pub struct SnapshotChunk {
    /// The section this chunk carries (`head`, `intern`, `nodes`,
    /// `edges`, `published`, `idents`).
    pub tag: &'static str,
    /// The serialized section slice.
    pub payload: Vec<u8>,
}

/// Section slice sizes — chosen so a serialized part stays a small
/// fraction of the ~2 MB row bound.
const INTERN_PART: usize = 4096;
const NODE_PART: usize = 4096;
const EDGE_PART: usize = 16384;
const PAIR_PART: usize = 8192;
const IDENT_PART: usize = 2048;

/// The snapshot's first chunk — everything that is not a section
/// array.
#[derive(Serialize, Deserialize)]
struct SnapshotHead {
    next_generation: u64,
    floor: i64,
    meter: Meter,
    freeze: Option<stow_types::api::DispatchFreezeRecord>,
    external_runs: Vec<(u64, u8)>,
    build_stats: Vec<((u32, u32), Vec<i64>)>,
}

/// One claimed node, ready for payload build and dispatch.
#[derive(Debug)]
pub struct Claimed {
    /// The task id (re-materialized from the interner).
    pub task_id: String,
    /// The minted generation.
    pub generation: u64,
    /// The attempt cycle.
    pub attempt: u32,
    /// The dispatch payload, subgraph rebuilt.
    pub payload: BuildTaskPayload,
}

/// What a merge changed.
#[derive(Debug, Default)]
pub struct MergeReport {
    /// Brand-new nodes.
    pub inserted: u32,
    /// Nodes already present (updated or skipped).
    pub merged: u32,
}

/// What one run-finished event resolved to.
#[derive(Debug, PartialEq, Eq)]
pub enum FinishOutcome {
    /// Applied to a bound run.
    Applied,
    /// Parked — the run's binding has not landed yet.
    Parked,
    /// An external run's completion was consumed.
    External,
    /// No live state named this run (stale delivery).
    Stale,
}

/// What one in-progress delivery resolved to.
#[derive(Debug, PartialEq, Eq)]
pub enum StartOutcome {
    /// A dispatched run moved to `running` (bound on delivery if its
    /// binding had not yet landed).
    Applied,
    /// A run the scheduler did not dispatch — tracked as external.
    External,
    /// A repeated or unknown delivery.
    Stale,
}

/// The window a (crate, target) build-cost stat keeps.
const SAMPLE_WINDOW: usize = 50;

impl Graph {
    /// Look up a node index by task id string.
    fn node_ix(&self, task_id: &str) -> Option<u32> {
        let interned = self.intern.get(task_id)?;
        self.ids.get(&interned).copied()
    }

    fn node(&self, ix: u32) -> &Node {
        &self.nodes[ix as usize]
    }

    fn node_mut(&mut self, ix: u32) -> &mut Node {
        &mut self.nodes[ix as usize]
    }

    /// This node's contiguous edge slice.
    fn edges_of(&self, ix: u32) -> &[Edge] {
        let node = self.node(ix);
        &self.edges[node.edges_start as usize..(node.edges_start + node.edges_len) as usize]
    }

    /// A dep's own node index, when the dep is a live node.
    fn dep_node(&self, dep: DepKey) -> Option<u32> {
        self.by_key.get(&dep).copied()
    }

    /// The dep key one `SubmissionNode` reduces to.
    fn dep_key(&mut self, node: &SubmissionNode) -> DepKey {
        DepKey {
            crate_name: self.intern.intern(node.crate_name.as_str()),
            version: self.intern.intern(&node.version.as_semver().to_string()),
            features: self.intern.intern(&node.features_json.raw()),
            target: self.intern.intern(node.target.as_str()),
            rustc: self.intern.intern(node.rustc_version.as_str()),
            host_side: node.host_side,
            dep_identity: self.intern.intern(node.dependency_identity.as_str()),
        }
    }

    /// One published slice row's dep key.
    fn row_dep_key(&mut self, target: &str, rustc: &str, row: &PublishedSliceRow) -> DepKey {
        DepKey {
            crate_name: self.intern.intern(row.crate_name.as_str()),
            version: self.intern.intern(&row.version.as_semver().to_string()),
            features: self.intern.intern(&row.features_json.raw()),
            target: self.intern.intern(target),
            rustc: self.intern.intern(rustc),
            host_side: row.unit_shape.side == stow_types::public_cache::UnitSide::Host,
            dep_identity: self.intern.intern(row.dependency_identity.as_str()),
        }
    }

    /// This node's own required published shapes.
    fn own_mask(&self, node: &Node) -> u8 {
        node_published_mask(
            node.key.host_side,
            self.intern.at(node.key.target),
            if node.explicit_spelling {
                ExplicitSpelling::KeysApart
            } else {
                ExplicitSpelling::KeysAsNative
            },
        )
    }

    /// The ready value a node orders under — `rank::raw_value` on its
    /// lane, family and operands.
    fn ready_value(&self, node: &Node) -> i64 {
        rank::raw_value(
            node.lane.sql_lane(),
            rank::dispatch_family(self.intern.at(node.key.target)),
            node.priority,
            node.demand,
        )
    }

    /// Whether a node may dispatch apart from its age/backoff gate.
    fn dispatchable(&self, node: &Node) -> bool {
        node.status == Status::Pending
            && node.unmet == 0
            && !node.blocked
            && (node.lane == Lane::Human || self.ready_value(node) >= self.floor)
    }

    /// The node's ready-set key: rank descending (`ready` is ascending,
    /// so the rank operand is negated), then FIFO.
    fn ready_key(&self, node: &Node) -> (i64, i64, u32) {
        (
            self.ready_value(node).checked_neg().unwrap_or(i64::MIN),
            node.first_requested,
            node.task_id,
        )
    }

    /// Insert or retire a node's ready-set entry.
    fn refresh_ready(&mut self, ix: u32) {
        let node = self.node(ix);
        let key = self.ready_key(node);
        let dispatchable = self.dispatchable(node);
        self.ready.remove(&key);
        if dispatchable {
            self.ready.insert(key);
        }
    }

    /// Merge one submission tree by task id. `now` is unix ms.
    ///
    /// A node id commits to its subtree: an existing id's edge set is
    /// never rewritten — the merge only ever raises `downloads` and
    /// `priority` on it. New nodes are born gated; each edge's `met`
    /// answers against the published-shape masks at insert.
    ///
    /// # Errors
    /// `QueueError::Invariant` on a malformed tree (dep index or root
    /// index out of range).
    pub fn merge(&mut self, tree: &SubmissionTree, now: i64) -> Result<MergeReport, QueueError> {
        let lane = Lane::from_source(tree.source);
        let op_priority = match tree.source {
            SubmissionSource::Operations { priority } => priority,
            _ => 0,
        };
        for &root in &tree.roots {
            if root as usize >= tree.nodes.len() {
                return Err(QueueError::Invariant(format!(
                    "submission root index {root} out of range ({} nodes)",
                    tree.nodes.len()
                )));
            }
        }
        let mut report = MergeReport::default();
        // Pass 1: intern everything; insert nodes absent by task id.
        let mut node_ixs = Vec::with_capacity(tree.nodes.len());
        let mut fresh = Vec::with_capacity(tree.nodes.len());
        for sub in &tree.nodes {
            let task_id = self.intern.intern(&sub.task_id);
            if let Some(&ix) = self.ids.get(&task_id) {
                let node = self.node_mut(ix);
                node.downloads = node.downloads.max(sub.downloads);
                node.priority = node
                    .priority
                    .max(op_priority + queue::compute_priority(sub.downloads, 0)?);
                node_ixs.push(ix);
                fresh.push(false);
                report.merged += 1;
                continue;
            }
            let key = self.dep_key(sub);
            let ix = u32::try_from(self.nodes.len())
                .map_err(|_| QueueError::Invariant("node count overflows u32".into()))?;
            self.nodes.push(Node {
                task_id,
                key,
                status: Status::Pending,
                lane,
                explicit_spelling: sub.explicit_spelling == ExplicitSpelling::KeysApart,
                preserve_lockfile: sub.preserve_lockfile,
                attempt: 1,
                dispatch_attempts: 0,
                generation: 0,
                run_id: 0,
                claimed_at: 0,
                not_before: 0,
                first_requested: now,
                priority: op_priority + queue::compute_priority(sub.downloads, 0)?,
                demand: 0,
                downloads: sub.downloads,
                unmet: 0,
                blocked: false,
                edges_start: 0,
                edges_len: 0,
                error: None,
                parked: None,
            });
            self.ids.insert(task_id, ix);
            self.by_key.insert(key, ix);
            node_ixs.push(ix);
            fresh.push(true);
            report.inserted += 1;
        }
        // Pass 2: edges for the fresh nodes only — an existing id's
        // subtree is committed by its first submission.
        for (sub_ix, sub) in tree.nodes.iter().enumerate() {
            if fresh[sub_ix] {
                self.merge_edges(tree, sub_ix, sub, node_ixs[sub_ix])?;
            }
        }
        Ok(report)
    }

    /// One fresh node's edge list — `merge`'s second pass.
    fn merge_edges(
        &mut self,
        tree: &SubmissionTree,
        sub_ix: usize,
        sub: &SubmissionNode,
        owner: u32,
    ) -> Result<(), QueueError> {
        {
            let _ = sub_ix;
            let (owner_target, owner_host_side, owner_explicit) = {
                let node = self.node(owner);
                (
                    self.intern.at(node.key.target).to_owned(),
                    node.key.host_side,
                    if node.explicit_spelling {
                        ExplicitSpelling::KeysApart
                    } else {
                        ExplicitSpelling::KeysAsNative
                    },
                )
            };
            let owner_task = self.node(owner).task_id;
            let edges_start = u32::try_from(self.edges.len())
                .map_err(|_| QueueError::Invariant("edge count overflows u32".into()))?;
            let mut unmet = 0u32;
            for &dep_ix in &sub.deps {
                let dep_sub = tree.nodes.get(dep_ix as usize).ok_or_else(|| {
                    QueueError::Invariant(format!(
                        "task {} dep index {dep_ix} out of range",
                        self.intern.at(owner_task)
                    ))
                })?;
                let dep_key = self.dep_key(dep_sub);
                let (invocations, _shapes) = queue::dep_edge_requirements(
                    &owner_target,
                    owner_host_side,
                    owner_explicit,
                    dep_sub.target.as_str(),
                    dep_sub.host_side,
                    dep_sub.explicit_spelling,
                );
                let required = required_shape_mask(dep_sub.host_side, invocations);
                let published = self.published.get(&dep_key).copied().unwrap_or(0);
                let met = published & required == required;
                if !met {
                    unmet += 1;
                }
                let edge_ix = u32::try_from(self.edges.len())
                    .map_err(|_| QueueError::Invariant("edge count overflows u32".into()))?;
                self.edges.push(Edge {
                    owner,
                    dep: dep_key,
                    required,
                    met,
                });
                self.dep_index.entry(dep_key).or_default().push(edge_ix);
            }
            let edges_len = u32::try_from(self.edges.len())
                .map_err(|_| QueueError::Invariant("edge count overflows u32".into()))?
                - edges_start;
            // A fresh node is blocked when any dep is a live failed
            // node; published dep identities gain a dependent.
            let mut blocked = false;
            for off in 0..edges_len {
                let dep = self.edges[(edges_start + off) as usize].dep;
                if self
                    .dep_node(dep)
                    .is_some_and(|dep_ix| self.node(dep_ix).status == Status::Failed)
                {
                    blocked = true;
                }
                if let Some(ident) = self.published_idents.get_mut(&dep) {
                    ident.dependents += 1;
                }
            }
            let node = self.node_mut(owner);
            node.edges_start = edges_start;
            node.edges_len = edges_len;
            node.unmet = unmet;
            node.blocked = blocked;
            self.refresh_ready(owner);
        }
        Ok(())
    }

    /// Apply a published-slice report: add/retire unit shapes, flip the
    /// edges they touch, and retire nodes whose own shapes are served.
    /// Returns the number of edge flips.
    pub fn apply_slice_report(
        &mut self,
        target: &str,
        rustc_version: &str,
        added: &[PublishedSliceRow],
        retired: &[PublishedSliceRow],
    ) -> u32 {
        let mut flips = 0;
        for row in retired {
            flips += self.apply_slice_row(target, rustc_version, row, false);
        }
        for row in added {
            flips += self.apply_slice_row(target, rustc_version, row, true);
        }
        flips
    }

    fn apply_slice_row(
        &mut self,
        target: &str,
        rustc: &str,
        row: &PublishedSliceRow,
        added: bool,
    ) -> u32 {
        let key = self.row_dep_key(target, rustc, row);
        let bit = shape_bit(row.unit_shape);
        let mask = {
            let entry = self.published.entry(key).or_insert(0);
            if added {
                *entry |= bit;
            } else {
                *entry &= !bit;
            }
            *entry
        };
        let mut flips = 0;
        if let Some(edge_ixs) = self.dep_index.get(&key).cloned() {
            for edge_ix in edge_ixs {
                let edge = &self.edges[edge_ix as usize];
                let (owner, required) = (edge.owner, edge.required);
                let met = mask & required == required;
                if edge.met == met {
                    continue;
                }
                self.edges[edge_ix as usize].met = met;
                let node = self.node_mut(owner);
                node.unmet = if met {
                    node.unmet.saturating_sub(1)
                } else {
                    node.unmet + 1
                };
                self.refresh_ready(owner);
                flips += 1;
            }
        }
        // Retire a live node whose own published shapes are now
        // covered — published nodes leave memory.
        if added && let Some(ix) = self.dep_node(key) {
            let own = self.own_mask(self.node(ix));
            if mask & own == own {
                self.retire_node(ix);
            }
        }
        flips
    }

    /// Move a published node out of the live set into the slim
    /// published-identity store.
    fn retire_node(&mut self, ix: u32) {
        let node = self.node_mut(ix);
        node.status = Status::Published;
        let (key, task_id, explicit) = (node.key, node.task_id, node.explicit_spelling);
        let deps: Vec<DepKey> = self.edges_of(ix).iter().map(|edge| edge.dep).collect();
        self.by_key.remove(&key);
        self.ready.retain(|&(_, _, tid)| tid != task_id);
        // Retiring this node releases its deps' dependent counts.
        let mut freed = Vec::new();
        for dep in &deps {
            if let Some(ident) = self.published_idents.get_mut(dep) {
                ident.dependents = ident.dependents.saturating_sub(1);
                if ident.dependents == 0 {
                    freed.push(*dep);
                }
            }
        }
        let dependents = self.dep_index.get(&key).map_or(0, |edge_ixs| {
            u32::try_from(
                edge_ixs
                    .iter()
                    .filter(|&&e| {
                        let owner = self.edges[e as usize].owner;
                        self.node(owner).status != Status::Published
                    })
                    .count(),
            )
            .unwrap_or(u32::MAX)
        });
        self.published_idents.insert(
            key,
            PublishedIdentity {
                task_id,
                explicit_spelling: explicit,
                deps,
                dependents,
            },
        );
        // Cascade: freed slim entries release their own deps.
        while let Some(dep) = freed.pop() {
            if let Some(ident) = self.published_idents.remove(&dep) {
                for child in ident.deps {
                    if let Some(child_ident) = self.published_idents.get_mut(&child) {
                        child_ident.dependents = child_ident.dependents.saturating_sub(1);
                        if child_ident.dependents == 0 {
                            freed.push(child);
                        }
                    }
                }
            }
        }
    }

    /// Claim up to `total_free` (and `macos_free` for the macOS family)
    /// ready nodes, minting one generation per claim. `now` is unix ms;
    /// nodes whose `not_before` is in the future are skipped. Returns
    /// claims in rank order — the dispatch pass writes ONE `Claims`
    /// event for this set before posting, and ONE `Bindings` row after.
    ///
    /// # Errors
    /// `QueueError::Invariant` when a claimed node's payload cannot be
    /// rebuilt — a dep identity absent from graph and published arena.
    pub fn claim(
        &mut self,
        total_free: u32,
        macos_free: u32,
        now: i64,
        stale_ms: i64,
    ) -> Result<Vec<Claimed>, QueueError> {
        // Stale-lease recovery first: in-flight nodes whose claim
        // outlived the lease return to pending.
        let stale: Vec<u32> = (0..u32::try_from(self.nodes.len()).unwrap_or(u32::MAX))
            .filter(|&ix| {
                let node = self.node(ix);
                matches!(node.status, Status::Dispatched | Status::Running)
                    && node.claimed_at + stale_ms <= now
            })
            .collect();
        for ix in stale {
            let node = self.node_mut(ix);
            node.status = Status::Pending;
            node.claimed_at = 0;
            node.run_id = 0;
            node.parked = None;
            self.refresh_ready(ix);
        }
        if self.freeze.is_some() {
            return Ok(Vec::new());
        }
        let mut claimed = Vec::new();
        let mut macos_taken = 0u32;
        let keys: Vec<(i64, i64, u32)> = self.ready.iter().copied().collect();
        for key in keys {
            if claimed.len() >= total_free as usize {
                break;
            }
            let Some(&ix) = self.ids.get(&key.2) else {
                self.ready.remove(&key);
                continue;
            };
            let node = self.node(ix);
            if node.not_before > now {
                continue;
            }
            let family = runner_family(self.intern.at(node.key.target)).ok_or_else(|| {
                QueueError::Invariant(format!(
                    "pending task {} targets `{}`, no runner family",
                    self.intern.at(node.task_id),
                    self.intern.at(node.key.target)
                ))
            })?;
            if family == RunnerFamily::MacOs && macos_taken >= macos_free {
                continue;
            }
            self.next_generation += 1;
            let generation = self.next_generation;
            let node = self.node_mut(ix);
            node.status = Status::Dispatched;
            node.generation = generation;
            node.dispatch_attempts += 1;
            node.claimed_at = now;
            node.run_id = 0;
            self.ready.remove(&key);
            if family == RunnerFamily::MacOs {
                macos_taken += 1;
            }
            let payload = self.task_payload(ix)?;
            let task_id = self.intern.at(self.node(ix).task_id).to_owned();
            claimed.push(Claimed {
                task_id,
                generation,
                attempt: self.node(ix).attempt,
                payload,
            });
        }
        Ok(claimed)
    }

    /// Bind a dispatch response's run id to a claim's generation, and
    /// consume a completion parked on the claim when one is waiting.
    /// Returns whether the binding applied (false = stale generation).
    pub fn bind(&mut self, task_id: &str, generation: u64, run_id: u64, now: i64) -> bool {
        let Some(ix) = self.node_ix(task_id) else {
            return false;
        };
        let node = self.node_mut(ix);
        if node.generation != generation
            || !matches!(node.status, Status::Dispatched | Status::Running)
        {
            return false;
        }
        node.run_id = run_id;
        if let Some(parked) = node.parked.take()
            && parked.run_id == run_id
        {
            self.finish_run_inner(ix, parked.success, parked.cancelled, parked.error, now);
        }
        true
    }

    /// A `workflow_dispatch` failure re-queues the claim under backoff.
    pub fn mark_dispatch_failed(
        &mut self,
        task_id: &str,
        generation: u64,
        error: &str,
        not_before: i64,
    ) {
        let Some(ix) = self.node_ix(task_id) else {
            return;
        };
        let node = self.node_mut(ix);
        if node.generation != generation
            || !matches!(node.status, Status::Dispatched | Status::Running)
            || node.run_id != 0
        {
            return;
        }
        node.status = Status::Pending;
        node.error = Some(error.into());
        node.not_before = not_before;
        node.parked = None;
        self.refresh_ready(ix);
    }

    /// A `workflow_run` `in_progress` delivery. A delivery naming a
    /// dispatched-but-unbound claim binds it — the run's own record is
    /// the authoritative binding (review Q6's delivery-side leg).
    pub fn run_started(
        &mut self,
        task_id: &str,
        run_id: u64,
        family: RunnerFamily,
    ) -> StartOutcome {
        if let Some(ix) = self.node_ix(task_id) {
            let node = self.node_mut(ix);
            if matches!(node.status, Status::Dispatched | Status::Running) {
                if node.run_id == run_id {
                    node.status = Status::Running;
                    return StartOutcome::Applied;
                }
                if node.run_id == 0 {
                    node.run_id = run_id;
                    node.status = Status::Running;
                    return StartOutcome::Applied;
                }
                return StartOutcome::Stale;
            }
        }
        let bit = 1u8 << (family as u8);
        if self.external_runs.insert(run_id, bit).is_none() {
            StartOutcome::External
        } else {
            StartOutcome::Stale
        }
    }

    /// Reconcile the run set after a wake (#877, review Q6): the
    /// `status` listing is the truth for occupancy, and a run title
    /// (`<rustc>-<task_id>`) that names an unbound dispatched claim
    /// re-lands its binding.
    pub fn reconcile_runs(&mut self, runs: &[(u64, String, RunnerFamily)], now: i64) {
        self.external_runs.clear();
        for (run_id, title, family) in runs {
            let task_id = title
                .split_once('-')
                .map(|(_, task_id)| task_id)
                .unwrap_or_default();
            if let Some(ix) = self.node_ix(task_id) {
                let node = self.node(ix);
                if matches!(node.status, Status::Dispatched | Status::Running) && node.run_id == 0 {
                    self.bind(task_id, node.generation, *run_id, now);
                    continue;
                }
            }
            self.external_runs.insert(*run_id, 1u8 << (*family as u8));
        }
    }

    /// A `workflow_run` `completed` delivery.
    pub fn run_finished(
        &mut self,
        task_id: &str,
        run_id: u64,
        success: bool,
        cancelled: bool,
        error: Option<String>,
        now: i64,
    ) -> FinishOutcome {
        let was_external = self.external_runs.remove(&run_id).is_some();
        let Some(ix) = self.node_ix(task_id) else {
            return if was_external {
                FinishOutcome::External
            } else {
                FinishOutcome::Stale
            };
        };
        let node = self.node(ix);
        if !matches!(node.status, Status::Dispatched | Status::Running) {
            return if was_external {
                FinishOutcome::External
            } else {
                FinishOutcome::Stale
            };
        }
        if node.run_id == 0 {
            self.node_mut(ix).parked = Some(ParkedCompletion {
                run_id,
                success,
                cancelled,
                error,
            });
            return FinishOutcome::Parked;
        }
        if node.run_id != run_id {
            return FinishOutcome::Stale;
        }
        self.finish_run_inner(ix, success, cancelled, error, now);
        FinishOutcome::Applied
    }

    /// The completion's own transition — shared by the direct apply and
    /// the parked-consume path.
    fn finish_run_inner(
        &mut self,
        ix: u32,
        success: bool,
        cancelled: bool,
        error: Option<String>,
        now: i64,
    ) {
        let node = self.node_mut(ix);
        if cancelled && !success {
            // Superseded duplicate — re-queue without an attempt bump.
            node.status = Status::Pending;
            node.run_id = 0;
            node.claimed_at = 0;
            self.refresh_ready(ix);
            return;
        }
        if success {
            node.status = Status::Completed;
            let elapsed = now.saturating_sub(node.claimed_at);
            let stat_key = (node.key.crate_name, node.key.target);
            let samples = self.build_stats.entry(stat_key).or_default();
            if samples.len() >= SAMPLE_WINDOW {
                samples.remove(0);
            }
            samples.push(elapsed.max(1));
            return;
        }
        node.attempt += 1;
        let dep = node.key;
        if node.attempt > queue::MAX_BUILD_ATTEMPTS {
            node.status = Status::Failed;
            node.error = error.map(Into::into);
            // Dependents of a failed dep become blocked.
            if let Some(edge_ixs) = self.dep_index.get(&dep).cloned() {
                for edge_ix in edge_ixs {
                    let owner = self.edges[edge_ix as usize].owner;
                    let owner_node = self.node_mut(owner);
                    owner_node.blocked = true;
                    self.refresh_ready(owner);
                }
            }
        } else {
            node.status = Status::Pending;
            node.error = error.map(Into::into);
            let backoff = queue::dispatch_backoff_minutes(node.attempt);
            node.not_before = now + i64::from(backoff) * 60_000;
            self.refresh_ready(ix);
        }
    }

    /// An accepted demand batch folded into the affected nodes.
    pub fn fold_demand(&mut self, entries: &[(String, i64)]) {
        for (task_id, delta) in entries {
            if let Some(ix) = self.node_ix(task_id) {
                let node = self.node_mut(ix);
                node.demand = node.demand.saturating_add(*delta);
                self.refresh_ready(ix);
            }
        }
    }

    /// Operator mutations over explicit task ids. Returns rows affected.
    pub fn mutate(&mut self, op: stow_types::api::MutationKind, task_ids: &[String]) -> u32 {
        let mut affected = 0;
        for task_id in task_ids {
            let Some(ix) = self.node_ix(task_id) else {
                continue;
            };
            let (changed, dep_key) = {
                let node = self.node_mut(ix);
                match op {
                    stow_types::api::MutationKind::Retry => {
                        if node.status == Status::Failed {
                            node.status = Status::Pending;
                            node.attempt = 1;
                            node.error = None;
                            node.not_before = 0;
                            (true, Some(node.key))
                        } else {
                            (false, None)
                        }
                    }
                    stow_types::api::MutationKind::Cancel => {
                        if node.status == Status::Pending {
                            node.status = Status::Published;
                            (true, None)
                        } else {
                            (false, None)
                        }
                    }
                    stow_types::api::MutationKind::Promote => {
                        if node.lane == Lane::Human {
                            (false, None)
                        } else {
                            node.lane = Lane::Human;
                            (true, None)
                        }
                    }
                    stow_types::api::MutationKind::Purge => {
                        node.status = Status::Published;
                        (true, None)
                    }
                }
            };
            if !changed {
                continue;
            }
            let tid = self.node(ix).task_id;
            self.ready.retain(|key| key.2 != tid);
            // A dep that rises from `failed` unblocks its dependents.
            if let Some(dep) = dep_key
                && let Some(edge_ixs) = self.dep_index.get(&dep).cloned()
            {
                for edge_ix in edge_ixs {
                    let owner = self.edges[edge_ix as usize].owner;
                    if self.edges[edge_ix as usize].met {
                        continue;
                    }
                    let owner_node = self.node_mut(owner);
                    if owner_node.status == Status::Pending {
                        owner_node.blocked = false;
                        self.refresh_ready(owner);
                    }
                }
            }
            self.refresh_ready(ix);
            affected += 1;
        }
        affected
    }

    /// Rebuild a claimed node's `BuildTaskPayload` — identity fields
    /// plus the dependency subgraph walked over live nodes and the
    /// published-identity arena (stow#588's contract, from memory).
    ///
    /// # Errors
    /// `QueueError::Invariant` when a dep identity resolves to neither
    /// a live node nor a published identity — the store is corrupt.
    pub fn task_payload(&self, ix: u32) -> Result<BuildTaskPayload, QueueError> {
        let node = self.node(ix);
        let task_id = self.intern.at(node.task_id).to_owned();
        let label = task_id.clone();
        let invalid =
            |error: String| QueueError::Invariant(format!("claimed task {label}: {error}"));
        // BFS over dep keys; visit order is the wire order.
        let mut seen: HashMap<DepKey, u32> = HashMap::new();
        let mut order: Vec<DepKey> = Vec::new();
        let mut frontier: Vec<DepKey> = Vec::new();
        let mut root_deps = Vec::new();
        for edge in self.edges_of(ix) {
            let rank = *seen.entry(edge.dep).or_insert_with(|| {
                order.push(edge.dep);
                frontier.push(edge.dep);
                u32::try_from(order.len() - 1).unwrap_or(u32::MAX)
            });
            root_deps.push(rank);
        }
        let mut head = 0;
        while head < frontier.len() {
            let dep = frontier[head];
            head += 1;
            for child in self.dep_children(dep) {
                if let std::collections::hash_map::Entry::Vacant(entry) = seen.entry(child) {
                    entry.insert(u32::try_from(order.len()).unwrap_or(u32::MAX));
                    order.push(child);
                    frontier.push(child);
                }
            }
        }
        let mut nodes = Vec::with_capacity(order.len());
        for dep in &order {
            let wire = self.dep_wire(*dep)?;
            nodes.push(SubgraphNode {
                crate_name: stow_types::identity::CrateName::parse(wire.crate_name)
                    .map_err(|e| invalid(e.to_string()))?,
                version: stow_types::identity::CrateVersion::new(
                    semver::Version::parse(&wire.version).map_err(|e| invalid(e.to_string()))?,
                ),
                features_json: stow_types::identity::FeaturesJson::from_sorted(
                    serde_json::from_str(&wire.features).map_err(|e| invalid(e.to_string()))?,
                )
                .map_err(|e| invalid(e.to_string()))?,
                host_side: wire.host_side,
                keys_apart: wire.keys_apart,
                deps: wire.deps.iter().map(|child| seen[child]).collect(),
            });
        }
        Ok(BuildTaskPayload {
            task_id,
            attempt: node.attempt,
            crate_name: stow_types::identity::CrateName::parse(self.intern.at(node.key.crate_name))
                .map_err(|e| invalid(e.to_string()))?,
            version: stow_types::identity::CrateVersion::new(
                semver::Version::parse(self.intern.at(node.key.version))
                    .map_err(|e| invalid(e.to_string()))?,
            ),
            features_json: stow_types::identity::FeaturesJson::from_sorted(
                serde_json::from_str(self.intern.at(node.key.features))
                    .map_err(|e| invalid(e.to_string()))?,
            )
            .map_err(|e| invalid(e.to_string()))?,
            target: stow_types::identity::TargetTriple::parse(self.intern.at(node.key.target))
                .map_err(|e| invalid(e.to_string()))?,
            rustc_version: stow_types::identity::WireRustcVersion::parse(
                self.intern.at(node.key.rustc),
            )
            .map_err(|e| invalid(e.to_string()))?,
            preserve_lockfile: node.preserve_lockfile,
            host_side: node.key.host_side,
            explicit_spelling: if node.explicit_spelling {
                ExplicitSpelling::KeysApart
            } else {
                ExplicitSpelling::KeysAsNative
            },
            dependency_subgraph: TaskSubgraph { root_deps, nodes },
        })
    }

    /// A dep identity's children — live node edges or published deps.
    fn dep_children(&self, dep: DepKey) -> Vec<DepKey> {
        if let Some(ident) = self.published_idents.get(&dep) {
            return ident.deps.clone();
        }
        if let Some(ix) = self.dep_node(dep) {
            return self.edges_of(ix).iter().map(|edge| edge.dep).collect();
        }
        Vec::new()
    }

    /// A dep identity's wire fields from a live node or the published
    /// arena; the store is corrupt when the identity is absent.
    fn dep_wire(&self, dep: DepKey) -> Result<DepWire, QueueError> {
        let fields = |deps: Vec<DepKey>, keys_apart: bool| DepWire {
            crate_name: self.intern.at(dep.crate_name).to_owned(),
            version: self.intern.at(dep.version).to_owned(),
            features: self.intern.at(dep.features).to_owned(),
            host_side: dep.host_side,
            keys_apart,
            deps,
        };
        if let Some(ident) = self.published_idents.get(&dep) {
            return Ok(fields(ident.deps.clone(), ident.explicit_spelling));
        }
        if let Some(ix) = self.dep_node(dep) {
            let node = self.node(ix);
            let deps = self.edges_of(ix).iter().map(|edge| edge.dep).collect();
            return Ok(fields(deps, node.explicit_spelling));
        }
        Err(QueueError::Invariant(format!(
            "dep {} has no node or published identity",
            self.intern.at(dep.dep_identity)
        )))
    }

    /// The promote lane's id-only submit (kept against memory, review
    /// Q4): known ids re-queue or answer published; unknown ids report.
    pub fn submit_by_ids(&mut self, entries: &[SubmitTaskIdEntry]) -> (u32, Vec<String>) {
        let mut inserted = 0;
        let mut unknown = Vec::new();
        for entry in entries {
            if let Some(ix) = self.node_ix(&entry.task_id) {
                let node = self.node_mut(ix);
                node.downloads = node.downloads.max(entry.downloads);
                if node.status == Status::Failed {
                    node.status = Status::Pending;
                    node.attempt = 1;
                    node.error = None;
                }
                self.refresh_ready(ix);
                inserted += 1;
            } else {
                let interned = self.intern.get(&entry.task_id);
                let published = interned.is_some_and(|tid| {
                    self.published_idents
                        .values()
                        .any(|ident| ident.task_id == tid)
                });
                if !published {
                    unknown.push(entry.task_id.clone());
                }
            }
        }
        (inserted, unknown)
    }

    /// `GET /status` counts — computed from the arena, no trigger.
    pub fn status_counts(&self) -> BTreeMap<&'static str, u64> {
        let mut counts = BTreeMap::new();
        for node in &self.nodes {
            let label = match node.status {
                Status::Pending if node.blocked => "blocked",
                Status::Pending => "pending",
                Status::Dispatched => "dispatched",
                Status::Running => "running",
                Status::Completed => "completed",
                Status::Failed => "failed",
                Status::Published => continue,
            };
            *counts.entry(label).or_insert(0) += 1;
        }
        counts
    }

    /// The earliest instant an alarm may make progress: the smallest
    /// `not_before`/age gate over dispatchable pending nodes, and the
    /// earliest in-flight lease expiry. `Some(now)` means work is
    /// claimable already.
    pub fn next_wake(&self, now: i64, dispatch_min_age_ms: i64, stale_ms: i64) -> Option<i64> {
        if self.freeze.is_some() {
            return None;
        }
        let mut wake: Option<i64> = None;
        for node in &self.nodes {
            match node.status {
                Status::Pending if node.unmet == 0 && !node.blocked => {
                    let age_gate = if node.lane == Lane::Human {
                        0
                    } else {
                        dispatch_min_age_ms
                    };
                    let eligible_at = (node.first_requested + age_gate).max(node.not_before);
                    if eligible_at <= now {
                        return Some(now);
                    }
                    if wake.is_none_or(|w| eligible_at < w) {
                        wake = Some(eligible_at);
                    }
                }
                Status::Dispatched | Status::Running => {
                    let expiry = node.claimed_at + stale_ms;
                    if expiry > now && wake.is_none_or(|w| expiry < w) {
                        wake = Some(expiry);
                    }
                }
                _ => {}
            }
        }
        wake
    }

    /// The freeze record while engaged.
    pub const fn freeze(&self) -> Option<&stow_types::api::DispatchFreezeRecord> {
        self.freeze.as_ref()
    }

    /// Set or clear the freeze record.
    pub fn set_freeze(&mut self, record: Option<stow_types::api::DispatchFreezeRecord>) {
        self.freeze = record;
    }

    /// The admission floor.
    pub const fn floor(&self) -> i64 {
        self.floor
    }

    /// Stamp the admission floor and re-evaluate eligibility.
    pub fn set_floor(&mut self, floor: i64) {
        self.floor = floor;
        for ix in 0..u32::try_from(self.nodes.len()).unwrap_or(u32::MAX) {
            self.refresh_ready(ix);
        }
    }

    /// Per-(crate,target) expected build cost (median of the sample
    /// window) — the rank's cost operand.
    pub fn expected_cost(&self, crate_name: &str, target: &str) -> i64 {
        let key = (self.intern.get(crate_name), self.intern.get(target));
        match key {
            (Some(c), Some(t)) => self.build_stats.get(&(c, t)).map_or(1, |samples| {
                let mut sorted = samples.clone();
                sorted.sort_unstable();
                sorted[sorted.len() / 2]
            }),
            _ => 1,
        }
    }

    /// External occupancy (runs the scheduler did not dispatch).
    pub fn external_total(&self) -> u32 {
        u32::try_from(self.external_runs.len()).unwrap_or(u32::MAX)
    }

    /// Apply one decoded log event — the replay half of wake. The
    /// submit reassembly buffer lives in `store.rs`; this handles the
    /// one-row-per-event kinds.
    pub fn apply(&mut self, event: &SchedulerEvent, now: i64) {
        match event {
            SchedulerEvent::SliceReport {
                target,
                rustc_version,
                added,
                retired,
                ..
            } => {
                self.apply_slice_report(target.as_str(), rustc_version.as_str(), added, retired);
            }
            SchedulerEvent::Claims { claims } => {
                for claim in claims {
                    if let Some(ix) = self.node_ix(&claim.task_id) {
                        let node = self.node_mut(ix);
                        if node.status == Status::Pending {
                            node.status = Status::Dispatched;
                            node.generation = claim.generation;
                            node.attempt = claim.attempt;
                            node.claimed_at = now;
                            node.run_id = 0;
                            self.next_generation = self.next_generation.max(claim.generation);
                        }
                    }
                }
            }
            SchedulerEvent::Bindings { bindings } => {
                for binding in bindings {
                    if let Ok(run_id) = binding.run_id.parse::<u64>() {
                        self.bind(&binding.task_id, binding.generation, run_id, now);
                    }
                }
            }
            SchedulerEvent::ExternalRunStarted { run_id, family } => {
                if let Ok(run_id) = run_id.parse::<u64>() {
                    self.external_runs.insert(run_id, 1u8 << (*family as u8));
                }
            }
            SchedulerEvent::RunFinished {
                run_id,
                task_id,
                success,
                cancelled,
                error,
            } => {
                if let Ok(run_id) = run_id.parse::<u64>() {
                    self.run_finished(task_id, run_id, *success, *cancelled, error.clone(), now);
                }
            }
            SchedulerEvent::Mutate { op, task_ids } => {
                self.mutate(*op, task_ids);
            }
            SchedulerEvent::Demand { entries, .. } => {
                self.fold_demand(
                    &entries
                        .iter()
                        .map(|entry| (entry.task_id.clone(), entry.delta))
                        .collect::<Vec<_>>(),
                );
            }
            SchedulerEvent::Freeze { record } => {
                self.freeze = record.as_deref().cloned();
            }
            SchedulerEvent::Floor { value } => {
                self.set_floor(*value);
            }
            SchedulerEvent::BuildSample {
                crate_name,
                target,
                duration_ms,
            } => {
                let c = self.intern.intern(crate_name.as_str());
                let t = self.intern.intern(target.as_str());
                let samples = self.build_stats.entry((c, t)).or_default();
                if samples.len() >= SAMPLE_WINDOW {
                    samples.remove(0);
                }
                samples.push(i64::try_from(*duration_ms).unwrap_or(i64::MAX));
            }
            // `Submit` parts are reassembled by the replay loop in
            // `store.rs` before this is reached; `Request` lifecycle
            // events land with the request-lane cutover (stage 7).
            SchedulerEvent::Submit { .. } | SchedulerEvent::Request { .. } => {}
        }
    }
}

impl Graph {
    /// `[head, intern, nodes, edges, published, idents]` section part
    /// counts — each part serializes one bounded slice.
    fn section_counts(&self) -> [usize; 6] {
        [
            1,
            self.intern.strings.len().div_ceil(INTERN_PART),
            self.nodes.len().div_ceil(NODE_PART),
            self.edges.len().div_ceil(EDGE_PART),
            self.published.len().div_ceil(PAIR_PART),
            self.published_idents.len().div_ceil(IDENT_PART),
        ]
    }

    /// The number of `snapshot_chunks` rows one snapshot writes.
    pub fn snapshot_chunk_count(&self) -> usize {
        self.section_counts().iter().sum()
    }

    /// Serialize one snapshot chunk — the caller iterates
    /// `0..snapshot_chunk_count()`, so peak memory is one part's
    /// bytes, never the whole image (stow#878 review).
    ///
    /// # Errors
    /// `QueueError::Invariant` when a part fails to serialize.
    pub fn snapshot_chunk(&self, index: usize) -> Result<Option<SnapshotChunk>, QueueError> {
        let counts = self.section_counts();
        if index == 0 {
            let head = SnapshotHead {
                next_generation: self.next_generation,
                floor: self.floor,
                meter: self.meter.clone(),
                freeze: self.freeze.clone(),
                external_runs: self.external_runs.iter().map(|(&k, &v)| (k, v)).collect(),
                build_stats: self
                    .build_stats
                    .iter()
                    .map(|(&k, v)| (k, v.clone()))
                    .collect(),
            };
            return Ok(Some(SnapshotChunk {
                tag: "head",
                payload: Self::encode(&head)?,
            }));
        }
        let mut at = index - 1;
        macro_rules! slice {
            ($len:expr, $part:expr) => {{
                let start = at * $part;
                (start, (start + $part).min($len))
            }};
        }
        if at < counts[1] {
            let (s, e) = slice!(self.intern.strings.len(), INTERN_PART);
            return Ok(Some(SnapshotChunk {
                tag: "intern",
                payload: Self::encode(&self.intern.strings[s..e].to_vec())?,
            }));
        }
        at -= counts[1];
        if at < counts[2] {
            let (s, e) = slice!(self.nodes.len(), NODE_PART);
            return Ok(Some(SnapshotChunk {
                tag: "nodes",
                payload: Self::encode(&self.nodes[s..e].to_vec())?,
            }));
        }
        at -= counts[2];
        if at < counts[3] {
            let (s, e) = slice!(self.edges.len(), EDGE_PART);
            return Ok(Some(SnapshotChunk {
                tag: "edges",
                payload: Self::encode(&self.edges[s..e].to_vec())?,
            }));
        }
        at -= counts[3];
        if at < counts[4] {
            let mut pairs: Vec<(DepKey, u8)> =
                self.published.iter().map(|(&k, &v)| (k, v)).collect();
            pairs.sort_unstable();
            let (s, e) = slice!(pairs.len(), PAIR_PART);
            return Ok(Some(SnapshotChunk {
                tag: "published",
                payload: Self::encode(&pairs[s..e])?,
            }));
        }
        at -= counts[4];
        if at < counts[5] {
            let mut pairs: Vec<(DepKey, PublishedIdentity)> = self
                .published_idents
                .iter()
                .map(|(&k, v)| (k, v.clone()))
                .collect();
            pairs.sort_unstable_by_key(|(k, _)| *k);
            let (s, e) = slice!(pairs.len(), IDENT_PART);
            return Ok(Some(SnapshotChunk {
                tag: "idents",
                payload: Self::encode(&pairs[s..e])?,
            }));
        }
        Ok(None)
    }

    fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, QueueError> {
        serde_json::to_vec(value)
            .map_err(|error| QueueError::Invariant(format!("snapshot encode: {error}")))
    }

    /// Rebuild a graph from its ordered snapshot chunks and rebuild
    /// every derived index (`ids`, `by_key`, `dep_index`, `ready`).
    ///
    /// # Errors
    /// `QueueError::Invariant` on an unknown tag or corrupt payload.
    pub fn from_snapshot_chunks(chunks: &[SnapshotChunk]) -> Result<Self, QueueError> {
        fn decode<T: for<'a> Deserialize<'a>>(tag: &str, bytes: &[u8]) -> Result<T, QueueError> {
            serde_json::from_slice(bytes)
                .map_err(|error| QueueError::Invariant(format!("snapshot {tag} decode: {error}")))
        }
        let mut graph = Self::default();
        let mut published = Vec::new();
        let mut idents = Vec::new();
        for chunk in chunks {
            match chunk.tag {
                "head" => {
                    let head: SnapshotHead = decode("head", &chunk.payload)?;
                    graph.next_generation = head.next_generation;
                    graph.floor = head.floor;
                    graph.meter = head.meter;
                    graph.freeze = head.freeze;
                    graph.external_runs = head.external_runs.into_iter().collect();
                    graph.build_stats = head.build_stats.into_iter().collect();
                }
                "intern" => {
                    graph
                        .intern
                        .strings
                        .extend(decode::<Vec<Box<str>>>("intern", &chunk.payload)?);
                }
                "nodes" => {
                    graph
                        .nodes
                        .extend(decode::<Vec<Node>>("nodes", &chunk.payload)?);
                }
                "edges" => {
                    graph
                        .edges
                        .extend(decode::<Vec<Edge>>("edges", &chunk.payload)?);
                }
                "published" => {
                    published.extend(decode::<Vec<(DepKey, u8)>>("published", &chunk.payload)?);
                }
                "idents" => {
                    idents.extend(decode::<Vec<(DepKey, PublishedIdentity)>>(
                        "idents",
                        &chunk.payload,
                    )?);
                }
                other => {
                    return Err(QueueError::Invariant(format!(
                        "unknown snapshot chunk tag {other}"
                    )));
                }
            }
        }
        graph.intern.index = graph
            .intern
            .strings
            .iter()
            .enumerate()
            .map(|(ix, s)| (s.clone(), u32::try_from(ix).unwrap_or(u32::MAX)))
            .collect();
        graph.published = published.into_iter().collect();
        graph.published_idents = idents.into_iter().collect();
        graph.rebuild_indexes();
        Ok(graph)
    }

    /// Rebuild every index the snapshot does not carry.
    fn rebuild_indexes(&mut self) {
        for (ix, node) in self.nodes.iter().enumerate() {
            self.ids
                .insert(node.task_id, u32::try_from(ix).unwrap_or(u32::MAX));
            if node.status != Status::Published {
                self.by_key
                    .insert(node.key, u32::try_from(ix).unwrap_or(u32::MAX));
            }
        }
        for (edge_ix, edge) in self.edges.iter().enumerate() {
            self.dep_index
                .entry(edge.dep)
                .or_default()
                .push(u32::try_from(edge_ix).unwrap_or(u32::MAX));
        }
        for ix in 0..u32::try_from(self.nodes.len()).unwrap_or(u32::MAX) {
            self.refresh_ready(ix);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stow_types::api::MutationKind;
    use stow_types::identity::{
        CrateName, CrateVersion, DependencyIdentity, FeaturesJson, TargetTriple, WireRustcVersion,
    };
    use stow_types::public_cache::{UnitInvocation, UnitKind, UnitSide};

    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const RUSTC: &str = "1.85.0";

    fn sub(name: &str) -> SubmissionNode {
        SubmissionNode {
            task_id: format!("{name}-id"),
            crate_name: CrateName::parse(name).expect("crate name"),
            version: CrateVersion::new(semver::Version::new(1, 0, 0)),
            features_json: FeaturesJson::from_sorted(Vec::new()).expect("features"),
            target: TargetTriple::parse(TARGET).expect("target"),
            rustc_version: WireRustcVersion::parse(RUSTC).expect("rustc"),
            host_side: false,
            explicit_spelling: ExplicitSpelling::KeysAsNative,
            preserve_lockfile: false,
            dependency_identity: DependencyIdentity::from_task_ids([name]).expect("dep identity"),
            deps: Vec::new(),
            downloads: 10,
        }
    }

    /// A → B → C chain (a depends on b, b on c), nodes in leaf order.
    fn chain() -> SubmissionTree {
        let mut c = sub("c");
        let mut b = sub("b");
        let a = sub("a");
        b.deps = vec![0];
        c.deps = Vec::new();
        let mut a_node = a;
        a_node.deps = vec![1];
        SubmissionTree {
            source: SubmissionSource::CacheMiss,
            roots: vec![2],
            nodes: vec![c, b, a_node],
        }
    }

    fn published_row(name: &str, kind: UnitKind) -> PublishedSliceRow {
        PublishedSliceRow {
            crate_name: CrateName::parse(name).expect("crate"),
            version: CrateVersion::new(semver::Version::new(1, 0, 0)),
            features_json: FeaturesJson::from_sorted(Vec::new()).expect("features"),
            unit_shape: UnitShape {
                side: UnitSide::Target,
                invocation: UnitInvocation::Native,
                kind,
            },
            dependency_identity: DependencyIdentity::from_task_ids([name]).expect("dep identity"),
        }
    }

    #[test]
    fn merge_inserts_and_dedups_by_task_id() {
        let mut graph = Graph::default();
        let report = graph.merge(&chain(), 1000).expect("merge");
        assert_eq!((report.inserted, report.merged), (3, 0));
        let report = graph.merge(&chain(), 2000).expect("remerge");
        assert_eq!((report.inserted, report.merged), (0, 3));
        assert_eq!(graph.status_counts()["pending"], 3);
    }

    #[test]
    fn gate_blocks_until_dep_publishes() {
        let mut graph = Graph::default();
        graph.merge(&chain(), 0).expect("merge");
        // Only the leaf is ready; a and b sit behind unmet edges.
        assert_eq!(graph.ready.len(), 1);
        let claimed = graph.claim(45, 16, 0, 3_600_000).expect("claim");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].task_id, "c-id");
    }

    #[test]
    fn publish_flips_edges_and_releases_dependents() {
        let mut graph = Graph::default();
        graph.merge(&chain(), 0).expect("merge");
        graph.claim(45, 16, 0, 3_600_000).expect("claim c");
        graph.run_finished("c-id", 100, true, false, None, 50_000);
        let flips = graph.apply_slice_report(
            TARGET,
            RUSTC,
            &[
                published_row("c", UnitKind::Linked),
                published_row("c", UnitKind::Unlinked),
            ],
            &[],
        );
        assert_eq!(flips, 1, "b's edge to c flips");
        let c = graph.node_ix("c-id").expect("tombstone");
        assert_eq!(graph.node(c).status, Status::Published);
        let claimed = graph.claim(45, 16, 60_000, 3_600_000).expect("claim b");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].task_id, "b-id");
        // The payload's subgraph rebuilds c from the published arena.
        assert_eq!(claimed[0].payload.dependency_subgraph.nodes.len(), 1);
        assert_eq!(
            claimed[0].payload.dependency_subgraph.nodes[0]
                .crate_name
                .as_str(),
            "c"
        );
    }

    #[test]
    fn completion_without_binding_parks_and_applies_on_bind() {
        let mut graph = Graph::default();
        let mut nodes = vec![sub("solo")];
        nodes[0].deps = Vec::new();
        graph
            .merge(
                &SubmissionTree {
                    source: SubmissionSource::CacheMiss,
                    roots: vec![0],
                    nodes,
                },
                0,
            )
            .expect("merge");
        let claimed = graph.claim(45, 16, 0, 3_600_000).expect("claim");
        let generation = claimed[0].generation;
        let outcome = graph.run_finished("solo-id", 4242, true, false, None, 10_000);
        assert_eq!(outcome, FinishOutcome::Parked);
        assert!(graph.bind("solo-id", generation, 4242, 11_000));
        let ix = graph.node_ix("solo-id").expect("node");
        assert_eq!(graph.node(ix).status, Status::Completed);
    }

    #[test]
    fn failure_retries_then_fails_and_blocks_dependents() {
        let mut graph = Graph::default();
        graph.merge(&chain(), 0).expect("merge");
        let claimed = graph.claim(45, 16, 0, 3_600_000).expect("claim c");
        graph.bind("c-id", claimed[0].generation, 77, 1_000);
        for _ in 1..queue::MAX_BUILD_ATTEMPTS {
            graph.run_finished("c-id", 77, false, false, Some("boom".into()), 2_000);
            let ix = graph.node_ix("c-id").expect("node");
            assert_eq!(graph.node(ix).status, Status::Pending);
            graph.node_mut(ix).not_before = 0;
            graph.refresh_ready(ix);
            let claimed = graph.claim(45, 16, 3_000, 3_600_000).expect("reclaim");
            graph.bind("c-id", claimed[0].generation, 77, 4_000);
        }
        graph.run_finished("c-id", 77, false, false, Some("boom".into()), 5_000);
        let ix = graph.node_ix("c-id").expect("node");
        assert_eq!(graph.node(ix).status, Status::Failed);
        let b = graph.node_ix("b-id").expect("b");
        assert!(graph.node(b).blocked);
        assert_eq!(graph.ready.len(), 0);
        let affected = graph.mutate(MutationKind::Retry, &["c-id".to_owned()]);
        assert_eq!(affected, 1);
        assert!(!graph.node(graph.node_ix("b-id").expect("b")).blocked);
    }

    #[test]
    fn stale_lease_reclaims_dispatch() {
        let mut graph = Graph::default();
        graph
            .merge(
                &SubmissionTree {
                    source: SubmissionSource::CacheMiss,
                    roots: vec![0],
                    nodes: vec![sub("solo")],
                },
                0,
            )
            .expect("merge");
        graph.claim(45, 16, 0, 3_600_000).expect("claim");
        let claimed = graph.claim(45, 16, 4_000_000, 3_600_000).expect("stale");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].task_id, "solo-id");
    }

    #[test]
    fn submit_ids_promotes_known_and_reports_unknown() {
        let mut graph = Graph::default();
        graph.merge(&chain(), 0).expect("merge");
        let (inserted, unknown) = graph.submit_by_ids(&[
            SubmitTaskIdEntry {
                task_id: "a-id".into(),
                downloads: 5,
            },
            SubmitTaskIdEntry {
                task_id: "ghost".into(),
                downloads: 5,
            },
        ]);
        assert_eq!(inserted, 1);
        assert_eq!(unknown, vec!["ghost"]);
    }

    #[test]
    fn snapshot_round_trip_preserves_state() {
        let mut graph = Graph::default();
        graph.merge(&chain(), 0).expect("merge");
        graph.claim(45, 16, 0, 3_600_000).expect("claim");
        graph.run_finished("c-id", 100, true, false, None, 10_000);
        graph.apply_slice_report(
            TARGET,
            RUSTC,
            &[
                published_row("c", UnitKind::Linked),
                published_row("c", UnitKind::Unlinked),
            ],
            &[],
        );
        graph.meter.roll_to("2026-10-23");
        graph.meter.record("test", 7, 11);
        let chunks: Vec<SnapshotChunk> = (0..graph.snapshot_chunk_count())
            .map(|ix| graph.snapshot_chunk(ix).expect("part").expect("chunk"))
            .collect();
        let mut restored = Graph::from_snapshot_chunks(&chunks).expect("load");
        assert_eq!(restored.status_counts(), graph.status_counts());
        assert_eq!(restored.meter.rows_written, 11);
        let claimed = restored.claim(45, 16, 20_000, 3_600_000).expect("claim b");
        assert_eq!(claimed[0].task_id, "b-id");
    }

    #[test]
    fn cancelled_completion_requeues_without_attempt() {
        let mut graph = Graph::default();
        graph
            .merge(
                &SubmissionTree {
                    source: SubmissionSource::CacheMiss,
                    roots: vec![0],
                    nodes: vec![sub("solo")],
                },
                0,
            )
            .expect("merge");
        let claimed = graph.claim(45, 16, 0, 3_600_000).expect("claim");
        graph.bind("solo-id", claimed[0].generation, 9, 1_000);
        let outcome = graph.run_finished("solo-id", 9, false, true, None, 2_000);
        assert_eq!(outcome, FinishOutcome::Applied);
        let ix = graph.node_ix("solo-id").expect("node");
        assert_eq!(graph.node(ix).status, Status::Pending);
        assert_eq!(graph.node(ix).attempt, 1);
    }

    #[test]
    fn external_runs_count_occupancy() {
        let mut graph = Graph::default();
        let outcome = graph.run_started("nobodys-task", 555, RunnerFamily::Linux);
        assert_eq!(outcome, StartOutcome::External);
        assert_eq!(graph.external_total(), 1);
        graph.run_finished("nobodys-task", 555, true, false, None, 0);
        assert_eq!(graph.external_total(), 0);
    }
}
