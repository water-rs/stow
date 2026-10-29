//! The scheduler's in-memory dependency graph (stow#878).
//!
//! Nodes, edges, per-node state and the ready set live here and nowhere
//! else: every accepted event mutates this structure and lands in the
//! flat log before it is acknowledged (`store.rs`); a wake rebuilds the
//! whole structure from a snapshot plus the log tail.
//!
//! Layout is sized against the 128 MiB object bound (`target/878-plan.md`
//! §2): a node is one fixed 68-byte record in an arena, its strings
//! interned once as `u32` ids and its dependency digest an inline
//! 32-byte value; its task id is never stored but re-minted from those
//! fields. The queue state of a node that has not published rides a
//! 48-byte slab entry, freed on publish; the fields few nodes carry sit
//! in a side table. Edges are flat `u32` arrays — forward spans per node
//! plus a CSR reverse index — and the ready set holds node indexes
//! only, ordered at claim time. A published node stays only while a
//! retained node still depends on it (dispatch payloads carry dependency
//! identities) and is dropped, with its edges, once its last dependent
//! is gone; a compaction squeezes the dropped records out. Every
//! derived index (id and identity tables, reverse edges, ready set,
//! counters) is rebuilt on load; the snapshot carries only the
//! irreducible state.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use stow_types::api::{
    BuildTaskPayload, PublishedSliceRow, RunnerFamily, SchedulerEvent, SubgraphNode,
    SubmissionNode, SubmissionTree, SubmitTaskIdEntry, TaskSubgraph, runner_family,
};
use stow_types::ci::{CiRunListing, CiRunStatus};
use stow_types::public_cache::{ExplicitSpelling, UnitShape};
use stow_types::task_graph::canonical_task_id;

use crate::errors::QueueError;
use crate::scheduler::queue;

mod edges;
mod index;
mod node;
mod snapshot;

use edges::Edges;
use index::{Interner, IxTable, hash_of};
use node::{Extra, Flags, Lane, NO_STATE, Node, ParkedCompletion, State, Status};

pub use snapshot::{ChunkSpan, SNAPSHOT_SPAN_ROWS, SnapshotLoader, SnapshotPlan, SpanEncoder};

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

/// The 16-byte key a task id keys the published-shape map by: the
/// leading bytes of the BLAKE3 hash of its canonical string.
type IdKey = [u8; 16];

/// An index slice: its target and rustc ids.
type SliceId = (u8, u8);

/// One published task id's entry: the unit shapes it serves and the
/// slice that reported them, so a full report can replace its slice's
/// set.
#[derive(Debug, Clone, Copy)]
struct Published {
    mask: u8,
    slice: SliceId,
}

/// The probe keys of one canonical task id.
#[derive(Debug, Clone, Copy)]
struct IdKeys {
    /// Probe key of the id index.
    tag: u32,
    /// Key of the published-shape map.
    key: IdKey,
}

impl IdKeys {
    fn of(task_id: &str) -> Self {
        let hash = blake3::hash(task_id.as_bytes());
        let bytes = hash.as_bytes();
        let tag = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let mut key = [0u8; 16];
        key.copy_from_slice(&bytes[..16]);
        Self { tag, key }
    }
}

/// What the graph derives once per target triple it has seen.
#[derive(Debug)]
struct TargetInfo {
    name: Box<str>,
    /// The runner family the target builds on.
    family: Option<RunnerFamily>,

    /// The unit shapes a node of this target must publish, indexed by
    /// `[host_side][explicit_spelling]`.
    own_masks: [[u8; 2]; 2],
}

impl TargetInfo {
    fn new(name: &str) -> Self {
        let mask = |host: bool, explicit: bool| {
            node_published_mask(
                host,
                name,
                if explicit {
                    ExplicitSpelling::KeysApart
                } else {
                    ExplicitSpelling::KeysAsNative
                },
            )
        };
        Self {
            name: name.into(),
            family: runner_family(name),
            own_masks: [
                [mask(false, false), mask(false, true)],
                [mask(true, false), mask(true, true)],
            ],
        }
    }
}

/// One operand class's candidate in a claim's k-way merge: its claim
/// key (rank, then request instant, then arrival — descending) and the
/// node index.
type Candidate = ((i128, std::cmp::Reverse<i64>, std::cmp::Reverse<u32>), u32);

/// The class a failed attempt is counted under — the error's first
/// line, capped so a stack dump cannot explode the class list, or
/// `unknown` for a failure that carried no error (`None` on success
/// or cancellation, which the freeze window never counts).
fn failure_class_of(success: bool, error: Option<&str>) -> Option<String> {
    const MAX_PREFIX_CHARS: usize = 200;
    if success {
        return None;
    }
    Some(
        error
            .and_then(|error| error.lines().next())
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map_or_else(
                || "unknown".to_owned(),
                |line| line.chars().take(MAX_PREFIX_CHARS).collect(),
            ),
    )
}
/// The scheduler's self-counted billed rows (stow#931): the one-row
/// `meter` table checkpoints the day totals at each wake and snapshot;
/// this is the in-memory copy the metering backend's settle folds
/// into. `seq` is the last `event_log` seq whose append cost the
/// totals already cover — replay re-counts only rows past it.
#[derive(Debug, Default, Clone)]
pub struct Meter {
    /// UTC day (`YYYY-MM-DD`) the counters apply to.
    pub day: String,
    /// Rows the DO read today.
    pub rows_read: u64,
    /// Rows the DO wrote today.
    pub rows_written: u64,
    /// The last `event_log` seq the totals cover — the checkpoint's
    /// `seq` column.
    pub seq: i64,
    /// Per-operation ledger for the budget probe — `ops` carries
    /// `(statements, rows_read, rows_written)`. It rides the snapshot
    /// head alone: per-op counts cannot be re-counted on replay
    /// (stow#928).
    pub ops: BTreeMap<String, (u64, u64, u64)>,
}

impl Meter {
    /// Roll the counters at a UTC-day boundary — the daily budget the
    /// breaker evaluates is per UTC day. Forward only: an event or a
    /// settle stamped on an earlier day than the meter's belongs to a
    /// day the meter no longer tracks, and rolling back would zero
    /// today's restored totals (stow#931).
    pub fn roll_to(&mut self, day: &str) {
        if self.day.as_str() < day {
            day.clone_into(&mut self.day);
            self.rows_read = 0;
            self.rows_written = 0;
        }
    }

    /// Book billed rows against the day.
    pub const fn add(&mut self, rows_read: u64, rows_written: u64) {
        self.rows_read += rows_read;
        self.rows_written += rows_written;
    }

    /// Book one operation's billed rows under its ledger entry.
    pub fn record(&mut self, op: &str, rows_read: u64, rows_written: u64) {
        self.add(rows_read, rows_written);
        let slot = self.ops.entry(op.to_owned()).or_default();
        slot.0 += 1;
        slot.1 += rows_read;
        slot.2 += rows_written;
    }

    /// Re-count one replayed log row at its append's billed cost — one
    /// written row plus the `RETURNING seq` read (stow#931). Rows at or
    /// under `seq` are already inside the checkpointed totals; rows
    /// past it died with the isolate that booked them, so the wake
    /// books them again. A row stamped on an earlier day than the
    /// meter's was still billed after the checkpoint that set `seq` —
    /// its append ran on or after the restored day — so it books on
    /// the meter's current day, the same convention `settle` uses,
    /// and `roll_to` keeps the restored day from ever moving
    /// backwards.
    pub fn replayed(&mut self, at_ms: i64, seq: i64) {
        if seq <= self.seq {
            return;
        }
        self.seq = seq;
        let day = utc_day(at_ms);
        self.roll_to(&day);
        self.add(1, 1);
    }
}

/// The UTC day (`YYYY-MM-DD`) of a unix-ms instant — the meter's key.
pub fn utc_day(ms: i64) -> String {
    format_utc(ms)[..10].to_owned()
}

/// One demand-feed hour — the `demand_feed_hours` row plus its
/// `demand_feed_pages` staging, replayed through `Feed` events
/// (stow#878 stage 7).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FeedSession {
    /// The generation stamp — the begin's unix-second attempt id,
    /// monotonically bumped on rotate.
    pub generation: i64,
    /// `staging` | `complete` | `delivered`.
    pub state: String,
    /// Pages staged under the live generation.
    pub staged_pages: u32,
    /// Entries staged under the live generation.
    pub staged_entries: u32,
    /// Pages the delivery has already folded into `Demand` events —
    /// `deliver` applies page `applied_pages` next.
    pub applied_pages: u32,
    /// The declared page count the `Complete` barrier recorded.
    pub page_count: u32,
    /// The declared entry total the `Complete` barrier recorded.
    pub entry_count: i64,
    /// Staged pages — `staged[i]` is page `i`'s wire entries; the
    /// deliver loop folds page `applied_pages` next. Emptied on the
    /// terminal `Deliver`.
    pub staged: Vec<Vec<stow_types::api::SchedulerDemandEntry>>,
    /// Ordered page hashes — the complete-manifest check's material.
    pub page_hashes: Vec<String>,
    /// Ordered chain hashes — `chain[i]` is blake3(chain[i-1] +
    /// `page_hashes[i]`) — the manifest's last element.
    pub chain_hashes: Vec<String>,
}

/// One completed attempt — the `attempt_outcomes_v2` /
/// `attempt_outcome_buckets` equivalent, folded in-place at event
/// apply and pruned by the freeze window at read (stow#878 stage 7).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttemptOutcome {
    /// The task's interned id resolved to its string.
    pub task_id: String,
    /// The minted generation the attempt ran under.
    pub generation_id: String,
    /// The attempt that ran.
    pub attempt: u32,
    /// The CI target the trip tallies on.
    pub target: String,
    /// `Some(first error line)` on failure, `None` on success.
    pub failure_class: Option<String>,
    /// The platform run id, when the binding carried one.
    pub run_id: String,
    /// When the completion landed (unix ms).
    pub finished_at_ms: i64,
}

/// The ring's bound — the window filter happens at read, so the cap
/// only bounds memory.
const ATTEMPT_OUTCOME_CAP: usize = 4_096;

/// One request-lane record — the `requests` table's row carried in
/// memory and replayed through `Request` events (stow#878 stage 7).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RequestRecord {
    /// The admission the first attempt stored.
    pub admission: Box<stow_types::api::RequestAdmission>,
    /// The live attempt — `RunUpdated`/`Outcome` events fence on it.
    pub attempt: u32,
    /// The unix-second dispatch stamp.
    pub dispatched_at: i64,
    /// `accepted` | `resolving` | `enqueued` | `failed`.
    pub state: String,
    /// The resolve run's title/id once `in_progress` lands.
    pub run_id: Option<String>,
    /// The resolve run's URL once `in_progress` lands.
    pub run_url: Option<String>,
    /// The serialized stored roots once `enqueued`.
    pub outcome_json: Option<String>,
    /// The failure reason once `failed`.
    pub error: Option<String>,
}

/// The whole in-memory graph. Nothing here serializes whole: the
/// snapshot (`snapshot.rs`) walks it one byte-bounded chunk at a time,
/// and a wake decodes it one chunk at a time — neither side ever holds
/// the graph's image in memory (stow#878 review).
#[derive(Debug, Default)]
pub struct Graph {
    /// Crate names, versions and feature lists, each stored once.
    intern: Interner,
    /// Every target triple the graph holds a node for; a node's
    /// `target` byte indexes it.
    targets: Vec<TargetInfo>,
    /// Likewise the rustc versions.
    rustcs: Vec<Box<str>>,
    /// Task-id probe index over `nodes`, keyed by `Node::id_tag`.
    /// Freed nodes stay in it until the next compaction and are
    /// skipped.
    ids: IxTable,
    /// Identity probe index — `(crate, version, features, target,
    /// rustc)` of every node, either side, any digest: the demand
    /// feed's root lookup.
    idents: IxTable,
    /// The node arena. Indexes are stable between compactions and
    /// compactions keep creation order.
    nodes: Vec<Node>,
    /// Queue state of the nodes that have not published.
    states: Vec<State>,
    /// Vacant `states` slots, reused before the slab grows.
    free_states: Vec<u32>,
    /// The rare per-node fields; see [`Extra`].
    extras: HashMap<u32, Extra>,
    /// Forward edges and the reverse index.
    edges: Edges,
    /// Published unit-shape mask per task id.
    published: HashMap<IdKey, Published>,
    /// The task ids each slice serves, derived from `published`: a full
    /// report retires the slice's stale ids from here, so its cost is
    /// the slice's own size rather than the whole map's.
    slice_members: HashMap<SliceId, HashSet<IdKey>>,
    /// The generation of the index each reported slice last applied.
    slice_generations: BTreeMap<SliceId, i64>,
    /// Dispatchable pending nodes, one age-ordered queue per rank
    /// operand (the node's priority, stow#879): `operand →
    /// BTreeSet<(first_requested, ix)>`. Within a class the oldest
    /// node ranks highest, so a claim reads only each class's oldest
    /// eligible entry — O(classes) per pick instead of an O(ready)
    /// re-rank, and the operand re-keys only when a merge raises the
    /// priority.
    ready: BTreeMap<i64, BTreeSet<(i64, u32)>>,
    /// Dispatched and running nodes.
    inflight: BTreeSet<u32>,
    /// Nodes per [`Status`].
    counts: [u32; Status::COUNT],
    /// Pending nodes whose blocked flag is set. With `counts`,
    /// `human_pending` and `pending_ages` it is the pending index
    /// [`Graph::index_pending`] keeps, so the status reads never walk
    /// the arena (stow#932).
    pending_blocked: u32,
    /// Pending nodes on the miss lane — what `STOW_MAX_QUEUE_PENDING`
    /// bounds, so preheat, operations and human backlog never count
    /// against a CLI miss.
    pending_miss: u32,
    /// Pending nodes on the human lane: `GET /status`'s
    /// `human_pending` is its length, and a human node's lane position
    /// compares only these.
    human_pending: BTreeSet<u32>,
    /// Pending nodes per `first_requested` instant, which never changes
    /// while a node holds queue state: the oldest pending request is
    /// its first key.
    pending_ages: BTreeMap<i64, u32>,
    /// External `build-crate.yml` runs (stow#877): run id → family bit.
    external_runs: HashMap<u64, u8>,
    /// The dispatch freeze record while engaged.
    freeze: Option<stow_types::api::DispatchFreezeRecord>,
    /// The recent freeze transitions, oldest first, bounded by
    /// [`FREEZE_HISTORY`] — the `GET /dispatch-freeze` log.
    freeze_history: std::collections::VecDeque<stow_types::api::DispatchFreezeTransition>,
    /// The admission floor (`min_dispatch_value`).
    floor: i64,
    /// The operator's dispatch-cap setting (stow#1039): replaces the
    /// deploy bindings' `STOW_MAX_CONCURRENT_JOBS` /
    /// `STOW_MAX_CONCURRENT_MACOS_JOBS` at claim time until the next
    /// `set`. `None` until the first one.
    dispatch_cap: Option<stow_types::api::DispatchCapSetting>,

    /// Completions and failures per UTC hour and target byte — the
    /// admin status's trailing-day tally, since a published node keeps
    /// no state to count.
    outcome_hours: BTreeMap<(i64, u8), (u32, u32)>,
    /// The next claim generation — monotonic, snapshot-carried.
    next_generation: u64,
    /// When the run listing was last attempted, succeeded or not —
    /// memory only: a wake reconciles at once. A failed attempt counts
    /// too, so a failing listing waits out the interval instead of
    /// re-arming the alarm at once (stow#940).
    reconcile_attempted_at: i64,
    /// Generations this isolate's dispatch pass claimed but has not
    /// yet settled (stow#940) — in memory only, so a woken graph
    /// parks nothing: a completion for a replayed dispatched-unbound
    /// claim binds the run and finishes the claim outright.
    settling: HashSet<u64>,
    /// The instant the last `workflow_run` delivery was accepted —
    /// the event's own `at` (stow#860). `None` until the first
    /// delivery; every delivery event's apply stamps it (`RunFinished`,
    /// `ExternalRunStarted`, `Request` `RunUpdated`, and the bare
    /// `RunUpdate` marker the own-run `in_progress` channel appends).
    pub last_run_update_ms: Option<i64>,
    /// The request lane's records — the `requests` table's rows,
    /// replayed by `Request` events (stow#878 stage 7).
    pub requests: std::collections::BTreeMap<String, RequestRecord>,
    /// Human-lane daily spend the `human_daily_task_budget` row held —
    /// `(unix-day index, task_count)`, the same UTC-day rollover
    /// `date('now')` gave the table.
    pub human_budget: (i64, i64),
    /// The sliding-window evidence the dispatch-freeze trip reads —
    /// every applied run outcome, capped; the window filter happens
    /// at read so replay needs no setting.
    pub attempt_outcomes: std::collections::VecDeque<AttemptOutcome>,
    /// Demand-feed hours by `YYYY-MM-DDTHH` — staging sessions carry
    /// their pages until `Deliver` folds them.
    pub feed_sessions: std::collections::BTreeMap<String, FeedSession>,
    /// `batch_id` → `(input_hash, touched_count)` — the `demand_batches`
    /// dedup the `/demand` route's replay guard reads.
    pub demand_batches: std::collections::BTreeMap<String, (String, i64)>,
    /// The delivered-hour cursor — `settings`' `watermark` key. Begin
    /// and deliver both fence on the canonical successor.
    pub feed_watermark: Option<String>,
    /// The in-memory billed-row counters.
    pub meter: Meter,
    /// When this graph was loaded — the wake that built it, unix ms. In
    /// memory only: the probe ledger reports it so a reader can tell a
    /// reload, which drops every ledger booking since the snapshot.
    pub woken_at_ms: i64,
    /// The fixture size the budget probe last seeded this store at —
    /// `None` until a seed runs. It rides the snapshot head so `rearm`
    /// and the probe read it from the graph: a `store_meta` row would
    /// bill a statement outside every checkpoint, which the meter's
    /// replay cannot re-count (stow#931).
    pub seeded_rows: Option<u32>,
    /// Log rows appended — or replayed — since the last snapshot; the
    /// trigger `SNAPSHOT_EVENT_THRESHOLD` reads.
    pub log_since_snapshot: u64,
    /// JSON bytes of those rows - the byte trigger
    /// `SNAPSHOT_BYTE_THRESHOLD` reads. Zero after a snapshot (it covers
    /// the whole log), recounted from the tail rows on replay.
    pub log_bytes_since_snapshot: u64,
    /// The chunks the next snapshot rewrites (stow#902): in memory
    /// only — a load and a snapshot write both clear it, and the
    /// replayed tail marks its own changes. `all` once a compaction
    /// renumbered the arena.
    dirty: snapshot::Dirty,
    /// Interned strings the persisted chunks already cover — the
    /// interner's only dirty mark, since it is append-only.
    intern_committed: usize,
}

/// Freeze transitions the graph keeps for `GET /dispatch-freeze`.
const FREEZE_HISTORY: usize = 25;

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
    /// Task ids of the nodes the published mask does not cover — the
    /// miss set the submit's caller logs (stow#886).
    pub unpublished: Vec<String>,
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

/// The 32 bytes a dependency identity's 64 hex digits spell.
fn digest_bytes(identity: &stow_types::identity::DependencyIdentity) -> [u8; 32] {
    let mut digest = [0u8; 32];
    hex::decode_to_slice(identity.as_str(), &mut digest)
        .expect("a dependency identity is 64 lowercase hex digits");
    digest
}

/// The canonical task id a submission node's identity columns spell.
fn minted_id(sub: &SubmissionNode) -> String {
    canonical_task_id(
        sub.crate_name.as_str(),
        &sub.version.to_string(),
        &sub.features_json.raw(),
        sub.target.as_str(),
        sub.rustc_version.as_str(),
        sub.dependency_identity.as_str(),
        sub.host_side,
    )
}

/// The identity-index hash of a node's five-field identity.
fn ident_hash(crate_name: u32, version: u32, features: u32, target: u8, rustc: u8) -> u64 {
    hash_of(&(crate_name, version, features, target, rustc))
}

/// A node to insert.
struct NewNode<'a> {
    crate_name: &'a str,
    version: &'a str,
    features: &'a str,
    target: &'a str,
    rustc: &'a str,
    digest: [u8; 32],
    keys: IdKeys,
    flags: Flags,
    /// `None` inserts the node already published.
    state: Option<State>,
}

/// Node-slab, index and bookkeeping primitives.
impl Graph {
    fn node(&self, ix: u32) -> &Node {
        &self.nodes[ix as usize]
    }

    fn node_mut(&mut self, ix: u32) -> &mut Node {
        self.touch(ix);
        &mut self.nodes[ix as usize]
    }

    /// The queue state of an unpublished node.
    fn state(&self, ix: u32) -> &State {
        let slot = self.node(ix).state;
        assert_ne!(
            slot, NO_STATE,
            "node {ix} is published and holds no queue state"
        );
        &self.states[slot as usize]
    }

    fn state_mut(&mut self, ix: u32) -> &mut State {
        self.touch(ix);
        let slot = self.node(ix).state;
        assert_ne!(
            slot, NO_STATE,
            "node {ix} is published and holds no queue state"
        );
        &mut self.states[slot as usize]
    }

    fn alloc_state(&mut self, state: State) -> u32 {
        if let Some(slot) = self.free_states.pop() {
            self.states[slot as usize] = state;
            slot
        } else {
            self.states.push(state);
            u32::try_from(self.states.len() - 1).expect("state slab holds fewer than 2^32 entries")
        }
    }

    /// The edge range of a node's forward span.
    fn edge_range(&self, ix: u32) -> std::ops::Range<usize> {
        let node = self.node(ix);
        let start = node.edges_start as usize;
        start..start + usize::from(node.edges_len)
    }

    /// The nodes `ix` depends on, once per edge.
    fn deps_of(&self, ix: u32) -> impl Iterator<Item = u32> + '_ {
        self.edge_range(ix).map(|edge| self.edges.dep(edge))
    }

    /// The nodes holding an edge onto `ix`, deduplicated and alive.
    fn dependents_of(&self, ix: u32) -> Vec<u32> {
        let mut owners = self.edges.owners_of(ix);
        owners.sort_unstable();
        owners.dedup();
        owners.retain(|&owner| self.node(owner).status != Status::Free);
        owners
    }

    /// A node's rank operand: its priority — what the rank multiplies
    /// by time waited and what the admission floor compares (stow#879).
    fn operand_of(&self, ix: u32) -> i64 {
        self.state(ix).priority
    }

    /// The node's claim rank: `operand × (now − first_requested)`,
    /// exact in i128 (stow#879).
    fn rank_at(&self, ix: u32, now: i64) -> i128 {
        i128::from(self.operand_of(ix))
            * i128::from(now.saturating_sub(self.state(ix).first_requested).max(0))
    }

    /// Whether a node may dispatch apart from its age/backoff gate.
    fn dispatchable(&self, ix: u32) -> bool {
        let node = self.node(ix);
        node.status == Status::Pending
            && node.unmet == 0
            && !node.flags.blocked()
            && (node.flags.lane() == Lane::Human || self.operand_of(ix) >= self.floor)
    }

    /// Drop a node's ready-set entry, whatever class it sits in.
    /// Call before mutating `priority` — the entry keys on
    /// the operand, so the old key must come out while the operand is
    /// still the one it was inserted under.
    fn remove_ready(&mut self, ix: u32) {
        if !self.node(ix).status.has_state() {
            return;
        }
        let operand = self.operand_of(ix);
        let key = (self.state(ix).first_requested, ix);
        if let Some(class) = self.ready.get_mut(&operand) {
            class.remove(&key);
            if class.is_empty() {
                self.ready.remove(&operand);
            }
        }
    }

    /// Re-evaluate a node's ready-set membership: enters it under its
    /// current operand when dispatchable, leaves it otherwise.
    fn refresh_ready(&mut self, ix: u32) {
        if self.dispatchable(ix) {
            let operand = self.operand_of(ix);
            let first = self.state(ix).first_requested;
            self.ready.entry(operand).or_default().insert((first, ix));
        } else {
            self.remove_ready(ix);
        }
    }

    /// Move a node to `to`, keeping the per-status counters and the
    /// in-flight set.
    fn set_status(&mut self, ix: u32, to: Status) {
        self.touch(ix);
        let from = self.nodes[ix as usize].status;
        if from == to {
            return;
        }
        self.index_pending(ix, false);
        self.nodes[ix as usize].status = to;
        self.index_pending(ix, true);
        self.counts[from.index()] -= 1;
        self.counts[to.index()] += 1;
        if from.in_flight() {
            self.inflight.remove(&ix);
        }
        if to.in_flight() {
            self.inflight.insert(ix);
        }
    }

    /// Add (`on`) or withdraw a node's share of the pending index —
    /// `pending_blocked`, `human_pending` and `pending_ages` — from its
    /// current status and flags; nothing for a node that is not
    /// pending. Every change to a node's status or flags withdraws the
    /// share first and adds it again after.
    fn index_pending(&mut self, ix: u32, on: bool) {
        let node = self.node(ix);
        if node.status != Status::Pending {
            return;
        }
        let blocked = u32::from(node.flags.blocked());
        let human = node.flags.lane() == Lane::Human;
        let miss = u32::from(node.flags.lane() == Lane::Miss);
        let first = self.state(ix).first_requested;
        if on {
            self.pending_blocked += blocked;
            self.pending_miss += miss;
            if human {
                self.human_pending.insert(ix);
            }
            *self.pending_ages.entry(first).or_default() += 1;
        } else {
            self.pending_blocked -= blocked;
            self.pending_miss -= miss;
            if human {
                assert!(
                    self.human_pending.remove(&ix),
                    "pending human node {ix} is missing from the human index"
                );
            }
            let std::collections::btree_map::Entry::Occupied(mut held) =
                self.pending_ages.entry(first)
            else {
                panic!("pending node {ix}'s request instant {first} is missing from the age index");
            };
            *held.get_mut() -= 1;
            if *held.get() == 0 {
                held.remove();
            }
        }
    }

    /// Edit a node's flags, keeping the pending index.
    fn edit_flags(&mut self, ix: u32, edit: impl FnOnce(&mut Flags)) {
        self.index_pending(ix, false);
        edit(&mut self.node_mut(ix).flags);
        self.index_pending(ix, true);
    }

    /// Run `edit` on the node's extra fields, creating the entry on
    /// demand and dropping it again when nothing is left set.
    fn edit_extra<R>(&mut self, ix: u32, edit: impl FnOnce(&mut Extra) -> R) -> R {
        self.touch(ix);
        let extra = self.extras.entry(ix).or_default();
        let result = edit(extra);
        if extra.is_blank() {
            self.extras.remove(&ix);
        }
        result
    }

    fn run_id_of(&self, ix: u32) -> u64 {
        self.extras.get(&ix).map_or(0, |extra| extra.run_id)
    }

    fn generation_of(&self, ix: u32) -> u64 {
        self.extras.get(&ix).map_or(0, |extra| extra.generation)
    }

    fn claimed_at_of(&self, ix: u32) -> i64 {
        self.extras.get(&ix).map_or(0, |extra| extra.claimed_at)
    }

    /// The instant the claim's lease measures from — its own stamp,
    /// pushed forward by each `status` reconcile that lists its run
    /// (stow#943). `claimed_at` alone stays the claim time the admin
    /// status shows; every lease check goes through here.
    fn lease_since_of(&self, ix: u32) -> i64 {
        self.extras
            .get(&ix)
            .map_or(0, |extra| extra.claimed_at.max(extra.lease_at))
    }

    fn not_before_of(&self, ix: u32) -> i64 {
        self.extras.get(&ix).map_or(0, |extra| extra.not_before)
    }

    fn error_of(&self, ix: u32) -> Option<&str> {
        self.extras
            .get(&ix)
            .and_then(|extra| extra.error.as_deref())
    }

    /// This node's own required published shapes.
    fn own_mask(&self, ix: u32) -> u8 {
        let node = self.node(ix);
        self.targets[usize::from(node.target)].own_masks[usize::from(node.flags.host())]
            [usize::from(node.flags.explicit())]
    }

    fn target_id(&mut self, name: &str) -> Result<u8, QueueError> {
        if let Some(at) = self.targets.iter().position(|target| &*target.name == name) {
            return Ok(u8::try_from(at).expect("target ids fit u8"));
        }
        let id = u8::try_from(self.targets.len()).map_err(|_| {
            QueueError::Invariant("the graph holds more than 256 distinct targets".into())
        })?;
        self.targets.push(TargetInfo::new(name));
        Ok(id)
    }

    fn rustc_id(&mut self, name: &str) -> Result<u8, QueueError> {
        if let Some(at) = self.rustcs.iter().position(|rustc| &**rustc == name) {
            return Ok(u8::try_from(at).expect("rustc ids fit u8"));
        }
        let id = u8::try_from(self.rustcs.len()).map_err(|_| {
            QueueError::Invariant("the graph holds more than 256 distinct rustc versions".into())
        })?;
        self.rustcs.push(name.into());
        Ok(id)
    }

    fn target_lookup(&self, name: &str) -> Option<u8> {
        let at = self
            .targets
            .iter()
            .position(|target| &*target.name == name)?;
        Some(u8::try_from(at).expect("target ids fit u8"))
    }

    fn rustc_lookup(&self, name: &str) -> Option<u8> {
        let at = self.rustcs.iter().position(|rustc| &**rustc == name)?;
        Some(u8::try_from(at).expect("rustc ids fit u8"))
    }

    /// Re-mint a node's canonical task id from its fields.
    fn task_id_of(&self, ix: u32) -> String {
        let node = self.node(ix);
        canonical_task_id(
            self.intern.at(node.crate_name),
            self.intern.at(node.version),
            self.intern.at(node.features),
            &self.targets[usize::from(node.target)].name,
            &self.rustcs[usize::from(node.rustc)],
            &hex::encode(node.digest),
            node.flags.host(),
        )
    }

    /// The live node whose canonical task id is `task_id`.
    fn find_id(&self, task_id: &str, keys: IdKeys) -> Option<u32> {
        self.ids.candidates(u64::from(keys.tag)).find(|&ix| {
            let node = self.node(ix);
            node.id_tag == keys.tag && node.status != Status::Free && self.task_id_of(ix) == task_id
        })
    }

    /// The live node whose canonical task id hashes to `key`.
    fn find_key(&self, key: IdKey) -> Option<u32> {
        let tag = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
        self.ids.candidates(u64::from(tag)).find(|&ix| {
            let node = self.node(ix);
            node.id_tag == tag
                && node.status != Status::Free
                && IdKeys::of(&self.task_id_of(ix)).key == key
        })
    }

    /// Look up a node index by task id string.
    fn node_ix(&self, task_id: &str) -> Option<u32> {
        self.find_id(task_id, IdKeys::of(task_id))
    }

    /// Append a node and index it.
    fn insert_node(&mut self, new: &NewNode<'_>) -> Result<u32, QueueError> {
        let ix = u32::try_from(self.nodes.len())
            .map_err(|_| QueueError::Invariant("node count overflows u32".into()))?;
        self.touch(ix);
        let crate_name = self.intern.intern(new.crate_name);
        let version = self.intern.intern(new.version);
        let features = self.intern.intern(new.features);
        let target = self.target_id(new.target)?;
        let rustc = self.rustc_id(new.rustc)?;
        let status = if new.state.is_some() {
            Status::Pending
        } else {
            Status::Published
        };
        let state = new.state.map_or(NO_STATE, |state| self.alloc_state(state));
        self.nodes.push(Node {
            digest: new.digest,
            crate_name,
            version,
            features,
            id_tag: new.keys.tag,
            state,
            edges_start: u32::try_from(self.edges.len())
                .map_err(|_| QueueError::Invariant("edge count overflows u32".into()))?,
            refs: 0,
            edges_len: 0,
            unmet: 0,
            target,
            rustc,
            status,
            flags: new.flags,
        });
        self.counts[status.index()] += 1;
        self.index_pending(ix, true);
        let nodes = &self.nodes;
        self.ids.insert(u64::from(new.keys.tag), ix, |held| {
            u64::from(nodes[held as usize].id_tag)
        });
        self.idents.insert(
            ident_hash(crate_name, version, features, target, rustc),
            ix,
            |held| {
                let node = &nodes[held as usize];
                ident_hash(
                    node.crate_name,
                    node.version,
                    node.features,
                    node.target,
                    node.rustc,
                )
            },
        );
        Ok(ix)
    }

    /// A node becomes published: its queue state goes, and the node
    /// itself goes with it unless a retained node still depends on it.
    fn publish(&mut self, ix: u32) {
        if !self.node(ix).status.has_state() {
            return;
        }
        self.remove_ready(ix);
        self.set_status(ix, Status::Published);
        let slot = std::mem::replace(&mut self.node_mut(ix).state, NO_STATE);
        self.free_states.push(slot);
        self.extras.remove(&ix);
        if self.node(ix).refs == 0 {
            self.release(ix);
        }
    }

    /// Free a published node nothing retained depends on, and every
    /// published node that only it kept alive.
    fn release(&mut self, ix: u32) {
        let mut work = vec![ix];
        while let Some(ix) = work.pop() {
            debug_assert_eq!(self.node(ix).status, Status::Published);
            self.set_status(ix, Status::Free);
            for edge in self.edge_range(ix) {
                let dep = self.edges.dep(edge);
                let held = self.node_mut(dep);
                held.refs -= 1;
                if held.refs == 0 && held.status == Status::Published {
                    work.push(dep);
                }
            }
        }
    }

    /// Squeeze the freed records out once they are an eighth of the
    /// arena.
    fn maybe_compact(&mut self) {
        let dead = self.counts[Status::Free.index()] as usize;
        if dead >= COMPACT_FLOOR && dead * 8 >= self.nodes.len() {
            self.compact();
        }
    }

    /// Drop every freed node and its edges in place. Creation order
    /// survives, so the claim's arrival tie-break is unchanged, and the
    /// derived indexes are rebuilt over the new indexes.
    pub(crate) fn compact(&mut self) {
        /// Remap entry of a dropped node.
        const GONE: u32 = u32::MAX;
        let dead = self.counts[Status::Free.index()];
        if dead == 0 {
            return;
        }
        // Every index renumbers: the next snapshot rewrites all chunks.
        self.dirty.all = true;
        let mut remap = vec![GONE; self.nodes.len()];
        let mut kept = 0u32;
        for (at, node) in self.nodes.iter().enumerate() {
            if node.status != Status::Free {
                remap[at] = kept;
                kept += 1;
            }
        }
        self.edges.compact(
            self.nodes
                .iter()
                .filter(|node| node.status != Status::Free)
                .map(|node| (node.edges_start as usize, usize::from(node.edges_len))),
            &remap,
        );
        let mut write = 0usize;
        let mut edges_end = 0u32;
        for read in 0..self.nodes.len() {
            if self.nodes[read].status == Status::Free {
                continue;
            }
            let mut node = self.nodes[read];
            node.edges_start = edges_end;
            edges_end += u32::from(node.edges_len);
            self.nodes[write] = node;
            write += 1;
        }
        self.nodes.truncate(write);
        self.ready = std::mem::take(&mut self.ready)
            .into_iter()
            .map(|(operand, class)| {
                (
                    operand,
                    class
                        .into_iter()
                        .map(|(first, ix)| (first, remap[ix as usize]))
                        .collect(),
                )
            })
            .collect();
        self.inflight = self
            .inflight
            .iter()
            .map(|&ix| remap[ix as usize])
            .collect::<BTreeSet<_>>();
        self.human_pending = self
            .human_pending
            .iter()
            .map(|&ix| remap[ix as usize])
            .collect::<BTreeSet<_>>();
        self.extras = std::mem::take(&mut self.extras)
            .into_iter()
            .map(|(ix, extra)| (remap[ix as usize], extra))
            .collect();
        self.counts[Status::Free.index()] = 0;
        self.rebuild_indexes_over_nodes();
    }

    /// Rebuild the id and identity tables and the reverse edges over
    /// the current arena.
    fn rebuild_indexes_over_nodes(&mut self) {
        let nodes = &self.nodes;
        let mut ids = IxTable::with_entries(nodes.len());
        let mut idents = IxTable::with_entries(nodes.len());
        for (at, node) in nodes.iter().enumerate() {
            let ix = u32::try_from(at).expect("node indexes fit u32");
            ids.insert(u64::from(node.id_tag), ix, |held| {
                u64::from(nodes[held as usize].id_tag)
            });
            idents.insert(
                ident_hash(
                    node.crate_name,
                    node.version,
                    node.features,
                    node.target,
                    node.rustc,
                ),
                ix,
                |held| {
                    let node = &nodes[held as usize];
                    ident_hash(
                        node.crate_name,
                        node.version,
                        node.features,
                        node.target,
                        node.rustc,
                    )
                },
            );
        }
        self.ids = ids;
        self.idents = idents;
        self.edges.rebuild_reverse(
            nodes.len(),
            nodes.iter().enumerate().map(|(at, node)| {
                (
                    u32::try_from(at).expect("node indexes fit u32"),
                    node.edges_start as usize,
                    usize::from(node.edges_len),
                )
            }),
        );
    }
}

/// Freed nodes below which a compaction is never worth its pass.
const COMPACT_FLOOR: usize = 1_024;

/// Merge, publish and the claim gate.
impl Graph {
    /// Merge one submission tree by task id. `now` is unix ms.
    ///
    /// A node id commits to its subtree: an existing id's edge set is
    /// never rewritten — the merge only ever raises `downloads` and
    /// `priority` on it. New nodes are born gated; each edge's `met`
    /// answers against the published-shape masks at insert. A node
    /// whose own shapes are already published is born published: it
    /// stays only as long as a node of this tree depends on it.
    ///
    /// # Errors
    /// `QueueError::Invariant` on a malformed tree (a root or dep index
    /// out of range, or a task id that does not re-derive from its
    /// identity columns).
    pub fn merge(&mut self, tree: &SubmissionTree, now: i64) -> Result<MergeReport, QueueError> {
        let ids = Self::validate_tree(tree)?;
        let lane = Lane::from_source(tree.source);
        let priority = queue::source_priority(tree.source);
        let mut report = MergeReport::default();
        // Pass 1: find or insert every node by task id.
        let mut node_ixs = Vec::with_capacity(tree.nodes.len());
        let mut is_fresh = Vec::with_capacity(tree.nodes.len());
        let mut fresh = Vec::new();
        for (sub, keys) in tree.nodes.iter().zip(&ids) {
            if let Some(ix) = self.find_id(&sub.task_id, *keys) {
                if self.node(ix).status.has_state() {
                    // A node reached from several entry points takes
                    // the highest priority; its first-requested instant
                    // never moves (stow#879).
                    self.remove_ready(ix);
                    let state = self.state_mut(ix);
                    state.downloads = state.downloads.max(sub.downloads);
                    state.priority = state.priority.max(priority);
                    self.refresh_ready(ix);
                }
                node_ixs.push(ix);
                is_fresh.push(false);
                report.merged += 1;
                if self.node(ix).status != Status::Published {
                    report.unpublished.push(sub.task_id.clone());
                }
                continue;
            }
            let ix = self.insert_new(sub, *keys, lane, priority, now)?;
            node_ixs.push(ix);
            is_fresh.push(true);
            fresh.push(ix);
            if self.node(ix).status == Status::Pending {
                report.inserted += 1;
                report.unpublished.push(sub.task_id.clone());
            } else {
                report.merged += 1;
            }
        }
        if lane == Lane::Human {
            // Human-lane spend folds in here so replay re-charges
            // identically: a human-source merge pays one task per
            // fresh insert (the graph never promotes or resurrects on
            // a remerge — stow#878 stage 7).
            let today = now.div_euclid(86_400_000);
            if self.human_budget.0 != today {
                self.human_budget = (today, 0);
            }
            self.human_budget.1 += i64::from(report.inserted);
        }
        // Pass 2: edges for the fresh nodes only — an existing id's
        // subtree is committed by its first submission.
        for (sub_at, sub) in tree.nodes.iter().enumerate() {
            if is_fresh[sub_at] {
                self.merge_edges(tree, &ids, &node_ixs, sub, node_ixs[sub_at])?;
            }
        }
        // A node born published that nothing in the tree depends on
        // has nothing left to keep.
        for ix in fresh {
            let node = self.node(ix);
            if node.status == Status::Published && node.refs == 0 {
                self.release(ix);
            }
        }
        self.maybe_compact();
        Ok(report)
    }

    /// The tree's shape and identity check, shared by `merge` and
    /// `merge_changes`: roots and deps in range, every task id the
    /// canonical id of its identity columns. Returns each node's probe
    /// keys.
    fn validate_tree(tree: &SubmissionTree) -> Result<Vec<IdKeys>, QueueError> {
        let len = tree.nodes.len();
        if let Some(root) = tree.roots.iter().find(|&&root| root as usize >= len) {
            return Err(QueueError::Invariant(format!(
                "submission root index {root} out of range ({len} nodes)"
            )));
        }
        if let Some(dep) = tree
            .nodes
            .iter()
            .flat_map(|sub| &sub.deps)
            .find(|&&dep| dep as usize >= len)
        {
            return Err(QueueError::Invariant(format!(
                "submission dep index {dep} out of range ({len} nodes)"
            )));
        }
        tree.nodes
            .iter()
            .map(|sub| {
                let minted = minted_id(sub);
                if minted != sub.task_id {
                    return Err(QueueError::Invariant(format!(
                        "submission task id {} does not re-derive from its identity columns ({minted})",
                        sub.task_id
                    )));
                }
                Ok(IdKeys::of(&sub.task_id))
            })
            .collect()
    }

    /// Insert a node no live node holds the id of; born published when
    /// the index already serves its own shapes.
    fn insert_new(
        &mut self,
        sub: &SubmissionNode,
        keys: IdKeys,
        lane: Lane,
        priority: i64,
        now: i64,
    ) -> Result<u32, QueueError> {
        let explicit = sub.explicit_spelling == ExplicitSpelling::KeysApart;
        let target = self.target_id(sub.target.as_str())?;
        let own = self.targets[usize::from(target)].own_masks[usize::from(sub.host_side)]
            [usize::from(explicit)];
        let published = self.published.get(&keys.key).map_or(0, |entry| entry.mask);
        let state = (published & own != own).then_some(State {
            first_requested: now,
            updated: now,
            priority,
            demand: 0,
            downloads: sub.downloads,
            attempt: 1,
            dispatch_attempts: 0,
        });
        self.insert_node(&NewNode {
            crate_name: sub.crate_name.as_str(),
            version: &sub.version.to_string(),
            features: &sub.features_json.raw(),
            target: sub.target.as_str(),
            rustc: sub.rustc_version.as_str(),
            digest: digest_bytes(&sub.dependency_identity),
            keys,
            flags: Flags::new(sub.host_side, explicit, sub.preserve_lockfile, lane),
            state,
        })
    }

    /// Whether merging `tree` would change the graph — a node it adds,
    /// or a `downloads`/`priority` it would raise — after checking the
    /// tree is well formed. A resubmission that changes nothing needs no
    /// log row: replaying it would be a no-op.
    ///
    /// # Errors
    /// `QueueError::Invariant` on a malformed tree, the same tree
    /// [`Graph::merge`] refuses.
    pub fn merge_changes(&self, tree: &SubmissionTree) -> Result<bool, QueueError> {
        let ids = Self::validate_tree(tree)?;
        let priority = queue::source_priority(tree.source);
        for (sub, keys) in tree.nodes.iter().zip(&ids) {
            let Some(ix) = self.find_id(&sub.task_id, *keys) else {
                return Ok(true);
            };
            if !self.node(ix).status.has_state() {
                continue;
            }
            let state = self.state(ix);
            if sub.downloads > state.downloads || state.priority < priority {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// One fresh node's edge list — `merge`'s second pass.
    fn merge_edges(
        &mut self,
        tree: &SubmissionTree,
        ids: &[IdKeys],
        node_ixs: &[u32],
        sub: &SubmissionNode,
        owner: u32,
    ) -> Result<(), QueueError> {
        let owner_explicit = if sub.explicit_spelling == ExplicitSpelling::KeysApart {
            ExplicitSpelling::KeysApart
        } else {
            ExplicitSpelling::KeysAsNative
        };
        let edges_start = u32::try_from(self.edges.len())
            .map_err(|_| QueueError::Invariant("edge count overflows u32".into()))?;
        let mut unmet = 0u16;
        let mut blocked = false;
        for &dep_at in &sub.deps {
            let dep_sub = &tree.nodes[dep_at as usize];
            let dep_ix = node_ixs[dep_at as usize];
            let (invocations, _shapes) = queue::dep_edge_requirements(
                sub.target.as_str(),
                sub.host_side,
                owner_explicit,
                dep_sub.target.as_str(),
                dep_sub.host_side,
                dep_sub.explicit_spelling,
            );
            let required = required_shape_mask(dep_sub.host_side, invocations);
            let published = self
                .published
                .get(&ids[dep_at as usize].key)
                .map_or(0, |entry| entry.mask);
            let met = published & required == required;
            if !met {
                unmet = unmet.checked_add(1).ok_or_else(|| {
                    QueueError::Invariant(format!("task {} has more than 65535 edges", sub.task_id))
                })?;
            }
            let edge = self.edges.push(owner, dep_ix, required, met)?;
            self.touch_edge(edge);
            self.node_mut(dep_ix).refs += 1;
            // A fresh node is blocked when an unmet dep is a live
            // failed node.
            blocked |= !met && self.node(dep_ix).status == Status::Failed;
        }
        let edges_len = u16::try_from(self.edges.len() - edges_start as usize).map_err(|_| {
            QueueError::Invariant(format!("task {} has more than 65535 edges", sub.task_id))
        })?;
        let node = self.node_mut(owner);
        node.edges_start = edges_start;
        node.edges_len = edges_len;
        node.unmet = unmet;
        self.edit_flags(owner, |flags| flags.set_blocked(blocked));
        if self.edges.reverse_stale() {
            self.rebuild_reverse();
        }
        self.refresh_ready(owner);
        Ok(())
    }

    /// Rebuild the reverse edges over the live arena.
    fn rebuild_reverse(&mut self) {
        let nodes = &self.nodes;
        self.edges.rebuild_reverse(
            nodes.len(),
            nodes.iter().enumerate().map(|(at, node)| {
                (
                    u32::try_from(at).expect("node indexes fit u32"),
                    node.edges_start as usize,
                    usize::from(node.edges_len),
                )
            }),
        );
    }

    /// Whether a slice report extends its slice's live generation. A
    /// full report (`base_generation` unset) always does — it replaces
    /// the set and restarts the sequence. A delta applies only on top
    /// of exactly the generation it was diffed against, and publishes
    /// the next one; anything else is a gap the reporter resyncs.
    ///
    /// # Errors
    /// `QueueError::SliceReportConflict` naming the live generation.
    pub fn check_slice_report(
        &self,
        target: &str,
        rustc_version: &str,
        base_generation: Option<i64>,
        generation: i64,
    ) -> Result<(), QueueError> {
        let Some(base) = base_generation else {
            return Ok(());
        };
        let live = self.slice_generation(target, rustc_version);
        if live != Some(base) {
            return Err(QueueError::SliceReportConflict(format!(
                "slice report base generation {base} conflicts with the live generation {}",
                live.map_or_else(|| "none".to_owned(), |live| live.to_string()),
            )));
        }
        if generation != base + 1 {
            return Err(QueueError::SliceReportConflict(format!(
                "slice report generation {generation} is not the generation after its base {base}"
            )));
        }
        Ok(())
    }

    /// The generation a slice last applied, if it was ever reported.
    pub fn slice_generation(&self, target: &str, rustc_version: &str) -> Option<i64> {
        let slice = self
            .target_lookup(target)
            .zip(self.rustc_lookup(rustc_version))?;
        self.slice_generations.get(&slice).copied()
    }

    /// The generation each reported slice last applied, by name.
    pub fn slice_generations(&self) -> Vec<(String, String, i64)> {
        self.slice_generations
            .iter()
            .map(|(&(target, rustc), &generation)| {
                (
                    self.targets[usize::from(target)].name.to_string(),
                    self.rustcs[usize::from(rustc)].to_string(),
                    generation,
                )
            })
            .collect()
    }

    /// Apply a published-slice report: a delta adds and retires unit
    /// shapes; a full report (`base_generation` unset) makes `added`
    /// the slice's whole set, retiring every shape the slice held that
    /// it no longer lists. Flips the edges they touch and drops nodes
    /// whose own shapes are served. Returns the number of edge flips.
    ///
    /// # Panics
    /// When the graph holds more than 256 targets or rustcs — the same
    /// bound every node insert enforces.
    pub fn apply_slice_report(
        &mut self,
        target: &str,
        rustc_version: &str,
        base_generation: Option<i64>,
        generation: i64,
        added: &[PublishedSliceRow],
        retired: &[PublishedSliceRow],
    ) -> u32 {
        let slice = (
            self.target_id(target).expect("target ids fit u8"),
            self.rustc_id(rustc_version).expect("rustc ids fit u8"),
        );
        self.slice_generations.insert(slice, generation);
        let mut flips = 0;
        if base_generation.is_none() {
            flips += self.replace_slice(slice, target, rustc_version, added);
        } else {
            for row in retired {
                flips += self.apply_slice_row(slice, target, rustc_version, row, false);
            }
            for row in added {
                flips += self.apply_slice_row(slice, target, rustc_version, row, true);
            }
        }
        self.maybe_compact();
        flips
    }

    /// A full report: `rows` become the slice's whole set. Cost is the
    /// report's rows plus the slice's own members.
    fn replace_slice(
        &mut self,
        slice: SliceId,
        target: &str,
        rustc: &str,
        rows: &[PublishedSliceRow],
    ) -> u32 {
        let mut next: HashMap<IdKey, u8> = HashMap::new();
        for row in rows {
            let (keys, bit) = Self::slice_row_key(target, rustc, row);
            *next.entry(keys.key).or_default() |= bit;
        }
        let mut flips = 0;
        let stale: Vec<IdKey> = self
            .slice_members
            .get(&slice)
            .into_iter()
            .flatten()
            .filter(|key| !next.contains_key(*key))
            .copied()
            .collect();
        for key in stale {
            flips += self.set_published(slice, key, 0);
        }
        for (key, mask) in next {
            flips += self.set_published(slice, key, mask);
        }
        flips
    }

    /// A slice row's published-map key and shape bit.
    fn slice_row_key(target: &str, rustc: &str, row: &PublishedSliceRow) -> (IdKeys, u8) {
        let task_id = canonical_task_id(
            row.crate_name.as_str(),
            &row.version.to_string(),
            &row.features_json.raw(),
            target,
            rustc,
            row.dependency_identity.as_str(),
            row.unit_shape.side == stow_types::public_cache::UnitSide::Host,
        );
        (IdKeys::of(&task_id), shape_bit(row.unit_shape))
    }

    fn apply_slice_row(
        &mut self,
        slice: SliceId,
        target: &str,
        rustc: &str,
        row: &PublishedSliceRow,
        added: bool,
    ) -> u32 {
        let (keys, bit) = Self::slice_row_key(target, rustc, row);
        let old = self.published.get(&keys.key).map_or(0, |entry| entry.mask);
        let mask = if added { old | bit } else { old & !bit };
        self.set_published(slice, keys.key, mask)
    }

    /// Set one task id's published mask, flip the edges that depend on
    /// it and release the node when its own shapes are covered.
    fn set_published(&mut self, slice: SliceId, key: IdKey, mask: u8) -> u32 {
        let old = self.published.get(&key).map_or(0, |entry| entry.mask);
        if mask != old {
            if mask == 0 {
                self.published.remove(&key);
                if let Some(members) = self.slice_members.get_mut(&slice) {
                    members.remove(&key);
                }
            } else {
                self.published.insert(key, Published { mask, slice });
                self.slice_members.entry(slice).or_default().insert(key);
            }
            self.touch_published(&key);
        }
        let Some(ix) = self.find_key(key) else {
            return 0;
        };
        let mut flips = 0;
        let was_failed = self.node(ix).status == Status::Failed;
        let owners = self.dependents_of(ix);
        let mut touched = Vec::new();
        for &owner in &owners {
            let mut flipped = false;
            for edge in self.edge_range(owner) {
                if self.edges.dep(edge) != ix {
                    continue;
                }
                let required = self.edges.required(edge);
                let met = mask & required == required;
                if self.edges.met(edge) == met {
                    continue;
                }
                self.edges.set_met(edge, met);
                self.touch_edge(u32::try_from(edge).expect("edge indexes fit u32"));
                let node = self.node_mut(owner);
                node.unmet = if met {
                    node.unmet.saturating_sub(1)
                } else {
                    node.unmet + 1
                };
                flips += 1;
                flipped = true;
            }
            if flipped {
                touched.push(owner);
            }
        }
        // A live node whose own published shapes are now covered
        // leaves the queue.
        if mask != 0 && self.node(ix).status.has_state() {
            let own = self.own_mask(ix);
            if mask & own == own {
                self.publish(ix);
            }
        }
        // Edges flipped or the dep left `failed`: recompute blocked
        // from the dependencies still failed.
        let recompute = if was_failed { &owners } else { &touched };
        for &owner in recompute {
            self.refresh_blocked(owner);
        }
        flips
    }

    /// Whether the index reports shapes for a task id the graph no
    /// longer holds a node for — a node that published and was freed.
    pub fn is_published(&self, task_id: &str) -> bool {
        self.node_ix(task_id).is_none()
            && self
                .published
                .get(&IdKeys::of(task_id).key)
                .is_some_and(|entry| entry.mask != 0)
    }

    /// The ids among `ids` that [`Self::is_published`] answers for.
    pub fn published_of(&self, ids: &[String]) -> BTreeSet<String> {
        ids.iter()
            .filter(|id| self.is_published(id))
            .cloned()
            .collect()
    }
}

/// Claims and the run lifecycle.
impl Graph {
    /// Claim up to `total_free` (and `macos_free` for the macOS family)
    /// ready nodes, minting one generation per claim. `now` is unix ms;
    /// nodes whose `not_before` is in the future are skipped. Returns
    /// claims in rank order — the dispatch pass writes ONE `Claims`
    /// event for this set before posting, and ONE `Bindings` row after.
    ///
    /// # Errors
    /// `QueueError::Invariant` when a claimed node's payload cannot be
    /// rebuilt or its target has no runner family.
    pub fn claim(
        &mut self,
        total_free: u32,
        macos_free: u32,
        now: i64,
        stale_ms: i64,
    ) -> Result<Vec<Claimed>, QueueError> {
        // Stale-lease recovery first: in-flight nodes whose claim
        // outlived the lease return to pending.
        let stale: Vec<u32> = self
            .inflight
            .iter()
            .copied()
            .filter(|&ix| self.lease_since_of(ix) + stale_ms <= now)
            .collect();
        for ix in stale {
            self.set_status(ix, Status::Pending);
            self.state_mut(ix).updated = now;
            self.edit_extra(ix, |extra| {
                extra.claimed_at = 0;
                extra.lease_at = 0;
                extra.run_id = 0;
                extra.parked = None;
            });
            self.refresh_ready(ix);
        }
        if self.freeze.is_some() {
            return Ok(Vec::new());
        }
        // The rank is `operand × time waited` (stow#879): within one
        // operand class the oldest entry ranks highest, so the best
        // node of each class is its oldest eligible one and the claim
        // is a k-way merge over class heads — O(classes) per pick,
        // never a re-rank of the ready bulk.
        let mut skipped: BTreeSet<(i64, u32)> = BTreeSet::new();
        let mut claimed = Vec::new();
        let mut macos_taken = 0u32;
        while claimed.len() < total_free as usize {
            let mut best: Option<Candidate> = None;
            for (&operand, class) in &self.ready {
                let candidate = class
                    .iter()
                    .copied()
                    .find(|key| !skipped.contains(key) && self.not_before_of(key.1) <= now);
                let Some((first, ix)) = candidate else {
                    continue;
                };
                // Higher rank first; ties fall to the older
                // first_requested, then the earlier arrival (stow#879).
                let key = (
                    i128::from(operand) * i128::from(now - first),
                    std::cmp::Reverse(first),
                    std::cmp::Reverse(ix),
                );
                if best.is_none_or(|(top, _)| key > top) {
                    best = Some((key, ix));
                }
            }
            let Some((_, ix)) = best else {
                break;
            };
            let target = &self.targets[usize::from(self.node(ix).target)];
            let family = target.family.ok_or_else(|| {
                QueueError::Invariant(format!(
                    "pending task {} targets `{}`, no runner family",
                    self.task_id_of(ix),
                    target.name
                ))
            })?;
            if family == RunnerFamily::MacOs && macos_taken >= macos_free {
                skipped.insert((self.state(ix).first_requested, ix));
                continue;
            }
            let generation = self.next_generation + 1;
            self.mark_claimed(ix, generation, now);
            self.settling.insert(generation);
            if family == RunnerFamily::MacOs {
                macos_taken += 1;
            }
            claimed.push(Claimed {
                task_id: self.task_id_of(ix),
                generation,
                attempt: u32::from(self.state(ix).attempt),
                payload: self.task_payload(ix)?,
            });
        }
        Ok(claimed)
    }

    /// The claim transition shared by [`Self::claim`] and the replay of
    /// a `Claims` event: the node leaves the ready set dispatched under
    /// `generation`, unbound, with its dispatch attempt counted.
    fn mark_claimed(&mut self, ix: u32, generation: u64, now: i64) {
        self.next_generation = self.next_generation.max(generation);
        self.set_status(ix, Status::Dispatched);
        let state = self.state_mut(ix);
        state.dispatch_attempts = state.dispatch_attempts.saturating_add(1);
        state.updated = now;
        self.edit_extra(ix, |extra| {
            extra.generation = generation;
            extra.claimed_at = now;
            extra.lease_at = 0;
            extra.run_id = 0;
            extra.parked = None;
        });
        self.remove_ready(ix);
    }

    /// Bind a dispatch response's run id to a claim's generation, and
    /// consume a completion parked on the claim when one is waiting.
    /// Returns whether the binding applied (false = stale generation).
    pub fn bind(&mut self, task_id: &str, generation: u64, run_id: u64, now: i64) -> bool {
        let Some(ix) = self.node_ix(task_id) else {
            return false;
        };
        if !self.node(ix).status.in_flight() || self.generation_of(ix) != generation {
            return false;
        }
        self.settling.remove(&generation);
        self.state_mut(ix).updated = now;
        let parked = self.edit_extra(ix, |extra| {
            extra.run_id = run_id;
            extra.parked.take()
        });
        if let Some(parked) = parked
            && parked.run_id == run_id
        {
            self.finish_run_inner(ix, parked.success, parked.cancelled, parked.error, now);
        }
        true
    }

    /// A `workflow_dispatch` failure re-queues the claim under the
    /// dispatch backoff its attempt count earns.
    pub fn mark_dispatch_failed(&mut self, task_id: &str, generation: u64, error: &str, now: i64) {
        let Some(ix) = self.node_ix(task_id) else {
            return;
        };
        if !self.node(ix).status.in_flight()
            || self.generation_of(ix) != generation
            || self.run_id_of(ix) != 0
        {
            return;
        }
        self.settling.remove(&generation);
        self.set_status(ix, Status::Pending);
        let state = self.state_mut(ix);
        state.updated = now;
        let backoff = i64::from(queue::dispatch_backoff_minutes(u32::from(
            state.dispatch_attempts,
        ))) * 60_000;
        self.edit_extra(ix, |extra| {
            extra.error = Some(error.into());
            extra.not_before = now + backoff;
            extra.parked = None;
        });
        self.refresh_ready(ix);
    }

    /// A `workflow_run` `in_progress` delivery — forwarded only for a
    /// run the scheduler did not dispatch (stow#940). A delivery naming
    /// a dispatched-but-unbound claim binds it — the run's own record
    /// is the authoritative binding (review Q6's delivery-side leg).
    pub fn run_started(
        &mut self,
        task_id: &str,
        run_id: u64,
        family: RunnerFamily,
        now: i64,
    ) -> StartOutcome {
        if let Some(ix) = self.node_ix(task_id)
            && self.node(ix).status.in_flight()
        {
            let bound = self.run_id_of(ix);
            if bound == run_id || bound == 0 {
                if bound == 0 {
                    self.edit_extra(ix, |extra| extra.run_id = run_id);
                }
                self.set_status(ix, Status::Running);
                self.state_mut(ix).updated = now;
                return StartOutcome::Applied;
            }
            return StartOutcome::Stale;
        }
        let bit = 1u8 << (family as u8);
        if self.external_runs.insert(run_id, bit).is_none() {
            StartOutcome::External
        } else {
            StartOutcome::Stale
        }
    }

    /// Reconcile the run set after a wake (#877, review Q6) and at
    /// most every `STATUS_RECONCILE_MS` while work lives: the `status`
    /// listing is the truth for occupancy — a run title
    /// (`<rustc>-<task_id>`) that names an unbound dispatched claim
    /// re-lands its binding, and a listed own run found `in_progress`
    /// moves to `Running` (stow#940; the listing takes over what the
    /// own-run `in_progress` delivery did). A listed own run also
    /// renews the claim's lease (stow#943): the listing only carries
    /// `queued` and `in_progress` runs, so a claim keeps its dispatch
    /// for as long as its run is known to live — a build may outlast
    /// `STOW_STALE_DISPATCH_MINUTES` without being re-dispatched. A
    /// listed run no live claim matches is external; a run whose
    /// title attributes to no family counts toward the total budget
    /// only, `Occupancy::add_unknown`'s convention.
    pub fn reconcile_runs(&mut self, runs: &[CiRunListing], now: i64) {
        self.reconcile_attempted_at = now;
        self.external_runs.clear();
        for run in runs {
            let task_id = run
                .title
                .split_once('-')
                .map(|(_, task_id)| task_id)
                .unwrap_or_default();
            if let Some(ix) = self.node_ix(task_id)
                && self.node(ix).status.in_flight()
            {
                let bound = self.run_id_of(ix);
                if bound == 0 {
                    let generation = self.generation_of(ix);
                    self.bind(task_id, generation, run.workflow_run_id, now);
                }
                if bound == 0 || bound == run.workflow_run_id {
                    // A parked completion the binding consumed may
                    // already have ended the claim; a listed run that
                    // still holds it renews the lease and moves
                    // `in_progress` to `Running`.
                    if self.node(ix).status.in_flight() {
                        self.edit_extra(ix, |extra| extra.lease_at = now);
                        if self.node(ix).status != Status::Running
                            && run.status == CiRunStatus::InProgress
                        {
                            self.set_status(ix, Status::Running);
                            self.state_mut(ix).updated = now;
                            // First sight of the run holding a runner —
                            // the instant the health rule's staleness
                            // measures from, in place of the
                            // `in_progress` delivery's stamp.
                            self.last_run_update_ms = Some(now);
                        }
                    }
                    continue;
                }
            }
            self.external_runs.insert(
                run.workflow_run_id,
                run.family.map_or(0, |family| 1u8 << (family as u8)),
            );
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
        let stale = if was_external {
            FinishOutcome::External
        } else {
            FinishOutcome::Stale
        };
        let Some(ix) = self.node_ix(task_id) else {
            return stale;
        };
        if !self.node(ix).status.in_flight() {
            return stale;
        }
        let bound = self.run_id_of(ix);
        if bound == 0 {
            if self.settling.contains(&self.generation_of(ix)) {
                // The claim's pass is between its `Claims` row and its
                // settle — the binding lands in this isolate, so the
                // completion waits on it.
                self.edit_extra(ix, |extra| {
                    extra.parked = Some(ParkedCompletion {
                        run_id,
                        success,
                        cancelled,
                        error,
                    });
                });
                return FinishOutcome::Parked;
            }
            // No pass is settling this claim — the `Bindings` row
            // never landed (an eviction replayed the claim
            // dispatched-unbound, or the dispatch answer was lost
            // after GitHub created the run). The completion binds the
            // run itself, exactly as `run_started`'s `bound == 0`
            // path does (stow#940).
            self.edit_extra(ix, |extra| extra.run_id = run_id);
            self.finish_run_inner(ix, success, cancelled, error, now);
            return FinishOutcome::Applied;
        }
        if bound != run_id {
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
        self.state_mut(ix).updated = now;
        let target = self.node(ix).target;
        if !cancelled || success {
            let attempt = self.state(ix).attempt;
            self.dirty.outcomes = true;
            self.attempt_outcomes.push_back(AttemptOutcome {
                task_id: self.task_id_of(ix),
                generation_id: self.generation_of(ix).to_string(),
                attempt: u32::from(attempt.saturating_add(u8::from(!success))),
                target: self.targets[usize::from(target)].name.to_string(),
                failure_class: failure_class_of(success, error.as_deref()),
                run_id: self.run_id_of(ix).to_string(),
                finished_at_ms: now,
            });
            while self.attempt_outcomes.len() > ATTEMPT_OUTCOME_CAP {
                self.attempt_outcomes.pop_front();
            }
        }
        if cancelled && !success {
            // Superseded duplicate — re-queue without an attempt bump.
            self.set_status(ix, Status::Pending);
            self.edit_extra(ix, |extra| {
                extra.run_id = 0;
                extra.claimed_at = 0;
                extra.lease_at = 0;
            });
            self.refresh_ready(ix);
            return;
        }
        if success {
            self.set_status(ix, Status::Completed);
            self.tally_outcome(now, target, true);
            return;
        }
        let state = self.state_mut(ix);
        state.attempt = state.attempt.saturating_add(1);
        let attempt = u32::from(state.attempt);
        if attempt > queue::MAX_BUILD_ATTEMPTS {
            self.set_status(ix, Status::Failed);
            self.edit_extra(ix, |extra| extra.error = error.map(Into::into));
            self.tally_outcome(now, target, false);
            // Dependents waiting on the failed dep become blocked.
            for owner in self.dependents_of(ix) {
                self.refresh_blocked(owner);
            }
        } else {
            self.set_status(ix, Status::Pending);
            let backoff = i64::from(queue::dispatch_backoff_minutes(attempt)) * 60_000;
            self.edit_extra(ix, |extra| {
                extra.error = error.map(Into::into);
                extra.not_before = now + backoff;
            });
            self.refresh_ready(ix);
        }
    }

    /// Count one finished build (or exhausted task) on its UTC hour —
    /// the admin status's trailing-day tally, kept two days.
    fn tally_outcome(&mut self, now: i64, target: u8, completed: bool) {
        let hour = now.div_euclid(3_600_000);
        let tally = self.outcome_hours.entry((hour, target)).or_default();
        if completed {
            tally.0 += 1;
        } else {
            tally.1 += 1;
        }
        let keep_from = hour - OUTCOME_HOURS_KEPT;
        while let Some(entry) = self.outcome_hours.first_entry() {
            if entry.key().0 >= keep_from {
                break;
            }
            entry.remove();
        }
    }
}

/// Trailing hours the outcome tally keeps — a day for the admin
/// window plus the hour being filled.
const OUTCOME_HOURS_KEPT: i64 = 25;

/// Demand, operator mutations, payloads and the counters the routes read.
impl Graph {
    /// The per-task contributions of one demand batch: every unbuilt
    /// node an identity names (either side) plus the unbuilt
    /// dependencies behind its unmet edges, deduped across diamonds and
    /// roots, each carrying the sum of the deltas that reached it.
    ///
    /// # Errors
    /// `QueueError::Overflow` on a delta sum, `QueueError::Invariant`
    /// when a delta would overflow a task's demand — checked for every
    /// task before anything folds, naming the offenders.
    pub fn demand_contributions(
        &self,
        deltas: &BTreeMap<[String; 5], i64>,
    ) -> Result<Vec<(String, i64)>, QueueError> {
        let mut contributions: BTreeMap<u32, i64> = BTreeMap::new();
        for (identity, delta) in deltas {
            let [crate_name, version, features, target, rustc] = identity;
            let (Some(crate_name), Some(version), Some(features), Some(target), Some(rustc)) = (
                self.intern.get(crate_name),
                self.intern.get(version),
                self.intern.get(features),
                self.target_lookup(target),
                self.rustc_lookup(rustc),
            ) else {
                continue;
            };
            let mut walk: Vec<u32> = self
                .idents
                .candidates(ident_hash(crate_name, version, features, target, rustc))
                .filter(|&ix| {
                    let node = self.node(ix);
                    node.status != Status::Free
                        && (
                            node.crate_name,
                            node.version,
                            node.features,
                            node.target,
                            node.rustc,
                        ) == (crate_name, version, features, target, rustc)
                })
                .collect();
            let mut seen: HashSet<u32> = HashSet::new();
            while let Some(ix) = walk.pop() {
                if !matches!(self.node(ix).status, Status::Pending | Status::Failed)
                    || !seen.insert(ix)
                {
                    continue;
                }
                let total = contributions.entry(ix).or_insert(0);
                *total = total.checked_add(*delta).ok_or(QueueError::Overflow {
                    field: "task demand contribution",
                    value: u64::MAX,
                })?;
                for edge in self.edge_range(ix) {
                    if !self.edges.met(edge) {
                        walk.push(self.edges.dep(edge));
                    }
                }
            }
        }
        let mut offending = Vec::new();
        let mut out = Vec::with_capacity(contributions.len());
        for (ix, delta) in contributions {
            let task_id = self.task_id_of(ix);
            if self.state(ix).demand.checked_add(delta).is_none() {
                offending.push(task_id);
            } else {
                out.push((task_id, delta));
            }
        }
        if !offending.is_empty() {
            return Err(QueueError::Invariant(format!(
                "demand would overflow {} task(s): {}",
                offending.len(),
                offending.join(", ")
            )));
        }
        out.sort();
        Ok(out)
    }

    /// An accepted demand batch folded into the affected nodes.
    pub fn fold_demand(&mut self, entries: &[(String, i64)]) {
        for (task_id, delta) in entries {
            if let Some(ix) = self.node_ix(task_id)
                && self.node(ix).status.has_state()
            {
                let state = self.state_mut(ix);
                state.demand = state.demand.saturating_add(*delta);
            }
        }
    }

    /// Operator mutations over explicit task ids. Returns the rows
    /// affected; each verb's own status/lane predicate bounds its
    /// domain, so a selector can only narrow it — `retry` revives only
    /// `failed` rows, `cancel` fails only live ones, `promote` moves
    /// only pending miss-lane rows, `purge` removes only terminal ones.
    pub fn mutate(
        &mut self,
        op: stow_types::api::MutationKind,
        task_ids: &[String],
        now: i64,
    ) -> u32 {
        use stow_types::api::MutationKind;
        let mut affected = 0;
        for task_id in task_ids {
            let Some(ix) = self.node_ix(task_id) else {
                continue;
            };
            let status = self.node(ix).status;
            if !status.has_state() {
                continue;
            }
            // `rose` — the node left `failed`; `fell` — it entered it.
            let (changed, rose, fell) = match op {
                MutationKind::Retry if status == Status::Failed => {
                    self.set_status(ix, Status::Pending);
                    self.state_mut(ix).attempt = 1;
                    self.edit_extra(ix, |extra| {
                        extra.error = None;
                        extra.not_before = 0;
                    });
                    (true, true, false)
                }
                MutationKind::Cancel
                    if matches!(
                        status,
                        Status::Pending | Status::Dispatched | Status::Running
                    ) =>
                {
                    self.set_status(ix, Status::Failed);
                    self.edit_extra(ix, |extra| {
                        extra.error = Some("cancelled by operator".into());
                        extra.parked = None;
                    });
                    self.tally_outcome(now, self.node(ix).target, false);
                    (true, false, true)
                }
                MutationKind::Promote
                    if status == Status::Pending && self.node(ix).flags.lane() != Lane::Human =>
                {
                    self.remove_ready(ix);
                    self.edit_flags(ix, |flags| flags.set_lane(Lane::Human));
                    // The verb's raise is the website class's operand —
                    // what a request someone asked for by name carries.
                    self.state_mut(ix).priority =
                        self.state(ix).priority.max(queue::REQUEST_PRIORITY);
                    (true, false, false)
                }
                MutationKind::Purge if matches!(status, Status::Completed | Status::Failed) => {
                    (true, false, false)
                }
                _ => (false, false, false),
            };
            if !changed {
                continue;
            }
            self.state_mut(ix).updated = now;
            self.remove_ready(ix);
            // A dep entering or leaving `failed` flips its dependents'
            // blocked flag.
            if rose || fell {
                for owner in self.dependents_of(ix) {
                    self.refresh_blocked(owner);
                }
            }
            if op == MutationKind::Purge {
                // A purged failed node leaves `failed` by publishing;
                // its dependents recompute once it has.
                let owners = if status == Status::Failed {
                    self.dependents_of(ix)
                } else {
                    Vec::new()
                };
                self.publish(ix);
                for owner in owners {
                    self.refresh_blocked(owner);
                }
            } else {
                self.refresh_ready(ix);
            }
            affected += 1;
        }
        self.maybe_compact();
        affected
    }

    /// Recompute `owner`'s blocked flag from its unmet failed
    /// dependencies and re-evaluate its ready-set membership —
    /// O(`owner`'s edges). Every path that changes a dependency's
    /// failed state or an edge's met state ends here.
    fn refresh_blocked(&mut self, owner: u32) {
        if !self.node(owner).status.has_state() {
            return;
        }
        let blocked = self.has_failed_dep(owner);
        self.edit_flags(owner, |flags| flags.set_blocked(blocked));
        self.refresh_ready(owner);
    }

    /// Whether any unmet edge of `owner` points at a live failed node.
    fn has_failed_dep(&self, owner: u32) -> bool {
        self.edge_range(owner).any(|edge| {
            !self.edges.met(edge) && self.node(self.edges.dep(edge)).status == Status::Failed
        })
    }

    /// Rebuild a claimed node's `BuildTaskPayload` — identity fields
    /// plus the dependency subgraph walked over the retained nodes
    /// (stow#588's contract, from memory).
    ///
    /// # Errors
    /// `QueueError::Invariant` when a dep identity no longer decodes —
    /// memory corruption, since identities were typed at merge.
    pub fn task_payload(&self, ix: u32) -> Result<BuildTaskPayload, QueueError> {
        let task_id = self.task_id_of(ix);
        let invalid =
            |error: String| QueueError::Invariant(format!("claimed task {task_id}: {error}"));
        // BFS over dep nodes; visit order is the wire order.
        let mut seen: HashMap<u32, u32> = HashMap::new();
        let mut order: Vec<u32> = Vec::new();
        let mut root_deps = Vec::new();
        for dep in self.deps_of(ix) {
            let rank = *seen.entry(dep).or_insert_with(|| {
                order.push(dep);
                u32::try_from(order.len() - 1).unwrap_or(u32::MAX)
            });
            root_deps.push(rank);
        }
        let mut head = 0;
        while head < order.len() {
            let dep = order[head];
            head += 1;
            for child in self.deps_of(dep) {
                if let std::collections::hash_map::Entry::Vacant(entry) = seen.entry(child) {
                    entry.insert(u32::try_from(order.len()).unwrap_or(u32::MAX));
                    order.push(child);
                }
            }
        }
        let mut nodes = Vec::with_capacity(order.len());
        for &dep in &order {
            let node = self.node(dep);
            let identity = self.identity_of(node).map_err(|e| invalid(e.to_string()))?;
            nodes.push(SubgraphNode {
                crate_name: identity.crate_name,
                version: identity.version,
                features_json: identity.features_json,
                host_side: node.flags.host(),
                keys_apart: node.flags.explicit(),
                deps: self.deps_of(dep).map(|child| seen[&child]).collect(),
            });
        }
        let node = self.node(ix);
        let identity = self.identity_of(node).map_err(|e| invalid(e.to_string()))?;
        Ok(BuildTaskPayload {
            task_id: task_id.clone(),
            attempt: u32::from(self.state(ix).attempt),
            crate_name: identity.crate_name,
            version: identity.version,
            features_json: identity.features_json,
            target: identity.target,
            rustc_version: identity.rustc_version,
            preserve_lockfile: node.flags.preserve(),
            host_side: node.flags.host(),
            explicit_spelling: if node.flags.explicit() {
                ExplicitSpelling::KeysApart
            } else {
                ExplicitSpelling::KeysAsNative
            },
            dependency_subgraph: TaskSubgraph { root_deps, nodes },
        })
    }

    /// The promote lane's id-only submit: a known id raises its
    /// downloads and priority in place, any other id is reported
    /// unknown — never re-minted. A node that published and was freed
    /// is unknown too: its build is in the index and there is nothing
    /// left to raise.
    pub fn submit_by_ids(&mut self, entries: &[SubmitTaskIdEntry]) -> (u32, Vec<String>) {
        let mut inserted = 0;
        let mut unknown = Vec::new();
        for entry in entries {
            let Some(ix) = self.node_ix(&entry.task_id) else {
                unknown.push(entry.task_id.clone());
                continue;
            };
            if self.node(ix).status.has_state() {
                self.remove_ready(ix);
                let state = self.state_mut(ix);
                state.downloads = state.downloads.max(entry.downloads);
                // A re-requested id is miss-class demand (stow#879):
                // the lane's source priority, never a computed one.
                state.priority = state.priority.max(queue::MISS_PRIORITY);
                self.refresh_ready(ix);
            }
            inserted += 1;
        }
        (inserted, unknown)
    }

    /// The longest a `running` run may go without a `workflow_run`
    /// delivery before the health check calls deliveries stopped
    /// (stow#860): a started `build-crate.yml` run must have delivered
    /// `completed` within its jobs' enforced timeouts. An idle
    /// scheduler, or one whose runs are only dispatched/queued, is
    /// never unhealthy on this rule.
    const DELIVERY_STALE_MS: i64 = stow_types::api::BUILD_CRATE_RUN_TIMEOUT_MINUTES * 60_000;

    /// `GET /api/v1/scheduler/health`'s body (stow#860): reads only
    /// state the graph already holds. The scheduler is unhealthy when
    /// the dispatch freeze is engaged, or when a run is `running` (its
    /// `workflow_run` `in_progress` was accepted) and no delivery has
    /// been accepted within [`Self::DELIVERY_STALE_MS`] — including a
    /// running run with no delivery ever recorded, whose `running`
    /// state a post-wake reconcile restored.
    pub fn health(&self, now: i64) -> stow_types::api::SchedulerHealth {
        let age_seconds = self
            .last_run_update_ms
            .map(|at| u64::try_from((now - at).max(0) / 1_000).unwrap_or(u64::MAX));
        let deliveries_stale = self.counts[Status::Running.index()] > 0
            && self
                .last_run_update_ms
                .is_none_or(|at| now - at > Self::DELIVERY_STALE_MS);
        let scheduler = if self.freeze.is_some() || deliveries_stale {
            stow_types::api::HealthState::Unhealthy
        } else {
            stow_types::api::HealthState::Ok
        };
        stow_types::api::SchedulerHealth {
            worker: stow_types::api::HealthState::Ok,
            scheduler,
            dispatch_frozen: self.freeze.is_some(),
            freeze_trigger: self
                .freeze
                .as_ref()
                .map(|record| record.trigger.kind().to_owned()),
            last_run_update_age_seconds: age_seconds,
        }
    }

    /// `GET /status`'s body, read from the counters the status changes
    /// keep — constant work whatever the graph holds.
    pub fn status(&self) -> stow_types::api::SchedulerStatus {
        let count = |status: Status| self.counts[status.index()];
        stow_types::api::SchedulerStatus {
            pending: count(Status::Pending),
            human_pending: u32::try_from(self.human_pending.len())
                .expect("the human index holds arena indexes, fewer than 2^32"),
            dispatched: count(Status::Dispatched),
            running: count(Status::Running),
            completed: count(Status::Completed),
            failed: count(Status::Failed),
            blocked: self.pending_blocked,
        }
    }

    /// The operator's stored `dispatch-cap set` (stow#1039), `None`
    /// until the first one. Only the scheduler object reads it, to
    /// build the settings a request or the alarm runs under
    /// ([`queue::SchedulerSettings::with_dispatch_cap`]); the graph's
    /// own cap reads take those settings as given.
    pub const fn dispatch_cap(&self) -> Option<&stow_types::api::DispatchCapSetting> {
        self.dispatch_cap.as_ref()
    }

    /// Drop the stored dispatch-cap setting — the budget drives'
    /// restore of the unset state the fixture seed wrote, made the
    /// store's state by the snapshot the caller writes next. No route
    /// reaches it: an operator `set` has no clear.
    pub fn restore_unset_dispatch_cap(&mut self) {
        self.dispatch_cap = None;
    }

    /// `GET /dispatch-cap`'s body: the caps `settings` carries — the
    /// ones a claim under them reads — and the stored operator setting
    /// behind them, if any (stow#1039).
    pub fn dispatch_cap_view(
        &self,
        settings: &queue::SchedulerSettings,
    ) -> stow_types::api::DispatchCaps {
        let max_concurrent_jobs = match settings.dispatch {
            queue::Dispatch::Limited(limit) => limit.get(),
            queue::Dispatch::Paused => 0,
        };
        stow_types::api::DispatchCaps {
            setting: self.dispatch_cap.clone(),
            max_concurrent_jobs,
            max_concurrent_macos_jobs: settings.max_concurrent_macos_jobs,
        }
    }

    /// Dispatch slots free under `settings`: the cap minus in-flight and
    /// external occupancy, in total and for the macOS family. A cap
    /// below the in-flight count saturates at zero — nothing in flight
    /// is moved.
    pub fn free_slots(&self, settings: &queue::SchedulerSettings) -> (u32, u32) {
        let (inflight, macos_inflight) = self.inflight();
        let total = match settings.dispatch {
            queue::Dispatch::Limited(limit) => limit.get(),
            queue::Dispatch::Paused => 0,
        }
        .saturating_sub(inflight)
        .saturating_sub(self.external_total());
        let macos = settings
            .max_concurrent_macos_jobs
            .saturating_sub(macos_inflight)
            .saturating_sub(self.external_family(RunnerFamily::MacOs));
        (total, macos)
    }

    /// Return a completed, unpublished node to the queue as never
    /// claimed - the budget fixture's re-arm of a run its lanes resolved.
    /// Reports whether the node was completed.
    pub fn reopen_completed(&mut self, task_id: &str) -> bool {
        let Some(ix) = self.node_ix(task_id) else {
            return false;
        };
        if self.node(ix).status != Status::Completed {
            return false;
        }
        self.set_status(ix, Status::Pending);
        self.state_mut(ix).attempt = 0;
        self.extras.remove(&ix);
        self.refresh_ready(ix);
        true
    }

    /// The wake the graph plans: the earliest instant an alarm can make
    /// progress, or a delete when nothing can. Pending work counts only
    /// while a slot is free for it and it clears the floor, its
    /// dependencies and its age gate; in-flight work counts by its lease
    /// expiry. `Now` means work is claimable already.
    pub fn wake_plan(&self, now: i64, settings: &queue::SchedulerSettings) -> queue::AlarmPlan {
        if self.freeze.is_some() {
            return queue::AlarmPlan::Delete;
        }
        // A due run-listing reconcile is timer work of its own: the
        // request passes that skip it — the completion's bounded pass
        // (stow#940) — leave it to the alarm.
        if self.reconcile_due(now, settings) {
            return queue::AlarmPlan::At(now);
        }
        let min_age = i64::from(settings.dispatch_min_age_minutes) * 60_000;
        let stale = i64::from(settings.stale_dispatch_minutes) * 60_000;
        let (free, macos_free) = self.free_slots(settings);
        let mut wake: Option<i64> = None;
        if free > 0 {
            for &(_, ix) in self.ready.values().flatten() {
                let node = self.node(ix);
                let macos =
                    self.targets[usize::from(node.target)].family == Some(RunnerFamily::MacOs);
                if macos && macos_free == 0 {
                    continue;
                }
                let age_gate = if node.flags.lane() == Lane::Human {
                    0
                } else {
                    min_age
                };
                let eligible_at =
                    (self.state(ix).first_requested + age_gate).max(self.not_before_of(ix));
                if eligible_at <= now {
                    return queue::AlarmPlan::At(now);
                }
                if wake.is_none_or(|w| eligible_at < w) {
                    wake = Some(eligible_at);
                }
            }
        }
        for &ix in &self.inflight {
            let expiry = self.lease_since_of(ix) + stale;
            if expiry > now && wake.is_none_or(|w| expiry < w) {
                wake = Some(expiry);
            }
        }
        wake.map_or(queue::AlarmPlan::Delete, queue::AlarmPlan::At)
    }

    /// The recent freeze transitions, newest first.
    pub fn freeze_transitions(&self) -> Vec<stow_types::api::DispatchFreezeTransition> {
        self.freeze_history.iter().rev().cloned().collect()
    }

    /// The freeze record while engaged.
    pub const fn freeze(&self) -> Option<&stow_types::api::DispatchFreezeRecord> {
        self.freeze.as_ref()
    }

    /// Stamp the admission floor (`min_dispatch_value`, a deploy
    /// binding — never persisted) and re-evaluate eligibility when it
    /// moved.
    pub fn set_floor(&mut self, floor: i64) {
        if self.floor == floor {
            return;
        }
        self.floor = floor;
        for ix in 0..u32::try_from(self.nodes.len()).expect("node indexes fit u32") {
            self.refresh_ready(ix);
        }
    }

    /// Whether a task id names a node the graph holds.
    pub fn has_task(&self, task_id: &str) -> bool {
        self.node_ix(task_id).is_some()
    }

    /// The graph's held sizes: `(nodes, edges, published)` — live
    /// nodes, their dependency edges, and published task ids.
    pub fn sizes(&self) -> (u64, u64, u64) {
        let live = self.nodes.len() - self.counts[Status::Free.index()] as usize;
        (
            live as u64,
            self.edges.len() as u64,
            self.published.len() as u64,
        )
    }

    /// The miss lane's pending depth, which `STOW_MAX_QUEUE_PENDING`
    /// gates: work other lanes queued is not the miss lane's to bound.
    pub const fn miss_pending_depth(&self) -> u32 {
        self.pending_miss
    }

    /// External occupancy by runner family (stow#877).
    pub fn external_family(&self, family: RunnerFamily) -> u32 {
        u32::try_from(
            self.external_runs
                .values()
                .filter(|&&bit| bit & (1u8 << (family as u8)) != 0)
                .count(),
        )
        .unwrap_or(u32::MAX)
    }

    /// In-flight (dispatched + running) count, total and per family.
    pub fn inflight(&self) -> (u32, u32) {
        let macos = self
            .inflight
            .iter()
            .filter(|&&ix| {
                self.targets[usize::from(self.node(ix).target)].family == Some(RunnerFamily::MacOs)
            })
            .count();
        (
            u32::try_from(self.inflight.len()).unwrap_or(u32::MAX),
            u32::try_from(macos).unwrap_or(u32::MAX),
        )
    }

    /// `status` reconciles the delivery-tracked external set at most
    /// once per [`stow_types::api::STATUS_RECONCILE_MS`] — ≤2 listing
    /// calls each, ≤12 calls/hour while the queue has work (stow#877).
    pub(super) const STATUS_RECONCILE_MS: i64 = stow_types::api::STATUS_RECONCILE_MS;

    /// Whether the run listing is due for another reconcile:
    /// [`Self::STATUS_RECONCILE_MS`] passed since the last attempt and
    /// the listing can change what a pass does — in-flight work, or
    /// dispatchable work while dispatch is not paused (a paused
    /// scheduler claims nothing whatever the occupancy). An idle or
    /// paused-and-drained scheduler never asks.
    pub fn reconcile_due(&self, now: i64, settings: &queue::SchedulerSettings) -> bool {
        now - self.reconcile_attempted_at >= Self::STATUS_RECONCILE_MS
            && (!self.inflight.is_empty()
                || (!self.ready.is_empty()
                    && !matches!(settings.dispatch, queue::Dispatch::Paused)))
    }

    /// A listing attempt that failed: the next one waits the interval
    /// like a successful one, and the delivery-tracked state stands.
    pub const fn reconcile_failed(&mut self, now: i64) {
        self.reconcile_attempted_at = now;
    }

    /// External occupancy (runs the scheduler did not dispatch).
    pub fn external_total(&self) -> u32 {
        u32::try_from(self.external_runs.len()).unwrap_or(u32::MAX)
    }

    /// Heap bytes the arenas, tables and edge arrays hold — the
    /// layout's measured size, apart from the side states.
    #[cfg(test)]
    pub(crate) fn heap_bytes(&self) -> usize {
        self.intern.heap_bytes()
            + self.ids.heap_bytes()
            + self.idents.heap_bytes()
            + self.nodes.capacity() * size_of::<Node>()
            + self.states.capacity() * size_of::<State>()
            + self.edges.heap_bytes()
            + self.published.capacity() * (size_of::<IdKey>() + size_of::<Published>())
            + self.published.len() * size_of::<IdKey>()
            + self.ready.len() * (size_of::<i64>() + size_of::<BTreeSet<(i64, u32)>>())
            + self.ready.values().map(BTreeSet::len).sum::<usize>() * (size_of::<(i64, u32)>() + 32)
    }
}

impl Graph {
    /// A `Freeze` event: set or clear the record and log the transition.
    fn apply_freeze(
        &mut self,
        record: Option<&stow_types::api::DispatchFreezeRecord>,
        at: &str,
        trigger: &stow_types::api::DispatchFreezeTrigger,
    ) {
        self.freeze = record.cloned();
        self.freeze_history
            .push_back(stow_types::api::DispatchFreezeTransition {
                at: at.to_owned(),
                event: if record.is_some() {
                    stow_types::api::FreezeTransitionEvent::Engaged
                } else {
                    stow_types::api::FreezeTransitionEvent::Cleared
                },
                trigger: Some(trigger.clone()),
            });
        while self.freeze_history.len() > FREEZE_HISTORY {
            self.freeze_history.pop_front();
        }
    }

    /// Count `bytes` appended to (or replayed from) the log since the
    /// last snapshot, and lift the meter's covered `seq`: the append's
    /// cost is already in the operation's unsettled counts, so a
    /// checkpoint folding those in covers this row too.
    pub const fn log_appended(&mut self, bytes: u64, seq: i64) {
        self.log_bytes_since_snapshot += bytes;
        if seq > self.meter.seq {
            self.meter.seq = seq;
        }
    }

    /// Whether the log tail a wake would replay has crossed a snapshot
    /// threshold, events or bytes - whichever comes first.
    #[must_use]
    pub const fn snapshot_due(&self) -> bool {
        self.log_since_snapshot > super::store::SNAPSHOT_EVENT_THRESHOLD
            || self.log_bytes_since_snapshot > super::store::SNAPSHOT_BYTE_THRESHOLD
    }

    /// Apply one decoded log event — the replay half of wake. The
    /// submit reassembly buffer lives in `store.rs`; this handles the
    /// one-row-per-event kinds.
    pub fn apply(&mut self, event: &SchedulerEvent, now: i64) {
        self.log_since_snapshot += 1;
        match event {
            SchedulerEvent::SliceReport {
                target,
                rustc_version,
                base_generation,
                generation,
                added,
                retired,
            } => {
                self.apply_slice_report(
                    target.as_str(),
                    rustc_version.as_str(),
                    *base_generation,
                    *generation,
                    added,
                    retired,
                );
            }
            SchedulerEvent::Claims { claims } => {
                for claim in claims {
                    // A claim on an in-flight node is a stale-lease
                    // recovery the original pass ran before it
                    // claimed: the lease return is not logged, its
                    // re-claim is.
                    if let Some(ix) = self.node_ix(&claim.task_id)
                        && matches!(
                            self.node(ix).status,
                            Status::Pending | Status::Dispatched | Status::Running
                        )
                    {
                        self.state_mut(ix).attempt = u8::try_from(claim.attempt).unwrap_or(u8::MAX);
                        self.mark_claimed(ix, claim.generation, now);
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
            SchedulerEvent::RunUpdate => {
                self.last_run_update_ms = Some(now);
            }
            SchedulerEvent::ExternalRunStarted { run_id, family } => {
                self.last_run_update_ms = Some(now);
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
                self.last_run_update_ms = Some(now);
                if let Ok(run_id) = run_id.parse::<u64>() {
                    self.run_finished(task_id, run_id, *success, *cancelled, error.clone(), now);
                }
            }
            // `Submit` parts are reassembled by the replay loop in
            // `store.rs` before this is reached.
            SchedulerEvent::StoreReset | SchedulerEvent::Submit { .. } => {}
            SchedulerEvent::Mutate { op, task_ids } => {
                self.mutate(*op, task_ids, now);
            }
            SchedulerEvent::SubmitIds { entries } => {
                self.submit_by_ids(entries);
            }
            SchedulerEvent::Demand {
                batch_id,
                input_hash,
                entries,
            } => {
                self.fold_demand(
                    &entries
                        .iter()
                        .map(|entry| (entry.task_id.clone(), entry.delta))
                        .collect::<Vec<_>>(),
                );
                self.touch_batch(batch_id);
                self.demand_batches.insert(
                    batch_id.clone(),
                    (
                        input_hash.clone(),
                        i64::try_from(entries.len()).unwrap_or(i64::MAX),
                    ),
                );
            }
            SchedulerEvent::DispatchCap { setting } => {
                self.dispatch_cap = Some((**setting).clone());
            }
            SchedulerEvent::Freeze {
                record,
                at,
                trigger,
            } => self.apply_freeze(record.as_deref(), at, trigger),

            // `Request` lifecycle events land with the request-lane
            // cutover (stage 7).
            SchedulerEvent::Request { request_id, kind } => {
                self.apply_request_event(request_id, kind, now);
            }
            SchedulerEvent::Feed { hour, kind } => self.apply_feed_event(hour, kind),
        }
    }
}

impl Graph {
    /// One request-lane lifecycle step (stow#878 stage 7). Attempt
    /// fencing replays cleanly: a superseded attempt's `RunUpdated` or
    /// `Outcome` lands on the live record's attempt check and drops.
    fn apply_request_event(
        &mut self,
        request_id: &str,
        kind: &stow_types::api::RequestEvent,
        now: i64,
    ) {
        use stow_types::api::{RequestEvent, RequestRunAction};
        // A `RunUpdated` request event is the `workflow_run` webhook's
        // resolve-run delivery — it stamps the health check's
        // last-delivery instant like a build run's own events do.
        if matches!(kind, RequestEvent::RunUpdated { .. }) {
            self.last_run_update_ms = Some(now);
        }
        self.touch_request(request_id);
        match kind {
            RequestEvent::Admitted {
                admission,
                attempt,
                dispatched_at,
            } => {
                self.requests.insert(
                    request_id.to_owned(),
                    RequestRecord {
                        admission: admission.clone(),
                        attempt: *attempt,
                        dispatched_at: *dispatched_at,
                        state: "accepted".to_owned(),
                        run_id: None,
                        run_url: None,
                        outcome_json: None,
                        error: None,
                    },
                );
            }
            RequestEvent::RunUpdated { update } => {
                if let Some(record) = self.requests.get_mut(request_id)
                    && update.attempt == record.attempt
                {
                    match update.action {
                        RequestRunAction::InProgress if record.state == "accepted" => {
                            "resolving".clone_into(&mut record.state);
                            record.run_id.clone_from(&update.run_id);
                            record.run_url.clone_from(&update.run_url);
                        }
                        RequestRunAction::Completed if record.state != "enqueued" => {
                            "failed".clone_into(&mut record.state);
                            record.error = Some(match update.conclusion.as_deref() {
                                Some("success") => {
                                    "resolve run completed without an outcome report".to_owned()
                                }
                                conclusion => format!(
                                    "resolve run finished `{conclusion:?}`{}",
                                    update
                                        .run_url
                                        .as_deref()
                                        .map(|url| format!(" ({url})"))
                                        .unwrap_or_default()
                                ),
                            });
                        }
                        _ => {}
                    }
                }
            }
            RequestEvent::Outcome {
                attempt,
                state,
                outcome_json,
                error,
            } => {
                if let Some(record) = self.requests.get_mut(request_id)
                    && *attempt == record.attempt
                {
                    record.state.clone_from(state);
                    record.outcome_json.clone_from(outcome_json);
                    record.error.clone_from(error);
                }
            }
        }
    }

    /// The feed hour's lifecycle — the `demand_feed_hours` /
    /// `demand_feed_pages` rows' machine (stow#878 stage 7).
    fn apply_feed_event(&mut self, hour: &str, kind: &stow_types::api::FeedEvent) {
        use stow_types::api::FeedEvent as K;
        match kind {
            K::Begin { generation } => {
                self.touch_feed(hour);
                let session = self
                    .feed_sessions
                    .entry(hour.to_owned())
                    .or_insert_with(|| FeedSession {
                        generation: 0,
                        state: "staging".to_owned(),
                        staged_pages: 0,
                        staged_entries: 0,
                        applied_pages: 0,
                        page_count: 0,
                        entry_count: 0,
                        staged: Vec::new(),
                        page_hashes: Vec::new(),
                        chain_hashes: Vec::new(),
                    });
                session.generation = *generation;
                "staging".clone_into(&mut session.state);
                session.staged_pages = 0;
                session.staged_entries = 0;
                session.applied_pages = 0;
                session.page_count = 0;
                session.entry_count = 0;
                session.staged.clear();
                session.page_hashes.clear();
                session.chain_hashes.clear();
            }
            K::Page {
                page_no, entries, ..
            } => {
                if let Some(session) = self.feed_sessions.get_mut(hour)
                    && session.state == "staging"
                    && *page_no == session.staged_pages
                {
                    self.dirty.feed.insert(snapshot::feed_bucket(hour));
                    let payload =
                        stow_types::api::demand_feed_page_payload(entries).unwrap_or_default();
                    let page_hash = blake3::hash(payload.as_bytes());
                    let chain_hash = if *page_no == 0 {
                        page_hash
                    } else {
                        let previous = session
                            .chain_hashes
                            .last()
                            .and_then(|hex| blake3::Hash::from_hex(hex).ok())
                            .expect("chain hash under page_no>0 fence");
                        stow_types::api::demand_feed_chain(&previous, &page_hash)
                    };
                    session.page_hashes.push(page_hash.to_hex().to_string());
                    session.chain_hashes.push(chain_hash.to_hex().to_string());
                    session.staged_pages += 1;
                    session.staged_entries +=
                        u32::try_from(entries.len()).expect("a page holds at most 256 entries");
                    session.staged.push(entries.clone());
                }
            }
            K::Complete { .. } => {
                if let Some(session) = self.feed_sessions.get_mut(hour)
                    && session.state == "staging"
                {
                    "complete".clone_into(&mut session.state);
                    session.page_count = session.staged_pages;
                    session.entry_count = i64::from(session.staged_entries);
                }
            }
            K::ApplyPage { page_no } => {
                if let Some(session) = self.feed_sessions.get_mut(hour)
                    && session.state == "complete"
                    && *page_no == session.applied_pages
                {
                    session.applied_pages += 1;
                }
            }
            K::Deliver { .. } => {
                if let Some(session) = self.feed_sessions.get_mut(hour)
                    && session.state == "complete"
                    && session.applied_pages == session.page_count
                {
                    self.dirty.feed.insert(snapshot::feed_bucket(hour));
                    "delivered".clone_into(&mut session.state);
                    session.staged.clear();
                    session.page_hashes.clear();
                    session.chain_hashes.clear();
                    self.feed_watermark = Some(hour.to_owned());
                }
            }
            K::Expire => {
                if self.feed_sessions.remove(hour).is_some() {
                    self.touch_feed(hour);
                }
            }
        }
    }
}

/// `YYYY-MM-DD HH:MM:SS` UTC for a unix-ms instant — the text form the
/// listing's timestamps carry.
fn format_utc(ms: i64) -> String {
    let at = time::OffsetDateTime::from_unix_timestamp(ms.div_euclid(1000))
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

/// The operator listing's row bound — an unbounded scan of a hot
/// graph would stall the object's single thread.
const ADMIN_LIST_LIMIT: u32 = 500;

/// The graph's answer for a request's root ids; see
/// [`Graph::probe_roots`].
#[derive(Debug, Default, Clone)]
pub struct RootProbe {
    /// Queue status of the roots the graph holds.
    pub statuses: BTreeMap<String, stow_types::api::RequestStatus>,
    /// The roots whose unit shapes are published.
    pub published: BTreeSet<String>,
}

/// A node's typed identity. The fields were typed at merge, so a parse
/// failure here is memory corruption, never data.
struct NodeIdentity {
    crate_name: stow_types::identity::CrateName,
    version: stow_types::identity::CrateVersion,
    features_json: stow_types::identity::FeaturesJson,
    target: stow_types::identity::TargetTriple,
    rustc_version: stow_types::identity::WireRustcVersion,
}

/// Read-side views for the request lane, the operator listing and the
/// admin status — all pure functions of the arena.
impl Graph {
    fn identity_of(&self, node: &Node) -> Result<NodeIdentity, QueueError> {
        let invalid = |field: &str, error: String| {
            QueueError::Invariant(format!(
                "node {} stored {field}: {error}",
                self.intern.at(node.crate_name)
            ))
        };
        Ok(NodeIdentity {
            crate_name: stow_types::identity::CrateName::parse(self.intern.at(node.crate_name))
                .map_err(|e| invalid("crate_name", e.to_string()))?,
            version: stow_types::identity::CrateVersion::new(
                semver::Version::parse(self.intern.at(node.version))
                    .map_err(|e| invalid("version", e.to_string()))?,
            ),
            features_json: stow_types::identity::FeaturesJson::from_sorted(
                serde_json::from_str(self.intern.at(node.features))
                    .map_err(|e| invalid("features_json", e.to_string()))?,
            )
            .map_err(|e| invalid("features_json", e.to_string()))?,
            target: stow_types::identity::TargetTriple::parse(
                &*self.targets[usize::from(node.target)].name,
            )
            .map_err(|e| invalid("target", e.to_string()))?,
            rustc_version: stow_types::identity::WireRustcVersion::parse(
                &*self.rustcs[usize::from(node.rustc)],
            )
            .map_err(|e| invalid("rustc_version", e.to_string()))?,
        })
    }

    /// The wire status of a node: `blocked` is a pending node parked
    /// behind a failed dependency.
    fn wire_status(node: &Node) -> stow_types::api::QueueTaskStatus {
        use stow_types::api::QueueTaskStatus as S;
        match node.status {
            Status::Pending if node.flags.blocked() => S::Blocked,
            Status::Pending => S::Pending,
            Status::Dispatched => S::Dispatched,
            Status::Running => S::Running,
            Status::Completed | Status::Published => S::Completed,
            Status::Failed => S::Failed,
            Status::Free => unreachable!("a freed node is never viewed"),
        }
    }

    const fn wire_lane(node: &Node) -> stow_types::api::TaskLane {
        match node.flags.lane() {
            Lane::Human | Lane::Operations => stow_types::api::TaskLane::Human,
            Lane::Miss | Lane::Preheat => stow_types::api::TaskLane::Miss,
        }
    }

    /// What holds a blocked node: the first failed dependency's task
    /// id, or `unknown dependency identity` when no live failed node
    /// explains the flag.
    fn blocked_by(&self, ix: u32) -> Option<String> {
        let node = self.node(ix);
        if node.status != Status::Pending || !node.flags.blocked() {
            return None;
        }
        self.edge_range(ix)
            .filter(|&edge| !self.edges.met(edge))
            .map(|edge| self.edges.dep(edge))
            .filter(|&dep| self.node(dep).status == Status::Failed)
            .map(|dep| self.task_id_of(dep))
            .min()
            .or_else(|| Some("unknown dependency identity".to_owned()))
    }

    /// 1-based position of a pending human node in dispatch order: the
    /// pending human nodes that rank ahead of it, plus one. The order is
    /// the claim order — rank, then request instant, then arrival.
    fn human_position(&self, ix: u32, now: i64) -> u32 {
        let order = |ix: u32| {
            (
                std::cmp::Reverse(self.rank_at(ix, now)),
                self.state(ix).first_requested,
                ix,
            )
        };
        let mine = order(ix);
        let ahead = self
            .human_pending
            .iter()
            .filter(|&&other| order(other) < mine)
            .count();
        u32::try_from(ahead).unwrap_or(u32::MAX).saturating_add(1)
    }

    /// A node's queue status for the request lane — the operator-facing
    /// fields `RequestStatus` carries.
    pub fn request_status(
        &self,
        task_id: &str,
        now: i64,
    ) -> Option<stow_types::api::RequestStatus> {
        let ix = self.node_ix(task_id)?;
        let node = self.node(ix);
        let identity = self
            .identity_of(node)
            .expect("graph identities were typed at merge");
        let status = Self::wire_status(node);
        let lane = Self::wire_lane(node);
        let human_pending = lane == stow_types::api::TaskLane::Human
            && status == stow_types::api::QueueTaskStatus::Pending;
        Some(stow_types::api::RequestStatus {
            task_id: task_id.to_owned(),
            crate_name: identity.crate_name,
            version: identity.version,
            features_json: identity.features_json,
            target: identity.target,
            rustc_version: identity.rustc_version,
            lane,
            status,
            human_lane_position: human_pending.then(|| self.human_position(ix, now)),
            blocked_by: self.blocked_by(ix),
            preserve_lockfile: node.flags.preserve(),
        })
    }

    /// What the graph says about a request's root ids: the queue
    /// status of the ones it holds and which ones are published (a
    /// published node with no dependents is freed and holds no status).
    pub fn probe_roots(&self, ids: &[String], now: i64) -> RootProbe {
        RootProbe {
            statuses: ids
                .iter()
                .filter_map(|id| {
                    self.request_status(id, now)
                        .map(|status| (id.clone(), status))
                })
                .collect(),
            published: self.published_of(ids),
        }
    }

    /// The nodes a selector names. Explicit ids select those nodes;
    /// otherwise the filter predicates conjoin. Published nodes carry
    /// no queue state and are never selected.
    ///
    /// # Errors
    /// `QueueError::EmptySelector` when no id and no predicate is set.
    fn select(
        &self,
        selector: &stow_types::api::QueueSelector,
        now: i64,
    ) -> Result<Vec<u32>, QueueError> {
        if !selector.task_ids.is_empty() {
            return Ok(selector
                .task_ids
                .iter()
                .filter_map(|id| self.node_ix(id))
                .filter(|&ix| self.node(ix).status.has_state())
                .collect());
        }
        if selector.status.is_none()
            && selector.target.is_none()
            && selector.rustc_version.is_none()
            && selector.crate_name.is_none()
            && selector.older_than_secs.is_none()
        {
            return Err(QueueError::EmptySelector);
        }
        let target = selector
            .target
            .as_ref()
            .map(|target| self.target_lookup(target.as_str()));
        let rustc = selector
            .rustc_version
            .as_ref()
            .map(|rustc| self.rustc_lookup(rustc.as_str()));
        let crate_name = selector
            .crate_name
            .as_ref()
            .map(|name| self.intern.get(name.as_str()));
        let cutoff = selector
            .older_than_secs
            .map(|secs| now.saturating_sub(i64::try_from(secs).unwrap_or(i64::MAX) * 1000));
        Ok(
            (0..u32::try_from(self.nodes.len()).expect("node indexes fit u32"))
                .filter(|&ix| {
                    let node = self.node(ix);
                    node.status.has_state()
                        && selector
                            .status
                            .is_none_or(|status| Self::wire_status(node) == status)
                        && target.is_none_or(|t| t == Some(node.target))
                        && rustc.is_none_or(|r| r == Some(node.rustc))
                        && crate_name.is_none_or(|c| c == Some(node.crate_name))
                        && cutoff.is_none_or(|cutoff| self.state(ix).updated <= cutoff)
                })
                .collect(),
        )
    }

    /// The task ids a mutation selector resolves to — `purge` demands
    /// an age floor so it can never sweep live work.
    ///
    /// # Errors
    /// `QueueError::EmptySelector`, or `QueueError::PurgeRequiresAge`
    /// for an id-less purge without `older_than`.
    pub fn select_ids(
        &self,
        op: stow_types::api::MutationKind,
        selector: &stow_types::api::QueueSelector,
        now: i64,
    ) -> Result<Vec<String>, QueueError> {
        if op == stow_types::api::MutationKind::Purge
            && selector.task_ids.is_empty()
            && selector.older_than_secs.is_none()
        {
            return Err(QueueError::PurgeRequiresAge);
        }
        Ok(self
            .select(selector, now)?
            .into_iter()
            .map(|ix| self.task_id_of(ix))
            .collect())
    }

    /// Queue rows matching a selector, newest first — by last
    /// transition for terminal statuses, by request instant otherwise.
    /// A fully empty selector lists everything.
    ///
    /// # Errors
    /// `QueueError::Invariant` when a node's identity cannot decode.
    pub fn list(
        &self,
        selector: &stow_types::api::QueueSelector,
        now: i64,
    ) -> Result<Vec<stow_types::api::QueueTask>, QueueError> {
        let mut ixs = match self.select(selector, now) {
            Ok(ixs) => ixs,
            Err(QueueError::EmptySelector) => (0..u32::try_from(self.nodes.len())
                .expect("node indexes fit u32"))
                .filter(|&ix| self.node(ix).status.has_state())
                .collect(),
            Err(error) => return Err(error),
        };
        let terminal = matches!(
            selector.status,
            Some(
                stow_types::api::QueueTaskStatus::Completed
                    | stow_types::api::QueueTaskStatus::Failed
            )
        );
        ixs.sort_by_key(|&ix| {
            let state = self.state(ix);
            std::cmp::Reverse((
                if terminal {
                    state.updated
                } else {
                    state.first_requested
                },
                ix,
            ))
        });
        let limit = selector
            .limit
            .map_or(ADMIN_LIST_LIMIT, |limit| limit.clamp(1, ADMIN_LIST_LIMIT));
        ixs.truncate(limit as usize);
        ixs.into_iter()
            .map(|ix| {
                let node = self.node(ix);
                let state = self.state(ix);
                let identity = self.identity_of(node)?;
                let run_id = self.run_id_of(ix);
                Ok(stow_types::api::QueueTask {
                    task_id: self.task_id_of(ix),
                    crate_name: identity.crate_name,
                    version: identity.version,
                    features_json: identity.features_json,
                    target: identity.target,
                    rustc_version: identity.rustc_version,
                    lane: Self::wire_lane(node),
                    status: Self::wire_status(node),
                    attempt: u32::from(state.attempt),
                    error: self.error_of(ix).unwrap_or_default().to_owned(),
                    downloads: state.downloads,
                    dispatch_attempts: u32::from(state.dispatch_attempts),
                    preserve_lockfile: node.flags.preserve(),
                    github_run_id: (run_id != 0).then(|| run_id.to_string()),
                    first_requested_at: format_utc(state.first_requested),
                    created_at: format_utc(state.first_requested),
                    updated_at: format_utc(state.updated),
                    blocked_by: self.blocked_by(ix),
                    host_side: node.flags.host(),
                    value: self.operand_of(ix).to_string(),
                    demand: state.demand,
                })
            })
            .collect()
    }

    /// The operator view behind `GET /admin/status`.
    ///
    /// # Errors
    /// `QueueError::Invariant` when an in-flight node's identity cannot
    /// decode.
    pub fn admin_status(&self, now: i64) -> Result<stow_types::api::AdminStatus, QueueError> {
        let status = self.status();
        let oldest_pending = self
            .pending_ages
            .first_key_value()
            .map(|(&first, _)| u64::try_from((now - first).max(0) / 1000).unwrap_or(0));
        let mut in_flight: Vec<u32> = self.inflight.iter().copied().collect();
        in_flight.sort_by_key(|&ix| (self.claimed_at_of(ix), ix));
        let in_flight = in_flight
            .into_iter()
            .map(|ix| {
                let node = self.node(ix);
                let state = self.state(ix);
                let identity = self.identity_of(node)?;
                let run_id = self.run_id_of(ix);
                Ok(stow_types::api::AdminInFlight {
                    task_id: self.task_id_of(ix),
                    crate_name: identity.crate_name,
                    version: identity.version,
                    target: identity.target,
                    rustc_version: identity.rustc_version,
                    status: Self::wire_status(node),
                    attempt: u32::from(state.attempt),
                    dispatch_attempts: u32::from(state.dispatch_attempts),
                    claimed_at: format_utc(self.claimed_at_of(ix)),
                    github_run_id: (run_id != 0).then(|| run_id.to_string()),
                })
            })
            .collect::<Result<Vec<_>, QueueError>>()?;
        // The trailing day, to the hour: a published node keeps no
        // state to count, so completions are tallied as they land.
        let since = (now - 24 * 3_600_000).div_euclid(3_600_000);
        let mut by_target: BTreeMap<u8, (u32, u32)> = BTreeMap::new();
        for (&(hour, target), &(completed, failed)) in &self.outcome_hours {
            if hour >= since {
                let tally = by_target.entry(target).or_default();
                tally.0 += completed;
                tally.1 += failed;
            }
        }
        let targets = by_target
            .into_iter()
            .filter(|(_, (completed, failed))| completed + failed > 0)
            .map(|(target, (completed_24h, failed_24h))| {
                Ok(stow_types::api::AdminTargetStats {
                    target: stow_types::identity::TargetTriple::parse(
                        &*self.targets[usize::from(target)].name,
                    )?,
                    completed_24h,
                    failed_24h,
                })
            })
            .collect::<Result<Vec<_>, QueueError>>()?;
        Ok(stow_types::api::AdminStatus {
            pending_miss: status.pending.saturating_sub(status.human_pending),
            pending_human: status.human_pending,
            blocked: status.blocked,
            oldest_pending_seconds: oldest_pending,
            in_flight,
            targets,
            dispatch_frozen: self.freeze.is_some(),
            index_slices: self
                .slice_generations()
                .into_iter()
                .map(|(target, rustc_version, generation)| {
                    Ok(stow_types::api::AdminIndexSlice {
                        target: stow_types::identity::TargetTriple::parse(&target)?,
                        rustc_version: stow_types::identity::WireRustcVersion::parse(
                            &rustc_version,
                        )?,
                        generation,
                    })
                })
                .collect::<Result<Vec<_>, QueueError>>()?,
        })
    }
}

impl Graph {
    /// Rebuild every index and counter the snapshot does not carry,
    /// over the arenas a load just filled.
    ///
    /// # Errors
    /// `QueueError::Invariant` when the snapshot's edges disagree with
    /// its nodes.
    fn rebuild_after_load(&mut self) -> Result<(), QueueError> {
        let mut end = 0u32;
        for node in &mut self.nodes {
            node.edges_start = end;
            end = end
                .checked_add(u32::from(node.edges_len))
                .ok_or_else(|| QueueError::Invariant("snapshot edge spans overflow u32".into()))?;
        }
        if end as usize != self.edges.len() {
            return Err(QueueError::Invariant(format!(
                "snapshot node spans cover {end} edges but it carries {}",
                self.edges.len()
            )));
        }
        for ix in 0..self.nodes.len() {
            let ix = u32::try_from(ix).expect("node indexes fit u32");
            let range = self.edge_range(ix);
            let mut unmet = 0u16;
            for edge in range {
                let dep = self.edges.dep(edge) as usize;
                let held = self.nodes.get_mut(dep).ok_or_else(|| {
                    QueueError::Invariant(format!("snapshot edge names node {dep} past the arena"))
                })?;
                held.refs += 1;
                if !self.edges.met(edge) {
                    unmet += 1;
                }
            }
            let node = self.node_mut(ix);
            node.unmet = unmet;
            let status = node.status;
            self.counts[status.index()] += 1;
            if status.in_flight() {
                self.inflight.insert(ix);
            }
            self.index_pending(ix, true);
        }
        self.rebuild_indexes_over_nodes();
        for ix in 0..u32::try_from(self.nodes.len()).expect("node indexes fit u32") {
            self.refresh_ready(ix);
        }
        Ok(())
    }
}
/// The scheduler's in-memory graph — one cell per Durable Object
/// instance, owned by [`Scheduler`] and layered into its router so
/// handlers extract it as `State<GraphCell>`. `State` requires
/// `Send + Sync` unconditionally — `Arc<Mutex>` supplies them on every
/// target with no unsafe impls: on wasm32 the single-threaded isolate
/// makes the lock a no-op wrapper, and on host the mutex is simply
/// correct. The lock is held only inside `with` — never across an
/// `.await`, so the DO input gate's serialization holds either way.
#[derive(Clone, Default)]
pub struct GraphCell {
    graph: std::sync::Arc<std::sync::Mutex<Graph>>,
    /// Whether `graph` holds the woken state rather than the empty
    /// placeholder a reset leaves behind.
    loaded: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Set by the wake, cleared by the one request that runs the
    /// post-wake CI status reconcile.
    reconcile_due: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The isolate's cached GitHub App installation token.
    tokens: crate::github_app::TokenCache,
    /// The isolate's billed-but-unsettled row counts — see [`Unsettled`].
    unsettled: std::sync::Arc<Unsettled>,
}

impl std::fmt::Debug for GraphCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("GraphCell").finish_non_exhaustive()
    }
}

/// The isolate's billed-but-unsettled row counts (stow#931): the
/// metering backend adds every statement's counters to it and
/// `Meter::settle` subtracts what it folds into the day meter, so a
/// meter checkpoint covering `graph.meter + unsettled` accounts for
/// every operation in flight, not only the one that writes it. It
/// lives on the cell — outside `Graph` — because the backend books
/// without the graph lock, and neither the wake's `install` nor the
/// reset's `clear` may drop counts a billed statement already paid.
#[derive(Debug, Default)]
pub struct Unsettled {
    rows_read: std::sync::atomic::AtomicU64,
    rows_written: std::sync::atomic::AtomicU64,
}

impl Unsettled {
    /// Book a statement's billed rows.
    pub(crate) fn add(&self, rows_read: u64, rows_written: u64) {
        use std::sync::atomic::Ordering::Relaxed;
        self.rows_read.fetch_add(rows_read, Relaxed);
        self.rows_written.fetch_add(rows_written, Relaxed);
    }

    /// Subtract what a settle folded into the day meter.
    pub(crate) fn sub(&self, rows_read: u64, rows_written: u64) {
        use std::sync::atomic::Ordering::Relaxed;
        self.rows_read.fetch_sub(rows_read, Relaxed);
        self.rows_written.fetch_sub(rows_written, Relaxed);
    }

    /// The running totals a checkpoint folds into the stored row.
    pub(crate) fn counts(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        (
            self.rows_read.load(Relaxed),
            self.rows_written.load(Relaxed),
        )
    }
}

/// Proof that the graph is loaded this isolate: the only way to read or
/// mutate it. A [`GraphCell`] hands one out from [`GraphCell::loaded`]
/// once the wake has installed the graph, so touching the graph before
/// loading it does not compile.
#[derive(Clone, Copy)]
pub struct LoadedGraph<'a> {
    cell: &'a GraphCell,
}

impl<'a> LoadedGraph<'a> {
    /// Mutate the in-memory graph — never across an `.await` and never
    /// re-entrant (a nested `with` would deadlock on the mutex).
    pub(crate) fn with<R>(self, f: impl FnOnce(&mut Graph) -> R) -> R {
        f(&mut self.cell.graph.lock().expect("graph cell poisoned"))
    }
    /// The isolate's installation-token cache.
    pub(crate) const fn tokens(self) -> &'a crate::github_app::TokenCache {
        &self.cell.tokens
    }
    /// The cell this handle proves loaded.
    pub(crate) const fn cell(self) -> &'a GraphCell {
        self.cell
    }
}

impl GraphCell {
    /// The loaded-graph handle, or `None` while the graph is not yet
    /// loaded this isolate (before the wake, or after a reset).
    pub(crate) fn loaded(&self) -> Option<LoadedGraph<'_>> {
        self.loaded
            .load(std::sync::atomic::Ordering::Acquire)
            .then_some(LoadedGraph { cell: self })
    }
    /// Install the freshly loaded graph — the wake. When another
    /// request installed one while this wake awaited the store, the
    /// loser is dropped: its replay saw a log the winner has since
    /// appended to. The winner's install makes the post-wake reconcile
    /// fall due. Returns the proof that the graph is now loaded.
    pub(crate) fn install(&self, graph: Graph) -> LoadedGraph<'_> {
        let mut slot = self.graph.lock().expect("graph cell poisoned");
        if !self.loaded.load(std::sync::atomic::Ordering::Acquire) {
            *slot = graph;
            self.loaded
                .store(true, std::sync::atomic::Ordering::Release);
            self.reconcile_due
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        drop(slot);
        LoadedGraph { cell: self }
    }
    /// Take the post-wake reconcile duty — `true` for exactly one
    /// caller per wake.
    pub(crate) fn take_reconcile(&self) -> bool {
        self.reconcile_due
            .swap(false, std::sync::atomic::Ordering::Relaxed)
    }
    /// Drop the in-memory graph — the operator reset: the next
    /// request wakes from the (reset) store.
    pub(crate) fn clear(&self) {
        *self.graph.lock().expect("graph cell poisoned") = Graph::default();
        self.loaded
            .store(false, std::sync::atomic::Ordering::Release);
    }
    /// The isolate's installation-token cache.
    pub(crate) const fn tokens(&self) -> &crate::github_app::TokenCache {
        &self.tokens
    }
    /// The isolate's unsettled billed counts — the metering backend's
    /// `Arc` clone books into it, `Meter::settle` subtracts, and a
    /// meter checkpoint folds the running totals in (stow#931).
    pub(crate) const fn unsettled(&self) -> &std::sync::Arc<Unsettled> {
        &self.unsettled
    }
}

/// `freeze::FreezeStore` over the in-memory graph — the transition
/// machinery runs on the same state `claim` gates on. Each `set` and
/// `delete` applies a `Freeze` event to the graph and stages it for
/// the caller to append to the log ([`Self::take_events`]): the
/// store's futures are `Send`, the `DurableDb` handle is not, so the
/// log write cannot happen inside them. `at`/`now_ms` stamp clear
/// transitions the store itself cannot timestamp (engages take the
/// record's own `frozen_at`).
pub struct GraphFreezeStore<'a> {
    cell: LoadedGraph<'a>,
    at: String,
    now_ms: i64,
    staged: std::sync::Mutex<Vec<SchedulerEvent>>,
}

impl<'a> GraphFreezeStore<'a> {
    /// The graph this store stages transitions for.
    pub const fn cell(&self) -> LoadedGraph<'a> {
        self.cell
    }

    /// The transition's wall-clock `at` and monotonic `now_ms`.
    pub const fn new(cell: LoadedGraph<'a>, at: String, now_ms: i64) -> Self {
        Self {
            cell,
            at,
            now_ms,
            staged: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// The `Freeze` events applied so far, for the caller to append.
    pub fn take_events(&self) -> Vec<SchedulerEvent> {
        std::mem::take(&mut *self.staged.lock().expect("staged freeze events"))
    }

    fn commit(&self, event: SchedulerEvent) {
        self.cell.with(|graph| graph.apply(&event, self.now_ms));
        self.staged
            .lock()
            .expect("staged freeze events")
            .push(event);
    }
}

impl crate::freeze::FreezeStore for GraphFreezeStore<'_> {
    fn record(
        &self,
    ) -> impl std::future::Future<
        Output = Result<Option<stow_types::api::DispatchFreezeRecord>, QueueError>,
    > + Send {
        let record = self.cell.with(|graph| graph.freeze().cloned());
        async move { Ok(record) }
    }
    fn set(
        &self,
        record: &stow_types::api::DispatchFreezeRecord,
    ) -> impl std::future::Future<Output = Result<(), QueueError>> + Send {
        self.commit(SchedulerEvent::Freeze {
            at: record.frozen_at.clone(),
            trigger: record.trigger.clone(),
            record: Some(Box::new(record.clone())),
        });
        async { Ok(()) }
    }
    fn delete(
        &self,
        cleared: &stow_types::api::DispatchFreezeRecord,
    ) -> impl std::future::Future<Output = Result<(), QueueError>> + Send {
        self.commit(SchedulerEvent::Freeze {
            record: None,
            at: self.at.clone(),
            trigger: cleared.trigger.clone(),
        });
        async { Ok(()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stow_types::api::{MutationKind, SubmissionSource};
    use stow_types::identity::{
        CrateName, CrateVersion, DependencyIdentity, FeaturesJson, TargetTriple, WireRustcVersion,
    };
    use stow_types::public_cache::{UnitInvocation, UnitKind, UnitSide};

    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const RUSTC: &str = "1.85.0";

    fn sub(name: &str) -> SubmissionNode {
        let mut node = SubmissionNode {
            task_id: String::new(),
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
        };
        node.task_id = minted_id(&node);
        node
    }

    /// The canonical task id of the test node `name`.
    fn id(name: &str) -> String {
        sub(name).task_id
    }

    /// A → B → C chain (a depends on b, b on c), nodes in leaf order.
    fn chain() -> SubmissionTree {
        let c = sub("c");
        let mut b = sub("b");
        b.deps = vec![0];
        let mut a = sub("a");
        a.deps = vec![1];
        SubmissionTree {
            source: SubmissionSource::CacheMiss,
            roots: vec![2],
            nodes: vec![c, b, a],
        }
    }

    fn solo() -> SubmissionTree {
        SubmissionTree {
            source: SubmissionSource::CacheMiss,
            roots: vec![0],
            nodes: vec![sub("solo")],
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

    fn publish(graph: &mut Graph, name: &str) -> u32 {
        let live = graph.slice_generation(TARGET, RUSTC);
        graph.apply_slice_report(
            TARGET,
            RUSTC,
            live,
            live.map_or(1, |live| live + 1),
            &[
                published_row(name, UnitKind::Linked),
                published_row(name, UnitKind::Unlinked),
            ],
            &[],
        )
    }

    fn report(
        graph: &mut Graph,
        base: Option<i64>,
        generation: i64,
        added: &[&str],
        retired: &[&str],
    ) -> Result<(), QueueError> {
        graph.check_slice_report(TARGET, RUSTC, base, generation)?;
        let rows = |names: &[&str]| -> Vec<PublishedSliceRow> {
            names
                .iter()
                .flat_map(|name| {
                    [
                        published_row(name, UnitKind::Linked),
                        published_row(name, UnitKind::Unlinked),
                    ]
                })
                .collect()
        };
        graph.apply_slice_report(
            TARGET,
            RUSTC,
            base,
            generation,
            &rows(added),
            &rows(retired),
        );
        Ok(())
    }

    fn is_ready(graph: &Graph, name: &str) -> bool {
        let ix = graph.node_ix(&id(name)).expect("node");
        graph
            .ready
            .values()
            .any(|set| set.iter().any(|&(_, at)| at == ix))
    }

    /// A delta that does not extend the slice's live generation is
    /// refused — the gap a lost report leaves — and a full report
    /// restarts the sequence (stow#1049).
    #[test]
    fn a_slice_report_that_leaves_a_gap_is_refused() {
        let mut graph = Graph::default();
        let conflict = |result: Result<(), QueueError>| {
            assert!(
                matches!(result, Err(QueueError::SliceReportConflict(_))),
                "{result:?}"
            );
        };
        // A delta on a slice the scheduler never saw.
        conflict(report(&mut graph, Some(1), 2, &["a"], &[]));
        report(&mut graph, None, 1, &["a"], &[]).expect("a full report");
        assert_eq!(graph.slice_generation(TARGET, RUSTC), Some(1));
        report(&mut graph, Some(1), 2, &["b"], &[]).expect("the next delta");
        // A lost generation 3: the delta based on it names a base the
        // scheduler never received.
        conflict(report(&mut graph, Some(3), 4, &["c"], &[]));
        // A replayed delta is stale.
        conflict(report(&mut graph, Some(1), 2, &["b"], &[]));
        // A base that skips ahead of its own generation.
        conflict(report(&mut graph, Some(2), 4, &["c"], &[]));
        assert_eq!(graph.slice_generation(TARGET, RUSTC), Some(2));
        assert!(graph.is_published(&id("a")) && graph.is_published(&id("b")));
        assert!(!graph.is_published(&id("c")));
        // The resync a conflict asks for: a full report whose
        // generation restarts below the live one.
        report(&mut graph, None, 1, &["a", "b", "c"], &[]).expect("resync");
        assert_eq!(graph.slice_generation(TARGET, RUSTC), Some(1));
        assert!(graph.is_published(&id("c")));
    }

    /// A full report replaces the slice's set: what the slice held and
    /// the report no longer lists is retired, and the nodes waiting on
    /// it wait again.
    #[test]
    fn a_full_report_replaces_the_slice_set() {
        let mut graph = Graph::default();
        report(&mut graph, None, 1, &["a", "b"], &[]).expect("first report");
        assert!(graph.is_published(&id("a")) && graph.is_published(&id("b")));
        report(&mut graph, None, 1, &["b", "c"], &[]).expect("replacing report");
        assert!(!graph.is_published(&id("a")), "a left the slice");
        assert!(graph.is_published(&id("b")) && graph.is_published(&id("c")));
        // A live dependent flips back to waiting when its dependency
        // leaves the slice.
        let mut graph = Graph::default();
        graph.merge(&chain(), 0).expect("merge");
        report(&mut graph, None, 1, &["c"], &[]).expect("c published");
        assert!(is_ready(&graph, "b"), "b is released by c");
        report(&mut graph, None, 1, &[], &[]).expect("empty replacement");
        assert!(!is_ready(&graph, "b"), "b waits on c again");
        assert!(!graph.is_published(&id("c")));
    }

    /// Generations and slice membership survive the snapshot.
    #[test]
    fn slice_generations_and_members_round_trip_the_snapshot() {
        let mut graph = Graph::default();
        report(&mut graph, None, 1, &["a", "b"], &[]).expect("full");
        report(&mut graph, Some(1), 2, &["c"], &["a"]).expect("delta");
        let mut restored = round_trip(&graph);
        assert_eq!(restored.slice_generation(TARGET, RUSTC), Some(2));
        assert!(restored.is_published(&id("c")) && !restored.is_published(&id("a")));
        // The restored members index drives a replacement.
        report(&mut restored, None, 1, &["c"], &[]).expect("replace");
        assert!(!restored.is_published(&id("b")));
    }

    fn status_of(graph: &Graph, name: &str) -> Option<Status> {
        graph.node_ix(&id(name)).map(|ix| graph.node(ix).status)
    }

    /// Nodes in the ready set — the operand-class map's total entries.
    fn ready_count(graph: &Graph) -> usize {
        graph.ready.values().map(BTreeSet::len).sum()
    }

    /// The pending index recomputed by walking the arena — what
    /// `index_pending` keeps through every transition must equal it.
    fn assert_pending_index(graph: &Graph) {
        let mut blocked = 0u32;
        let mut miss = 0u32;
        let mut human = BTreeSet::new();
        let mut ages: BTreeMap<i64, u32> = BTreeMap::new();
        for (ix, node) in (0u32..).zip(&graph.nodes) {
            if node.status != Status::Pending {
                continue;
            }
            blocked += u32::from(node.flags.blocked());
            miss += u32::from(node.flags.lane() == Lane::Miss);
            if node.flags.lane() == Lane::Human {
                human.insert(ix);
            }
            *ages.entry(graph.state(ix).first_requested).or_default() += 1;
        }
        assert_eq!(graph.pending_blocked, blocked, "blocked pending nodes");
        assert_eq!(graph.pending_miss, miss, "pending miss nodes");
        assert_eq!(graph.human_pending, human, "pending human nodes");
        assert_eq!(graph.pending_ages, ages, "pending request instants");
    }

    /// What a wake decodes when the store holds exactly this graph's
    /// plan — every row of every dirty span, in key order.
    fn round_trip(graph: &Graph) -> Graph {
        let plan = graph.snapshot_plan().expect("plan");
        let mut loader = SnapshotLoader::default();
        for span in plan.spans {
            let mut encoder = graph.snapshot_encoder(span);
            let mut sub = 0i64;
            while let Some(payload) = encoder.next_row(graph).expect("row") {
                loader.apply(span.lo_key() + sub, &payload).expect("apply");
                sub += 1;
            }
        }
        loader.finish().expect("load")
    }

    #[test]
    fn records_keep_their_sizes() {
        assert_eq!(size_of::<Node>(), 68);
        assert_eq!(size_of::<State>(), 48);
    }

    #[test]
    fn merge_inserts_and_dedups_by_task_id() {
        let mut graph = Graph::default();
        let report = graph.merge(&chain(), 1000).expect("merge");
        assert_eq!((report.inserted, report.merged), (3, 0));
        let report = graph.merge(&chain(), 2000).expect("remerge");
        assert_eq!((report.inserted, report.merged), (0, 3));
        assert_eq!(graph.status().pending, 3);
    }

    #[test]
    fn merge_refuses_an_id_its_columns_do_not_derive() {
        let mut tree = solo();
        tree.nodes[0].task_id = "not-the-canonical-id".to_owned();
        let mut graph = Graph::default();
        assert!(matches!(
            graph.merge(&tree, 0),
            Err(QueueError::Invariant(_))
        ));
        assert!(matches!(
            graph.merge_changes(&tree),
            Err(QueueError::Invariant(_))
        ));
    }

    #[test]
    fn ids_re_mint_from_the_node() {
        let mut graph = Graph::default();
        graph.merge(&chain(), 0).expect("merge");
        for name in ["a", "b", "c"] {
            let ix = graph.node_ix(&id(name)).expect("node");
            assert_eq!(graph.task_id_of(ix), id(name));
        }
        assert!(graph.node_ix("c-id").is_none());
    }

    #[test]
    fn gate_blocks_until_dep_publishes() {
        let mut graph = Graph::default();
        graph.merge(&chain(), 0).expect("merge");
        // Only the leaf is ready; a and b sit behind unmet edges.
        assert_eq!(ready_count(&graph), 1);
        let claimed = graph.claim(45, 16, 0, 3_600_000).expect("claim");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].task_id, id("c"));
    }

    #[test]
    fn publish_flips_edges_and_releases_dependents() {
        let mut graph = Graph::default();
        graph.merge(&chain(), 0).expect("merge");
        graph.claim(45, 16, 0, 3_600_000).expect("claim c");
        graph.run_finished(&id("c"), 100, true, false, None, 50_000);
        let flips = publish(&mut graph, "c");
        assert_eq!(flips, 1, "b's edge to c flips");
        // b still depends on c, so c is retained without queue state.
        assert_eq!(status_of(&graph, "c"), Some(Status::Published));
        let claimed = graph.claim(45, 16, 60_000, 3_600_000).expect("claim b");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].task_id, id("b"));
        // The payload's subgraph rebuilds c from the retained node.
        assert_eq!(claimed[0].payload.dependency_subgraph.nodes.len(), 1);
        assert_eq!(
            claimed[0].payload.dependency_subgraph.nodes[0]
                .crate_name
                .as_str(),
            "c"
        );
    }

    #[test]
    fn a_published_node_is_freed_with_its_last_dependent() {
        let mut graph = Graph::default();
        graph.merge(&chain(), 0).expect("merge");
        publish(&mut graph, "c");
        // b and a still hang on c through b.
        assert_eq!(status_of(&graph, "c"), Some(Status::Published));
        publish(&mut graph, "b");
        assert_eq!(status_of(&graph, "b"), Some(Status::Published));
        assert_eq!(status_of(&graph, "c"), Some(Status::Published));
        publish(&mut graph, "a");
        // a had no dependent: it goes, and b and c with it.
        for name in ["a", "b", "c"] {
            assert_eq!(status_of(&graph, name), None, "{name} freed");
            assert!(graph.is_published(&id(name)), "{name} stays published");
        }
        assert_eq!(graph.states.len() - graph.free_states.len(), 0);
        graph.compact();
        assert_eq!(graph.sizes().0, 0);
        assert_eq!(graph.edges.len(), 0);
    }

    #[test]
    fn a_resubmitted_published_node_is_not_rebuilt() {
        let mut graph = Graph::default();
        graph.merge(&chain(), 0).expect("merge");
        publish(&mut graph, "c");
        publish(&mut graph, "b");
        publish(&mut graph, "a");
        graph.compact();
        let report = graph.merge(&chain(), 1_000).expect("remerge");
        assert_eq!(
            (report.inserted, report.merged),
            (0, 3),
            "everything the index serves is born published"
        );
        assert_eq!(ready_count(&graph), 0);
        assert_eq!(graph.status().pending, 0);
        // Born published and unreferenced: nothing stays.
        graph.compact();
        assert_eq!(graph.sizes().0, 0);
    }

    #[test]
    fn a_new_dependent_retains_a_published_node() {
        let mut graph = Graph::default();
        graph.merge(&chain(), 0).expect("merge");
        publish(&mut graph, "c");
        publish(&mut graph, "b");
        publish(&mut graph, "a");
        graph.compact();
        // d depends on c, which published and was freed: it is rebuilt
        // from the tree as a published node and kept for d.
        let c = sub("c");
        let mut d = sub("d");
        d.deps = vec![0];
        graph
            .merge(
                &SubmissionTree {
                    source: SubmissionSource::CacheMiss,
                    roots: vec![1],
                    nodes: vec![c, d],
                },
                2_000,
            )
            .expect("merge d");
        assert_eq!(status_of(&graph, "c"), Some(Status::Published));
        assert_eq!(ready_count(&graph), 1, "d's only edge is met");
        let claimed = graph.claim(45, 16, 10_000_000, 3_600_000).expect("claim d");
        assert_eq!(claimed[0].task_id, id("d"));
        assert_eq!(claimed[0].payload.dependency_subgraph.nodes.len(), 1);
    }

    #[test]
    fn compaction_keeps_ids_edges_and_the_ready_set() {
        let mut graph = Graph::default();
        // Leaves l0..l1999, each with a dependent d0..d1999.
        let mut nodes = Vec::new();
        for n in 0..2_000 {
            nodes.push(sub(&format!("l{n}")));
        }
        for n in 0..2_000u32 {
            let mut dependent = sub(&format!("d{n}"));
            dependent.deps = vec![n];
            nodes.push(dependent);
        }
        graph
            .merge(
                &SubmissionTree {
                    source: SubmissionSource::CacheMiss,
                    roots: vec![],
                    nodes,
                },
                0,
            )
            .expect("merge");
        // Publish every leaf of the first half, then their dependents:
        // the freed leaves and dependents leave holes in the arena.
        for n in 0..1_000 {
            publish(&mut graph, &format!("l{n}"));
        }
        for n in 0..1_000 {
            publish(&mut graph, &format!("d{n}"));
        }
        assert_eq!(graph.sizes().0, 2_000);
        graph.compact();
        assert_eq!(graph.nodes.len(), 2_000);
        for n in 1_000..2_000 {
            let leaf = graph.node_ix(&id(&format!("l{n}"))).expect("leaf");
            let dependent = graph.node_ix(&id(&format!("d{n}"))).expect("dependent");
            assert_eq!(
                graph.deps_of(dependent).collect::<Vec<_>>(),
                vec![leaf],
                "edge survives the renumbering"
            );
            assert_eq!(graph.edges.owners_of(leaf), vec![dependent]);
        }
        assert_eq!(ready_count(&graph), 1_000, "the unpublished leaves");
        assert_pending_index(&graph);
        // The renumbered graph still flips edges.
        assert_eq!(publish(&mut graph, "l1500"), 1);
        assert_eq!(ready_count(&graph), 1_000, "l1500 left, d1500 joined");
        assert_pending_index(&graph);
    }

    #[test]
    fn many_edges_flip_across_a_reverse_rebuild() {
        let mut graph = Graph::default();
        // One shared leaf with enough dependents to push the overlay
        // past a rebuild.
        let mut nodes = vec![sub("shared")];
        let dependents = REBUILD_PROBE;
        for n in 0..dependents {
            let mut dependent = sub(&format!("x{n}"));
            dependent.deps = vec![0];
            nodes.push(dependent);
        }
        graph
            .merge(
                &SubmissionTree {
                    source: SubmissionSource::CacheMiss,
                    roots: vec![],
                    nodes,
                },
                0,
            )
            .expect("merge");
        let flips = publish(&mut graph, "shared");
        assert_eq!(flips as usize, dependents);
        assert_eq!(ready_count(&graph), dependents);
    }

    /// Edges onto one leaf: more than the reverse index's rebuild floor.
    const REBUILD_PROBE: usize = 9_000;

    #[test]
    fn completion_without_binding_parks_and_applies_on_bind() {
        let mut graph = Graph::default();
        graph.merge(&solo(), 0).expect("merge");
        let claimed = graph.claim(45, 16, 0, 3_600_000).expect("claim");
        let generation = claimed[0].generation;
        let outcome = graph.run_finished(&id("solo"), 4242, true, false, None, 10_000);
        assert_eq!(outcome, FinishOutcome::Parked);
        assert!(graph.bind(&id("solo"), generation, 4242, 11_000));
        assert_eq!(status_of(&graph, "solo"), Some(Status::Completed));
    }

    /// One `status`-listing row for `title`.
    fn listing(run_id: u64, title: &str, status: CiRunStatus) -> CiRunListing {
        CiRunListing {
            workflow_run_id: run_id,
            title: title.to_owned(),
            family: Some(RunnerFamily::Linux),
            status,
        }
    }

    /// stow#940: a claim replayed `dispatched`-unbound binds by title
    /// on the post-wake reconcile; a `queued` listing keeps it
    /// `dispatched`, and the `in_progress` listing moves it to
    /// `running` — the job the own-run `in_progress` delivery did.
    #[test]
    fn a_reconcile_restores_running_from_the_listing() {
        let mut graph = Graph::default();
        graph.merge(&solo(), 0).expect("merge");
        let ix = graph.node_ix(&id("solo")).expect("node");
        graph.mark_claimed(ix, 7, 0);
        assert_eq!(status_of(&graph, "solo"), Some(Status::Dispatched));
        let title = format!("{RUSTC}-{}", id("solo"));
        graph.reconcile_runs(&[listing(11, &title, CiRunStatus::Queued)], 1_000);
        assert_eq!(status_of(&graph, "solo"), Some(Status::Dispatched));
        assert_eq!(graph.run_id_of(ix), 11);
        graph.reconcile_runs(&[listing(11, &title, CiRunStatus::InProgress)], 2_000);
        assert_eq!(status_of(&graph, "solo"), Some(Status::Running));
        assert_eq!(graph.last_run_update_ms, Some(2_000));
    }

    /// stow#943: an own run listed `in_progress` at t0+50min renews the
    /// lease — the claim pass at t0+70min, past the 60-minute lease
    /// `claimed_at` alone would give, keeps it `running` with its run
    /// id instead of re-dispatching.
    #[test]
    fn an_in_progress_listing_renews_the_lease() {
        let mut graph = Graph::default();
        graph.merge(&solo(), 0).expect("merge");
        let claimed = graph.claim(45, 16, 0, 3_600_000).expect("claim");
        graph.bind(&id("solo"), claimed[0].generation, 11, 1_000);
        let ix = graph.node_ix(&id("solo")).expect("node");
        graph.reconcile_runs(
            &[listing(
                11,
                &format!("{RUSTC}-{}", id("solo")),
                CiRunStatus::InProgress,
            )],
            50 * 60_000,
        );
        let reclaimed = graph
            .claim(45, 16, 70 * 60_000, 3_600_000)
            .expect("claim pass");
        assert!(reclaimed.is_empty(), "the living run is not re-dispatched");
        assert_eq!(status_of(&graph, "solo"), Some(Status::Running));
        assert_eq!(graph.run_id_of(ix), 11);
    }

    /// stow#943: an own run still listed `queued` renews the lease the
    /// same way — a run waiting on a runner outlives the lease as a
    /// running one does.
    #[test]
    fn a_queued_listing_renews_the_lease() {
        let mut graph = Graph::default();
        graph.merge(&solo(), 0).expect("merge");
        graph.claim(45, 16, 0, 3_600_000).expect("claim");
        let ix = graph.node_ix(&id("solo")).expect("node");
        // The claim is unbound; the listing binds it by title and
        // renews the lease in the same pass.
        graph.reconcile_runs(
            &[listing(
                11,
                &format!("{RUSTC}-{}", id("solo")),
                CiRunStatus::Queued,
            )],
            50 * 60_000,
        );
        assert_eq!(graph.run_id_of(ix), 11);
        let reclaimed = graph
            .claim(45, 16, 70 * 60_000, 3_600_000)
            .expect("claim pass");
        assert!(reclaimed.is_empty(), "the queued run is not re-dispatched");
        assert_eq!(status_of(&graph, "solo"), Some(Status::Dispatched));
        assert_eq!(graph.run_id_of(ix), 11);
    }

    /// stow#943: a run absent from the listing renews nothing — the
    /// claim's lease lapses at `claimed_at + stale` and the pass
    /// re-dispatches it, exactly as before the renewal.
    #[test]
    fn an_unlisted_own_run_lets_the_lease_lapse() {
        let mut graph = Graph::default();
        graph.merge(&solo(), 0).expect("merge");
        let claimed = graph.claim(45, 16, 0, 3_600_000).expect("claim");
        graph.bind(&id("solo"), claimed[0].generation, 11, 1_000);
        graph.reconcile_runs(&[], 50 * 60_000);
        let reclaimed = graph
            .claim(45, 16, 70 * 60_000, 3_600_000)
            .expect("claim pass");
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].task_id, id("solo"));
        assert!(reclaimed[0].generation > claimed[0].generation);
    }

    /// stow#943: the wake plan's in-flight expiry moves with the
    /// renewal — a claim renewed at t0+50min wakes at t0+110min, not
    /// the t0+60min its claim stamp alone gives.
    #[test]
    fn the_wake_plan_tracks_a_renewed_lease() {
        let settings = queue::SchedulerSettings::default();
        let stale = i64::from(settings.stale_dispatch_minutes) * 60_000;
        let mut graph = Graph::default();
        graph.merge(&solo(), 0).expect("merge");
        let ix = graph.node_ix(&id("solo")).expect("node");
        graph.mark_claimed(ix, 7, 0);
        let renewed = 50 * 60_000;
        graph.reconcile_runs(
            &[listing(
                11,
                &format!("{RUSTC}-{}", id("solo")),
                CiRunStatus::InProgress,
            )],
            renewed,
        );
        // Inside the reconcile interval: the plan reads the renewed
        // lease rather than asking for another listing.
        let now = renewed + 5 * 60_000;
        assert!(!graph.reconcile_due(now, &settings));
        assert_eq!(
            graph.wake_plan(now, &settings),
            queue::AlarmPlan::At(renewed + stale)
        );
    }

    /// stow#940: a failed listing counts as an attempt — the plan goes
    /// back to the lease clock instead of re-arming at once, so a
    /// failing listing cannot spin the alarm.
    #[test]
    fn a_failed_reconcile_waits_out_the_interval() {
        let settings = queue::SchedulerSettings::default();
        let stale = i64::from(settings.stale_dispatch_minutes) * 60_000;
        let mut graph = Graph::default();
        graph.merge(&solo(), 0).expect("merge");
        let ix = graph.node_ix(&id("solo")).expect("node");
        graph.mark_claimed(ix, 7, 0);
        let now = Graph::STATUS_RECONCILE_MS;
        assert!(now < stale);
        assert_eq!(graph.wake_plan(now, &settings), queue::AlarmPlan::At(now));
        graph.reconcile_failed(now);
        assert!(!graph.reconcile_due(now, &settings));
        assert_eq!(graph.wake_plan(now, &settings), queue::AlarmPlan::At(stale));
    }

    /// stow#940: a paused scheduler holding only queued work has
    /// nothing a listing could release, so it asks for none and plans
    /// no wake.
    #[test]
    fn a_paused_queue_plans_no_reconcile_wake() {
        let settings = queue::SchedulerSettings {
            dispatch: queue::Dispatch::Paused,
            ..queue::SchedulerSettings::default()
        };
        let mut graph = Graph::default();
        graph.merge(&solo(), 0).expect("merge");
        let now = Graph::STATUS_RECONCILE_MS;
        assert!(!graph.reconcile_due(now, &settings));
        assert_eq!(graph.wake_plan(now, &settings), queue::AlarmPlan::Delete);
    }

    /// stow#1039: the operator's `set` replaces the binding caps in the
    /// settings the scheduler object builds — a `--macos`-less set
    /// leaves that cap on its binding, a lowered cap frees nothing in
    /// flight, and `0` pauses dispatch like the binding's `"0"`. The
    /// graph reads only the settings it is passed: a caller's explicit
    /// settings stay authoritative over the stored setting.
    #[test]
    fn the_operator_cap_replaces_the_bindings_in_built_settings() {
        let bindings = queue::SchedulerSettings::default();
        let macos = bindings.max_concurrent_macos_jobs;
        let mut graph = Graph::default();
        graph.merge(&solo(), 0).expect("merge");
        let built = |graph: &Graph| bindings.with_dispatch_cap(graph.dispatch_cap());
        // No setting yet: the bindings rule.
        assert_eq!(graph.free_slots(&built(&graph)), (45, macos));

        let set = |jobs: u32, macos: Option<u32>| SchedulerEvent::DispatchCap {
            setting: Box::new(stow_types::api::DispatchCapSetting {
                max_concurrent_jobs: jobs,
                max_concurrent_macos_jobs: macos,
                set_at: "2026-01-01T00:00:00Z".to_owned(),
                actor: "ops".to_owned(),
            }),
        };
        graph.apply(&set(3, None), 0);
        assert_eq!(graph.free_slots(&built(&graph)), (3, macos));
        // Explicit settings are never second-guessed by the stored one.
        assert_eq!(graph.free_slots(&bindings), (45, macos));

        // A lowered cap moves nothing in flight — the claimed row
        // holds its slot and the count saturates at zero, not a free
        // slot it must yield.
        let ix = graph.node_ix(&id("solo")).expect("node");
        graph.mark_claimed(ix, 1, 0);
        assert_eq!(graph.free_slots(&built(&graph)), (2, macos));
        graph.apply(&set(1, Some(1)), 0);
        assert_eq!(graph.free_slots(&built(&graph)), (0, 1));
        graph.apply(&set(0, None), 0);
        let paused = built(&graph);
        assert_eq!(paused.dispatch, queue::Dispatch::Paused);
        assert_eq!(graph.free_slots(&paused), (0, macos));

        let view = graph.dispatch_cap_view(&paused);
        assert_eq!(view.max_concurrent_jobs, 0);
        assert_eq!(view.max_concurrent_macos_jobs, macos);
        assert_eq!(view.setting.map(|set| set.max_concurrent_jobs), Some(0));
    }

    /// stow#940: a `running` state the reconcile restored stamps its
    /// sighting — the staleness rule trips once the bound runs out
    /// with no delivery, exactly as it did for a delivered
    /// `in_progress`.
    #[test]
    fn health_reconciled_running_goes_unhealthy_after_the_bound() {
        use stow_types::api::HealthState;
        let t0 = 1_000_000i64;
        let mut graph = Graph::default();
        graph.merge(&solo(), t0).expect("merge");
        let ix = graph.node_ix(&id("solo")).expect("node");
        graph.mark_claimed(ix, 1, t0);
        graph.reconcile_runs(
            &[listing(
                42,
                &format!("{RUSTC}-{}", id("solo")),
                CiRunStatus::InProgress,
            )],
            t0,
        );
        assert_eq!(status_of(&graph, "solo"), Some(Status::Running));
        assert_eq!(
            graph.health(t0 + Graph::DELIVERY_STALE_MS).scheduler,
            HealthState::Ok
        );
        assert_eq!(
            graph.health(t0 + Graph::DELIVERY_STALE_MS + 1).scheduler,
            HealthState::Unhealthy
        );
    }

    /// stow#940: a completion for an unbound claim no pass is settling
    /// — the dispatched-unbound state a wake's replay leaves — binds
    /// the run and finishes the claim, where it used to park forever.
    #[test]
    fn a_completion_binds_a_replayed_unbound_claim() {
        let mut graph = Graph::default();
        graph.merge(&solo(), 0).expect("merge");
        let ix = graph.node_ix(&id("solo")).expect("node");
        graph.mark_claimed(ix, 7, 0);
        let outcome = graph.run_finished(&id("solo"), 4242, true, false, None, 10_000);
        assert_eq!(outcome, FinishOutcome::Applied);
        assert_eq!(graph.run_id_of(ix), 4242);
        assert_eq!(status_of(&graph, "solo"), Some(Status::Completed));
    }

    /// stow#940: a dispatch POST that failed after GitHub created the
    /// run re-queues the claim; the re-claim's binding never lands,
    /// and the orphaned run's completion binds and finishes the claim.
    #[test]
    fn a_completion_binds_after_a_failed_dispatch() {
        let mut graph = Graph::default();
        graph.merge(&solo(), 0).expect("merge");
        let claimed = graph.claim(45, 16, 0, 3_600_000).expect("claim");
        graph.mark_dispatch_failed(&id("solo"), claimed[0].generation, "POST failed", 1_000);
        let ix = graph.node_ix(&id("solo")).expect("node");
        assert_eq!(graph.node(ix).status, Status::Pending);
        graph.edit_extra(ix, |extra| extra.not_before = 0);
        graph.refresh_ready(ix);
        let reclaimed = graph.claim(45, 16, 2_000, 3_600_000).expect("reclaim");
        assert_eq!(reclaimed.len(), 1);
        // The reclaim pass's settle never lands (an eviction, a lost
        // answer): a woken graph carries no settling set.
        graph.settling.clear();
        let outcome = graph.run_finished(&id("solo"), 4242, true, false, None, 10_000);
        assert_eq!(outcome, FinishOutcome::Applied);
        assert_eq!(graph.run_id_of(ix), 4242);
        assert_eq!(status_of(&graph, "solo"), Some(Status::Completed));
    }

    /// One named node under `source`, the tree shape `merge` takes.
    fn single(name: &str, source: SubmissionSource) -> SubmissionTree {
        SubmissionTree {
            source,
            roots: vec![0],
            nodes: vec![sub(name)],
        }
    }

    /// stow#879: the rank is `priority × time waited`. A 30× request
    /// waiting 2 minutes ties a 1× miss waiting an hour — the tie
    /// falls to the older `first_requested` (the miss), and a second
    /// later the request leads.
    #[test]
    fn claim_rank_is_priority_times_waited() {
        let mut graph = Graph::default();
        graph
            .merge(&single("missed", SubmissionSource::CacheMiss), 0)
            .expect("miss merge");
        graph
            .merge(
                &single("asked", SubmissionSource::HumanRequest),
                58 * 60_000,
            )
            .expect("request merge");
        // At +60 min: miss 100 × 60min == request 3000 × 2min; the
        // miss's earlier first_requested wins the tie.
        let claimed = graph.claim(2, 16, 60 * 60_000, 3_600_000).expect("claim");
        let ids: Vec<_> = claimed.iter().map(|claim| claim.task_id.clone()).collect();
        assert_eq!(
            ids,
            vec![id("missed"), id("asked")],
            "tied rank, older first"
        );
    }

    /// stow#879: waited time is uncapped — a preheat node (operand 10)
    /// eventually outranks misses (operand 100) submitted after it.
    #[test]
    fn a_waited_preheat_outranks_fresh_misses() {
        let mut graph = Graph::default();
        graph
            .merge(&single("low", SubmissionSource::Preheat), 0)
            .expect("preheat merge");
        graph
            .merge(&single("fresh", SubmissionSource::CacheMiss), 10_000_000)
            .expect("miss merge");
        // At +11M ms: preheat 10 × 11M = 110M outranks the miss's
        // 100 × 1M = 100M — the waited node wins eventually (stow#879).
        let claimed = graph.claim(2, 16, 11_000_000, 3_600_000).expect("claim");
        let ids: Vec<_> = claimed.iter().map(|claim| claim.task_id.clone()).collect();
        assert_eq!(ids, vec![id("low"), id("fresh")]);
    }

    /// stow#879: a node reached from a higher-priority entry point
    /// merges to the max priority and keeps its first-requested time.
    #[test]
    fn a_remerge_takes_the_highest_priority() {
        let mut graph = Graph::default();
        graph
            .merge(&single("shared", SubmissionSource::Preheat), 0)
            .expect("preheat merge");
        graph
            .merge(&single("shared", SubmissionSource::HumanRequest), 1_000)
            .expect("request remerge");
        graph
            .merge(&single("rival", SubmissionSource::HumanRequest), 1_000)
            .expect("rival merge");
        let ix = graph.node_ix(&id("shared")).expect("node");
        assert_eq!(graph.state(ix).priority, queue::REQUEST_PRIORITY);
        assert_eq!(graph.state(ix).first_requested, 0);
        // Same class as the rival, but twice the wait — it leads.
        let claimed = graph.claim(2, 16, 2_000, 3_600_000).expect("claim");
        let ids: Vec<_> = claimed.iter().map(|claim| claim.task_id.clone()).collect();
        assert_eq!(ids, vec![id("shared"), id("rival")]);
    }

    /// stow#879: operations submissions carry the caller's operand.
    #[test]
    fn operations_carry_the_callers_priority() {
        let mut graph = Graph::default();
        graph
            .merge(
                &single("ops", SubmissionSource::Operations { priority: 500 }),
                0,
            )
            .expect("ops merge");
        graph
            .merge(&single("miss", SubmissionSource::CacheMiss), 0)
            .expect("miss merge");
        // 500 vs 100 at equal waits — the operations node leads.
        let claimed = graph.claim(1, 16, 1_000, 3_600_000).expect("claim");
        assert_eq!(claimed[0].task_id, id("ops"));
    }

    #[test]
    fn failure_retries_then_fails_and_blocks_dependents() {
        let mut graph = Graph::default();
        graph.merge(&chain(), 0).expect("merge");
        let claimed = graph.claim(45, 16, 0, 3_600_000).expect("claim c");
        graph.bind(&id("c"), claimed[0].generation, 77, 1_000);
        for _ in 1..queue::MAX_BUILD_ATTEMPTS {
            graph.run_finished(&id("c"), 77, false, false, Some("boom".into()), 2_000);
            let ix = graph.node_ix(&id("c")).expect("node");
            assert_eq!(graph.node(ix).status, Status::Pending);
            graph.edit_extra(ix, |extra| extra.not_before = 0);
            graph.refresh_ready(ix);
            let claimed = graph.claim(45, 16, 3_000, 3_600_000).expect("reclaim");
            graph.bind(&id("c"), claimed[0].generation, 77, 4_000);
        }
        graph.run_finished(&id("c"), 77, false, false, Some("boom".into()), 5_000);
        assert_eq!(status_of(&graph, "c"), Some(Status::Failed));
        let b = graph.node_ix(&id("b")).expect("b");
        assert!(graph.node(b).flags.blocked());
        assert_eq!(ready_count(&graph), 0);
        let affected = graph.mutate(MutationKind::Retry, &[id("c")], 6_000);
        assert_eq!(affected, 1);
        assert!(!graph.node(b).flags.blocked());
    }

    /// `top` depends on the leaves `x` and `y`.
    fn fork() -> SubmissionTree {
        let x = sub("x");
        let y = sub("y");
        let mut top = sub("top");
        top.deps = vec![0, 1];
        SubmissionTree {
            source: SubmissionSource::CacheMiss,
            roots: vec![2],
            nodes: vec![x, y, top],
        }
    }

    /// Put `name` in `failed` the way the failure path leaves it.
    fn fail(graph: &mut Graph, name: &str) {
        let ix = graph.node_ix(&id(name)).expect("node");
        graph.set_status(ix, Status::Failed);
        graph.remove_ready(ix);
        for owner in graph.dependents_of(ix) {
            graph.refresh_blocked(owner);
        }
    }

    fn top_state(graph: &Graph) -> (bool, bool) {
        let top = graph.node_ix(&id("top")).expect("top");
        (graph.node(top).flags.blocked(), graph.dispatchable(top))
    }

    /// stow#1050: the only failed dependency publishes.
    #[test]
    fn a_consumer_unblocks_when_its_only_failed_dep_publishes() {
        let mut graph = Graph::default();
        graph.merge(&chain(), 0).expect("merge");
        fail(&mut graph, "c");
        let b = graph.node_ix(&id("b")).expect("b");
        assert!(graph.node(b).flags.blocked());
        publish(&mut graph, "c");
        assert_eq!(graph.node(b).unmet, 0);
        assert!(!graph.node(b).flags.blocked());
        assert!(graph.dispatchable(b));
        assert_eq!(ready_count(&graph), 1);
        assert_pending_index(&graph);
    }

    /// stow#1050: one of two failed dependencies publishes.
    #[test]
    fn a_consumer_stays_blocked_on_its_other_failed_dep() {
        let mut graph = Graph::default();
        graph.merge(&fork(), 0).expect("merge");
        fail(&mut graph, "x");
        fail(&mut graph, "y");
        assert_eq!(top_state(&graph), (true, false));
        publish(&mut graph, "x");
        assert_eq!(top_state(&graph), (true, false), "y is still failed");
        assert_pending_index(&graph);
        publish(&mut graph, "y");
        assert_eq!(top_state(&graph), (false, true));
        assert_pending_index(&graph);
    }

    /// A slice retirement re-opens an edge onto a failed dep: the
    /// consumer is blocked again.
    #[test]
    fn a_retired_dep_row_blocks_the_consumer_on_a_failed_dep() {
        let mut graph = Graph::default();
        graph.merge(&fork(), 0).expect("merge");
        publish(&mut graph, "x");
        fail(&mut graph, "y");
        assert_eq!(top_state(&graph), (true, false));
        let live = graph.slice_generation(TARGET, RUSTC);
        graph.apply_slice_report(
            TARGET,
            RUSTC,
            live,
            live.map_or(1, |live| live + 1),
            &[],
            &[
                published_row("x", UnitKind::Linked),
                published_row("x", UnitKind::Unlinked),
            ],
        );
        assert_eq!(top_state(&graph), (true, false));
        publish(&mut graph, "y");
        assert!(!top_state(&graph).0, "y published; x still unmet");
        assert!(!top_state(&graph).1, "x's edge is unmet");
        assert_pending_index(&graph);
    }

    /// Purging a failed dep publishes it; its consumers are unblocked.
    #[test]
    fn purging_a_failed_dep_unblocks_its_consumers() {
        let mut graph = Graph::default();
        graph.merge(&chain(), 0).expect("merge");
        fail(&mut graph, "c");
        let b = graph.node_ix(&id("b")).expect("b");
        assert!(graph.node(b).flags.blocked());
        assert_eq!(graph.mutate(MutationKind::Purge, &[id("c")], 1_000), 1);
        assert!(!graph.node(b).flags.blocked());
        assert_pending_index(&graph);
    }

    /// A retry clears the flag only when no other dep is failed.
    #[test]
    fn retry_unblocks_only_when_no_other_dep_is_failed() {
        let mut graph = Graph::default();
        graph.merge(&fork(), 0).expect("merge");
        fail(&mut graph, "x");
        fail(&mut graph, "y");
        assert_eq!(graph.mutate(MutationKind::Retry, &[id("x")], 1_000), 1);
        assert_eq!(top_state(&graph), (true, false), "y is still failed");
        assert_eq!(graph.mutate(MutationKind::Retry, &[id("y")], 1_000), 1);
        assert!(!top_state(&graph).0);
        assert_pending_index(&graph);
    }

    /// The status reads come from the pending index, so it must match
    /// the arena after every kind of transition: a merge, a failure
    /// that blocks dependents, each operator verb, a publish, a
    /// compaction and a wake.
    #[test]
    fn the_pending_index_tracks_every_transition() {
        let mut graph = Graph::default();
        graph.merge(&chain(), 1_000).expect("merge");
        assert_pending_index(&graph);
        let claimed = graph.claim(45, 16, 1_000, 3_600_000).expect("claim c");
        graph.bind(&id("c"), claimed[0].generation, 77, 1_000);
        assert_pending_index(&graph);
        for _ in 1..queue::MAX_BUILD_ATTEMPTS {
            graph.run_finished(&id("c"), 77, false, false, Some("boom".into()), 2_000);
            assert_pending_index(&graph);
            let ix = graph.node_ix(&id("c")).expect("node");
            graph.edit_extra(ix, |extra| extra.not_before = 0);
            graph.refresh_ready(ix);
            let claimed = graph.claim(45, 16, 3_000, 3_600_000).expect("reclaim");
            graph.bind(&id("c"), claimed[0].generation, 77, 4_000);
        }
        graph.run_finished(&id("c"), 77, false, false, Some("boom".into()), 5_000);
        assert_pending_index(&graph);
        assert_eq!(graph.status().blocked, 1, "b waits on the failed c");

        for (name, at) in [("h1", 6_000), ("h2", 7_000)] {
            let tree = SubmissionTree {
                source: SubmissionSource::HumanRequest,
                roots: vec![0],
                nodes: vec![sub(name)],
            };
            graph.merge(&tree, at).expect("merge human");
        }
        assert_pending_index(&graph);
        assert_eq!(graph.status().human_pending, 2);
        assert_eq!(graph.mutate(MutationKind::Promote, &[id("b")], 8_000), 1);
        assert_pending_index(&graph);
        assert_eq!(graph.status().human_pending, 3);
        assert_eq!(graph.mutate(MutationKind::Retry, &[id("c")], 9_000), 1);
        assert_pending_index(&graph);
        assert_eq!(graph.status().blocked, 0, "c left failed");
        assert_eq!(graph.mutate(MutationKind::Cancel, &[id("h1")], 10_000), 1);
        assert_pending_index(&graph);
        assert_eq!(graph.mutate(MutationKind::Purge, &[id("h1")], 11_000), 1);
        assert_pending_index(&graph);

        let status = graph.admin_status(1_000 + 61_000).expect("admin status");
        assert_eq!(
            status.oldest_pending_seconds,
            Some(61),
            "a and b from t=1000"
        );
        assert_eq!((status.pending_human, status.pending_miss), (2, 2));

        let claimed = graph.claim(45, 16, 12_000, 3_600_000).expect("claim");
        for (run, task) in (100u64..).zip(&claimed) {
            graph.bind(&task.task_id, task.generation, run, 12_000);
            graph.run_finished(&task.task_id, run, true, false, None, 13_000);
        }
        assert_pending_index(&graph);
        // A human node behind the purged h1's slot: the compaction
        // renumbers it.
        let tree = SubmissionTree {
            source: SubmissionSource::HumanRequest,
            roots: vec![0],
            nodes: vec![sub("h3")],
        };
        graph.merge(&tree, 14_000).expect("merge h3");
        publish(&mut graph, "c");
        assert_pending_index(&graph);
        let h3 = graph.node_ix(&id("h3")).expect("h3");
        graph.compact();
        assert_ne!(
            graph.node_ix(&id("h3")),
            Some(h3),
            "the compaction moved h3"
        );
        assert_pending_index(&graph);

        let restored = round_trip(&graph);
        assert_pending_index(&restored);
        assert_eq!(restored.status(), graph.status());
    }

    #[test]
    fn stale_lease_reclaims_dispatch() {
        let mut graph = Graph::default();
        graph.merge(&solo(), 0).expect("merge");
        graph.claim(45, 16, 0, 3_600_000).expect("claim");
        let claimed = graph.claim(45, 16, 4_000_000, 3_600_000).expect("stale");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].task_id, id("solo"));
    }

    #[test]
    fn submit_ids_promotes_known_and_reports_unknown() {
        let mut graph = Graph::default();
        graph.merge(&chain(), 0).expect("merge");
        let (inserted, unknown) = graph.submit_by_ids(&[
            SubmitTaskIdEntry {
                task_id: id("a"),
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
        graph.run_finished(&id("c"), 100, true, false, None, 10_000);
        publish(&mut graph, "c");
        graph.meter.roll_to("2026-10-23");
        graph.meter.record("test", 7, 11);
        graph.seeded_rows = Some(10_000);
        let mut restored = round_trip(&graph);
        assert_eq!(restored.status(), graph.status());
        // stow#931: the head carries only the probe ledger — the day
        // totals live in the `meter` table row alone.
        assert_eq!(restored.meter.rows_read, 0);
        assert_eq!(restored.meter.rows_written, 0);
        assert_eq!(restored.meter.ops.get("test"), Some(&(1, 7, 11)));
        assert_eq!(restored.seeded_rows, Some(10_000));
        let claimed = restored.claim(45, 16, 20_000, 3_600_000).expect("claim b");
        assert_eq!(claimed[0].task_id, id("b"));
        assert_eq!(claimed[0].payload.dependency_subgraph.nodes.len(), 1);
    }

    #[test]
    fn snapshot_refuses_a_graph_with_freed_nodes() {
        let mut graph = Graph::default();
        graph.merge(&solo(), 0).expect("merge");
        publish(&mut graph, "solo");
        assert_eq!(graph.counts[Status::Free.index()], 1);
        assert!(graph.snapshot_plan().is_err());
        graph.compact();
        assert!(graph.snapshot_plan().is_ok());
    }

    #[test]
    fn cancelled_completion_requeues_without_attempt() {
        let mut graph = Graph::default();
        graph.merge(&solo(), 0).expect("merge");
        let claimed = graph.claim(45, 16, 0, 3_600_000).expect("claim");
        graph.bind(&id("solo"), claimed[0].generation, 9, 1_000);
        let outcome = graph.run_finished(&id("solo"), 9, false, true, None, 2_000);
        assert_eq!(outcome, FinishOutcome::Applied);
        let ix = graph.node_ix(&id("solo")).expect("node");
        assert_eq!(graph.node(ix).status, Status::Pending);
        assert_eq!(graph.state(ix).attempt, 1);
    }

    #[test]
    fn external_runs_count_occupancy() {
        let mut graph = Graph::default();
        let outcome = graph.run_started("nobodys-task", 555, RunnerFamily::Linux, 0);
        assert_eq!(outcome, StartOutcome::External);
        assert_eq!(graph.external_total(), 1);
        graph.run_finished("nobodys-task", 555, true, false, None, 0);
        assert_eq!(graph.external_total(), 0);
    }

    #[test]
    fn claim_order_is_rank_then_arrival() {
        let mut graph = Graph::default();
        let mut first = sub("first");
        first.downloads = 1_000;
        graph
            .merge(&single("older", SubmissionSource::CacheMiss), 0)
            .expect("older merge");
        graph
            .merge(&single("newer", SubmissionSource::CacheMiss), 1_000)
            .expect("newer merge");
        // Same operand class: the rank reduces to time waited — the
        // older node leads regardless of downloads (stow#879).
        let claimed = graph.claim(1, 16, 2_000, 3_600_000).expect("claim");
        assert_eq!(claimed[0].task_id, id("older"));
    }

    /// The record's presence is the flag: the `Freeze` event sets it,
    /// a clear lands as `record: None` — the SQL `settings` row it
    /// replaced read exactly that way (stow#878 stage 7).
    #[test]
    fn freeze_record_applies_and_clears() {
        use stow_types::api::{
            ChannelOutcome, DispatchFreezeRecord, DispatchFreezeTrigger, SchedulerEvent,
        };
        let record = DispatchFreezeRecord {
            frozen_at: "2026-09-22T03:51:00Z".to_owned(),
            trigger: DispatchFreezeTrigger::Manual {
                actor: "test".to_owned(),
            },
            notify: ChannelOutcome::Disabled {
                reason: "test".to_owned(),
            },
        };
        let mut graph = Graph::default();
        assert!(graph.freeze().is_none());
        graph.apply(
            &SchedulerEvent::Freeze {
                at: record.frozen_at.clone(),
                trigger: record.trigger.clone(),
                record: Some(Box::new(record.clone())),
            },
            0,
        );
        assert_eq!(graph.freeze(), Some(&record));
        graph.apply(
            &SchedulerEvent::Freeze {
                at: "2026-09-22T04:00:00Z".to_owned(),
                trigger: DispatchFreezeTrigger::Manual {
                    actor: "test".to_owned(),
                },
                record: None,
            },
            0,
        );
        assert!(graph.freeze().is_none());
    }

    /// While frozen, claim returns nothing and `next_wake` plans no
    /// alarm — but merge keeps accepting misses, which dispatch on the
    /// clear. The queue-side `claim`/`next_alarm` gates it replaced
    /// read the same flag (stow#878 stage 7).
    #[test]
    fn freeze_gates_claim_and_next_wake_but_not_merge() {
        use stow_types::api::{
            ChannelOutcome, DispatchFreezeRecord, DispatchFreezeTrigger, SchedulerEvent,
        };
        let record = DispatchFreezeRecord {
            frozen_at: "2026-09-22T03:51:00Z".to_owned(),
            trigger: DispatchFreezeTrigger::Manual {
                actor: "test".to_owned(),
            },
            notify: ChannelOutcome::Disabled {
                reason: "test".to_owned(),
            },
        };
        let mut graph = Graph::default();
        graph.merge(&chain(), 0).expect("merge while frozen");
        graph.apply(
            &SchedulerEvent::Freeze {
                at: record.frozen_at.clone(),
                trigger: record.trigger.clone(),
                record: Some(Box::new(record)),
            },
            0,
        );
        assert!(graph.claim(45, 16, 0, 3_600_000).expect("claim").is_empty());
        assert_eq!(
            graph.wake_plan(0, &queue::SchedulerSettings::default()),
            queue::AlarmPlan::Delete
        );
        graph.apply(
            &SchedulerEvent::Freeze {
                at: "2026-09-22T04:00:00Z".to_owned(),
                trigger: DispatchFreezeTrigger::Manual {
                    actor: "test".to_owned(),
                },
                record: None,
            },
            0,
        );
        assert_eq!(graph.claim(45, 16, 0, 3_600_000).expect("claim").len(), 1);
    }

    /// A `solo` node claimed and moved to `running` by its accepted
    /// `in_progress` delivery, stamped at `now` — the state the
    /// delivery-staleness rule reads (stow#860).
    fn running_graph(now: i64) -> Graph {
        let mut graph = Graph::default();
        graph.merge(&solo(), now).expect("merge");
        let ix = graph.node_ix(&id("solo")).expect("node");
        graph.mark_claimed(ix, 1, now);
        assert_eq!(
            graph.run_started(&id("solo"), 42, stow_types::api::RunnerFamily::Linux, now),
            StartOutcome::Applied
        );
        graph
    }

    /// A frozen scheduler is unhealthy whatever its deliveries look
    /// like, and the body names the trigger the record carries.
    #[test]
    fn health_frozen_scheduler_is_unhealthy() {
        use stow_types::api::{
            ChannelOutcome, DispatchFreezeRecord, DispatchFreezeTrigger, HealthState,
        };
        let mut graph = Graph::default();
        graph.apply(
            &SchedulerEvent::Freeze {
                at: "2026-10-24T00:00:00Z".to_owned(),
                trigger: DispatchFreezeTrigger::Manual {
                    actor: "test".to_owned(),
                },
                record: Some(Box::new(DispatchFreezeRecord {
                    frozen_at: "2026-10-24T00:00:00Z".to_owned(),
                    trigger: DispatchFreezeTrigger::Manual {
                        actor: "test".to_owned(),
                    },
                    notify: ChannelOutcome::Disabled {
                        reason: "test".to_owned(),
                    },
                })),
            },
            0,
        );
        let health = graph.health(1_000);
        assert_eq!(health.scheduler, HealthState::Unhealthy);
        assert_eq!(health.worker, HealthState::Ok);
        assert!(health.dispatch_frozen);
        assert_eq!(health.freeze_trigger.as_deref(), Some("manual"));
    }

    /// A `running` run whose last accepted delivery aged past
    /// `build-crate.yml`'s job-timeout bound means deliveries stopped.
    #[test]
    fn health_stale_deliveries_with_a_running_run_is_unhealthy() {
        use stow_types::api::HealthState;
        let t0 = 1_000_000i64;
        let graph = {
            let mut graph = running_graph(t0);
            graph.apply(&SchedulerEvent::RunUpdate, t0);
            graph
        };
        assert_eq!(
            graph.health(t0 + Graph::DELIVERY_STALE_MS).scheduler,
            HealthState::Ok,
            "the bound itself is still inside it"
        );
        let health = graph.health(t0 + Graph::DELIVERY_STALE_MS + 1);
        assert_eq!(health.scheduler, HealthState::Unhealthy);
        assert_eq!(
            health.last_run_update_age_seconds,
            Some(u64::try_from(Graph::DELIVERY_STALE_MS + 1).expect("positive") / 1_000)
        );
    }

    /// Deliveries may be arbitrarily old when nothing runs — an idle
    /// scheduler is healthy however stale the last one is.
    #[test]
    fn health_idle_with_an_old_delivery_is_healthy() {
        use stow_types::api::HealthState;
        let mut graph = Graph::default();
        graph.apply(&SchedulerEvent::RunUpdate, 1_000);
        let health = graph.health(1_000 + Graph::DELIVERY_STALE_MS * 10);
        assert_eq!(health.scheduler, HealthState::Ok);
        assert!(!health.dispatch_frozen);
        assert_eq!(health.freeze_trigger, None);
        assert_eq!(
            health.last_run_update_age_seconds,
            Some(u64::try_from(Graph::DELIVERY_STALE_MS * 10).expect("positive") / 1_000)
        );
    }

    /// A queue that only dispatched — no `in_progress` accepted yet —
    /// is healthy: a claimed-but-not-running run is not owed a
    /// `completed` delivery.
    #[test]
    fn health_dispatched_only_is_healthy() {
        use stow_types::api::HealthState;
        let mut graph = Graph::default();
        graph.merge(&solo(), 1_000).expect("merge");
        let ix = graph.node_ix(&id("solo")).expect("node");
        graph.mark_claimed(ix, 1, 1_000);
        assert_eq!(status_of(&graph, "solo"), Some(Status::Dispatched));
        let health = graph.health(1_000 + Graph::DELIVERY_STALE_MS * 10);
        assert_eq!(health.scheduler, HealthState::Ok);
        assert_eq!(health.last_run_update_age_seconds, None);
    }
}
