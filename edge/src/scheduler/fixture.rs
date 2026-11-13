//! Deterministic production-shaped scheduler state for the stow#433 cost
//! gate: the in-memory dependency graph, its flat snapshot and a short
//! log tail (stow#878). Every node is a pure function of its queue
//! order `n`, and every state it holds was reached through the same
//! events a live scheduler appends — `Submit` merges, `Claims`,
//! `Bindings`, `RunFinished`, `SliceReport`, `Mutate` — so the budget
//! drives measure code paths over the shape production keeps, never a
//! hand-built memory image. The same builder seeds both harnesses: the
//! host gate drives [`GATE`] (10k nodes) and the workerd harness seeds
//! [`FixtureShape::PRODUCTION`] and the larger size
//! `STOW_TRAFFIC_SIZES` carries.
//!
//! Shape, in queue order `n` (the `stow_types::fixture` arithmetic):
//! * `n <= pending_end` are `pending` — about 60%;
//! * the next ~35% are `completed` and published: their unit shapes sit
//!   in the live slices, so the node retires to the slim published
//!   identity the way a published node leaves memory;
//! * ~2.5% are `failed` (a cancelled pending node), and so is the tail
//!   past the in-flight window;
//! * exactly [`FixtureShape::IN_FLIGHT_ROWS`] are `dispatched`/`running`
//!   — each claimed and bound to its own run in the log tail, the way
//!   a dispatch pass leaves them;
//! * the claimable pending span is the planted window of
//!   at least [`FixtureShape::DISPATCH_ELIGIBLE_ROWS`] rows above the human pins,
//!   expanded for the configured dispatch capacity,
//!   each edge met against a 64-leaf pool of published nodes and each
//!   carrying [`WINDOW_DEMAND`] so its Windows rows price above every
//!   bulk row; every other pending row gates on an unmet dependency;
//! * the sixteen human pins hold a met pool edge plus an unmet one — the
//!   human lane stays `pending` and visible without ever claiming;
//! * `first_requested` spreads over the trailing two days and exactly
//!   [`FixtureShape::LAST_24H_ROWS`] completions sit inside the last
//!   24 h — the quantities a route may legitimately be bounded by, held
//!   constant across sizes so the scale check sees only the stored bulk
//!   grow.

use std::collections::HashMap;

use skyzen_services::durable::DurableDb;
use stow_types::api::{
    CI_TARGET_TRIPLES, DispatchBinding, DispatchClaim, MutationKind, PublishedSliceRow,
    RequestAdmission, RequestEvent, SchedulerEvent, SchedulerSeedReport, SubmissionNode,
    SubmissionSource, SubmissionTree,
};
pub use stow_types::fixture::FixtureShape;
use stow_types::fixture::{
    REQUEST_FIXTURE_ENQUEUED, REQUEST_FIXTURE_FAILED, crate_identity, fixture_task_id,
    named_task_id, seeded_rustc, target_of,
};
use stow_types::identity::{
    CrateName, CrateVersion, DependencyIdentity, FeaturesJson, TargetTriple, WireRustcVersion,
};
use stow_types::public_cache::{ExplicitSpelling, UnitInvocation, UnitShape};

use super::graph::{
    Fetched, FreshDigest, Graph, GraphCell, LoadedGraph, PublishedNeeds, PublishedRow,
    ValidatedSubmission,
};
#[cfg(test)]
use super::graph::{IdKey, SliceId};
use super::routes;
use super::store;
use crate::errors::QueueError;

/// The host-gate shape — 10k nodes — small enough that `cargo test`
/// stays fast. Only the host pre-check uses it; the workerd harness
/// seeds `PRODUCTION` and the larger size `STOW_TRAFFIC_SIZES` carries.
#[cfg(test)]
pub const GATE: FixtureShape = FixtureShape { queue_rows: 10_000 };

/// Dispatch limits shared by host graph and store fixtures.
#[cfg(test)]
pub fn claim_settings(total: u32, macos: u32) -> super::queue::SchedulerSettings {
    super::queue::SchedulerSettings {
        dispatch: super::queue::Dispatch::Limited(
            std::num::NonZeroU32::new(total).expect("positive cap"),
        ),
        max_concurrent_macos_jobs: macos,
        ..super::queue::SchedulerSettings::default()
    }
}

/// The stored `demand` every window node carries — folded straight
/// onto the node's rank operand (stow#879), so a window node sits at
/// `MISS_PRIORITY + 1000` while the bulk stays at `MISS_PRIORITY`.
pub const WINDOW_DEMAND: i64 = 1_000;

/// Nodes one submission tree carries while the builder merges — bounded
/// so a tree never holds the whole fixture, and sized to the snapshot's
/// node part.
const TREE_NODES: u32 = 4_096;

/// Log events the tail holds beyond the in-flight claims: demand
/// batches a live scheduler appended since the snapshot, so a wake
/// replay prices a real tail rather than an empty one.
pub const TAIL_DEMAND_BATCHES: u32 = 64;

const DAY_MS: i64 = 86_400_000;
const MINUTE_MS: i64 = 60_000;

/// Slice rows a delta report moves — retired from the live set plus the
/// same number added. The dependent refresh must stay proportional to
/// this, not to the slice.
pub const DELTA_ROWS: u32 = 30;

/// A fixture node's dependency digest — its own hex id, the formula the
/// edges and slice rows agree on.
fn digest_of(n: u64) -> DependencyIdentity {
    stow_types::fixture::digest_hex(n)
        .parse()
        .expect("a 64-hex fixture digest parses")
}

/// A node's published unit shapes — production's `required_unit_shapes`
/// at the node's own side and the invocation `for_task` assigns its
/// target on the family's host triple.
#[must_use]
pub fn node_shapes(host_side: bool, target: &str) -> Vec<UnitShape> {
    let invocation = stow_types::api::runner_family(target)
        .map_or(UnitInvocation::Native, |family| {
            UnitInvocation::for_task(target, family.host_triple())
        });
    stow_types::public_cache::required_unit_shapes(
        host_side,
        invocation,
        ExplicitSpelling::KeysAsNative,
    )
}

/// The fixture node `n` as a submission node, `deps` indexing into its
/// tree. With no deps it is a bare copy: merged against the graph that
/// holds `n` it changes nothing, so a drive's tree can name a fixture
/// node as a dependency.
#[must_use]
pub fn fixture_node(n: u32, deps: Vec<u32>) -> SubmissionNode {
    let (crate_name, version) = crate_identity(n);
    SubmissionNode {
        task_id: fixture_task_id(u64::from(n)),
        crate_name: CrateName::parse(crate_name).expect("fixture crate name"),
        version: CrateVersion::new(semver::Version::parse(&version).expect("fixture version")),
        features_json: FeaturesJson::default(),
        target: TargetTriple::parse(target_of(n)).expect("fixture target"),
        rustc_version: WireRustcVersion::parse(seeded_rustc(u64::from(n))).expect("fixture rustc"),
        host_side: n.is_multiple_of(10),
        explicit_spelling: ExplicitSpelling::KeysAsNative,
        preserve_lockfile: false,
        dependency_identity: digest_of(u64::from(n)),
        deps,
        downloads: u64::from(n % 7) * 1_000,
        profile: stow_types::node_profile::NodeProfile::Dev,
    }
}

/// A drive-owned node outside the fixture's `1..=queue_rows` range:
/// `seed` mints its task id and digest, `name` its crate, so no fixture
/// node shares an identity with it.
#[must_use]
pub fn named_node(name: &str, seed: u64, target: &str, deps: Vec<u32>) -> SubmissionNode {
    SubmissionNode {
        task_id: named_task_id(name, seed, target),
        crate_name: CrateName::parse(name).expect("drive crate name"),
        version: CrateVersion::new(semver::Version::new(1, 0, 0)),
        features_json: FeaturesJson::default(),
        target: TargetTriple::parse(target).expect("drive target"),
        rustc_version: WireRustcVersion::parse("1.86.0").expect("drive rustc"),
        host_side: false,
        explicit_spelling: ExplicitSpelling::KeysAsNative,
        preserve_lockfile: false,
        dependency_identity: digest_of(seed),
        deps,
        downloads: 1,
        profile: stow_types::node_profile::NodeProfile::Dev,
    }
}

/// One slice row of fixture node `n`.
fn slice_row(n: u32, unit_shape: UnitShape) -> PublishedSliceRow {
    let (crate_name, version) = crate_identity(n);
    PublishedSliceRow {
        dependency_identity: digest_of(u64::from(n)),
        crate_name: CrateName::parse(crate_name).expect("fixture crate name"),
        version: CrateVersion::new(semver::Version::parse(&version).expect("fixture version")),
        features_json: FeaturesJson::default(),
        unit_shape,
        node_profile: stow_types::node_profile::NodeProfile::Dev,
    }
}

/// A growing submission tree: owners with their dependency edges, and a
/// bare copy of every dependency the tree does not own (an existing id
/// merges as itself, never rewriting its edges).
struct TreeBuilder {
    nodes: Vec<SubmissionNode>,
    index: HashMap<u32, u32>,
}

impl TreeBuilder {
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            index: HashMap::new(),
        }
    }

    fn ix_of(&mut self, n: u32) -> u32 {
        if let Some(&ix) = self.index.get(&n) {
            return ix;
        }
        let ix = u32::try_from(self.nodes.len()).expect("tree fits u32");
        self.nodes.push(fixture_node(n, Vec::new()));
        self.index.insert(n, ix);
        ix
    }

    /// Add owner `n` with edges onto `deps` (fixture ids).
    fn owner(&mut self, n: u32, deps: &[u32]) {
        let ix = self.ix_of(n);
        let dep_ixs: Vec<u32> = deps.iter().map(|&dep| self.ix_of(dep)).collect();
        self.nodes[ix as usize].deps = dep_ixs;
    }

    fn into_tree(self, source: SubmissionSource) -> SubmissionTree {
        SubmissionTree {
            source,
            roots: Vec::new(),
            nodes: self.nodes,
        }
    }
}

/// One miss-lane tree of the dependency-free fixture nodes `lo..=hi`.
#[cfg(test)]
pub fn fresh_tree(lo: u32, hi: u32) -> SubmissionTree {
    let mut builder = TreeBuilder::new();
    for n in lo..=hi {
        builder.owner(n, &[]);
    }
    builder.into_tree(SubmissionSource::CacheMiss)
}

/// `n * multiplier mod modulus`, exact at any fixture size.
fn spread(n: u32, multiplier: u64, modulus: u32) -> u32 {
    u32::try_from(u64::from(n) * multiplier % u64::from(modulus)).expect("below the modulus")
}

/// Keep two dispatch passes available in each independently capped pool.
/// The window depends on capacity, never on the stored queue size.
fn dispatch_window(settings: &super::queue::SchedulerSettings) -> u32 {
    let total = match settings.dispatch {
        super::queue::Dispatch::Limited(limit) => limit.get(),
        super::queue::Dispatch::Paused => 0,
    };
    let mut non_macos = 0u64;
    let mut macos = 0u64;
    let mut rows = 0;
    while rows < FixtureShape::DISPATCH_ELIGIBLE_ROWS
        || non_macos < 2 * u64::from(total)
        || macos < 2 * u64::from(settings.max_concurrent_macos_jobs.min(total))
    {
        rows += 1;
        let n = FixtureShape::HUMAN_LANE_ROWS + rows;
        if n % 20 == 1 {
            continue;
        }
        if stow_types::api::runner_family(target_of(n))
            == Some(stow_types::api::RunnerFamily::MacOs)
        {
            macos += 1;
        } else {
            non_macos += 1;
        }
    }
    rows
}

/// The dependency ids of pending node `n`, every one a node already in
/// the graph by the time `n`'s tree merges (rows above `pending_end`
/// are built first, and pending deps point at lower `n`).
fn pending_deps(shape: FixtureShape, eligible_rows: u32, n: u32) -> Vec<u32> {
    let rows = shape.queue_rows;
    let human_end = FixtureShape::HUMAN_LANE_ROWS;
    let human_pin = human_end - FixtureShape::HUMAN_PROBE_ROWS;
    let eligible_end = human_end + eligible_rows;
    // The pool starts at `completed_row(2)`, clear of the purge
    // drive's `completed_row(0)`/`completed_row(1)`; the `n % 64` pool
    // spreads the window's edges over 64 published leaves so no leaf
    // accrues fan-in that grows with the window.
    let pool = shape.pending_end() + 3 + n % 64;
    // A pending dep always points below `n`, so it merged earlier.
    let lower = |pick: u32| -> u32 {
        if pick <= shape.pending_end() && pick >= n {
            if n > 1 {
                pick % (n - 1) + 1
            } else {
                shape.failed_row(0)
            }
        } else {
            pick
        }
    };
    if n > human_pin && n <= human_end {
        // A human pin: a met pool edge and an unmet lower one, so it
        // stays `pending` and visible but never claimable.
        return vec![pool, lower(spread(n, 7919, rows) + 1)];
    }
    if n > human_end && n <= eligible_end {
        // The window: met pool edge; the `n % 20 = 1` rows add an
        // unmet one — the production state a parked row holds.
        let mut deps = vec![pool];
        if n % 20 == 1 {
            deps.push(spread(n, 7919, n - 1) + 1);
        }
        return deps;
    }
    // Bulk: the first edge is an unmet lower pending node (or a failed
    // one for the first row), so no bulk row is claimable; every third
    // row adds a spread edge onto the whole queue.
    let first = if n > 1 {
        spread(n, 7919, n - 1) + 1
    } else {
        shape.failed_row(0)
    };
    let mut deps = vec![first];
    if n.is_multiple_of(3) {
        let extra = lower(spread(n, 15_485_863, rows) + 1);
        if extra != first {
            deps.push(extra);
        }
    }
    deps
}

/// The finish instant of completed node `k` (the `k`-th completed row):
/// exactly [`FixtureShape::LAST_24H_ROWS`] land inside the last 24 h,
/// the rest 1-28 days back.
fn finished_at(now: i64, k: u32) -> i64 {
    let minutes = if k < FixtureShape::LAST_24H_ROWS {
        i64::from(k % 1440)
    } else {
        1440 + i64::from(k % 38_880)
    };
    now - minutes * MINUTE_MS
}

/// The next generation a claim mints — the builder owns the counter so
/// every `Claims` event carries a distinct one.
struct Generations(u64);

impl Generations {
    const fn next(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }
}

/// Digest rows the build holds before it flushes them to the store: a
/// merge flushes once at least this many are held, so the ledger never
/// exceeds this plus one tree's [`TREE_NODES`] — the whole population's
/// rows (36 bytes each) are never in memory at once.
const LEDGER_FLUSH_ENTRIES: usize = 4_096;

/// Where the build's rows go and where its published reads come from:
/// the store tables a live scheduler keeps, the seed never holding
/// either population in memory.
pub trait SeedStore {
    /// Write `fresh`, in build order: a later entry of a slot overwrites
    /// an earlier one.
    ///
    /// # Errors
    /// `QueueError::Sql` when the write fails.
    async fn write_digests(&mut self, fresh: &[FreshDigest]) -> Result<(), QueueError>;

    /// Read the `published` rows `needs` names.
    ///
    /// # Errors
    /// `QueueError::Sql` when the read fails.
    async fn read_published(&mut self, needs: &PublishedNeeds) -> Result<Fetched, QueueError>;

    /// Write published `rows` to the `published` table, in the shape a
    /// snapshot's storage turn writes them.
    ///
    /// # Errors
    /// `QueueError::Sql` when the write fails.
    async fn write_published(&mut self, rows: &[PublishedRow]) -> Result<(), QueueError>;
}

/// The store the seed writes the `node_digests` and `published` rows to.
pub struct Stored<'a>(pub &'a DurableDb);

impl SeedStore for Stored<'_> {
    async fn write_digests(&mut self, fresh: &[FreshDigest]) -> Result<(), QueueError> {
        store::write_digests(self.0, fresh).await
    }

    async fn read_published(&mut self, needs: &PublishedNeeds) -> Result<Fetched, QueueError> {
        store::read_published(self.0, needs).await
    }

    async fn write_published(&mut self, rows: &[PublishedRow]) -> Result<(), QueueError> {
        store::write_published(self.0, rows).await
    }
}

/// Host tests that build a graph with no database: the digest rows drop
/// (the graph mints from its own test shadow) and the published rows
/// live in a map standing in for the table.
#[cfg(test)]
#[derive(Default)]
pub struct InMemory {
    table: HashMap<IdKey, (SliceId, u8)>,
}

#[cfg(test)]
impl SeedStore for InMemory {
    fn write_digests(&mut self, _: &[FreshDigest]) -> impl Future<Output = Result<(), QueueError>> {
        std::future::ready(Ok(()))
    }

    fn read_published(
        &mut self,
        needs: &PublishedNeeds,
    ) -> impl Future<Output = Result<Fetched, QueueError>> {
        let mut fetched = Fetched::default();
        for (key, _) in needs.keys() {
            fetched.expect(key);
            if let Some(&(_, mask)) = self.table.get(&key) {
                fetched.set_mask(key, mask);
            }
        }
        for slice in needs.slices() {
            fetched.set_members(
                slice,
                self.table
                    .iter()
                    .filter(|(_, (held, _))| *held == slice)
                    .map(|(&key, &(_, mask))| (key, mask))
                    .collect(),
            );
        }
        std::future::ready(Ok(fetched))
    }

    fn write_published(
        &mut self,
        rows: &[PublishedRow],
    ) -> impl Future<Output = Result<(), QueueError>> {
        for &(slice, key, mask) in rows {
            if mask == 0 {
                self.table.remove(&key);
            } else {
                self.table.insert(key, (slice, mask));
            }
        }
        std::future::ready(Ok(()))
    }
}

/// The digests of the merges since the last flush, in merge order.
struct Ledger<S> {
    sink: S,
    held: Vec<FreshDigest>,
}

impl<S: SeedStore> Ledger<S> {
    /// Write what is held and empty the ledger.
    async fn flush(&mut self) -> Result<(), QueueError> {
        self.sink.write_digests(&self.held).await?;
        self.held.clear();
        Ok(())
    }

    /// Write the graph's published changes to the table and forget
    /// them — the seed's stand-in for a snapshot's storage turn, run
    /// after each batch of reports so the graph never holds the
    /// population's masks.
    async fn flush_published(&mut self, graph: &mut Graph) -> Result<(), QueueError> {
        self.sink
            .write_published(&graph.published_page(None, usize::MAX))
            .await?;
        graph.published_flushed();
        Ok(())
    }
}

/// Merge `tree` and keep the merge honest: a fixture tree that fails to
/// merge is a builder bug.
async fn merge<S: SeedStore>(
    graph: &mut Graph,
    tree: &SubmissionTree,
    at: i64,
    ledger: &mut Ledger<S>,
) -> Result<(), QueueError> {
    let validated = ValidatedSubmission::new(tree)?;
    let mut needs = PublishedNeeds::default();
    graph.merge_needs(&validated, &mut needs);
    let mut base = ledger.sink.read_published(&needs).await?;
    ledger
        .held
        .extend(graph.merge_validated(&validated, at, &mut base)?.digests);
    if ledger.held.len() >= LEDGER_FLUSH_ENTRIES {
        ledger.flush().await?;
    }
    Ok(())
}

/// The `(lo, hi)` runs of at most [`TREE_NODES`] ids covering
/// `start..=end`, in ascending order.
fn runs(start: u32, end: u32) -> impl Iterator<Item = (u32, u32)> {
    (start..=end)
        .step_by(TREE_NODES as usize)
        .map(move |lo| (lo, (lo + TREE_NODES - 1).min(end)))
}

/// Merge fixture nodes `lo..=hi` as one tree of `source`, each on the
/// dependencies `deps` names, born at `at`.
async fn merge_run<S: SeedStore>(
    graph: &mut Graph,
    (lo, hi): (u32, u32),
    source: SubmissionSource,
    at: i64,
    ledger: &mut Ledger<S>,
    deps: impl Fn(u32) -> Vec<u32>,
) -> Result<(), QueueError> {
    let mut builder = TreeBuilder::new();
    for n in lo..=hi {
        builder.owner(n, &deps(n));
    }
    merge(graph, &builder.into_tree(source), at, ledger).await?;
    #[cfg(target_arch = "wasm32")]
    trace_population(graph, "incremental merge completed");
    Ok(())
}

/// The instant node `n` was first requested, spread over the last two
/// days.
fn first_at(shape: FixtureShape, now: i64, n: u32) -> i64 {
    let two_days_ago = now - 2 * DAY_MS;
    two_days_ago + (now - two_days_ago) * i64::from(n) / i64::from(shape.queue_rows.max(1))
}

/// Completed rows: submit, claim, bind, finish at their spread
/// instants, then publish their unit shapes — the node retires to its
/// slim published identity.
async fn build_completed<S: SeedStore>(
    graph: &mut Graph,
    shape: FixtureShape,
    now: i64,
    generations: &mut Generations,
    ledger: &mut Ledger<S>,
) -> Result<(), QueueError> {
    let completed_first = shape.completed_row(0);
    for (lo, hi) in runs(completed_first, shape.completed_end()) {
        merge_run(
            graph,
            (lo, hi),
            SubmissionSource::CacheMiss,
            first_at(shape, now, lo),
            ledger,
            |_| Vec::new(),
        )
        .await?;
        let claims: Vec<DispatchClaim> = (lo..=hi)
            .map(|n| DispatchClaim {
                task_id: fixture_task_id(u64::from(n)),
                generation: generations.next(),
                attempt: 1,
            })
            .collect();
        let bindings: Vec<DispatchBinding> = claims
            .iter()
            .zip(lo..=hi)
            .map(|(claim, n)| DispatchBinding {
                task_id: claim.task_id.clone(),
                generation: claim.generation,
                run_id: n.to_string(),
            })
            .collect();
        graph.apply(
            &SchedulerEvent::Claims { claims },
            finished_at(now, lo - completed_first) - 30 * MINUTE_MS,
        );
        graph.apply(
            &SchedulerEvent::Bindings { bindings },
            finished_at(now, lo - completed_first) - 29 * MINUTE_MS,
        );
        for n in lo..=hi {
            graph.apply(
                &SchedulerEvent::RunFinished {
                    source_failure: None,
                    run_id: n.to_string(),
                    task_id: fixture_task_id(u64::from(n)),
                    success: true,
                    cancelled: false,
                    error: None,
                },
                finished_at(now, n - completed_first),
            );
        }
        for report in slice_reports(graph, lo, hi) {
            let mut needs = PublishedNeeds::default();
            graph.event_needs(&report, &mut needs);
            let mut base = ledger.sink.read_published(&needs).await?;
            graph.apply_slice_report_event(&report, &mut base)?;
        }
        ledger.flush_published(graph).await?;
    }
    Ok(())
}

/// Failed rows: submitted, then cancelled — the failed state an
/// operator verb produces, with the dependents' blocked refresh.
async fn build_failed<S: SeedStore>(
    graph: &mut Graph,
    shape: FixtureShape,
    now: i64,
    ledger: &mut Ledger<S>,
) -> Result<(), QueueError> {
    let ranges = [
        (shape.failed_row(0), shape.failed_end()),
        (
            shape.failed_end() + FixtureShape::IN_FLIGHT_ROWS + 1,
            shape.queue_rows,
        ),
    ];
    for (start, end) in ranges {
        for (lo, hi) in runs(start, end) {
            merge_run(
                graph,
                (lo, hi),
                SubmissionSource::CacheMiss,
                first_at(shape, now, lo),
                ledger,
                |_| Vec::new(),
            )
            .await?;
            let ids: Vec<String> = (lo..=hi).map(|n| fixture_task_id(u64::from(n))).collect();
            graph.apply(
                &SchedulerEvent::Mutate {
                    op: MutationKind::Cancel,
                    task_ids: ids,
                },
                finished_at(now, lo),
            );
        }
    }
    Ok(())
}

/// Pending rows, ascending, split at the human pins so each tree has
/// one source, then the window's stored demand.
async fn build_pending<S: SeedStore>(
    graph: &mut Graph,
    shape: FixtureShape,
    eligible_rows: u32,
    now: i64,
    ledger: &mut Ledger<S>,
) -> Result<(), QueueError> {
    let human_end = FixtureShape::HUMAN_LANE_ROWS;
    let human_pin = human_end - FixtureShape::HUMAN_PROBE_ROWS;
    let segments = [
        (1, human_pin, SubmissionSource::CacheMiss),
        (human_pin + 1, human_end, SubmissionSource::HumanRequest),
        (
            human_end + 1,
            shape.pending_end(),
            SubmissionSource::CacheMiss,
        ),
    ];
    for (start, end, source) in segments {
        for (lo, hi) in runs(start, end) {
            merge_run(
                graph,
                (lo, hi),
                source,
                first_at(shape, now, lo),
                ledger,
                |n| pending_deps(shape, eligible_rows, n),
            )
            .await?;
        }
    }
    let eligible_end = human_end + eligible_rows;
    let window: Vec<(String, i64)> = (human_end + 1..=eligible_end)
        .map(|n| (fixture_task_id(u64::from(n)), WINDOW_DEMAND))
        .collect();
    graph.fold_demand(&window);
    Ok(())
}

/// Build the snapshot-time graph for `shape` at `now` (unix ms): every
/// node and every state except the in-flight claims and the demand
/// tail, which [`tail`] appends after the snapshot is written.
///
/// Every `(state slot, digest)` the merges allocate goes to `sink` in
/// merge order as the build proceeds — the `node_digests` rows the store
/// holds for this graph, a reused slot's later entry overwriting its
/// earlier — never more than [`LEDGER_FLUSH_ENTRIES`] plus one tree at
/// a time.
///
/// # Errors
/// `QueueError::Invariant` when a fixture tree fails to merge,
/// otherwise `sink`'s.
pub async fn build<S: SeedStore>(
    shape: FixtureShape,
    settings: &super::queue::SchedulerSettings,
    now: i64,
    sink: S,
) -> Result<Graph, QueueError> {
    let mut graph = Graph::default();
    let mut ledger = Ledger {
        sink,
        held: Vec::new(),
    };
    let mut generations = Generations(0);
    build_completed(&mut graph, shape, now, &mut generations, &mut ledger).await?;
    #[cfg(target_arch = "wasm32")]
    trace_population(&graph, "completed population built");
    build_failed(&mut graph, shape, now, &mut ledger).await?;
    // The in-flight window's nodes (claimed in the tail).
    let mut builder = TreeBuilder::new();
    for k in 0..FixtureShape::IN_FLIGHT_ROWS {
        builder.owner(shape.in_flight_row(k), &[]);
    }
    merge(
        &mut graph,
        &builder.into_tree(SubmissionSource::CacheMiss),
        now - 35 * MINUTE_MS,
        &mut ledger,
    )
    .await?;
    build_pending(
        &mut graph,
        shape,
        dispatch_window(settings),
        now,
        &mut ledger,
    )
    .await?;
    ledger.flush().await?;
    #[cfg(target_arch = "wasm32")]
    trace_population(&graph, "pending population built");
    seed_requests(&mut graph, shape);
    // The pins above charged the human lane's day; the fixture starts
    // the day unspent, as the SQL fixture's direct rows did.
    graph.human_budget = (0, 0);
    // Replaying the build is not log traffic.
    graph.log_since_snapshot = 0;
    graph.log_bytes_since_snapshot = 0;
    graph.compact();
    Ok(graph)
}

/// `SliceReport` events publishing completed nodes `lo..=hi`, grouped by
/// the `(target, rustc)` slice each belongs to: a slice's first report
/// is full, every later one a delta on the graph's live generation.
pub fn slice_reports(graph: &Graph, lo: u32, hi: u32) -> Vec<SchedulerEvent> {
    let mut groups: std::collections::BTreeMap<
        (&'static str, &'static str),
        Vec<PublishedSliceRow>,
    > = std::collections::BTreeMap::new();
    for n in lo..=hi {
        let target = target_of(n);
        let rustc = seeded_rustc(u64::from(n));
        let rows = groups.entry((target, rustc)).or_default();
        for shape in node_shapes(n.is_multiple_of(10), target) {
            rows.push(slice_row(n, shape));
        }
    }
    groups
        .into_iter()
        .map(|((target, rustc), added)| {
            let live = graph.slice_generation(target, rustc);
            SchedulerEvent::SliceReport {
                target: TargetTriple::parse(target).expect("fixture target"),
                rustc_version: WireRustcVersion::parse(rustc).expect("fixture rustc"),
                base_generation: live,
                generation: live.map_or(1, |live| live + 1),
                part: 0,
                parts: 1,
                added,
                retired: Vec::new(),
            }
        })
        .collect()
}

/// Population and retained Wasm pages at probe phase boundaries. Linear
/// memory includes allocator slack; it is not the isolate's JS heap or
/// Cloudflare's billed memory. No platform memory claim derives from it.
#[cfg(target_arch = "wasm32")]
pub(super) fn trace_population(graph: &Graph, phase: &str) {
    graph.trace_occupancy("fixture population", phase, "observation");
    let (nodes, edges, published) = graph.sizes();
    let status = graph.status();
    let state_nodes = u64::from(status.pending)
        + u64::from(status.dispatched)
        + u64::from(status.running)
        + u64::from(status.completed)
        + u64::from(status.failed);
    tracing::info!(
        phase,
        nodes,
        edges,
        published,
        pending = status.pending,
        state_nodes,
        wasm_linear_bytes = super::memory::linear_bytes(),
        "scheduler probe population"
    );
}

/// The two request records: an `enqueued` one whose stored roots name a
/// pending human node (the status read's re-probe), a published node
/// (the `cached` arm) and a no-library root, and a `failed` one.
fn seed_requests(graph: &mut Graph, shape: FixtureShape) {
    let admission = |request_id: &str, crate_name: &str| RequestAdmission {
        request_id: request_id.to_owned(),
        crate_name: CrateName::parse(crate_name).expect("request crate"),
        version: CrateVersion::new(semver::Version::new(1, 0, 0)),
        features_json: FeaturesJson::default(),
        rustc_version: WireRustcVersion::parse("1.86.0").expect("request rustc"),
        max_closure: 100,
    };
    let pending_root = fixture_task_id(u64::from(FixtureShape::HUMAN_LANE_ROWS - 5));
    // Row 5 stays clear of the purge drive's row-0/1 purges, which
    // run before `GET /requests/{id}` re-probes this root.
    let completed_root = fixture_task_id(u64::from(shape.completed_row(5)));
    let outcome = serde_json::json!([
        {
            "target": CI_TARGET_TRIPLES[0],
            "task_id": pending_root,
            "cached": false,
            "was_queued": false,
        },
        {
            "target": CI_TARGET_TRIPLES[1],
            "task_id": completed_root,
            "cached": false,
            "was_queued": true,
        },
        {
            "target": CI_TARGET_TRIPLES[2],
            "task_id": null,
            "cached": false,
            "was_queued": false,
        },
    ])
    .to_string();
    for (request_id, crate_name, attempt, state, outcome_json, error) in [
        (
            REQUEST_FIXTURE_ENQUEUED,
            "serde",
            1,
            "enqueued",
            Some(outcome),
            None,
        ),
        (
            REQUEST_FIXTURE_FAILED,
            "clap",
            2,
            "failed",
            None,
            Some(
                "resolve run concluded 'failure' (https://github.com/water-rs/stow/actions/runs/43)"
                    .to_owned(),
            ),
        ),
    ] {
        graph.apply(
            &SchedulerEvent::Request {
                request_id: request_id.to_owned(),
                kind: RequestEvent::Admitted {
                    admission: Box::new(admission(request_id, crate_name)),
                    attempt,
                    dispatched_at: 0,
                },
            },
            0,
        );
        graph.apply(
            &SchedulerEvent::Request {
                request_id: request_id.to_owned(),
                kind: RequestEvent::Outcome {
                    attempt,
                    state: state.to_owned(),
                    outcome_json,
                    error,
                },
            },
            0,
        );
    }
}

/// The log tail the seed appends after the snapshot, each event paired
/// with the instant it carries: the in-flight window's claims and
/// bindings — the state a dispatch pass leaves between its POST and
/// the run's `completed` delivery — then [`TAIL_DEMAND_BATCHES`]
/// demand batches. In-flight stamps lie a day ahead, like a live
/// heartbeat, so the stale-lease recovery never reclaims them however
/// long the drives run.
#[must_use]
pub fn tail(shape: FixtureShape, now: i64) -> Vec<(i64, SchedulerEvent)> {
    let claimed_at = now + DAY_MS;
    let claims: Vec<DispatchClaim> = (0..FixtureShape::IN_FLIGHT_ROWS)
        .map(|k| DispatchClaim {
            task_id: shape.in_flight_run(k).task_id,
            // Past every generation the build minted.
            generation: u64::from(shape.queue_rows) + 1 + u64::from(k),
            attempt: 1,
        })
        .collect();
    let bindings: Vec<DispatchBinding> = claims
        .iter()
        .enumerate()
        .map(|(k, claim)| DispatchBinding {
            task_id: claim.task_id.clone(),
            generation: claim.generation,
            run_id: shape
                .in_flight_run(u32::try_from(k).expect("in-flight count fits u32"))
                .run_id
                .to_string(),
        })
        .collect();
    let mut events = vec![
        (claimed_at, SchedulerEvent::Claims { claims }),
        (claimed_at, SchedulerEvent::Bindings { bindings }),
    ];
    for batch in 0..TAIL_DEMAND_BATCHES {
        events.push((
            now,
            SchedulerEvent::Demand {
                batch_id: format!("fixture-tail-{batch}"),
                input_hash: format!("fixture-tail-hash-{batch}"),
                entries: vec![stow_types::api::DemandEntry {
                    task_id: fixture_task_id(u64::from(
                        FixtureShape::HUMAN_LANE_ROWS + 1 + batch % 600,
                    )),
                    delta: 1,
                }],
            },
        ));
    }
    events
}

/// The odd in-flight rows' `in_progress` state: delivered, not logged —
/// the post-wake reconcile restores it from the run listing.
pub fn mark_running(graph: &mut Graph, shape: FixtureShape, now: i64) {
    for k in 0..FixtureShape::IN_FLIGHT_ROWS {
        let run = shape.in_flight_run(k);
        if run.run_id % 2 == 1 {
            let family = stow_types::api::runner_family(target_of(
                u32::try_from(run.run_id).expect("run id fits u32"),
            ))
            .unwrap_or(stow_types::api::RunnerFamily::Linux);
            graph.run_started(&run.task_id, run.run_id, family, now);
        }
    }
}

/// Empty the store's graph tables — the probe's wipe. A `DELETE`,
/// never DDL: the schema belongs to `POST /reset`. The `meter` table
/// deliberately stays: the seed's own snapshot checkpoint rewrites it
/// (`seq = 0`, the fresh graph's totals plus the isolate's unsettled
/// counts), so the probe's day totals restart at the seed.
///
/// # Errors
/// `QueueError::Sql` when a delete fails.
pub async fn wipe(db: &DurableDb) -> Result<(), QueueError> {
    for table in [
        "event_log",
        "snapshot_chunks",
        "store_meta",
        "node_digests",
        "published",
        "backlog",
        "memory_line",
    ] {
        db.query(&format!("DELETE FROM {table}"))
            .execute()
            .await
            .map_err(|error| QueueError::Sql(format!("wipe {table}: {error}")))?;
    }
    Ok(())
}

/// Seed the fixture: wipe the store, build the graph, write its
/// snapshot, append the log tail and install the post-tail graph in
/// `cell` — a wake of this store replays to exactly this graph. The
/// seeded shape is recorded on the graph itself (`seeded_rows`), so
/// it rides the snapshot head instead of a `store_meta` row — a
/// billed non-append statement outside a checkpoint is one the
/// meter's replay cannot re-count (stow#931).
///
/// # Errors
/// `QueueError` when the build or any store write fails.
pub async fn seed(
    db: &DurableDb,
    cell: &GraphCell,
    shape: FixtureShape,
    settings: &super::queue::SchedulerSettings,
    now: i64,
) -> Result<SchedulerSeedReport, QueueError> {
    wipe(db).await?;
    // The installed graph goes first: building the fixture beside it
    // would hold two graphs at once.
    cell.clear();
    // The wipe left no `memory_line` row, so the cell knows the setting
    // as a wake of this store would: the drives price a resident graph.
    cell.set_memory_line(None);
    tracing::info!(rows = shape.queue_rows, "fixture seed: store wiped");
    let mut graph = build(shape, settings, now, Stored(db)).await?;
    tracing::info!(nodes = graph.sizes().0, "fixture seed: graph built");
    #[cfg(target_arch = "wasm32")]
    trace_population(&graph, "seed built");
    graph.seeded_rows = Some(shape.queue_rows);
    store::write_snapshot(db, &mut graph, cell, now).await?;
    tracing::info!("fixture seed: snapshot written");
    #[cfg(target_arch = "wasm32")]
    trace_population(&graph, "seed snapshot written");
    let cell = cell.install(graph);
    replay_tail(cell, db, shape, now).await?;
    let (nodes, edges, published) = cell.with(|graph| graph.sizes());
    Ok(SchedulerSeedReport {
        nodes,
        edges,
        published,
    })
}

/// The leading tail events that bind the in-flight window: the claims
/// and their bindings.
const IN_FLIGHT_EVENTS: usize = 2;

/// Append the seed's log tail and apply it, then mark the in-flight
/// window running.
async fn replay_tail(
    cell: LoadedGraph<'_>,
    db: &DurableDb,
    shape: FixtureShape,
    now: i64,
) -> Result<(), QueueError> {
    for (at, event) in tail(shape, now) {
        routes::commit(cell, db, std::slice::from_ref(&event), at).await?;
    }
    cell.with(|graph| mark_running(graph, shape, now));
    Ok(())
}

/// Bind the in-flight window to its runs again after the lanes
/// resolved some: the completed rows reopen, a snapshot makes that the
/// store's state (a wake replays exactly this graph), and the seed's
/// claims and bindings replay on top. With no completed rows, the log
/// already describes the graph and no snapshot is needed.
///
/// # Errors
/// `QueueError` on a failed snapshot or log append.
pub async fn rearm(
    db: &DurableDb,
    cell: LoadedGraph<'_>,
    shape: FixtureShape,
    now: i64,
) -> Result<(), QueueError> {
    let reopened = cell.with(|graph| {
        let mut reopened = false;
        for k in 0..FixtureShape::IN_FLIGHT_ROWS {
            reopened |= graph.reopen_completed(&shape.in_flight_run(k).task_id);
        }
        reopened
    });
    if reopened {
        routes::snapshot(cell, db, now).await?;
    }
    for (at, event) in tail(shape, now).into_iter().take(IN_FLIGHT_EVENTS) {
        routes::commit(cell, db, std::slice::from_ref(&event), at).await?;
    }
    cell.with(|graph| mark_running(graph, shape, now));
    Ok(())
}

/// The full-report drive's slice: a held-size membership (100 rows) on
/// a dedicated slice — `CI_TARGET_TRIPLES[8]` / `stow-gate-full-*` —
/// that the seed never writes, so the same report shape applies at every
/// size. Fifty identities carry both rows of their
/// `required_unit_shapes`, the membership a genuinely completed node
/// publishes.
#[must_use]
pub fn full_slice_report() -> Vec<PublishedSliceRow> {
    let target = CI_TARGET_TRIPLES[8];
    (0..50)
        .flat_map(|i| {
            node_shapes(false, target)
                .into_iter()
                .map(move |shape| PublishedSliceRow {
                    dependency_identity: format!("{i:064x}").parse().expect("digest"),
                    crate_name: format!("stow-gate-full-{i}").parse().expect("full crate"),
                    version: "1.0.0".parse().expect("full version"),
                    features_json: FeaturesJson::default(),
                    unit_shape: shape,
                    node_profile: stow_types::node_profile::NodeProfile::Dev,
                })
        })
        .collect()
}

/// The delta report for `(CI_TARGET_TRIPLES[0], '1.85.0')`: retire one
/// required shape row of each of the slice's [`DELTA_ROWS`] tail
/// members and add as many fresh rows (`DELTA_ROWS / 2` identities x
/// their two shapes) — a `2 * DELTA_ROWS` change set. Every retired row
/// is one the fixture published for that node — its first
/// `required_unit_shapes` entry — so each retire leaves a real node
/// partially published, the missing-shape probe the dependent refresh
/// measures. The fixture's live members are the completed rows whose
/// `n % 9` lands on that target; `n % 9 == 0` implies `n % 3 == 0`,
/// the `1.85.0` rustc arm.
#[must_use]
pub fn delta_slice_report(shape: FixtureShape) -> (Vec<PublishedSliceRow>, Vec<PublishedSliceRow>) {
    let live = shape.slice_live_rows(0);
    let first = shape.slice_first_row(0);
    let target = CI_TARGET_TRIPLES[0];
    let retired = (0..DELTA_ROWS)
        .map(|i| {
            let n = first + (live - 1 - i) * 9;
            slice_row(n, node_shapes(n.is_multiple_of(10), target)[0])
        })
        .collect();
    let mut added = Vec::new();
    for i in 0..DELTA_ROWS / 2 {
        added.extend(
            node_shapes(false, target)
                .into_iter()
                .map(|shape| PublishedSliceRow {
                    dependency_identity: format!("{i:064x}").parse().expect("digest"),
                    crate_name: format!("stow-gate-delta-{i}").parse().expect("delta crate"),
                    version: "9.9.9".parse().expect("delta version"),
                    features_json: FeaturesJson::default(),
                    unit_shape: shape,
                    node_profile: stow_types::node_profile::NodeProfile::Dev,
                }),
        );
    }
    (added, retired)
}
