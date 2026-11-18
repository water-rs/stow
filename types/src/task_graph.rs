//! Merkle task-graph identity (stow#588).
//!
//! A node's task id commits to the task ids of its resolved direct
//! dependencies — recursively to its whole dependency subgraph — the way
//! cargo's `-C metadata` commits to the units it actually links. Two
//! nodes sharing the seven-field [`TaskNodeIdentity`] tuple but sitting
//! over different dependency contexts are different tasks; two resolving
//! to identical subgraphs deduplicate on the same id.
//!
//! [`ResolvedTaskGraph::resolve`] validates the edge set, then computes
//! every node's [`DependencyIdentity`] and task id bottom-up with
//! petgraph's iterative topological sort, so parents are derived only
//! from already-computed children. The graph serializes as its input
//! nodes alone — computed identities are re-derived on read, never
//! trusted from the wire.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utoipa::ToSchema;

use crate::identity::{
    CrateName, CrateVersion, DependencyIdentity, FeaturesJson, TargetTriple, WireRustcVersion,
};
use crate::node_profile::NodeProfile;
use crate::stow_error;

/// A node's semantic identity — the seven-field tuple one unit compiles at.
///
/// Crate, version, canonical feature set, target, rustc, compile side and
/// profile. Two nodes may share this tuple; their dependency identities are
/// what separate them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub struct TaskNodeIdentity {
    /// Crate name.
    pub crate_name: CrateName,
    /// Crate version.
    pub version: CrateVersion,
    /// Canonical feature list the unit compiles with.
    pub features_json: FeaturesJson,
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Toolchain the unit compiles with.
    pub rustc_version: WireRustcVersion,
    /// Whether this is the host side of the consumer's unit graph.
    pub host_side: bool,
    /// The named profile the unit builds under.
    pub profile: NodeProfile,
}

impl TaskNodeIdentity {
    /// The identity of the node that published a row of a signed index
    /// slice: the row's own fields, the slice's target and rustc, and the
    /// node's side as the row's unit shape records it. Every reader that
    /// joins rows to nodes derives the identity here.
    #[must_use]
    pub fn of_published_row(
        crate_name: &CrateName,
        version: &CrateVersion,
        features_json: &FeaturesJson,
        slice_target: &TargetTriple,
        slice_rustc_version: &WireRustcVersion,
        side: crate::public_cache::UnitSide,
        profile: NodeProfile,
    ) -> Self {
        Self {
            crate_name: crate_name.clone(),
            version: version.clone(),
            features_json: features_json.clone(),
            target: slice_target.clone(),
            rustc_version: slice_rustc_version.clone(),
            host_side: side == crate::public_cache::UnitSide::Host,
            profile,
        }
    }

    /// The canonical scheduler task id: the shared tuple prefix, then
    /// `-d<dependency digest>` committing to the node's whole dependency
    /// subgraph, then `-host` for host-side nodes and the profile's
    /// segment for any profile but dev.
    #[must_use]
    pub fn task_id(&self, dependency_identity: &DependencyIdentity) -> String {
        canonical_task_id(&TaskIdFields {
            crate_name: self.crate_name.as_str(),
            version: &self.version.to_string(),
            features_json: &self.features_json.raw(),
            target: self.target.as_str(),
            rustc_version: self.rustc_version.as_str(),
            dependency_identity: dependency_identity.as_str(),
            host_side: self.host_side,
            profile: self.profile,
        })
    }
}

/// The rendered fields of a node identity, as a holder that keeps them
/// interned rather than typed spells them to [`canonical_task_id`].
#[derive(Debug, Clone, Copy)]
pub struct TaskIdFields<'a> {
    /// Crate name.
    pub crate_name: &'a str,
    /// Crate version.
    pub version: &'a str,
    /// The canonical raw feature list.
    pub features_json: &'a str,
    /// Target triple.
    pub target: &'a str,
    /// Wire rustc version.
    pub rustc_version: &'a str,
    /// The 64-hex dependency digest.
    pub dependency_identity: &'a str,
    /// Whether the node is host-side.
    pub host_side: bool,
    /// The node's named profile.
    pub profile: NodeProfile,
}

/// [`TaskNodeIdentity::task_id`] over the identity's rendered fields.
///
/// For holders that keep the fields interned rather than typed (the
/// scheduler's in-memory graph re-mints ids from them on demand).
/// `features_json` is the canonical raw list and `dependency_identity`
/// its 64-hex digest.
#[must_use]
pub fn canonical_task_id(fields: &TaskIdFields<'_>) -> String {
    let TaskIdFields {
        crate_name,
        version,
        features_json,
        target,
        rustc_version,
        dependency_identity,
        host_side,
        profile,
    } = *fields;
    let mut id = format!(
        "{}-d{dependency_identity}",
        crate::api::task_id_prefix(crate_name, version, features_json, target, rustc_version),
    );
    if host_side {
        id.push_str("-host");
    }
    if let Some(segment) = profile.id_segment() {
        id.push('-');
        id.push_str(segment);
    }
    id
}

/// One node of a resolved task graph.
///
/// Its semantic identity plus the indexes of the nodes it directly
/// depends on. Indexed edges let two nodes carry an identical
/// [`TaskNodeIdentity`] while committing to different child contexts
/// inside the same graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ResolvedTaskNode {
    /// The node's semantic identity.
    pub identity: TaskNodeIdentity,
    /// Whether this node keys differently under the explicit `--target
    /// <host>` spelling (stow#736). Semantic graph data, derived
    /// bottom-up by whichever projection produced the node — it is
    /// presentation, never identity: task ids and dependency digests
    /// ignore it.
    pub explicit_spelling: crate::public_cache::ExplicitSpelling,
    /// Indexes of this node's direct dependencies in the graph's node
    /// list. Every entry must name a real node; ordering and repetition
    /// do not change identity.
    pub dependencies: Vec<usize>,
}

/// A resolved task graph with computed Merkle identities.
///
/// Constructed only by [`Self::resolve`], which derives each node's
/// dependency digest and task id bottom-up over the DAG — children
/// before parents — so a node's id commits to its whole subgraph. Inputs
/// and computed outputs stay private behind getters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTaskGraph {
    nodes: Vec<ResolvedTaskNode>,
    task_ids: Vec<String>,
    dependency_identities: Vec<DependencyIdentity>,
}

impl ResolvedTaskGraph {
    /// Validate the edge set, then compute every node's identity
    /// bottom-up.
    ///
    /// Every dependency index is bounds-checked before any edge is read;
    /// a node depending on itself or closing a multi-node cycle is an
    /// error — never a silently discarded edge. Repeated or reordered
    /// edges change nothing, and the empty graph is valid.
    ///
    /// # Errors
    /// Fails when a dependency index is out of range, a node depends on
    /// itself, the edges contain a cycle, or a dependency digest cannot
    /// be computed.
    pub fn resolve(nodes: Vec<ResolvedTaskNode>) -> crate::error::Result<Self> {
        for (index, node) in nodes.iter().enumerate() {
            for &dependency in &node.dependencies {
                if dependency >= nodes.len() {
                    return Err(stow_error!(
                        "task graph node {index} ({} {}) depends on missing node {dependency}",
                        node.identity.crate_name,
                        node.identity.version,
                    ));
                }
                if dependency == index {
                    return Err(stow_error!(
                        "task graph node {index} ({} {}) depends on itself",
                        node.identity.crate_name,
                        node.identity.version,
                    ));
                }
            }
        }

        // Edges run dependency -> parent, so petgraph's iterative
        // toposort yields every child before the nodes that consume it.
        let edge_count = nodes.iter().map(|node| node.dependencies.len()).sum();
        let mut graph = petgraph::graph::DiGraph::<(), ()>::with_capacity(nodes.len(), edge_count);
        let graph_indexes: Vec<petgraph::graph::NodeIndex> =
            (0..nodes.len()).map(|_| graph.add_node(())).collect();
        let mut edges = BTreeSet::new();
        for (index, node) in nodes.iter().enumerate() {
            for &dependency in &node.dependencies {
                if edges.insert((dependency, index)) {
                    graph.add_edge(graph_indexes[dependency], graph_indexes[index], ());
                }
            }
        }
        let order = petgraph::algo::toposort(&graph, None).map_err(|cycle| {
            let index = cycle.node_id().index();
            let node = &nodes[index];
            stow_error!(
                "task graph dependency cycle through node {index} ({} {})",
                node.identity.crate_name,
                node.identity.version,
            )
        })?;

        let mut task_ids = vec![None::<String>; nodes.len()];
        let mut dependency_identities = vec![None::<DependencyIdentity>; nodes.len()];
        for node_index in order {
            let index = node_index.index();
            let mut children = Vec::with_capacity(nodes[index].dependencies.len());
            for &dependency in &nodes[index].dependencies {
                // Topological order resolves every dependency before its
                // dependents.
                let Some(child_id) = task_ids[dependency].as_deref() else {
                    return Err(stow_error!(
                        "task graph node {index} resolved before its dependency {dependency}"
                    ));
                };
                children.push(child_id);
            }
            let digest = DependencyIdentity::from_task_ids(children)?;
            task_ids[index] = Some(nodes[index].identity.task_id(&digest));
            dependency_identities[index] = Some(digest);
        }
        let task_ids = task_ids
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| stow_error!("topological order did not cover every task graph node"))?;
        let dependency_identities = dependency_identities
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| stow_error!("topological order did not cover every task graph node"))?;
        Ok(Self {
            nodes,
            task_ids,
            dependency_identities,
        })
    }

    /// The input nodes, in input order.
    #[must_use]
    pub fn nodes(&self) -> &[ResolvedTaskNode] {
        &self.nodes
    }

    /// The computed task id of the node at `index`, `None` when `index`
    /// is out of range.
    #[must_use]
    pub fn task_id(&self, index: usize) -> Option<&str> {
        self.task_ids.get(index).map(String::as_str)
    }

    /// The sorted, deduplicated task ids of `index`'s direct
    /// dependencies — the preimage [`Self::dependency_identity`] hashes
    /// (stow#919). `None` when `index` is out of range.
    #[must_use]
    pub fn dependency_task_ids(&self, index: usize) -> Option<Vec<String>> {
        let node = self.nodes.get(index)?;
        let mut ids = node
            .dependencies
            .iter()
            .map(|&dep| self.task_ids[dep].clone())
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        Some(ids)
    }

    /// The computed dependency digest of the node at `index`, `None`
    /// when `index` is out of range.
    #[must_use]
    pub fn dependency_identity(&self, index: usize) -> Option<&DependencyIdentity> {
        self.dependency_identities.get(index)
    }
}

/// The identity a resolved node takes inside one subgraph — borrowed
/// for interning, so a repeat occurrence costs a map lookup and no
/// construction. `scope` is the carrying subgraph's root target: a
/// target-side node keys at its root's own target, so the same wire
/// node inside two differently-rooted subgraphs is two resolved nodes —
/// and a node legitimately has different dependency contexts per scope.
#[derive(PartialEq, Eq, Hash)]
struct UnionKey<'a> {
    scope: &'a str,
    crate_name: &'a str,
    version: &'a semver::Version,
    features: &'a [String],
    target: &'a str,
    rustc_version: &'a str,
    host_side: bool,
    profile: NodeProfile,
}

/// One expanded-graph entry's contribution to
/// [`shared_dependency_identities`]: the identity the entry's own node
/// resolves at and the dependency subgraph it carries (stow#790).
#[derive(Debug)]
pub struct DigestEntry<'a> {
    /// The entry's own task identity — the same fields
    /// [`crate::api::TaskSubgraph::resolve`]'s root takes.
    pub identity: &'a TaskNodeIdentity,
    /// The root's own explicit-spelling flag — presentation data; it
    /// never enters the digest.
    pub root_spelling: crate::public_cache::ExplicitSpelling,
    /// The dependency subgraph the entry carries.
    pub subgraph: &'a crate::api::TaskSubgraph,
}

/// Every entry's root dependency digest in one bottom-up pass —
/// the memoized equivalent of per-entry [`crate::api::TaskSubgraph`]
/// resolves (stow#790).
///
/// A node's digest is derived from its own identity and its
/// dependencies' digests, so each distinct node is computed once.
///
/// Wire nodes deduplicate on the seven-field [`TaskNodeIdentity`]
/// [`crate::api::TaskSubgraph::resolve`] derives — crate, version,
/// canonical features, the entry-root-scoped target, rustc and side —
/// and a second occurrence of a node declaring a different dependency
/// set is an inconsistent wire, refused like every other shape the
/// per-entry resolve rejects: out-of-range indexes, self-edges, cycles
/// and a root target with no runner family all fail the whole call.
///
/// `entries[i]`'s result is the digest its own subgraph resolves to —
/// `entry.subgraph.resolve(entry.identity, entry.root_spelling)`'s
/// `dependency_identity(0)` — and the returned vector lines up with
/// `entries` one for one.
///
/// # Errors
/// Everything [`crate::api::TaskSubgraph::resolve`] rejects, plus a
/// node whose two declarations disagree on its dependencies.
pub fn shared_dependency_identities<'a>(
    entries: &'a [DigestEntry<'a>],
) -> crate::error::Result<Vec<DependencyIdentity>> {
    let mut index_of = std::collections::HashMap::<UnionKey<'a>, usize>::new();
    let mut nodes = Vec::<ResolvedTaskNode>::new();
    let mut declared = Vec::<Option<Vec<usize>>>::new();
    let mut root_indexes = Vec::with_capacity(entries.len());
    let mut scratch = Vec::<usize>::new();

    for entry in entries {
        // The same derivation `TaskSubgraph::resolve` applies: host
        // nodes key at the root target's family host triple, target
        // nodes at the root's own target — so a wire node's identity is
        // scoped to the subgraph it arrived in.
        let host_triple = crate::api::runner_family(entry.identity.target.as_str())
            .ok_or_else(|| {
                stow_error!(
                    "task target `{}` maps to no runner family — host-side subgraph nodes have no host triple to key on",
                    entry.identity.target
                )
            })?
            .host_triple();
        let mut wire_indexes = Vec::with_capacity(entry.subgraph.nodes.len());
        for node in &entry.subgraph.nodes {
            wire_indexes.push(intern_union_node(
                &mut index_of,
                &mut nodes,
                &mut declared,
                UnionKey {
                    scope: entry.identity.target.as_str(),
                    crate_name: node.crate_name.as_str(),
                    version: node.version.as_semver(),
                    features: node.features_json.features(),
                    target: if node.host_side {
                        host_triple
                    } else {
                        entry.identity.target.as_str()
                    },
                    rustc_version: entry.identity.rustc_version.as_str(),
                    host_side: node.host_side,
                    profile: node.profile,
                },
                || resolved_wire_node(node, entry.identity, host_triple),
            )?);
        }
        let root_key = UnionKey {
            scope: entry.identity.target.as_str(),
            crate_name: entry.identity.crate_name.as_str(),
            version: entry.identity.version.as_semver(),
            features: entry.identity.features_json.features(),
            target: entry.identity.target.as_str(),
            rustc_version: entry.identity.rustc_version.as_str(),
            host_side: entry.identity.host_side,
            profile: entry.identity.profile,
        };
        let root_index =
            intern_union_node(&mut index_of, &mut nodes, &mut declared, root_key, || {
                Ok(ResolvedTaskNode {
                    identity: entry.identity.clone(),
                    explicit_spelling: entry.root_spelling,
                    dependencies: Vec::new(),
                })
            })?;
        root_indexes.push(root_index);

        declare_union_deps(
            root_index,
            &entry.subgraph.root_deps,
            &wire_indexes,
            &mut declared,
            &mut scratch,
            &nodes,
        )?;
        for (wire, node) in entry.subgraph.nodes.iter().enumerate() {
            declare_union_deps(
                wire_indexes[wire],
                &node.deps,
                &wire_indexes,
                &mut declared,
                &mut scratch,
                &nodes,
            )?;
        }
    }

    for (index, node) in nodes.iter_mut().enumerate() {
        node.dependencies = declared[index].take().unwrap_or_default();
    }
    let graph = ResolvedTaskGraph::resolve(nodes)?;
    root_indexes
        .iter()
        .map(|&index| {
            graph
                .dependency_identity(index)
                .cloned()
                .ok_or_else(|| stow_error!("resolved task graph yields no digest for node {index}"))
        })
        .collect()
}

/// The resolved node one wire [`crate::api::SubgraphNode`] becomes
/// under `root`: the same construction [`crate::api::TaskSubgraph::resolve`]
/// applies — host nodes key at the family's host triple, target nodes
/// at the root's own target.
fn resolved_wire_node(
    node: &crate::api::SubgraphNode,
    root: &TaskNodeIdentity,
    host_triple: &'static str,
) -> crate::error::Result<ResolvedTaskNode> {
    Ok(ResolvedTaskNode {
        identity: TaskNodeIdentity {
            crate_name: node.crate_name.clone(),
            version: node.version.clone(),
            features_json: node.features_json.clone(),
            target: TargetTriple::parse(if node.host_side {
                host_triple
            } else {
                root.target.as_str()
            })?,
            rustc_version: root.rustc_version.clone(),
            host_side: node.host_side,
            profile: node.profile,
        },
        explicit_spelling: if node.keys_apart {
            crate::public_cache::ExplicitSpelling::KeysApart
        } else {
            crate::public_cache::ExplicitSpelling::KeysAsNative
        },
        dependencies: Vec::new(),
    })
}

/// Intern one union node by its wire-scoped identity: a repeat
/// occurrence costs a map lookup and returns the existing index.
fn intern_union_node<'a>(
    index_of: &mut std::collections::HashMap<UnionKey<'a>, usize>,
    nodes: &mut Vec<ResolvedTaskNode>,
    declared: &mut Vec<Option<Vec<usize>>>,
    key: UnionKey<'a>,
    node: impl FnOnce() -> crate::error::Result<ResolvedTaskNode>,
) -> crate::error::Result<usize> {
    if let Some(&index) = index_of.get(&key) {
        return Ok(index);
    }
    let index = nodes.len();
    nodes.push(node()?);
    declared.push(None);
    index_of.insert(key, index);
    Ok(index)
}

/// Record one union node's declared dependency set, mapped through the
/// carrying subgraph's wire indexes. A second declaration of the same
/// node must name the same set — a forged or inconsistent wire has no
/// canonical digest to compute, so it fails like the other
/// resolve-time violations.
fn declare_union_deps(
    index: usize,
    deps: &[u32],
    wire_indexes: &[usize],
    declared: &mut [Option<Vec<usize>>],
    scratch: &mut Vec<usize>,
    nodes: &[ResolvedTaskNode],
) -> crate::error::Result<()> {
    scratch.clear();
    for &dep in deps {
        let wire = usize::try_from(dep).map_err(|error| stow_error!("{error}"))?;
        let Some(&dep_index) = wire_indexes.get(wire) else {
            let node = &nodes[index].identity;
            return Err(stow_error!(
                "task graph node {} {} depends on missing node {wire}",
                node.crate_name,
                node.version,
            ));
        };
        scratch.push(dep_index);
    }
    scratch.sort_unstable();
    scratch.dedup();
    match &mut declared[index] {
        Some(existing) if existing != scratch => {
            let node = &nodes[index].identity;
            Err(stow_error!(
                "task graph node {} {} is declared with conflicting dependency sets",
                node.crate_name,
                node.version,
            ))
        }
        slot @ None => {
            *slot = Some(std::mem::take(scratch));
            Ok(())
        }
        _ => Ok(()),
    }
}

/// A target-side node keyed at a triple other than that of a node whose
/// dependency closure holds it (stow#1593): `owner` and `foreign` index
/// the caller's node list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForeignTargetSide {
    /// The node whose closure holds `foreign`.
    pub owner: usize,
    /// The target-side node at another triple.
    pub foreign: usize,
}

/// The first node whose dependency closure, below the node itself, holds
/// a target-side node at a triple other than the node's own — `None`
/// when every node keeps the rule.
///
/// The rule is what a dispatch payload can carry: its wire subgraph
/// ([`crate::api::TaskSubgraph`]) keys every target-side node at the
/// task's own target and every host-side node at the runner family's
/// host triple, so a node breaking it dispatches a subgraph that
/// re-derives another task id, and no build of the task's target could
/// compile a target-side unit for another triple anyway. A native
/// consumer's host node legitimately depends on target-side nodes at the
/// host triple — dedup-shadow and self-twin edges (stow#506, stow#723);
/// the same node inside a closure rooted at another target does not.
///
/// One post-order pass, each node and edge visited once: every node
/// records one target-side node its closure holds (itself when it is
/// target-side), and because a node is checked only after its
/// dependencies keep the rule, every target-side node in one closure
/// shares that one's target. `deps` pushes a node's direct
/// dependencies; a cycle is not this check's to report, so an edge
/// back into the walk's own path is skipped.
pub fn foreign_target_side<T: PartialEq>(
    len: usize,
    target: impl Fn(usize) -> T,
    host_side: impl Fn(usize) -> bool,
    deps: impl Fn(usize, &mut Vec<usize>),
) -> Option<ForeignTargetSide> {
    // `Some(held)` once a node is done: the target-side node its closure
    // holds, if any.
    let mut done = vec![None::<Option<usize>>; len];
    let mut on_path = vec![false; len];
    let mut children = Vec::new();
    for start in 0..len {
        if done[start].is_some() {
            continue;
        }
        let mut stack = vec![(start, false)];
        while let Some((at, expanded)) = stack.pop() {
            if done[at].is_some() {
                continue;
            }
            children.clear();
            deps(at, &mut children);
            if !expanded {
                if on_path[at] {
                    continue;
                }
                on_path[at] = true;
                stack.push((at, true));
                stack.extend(
                    children
                        .iter()
                        .filter(|&&child| done[child].is_none() && !on_path[child])
                        .map(|&child| (child, false)),
                );
                continue;
            }
            on_path[at] = false;
            let mut held = (!host_side(at)).then_some(at);
            for &child in &children {
                let Some(Some(foreign)) = done[child] else {
                    continue;
                };
                if target(foreign) != target(at) {
                    return Some(ForeignTargetSide { owner: at, foreign });
                }
                held.get_or_insert(foreign);
            }
            done[at] = Some(held);
        }
    }
    None
}

/// The first target-side node in `start`'s closure keyed at another triple.
///
/// It is [`foreign_target_side`]'s rule checked for one root, the closure
/// its dispatch payload carries. One walk, each node visited once.
pub fn foreign_target_side_below<T: PartialEq>(
    start: usize,
    target: impl Fn(usize) -> T,
    host_side: impl Fn(usize) -> bool,
    deps: impl Fn(usize, &mut Vec<usize>),
) -> Option<usize> {
    let own = target(start);
    let mut seen = std::collections::HashSet::from([start]);
    let mut stack = Vec::new();
    deps(start, &mut stack);
    while let Some(at) = stack.pop() {
        if !seen.insert(at) {
            continue;
        }
        if !host_side(at) && target(at) != own {
            return Some(at);
        }
        deps(at, &mut stack);
    }
    None
}

/// What a closure breaking [`foreign_target_side`]'s rule holds, in the
/// words every refusal of one uses: `<crate> <version> on the target
/// side for <foreign>, which a node for <own> cannot carry`.
#[must_use]
pub fn foreign_target_side_text(
    crate_name: impl std::fmt::Display,
    version: impl std::fmt::Display,
    foreign_target: impl std::fmt::Display,
    own_target: impl std::fmt::Display,
) -> String {
    format!(
        "{crate_name} {version} on the target side for {foreign_target}, which a node for {own_target} cannot carry"
    )
}

/// One way a closure's context edges differ from the ones a single
/// consumer build of that closure mints (stow#1566).
///
/// The resolver mints a node's dedup-shadow edges (stow#506) and its
/// self-twin edge (stow#723) from the whole resolve it sits in, and the
/// builder re-derives them from the closure the dispatch payload pins —
/// so a closure is buildable only when every node in it carries exactly
/// the context edges that closure implies. Each variant names the node
/// whose context disagrees and the node the disagreement is about, as
/// indexes of the caller's arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextIncoherence {
    /// Two nodes of one identity — one unit in any build — over
    /// different dependency contexts.
    Duplicate {
        /// The node met first.
        first: usize,
        /// The other node of the same identity.
        second: usize,
    },
    /// `owner` reaches a host-side node whose target-side twin `twin`
    /// the closure holds, and carries no edge to it.
    MissingShadow {
        /// The node lacking the edge.
        owner: usize,
        /// The target-side twin it must depend on.
        twin: usize,
    },
    /// The host-side node `owner` depends on the target-side node
    /// `child`, which is neither its own twin nor the twin of a host-side
    /// node it reaches.
    StrayTarget {
        /// The host-side node.
        owner: usize,
        /// Its target-side child.
        child: usize,
    },
    /// The host-side node `owner` carries a self-twin edge to `twin`
    /// although a native build shares the pair, or lacks one although
    /// the build keeps the pair apart.
    SelfTwin {
        /// The host-side node.
        owner: usize,
        /// Its target-side twin.
        twin: usize,
    },
}

impl ContextIncoherence {
    /// The two nodes the disagreement is about: the node whose context
    /// is wrong first.
    #[must_use]
    pub const fn nodes(self) -> [usize; 2] {
        match self {
            Self::Duplicate { first, second } => [first, second],
            Self::MissingShadow { owner, twin } | Self::SelfTwin { owner, twin } => [owner, twin],
            Self::StrayTarget { owner, child } => [owner, child],
        }
    }

    /// The disagreement in the words every refusal of one uses, `name`
    /// naming an arena node.
    pub fn text(self, name: impl Fn(usize) -> String) -> String {
        match self {
            Self::Duplicate { first, second: _ } => format!(
                "{} twice, over two dependency contexts, which one build cannot compile",
                name(first)
            ),
            Self::MissingShadow { owner, twin } => format!(
                "{} without its edge to {}, which a build of the closure links",
                name(owner),
                name(twin)
            ),
            Self::StrayTarget { owner, child } => format!(
                "{} depending on {}, which no build of the closure links into it",
                name(owner),
                name(child)
            ),
            Self::SelfTwin { owner, twin } => format!(
                "{} with a self-twin edge to {} that a build of the closure decides otherwise",
                name(owner),
                name(twin)
            ),
        }
    }
}

/// The first [`ContextIncoherence`] in `start`'s closure, `start`
/// included — `None` when one consumer build of the closure mints every
/// node's context edges as the closure carries them (stow#1566).
///
/// The closure stands in for the resolve: it is what the builder pins.
/// With `twin(D)` the target-side node of the closure sharing the
/// host-side node `D`'s `identity` (every identity field but the side)
/// whose profile `shares`, the rules are the resolver's own:
///
/// - one node per identity and side;
/// - a node depends on `twin(D)` for every host-side `D` it reaches
///   through host-side edges (`dedup_shadow_edges`);
/// - a host-side node's target-side children are those twins and its own
///   twin, nothing else — a host unit links host units only;
/// - a host-side node `X` whose twin the closure holds depends on it
///   exactly when a native build keeps the pair apart
///   (`self_twin_edges`): the pair shares when every host-side child of
///   `X` is a child of the twin or has a twin among the twin's children
///   that shares in turn, and the twin has no host-side child `X` lacks.
///   Same package and features give both sides the same dependency
///   declarations, so this reads the raw pairing off the task edges:
///   the twin's target-side children that pair with no host-side child
///   of `X` are its shadow edges, which cargo's pairing never sees.
///
/// `identity` keys a node without its side; `deps` pushes a node's
/// direct dependencies. A cycle is not this check's to report, so an
/// edge back into the walk's own path is skipped. One walk collects the
/// closure; each node's reached twins are computed once, bottom-up.
#[allow(clippy::too_many_lines)] // one closure pass, its four rules in order
pub fn context_incoherence_below<K: Ord>(
    start: usize,
    identity: impl Fn(usize) -> K,
    host_side: impl Fn(usize) -> bool,
    shares: impl Fn(usize) -> bool,
    deps: impl Fn(usize, &mut Vec<usize>),
) -> Option<ContextIncoherence> {
    use std::collections::{BTreeMap, HashMap};

    // Post-order over the closure: every node after its children.
    let mut order = Vec::new();
    let mut local = HashMap::<usize, usize>::new();
    let mut children = Vec::<Vec<usize>>::new();
    let mut done = std::collections::HashSet::new();
    let mut on_path = std::collections::HashSet::new();
    let mut stack = vec![(start, false)];
    let mut pushed = Vec::new();
    while let Some((at, expanded)) = stack.pop() {
        if done.contains(&at) {
            continue;
        }
        if expanded {
            on_path.remove(&at);
            done.insert(at);
            local.insert(at, order.len());
            order.push(at);
            continue;
        }
        if !on_path.insert(at) {
            continue;
        }
        stack.push((at, true));
        pushed.clear();
        deps(at, &mut pushed);
        stack.extend(
            pushed
                .iter()
                .filter(|child| !done.contains(*child) && !on_path.contains(*child))
                .map(|&child| (child, false)),
        );
    }
    // An edge back into the walk's own path closes a cycle, which is not
    // this check's to report: it is skipped, as `foreign_target_side`
    // skips it, so the local graph is a DAG in post-order.
    for (position, &at) in order.iter().enumerate() {
        pushed.clear();
        deps(at, &mut pushed);
        let mut mine: Vec<usize> = pushed
            .iter()
            .map(|child| local[child])
            .filter(|&child| child < position)
            .collect();
        mine.sort_unstable();
        mine.dedup();
        children.push(mine);
    }
    let len = order.len();
    let host: Vec<bool> = order.iter().map(|&at| host_side(at)).collect();
    let keys: Vec<K> = order.iter().map(|&at| identity(at)).collect();
    let has = |owner: usize, child: usize| children[owner].binary_search(&child).is_ok();

    // One node per identity and side; the target-side one is a twin.
    let mut seen = BTreeMap::<(&K, bool), usize>::new();
    let mut targets = BTreeMap::<&K, usize>::new();
    for at in 0..len {
        if let Some(&first) = seen.get(&(&keys[at], host[at])) {
            return Some(ContextIncoherence::Duplicate {
                first: order[first],
                second: order[at],
            });
        }
        seen.insert((&keys[at], host[at]), at);
        if !host[at] {
            targets.insert(&keys[at], at);
        }
    }
    let twin: Vec<Option<usize>> = (0..len)
        .map(|at| {
            (host[at] && shares(order[at]))
                .then(|| targets.get(&keys[at]).copied())
                .flatten()
        })
        .collect();

    // The twins each host-side node reaches through host-side edges, its
    // own included; children come first in `order`.
    let mut reached = vec![Vec::<usize>::new(); len];
    for at in 0..len {
        if !host[at] {
            continue;
        }
        let mut twins: Vec<usize> = twin[at].into_iter().collect();
        for &child in children[at].iter().filter(|&&child| host[child]) {
            twins.extend(&reached[child]);
        }
        twins.sort_unstable();
        twins.dedup();
        reached[at] = twins;
    }
    let shadows = |owner: usize| {
        let mut twins: Vec<usize> = children[owner]
            .iter()
            .filter(|&&child| host[child])
            .flat_map(|&child| reached[child].iter().copied())
            .filter(|&twin| twin != owner)
            .collect();
        twins.sort_unstable();
        twins.dedup();
        twins
    };

    let mut pairs = HashMap::<(usize, usize), bool>::new();
    for at in 0..len {
        let shadows = shadows(at);
        if let Some(&twin) = shadows.iter().find(|&&twin| !has(at, twin)) {
            return Some(ContextIncoherence::MissingShadow {
                owner: order[at],
                twin: order[twin],
            });
        }
        if !host[at] {
            continue;
        }
        if let Some(&child) = children[at].iter().find(|&&child| {
            !host[child] && Some(child) != twin[at] && shadows.binary_search(&child).is_err()
        }) {
            return Some(ContextIncoherence::StrayTarget {
                owner: order[at],
                child: order[child],
            });
        }
        if let Some(own) = twin[at] {
            let pair_shares = twins_share(at, own, &children, &host, &twin, &has, &mut pairs);
            if has(at, own) == pair_shares {
                return Some(ContextIncoherence::SelfTwin {
                    owner: order[at],
                    twin: order[own],
                });
            }
        }
    }
    None
}

/// Whether a native build shares the host-side node `host` with its
/// target-side twin `target` — the pairing [`context_incoherence_below`]
/// states, memoized per pair. Both are local indexes; the closure is
/// acyclic, so the recursion ends.
fn twins_share(
    host: usize,
    target: usize,
    children: &[Vec<usize>],
    host_side: &[bool],
    twin: &[Option<usize>],
    has: &impl Fn(usize, usize) -> bool,
    pairs: &mut std::collections::HashMap<(usize, usize), bool>,
) -> bool {
    if let Some(&answer) = pairs.get(&(host, target)) {
        return answer;
    }
    let mut answer = true;
    for &child in children[host].iter().filter(|&&child| host_side[child]) {
        if has(target, child) {
            continue;
        }
        answer = twin[child].is_some_and(|child_twin| {
            has(target, child_twin)
                && twins_share(child, child_twin, children, host_side, twin, has, pairs)
        });
        if !answer {
            break;
        }
    }
    if answer {
        answer = children[target]
            .iter()
            .all(|&child| !host_side[child] || has(host, child));
    }
    pairs.insert((host, target), answer);
    answer
}

// The wire shape is the input nodes alone: computed digests and task
// ids are re-derived by `resolve` on read, so a serialized graph can
// never carry a forged identity.
impl Serialize for ResolvedTaskGraph {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.nodes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ResolvedTaskGraph {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let nodes = Vec::<ResolvedTaskNode>::deserialize(deserializer)?;
        Self::resolve(nodes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const RUSTC: &str = "1.99.0";

    fn identity(
        crate_name: &str,
        version: &str,
        features: &[&str],
        target: &str,
        rustc_version: &str,
        host_side: bool,
    ) -> TaskNodeIdentity {
        TaskNodeIdentity {
            crate_name: CrateName::parse(crate_name).unwrap(),
            version: CrateVersion::new(semver::Version::parse(version).unwrap()),
            features_json: FeaturesJson::canonicalize(
                features
                    .iter()
                    .map(|feature| (*feature).to_owned())
                    .collect(),
            )
            .unwrap(),
            target: TargetTriple::parse(target).unwrap(),
            rustc_version: WireRustcVersion::parse(rustc_version).unwrap(),
            host_side,
            profile: crate::node_profile::NodeProfile::Dev,
        }
    }

    fn node(identity: TaskNodeIdentity, dependencies: &[usize]) -> ResolvedTaskNode {
        ResolvedTaskNode {
            identity,
            explicit_spelling: crate::public_cache::ExplicitSpelling::KeysAsNative,
            dependencies: dependencies.to_vec(),
        }
    }

    fn leaf(crate_name: &str, version: &str, features: &[&str]) -> ResolvedTaskNode {
        node(
            identity(crate_name, version, features, TARGET, RUSTC, false),
            &[],
        )
    }

    /// stow#588's shape: `alloc-stdlib` 0.3.0 [] sits over
    /// `alloc-no-stdlib` 2.0.4 at [] in one consumer's graph and at
    /// `[unsafe]` in another's — the same seven-field tuple mints two task
    /// ids because the dependency subgraphs differ.
    #[test]
    fn dependency_context_separates_identical_tuples() {
        let graph = ResolvedTaskGraph::resolve(vec![
            leaf("alloc-no-stdlib", "2.0.4", &[]),
            leaf("alloc-no-stdlib", "2.0.4", &["unsafe"]),
            node(
                identity("alloc-stdlib", "0.3.0", &[], TARGET, RUSTC, false),
                &[0],
            ),
            node(
                identity("alloc-stdlib", "0.3.0", &[], TARGET, RUSTC, false),
                &[1],
            ),
        ])
        .unwrap();
        assert_eq!(graph.nodes()[2].identity, graph.nodes()[3].identity);
        assert_ne!(graph.task_id(2), graph.task_id(3));
        assert_ne!(graph.dependency_identity(2), graph.dependency_identity(3));
        assert_ne!(graph.task_id(0), graph.task_id(1));
    }

    /// A root's id changes when only its grandchild's context changes —
    /// the Merkle commitment is transitive.
    #[test]
    fn a_grandchild_change_changes_the_root() {
        let graph = ResolvedTaskGraph::resolve(vec![
            leaf("leaf", "1.0.0", &[]),
            leaf("leaf", "1.0.0", &["extra"]),
            node(identity("mid", "2.0.0", &[], TARGET, RUSTC, false), &[0]),
            node(identity("mid", "2.0.0", &[], TARGET, RUSTC, false), &[1]),
            node(identity("root", "3.0.0", &[], TARGET, RUSTC, false), &[2]),
            node(identity("root", "3.0.0", &[], TARGET, RUSTC, false), &[3]),
        ])
        .unwrap();
        assert_ne!(
            graph.task_id(2),
            graph.task_id(3),
            "same mid tuple, different child"
        );
        assert_ne!(
            graph.task_id(4),
            graph.task_id(5),
            "same root tuple, different grandchild"
        );
    }

    /// Two rows resolving to the same subgraph mint the same id —
    /// dedup is id equality; the rows themselves are never fused.
    #[test]
    fn identical_subgraphs_deduplicate_to_equal_ids() {
        let graph = ResolvedTaskGraph::resolve(vec![
            leaf("leaf", "1.0.0", &[]),
            node(identity("parent", "2.0.0", &[], TARGET, RUSTC, false), &[0]),
            node(identity("parent", "2.0.0", &[], TARGET, RUSTC, false), &[0]),
        ])
        .unwrap();
        assert_eq!(graph.task_id(1), graph.task_id(2));
        assert_eq!(graph.dependency_identity(1), graph.dependency_identity(2));
        assert_eq!(graph.nodes().len(), 3, "equal ids never fuse graph rows");
    }

    #[test]
    fn edge_ordering_and_repetition_do_not_change_identity() {
        let graph = ResolvedTaskGraph::resolve(vec![
            leaf("dep-a", "1.0.0", &[]),
            leaf("dep-b", "1.0.0", &[]),
            node(
                identity("parent", "2.0.0", &[], TARGET, RUSTC, false),
                &[0, 1],
            ),
            node(
                identity("parent", "2.0.0", &[], TARGET, RUSTC, false),
                &[1, 0],
            ),
            node(
                identity("parent", "2.0.0", &[], TARGET, RUSTC, false),
                &[0, 1, 1, 0],
            ),
        ])
        .unwrap();
        assert_eq!(graph.task_id(2), graph.task_id(3));
        assert_eq!(graph.task_id(2), graph.task_id(4));
        // The input rows keep their declared edges — only identity dedups.
        assert_eq!(graph.nodes()[3].dependencies, vec![1, 0]);
        assert_eq!(graph.nodes()[4].dependencies, vec![0, 1, 1, 0]);
    }

    /// A missing edge endpoint, a self-edge and a multi-node cycle are
    /// each an error — never a silently dropped dependency.
    #[test]
    fn resolve_rejects_missing_self_and_cyclic_edges() {
        let out_of_range = ResolvedTaskGraph::resolve(vec![
            leaf("leaf", "1.0.0", &[]),
            node(identity("parent", "2.0.0", &[], TARGET, RUSTC, false), &[7]),
        ]);
        let message = out_of_range.unwrap_err().to_string();
        assert!(message.contains("missing node 7"), "{message}");

        let self_loop = ResolvedTaskGraph::resolve(vec![node(
            identity("selfish", "1.0.0", &[], TARGET, RUSTC, false),
            &[0],
        )]);
        let message = self_loop.unwrap_err().to_string();
        assert!(message.contains("depends on itself"), "{message}");

        let cycle = ResolvedTaskGraph::resolve(vec![
            node(identity("a", "1.0.0", &[], TARGET, RUSTC, false), &[2]),
            node(identity("b", "1.0.0", &[], TARGET, RUSTC, false), &[0]),
            node(identity("c", "1.0.0", &[], TARGET, RUSTC, false), &[1]),
        ]);
        let message = cycle.unwrap_err().to_string();
        assert!(message.contains("cycle"), "{message}");
    }

    /// The same crate at the same tuple on the host side is a different
    /// task than its target-side twin.
    #[test]
    fn host_and_target_sides_produce_distinct_ids() {
        let graph = ResolvedTaskGraph::resolve(vec![
            node(
                identity("shared", "1.0.0", &["std"], TARGET, RUSTC, false),
                &[],
            ),
            node(
                identity("shared", "1.0.0", &["std"], TARGET, RUSTC, true),
                &[],
            ),
        ])
        .unwrap();
        let target_id = graph.task_id(0).unwrap();
        let host_id = graph.task_id(1).unwrap();
        assert_ne!(target_id, host_id);
        assert!(host_id.ends_with("-host"), "{host_id}");
        assert_eq!(format!("{target_id}-host"), host_id);
    }

    /// The dep digest does not wash out the outer tuple: changing any of
    /// version, features, target or rustc still separates two nodes.
    #[test]
    fn every_identity_field_separates_the_task_id() {
        let graph = ResolvedTaskGraph::resolve(vec![
            leaf("leaf", "1.0.0", &[]),
            node(
                identity("same-deps", "1.0.0", &[], TARGET, RUSTC, false),
                &[0],
            ),
            node(
                identity("same-deps", "1.0.1", &[], TARGET, RUSTC, false),
                &[0],
            ),
            node(
                identity("same-deps", "1.0.0", &["extra"], TARGET, RUSTC, false),
                &[0],
            ),
            node(
                identity(
                    "same-deps",
                    "1.0.0",
                    &[],
                    "aarch64-apple-darwin",
                    RUSTC,
                    false,
                ),
                &[0],
            ),
            node(
                identity("same-deps", "1.0.0", &[], TARGET, "1.98.0", false),
                &[0],
            ),
        ])
        .unwrap();
        let baseline = graph.task_id(1).unwrap();
        for index in 2..6 {
            assert_ne!(
                graph.task_id(index).unwrap(),
                baseline,
                "node {index} shares the dep digest but must not share the id"
            );
        }
    }

    /// Every id embeds its full 64-hex dependency digest, the `-host`
    /// suffix marks host-side nodes only, and a leaf commits to the
    /// canonical empty-list digest.
    #[test]
    fn task_ids_carry_the_full_dependency_digest() {
        let graph = ResolvedTaskGraph::resolve(vec![
            leaf("leaf", "1.0.0", &[]),
            node(identity("parent", "2.0.0", &[], TARGET, RUSTC, false), &[0]),
            node(identity("parent", "2.0.0", &[], TARGET, RUSTC, true), &[0]),
        ])
        .unwrap();
        for (index, host) in [(0, false), (1, false), (2, true)] {
            let id = graph.task_id(index).unwrap();
            let digest = graph.dependency_identity(index).unwrap();
            assert_eq!(digest.as_str().len(), 64, "full 256-bit digest");
            assert!(id.contains(&format!("-d{digest}")), "{id}");
            assert_eq!(id.ends_with("-host"), host, "{id}");
        }
        assert_eq!(
            graph.dependency_identity(0).unwrap(),
            &DependencyIdentity::leaf().unwrap()
        );
    }

    /// A 10,000-node chain resolves without recursion — the traversal is
    /// petgraph's iterative toposort.
    #[test]
    fn a_deep_chain_resolves() {
        let nodes = (0..10_000)
            .map(|depth| {
                let dependencies = if depth == 0 { vec![] } else { vec![depth - 1] };
                node(
                    identity("chain", "1.0.0", &[], TARGET, RUSTC, false),
                    &dependencies,
                )
            })
            .collect();
        let graph = ResolvedTaskGraph::resolve(nodes).unwrap();
        assert_eq!(graph.nodes().len(), 10_000);
        assert_ne!(graph.task_id(0), graph.task_id(9_999));
    }

    #[test]
    fn an_empty_graph_resolves() {
        let graph = ResolvedTaskGraph::resolve(vec![]).unwrap();
        assert_eq!(graph.nodes().len(), 0);
        assert_eq!(graph.task_id(0), None);
        assert_eq!(graph.dependency_identity(0), None);
    }

    /// The wire shape is the input nodes alone: deserialization resolves
    /// the graph again, so a stored or forged digest can never be trusted.
    #[test]
    fn serialization_round_trip_recomputes_identities() {
        let graph = ResolvedTaskGraph::resolve(vec![
            leaf("leaf", "1.0.0", &[]),
            node(identity("parent", "2.0.0", &[], TARGET, RUSTC, false), &[0]),
        ])
        .unwrap();
        let mut wire = serde_json::to_value(&graph).unwrap();
        assert!(
            wire.as_array().is_some(),
            "a graph serializes as its input nodes: {wire}"
        );
        let restored: ResolvedTaskGraph = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(restored.task_id(0), graph.task_id(0));
        assert_eq!(restored.task_id(1), graph.task_id(1));

        // Re-edge the parent on the wire — the digest is recomputed,
        // not remembered.
        wire[1]["dependencies"] = serde_json::json!([]);
        let tampered: ResolvedTaskGraph = serde_json::from_value(wire).unwrap();
        assert_ne!(tampered.task_id(1), graph.task_id(1));
        assert_eq!(
            tampered.dependency_identity(1).unwrap(),
            &DependencyIdentity::leaf().unwrap()
        );
    }

    /// stow#790: the shared bottom-up pass mints, for every entry, the
    /// same root digest its own subgraph resolves to — over a
    /// multi-level graph with host-side nodes and shared deps, so the
    /// per-root target derivation (host nodes key at the family host
    /// triple, target nodes at the root's own) is exercised on both
    /// sides.
    #[test]
    fn shared_pass_matches_per_entry_resolve() {
        // wasm32 builds on the Linux family — its host triple is the
        // Linux runner, a different platform than the consumer target.
        const TARGET: &str = "wasm32-unknown-unknown";
        const HOST: &str = "x86_64-unknown-linux-gnu";
        let resolved = ResolvedTaskGraph::resolve(vec![
            leaf("leaf", "1.0.0", &[]),
            node(
                identity("leaf-host", "1.0.0", &["macro"], HOST, RUSTC, true),
                &[],
            ),
            node(identity("shared", "1.4.0", &[], TARGET, RUSTC, false), &[0]),
            node(
                identity("mid-host", "2.0.0", &[], HOST, RUSTC, true),
                &[1, 2],
            ),
            node(
                identity("root", "3.0.0", &["full"], TARGET, RUSTC, false),
                &[2, 3],
            ),
            node(
                identity("root-host", "3.0.0", &[], HOST, RUSTC, true),
                &[3, 0],
            ),
        ])
        .unwrap();

        let subgraphs = (0..resolved.nodes().len())
            .map(|index| crate::api::TaskSubgraph::from_resolved(&resolved, index).unwrap())
            .collect::<Vec<_>>();
        let entries = resolved
            .nodes()
            .iter()
            .zip(&subgraphs)
            .map(|(node, subgraph)| DigestEntry {
                identity: &node.identity,
                root_spelling: node.explicit_spelling,
                subgraph,
            })
            .collect::<Vec<_>>();

        let digests = shared_dependency_identities(&entries).unwrap();
        for (index, entry) in entries.iter().enumerate() {
            let own = entry
                .subgraph
                .resolve(entry.identity, entry.root_spelling)
                .unwrap();
            assert_eq!(
                &digests[index],
                own.dependency_identity(0).unwrap(),
                "node {index} ({}) digest differs",
                entry.identity.crate_name
            );
        }
    }

    /// stow#736: the explicit-spelling flag is semantic graph data,
    /// never identity — two nodes differing only in the flag mint the
    /// same task id and the same dependency digest, so a flag carried
    /// by an older submission cannot fork the queue's identity space.
    #[test]
    fn explicit_spelling_is_not_task_identity() {
        let flagged = ResolvedTaskNode {
            explicit_spelling: crate::public_cache::ExplicitSpelling::KeysApart,
            ..node(identity("dep", "1.0.0", &[], TARGET, RUSTC, false), &[])
        };
        let plain = node(identity("dep", "1.0.0", &[], TARGET, RUSTC, false), &[]);
        let graph = ResolvedTaskGraph::resolve(vec![
            flagged,
            plain,
            node(identity("root", "2.0.0", &[], TARGET, RUSTC, false), &[0]),
            node(identity("root", "2.0.0", &[], TARGET, RUSTC, false), &[1]),
        ])
        .unwrap();
        assert_eq!(graph.task_id(0), graph.task_id(1));
        assert_eq!(graph.task_id(2), graph.task_id(3));
        assert_eq!(graph.dependency_identity(2), graph.dependency_identity(3));
    }
}
