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
