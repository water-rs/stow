//! Merkle task-graph identity (stow#588).
//!
//! A node's task id commits to the task ids of its resolved direct
//! dependencies — recursively to its whole dependency subgraph — the way
//! cargo's `-C metadata` commits to the units it actually links. Two
//! nodes sharing the six-field [`TaskNodeIdentity`] tuple but sitting
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
use crate::stow_error;

/// A node's semantic identity — the six-field tuple one unit compiles at.
///
/// Crate, version, canonical feature set, target, rustc and compile
/// side. Two nodes may share this tuple; their dependency identities are
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
}

impl TaskNodeIdentity {
    /// The canonical scheduler task id: the shared tuple prefix, then
    /// `-d<dependency digest>` committing to the node's whole dependency
    /// subgraph, then `-host` for host-side nodes.
    #[must_use]
    pub fn task_id(&self, dependency_identity: &DependencyIdentity) -> String {
        let base = format!(
            "{}-d{}",
            crate::api::task_id_prefix(
                self.crate_name.as_str(),
                &self.version.to_string(),
                &self.features_json.raw(),
                self.target.as_str(),
                self.rustc_version.as_str(),
            ),
            dependency_identity,
        );
        if self.host_side {
            format!("{base}-host")
        } else {
            base
        }
    }
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

    /// The computed dependency digest of the node at `index`, `None`
    /// when `index` is out of range.
    #[must_use]
    pub fn dependency_identity(&self, index: usize) -> Option<&DependencyIdentity> {
        self.dependency_identities.get(index)
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
        }
    }

    fn node(identity: TaskNodeIdentity, dependencies: &[usize]) -> ResolvedTaskNode {
        ResolvedTaskNode {
            identity,
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
    /// `[unsafe]` in another's — the same six-field tuple mints two task
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
}
