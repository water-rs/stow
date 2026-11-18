//! A target-side node keyed at a foreign triple inside a closure
//! (stow#1593).
//!
//! The fixture is the `BuildTaskPayload` run 44073370559 dispatched for
//! `derive_more 1.0.0` on `wasm32-unknown-unknown`, copied from the run's
//! inputs. Its subgraph carries the host-side `derive_more-impl 1.0.0`
//! node of a native `x86_64-unknown-linux-gnu` consumer — the containing
//! (`full`) feature set superset serving moved the wasm root onto — whose
//! dedup-shadow edges pin the target-side `unicode-segmentation` at the
//! host triple. The task id was minted over that node; the wire keys
//! every target-side node at the task's own target, so the builder
//! re-derived another id and refused the task.

use stow_types::api::{
    BuildTaskPayload, SubmissionNode, SubmissionSource, SubmissionTree, TaskSubgraph,
};
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple};
use stow_types::task_graph::{ResolvedTaskGraph, ResolvedTaskNode, TaskNodeIdentity};

/// The runner family's host triple for `wasm32-unknown-unknown`.
const HOST: &str = "x86_64-unknown-linux-gnu";

fn payload() -> BuildTaskPayload {
    serde_json::from_str(include_str!("fixtures/derive_more_1593_payload.json")).unwrap()
}

/// The payload's root re-keyed at the native host triple: the native
/// consumer's `derive_more` the dispatched subtree was resolved under.
fn native_root(payload: &BuildTaskPayload) -> TaskNodeIdentity {
    TaskNodeIdentity {
        target: TargetTriple::parse(HOST).unwrap(),
        ..payload.task_node_identity()
    }
}

/// The dispatched subgraph under a native root, so every target-side
/// node keys at the host triple.
fn dispatched_graph(payload: &BuildTaskPayload) -> ResolvedTaskGraph {
    payload
        .dependency_subgraph
        .resolve(&native_root(payload), payload.explicit_spelling)
        .unwrap()
}

/// The native consumer's resolved graph: the dispatched subgraph plus
/// the dedup-shadow edge the native root carries to the target-side
/// `unicode-segmentation`, the twin of the host-side one it reaches
/// through `derive_more-impl` (stow#506) — the edge the wasm root, whose
/// subgraph this was, never had.
fn native_graph(payload: &BuildTaskPayload) -> ResolvedTaskGraph {
    let mut nodes = dispatched_graph(payload).nodes().to_vec();
    let twin = nodes
        .iter()
        .position(|node| {
            node.identity.crate_name.as_str() == "unicode-segmentation" && !node.identity.host_side
        })
        .unwrap();
    nodes[0].dependencies.push(twin);
    ResolvedTaskGraph::resolve(nodes).unwrap()
}

/// A one-root submission tree holding every node of `graph`.
fn tree_of(graph: &ResolvedTaskGraph) -> SubmissionTree {
    let nodes = graph
        .nodes()
        .iter()
        .enumerate()
        .map(|(index, node)| SubmissionNode {
            task_id: graph.task_id(index).unwrap().to_owned(),
            crate_name: node.identity.crate_name.clone(),
            version: node.identity.version.clone(),
            features_json: node.identity.features_json.clone(),
            target: node.identity.target.clone(),
            rustc_version: node.identity.rustc_version.clone(),
            host_side: node.identity.host_side,
            profile: node.identity.profile,
            explicit_spelling: node.explicit_spelling,
            preserve_lockfile: false,
            dependency_identity: graph.dependency_identity(index).unwrap().clone(),
            deps: node
                .dependencies
                .iter()
                .map(|&dep| u32::try_from(dep).unwrap())
                .collect(),
            downloads: 0,
        })
        .collect();
    SubmissionTree {
        source: SubmissionSource::Preheat,
        roots: vec![0],
        nodes,
    }
}

/// `graph` with its root replaced by the payload's own wasm root — the
/// tree superset serving spliced.
fn spliced_graph(payload: &BuildTaskPayload) -> ResolvedTaskGraph {
    let mut nodes = dispatched_graph(payload).nodes().to_vec();
    nodes[0].identity = payload.task_node_identity();
    ResolvedTaskGraph::resolve(nodes).unwrap()
}

/// The wasm consumer's own resolve: `derive_more`'s enabled features
/// turn on only `deref deref_mut display from from_str into` of
/// `derive_more-impl` — no `convert_case`, so no `unicode-segmentation`
/// and no dedup-shadow edge — over the dispatched host nodes for
/// `proc-macro2`, `quote`, `syn`, `unicode-xid` and `unicode-ident`.
fn wasm_graph(payload: &BuildTaskPayload) -> ResolvedTaskGraph {
    let native = native_graph(payload);
    let nodes = native.nodes();
    let index_of = |name: &str| {
        nodes
            .iter()
            .position(|node| node.identity.crate_name.as_str() == name)
            .unwrap()
    };
    let impl_index = index_of("derive_more-impl");
    let kept = [
        "proc-macro2",
        "quote",
        "syn",
        "unicode-xid",
        "unicode-ident",
    ]
    .map(index_of);
    // New order: root, derive_more-impl, then the kept nodes.
    let position = |old: usize| 2 + kept.iter().position(|&index| index == old).unwrap();
    let mut out = vec![
        ResolvedTaskNode {
            identity: payload.task_node_identity(),
            explicit_spelling: payload.explicit_spelling,
            dependencies: vec![1],
        },
        ResolvedTaskNode {
            identity: TaskNodeIdentity {
                features_json: FeaturesJson::canonicalize(
                    ["deref", "deref_mut", "display", "from", "from_str", "into"]
                        .map(str::to_owned)
                        .to_vec(),
                )
                .unwrap(),
                ..nodes[impl_index].identity.clone()
            },
            explicit_spelling: nodes[impl_index].explicit_spelling,
            dependencies: ["proc-macro2", "quote", "syn", "unicode-xid"]
                .map(|name| position(index_of(name)))
                .to_vec(),
        },
    ];
    for &old in &kept {
        out.push(ResolvedTaskNode {
            identity: nodes[old].identity.clone(),
            explicit_spelling: nodes[old].explicit_spelling,
            dependencies: nodes[old]
                .dependencies
                .iter()
                .map(|&dep| position(dep))
                .collect(),
        });
    }
    ResolvedTaskGraph::resolve(out).unwrap()
}

/// Every node of `tree` dispatches a payload whose subgraph re-derives
/// its own task id — the builder's first check.
fn assert_every_payload_rederives(tree: &SubmissionTree) {
    let graph = ResolvedTaskGraph::resolve(
        tree.nodes
            .iter()
            .map(|node| ResolvedTaskNode {
                identity: TaskNodeIdentity {
                    crate_name: node.crate_name.clone(),
                    version: node.version.clone(),
                    features_json: node.features_json.clone(),
                    target: node.target.clone(),
                    rustc_version: node.rustc_version.clone(),
                    host_side: node.host_side,
                    profile: node.profile,
                },
                explicit_spelling: node.explicit_spelling,
                dependencies: node.deps.iter().map(|&dep| dep as usize).collect(),
            })
            .collect(),
    )
    .unwrap();
    for (index, node) in tree.nodes.iter().enumerate() {
        assert_eq!(graph.task_id(index).unwrap(), node.task_id);
        let subgraph = TaskSubgraph::from_resolved(&graph, index).unwrap();
        let derived = subgraph
            .resolve(&graph.nodes()[index].identity, node.explicit_spelling)
            .unwrap();
        assert_eq!(
            derived.task_id(0).unwrap(),
            node.task_id,
            "{} {} ({}) dispatches a subgraph of another id",
            node.crate_name,
            node.version,
            node.target,
        );
    }
}

/// The dispatched id was minted over the native `derive_more-impl`
/// subtree spliced under the wasm root, and the wire cannot carry it.
#[test]
fn the_dispatched_id_commits_to_a_native_subtree_under_the_wasm_root() {
    let payload = payload();
    let error = payload.verified_dependency_graph().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not match the derived root id"),
        "{error}"
    );
    assert_eq!(spliced_graph(&payload).task_id(0).unwrap(), payload.task_id);
}

/// The spliced tree breaks the rule, and superset serving refuses it as
/// input, naming the target-side node it holds at the host triple.
#[test]
fn a_tree_holding_a_foreign_target_side_node_is_refused() {
    let payload = payload();
    let spliced = tree_of(&spliced_graph(&payload));
    let expected = "unicode-segmentation 1.13.3 on the target side for x86_64-unknown-linux-gnu, \
                    which a node for wasm32-unknown-unknown cannot carry";
    let error = spliced.ensure_target_side_keys().unwrap_err().to_string();
    assert!(error.contains(expected), "{error}");
    let error = SubmissionTree::substitute_contained_sets(&mut [spliced], &[])
        .unwrap_err()
        .to_string();
    assert!(error.contains(expected), "{error}");
    // The native consumer's own tree keeps the rule: its shadow edges
    // pin target-side nodes at its own target.
    tree_of(&native_graph(&payload))
        .ensure_target_side_keys()
        .unwrap();
}

/// Superset serving leaves the wasm root's `derive_more-impl` on its own
/// set instead of splicing the native `full` node's subtree, while the
/// native tree keeps that node — and every node of both trees
/// dispatches a payload that re-derives its own id.
#[test]
fn superset_serving_keeps_a_native_subtree_out_of_a_wasm_closure() {
    let payload = payload();
    let mut trees = vec![
        tree_of(&wasm_graph(&payload)),
        tree_of(&native_graph(&payload)),
    ];
    let before = trees.clone();
    SubmissionTree::substitute_contained_sets(&mut trees, &[]).unwrap();
    let impl_features = |tree: &SubmissionTree| {
        tree.nodes
            .iter()
            .filter(|node| node.crate_name.as_str() == "derive_more-impl")
            .map(|node| node.features_json.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(impl_features(&trees[0]), impl_features(&before[0]));
    assert_eq!(impl_features(&trees[1]), impl_features(&before[1]));
    assert!(
        trees[0]
            .nodes
            .iter()
            .all(|node| node.crate_name.as_str() != "unicode-segmentation"),
        "the wasm closure carries no unicode-segmentation"
    );
    assert_ne!(
        trees[0].nodes[trees[0].roots[0] as usize].task_id,
        payload.task_id
    );
    for tree in &trees {
        tree.ensure_closure_agreement().unwrap();
        tree.ensure_target_side_keys().unwrap();
        assert_every_payload_rederives(tree);
    }
}

/// A move the rule does not concern still happens: a wasm-side host
/// node whose serving set carries no target-side node moves onto it.
#[test]
fn superset_serving_still_moves_a_host_node_onto_a_cross_context_set() {
    let payload = payload();
    let wasm = wasm_graph(&payload);
    // A second wasm consumer of `derive_more-impl` at a containing set
    // with the same host-only subtree.
    let mut wider = wasm.nodes().to_vec();
    wider[0].identity.crate_name = CrateName::parse("wider").unwrap();
    wider[0].identity.version = CrateVersion::new(semver::Version::new(0, 1, 0));
    wider[1].identity.features_json = FeaturesJson::canonicalize(
        [
            "deref",
            "deref_mut",
            "display",
            "from",
            "from_str",
            "into",
            "not",
        ]
        .map(str::to_owned)
        .to_vec(),
    )
    .unwrap();
    let wider = ResolvedTaskGraph::resolve(wider).unwrap();
    let mut trees = vec![tree_of(&wasm), tree_of(&wider)];
    SubmissionTree::substitute_contained_sets(&mut trees, &[]).unwrap();
    let impl_node = trees[0]
        .nodes
        .iter()
        .find(|node| node.crate_name.as_str() == "derive_more-impl")
        .unwrap();
    assert!(
        impl_node
            .features_json
            .features()
            .iter()
            .any(|feature| feature == "not"),
        "the wasm root moved onto the containing set"
    );
    for tree in &trees {
        assert_every_payload_rederives(tree);
    }
}
