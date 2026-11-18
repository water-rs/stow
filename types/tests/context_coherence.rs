//! Closures whose context edges no single build mints (stow#1566).
//!
//! The fixtures are `BuildTaskPayload`s copied from the inputs of
//! production `build-crate.yml` runs on rustc 1.100.0. Four were refused
//! by the build stage's dependency-context check:
//!
//! - `darling_core 0.24.1` host-side on `x86_64-unknown-linux-gnu`
//!   (run 43813149511), whose closure holds host-side `proc-macro2` and
//!   `quote` twice: once under `darling_core` itself with no target-side
//!   twins, once under a `syn` set carrying `fold, visit, visit-mut` —
//!   which nothing in `darling_core`'s closure enables — whose subtree pins
//!   their target-side twins;
//! - `clap 4.6.7` on `x86_64-pc-windows-msvc` (run 44199090441), which
//!   reaches host-side `proc-macro2` through `clap_derive` while its
//!   closure holds the target-side twin, and carries no edge to it;
//! - `system-deps 9.0.1` host-side on `x86_64-pc-windows-msvc` (run
//!   44200620774), which depends on target-side `toml_parser` at
//!   `alloc, default, std` while the host-side one it reaches sits at
//!   `alloc, std` — an edge no build links;
//! - `dlopen 0.1.8` host-side on `x86_64-pc-windows-msvc` (run
//!   44201592604), whose `lazy_static` pair sits over host-side `spin` at
//!   a set the target-side `spin` lacks, so a native build keeps the
//!   pair apart, yet the host node carries no self-twin edge.
//!
//! `color 0.3.3` on `x86_64-unknown-linux-gnu` (run 44202020932) built
//! and published; its closure carries shadow and self-twin edges and
//! keeps every rule.

use stow_types::api::{BuildTaskPayload, SubmissionNode, SubmissionSource, SubmissionTree};
use stow_types::identity::FeaturesJson;
use stow_types::task_graph::{
    ContextIncoherence, ResolvedTaskGraph, ResolvedTaskNode, TaskNodeIdentity,
};

fn payload(json: &str) -> BuildTaskPayload {
    serde_json::from_str(json).unwrap()
}

fn darling_core() -> BuildTaskPayload {
    payload(include_str!("fixtures/darling_core_1566_payload.json"))
}

/// The graph a payload dispatches — its root first, wire node `i` at
/// `i + 1` — after checking it re-derives the payload's task id.
fn dispatched(payload: &BuildTaskPayload) -> ResolvedTaskGraph {
    payload.verified_dependency_graph().unwrap()
}

/// The first disagreement in `graph`'s root closure, with the crates it
/// names.
fn incoherence(graph: &ResolvedTaskGraph) -> Option<(ContextIncoherence, [String; 2])> {
    let nodes = graph.nodes();
    let found = stow_types::task_graph::context_incoherence_below(
        0,
        |index| TaskNodeIdentity {
            host_side: false,
            ..nodes[index].identity.clone()
        },
        |index| nodes[index].identity.host_side,
        |index| {
            let profile = nodes[index].identity.profile;
            profile.host_can_share_target(profile)
        },
        |index, stack| stack.extend(nodes[index].dependencies.iter().copied()),
    )?;
    let name = |index: usize| {
        let identity = &nodes[index].identity;
        format!(
            "{}{}",
            identity.crate_name,
            if identity.host_side { " (host)" } else { "" }
        )
    };
    Some((found, found.nodes().map(name)))
}

/// A submission tree holding every node of `graph`, `roots` its roots.
fn tree_of(graph: &ResolvedTaskGraph, roots: Vec<u32>) -> SubmissionTree {
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
        roots,
        nodes,
    }
}

/// `graph` restricted to `kept` (indexes into it), in that order, each
/// node's edges re-pointed; an edge leaving `kept` is dropped, for the
/// caller to replace.
fn subgraph(graph: &ResolvedTaskGraph, kept: &[usize]) -> Vec<ResolvedTaskNode> {
    let position = |old: usize| kept.iter().position(|&index| index == old);
    kept.iter()
        .map(|&old| {
            let node = &graph.nodes()[old];
            ResolvedTaskNode {
                identity: node.identity.clone(),
                explicit_spelling: node.explicit_spelling,
                dependencies: node
                    .dependencies
                    .iter()
                    .filter_map(|&dep| position(dep))
                    .collect(),
            }
        })
        .collect()
}

/// `syn 3.0.10` at the set `darling_core` 0.24.1 enables itself — `full`
/// and `extra-traits` over syn's defaults (the crates.io index).
fn darling_syn_features() -> FeaturesJson {
    FeaturesJson::canonicalize(
        [
            "clone-impls",
            "default",
            "derive",
            "extra-traits",
            "full",
            "parsing",
            "printing",
            "proc-macro",
        ]
        .map(str::to_owned)
        .to_vec(),
    )
    .unwrap()
}

// Indexes into the dispatched darling_core graph: the root, then wire
// node `i` at `i + 1`.
const DARLING_CORE: usize = 0;
const PROC_MACRO2_BARE: usize = 1;
const QUOTE_BARE: usize = 2;
const SYN_WIDE: usize = 3;
const IDENT_CASE: usize = 4;
const STRSIM_HOST: usize = 5;
const STRSIM_TARGET: usize = 6;
const UNICODE_IDENT_HOST: usize = 7;
const PROC_MACRO2_TARGET: usize = 8;
const PROC_MACRO2_PINNED: usize = 9;
const QUOTE_TARGET: usize = 10;
const QUOTE_PINNED: usize = 11;
const UNICODE_IDENT_TARGET: usize = 12;

/// `darling_core`'s own resolve: its closure with `syn` at the set it
/// enables, over the `proc-macro2` and `quote` contexts the dispatch
/// put directly under it — no target-side twins but `strsim`'s.
fn darling_core_resolve(graph: &ResolvedTaskGraph) -> ResolvedTaskGraph {
    let mut nodes = subgraph(
        graph,
        &[
            DARLING_CORE,
            PROC_MACRO2_BARE,
            QUOTE_BARE,
            IDENT_CASE,
            STRSIM_HOST,
            STRSIM_TARGET,
            UNICODE_IDENT_HOST,
        ],
    );
    // darling_core loses its edge to the wide syn; its own syn joins.
    let syn = nodes.len();
    nodes[0].dependencies = vec![1, 2, 3, 4, 5, syn];
    nodes.push(ResolvedTaskNode {
        identity: TaskNodeIdentity {
            features_json: darling_syn_features(),
            ..graph.nodes()[SYN_WIDE].identity.clone()
        },
        explicit_spelling: graph.nodes()[SYN_WIDE].explicit_spelling,
        dependencies: vec![1, 2, 6],
    });
    ResolvedTaskGraph::resolve(nodes).unwrap()
}

/// The resolve the wide `syn` set came from: the dispatched syn subtree,
/// whose host-side nodes pin their target-side twins.
fn wide_syn_resolve(graph: &ResolvedTaskGraph) -> ResolvedTaskGraph {
    ResolvedTaskGraph::resolve(subgraph(
        graph,
        &[
            SYN_WIDE,
            PROC_MACRO2_TARGET,
            PROC_MACRO2_PINNED,
            QUOTE_TARGET,
            QUOTE_PINNED,
            UNICODE_IDENT_TARGET,
            UNICODE_IDENT_HOST,
        ],
    ))
    .unwrap()
}

/// The fixtures' named nodes are where the indexes say.
#[test]
fn the_darling_core_fixture_indexes_name_its_nodes() {
    let graph = dispatched(&darling_core());
    let named = |index: usize| {
        let identity = &graph.nodes()[index].identity;
        (identity.crate_name.as_str().to_owned(), identity.host_side)
    };
    for (index, crate_name, host_side) in [
        (DARLING_CORE, "darling_core", true),
        (PROC_MACRO2_BARE, "proc-macro2", true),
        (QUOTE_BARE, "quote", true),
        (SYN_WIDE, "syn", true),
        (IDENT_CASE, "ident_case", true),
        (STRSIM_HOST, "strsim", true),
        (STRSIM_TARGET, "strsim", false),
        (UNICODE_IDENT_HOST, "unicode-ident", true),
        (PROC_MACRO2_TARGET, "proc-macro2", false),
        (PROC_MACRO2_PINNED, "proc-macro2", true),
        (QUOTE_TARGET, "quote", false),
        (QUOTE_PINNED, "quote", true),
        (UNICODE_IDENT_TARGET, "unicode-ident", false),
    ] {
        assert_eq!(named(index), (crate_name.to_owned(), host_side), "{index}");
    }
    assert_eq!(graph.nodes().len(), 13);
}

/// Every refused payload re-derives its own task id — the wire carries
/// it faithfully — and breaks one rule; the published one keeps them all.
#[test]
fn each_refused_payload_breaks_a_rule_the_published_one_keeps() {
    let darling = dispatched(&darling_core());
    let (found, names) = incoherence(&darling).expect("darling_core breaks a rule");
    assert!(
        matches!(found, ContextIncoherence::Duplicate { .. }),
        "{found:?} {names:?}"
    );
    assert!(
        ["proc-macro2 (host)", "quote (host)"].contains(&names[0].as_str()),
        "{names:?}"
    );

    let clap = dispatched(&payload(include_str!("fixtures/clap_1566_payload.json")));
    let (found, names) = incoherence(&clap).expect("clap breaks a rule");
    assert!(
        matches!(found, ContextIncoherence::MissingShadow { .. }),
        "{found:?} {names:?}"
    );

    let system_deps = dispatched(&payload(include_str!(
        "fixtures/system_deps_1566_payload.json"
    )));
    let (found, names) = incoherence(&system_deps).expect("system-deps breaks a rule");
    assert_eq!(
        (found, names.clone()),
        (
            ContextIncoherence::StrayTarget {
                owner: 0,
                child: found.nodes()[1]
            },
            ["system-deps (host)".to_owned(), "toml_parser".to_owned()]
        ),
        "{names:?}"
    );

    let dlopen = dispatched(&payload(include_str!("fixtures/dlopen_1566_payload.json")));
    let (found, names) = incoherence(&dlopen).expect("dlopen breaks a rule");
    assert!(
        matches!(found, ContextIncoherence::SelfTwin { .. }),
        "{found:?} {names:?}"
    );
    assert_eq!(names, ["lazy_static (host)", "lazy_static"]);

    let color = dispatched(&payload(include_str!("fixtures/color_1566_payload.json")));
    assert_eq!(incoherence(&color), None);
}

/// The dispatched `darling_core` closure is a splice of two closures that
/// each keep every rule: `darling_core`'s own, and the one the wide `syn`
/// set was minted in.
#[test]
fn the_darling_core_payload_splices_two_coherent_resolves() {
    let graph = dispatched(&darling_core());
    let own = darling_core_resolve(&graph);
    let wide = wide_syn_resolve(&graph);
    assert_eq!(incoherence(&own), None);
    assert_eq!(incoherence(&wide), None);
    // The dispatched root differs from darling_core's own only in its
    // syn child: the wide syn, whose subtree is the wide resolve's.
    let children = |graph: &ResolvedTaskGraph| {
        let mut ids: Vec<String> = graph.nodes()[0]
            .dependencies
            .iter()
            .filter(|&&dep| graph.nodes()[dep].identity.crate_name.as_str() != "syn")
            .map(|&dep| graph.task_id(dep).unwrap().to_owned())
            .collect();
        ids.sort();
        ids
    };
    assert_eq!(children(&graph), children(&own));
    let dispatched_syn = graph.nodes()[DARLING_CORE]
        .dependencies
        .iter()
        .find(|&&dep| dep == SYN_WIDE)
        .copied()
        .unwrap();
    assert_eq!(
        graph.task_id(dispatched_syn).unwrap(),
        wide.task_id(0).unwrap()
    );
    assert!(incoherence(&graph).is_some());
}

/// Superset serving leaves `darling_core`'s `syn` on its own set: moving
/// it onto the wide set would splice a closure no build mints. Every
/// tree keeps every rule afterwards, and the wide tree is untouched.
#[test]
fn superset_serving_keeps_darling_core_off_the_wide_syn_set() {
    let graph = dispatched(&darling_core());
    let own = darling_core_resolve(&graph);
    let wide = wide_syn_resolve(&graph);
    let mut trees = vec![
        tree_of(
            &own,
            (0..u32::try_from(own.nodes().len()).unwrap()).collect(),
        ),
        tree_of(
            &wide,
            (0..u32::try_from(wide.nodes().len()).unwrap()).collect(),
        ),
    ];
    let before = trees.clone();
    SubmissionTree::substitute_contained_sets(&mut trees, &[]).unwrap();
    let syn_sets = |tree: &SubmissionTree| {
        tree.nodes
            .iter()
            .filter(|node| node.crate_name.as_str() == "syn")
            .map(|node| node.features_json.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(syn_sets(&trees[0]), vec![darling_syn_features()]);
    let ids = |tree: &SubmissionTree| {
        let mut ids: Vec<String> = tree.nodes.iter().map(|node| node.task_id.clone()).collect();
        ids.sort();
        ids
    };
    assert_eq!(ids(&trees[0]), ids(&before[0]));
    assert_eq!(ids(&trees[1]), ids(&before[1]));
    let root = trees[0]
        .nodes
        .iter()
        .find(|node| node.crate_name.as_str() == "darling_core")
        .unwrap();
    assert_ne!(root.task_id, darling_core().task_id);
    for tree in &trees {
        tree.ensure_context_coherence().unwrap();
    }
}

/// A tree already holding such a splice is refused as input, naming the
/// node whose context no build mints.
#[test]
fn a_spliced_tree_is_refused_as_input() {
    let graph = dispatched(&darling_core());
    let tree = tree_of(&graph, vec![0]);
    let error = tree.ensure_context_coherence().unwrap_err().to_string();
    assert!(error.contains("over two dependency contexts"), "{error}");
    let error = SubmissionTree::substitute_contained_sets(&mut [tree], &[])
        .unwrap_err()
        .to_string();
    assert!(error.contains("over two dependency contexts"), "{error}");
}

/// A cycle is not the check's to report: the walk skips the edge back
/// into its path and ends — on a self-edge and on a two-node cycle.
#[test]
fn a_cycle_ends_the_walk() {
    for edges in [vec![vec![0]], vec![vec![1], vec![0]]] {
        let found = stow_types::task_graph::context_incoherence_below(
            0,
            |index| index,
            |_| false,
            |_| true,
            |index, stack| stack.extend(edges[index].iter().copied()),
        );
        assert_eq!(found, None, "{edges:?}");
    }
}
