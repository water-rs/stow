//! Merkle task identity over unit graphs (stow#588):
//! `resolved_task_graph` lifts a resolve's `TaskUnit`s into the shared
//! `ResolvedTaskGraph`, whose task ids commit to each node's whole
//! dependency subgraph.
//!
//! The fixtures here are synthetic `TaskUnit` values — the shape a unit
//! source (`stow-resolver`'s cargo resolve, `stow-cli`'s `--unit-graph`
//! conversion) produces — so the identity machinery is exercised without
//! cargo. `stow-resolver`'s `tests/offline.rs` covers the same shape
//! end-to-end on a real resolve.

use stow_types::identity::WireRustcVersion;
use stow_types::task_graph::ResolvedTaskGraph;
use stow_types::unit_graph::{
    TaskUnit, TaskUnitDep, TaskUnitKey, TaskUnitKind, TaskUnitSide, resolved_task_graph,
};

/// The requested target triple — what consumer-side units compile on.
const TARGET: &str = "aarch64-unknown-linux-gnu";
/// The runner family's host triple — what host-side units key on.
const HOST: &str = "x86_64-unknown-linux-gnu";

fn rustc() -> WireRustcVersion {
    WireRustcVersion::parse("1.99.0").unwrap()
}

fn pkg(name: &str, version: &str) -> String {
    format!("registry+https://github.com/rust-lang/crates.io-index#{name}@{version}")
}

fn key(
    name: &str,
    version: &str,
    platform: &str,
    side: TaskUnitSide,
    kind: TaskUnitKind,
) -> TaskUnitKey {
    TaskUnitKey {
        pkg: pkg(name, version),
        platform: platform.to_owned(),
        side,
        kind,
    }
}

fn dep(
    name: &str,
    version: &str,
    platform: &str,
    side: TaskUnitSide,
    kind: TaskUnitKind,
) -> TaskUnitDep {
    TaskUnitDep {
        key: key(name, version, platform, side, kind),
        name: name.to_owned(),
        version: version.to_owned(),
    }
}

fn build_dep(name: &str, version: &str) -> TaskUnitDep {
    dep(name, version, HOST, TaskUnitSide::Host, TaskUnitKind::Lib)
}

fn dep_of(unit: &TaskUnit) -> TaskUnitDep {
    TaskUnitDep {
        key: unit.key.clone(),
        name: unit.name.clone(),
        version: unit.version.clone(),
    }
}

/// Same name+version from a registry source and a path source — the
/// package id's source half is what keeps the units distinct.
fn pkg_sources(name: &str, version: &str) -> (tempfile::TempDir, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let registry = pkg(name, version);
    let path = format!("path+file://{}#{name}@{version}", dir.path().display());
    (dir, registry, path)
}

fn unit(
    key: TaskUnitKey,
    name: &str,
    version: &str,
    features: &[&str],
    is_crates_io: bool,
    deps: Vec<TaskUnitDep>,
) -> TaskUnit {
    TaskUnit {
        key,
        name: name.to_owned(),
        version: version.to_owned(),
        features: features
            .iter()
            .map(|feature| (*feature).to_owned())
            .collect(),
        is_crates_io,
        deps,
    }
}

/// A target-side crates.io lib unit.
fn lib(name: &str, version: &str, features: &[&str], deps: Vec<TaskUnitDep>) -> TaskUnit {
    unit(
        key(
            name,
            version,
            TARGET,
            TaskUnitSide::Target,
            TaskUnitKind::Lib,
        ),
        name,
        version,
        features,
        true,
        deps,
    )
}

/// A host-side crates.io unit — a lib dep or a build-script compile unit.
fn host_unit(name: &str, version: &str, kind: TaskUnitKind, deps: Vec<TaskUnitDep>) -> TaskUnit {
    unit(
        key(name, version, HOST, TaskUnitSide::Host, kind),
        name,
        version,
        &[],
        true,
        deps,
    )
}

/// The index `crate_name` occupies in the graph's node list.
fn node_index(graph: &ResolvedTaskGraph, crate_name: &str) -> usize {
    graph
        .nodes()
        .iter()
        .position(|node| node.identity.crate_name == crate_name)
        .unwrap_or_else(|| panic!("{crate_name} is not a node"))
}

/// stow#588's shape resolved per consumer: `alloc-stdlib` 0.3.0 [] sits
/// over `alloc-no-stdlib` 2.0.4 at [] in one resolve and at `[unsafe]`
/// in another — the same node tuple mints two task ids.
#[test]
fn separate_resolves_mint_distinct_ids_for_distinct_subgraphs() {
    let units = |dep_features: &[&str]| {
        vec![
            lib(
                "alloc-stdlib",
                "0.3.0",
                &[],
                vec![dep(
                    "alloc-no-stdlib",
                    "2.0.4",
                    TARGET,
                    TaskUnitSide::Target,
                    TaskUnitKind::Lib,
                )],
            ),
            lib("alloc-no-stdlib", "2.0.4", dep_features, vec![]),
        ]
    };
    let plain = resolved_task_graph(&units(&[]), &rustc()).unwrap();
    let unsafe_ = resolved_task_graph(&units(&["unsafe"]), &rustc()).unwrap();

    let (plain_i, unsafe_i) = (
        node_index(&plain, "alloc-stdlib"),
        node_index(&unsafe_, "alloc-stdlib"),
    );
    assert_eq!(
        plain.nodes()[plain_i].identity,
        unsafe_.nodes()[unsafe_i].identity,
        "the parent tuple is identical across the two resolves"
    );
    assert_ne!(
        plain.dependency_identity(plain_i),
        unsafe_.dependency_identity(unsafe_i),
    );
    assert_ne!(plain.task_id(plain_i), unsafe_.task_id(unsafe_i));
}

/// Unit order in the resolve output and dep order inside a unit change
/// nothing — node order is the node set's canonical sort and edges
/// dedup before hashing.
#[test]
fn unit_and_edge_ordering_do_not_change_identity() {
    let units = |reverse: bool| {
        let mut deps = vec![
            dep(
                "dep-a",
                "1.0.0",
                TARGET,
                TaskUnitSide::Target,
                TaskUnitKind::Lib,
            ),
            dep(
                "dep-b",
                "1.0.0",
                TARGET,
                TaskUnitSide::Target,
                TaskUnitKind::Lib,
            ),
        ];
        if reverse {
            deps.reverse();
        }
        vec![
            lib("dep-a", "1.0.0", &[], vec![]),
            lib("dep-b", "1.0.0", &[], vec![]),
            lib("root", "1.0.0", &[], deps),
        ]
    };
    let mut reordered = units(true);
    reordered.reverse();
    let forward = resolved_task_graph(&units(false), &rustc()).unwrap();
    let backward = resolved_task_graph(&reordered, &rustc()).unwrap();
    assert_eq!(
        forward.nodes(),
        backward.nodes(),
        "canonical node order is input-order invariant"
    );
    for index in 0..forward.nodes().len() {
        assert_eq!(forward.task_id(index), backward.task_id(index));
        assert_eq!(
            forward.dependency_identity(index),
            backward.dependency_identity(index),
        );
    }
}

/// A build script's lib deps are the owner's edges, and host-side lib
/// deps (proc-macros, build deps) commit to the parent's digest the same
/// as target-side ones.
#[test]
fn host_and_build_script_edges_join_the_digest() {
    let root_only = resolved_task_graph(&[lib("root", "1.0.0", &[], vec![])], &rustc()).unwrap();
    let root = node_index(&root_only, "root");
    let root_digest = root_only.dependency_identity(root).unwrap().clone();

    // root's build-script compile unit links host-dep — the edge belongs
    // to root's task deps even though the lib's own dep list is empty.
    let with_script = resolved_task_graph(
        &[
            lib("root", "1.0.0", &[], vec![]),
            // A package's build-script unit keys on the lib's feature set.
            host_unit(
                "root",
                "1.0.0",
                TaskUnitKind::BuildScript,
                vec![build_dep("host-dep", "1.0.0")],
            ),
            host_unit("host-dep", "1.0.0", TaskUnitKind::Lib, vec![]),
        ],
        &rustc(),
    )
    .unwrap();
    let root = node_index(&with_script, "root");
    assert_ne!(
        with_script.dependency_identity(root).unwrap(),
        &root_digest,
        "the build-dep edge changes the parent's digest"
    );
    let host_dep = node_index(&with_script, "host-dep");
    assert_eq!(
        with_script.nodes()[root].dependencies,
        vec![host_dep],
        "the script's dep is the lib's edge"
    );

    // A host-side lib dep (the proc-macro shape) has no target twin —
    // the optional shadow lookup misses legitimately — but the edge
    // itself still commits to the digest.
    let with_pm = resolved_task_graph(
        &[
            lib(
                "root",
                "1.0.0",
                &[],
                vec![dep(
                    "pm",
                    "1.0.0",
                    HOST,
                    TaskUnitSide::Host,
                    TaskUnitKind::Lib,
                )],
            ),
            host_unit("pm", "1.0.0", TaskUnitKind::Lib, vec![]),
        ],
        &rustc(),
    )
    .unwrap();
    let root = node_index(&with_pm, "root");
    assert_ne!(with_pm.dependency_identity(root).unwrap(), &root_digest);
}

/// A Lib dep ref with no unit in the resolve — a normal dep or one
/// reached through the owner's build script — fails naming owner and
/// endpoint. A lib self-edge and a cross-node cycle fail as clearly.
#[test]
fn missing_lib_endpoints_self_edges_and_cycles_fail() {
    let missing_normal = resolved_task_graph(
        &[lib(
            "root",
            "1.0.0",
            &[],
            vec![dep(
                "ghost",
                "1.0.0",
                TARGET,
                TaskUnitSide::Target,
                TaskUnitKind::Lib,
            )],
        )],
        &rustc(),
    )
    .unwrap_err();
    let message = format!("{missing_normal:#}");
    assert!(message.contains("ghost"), "{message}");
    assert!(message.contains("root"), "{message}");

    let missing_build = resolved_task_graph(
        &[
            lib("root", "1.0.0", &[], vec![]),
            host_unit(
                "root",
                "1.0.0",
                TaskUnitKind::BuildScript,
                vec![build_dep("ghost", "2.0.0")],
            ),
        ],
        &rustc(),
    )
    .unwrap_err();
    let message = format!("{missing_build:#}");
    assert!(message.contains("ghost"), "{message}");

    let self_edge = resolved_task_graph(
        &[lib(
            "selfish",
            "1.0.0",
            &[],
            vec![dep(
                "selfish",
                "1.0.0",
                TARGET,
                TaskUnitSide::Target,
                TaskUnitKind::Lib,
            )],
        )],
        &rustc(),
    )
    .unwrap_err();
    assert!(
        format!("{self_edge:#}").contains("depends on itself"),
        "{self_edge:#}"
    );

    let cycle = resolved_task_graph(
        &[
            lib(
                "a",
                "1.0.0",
                &[],
                vec![dep(
                    "b",
                    "1.0.0",
                    TARGET,
                    TaskUnitSide::Target,
                    TaskUnitKind::Lib,
                )],
            ),
            lib(
                "b",
                "1.0.0",
                &[],
                vec![dep(
                    "a",
                    "1.0.0",
                    TARGET,
                    TaskUnitSide::Target,
                    TaskUnitKind::Lib,
                )],
            ),
        ],
        &rustc(),
    )
    .unwrap_err();
    assert!(format!("{cycle:#}").contains("cycle"), "{cycle:#}");
}

/// Path/git-style interior units carry edges but mint no nodes: the
/// registry lib on the far side becomes the node's direct dep.
#[test]
fn non_registry_units_traverse_without_minting_nodes() {
    let graph = resolved_task_graph(
        &[
            lib(
                "root",
                "1.0.0",
                &[],
                vec![dep(
                    "middle",
                    "1.0.0",
                    TARGET,
                    TaskUnitSide::Target,
                    TaskUnitKind::Lib,
                )],
            ),
            unit(
                key(
                    "middle",
                    "1.0.0",
                    TARGET,
                    TaskUnitSide::Target,
                    TaskUnitKind::Lib,
                ),
                "middle",
                "1.0.0",
                &[],
                false,
                vec![dep(
                    "inner",
                    "1.0.0",
                    TARGET,
                    TaskUnitSide::Target,
                    TaskUnitKind::Lib,
                )],
            ),
            lib("inner", "1.0.0", &[], vec![]),
        ],
        &rustc(),
    )
    .unwrap();
    assert_eq!(
        graph.nodes().len(),
        2,
        "only crates.io units mint nodes — middle is interior"
    );
    let root = node_index(&graph, "root");
    let inner = node_index(&graph, "inner");
    assert_eq!(graph.nodes()[root].dependencies, vec![inner]);
}

#[test]
fn dependency_endpoints_preserve_package_source() {
    let (_dir, registry, path) = pkg_sources("middle", "1.0.0");
    let inner = lib("inner", "1.0.0", &[], vec![]);
    let mut registry_unit = lib("middle", "1.0.0", &[], vec![]);
    registry_unit.key.pkg = registry;
    let mut path_unit = lib("middle", "1.0.0", &[], vec![dep_of(&inner)]);
    path_unit.key.pkg = path;
    path_unit.is_crates_io = false;

    for (endpoint, expected) in [(&registry_unit, "middle"), (&path_unit, "inner")] {
        let root = lib("root", "1.0.0", &[], vec![dep_of(endpoint)]);
        let mut units = vec![
            root,
            registry_unit.clone(),
            path_unit.clone(),
            inner.clone(),
        ];
        let forward = resolved_task_graph(&units, &rustc()).unwrap();
        units.reverse();
        let backward = resolved_task_graph(&units, &rustc()).unwrap();
        let root = node_index(&forward, "root");
        assert_eq!(
            forward.nodes()[root].dependencies,
            vec![node_index(&forward, expected)],
        );
        assert_eq!(forward.nodes(), backward.nodes());
        assert_eq!(forward.task_id(root), backward.task_id(root));
    }

    // A same-tuple unit from another source is not the declared endpoint.
    let root = lib("root", "1.0.0", &[], vec![dep_of(&registry_unit)]);
    let error = resolved_task_graph(&[root, path_unit, inner], &rustc()).unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("middle"), "{message}");
    assert!(
        message.contains("https://github.com/rust-lang/crates.io-index"),
        "{message}"
    );
    assert!(message.contains("no such unit"), "{message}");
}

#[test]
fn build_script_owner_preserves_package_source() {
    let (_dir, registry, path) = pkg_sources("root", "1.0.0");
    let registry_dep = host_unit("registry-dep", "1.0.0", TaskUnitKind::Lib, vec![]);
    let path_dep = host_unit("path-dep", "1.0.0", TaskUnitKind::Lib, vec![]);
    let mut root = lib("root", "1.0.0", &[], vec![]);
    root.key.pkg = registry.clone();
    let mut registry_script = host_unit(
        "root",
        "1.0.0",
        TaskUnitKind::BuildScript,
        vec![dep_of(&registry_dep)],
    );
    registry_script.key.pkg = registry;
    let mut path_script = host_unit(
        "root",
        "1.0.0",
        TaskUnitKind::BuildScript,
        vec![dep_of(&path_dep)],
    );
    path_script.key.pkg = path;
    path_script.is_crates_io = false;

    let mut units = vec![root, path_script, registry_script, registry_dep, path_dep];
    let forward = resolved_task_graph(&units, &rustc()).unwrap();
    units.reverse();
    let backward = resolved_task_graph(&units, &rustc()).unwrap();
    let root = node_index(&forward, "root");
    assert_eq!(
        forward.nodes()[root].dependencies,
        vec![node_index(&forward, "registry-dep")],
    );
    assert_eq!(forward.nodes(), backward.nodes());
    assert_eq!(forward.task_id(root), backward.task_id(root));
}

#[test]
fn optional_shadow_preserves_package_source() {
    let (_dir, registry, path) = pkg_sources("middle", "1.0.0");
    let mut host = host_unit("middle", "1.0.0", TaskUnitKind::Lib, vec![]);
    host.key.pkg = registry.clone();
    let mut target = unit(
        key(
            "middle",
            "1.0.0",
            HOST,
            TaskUnitSide::Target,
            TaskUnitKind::Lib,
        ),
        "middle",
        "1.0.0",
        &["native"],
        true,
        vec![],
    );
    target.key.pkg = registry;
    let mut other_source = target.clone();
    other_source.key.pkg = path;
    other_source.is_crates_io = false;
    let mut root = lib("root", "1.0.0", &[], vec![]);
    root.key.platform = HOST.to_owned();
    let script = host_unit(
        "root",
        "1.0.0",
        TaskUnitKind::BuildScript,
        vec![dep_of(&host)],
    );
    let mut units = vec![root, script, host, other_source, target];
    let forward = resolved_task_graph(&units, &rustc()).unwrap();
    units.reverse();
    let backward = resolved_task_graph(&units, &rustc()).unwrap();
    let root = node_index(&forward, "root");
    assert_eq!(forward.nodes()[root].dependencies.len(), 2);
    assert_eq!(forward.nodes(), backward.nodes());
    assert_eq!(forward.task_id(root), backward.task_id(root));
}
