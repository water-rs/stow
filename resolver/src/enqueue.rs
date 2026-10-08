//! Units → [`EnqueueRequest`].
//!
//! The conversion `enqueue_requests_from_output` runs today, ported
//! verbatim from `edge/src/worker_resolver.rs` so both admin lanes and
//! (#429) the edge share one implementation.
//!
//! A node's task deps are the lib units its own build must find in the
//! cache: its normal-dependency lib units (the lib unit's `deps` of kind
//! `Lib`), plus the build-dependency lib units its build script links
//! (the compile unit's `deps` of kind `Lib`). Run and compile units are
//! interior — they happen inside the owning lib's task and mint no task
//! of their own.

use std::collections::BTreeSet;

use cargo::CargoResult;
use stow_types::api::{EnqueueDependency, EnqueueRequest, EnqueueSource};
use stow_types::identity::WireRustcVersion;
use stow_types::task_graph::ResolvedTaskGraph;
use stow_types::unit_graph::{TaskUnit, TaskUnitDep, TaskUnitKey, TaskUnitKind, TaskUnitSide};

use crate::units::{StowSide, StowUnit, StowUnitKind};

/// The lean unit model the shared projection reads — `stow-resolver`'s
/// cargo-typed [`StowUnit`] converted once at the boundary so
/// `stow-build`'s real `--unit-graph` resolves project onto the same
/// task identities (stow#588).
fn lean_unit(unit: &StowUnit) -> TaskUnit {
    TaskUnit {
        key: lean_key(&unit.key),
        name: unit.name.clone(),
        version: unit.version.clone(),
        features: unit.features.clone(),
        is_crates_io: unit.is_crates_io,
        deps: unit
            .deps
            .iter()
            .map(|dep| TaskUnitDep {
                key: lean_key(&dep.key),
                name: dep.name.clone(),
                version: dep.version.clone(),
            })
            .collect(),
    }
}

fn lean_key(key: &crate::units::StowUnitKey) -> TaskUnitKey {
    TaskUnitKey {
        // `PackageIdSpec`'s Display carries the package's source url
        // (cargo fills `url` from `source_id` in `PackageId::to_spec`),
        // so the key is the full cargo package id, source included.
        pkg: key.pkg.to_string(),
        platform: key.platform.clone(),
        side: match key.side {
            StowSide::Target => TaskUnitSide::Target,
            StowSide::Host => TaskUnitSide::Host,
            StowSide::Artifact => TaskUnitSide::Artifact,
        },
        kind: match key.kind {
            StowUnitKind::Lib => TaskUnitKind::Lib,
            StowUnitKind::BuildScript => TaskUnitKind::BuildScript,
            StowUnitKind::RunBuildScript => TaskUnitKind::RunBuildScript,
        },
    }
}

/// The Merkle task identity of one resolve's unit graph (stow#588) —
/// the shared projection in `stow-types` run over this resolve's
/// converted units.
///
/// # Errors
/// As [`stow_types::unit_graph::resolved_task_graph`].
pub fn resolved_task_graph(
    units: &[StowUnit],
    rustc_version: &WireRustcVersion,
) -> CargoResult<ResolvedTaskGraph> {
    let lean: Vec<TaskUnit> = units.iter().map(lean_unit).collect();
    stow_types::unit_graph::resolved_task_graph(&lean, rustc_version)
        .map_err(|error| anyhow::anyhow!("{error}"))
}

/// One target's resolved graph and the request's library root.
///
/// The root is the requested crate's lib unit; when the
/// only lib root is a proc-macro the lib lives on the host side, so its
/// task keys on the runner family's host triple.
#[derive(Debug)]
pub struct RequestPlanParts {
    /// The resolve's task graph with Merkle identities (stow#588).
    pub graph: ResolvedTaskGraph,
    /// The requested crate's lib-unit task id — `None` for a
    /// binary-only root, which legitimately mints no lib task.
    pub root_task_id: Option<String>,
    /// The root unit's platform, or the requested target when there is
    /// no lib root.
    pub root_target: String,
    /// The root's cargo side — true only for a proc-macro root, whose
    /// lib unit lives on the host side of its own resolve.
    pub root_host_side: bool,
}

/// Assemble [`RequestPlanParts`] from one target's resolve output.
///
/// # Errors
/// As [`resolved_task_graph`], plus a declared lib root whose complete
/// [`crate::units::StowUnitKey`] finds no unit or whose unit minted no
/// node.
pub fn request_plan_parts(
    units: &[StowUnit],
    roots: &[crate::units::StowUnitKey],
    target: &str,
    rustc_version: &WireRustcVersion,
) -> CargoResult<RequestPlanParts> {
    let graph = resolved_task_graph(units, rustc_version)?;
    let root_key = roots.iter().find(|key| key.kind == StowUnitKind::Lib);
    let root_task_id = root_key
        .map(|key| {
            let unit = units.iter().find(|unit| &unit.key == key).ok_or_else(|| {
                anyhow::anyhow!(
                    "declared lib root {} ({}, {:?}) has no unit in this resolve",
                    key.pkg,
                    key.platform,
                    key.side,
                )
            })?;
            let node = stow_types::unit_graph::task_node(&lean_unit(unit))
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            let identity = stow_types::unit_graph::task_identity(&node, rustc_version)
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            let index = graph
                .nodes()
                .iter()
                .position(|resolved| resolved.identity == identity)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "root unit {} {} minted no task node in this resolve",
                        unit.name,
                        unit.version,
                    )
                })?;
            graph
                .task_id(index)
                .map(str::to_owned)
                .ok_or_else(|| anyhow::anyhow!("resolved node {index} has no task id"))
        })
        .transpose()?;
    let (root_target, root_host_side) = root_key.map_or_else(
        || (target.to_owned(), false),
        |key| (key.platform.clone(), key.side == StowSide::Host),
    );
    Ok(RequestPlanParts {
        graph,
        root_task_id,
        root_target,
        root_host_side,
    })
}

/// Assemble the enqueue batch for one resolve output: `(requests,
/// uncovered task ids)`.
///
/// # Errors
/// As [`resolved_task_graph`].
pub fn enqueue_requests_from_output(
    units: &[StowUnit],
    rustc_version: &WireRustcVersion,
    source: EnqueueSource,
    downloads: u64,
) -> CargoResult<(Vec<EnqueueRequest>, BTreeSet<String>)> {
    let graph = resolved_task_graph(units, rustc_version)?;
    enqueue_requests_inner(&graph, &BTreeSet::new(), source, downloads)
}

/// Emit requests for graph nodes absent from contextual coverage.
///
/// Coverage matching is exact contextual identity — the node's
/// Merkle task id — so a row published under a different dependency
/// context never counts as covering.
///
/// `depends_on` carries each child's own fields plus the digest the
/// graph computed for it, so the queue gate releases on the exact
/// published context rather than a bare tuple. Each dep names the dep's
/// own platform: the runner family's host triple for host-side units.
///
/// # Errors
/// A `resolve`d graph is complete by construction; `CargoResult` keeps
/// the call chain uniform.
pub fn enqueue_requests_inner(
    graph: &ResolvedTaskGraph,
    covered_ids: &BTreeSet<String>,
    source: EnqueueSource,
    downloads: u64,
) -> CargoResult<(Vec<EnqueueRequest>, BTreeSet<String>)> {
    let mut requests = Vec::new();
    let mut uncovered = BTreeSet::new();
    for (index, node) in graph.nodes().iter().enumerate() {
        let task_id = graph
            .task_id(index)
            .ok_or_else(|| anyhow::anyhow!("resolved node {index} has no task id"))?;
        if covered_ids.contains(task_id) {
            continue;
        }
        uncovered.insert(task_id.to_owned());
        let depends_on = node
            .dependencies
            .iter()
            .map(|dep_index| {
                let dep = &graph.nodes()[*dep_index].identity;
                Ok(EnqueueDependency {
                    crate_name: dep.crate_name.clone(),
                    version: dep.version.clone(),
                    features_json: dep.features_json.clone(),
                    target: dep.target.clone(),
                    rustc_version: dep.rustc_version.clone(),
                    host_side: dep.host_side,
                    dependency_identity: graph
                        .dependency_identity(*dep_index)
                        .ok_or_else(|| {
                            anyhow::anyhow!("resolved node {dep_index} has no dependency digest")
                        })?
                        .clone(),
                })
            })
            .collect::<CargoResult<Vec<_>>>()?;
        requests.push(EnqueueRequest {
            crate_name: node.identity.crate_name.clone(),
            version: node.identity.version.clone(),
            features_json: node.identity.features_json.clone(),
            target: node.identity.target.clone(),
            rustc_version: node.identity.rustc_version.clone(),
            downloads,
            source,
            depends_on,
            dependency_identity: graph
                .dependency_identity(index)
                .ok_or_else(|| anyhow::anyhow!("resolved node {index} has no dependency digest"))?
                .clone(),
            dependency_subgraph: stow_types::api::TaskSubgraph::from_resolved(&graph, index)
                .map_err(|error| anyhow::anyhow!("{error}"))?,
            preserve_lockfile: false,
            host_side: node.identity.host_side,
        });
    }
    Ok((requests, uncovered))
}
