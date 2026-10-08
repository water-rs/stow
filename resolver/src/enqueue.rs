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

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Context as _;
use cargo::CargoResult;
use stow_types::api::{EnqueueDependency, EnqueueRequest, EnqueueSource};
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};
use stow_types::task_graph::{ResolvedTaskGraph, ResolvedTaskNode, TaskNodeIdentity};

use crate::units::{StowDep, StowSide, StowUnit, StowUnitKey, StowUnitKind};

/// A node in the per-platform task graph — the task's identity minus
/// `rustc_version` (shared by the wave).
///
/// Crate, version, resolved feature set, the triple the unit compiles
/// on, and the cargo side the unit lives on. Host-side units
/// (proc-macros, build dependencies) key at the runner family's host
/// triple, not the consumer's target — and carry `host_side` so they
/// stay distinct from a target-side node at the same triple.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TaskNode {
    /// Crate name.
    pub crate_name: CrateName,
    /// Crate version.
    pub version: CrateVersion,
    /// Canonical features JSON (sorted array).
    pub features_json: String,
    /// Compilation target triple the unit keys on.
    pub target: String,
    /// Whether the unit lives on the host side of the build graph.
    pub host_side: bool,
}

/// The lib-unit graph the wave machinery works on: every task node and
/// its task-level dependency edges.
pub type TaskGraph = (BTreeSet<TaskNode>, BTreeMap<TaskNode, BTreeSet<TaskNode>>);

/// Serialize a feature set into the canonical JSON the wire carries —
/// a sorted array. `serde_json` has no Set impl with ordering, so sort
/// explicitly.
///
/// # Errors
/// A `BTreeSet<String>` cannot fail to serialize; `CargoResult` keeps
/// the call chain uniform.
pub fn serialize_feature_set(features: &BTreeSet<String>) -> CargoResult<String> {
    let sorted: Vec<&String> = features.iter().collect();
    serde_json::to_string(&sorted).map_err(anyhow::Error::from)
}

/// Decode a canonical features JSON string back into the typed form.
fn features_json(raw: &str) -> FeaturesJson {
    decode_features_json(raw).expect("canonical features json")
}

/// The fallible half of [`features_json`] — malformed JSON or a
/// non-canonical list is an error, so a caller minting an identity can
/// never default a feature set silently.
fn decode_features_json(raw: &str) -> CargoResult<FeaturesJson> {
    let features: Vec<String> = serde_json::from_str(raw).context("canonical features json")?;
    FeaturesJson::from_sorted(features).map_err(anyhow::Error::from)
}

/// The lib-unit graph the wave machinery works on: every task node and
/// its task-level dependency edges.
///
/// # Errors
/// A unit whose feature set cannot serialize.
pub fn task_graph(units: &[StowUnit]) -> CargoResult<TaskGraph> {
    // Index once — dep and build-script lookups used to re-scan `units`
    // inside per-unit loops, which is quadratic on a zed-sized resolve.
    let mut libs = BTreeMap::new();
    let mut scripts = BTreeMap::new();
    for unit in units {
        match unit.key.kind {
            StowUnitKind::Lib => {
                libs.entry(&unit.key).or_insert(unit);
            }
            StowUnitKind::BuildScript => {
                scripts
                    .entry((&unit.key.pkg, unit.features.as_slice()))
                    .or_insert(unit);
            }
            StowUnitKind::RunBuildScript => {}
        }
    }
    let by_key = |key: &StowUnitKey| libs.get(key).copied();
    let node_of = |unit: &StowUnit| -> CargoResult<TaskNode> {
        Ok(TaskNode {
            crate_name: CrateName::parse(unit.name.clone()).map_err(anyhow::Error::from)?,
            version: CrateVersion::new(
                semver::Version::parse(&unit.version).context("resolver emits semver versions")?,
            ),
            features_json: serialize_feature_set(
                &unit.features.iter().cloned().collect::<BTreeSet<_>>(),
            )?,
            target: unit.key.platform.clone(),
            host_side: unit.key.side == StowSide::Host,
        })
    };
    // One unit's direct lib edges: its normal-dep libs plus the build-dep
    // libs its build-script compile unit links (dedup'd by feature set as
    // `emit_units` produced it). A dep ref of kind Lib that resolves to no
    // unit in this resolve is a resolver inconsistency — an error naming
    // the owner and the missing endpoint, never a dropped edge.
    let missing_lib = |owner: &StowUnit, dep: &StowDep| -> anyhow::Error {
        anyhow::anyhow!(
            "{} {} ({}, {:?}) declares {} {} ({}, {:?}, {}) as a lib dep, but no such unit is in this resolve",
            owner.name,
            owner.version,
            owner.key.platform,
            owner.key.side,
            dep.name,
            dep.version,
            dep.key.platform,
            dep.key.side,
            dep.key.pkg,
        )
    };
    let raw_deps = |unit: &StowUnit| -> CargoResult<Vec<&StowUnit>> {
        let mut direct = Vec::with_capacity(unit.deps.len());
        for dep in unit
            .deps
            .iter()
            .filter(|dep| dep.key.kind == StowUnitKind::Lib)
        {
            direct.push(by_key(&dep.key).ok_or_else(|| missing_lib(unit, dep))?);
        }
        if let Some(compile) = scripts.get(&(&unit.key.pkg, unit.features.as_slice())) {
            for dep in compile
                .deps
                .iter()
                .filter(|dep| dep.key.kind == StowUnitKind::Lib)
            {
                direct.push(by_key(&dep.key).ok_or_else(|| missing_lib(compile, dep))?);
            }
        }
        Ok(direct)
    };
    let mut nodes = BTreeSet::new();
    let mut edges = BTreeMap::<TaskNode, BTreeSet<TaskNode>>::new();
    for unit in units {
        if unit.key.kind != StowUnitKind::Lib || !unit.is_crates_io {
            continue;
        }
        let node = node_of(unit)?;
        nodes.insert(node.clone());
        let deps = direct_dep_nodes(unit, &node, &raw_deps, &node_of)?;
        edges.entry(node).or_default().extend(deps);
    }
    for (node, shadows) in dedup_shadow_edges(units, raw_deps, by_key, node_of)? {
        edges.entry(node).or_default().extend(shadows);
    }
    Ok((nodes, edges))
}

/// One node's task-dep edge set: every crates.io lib reached through
/// `unit`'s direct lib deps. Non-crates.io units (project members, path
/// deps, git packages) carry the resolve's edges but mint no task — a
/// project's own crates are the way into the crates.io graph — so the
/// walk passes through them to the crates.io libs on the far side.
///
/// # Errors
/// A `raw_deps` failure, or a real self-edge — a lib that resolves to
/// its own dependency is a resolver inconsistency: cargo's unit graph
/// is acyclic.
fn direct_dep_nodes<'u>(
    unit: &'u StowUnit,
    node: &TaskNode,
    raw_deps: &impl Fn(&'u StowUnit) -> CargoResult<Vec<&'u StowUnit>>,
    node_of: &impl Fn(&StowUnit) -> CargoResult<TaskNode>,
) -> CargoResult<BTreeSet<TaskNode>> {
    let mut deps = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut stack = raw_deps(unit)?;
    while let Some(dep_unit) = stack.pop() {
        if !seen.insert(&dep_unit.key) {
            continue;
        }
        if dep_unit.is_crates_io {
            deps.insert(node_of(dep_unit)?);
        } else {
            stack.extend(raw_deps(dep_unit)?);
        }
    }
    if deps.contains(node) {
        return Err(anyhow::anyhow!(
            "task node {} {} ({}, {:?}) depends on itself",
            node.crate_name,
            node.version,
            node.target,
            unit.key.side,
        ));
    }
    Ok(deps)
}

/// The Merkle task identity of one resolve's unit graph (stow#588).
///
/// Every [`TaskNode`] of `units`' lib graph becomes a
/// [`ResolvedTaskNode`] whose `dependencies` index into the same node
/// list — `BTreeSet` iteration order is the stable input order every
/// caller shares — then [`ResolvedTaskGraph::resolve`] derives each
/// node's dependency digest and task id bottom-up. Compute this on the
/// output of ONE resolve, before merging graphs from different sources:
/// two resolves can mint the same six-field [`TaskNode`] over different
/// dependency subgraphs, and only per-resolve ids keep the contexts
/// separate.
///
/// # Errors
/// As [`task_graph`], plus an edge endpoint missing from the node set or
/// a node field that fails typed-identity validation.
pub fn resolved_task_graph(
    units: &[StowUnit],
    rustc_version: &WireRustcVersion,
) -> CargoResult<ResolvedTaskGraph> {
    let (nodes, edges) = task_graph(units)?;
    let ordered: Vec<&TaskNode> = nodes.iter().collect();
    let index_of: BTreeMap<&TaskNode, usize> = ordered
        .iter()
        .enumerate()
        .map(|(index, node)| (*node, index))
        .collect();
    let mut resolved = Vec::with_capacity(ordered.len());
    for (index, node) in ordered.iter().enumerate() {
        let mut dependencies = Vec::new();
        for dep in edges.get(*node).into_iter().flatten() {
            dependencies.push(*index_of.get(dep).ok_or_else(|| {
                anyhow::anyhow!(
                    "task graph edge from node {index} ({} {}) names {} {}, which is not a node",
                    node.crate_name,
                    node.version,
                    dep.crate_name,
                    dep.version,
                )
            })?);
        }
        resolved.push(ResolvedTaskNode {
            identity: TaskNodeIdentity {
                crate_name: node.crate_name.clone(),
                version: node.version.clone(),
                features_json: decode_features_json(&node.features_json)?,
                target: TargetTriple::parse(&node.target)?,
                rustc_version: rustc_version.clone(),
                host_side: node.host_side,
            },
            dependencies,
        });
    }
    ResolvedTaskGraph::resolve(resolved).map_err(|error| anyhow::anyhow!("{error}"))
}

/// Mirror the consumer's shared-dep dedup inside the task's own
/// resolve: a lib reachable through host-side edges that also has a
/// target-side unit resolves to the deduped unit in a consumer's
/// build, so the task carries the target unit as a normal dep edge —
/// the wrapper then pins it under `[dependencies]` at the target
/// unit's feature set, which is the identity a consumer computes.
/// Without the pin the wrapper resolves the host subtree alone and
/// the task publishes dep identities no consumer links (stow#506).
fn dedup_shadow_edges<'u>(
    units: &'u [StowUnit],
    raw_deps: impl Fn(&'u StowUnit) -> CargoResult<Vec<&'u StowUnit>>,
    by_key: impl Fn(&StowUnitKey) -> Option<&'u StowUnit>,
    node_of: impl Fn(&StowUnit) -> CargoResult<TaskNode>,
) -> CargoResult<BTreeMap<TaskNode, BTreeSet<TaskNode>>> {
    let mut extra_edges = BTreeMap::<TaskNode, BTreeSet<TaskNode>>::new();
    for unit in units {
        if unit.key.kind != StowUnitKind::Lib || !unit.is_crates_io {
            continue;
        }
        let node = node_of(unit)?;
        let mut seen = BTreeSet::new();
        seen.insert(&unit.key);
        let mut stack: Vec<&StowUnit> = raw_deps(unit)?
            .into_iter()
            .filter(|dep| dep.key.side == StowSide::Host)
            .collect();
        let mut shadows = BTreeSet::new();
        while let Some(dep_unit) = stack.pop() {
            if !seen.insert(&dep_unit.key) {
                continue;
            }
            // The target-side twin is optional by construction: a dep
            // only ever seen host-side has none.
            let target_key = StowUnitKey {
                side: StowSide::Target,
                ..dep_unit.key.clone()
            };
            if dep_unit.is_crates_io
                && let Some(target) = by_key(&target_key)
                && target.is_crates_io
            {
                shadows.insert(node_of(target)?);
            }
            stack.extend(
                raw_deps(dep_unit)?
                    .into_iter()
                    .filter(|dep| dep.key.side == StowSide::Host),
            );
        }
        // The node's own target twin is pin-context dedup, not an edge:
        // the task already compiles that unit, so it must not pin it.
        shadows.remove(&node);
        extra_edges.entry(node).or_default().extend(shadows);
    }
    Ok(extra_edges)
}

/// A unit's canonical features JSON — the root task key's feature
/// payload when `request_plan_parts` locates the root's lib unit.
fn unit_features(units: &[StowUnit], key: &crate::units::StowUnitKey) -> Option<String> {
    let unit = units.iter().find(|unit| &unit.key == key)?;
    serialize_feature_set(&unit.features.iter().cloned().collect::<BTreeSet<_>>()).ok()
}

/// The enqueue-free half of the request lane's plan.
///
/// The task graph plus the root task's key, target triple, and cargo
/// side. The root is the requested crate's lib unit; when the only lib
/// root is a proc-macro the lib lives on the host side, so its task
/// keys on the runner family's host triple.
#[derive(Debug)]
pub struct RequestPlanParts {
    /// Every task node in the resolved closure.
    pub nodes: BTreeSet<TaskNode>,
    /// Task-level dependency edges between nodes.
    pub edges: BTreeMap<TaskNode, BTreeSet<TaskNode>>,
    /// The requested crate's lib-unit task key, at the platform its
    /// `roots` entry carries.
    pub root_key: Option<TaskNode>,
    /// `root_key`'s triple, or the requested target when there is no lib
    /// root.
    pub root_target: String,
    /// `root_key`'s cargo side — true only for a proc-macro root, whose
    /// lib unit lives on the host side of its own resolve.
    pub root_host_side: bool,
}

/// Assemble [`RequestPlanParts`] from one target's resolve output.
///
/// # Errors
/// [`task_graph`] failures — malformed units.
pub fn request_plan_parts(
    units: &[StowUnit],
    roots: &[crate::units::StowUnitKey],
    crate_name: &str,
    version: &semver::Version,
    target: &str,
) -> CargoResult<RequestPlanParts> {
    let (nodes, edges) = task_graph(units)?;
    let root_key = roots
        .iter()
        .find(|key| key.kind == StowUnitKind::Lib)
        .map(|key| {
            Ok::<_, anyhow::Error>(TaskNode {
                crate_name: CrateName::parse(crate_name)?,
                version: CrateVersion::new(version.clone()),
                features_json: unit_features(units, key).unwrap_or_default(),
                target: key.platform.clone(),
                host_side: key.side == StowSide::Host,
            })
        })
        .transpose()?;
    let (root_target, root_host_side) = root_key.as_ref().map_or_else(
        || (target.to_owned(), false),
        |key| (key.target.clone(), key.host_side),
    );
    Ok(RequestPlanParts {
        nodes,
        edges,
        root_key,
        root_target,
        root_host_side,
    })
}

/// Assemble the enqueue batch for a resolve output: `(requests, nodes)`.
///
/// # Errors
/// As [`task_graph`].
pub fn enqueue_requests_from_output(
    units: &[StowUnit],
    rustc_version: &WireRustcVersion,
    source: EnqueueSource,
    downloads: u64,
) -> CargoResult<(Vec<EnqueueRequest>, BTreeSet<TaskNode>)> {
    let (nodes, edges) = task_graph(units)?;
    Ok(enqueue_requests_inner(
        &nodes,
        &edges,
        &BTreeSet::new(),
        rustc_version,
        source,
        downloads,
    ))
}

/// Emit one [`EnqueueRequest`] per uncovered node.
///
/// `depends_on` carries the node's own task deps — the lib units its
/// build links — so a dependent dispatches only once its dependencies
/// are servable, which is the queue gate's release signal. Each dep
/// names the dep's own platform: the runner family's host triple for
/// host-side units.
///
/// # Panics
/// The resolver only emits CI triples and runner-family hosts, which
/// always parse.
#[must_use]
pub fn enqueue_requests_inner(
    nodes: &BTreeSet<TaskNode>,
    edges: &BTreeMap<TaskNode, BTreeSet<TaskNode>>,
    covered: &BTreeSet<TaskNode>,
    rustc_version: &WireRustcVersion,
    source: EnqueueSource,
    downloads: u64,
) -> (Vec<EnqueueRequest>, BTreeSet<TaskNode>) {
    let uncovered: BTreeSet<TaskNode> = nodes
        .iter()
        .filter(|n| !covered.contains(*n))
        .cloned()
        .collect();
    let mut requests = Vec::new();
    for node in &uncovered {
        let depends_on = edges
            .get(node)
            .into_iter()
            .flatten()
            .map(|dep| EnqueueDependency {
                crate_name: dep.crate_name.clone(),
                version: dep.version.clone(),
                features_json: features_json(&dep.features_json),
                target: TargetTriple::parse(&dep.target)
                    .expect("resolver emits CI or host triples"),
                rustc_version: rustc_version.clone(),
                host_side: dep.host_side,
            })
            .collect::<Vec<_>>();
        requests.push(EnqueueRequest {
            crate_name: node.crate_name.clone(),
            version: node.version.clone(),
            features_json: features_json(&node.features_json),
            target: TargetTriple::parse(&node.target).expect("resolver emits CI or host triples"),
            rustc_version: rustc_version.clone(),
            downloads,
            source,
            depends_on,
            preserve_lockfile: false,
            host_side: node.host_side,
        });
    }
    (requests, uncovered)
}
