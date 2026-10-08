//! The lean unit model and the unit-to-task-graph projection shared by
//! every lane that turns a resolved unit set into task identities.
//!
//! The model carries exactly the unit facts the projection reads —
//! nothing cargo-specific is needed, so `stow-resolver` (the `cargo`
//! crate's in-process resolve), `stow-build` (`cargo --unit-graph`
//! against the real toolchain) and `stow-cli` all compute the same graph
//! from their own unit sources.
//!
//! A node's task deps are the lib units its own build must find in the
//! cache: its normal-dependency lib units (the lib unit's `deps` of kind
//! `Lib`), plus the build-dependency lib units its build script links
//! (the compile unit's `deps` of kind `Lib`). Run and compile units are
//! interior — they happen inside the owning lib's task and mint no task
//! of their own.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::Result;
use crate::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};
use crate::stow_error;
use crate::task_graph::{ResolvedTaskGraph, ResolvedTaskNode, TaskNodeIdentity};

/// Which cargo side of a consumer's build a unit serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskUnitSide {
    /// A `--extern` unit the consumer links.
    Target,
    /// A proc-macro or build-dependency unit, keyed at the runner
    /// family's host triple.
    Host,
    /// A dep artifact resolve: the prebuilt dep's own platform.
    Artifact,
}

/// Which unit of one crate's build this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskUnitKind {
    /// The library unit — the only kind that mints a task node.
    Lib,
    /// The build-script compile unit — its lib deps merge onto the
    /// owning lib's task deps.
    BuildScript,
    /// The build-script run unit — interior to the owning task.
    RunBuildScript,
}

/// Identity of one unit inside one resolve's unit set.
///
/// `pkg` is the full Cargo package id, source included
/// (`registry+https://github.com/rust-lang/crates.io-index#name@version`,
/// `path+file:///…#version`): units are never matched by name and
/// version alone.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TaskUnitKey {
    /// The full Cargo package id, source included.
    pub pkg: String,
    /// The triple the unit compiles on — the runner family's host
    /// triple for host-side units.
    pub platform: String,
    /// Which side of the consumer's build the unit serves.
    pub side: TaskUnitSide,
    /// Which unit of the crate's build this is.
    pub kind: TaskUnitKind,
}

/// One dep edge's endpoint: the dep unit's own key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskUnitDep {
    /// The dep unit's identity key.
    pub key: TaskUnitKey,
    /// Dep crate name, kept for error messages.
    pub name: String,
    /// Dep crate version, kept for error messages.
    pub version: String,
}

/// One cargo unit's projection-relevant facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskUnit {
    /// The unit's key inside this resolve.
    pub key: TaskUnitKey,
    /// Crate name.
    pub name: String,
    /// Crate version (semver).
    pub version: String,
    /// The resolved feature set the unit compiles with.
    pub features: Vec<String>,
    /// Whether the package came from crates.io — only crates.io units
    /// mint task nodes; everything else is a way into the graph.
    pub is_crates_io: bool,
    /// The unit's dependency edges.
    pub deps: Vec<TaskUnitDep>,
}

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
/// A `BTreeSet<String>` cannot fail to serialize.
pub fn serialize_feature_set(features: &BTreeSet<String>) -> Result<String> {
    let sorted: Vec<&String> = features.iter().collect();
    serde_json::to_string(&sorted).map_err(|error| stow_error!("serialize feature set: {error}"))
}

/// The lib-unit graph the wave machinery works on: every task node and
/// its task-level dependency edges.
///
/// # Errors
/// A unit whose feature set cannot serialize, or a dep ref that names
/// no unit in this resolve.
pub fn task_graph(units: &[TaskUnit]) -> Result<TaskGraph> {
    // Index once — dep and build-script lookups used to re-scan `units`
    // inside per-unit loops, which is quadratic on a zed-sized resolve.
    let mut libs = BTreeMap::new();
    let mut scripts = BTreeMap::new();
    for unit in units {
        match unit.key.kind {
            TaskUnitKind::Lib => {
                libs.entry(&unit.key).or_insert(unit);
            }
            TaskUnitKind::BuildScript => {
                scripts
                    .entry((&unit.key.pkg, unit.features.as_slice()))
                    .or_insert(unit);
            }
            TaskUnitKind::RunBuildScript => {}
        }
    }
    let by_key = |key: &TaskUnitKey| libs.get(key).copied();
    // One unit's direct lib edges: its normal-dep libs plus the build-dep
    // libs its build-script compile unit links (dedup'd by feature set as
    // the unit source produced it). A dep ref of kind Lib that resolves to
    // no unit in this resolve is a unit-source inconsistency — an error
    // naming the owner and the missing endpoint, never a dropped edge.
    let missing_lib = |owner: &TaskUnit, dep: &TaskUnitDep| -> crate::error::Error {
        stow_error!(
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
    let raw_deps = |unit: &TaskUnit| -> Result<Vec<&TaskUnit>> {
        let mut direct = Vec::with_capacity(unit.deps.len());
        for dep in unit
            .deps
            .iter()
            .filter(|dep| dep.key.kind == TaskUnitKind::Lib)
        {
            direct.push(by_key(&dep.key).ok_or_else(|| missing_lib(unit, dep))?);
        }
        if let Some(compile) = scripts.get(&(&unit.key.pkg, unit.features.as_slice())) {
            for dep in compile
                .deps
                .iter()
                .filter(|dep| dep.key.kind == TaskUnitKind::Lib)
            {
                direct.push(by_key(&dep.key).ok_or_else(|| missing_lib(compile, dep))?);
            }
        }
        Ok(direct)
    };
    let mut nodes = BTreeSet::new();
    let mut edges = BTreeMap::<TaskNode, BTreeSet<TaskNode>>::new();
    for unit in units {
        if unit.key.kind != TaskUnitKind::Lib || !unit.is_crates_io {
            continue;
        }
        let node = task_node(unit)?;
        nodes.insert(node.clone());
        let deps = direct_dep_nodes(unit, &node, &raw_deps)?;
        edges.entry(node).or_default().extend(deps);
    }
    for (node, shadows) in dedup_shadow_edges(units, raw_deps, by_key)? {
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
/// its own dependency is a unit-source inconsistency: cargo's unit graph
/// is acyclic.
fn direct_dep_nodes<'u>(
    unit: &'u TaskUnit,
    node: &TaskNode,
    raw_deps: &impl Fn(&'u TaskUnit) -> Result<Vec<&'u TaskUnit>>,
) -> Result<BTreeSet<TaskNode>> {
    let mut deps = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut stack = raw_deps(unit)?;
    while let Some(dep_unit) = stack.pop() {
        if !seen.insert(&dep_unit.key) {
            continue;
        }
        if dep_unit.is_crates_io {
            deps.insert(task_node(dep_unit)?);
        } else {
            stack.extend(raw_deps(dep_unit)?);
        }
    }
    if deps.contains(node) {
        return Err(stow_error!(
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
    units: &[TaskUnit],
    rustc_version: &WireRustcVersion,
) -> Result<ResolvedTaskGraph> {
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
                stow_error!(
                    "task graph edge from node {index} ({} {}) names {} {}, which is not a node",
                    node.crate_name,
                    node.version,
                    dep.crate_name,
                    dep.version,
                )
            })?);
        }
        resolved.push(ResolvedTaskNode {
            identity: task_identity(node, rustc_version)?,
            dependencies,
        });
    }
    ResolvedTaskGraph::resolve(resolved)
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
    units: &'u [TaskUnit],
    raw_deps: impl Fn(&'u TaskUnit) -> Result<Vec<&'u TaskUnit>>,
    by_key: impl Fn(&TaskUnitKey) -> Option<&'u TaskUnit>,
) -> Result<BTreeMap<TaskNode, BTreeSet<TaskNode>>> {
    let mut extra_edges = BTreeMap::<TaskNode, BTreeSet<TaskNode>>::new();
    for unit in units {
        if unit.key.kind != TaskUnitKind::Lib || !unit.is_crates_io {
            continue;
        }
        let node = task_node(unit)?;
        let mut seen = BTreeSet::new();
        seen.insert(&unit.key);
        let mut stack: Vec<&TaskUnit> = raw_deps(unit)?
            .into_iter()
            .filter(|dep| dep.key.side == TaskUnitSide::Host)
            .collect();
        let mut shadows = BTreeSet::new();
        while let Some(dep_unit) = stack.pop() {
            if !seen.insert(&dep_unit.key) {
                continue;
            }
            // The target-side twin is optional by construction: a dep
            // only ever seen host-side has none.
            let target_key = TaskUnitKey {
                side: TaskUnitSide::Target,
                ..dep_unit.key.clone()
            };
            if dep_unit.is_crates_io
                && let Some(target) = by_key(&target_key)
                && target.is_crates_io
            {
                shadows.insert(task_node(target)?);
            }
            stack.extend(
                raw_deps(dep_unit)?
                    .into_iter()
                    .filter(|dep| dep.key.side == TaskUnitSide::Host),
            );
        }
        // The node's own target twin is pin-context dedup, not an edge:
        // the task already compiles that unit, so it must not pin it.
        shadows.remove(&node);
        extra_edges.entry(node).or_default().extend(shadows);
    }
    Ok(extra_edges)
}

/// A unit's raw six-field task node.
///
/// # Errors
/// A unit name/version/features the typed identity cannot carry.
pub fn task_node(unit: &TaskUnit) -> Result<TaskNode> {
    Ok(TaskNode {
        crate_name: CrateName::parse(unit.name.clone()).map_err(|error| {
            stow_error!("unit {} has no valid crate name: {error}", unit.key.pkg)
        })?,
        version: CrateVersion::new(semver::Version::parse(&unit.version).map_err(|error| {
            stow_error!("unit {} has no semver version: {error}", unit.key.pkg)
        })?),
        features_json: serialize_feature_set(
            &unit.features.iter().cloned().collect::<BTreeSet<_>>(),
        )?,
        target: unit.key.platform.clone(),
        host_side: unit.key.side == TaskUnitSide::Host,
    })
}

/// The shared typed identity of a raw [`TaskNode`] under `rustc_version`.
///
/// # Errors
/// A node field that fails typed-identity validation.
pub fn task_identity(
    node: &TaskNode,
    rustc_version: &WireRustcVersion,
) -> Result<TaskNodeIdentity> {
    Ok(TaskNodeIdentity {
        crate_name: node.crate_name.clone(),
        version: node.version.clone(),
        features_json: decode_features_json(&node.features_json)?,
        target: TargetTriple::parse(&node.target)?,
        rustc_version: rustc_version.clone(),
        host_side: node.host_side,
    })
}

/// The fallible half of decoding a canonical features JSON string —
/// malformed JSON or a non-canonical list is an error, so a caller
/// minting an identity can never default a feature set silently.
fn decode_features_json(raw: &str) -> Result<FeaturesJson> {
    let features: Vec<String> = serde_json::from_str(raw)
        .map_err(|error| stow_error!("canonical features json: {error}"))?;
    FeaturesJson::from_sorted(features)
        .map_err(|error| stow_error!("canonical features json: {error}"))
}
