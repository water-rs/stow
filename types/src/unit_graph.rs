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
use crate::node_profile::NodeProfile;
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
    /// The dep is a proc-macro crate: the edge puts a proc-macro in the
    /// parent's `--extern` set, where its key differs between the
    /// native and explicit `--target` spellings (stow#736).
    pub proc_macro: bool,
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
    /// The named profile cargo builds the unit under.
    pub profile: NodeProfile,
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
    /// The named profile the unit builds under.
    pub profile: NodeProfile,
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
pub fn task_graph<'u>(units: &'u [TaskUnit]) -> Result<TaskGraph> {
    let index = UnitIndex::new(units);
    let raw_deps = |unit: &'u TaskUnit| index.raw_deps(unit);
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
    for (node, shadows) in dedup_shadow_edges(units, raw_deps, |key| index.lib(key))? {
        edges.entry(node).or_default().extend(shadows);
    }
    for (host, target) in self_twin_edges(units)? {
        edges
            .entry(task_node(host)?)
            .or_default()
            .insert(task_node(target)?);
    }
    Ok((nodes, edges))
}

/// The lib units and build-script compile units of one resolve, indexed
/// for the lookups `task_graph` and the sharing predicate share —
/// built once per unit set, not per unit.
struct UnitIndex<'u> {
    libs: BTreeMap<&'u TaskUnitKey, &'u TaskUnit>,
    /// The build-script *compile* unit per `(pkg, features)` — cargo
    /// shares it across sides at equal features, so a twin pair's
    /// `raw_deps` carry the same compile unit's deps.
    scripts: BTreeMap<(&'u str, &'u [String]), &'u TaskUnit>,
}

impl<'u> UnitIndex<'u> {
    fn new(units: &'u [TaskUnit]) -> Self {
        let mut libs = BTreeMap::new();
        let mut scripts = BTreeMap::new();
        for unit in units {
            match unit.key.kind {
                TaskUnitKind::Lib => {
                    libs.entry(&unit.key).or_insert(unit);
                }
                TaskUnitKind::BuildScript => {
                    scripts
                        .entry((unit.key.pkg.as_str(), unit.features.as_slice()))
                        .or_insert(unit);
                }
                TaskUnitKind::RunBuildScript => {}
            }
        }
        Self { libs, scripts }
    }

    fn lib(&self, key: &TaskUnitKey) -> Option<&'u TaskUnit> {
        self.libs.get(key).copied()
    }

    /// One unit's direct lib deps: its normal-dep libs plus the
    /// build-dep libs its build-script compile unit links (dedup'd by
    /// feature set as the unit source produced it). A dep ref of kind
    /// Lib that resolves to no unit in this resolve is a unit-source
    /// inconsistency — an error naming the owner and the missing
    /// endpoint, never a dropped edge.
    fn raw_deps(&self, unit: &'u TaskUnit) -> Result<Vec<&'u TaskUnit>> {
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
        let mut direct = Vec::with_capacity(unit.deps.len());
        for dep in unit
            .deps
            .iter()
            .filter(|dep| dep.key.kind == TaskUnitKind::Lib)
        {
            direct.push(self.lib(&dep.key).ok_or_else(|| missing_lib(unit, dep))?);
        }
        if let Some(compile) = self
            .scripts
            .get(&(unit.key.pkg.as_str(), unit.features.as_slice()))
        {
            for dep in compile
                .deps
                .iter()
                .filter(|dep| dep.key.kind == TaskUnitKind::Lib)
            {
                direct.push(
                    self.lib(&dep.key)
                        .ok_or_else(|| missing_lib(compile, dep))?,
                );
            }
        }
        Ok(direct)
    }
}

/// Every `(host lib, target twin)` pair cargo keeps apart under a
/// native build (stow#723).
///
/// For each crates.io host lib unit `X_h` whose same-package,
/// same-platform, same-features target-side twin `X_t` exists, the pair
/// lands here exactly when `traverse_and_share` would NOT merge the two
/// into one unit — the outcome-3 case whose host unit compiles
/// `debuginfo=2` over its own host dependencies and whose compile key
/// no plain-id task ever produces. Outcome 2 (the pair merges, one
/// shared unit) and outcome 1 (no twin) produce no edge.
///
/// The twin lookup is the same `dedup_shadow_edges` performs: side
/// flipped, package and platform identical, features compared as sets —
/// a different-feature twin is never shared (stow#722). Whether cargo
/// merges the pair is the recursive interning rule of
/// `traverse_and_share`: a host unit and a target unit intern to one
/// unit only when every interned field matches, and `new_dep_hash`
/// covers the sorted list of each unit's dependency units *after* the
/// same rule has been applied to each dependency. Cargo's unit graph is
/// a DAG, so the recursion terminates; the memo keeps it linear.
///
/// # Errors
/// A lib dep ref that names no unit in this resolve — a unit-source
/// inconsistency, never a dropped edge.
pub fn self_twin_edges(units: &[TaskUnit]) -> Result<Vec<(&TaskUnit, &TaskUnit)>> {
    let index = UnitIndex::new(units);
    let mut memo = BTreeMap::new();
    let mut twins = Vec::new();
    for unit in units {
        if unit.key.kind != TaskUnitKind::Lib
            || unit.key.side != TaskUnitSide::Host
            || !unit.is_crates_io
        {
            continue;
        }
        let target_key = TaskUnitKey {
            side: TaskUnitSide::Target,
            ..unit.key.clone()
        };
        let Some(target) = index.lib(&target_key) else {
            continue;
        };
        if !same_features(unit, target) {
            continue;
        }
        if !twins_shareable(&index, unit, target, &mut memo)? {
            twins.push((unit, target));
        }
    }
    Ok(twins)
}

/// Feature sets equal — `dedup_shadow_edges`'s comparison: `TaskUnitKey`
/// carries no features, so twins compare the sets themselves.
fn same_features(left: &TaskUnit, right: &TaskUnit) -> bool {
    left.features.iter().collect::<BTreeSet<_>>() == right.features.iter().collect::<BTreeSet<_>>()
}

/// Whether cargo's native-build interning would merge `host` and
/// `target` — a twin pair the caller already knows shares package,
/// platform and features — into one unit. Cargo's rule, applied to the
/// lean model: the lib dependency lists of both sides pair up exactly,
/// where the list is `raw_deps` (own lib deps plus the shared
/// build-script compile unit's lib deps — one `(pkg, features)` unit
/// on both sides, so its entries pair by identity) and a dep pairs
/// either with the identical unit — a host-kinded dep both sides reach,
/// like a proc-macro or build-dependency lib — or as a host/target twin
/// pair that is itself shareable. In a resolver-emitted unit set the
/// host side also carries the deduped target-side edge for each dep it
/// can share; those entries pair by identity and change nothing.
fn twins_shareable<'u>(
    index: &UnitIndex<'u>,
    host: &'u TaskUnit,
    target: &'u TaskUnit,
    memo: &mut BTreeMap<(TaskUnitKey, TaskUnitKey), bool>,
) -> Result<bool> {
    let key = (host.key.clone(), target.key.clone());
    if let Some(&answer) = memo.get(&key) {
        return Ok(answer);
    }
    let host_deps = index.raw_deps(host)?;
    let target_deps = index.raw_deps(target)?;
    let mut answer = host_deps.iter().try_fold(true, |paired, host_dep| {
        target_deps
            .iter()
            .try_fold(false, |found, target_dep| {
                deps_pair(index, host_dep, target_dep, memo).map(|pairs| found || pairs)
            })
            .map(|found| paired && found)
    })?;
    if answer {
        answer = target_deps.iter().try_fold(true, |paired, target_dep| {
            host_deps
                .iter()
                .try_fold(false, |found, host_dep| {
                    deps_pair(index, host_dep, target_dep, memo).map(|pairs| found || pairs)
                })
                .map(|found| paired && found)
        })?;
    }
    memo.insert(key, answer);
    Ok(answer)
}

/// One dep-pairing test under cargo's interning rule: the identical
/// unit on both lists, or a host/target twin pair — same package,
/// platform and features — that is itself shareable.
fn deps_pair<'u>(
    index: &UnitIndex<'u>,
    host_dep: &'u TaskUnit,
    target_dep: &'u TaskUnit,
    memo: &mut BTreeMap<(TaskUnitKey, TaskUnitKey), bool>,
) -> Result<bool> {
    if host_dep.key == target_dep.key {
        return Ok(true);
    }
    if host_dep.key.side != TaskUnitSide::Host
        || target_dep.key.side != TaskUnitSide::Target
        || host_dep.key.pkg != target_dep.key.pkg
        || host_dep.key.platform != target_dep.key.platform
        || !same_features(host_dep, target_dep)
    {
        return Ok(false);
    }
    twins_shareable(index, host_dep, target_dep, memo)
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

/// Every lib unit's explicit-spelling flag (stow#736).
///
/// Derived bottom-up: a target-side unit is [`ExplicitSpelling::KeysApart`]
/// when one of its lib deps is a proc-macro — the edge puts it in the
/// parent's `--extern`, where it keys differently per invocation
/// spelling — or one of its target-side lib deps is itself
/// `KeysApart`. A host-side unit is always `KeysAsNative`: it already
/// publishes both spellings. Build-script deps never reach a lib's
/// `--extern`, so they can never flag a node.
///
/// # Errors
/// A lib dep ref that names no unit in this resolve, or a lib
/// dependency cycle — both unit-source inconsistencies, never dropped
/// edges.
pub fn explicit_spellings(
    units: &[TaskUnit],
) -> Result<BTreeMap<TaskUnitKey, crate::public_cache::ExplicitSpelling>> {
    use crate::public_cache::ExplicitSpelling;
    let libs: BTreeMap<&TaskUnitKey, &TaskUnit> = units
        .iter()
        .filter(|unit| unit.key.kind == TaskUnitKind::Lib)
        .map(|unit| (&unit.key, unit))
        .collect();
    let mut flags = BTreeMap::<&TaskUnitKey, ExplicitSpelling>::new();
    for &unit in libs.values() {
        // Iterative post-order over the lib-dep DAG: `visiting` doubles
        // as the cycle check — cargo's unit graph is acyclic, so a
        // repeat is a unit-source inconsistency.
        let mut stack = vec![(unit, false)];
        let mut visiting = BTreeSet::<&TaskUnitKey>::new();
        while let Some((current, children_done)) = stack.pop() {
            if children_done {
                visiting.remove(&current.key);
                let flag = if current.key.side == TaskUnitSide::Host {
                    ExplicitSpelling::KeysAsNative
                } else if current
                    .deps
                    .iter()
                    .filter(|dep| dep.key.kind == TaskUnitKind::Lib)
                    .any(|dep| {
                        dep.proc_macro
                            || (dep.key.side == TaskUnitSide::Target
                                && flags.get(&dep.key) == Some(&ExplicitSpelling::KeysApart))
                    })
                {
                    ExplicitSpelling::KeysApart
                } else {
                    ExplicitSpelling::KeysAsNative
                };
                flags.insert(&current.key, flag);
                continue;
            }
            if flags.contains_key(&current.key) {
                continue;
            }
            if !visiting.insert(&current.key) {
                return Err(stow_error!(
                    "{} {} ({}, {:?}) sits on a lib dependency cycle",
                    current.name,
                    current.version,
                    current.key.platform,
                    current.key.side,
                ));
            }
            stack.push((current, true));
            for dep in &current.deps {
                if dep.key.kind != TaskUnitKind::Lib || flags.contains_key(&dep.key) {
                    continue;
                }
                let dep_unit = libs.get(&dep.key).ok_or_else(|| {
                    stow_error!(
                        "{} {} ({}, {:?}) declares {} {} ({}, {:?}, {}) as a lib dep, but no such unit is in this resolve",
                        current.name,
                        current.version,
                        current.key.platform,
                        current.key.side,
                        dep.name,
                        dep.version,
                        dep.key.platform,
                        dep.key.side,
                        dep.key.pkg,
                    )
                })?;
                stack.push((dep_unit, false));
            }
        }
    }
    Ok(flags
        .into_iter()
        .map(|(key, flag)| (key.clone(), flag))
        .collect())
}

/// The Merkle task identity of one resolve's unit graph (stow#588).
///
/// Every [`TaskNode`] of `units`' lib graph becomes a
/// [`ResolvedTaskNode`] whose `dependencies` index into the same node
/// list — `BTreeSet` iteration order is the stable input order every
/// caller shares — then [`ResolvedTaskGraph::resolve`] derives each
/// node's dependency digest and task id bottom-up. Compute this on the
/// output of ONE resolve, before merging graphs from different sources:
/// two resolves can mint the same seven-field [`TaskNode`] over different
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
    let spellings = explicit_spellings(units)?;
    let mut spelling_by_node = BTreeMap::<TaskNode, crate::public_cache::ExplicitSpelling>::new();
    for unit in units {
        if unit.key.kind != TaskUnitKind::Lib || !unit.is_crates_io {
            continue;
        }
        let flag = spellings.get(&unit.key).copied().ok_or_else(|| {
            stow_error!(
                "lib unit {} {} ({}, {:?}) minted no explicit-spelling flag",
                unit.name,
                unit.version,
                unit.key.platform,
                unit.key.side,
            )
        })?;
        spelling_by_node.insert(task_node(unit)?, flag);
    }
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
            explicit_spelling: spelling_by_node.get(*node).copied().ok_or_else(|| {
                stow_error!(
                    "task node {} {} ({}) minted no explicit-spelling flag",
                    node.crate_name,
                    node.version,
                    node.target,
                )
            })?,
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
///
/// The twin must be the unit the same package's target side resolves —
/// the same package at the same feature set. `TaskUnitKey` carries no
/// features, so the lookup below compares them itself, as the sets
/// `task_node` canonicalizes. Whether cargo would actually share the
/// pair is the dependent's host-side context, not the pin's problem:
/// the target unit exists in the consumer's resolve either way — as
/// the shared unit in outcome 2 and as the distinct unit in outcome 3
/// (stow#723, where [`self_twin_edges`] decides sharing recursively) —
/// so the task pins it whenever it resolves. A different-feature twin
/// never shares and resolves as its own identity, so pinning it
/// reproduces nothing a consumer computes and makes the task compile
/// units no node publishes (stow#722).
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
                && target.features.iter().collect::<BTreeSet<_>>()
                    == dep_unit.features.iter().collect::<BTreeSet<_>>()
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
        // The outcome-3 self-twin edge a host node carries when cargo
        // keeps its own pair apart is a different edge —
        // `self_twin_edges` adds it in `task_graph`.
        shadows.remove(&node);
        extra_edges.entry(node).or_default().extend(shadows);
    }
    Ok(extra_edges)
}

/// A unit's raw seven-field task node.
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
        profile: unit.profile,
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
        profile: node.profile,
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

#[cfg(test)]
mod tests {
    use super::{
        ResolvedTaskGraph, TaskUnit, TaskUnitDep, TaskUnitKey, TaskUnitKind, TaskUnitSide,
        resolved_task_graph, task_graph, task_node,
    };
    use crate::identity::WireRustcVersion;

    const PLATFORM: &str = "x86_64-unknown-linux-gnu";

    fn crates_io_lib(name: &str, version: &str, side: TaskUnitSide, features: &[&str]) -> TaskUnit {
        TaskUnit {
            key: TaskUnitKey {
                pkg: format!(
                    "registry+https://github.com/rust-lang/crates.io-index#{name}@{version}"
                ),
                platform: PLATFORM.to_owned(),
                side,
                kind: TaskUnitKind::Lib,
            },
            name: name.to_owned(),
            version: version.to_owned(),
            features: features
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect(),
            is_crates_io: true,
            deps: Vec::new(),
            profile: crate::node_profile::NodeProfile::Dev,
        }
    }

    fn dep_on(unit: &TaskUnit) -> TaskUnitDep {
        TaskUnitDep {
            key: unit.key.clone(),
            name: unit.name.clone(),
            version: unit.version.clone(),
            proc_macro: false,
        }
    }

    /// The shadow edge names the twin cargo would share — the same
    /// package at the same feature set. A host dep with `[]` pins its
    /// `[]` target twin, and pins nothing when the only target unit
    /// carries `["std"]` (stow#722).
    #[test]
    fn a_shadow_edge_names_only_a_same_feature_twin() {
        let host_dep = crates_io_lib("dep", "1.0.0", TaskUnitSide::Host, &[]);
        let mut owner = crates_io_lib("owner", "1.0.0", TaskUnitSide::Target, &[]);
        owner.deps.push(dep_on(&host_dep));
        let owner_node = task_node(&owner).expect("owner node");
        let host_dep_node = task_node(&host_dep).expect("host dep node");

        // The twin at the host dep's own feature set is one cargo
        // shares — the node gains the edge.
        let twin = crates_io_lib("dep", "1.0.0", TaskUnitSide::Target, &[]);
        let twin_node = task_node(&twin).expect("twin node");
        let (_, edges) = task_graph(&[owner.clone(), host_dep.clone(), twin]).expect("task graph");
        let deps = &edges[&owner_node];
        assert!(deps.contains(&host_dep_node));
        assert!(deps.contains(&twin_node));

        // A different-feature twin is one cargo never shares — the
        // node gains no edge to it.
        let other = crates_io_lib("dep", "1.0.0", TaskUnitSide::Target, &["std"]);
        let other_node = task_node(&other).expect("other node");
        let (_, edges) = task_graph(&[owner, host_dep, other]).expect("task graph");
        let deps = &edges[&owner_node];
        assert!(deps.contains(&host_dep_node));
        assert!(!deps.contains(&other_node));
    }

    /// One lib dep wired from a parent unit.
    fn with_lib_deps(mut unit: TaskUnit, deps: &[&TaskUnit]) -> TaskUnit {
        unit.deps.extend(deps.iter().map(|dep| dep_on(dep)));
        unit
    }

    /// The pair `(x host, x target)` plus the twin pair of `dep` each
    /// side links: shareable iff `dep`'s two sides resolve the same
    /// features.
    fn twin_scenario(dep_features: &[&str], target_dep_features: &[&str]) -> Vec<TaskUnit> {
        let dep_h = crates_io_lib("dep", "1.0.0", TaskUnitSide::Host, dep_features);
        let dep_t = crates_io_lib("dep", "1.0.0", TaskUnitSide::Target, target_dep_features);
        let x_h = with_lib_deps(
            crates_io_lib("x", "1.0.0", TaskUnitSide::Host, &[]),
            &[&dep_h],
        );
        let x_t = with_lib_deps(
            crates_io_lib("x", "1.0.0", TaskUnitSide::Target, &[]),
            &[&dep_t],
        );
        vec![x_h, x_t, dep_h, dep_t]
    }

    /// stow#723: a same-feature twin pair whose lib dep lists pair up —
    /// recursively — is the pair cargo merges into one unit (outcome
    /// 2), and the host node carries no self-twin edge.
    #[test]
    fn a_shareable_twin_pair_adds_no_self_edge() {
        let units = twin_scenario(&[], &[]);
        let (_, edges) = task_graph(&units).expect("task graph");
        let x_h = task_node(&units[0]).expect("host node");
        let x_t = task_node(&units[1]).expect("target node");
        assert!(
            !edges[&x_h].contains(&x_t),
            "a shareable pair mints the plain host identity"
        );
    }

    /// stow#723: the pair splits (outcome 3) when a dep pair is not a
    /// twin — here the two sides' `dep` units resolve different feature
    /// sets — and the host node gains the edge that re-mints its id.
    #[test]
    fn an_unshareable_twin_pair_adds_the_self_edge() {
        let units = twin_scenario(&[], &["std"]);
        let (_, edges) = task_graph(&units).expect("task graph");
        let x_h = task_node(&units[0]).expect("host node");
        let x_t = task_node(&units[1]).expect("target node");
        assert!(
            edges[&x_h].contains(&x_t),
            "an outcome-3 host node pins its distinct target twin"
        );
        assert!(
            !edges[&x_t].contains(&x_h),
            "the twin edge is one direction only"
        );
    }

    /// stow#723: the rule is recursive — the differing pair can sit any
    /// depth below the twins — and a dependent re-mints because the
    /// host child's task id changes with the edge.
    #[test]
    fn a_recursive_difference_edges_the_twin_and_remints_dependents() {
        let rustc = WireRustcVersion::parse("1.85.0").expect("rustc");
        let build = |leaf_t_features: &[&str]| {
            let leaf_h = crates_io_lib("leaf", "1.0.0", TaskUnitSide::Host, &[]);
            let leaf_t = crates_io_lib("leaf", "1.0.0", TaskUnitSide::Target, leaf_t_features);
            let z_h = with_lib_deps(
                crates_io_lib("z", "1.0.0", TaskUnitSide::Host, &[]),
                &[&leaf_h],
            );
            let z_t = with_lib_deps(
                crates_io_lib("z", "1.0.0", TaskUnitSide::Target, &[]),
                &[&leaf_t],
            );
            let y_h = with_lib_deps(
                crates_io_lib("y", "1.0.0", TaskUnitSide::Host, &[]),
                &[&z_h],
            );
            let y_t = with_lib_deps(
                crates_io_lib("y", "1.0.0", TaskUnitSide::Target, &[]),
                &[&z_t],
            );
            let x_h = with_lib_deps(
                crates_io_lib("x", "1.0.0", TaskUnitSide::Host, &[]),
                &[&y_h],
            );
            let x_t = with_lib_deps(
                crates_io_lib("x", "1.0.0", TaskUnitSide::Target, &[]),
                &[&y_t],
            );
            let parent = with_lib_deps(
                crates_io_lib("parent", "1.0.0", TaskUnitSide::Target, &[]),
                &[&x_h],
            );
            vec![parent, x_h, x_t, y_h, y_t, z_h, z_t, leaf_h, leaf_t]
        };
        let split_units = build(&["std"]);
        let shared_units = build(&[]);
        let (_, split_edges) = task_graph(&split_units).expect("split graph");
        let x_h = task_node(&split_units[1]).expect("host node");
        let x_t = task_node(&split_units[2]).expect("target node");
        assert!(
            split_edges[&x_h].contains(&x_t),
            "a difference two levels down splits the twin"
        );
        // The differing leaf's different-feature twin is not a
        // candidate: the pair never shares (stow#722) and `z` splits on
        // it before feature lookup.
        let (_, shared_edges) = task_graph(&shared_units).expect("shared graph");
        let s_x_h = task_node(&shared_units[1]).expect("host node");
        assert!(
            !shared_edges[&s_x_h].contains(&task_node(&shared_units[2]).expect("target node")),
            "identical deps merge the twin"
        );

        let split_graph = resolved_task_graph(&split_units, &rustc).expect("split resolves");
        let shared_graph = resolved_task_graph(&shared_units, &rustc).expect("shared resolves");
        let find = |graph: &ResolvedTaskGraph, name: &str, host_side: bool| {
            graph
                .nodes()
                .iter()
                .position(|node| {
                    node.identity.crate_name.as_str() == name
                        && node.identity.host_side == host_side
                })
                .and_then(|index| graph.task_id(index).map(str::to_owned))
                .unwrap_or_else(|| panic!("{name} host_side={host_side} resolves"))
        };
        assert_ne!(
            find(&split_graph, "x", true),
            find(&shared_graph, "x", true),
            "the self-twin edge re-mints the host node's id"
        );
        assert_ne!(
            find(&split_graph, "parent", false),
            find(&shared_graph, "parent", false),
            "a dependent re-mints through the child id"
        );
    }

    /// Host-kinded deps — a proc-macro or a build-dependency lib — are
    /// the identical unit on both sides of a twin pair: they pair by
    /// identity, so a pair sharing only host deps merges.
    #[test]
    fn host_kinded_deps_pair_by_identity() {
        let pm = crates_io_lib("pm", "1.0.0", TaskUnitSide::Host, &[]);
        let bd = crates_io_lib("bd", "1.0.0", TaskUnitSide::Host, &[]);
        let mut pm_dep = dep_on(&pm);
        pm_dep.proc_macro = true;
        let script = TaskUnit {
            key: TaskUnitKey {
                pkg: "registry+https://github.com/rust-lang/crates.io-index#x@1.0.0".to_owned(),
                platform: PLATFORM.to_owned(),
                side: TaskUnitSide::Host,
                kind: TaskUnitKind::BuildScript,
            },
            name: "x".to_owned(),
            version: "1.0.0".to_owned(),
            features: Vec::new(),
            is_crates_io: true,
            deps: vec![dep_on(&bd)],
            profile: crate::node_profile::NodeProfile::Dev,
        };
        let mut x_h = crates_io_lib("x", "1.0.0", TaskUnitSide::Host, &[]);
        x_h.deps.push(pm_dep.clone());
        let mut x_t = crates_io_lib("x", "1.0.0", TaskUnitSide::Target, &[]);
        x_t.deps.push(pm_dep);
        let units = vec![x_h, x_t, pm, bd, script];
        let (_, edges) = task_graph(&units).expect("task graph");
        let host_node = task_node(&units[0]).expect("host node");
        let twin_node = task_node(&units[1]).expect("target node");
        assert!(
            !edges[&host_node].contains(&twin_node),
            "identical host-kinded deps leave the pair shareable"
        );
    }

    /// A different-feature twin never merges (stow#722) and never adds
    /// the self-twin edge — the target unit is simply not the twin.
    #[test]
    fn a_different_feature_twin_adds_no_self_edge() {
        let x_h = crates_io_lib("x", "1.0.0", TaskUnitSide::Host, &[]);
        let x_t = crates_io_lib("x", "1.0.0", TaskUnitSide::Target, &["std"]);
        let (_, edges) = task_graph(&[x_h.clone(), x_t.clone()]).expect("task graph");
        let host_node = task_node(&x_h).expect("host node");
        let twin_node = task_node(&x_t).expect("target node");
        assert!(
            !edges
                .get(&host_node)
                .is_some_and(|deps| deps.contains(&twin_node)),
            "different features are not a twin pair"
        );
    }
}
