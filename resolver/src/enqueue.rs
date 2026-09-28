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

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::Context as _;
use cargo::CargoResult;
use stow_types::api::{EnqueueDependency, EnqueueRequest, EnqueueSource};
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};

use crate::units::{StowSide, StowUnit, StowUnitKind};

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
    let features: Vec<String> = serde_json::from_str(raw).expect("canonical features json");
    FeaturesJson::from_sorted(features).expect("serialize_feature_set sorted")
}

/// The lib-unit graph the wave machinery works on: every task node and
/// its task-level dependency edges.
///
/// # Errors
/// A unit whose feature set cannot serialize.
pub fn task_graph(units: &[StowUnit]) -> CargoResult<TaskGraph> {
    // Index once — dep and build-script lookups used to re-scan `units`
    // inside per-unit loops, which is quadratic on a zed-sized resolve.
    let mut libs: HashMap<(&str, &str, &str, StowSide), &StowUnit> =
        HashMap::with_capacity(units.len());
    let mut scripts: HashMap<(&str, &str, &[String]), &StowUnit> =
        HashMap::with_capacity(units.len());
    for unit in units {
        match unit.key.kind {
            StowUnitKind::Lib => {
                libs.entry((
                    unit.name.as_str(),
                    unit.version.as_str(),
                    unit.key.platform.as_str(),
                    unit.key.side,
                ))
                .or_insert(unit);
            }
            StowUnitKind::BuildScript => {
                scripts
                    .entry((unit.name.as_str(), unit.version.as_str(), &unit.features))
                    .or_insert(unit);
            }
            StowUnitKind::RunBuildScript => {}
        }
    }
    let by_key = |name: &str, version: &str, platform: &str, side| {
        libs.get(&(name, version, platform, side)).copied()
    };
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
    // `emit_units` produced it).
    let raw_deps = |unit: &StowUnit| -> Vec<&StowUnit> {
        let mut direct: Vec<&StowUnit> = unit
            .deps
            .iter()
            .filter(|dep| dep.key.kind == StowUnitKind::Lib)
            .filter_map(|dep| by_key(&dep.name, &dep.version, &dep.key.platform, dep.key.side))
            .collect();
        let compile = scripts.get(&(&unit.name, &unit.version, &unit.features));
        if let Some(compile) = compile {
            direct.extend(
                compile
                    .deps
                    .iter()
                    .filter(|dep| dep.key.kind == StowUnitKind::Lib)
                    .filter_map(|dep| {
                        by_key(&dep.name, &dep.version, &dep.key.platform, dep.key.side)
                    }),
            );
        }
        direct
    };
    let mut nodes = BTreeSet::new();
    let mut edges = BTreeMap::<TaskNode, BTreeSet<TaskNode>>::new();
    for unit in units {
        if unit.key.kind != StowUnitKind::Lib || !unit.is_crates_io {
            continue;
        }
        let node = node_of(unit)?;
        nodes.insert(node.clone());
        let entry = edges.entry(node.clone()).or_default();
        // Non-crates.io units (project members, path deps, git packages)
        // carry the resolve's edges but mint no task — a project's own
        // crates are the way into the crates.io graph. Walk through them
        // so a node's deps are the crates.io libs on the far side.
        let mut seen = BTreeSet::new();
        let mut stack = raw_deps(unit);
        while let Some(dep_unit) = stack.pop() {
            if !seen.insert(&dep_unit.key) {
                continue;
            }
            if dep_unit.is_crates_io {
                entry.insert(node_of(dep_unit)?);
            } else {
                stack.extend(raw_deps(dep_unit));
            }
        }
        entry.remove(&node);
    }
    Ok((nodes, edges))
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
