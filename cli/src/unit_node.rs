//! Which node of the build's unit graph a compiled unit is (stow#615).
//!
//! Two different feature sets used to be read from one place. The `--cfg
//! feature="…"` scan of a rustc command line is cargo's resolved set for
//! the unit *plus* whatever its build script printed as
//! `cargo:rustc-cfg=feature="…"` (`target-lexicon`'s `rust_1_40`,
//! `winapi`'s closure of its own enabled features) — a fact about the
//! command line, which only the compile key consumes. The unit's cargo
//! feature set is the resolver's answer, and only the build's own unit
//! graph knows it: the semantic request, the local row's label, and the
//! miss graph all resolve a compiled unit to its node here.

use std::collections::BTreeSet;

use semver::Version;
use stow_types::api::ResolvedDependencyGraphEntry;
use stow_types::identity::CrateName;

use crate::rustc_args::ParsedRustcArgs;

/// One lib node's coordinates in the build's unit graph: which side of
/// the host/target split it sits on, and the feature set cargo's
/// resolver computed for it.
///
/// `features` is the unit graph's `unit.features` verbatim — never the
/// argv `--cfg feature="…"` scan, which also carries a build script's
/// `cargo:rustc-cfg=feature="…"` output (stow#615).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UnitNode {
    /// The crates.io package name.
    pub crate_name: CrateName,
    /// The resolved version.
    pub version: Version,
    /// The side of the unit graph the node is on.
    pub host_side: bool,
    /// Cargo's resolved feature set for this side's unit.
    pub features: Vec<String>,
}

impl UnitNode {
    /// The node's coordinates as [`resolve_unit_node`] reads them.
    pub fn coordinates(&self) -> NodeCoordinates<'_> {
        NodeCoordinates {
            crate_name: self.crate_name.as_str(),
            version: &self.version,
            host_side: self.host_side,
            features: &self.features,
        }
    }
}

/// The per-side node table of one build's unit graph — what the
/// wrapper's decision path and the miss graph's minter resolve a
/// compiled unit against. `STOW_EXPANDED_GRAPH_JSON` carries this for a
/// nested or unsupervised wrapper; a supervised build's `AnalysisFacts`
/// cell holds it directly (stow#615).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnitNodeTable {
    /// Whether the graph's cargo invocation was given a target —
    /// `--target`, `CARGO_BUILD_TARGET`, or `build.target`. Under it
    /// cargo hands the flag to every target unit and to no host unit, so
    /// a flagless invocation resolves host-side outright; a native build
    /// spells neither, and side arbitration falls to the scan and the
    /// profile signal.
    pub consumer_spelled_target: bool,
    /// The graph's lib nodes — one per `(crate, version, side)`.
    pub nodes: Vec<UnitNode>,
}

impl UnitNodeTable {
    /// The table an expanded dependency graph's per-side entries carry.
    pub fn from_expanded(
        entries: &[ResolvedDependencyGraphEntry],
        consumer_spelled_target: bool,
    ) -> Self {
        Self {
            consumer_spelled_target,
            nodes: entries
                .iter()
                .map(|entry| UnitNode {
                    crate_name: entry.crate_name.clone(),
                    version: entry.version.clone(),
                    host_side: entry.host_side,
                    features: entry.features.clone(),
                })
                .collect(),
        }
    }

    /// The nodes as borrowed coordinates, for [`resolve_unit_node`].
    pub fn coordinates(&self) -> impl Iterator<Item = NodeCoordinates<'_>> {
        self.nodes.iter().map(UnitNode::coordinates)
    }
}

/// A graph node's coordinates, borrowed from whichever store the caller
/// holds — the wrapper's [`UnitNodeTable`], or the resolved task graph
/// the miss drain projects.
#[derive(Debug, Clone, Copy)]
pub struct NodeCoordinates<'a> {
    /// The crates.io package name.
    pub crate_name: &'a str,
    /// The resolved version.
    pub version: &'a Version,
    /// The side of the unit graph the node is on.
    pub host_side: bool,
    /// Cargo's resolved feature set for this side's unit.
    pub features: &'a [String],
}

impl<'a> From<&'a stow_types::task_graph::ResolvedTaskNode> for NodeCoordinates<'a> {
    fn from(node: &'a stow_types::task_graph::ResolvedTaskNode) -> Self {
        Self {
            crate_name: node.identity.crate_name.as_str(),
            version: node.identity.version.as_semver(),
            host_side: node.identity.host_side,
            features: node.identity.features_json.features(),
        }
    }
}

/// The command-line evidence a compiled unit's node resolution reads —
/// everything about the invocation that is a fact about the command
/// line, not the graph.
#[derive(Debug)]
pub struct UnitEvidence<'a> {
    /// The crates.io package name the invocation compiles.
    pub crate_name: &'a str,
    /// The resolved version the invocation compiles.
    pub version: &'a str,
    /// Whether the rustc invocation spells `--target`.
    pub spelled_target: bool,
    /// The argv `--cfg feature="…"` scan — cargo's resolved set plus any
    /// `cargo:rustc-cfg=feature="…"` lines the unit's build script
    /// printed. Evidence only; the resolved set is the graph's (stow#615).
    pub feature_scan: &'a BTreeSet<String>,
    /// The build-override profile signal — cargo spells explicit codegen
    /// flags for target units but not for the build-override units on
    /// the host half (stow#349; replacing the signal is stow#596).
    pub build_override: bool,
}

impl<'a> UnitEvidence<'a> {
    /// The evidence one parsed rustc invocation carries about the
    /// registry unit `(crate_name, version)` it compiles.
    pub const fn from_invocation(
        crate_name: &'a str,
        version: &'a str,
        parsed: &'a ParsedRustcArgs,
    ) -> Self {
        Self {
            crate_name,
            version,
            spelled_target: parsed.target.is_some(),
            feature_scan: &parsed.features,
            build_override: build_override_signal(parsed),
        }
    }
}

/// The argv signal cargo leaves on a build-override unit: it spells no
/// explicit codegen flags, where a target unit's invocation always
/// carries them (stow#349).
pub const fn build_override_signal(parsed: &ParsedRustcArgs) -> bool {
    parsed.debuginfo.is_none() && parsed.opt_level.is_none()
}

/// Which node of `nodes` the compiled unit `unit` is — the side it
/// compiled on and cargo's resolved feature set for it.
///
/// Rule, in order:
///
/// 1. No node for `(crate, version)` — an error naming both.
/// 2. Nodes on one side only — that node.
/// 3. Nodes on both sides: a spelled `--target` invocation is the
///    target node; under a graph resolved with a given target a flagless
///    invocation is the host node; under a native build the side whose
///    feature set the scan covers wins when exactly one is covered, and
///    otherwise the build-override signal decides.
///
/// The scan only ever arbitrates a native build's twin, and only by
/// containment: a build-script crate's scan is a strict superset of its
/// resolved set, so "the scan equals the node's set" can never be the
/// test (stow#615). When both sides carry the same set the features are
/// the same whichever side is chosen.
///
/// # Errors
///
/// A `(crate, version)` no node covers, a version that is not semver, or
/// one side carrying two different feature sets — the projection
/// enforces the same invariant [`crate::workspace_deps`] builds under.
pub fn resolve_unit_node<'a>(
    nodes: impl IntoIterator<Item = NodeCoordinates<'a>>,
    consumer_spelled_target: bool,
    unit: &UnitEvidence<'_>,
) -> stow_types::error::Result<NodeCoordinates<'a>> {
    let version = Version::parse(unit.version).map_err(|error| {
        stow_types::stow_error!("compiled unit version `{}`: {error}", unit.version)
    })?;
    let mut target_node = None;
    let mut host_node = None;
    for node in nodes {
        if node.crate_name != unit.crate_name || *node.version != version {
            continue;
        }
        let slot = if node.host_side {
            &mut host_node
        } else {
            &mut target_node
        };
        match slot {
            None => *slot = Some(node),
            Some(existing) if existing.features == node.features => {}
            Some(existing) => {
                return Err(stow_types::stow_error!(
                    "the build's unit graph holds two feature sets for the {} node of {} {}: {:?} and {:?}",
                    if node.host_side { "host" } else { "target" },
                    unit.crate_name,
                    unit.version,
                    existing.features,
                    node.features,
                ));
            }
        }
    }
    match (target_node, host_node) {
        (None, None) => Err(stow_types::stow_error!(
            "the build's unit graph holds no node for {} {}",
            unit.crate_name,
            unit.version
        )),
        (Some(node), None) | (None, Some(node)) => Ok(node),
        (Some(target), Some(host)) => {
            if unit.spelled_target {
                return Ok(target);
            }
            if consumer_spelled_target {
                return Ok(host);
            }
            let covered = |node: &NodeCoordinates<'_>| {
                node.features
                    .iter()
                    .all(|feature| unit.feature_scan.contains(feature))
            };
            match (covered(&target), covered(&host)) {
                (true, false) => Ok(target),
                (false, true) => Ok(host),
                _ => Ok(if unit.build_override { host } else { target }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node<'a>(
        crate_name: &'a str,
        version: &'a Version,
        host_side: bool,
        features: &'a [String],
    ) -> NodeCoordinates<'a> {
        NodeCoordinates {
            crate_name,
            version,
            host_side,
            features,
        }
    }

    fn evidence<'a>(
        crate_name: &'a str,
        version: &'a str,
        spelled_target: bool,
        feature_scan: &'a BTreeSet<String>,
        build_override: bool,
    ) -> UnitEvidence<'a> {
        UnitEvidence {
            crate_name,
            version,
            spelled_target,
            feature_scan,
            build_override,
        }
    }

    fn scan(features: &[&str]) -> BTreeSet<String> {
        features
            .iter()
            .map(|feature| (*feature).to_owned())
            .collect()
    }

    fn strings(features: &[&str]) -> Vec<String> {
        features
            .iter()
            .map(|feature| (*feature).to_owned())
            .collect()
    }

    /// A crate the graph does not carry is an error naming it — never a
    /// guessed node.
    #[test]
    fn a_unit_absent_from_the_graph_is_an_error() {
        let version = Version::parse("1.0.0").unwrap();
        let nodes = [node("other", &version, false, &[])];
        let error = resolve_unit_node(
            nodes,
            false,
            &evidence("missing", "1.0.0", false, &scan(&[]), false),
        )
        .expect_err("absent unit errors");
        assert!(
            error.to_string().contains("missing 1.0.0"),
            "the error names the unit: {error}"
        );
    }

    /// One node on one side resolves to it whatever the scan carries —
    /// a build-script crate's scan is its resolved set plus the names its
    /// `cargo:rustc-cfg=feature="…"` lines printed (stow#615).
    #[test]
    fn a_single_side_build_script_crate_resolves_to_that_node() {
        let version = Version::parse("1.0.0").unwrap();
        let resolved = strings(&["default", "std"]);
        let nodes = [node("lexicon", &version, false, &resolved)];
        // `target-lexicon`'s shape: the scan adds `rust_1_40` on top of
        // the resolved set.
        let resolved_node = resolve_unit_node(
            nodes,
            false,
            &evidence(
                "lexicon",
                "1.0.0",
                false,
                &scan(&["default", "std", "rust_1_40"]),
                false,
            ),
        )
        .expect("one side resolves unconditionally");
        assert!(!resolved_node.host_side);
        assert_eq!(resolved_node.features, resolved.as_slice());
    }

    /// A spelled `--target` invocation resolves to the target side's
    /// node even when the two sides carry different feature sets.
    #[test]
    fn a_spelled_target_invocation_takes_the_target_node() {
        let version = Version::parse("1.0.0").unwrap();
        let host_features = strings(&["default", "f1"]);
        let target_features = strings(&[]);
        let nodes = [
            node("feat-a", &version, true, &host_features),
            node("feat-a", &version, false, &target_features),
        ];
        let resolved_node = resolve_unit_node(
            nodes,
            true,
            &evidence("feat-a", "1.0.0", true, &scan(&[]), false),
        )
        .expect("spelled target resolves");
        assert!(!resolved_node.host_side);
        assert_eq!(resolved_node.features, target_features.as_slice());
    }

    /// Under a graph resolved with a spelled `--target`, a flagless
    /// invocation is the host-side node — including when its set is a
    /// strict subset of the target side's.
    #[test]
    fn a_flagless_invocation_under_a_target_graph_takes_the_host_node() {
        let version = Version::parse("1.0.0").unwrap();
        let host_features = strings(&["default"]);
        let target_features = strings(&["default", "f1", "f2"]);
        let nodes = [
            node("both", &version, true, &host_features),
            node("both", &version, false, &target_features),
        ];
        let resolved_node = resolve_unit_node(
            nodes,
            true,
            &evidence("both", "1.0.0", false, &scan(&["default"]), false),
        )
        .expect("flagless invocation under a target graph is host");
        assert!(resolved_node.host_side);
        assert_eq!(resolved_node.features, host_features.as_slice());
    }

    /// A native build's twin resolves by containment: the host set is a
    /// strict subset of the target set, so a flagless host unit's scan
    /// covers only its own side's set — the subset test picks the host
    /// node. The target unit's scan covers both sets (its superset
    /// contains the host's), so its side falls to the profile signal.
    #[test]
    fn a_native_build_twin_resolves_by_scan_containment() {
        let version = Version::parse("1.0.0").unwrap();
        let host_features = strings(&["default"]);
        let target_features = strings(&["default", "f1", "f2"]);
        let nodes = [
            node("both", &version, true, &host_features),
            node("both", &version, false, &target_features),
        ];
        // The host unit's scan covers only the host set — the strict
        // subset disambiguates.
        let resolved_node = resolve_unit_node(
            nodes,
            false,
            &evidence("both", "1.0.0", false, &scan(&["default"]), true),
        )
        .expect("host scan covers only the host set");
        assert!(resolved_node.host_side);
        assert_eq!(resolved_node.features, host_features.as_slice());
        // The target unit's scan covers the host subset too, so
        // containment cannot split them — the profile signal says
        // target (its invocation carries explicit codegen flags).
        let resolved_node = resolve_unit_node(
            nodes,
            false,
            &evidence(
                "both",
                "1.0.0",
                false,
                &scan(&["default", "f1", "f2"]),
                false,
            ),
        )
        .expect("the profile signal arbitrates the subset scan");
        assert!(!resolved_node.host_side);
        assert_eq!(resolved_node.features, target_features.as_slice());
    }

    /// The `winapi` shape: a build-script crate on both sides whose
    /// scan covers both sets — the script prints its enabled features'
    /// closure on top of the resolved set, so the containment test
    /// cannot split them and the profile signal decides.
    #[test]
    fn a_scan_covering_both_sides_falls_to_the_profile_signal() {
        let version = Version::parse("1.0.0").unwrap();
        let host_features = strings(&["winapi-x", "default"]);
        let target_features = strings(&["winapi-x", "default", "winapi-y"]);
        let nodes = [
            node("winapi", &version, true, &host_features),
            node("winapi", &version, false, &target_features),
        ];
        // The build script's `cargo:rustc-cfg` output inflates the scan
        // past both resolved sets.
        let inflated = scan(&["winapi-x", "default", "winapi-y", "winapi-z"]);
        let resolved_node = resolve_unit_node(
            nodes,
            false,
            &evidence("winapi", "1.0.0", false, &inflated, true),
        )
        .expect("the profile signal arbitrates");
        assert!(resolved_node.host_side);
        let nodes = [
            node("winapi", &version, true, &host_features),
            node("winapi", &version, false, &target_features),
        ];
        let resolved_node = resolve_unit_node(
            nodes,
            false,
            &evidence("winapi", "1.0.0", false, &inflated, false),
        )
        .expect("the profile signal arbitrates");
        assert!(!resolved_node.host_side);
    }

    /// A native build's twin at equal feature sets: whichever side is
    /// chosen the features agree, so the profile signal may pick freely.
    #[test]
    fn equal_sets_on_both_sides_take_the_profile_signal_side() {
        let version = Version::parse("1.0.0").unwrap();
        let features = strings(&["default"]);
        let nodes = [
            node("shared", &version, true, &features),
            node("shared", &version, false, &features),
        ];
        let resolved_node = resolve_unit_node(
            nodes,
            false,
            &evidence("shared", "1.0.0", false, &scan(&["default"]), true),
        )
        .expect("equal sets arbitrate on the signal");
        assert!(resolved_node.host_side);
        assert_eq!(resolved_node.features, features.as_slice());
    }
}
