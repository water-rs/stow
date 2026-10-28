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

use std::collections::{BTreeMap, BTreeSet};

use semver::Version;
use stow_types::api::ResolvedDependencyGraphEntry;
use stow_types::identity::CrateName;
use stow_types::platform::Profile;

use crate::rustc_args::ParsedRustcArgs;

/// Each node's compile profile as cargo's unit graph states it, keyed
/// by node identity — crate, version, side. A host node minted by
/// re-splitting a unit cargo merged into one compile carries no
/// profile: the shared compile is the target node's, and the host node
/// has no compile of its own in this build to state a profile for
/// (stow#596).
pub type NodeProfiles = BTreeMap<(CrateName, Version, bool), Profile>;

/// One lib node's coordinates in the build's unit graph: which side of
/// the host/target split it sits on, and the feature set cargo's
/// resolver computed for it.
///
/// `features` is the unit graph's `unit.features` verbatim — never the
/// argv `--cfg feature="…"` scan, which also carries a build script's
/// `cargo:rustc-cfg=feature="…"` output (stow#615). `profile` is the
/// unit's own compile profile as cargo states it (`unit.profile`), or
/// `None` for the host node of a twin cargo merged into a single
/// target-side compile (stow#596).
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
    /// The compile profile cargo states for this node's own unit —
    /// `None` when the node was re-split from a unit whose compile is
    /// the other side's (a merged native twin — stow#596).
    pub profile: Option<Profile>,
}

impl UnitNode {
    /// The node's coordinates as [`resolve_unit_node`] reads them.
    pub fn coordinates(&self) -> NodeCoordinates<'_> {
        NodeCoordinates {
            crate_name: self.crate_name.as_str(),
            version: &self.version,
            host_side: self.host_side,
            features: &self.features,
            profile: self.profile.as_ref(),
        }
    }
}

/// The per-side node table of one build's unit graph — what the
/// wrapper's decision path and the miss graph's minter resolve a
/// compiled unit against. The file `STOW_EXPANDED_GRAPH_PATH` names
/// carries this for a nested or unsupervised wrapper; a supervised
/// build's `AnalysisFacts` cell holds it directly (stow#615).
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
    /// `profiles` is the same unit graph's per-node compile profiles —
    /// [`crate::workspace_deps::ExpandedDependencyGraph::node_profiles`].
    pub fn from_expanded(
        entries: &[ResolvedDependencyGraphEntry],
        profiles: &NodeProfiles,
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
                    profile: profiles
                        .get(&(
                            entry.crate_name.clone(),
                            entry.version.clone(),
                            entry.host_side,
                        ))
                        .cloned(),
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
    /// The compile profile cargo states for this node's own unit —
    /// `None` for the host node of a native twin cargo merged into one
    /// target-side compile: it has no compile of its own in this build,
    /// so nothing on the invocation could prove it (stow#596).
    pub profile: Option<&'a Profile>,
}

impl<'a> NodeCoordinates<'a> {
    /// A task graph node's coordinates, with its compile profile looked
    /// up in `profiles` — the same unit graph's [`NodeProfiles`].
    pub fn from_task_node(
        node: &'a stow_types::task_graph::ResolvedTaskNode,
        profiles: &'a NodeProfiles,
    ) -> Self {
        Self {
            crate_name: node.identity.crate_name.as_str(),
            version: node.identity.version.as_semver(),
            host_side: node.identity.host_side,
            features: node.identity.features_json.features(),
            profile: profiles.get(&(
                node.identity.crate_name.clone(),
                node.identity.version.as_semver().clone(),
                node.identity.host_side,
            )),
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
    /// The profile the invocation compiles with — normalized the way the
    /// unit graph states it (`unit.profile`), so the two compare like
    /// for like (stow#596).
    pub profile: Profile,
}

impl<'a> UnitEvidence<'a> {
    /// The evidence one parsed rustc invocation carries about the
    /// registry unit `(crate_name, version)` it compiles.
    ///
    /// # Errors
    /// As [`ParsedRustcArgs::profile`] — a codegen flag value outside the
    /// set rustc documents.
    pub fn from_invocation(
        crate_name: &'a str,
        version: &'a str,
        parsed: &'a ParsedRustcArgs,
    ) -> Result<Self, String> {
        Ok(Self {
            crate_name,
            version,
            spelled_target: parsed.target.is_some(),
            feature_scan: &parsed.features,
            profile: invocation_profile(parsed)?,
        })
    }
}

/// The profile the invocation compiles with, normalized like the unit
/// graph's `unit.profile` — rustc's real flag defaults applied to
/// absent codegen flags: `-C debug-assertions` is on only at
/// `opt-level=0` and `-C overflow-checks` follows it.
///
/// [`ParsedRustcArgs::profile`] cannot supply this: it defaults both to
/// `true` when the flag is absent, which no `opt-level != 0` unit runs
/// with — its values ride the compile key, so the defect stays there
/// and is corrected here instead (stow#596).
fn invocation_profile(parsed: &ParsedRustcArgs) -> Result<Profile, String> {
    let mut profile = parsed.profile()?;
    profile.debug_assertions = parsed.debug_assertions.unwrap_or(profile.opt_level == "0");
    profile.overflow_checks = parsed.overflow_checks.unwrap_or(profile.debug_assertions);
    Ok(profile)
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
///    invocation is the host node; under a native build the node whose
///    stated profile equals the invocation's wins when exactly one
///    matches, then the node whose resolved feature set equals the
///    scan's, and anything left is an error — the side is never
///    guessed (stow#596).
///
/// The profile comparison is general: it compares full normalized
/// profiles, so it holds whatever profile either side compiles at —
/// dev, release, or a `build-override` of either (stow#596). A node
/// carrying no profile — the host half of a unit cargo merged into one
/// compile — can never match, so a merged unit resolves to the target
/// node whose compile it actually was.
///
/// The scan only ever arbitrates a native build's twin whose stated
/// profiles tie, and by equality: cargo spells `--cfg feature="…"`
/// from `unit.features` verbatim, so the compile's scan is its
/// resolved set. A build script's `cargo:rustc-cfg=feature="…"` output
/// can inflate the scan past that set (stow#615) — an inflated scan
/// then matches neither node and the compile errors rather than
/// guessing.
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
            let matches = |node: &NodeCoordinates<'_>| {
                node.profile.is_some_and(|profile| *profile == unit.profile)
            };
            match (matches(&target), matches(&host)) {
                (true, false) => Ok(target),
                (false, true) => Ok(host),
                (false, false) => Err(stow_types::stow_error!(
                    "the build's unit graph holds no node at the {} {} compile's profile {:?}",
                    unit.crate_name,
                    unit.version,
                    unit.profile,
                )),
                (true, true) => {
                    let equals = |node: &NodeCoordinates<'_>| {
                        node.features.len() == unit.feature_scan.len()
                            && node
                                .features
                                .iter()
                                .all(|feature| unit.feature_scan.contains(feature))
                    };
                    match (equals(&target), equals(&host)) {
                        (true, false) => Ok(target),
                        (false, true) => Ok(host),
                        _ => Err(stow_types::stow_error!(
                            "the build's unit graph holds a {} {} twin its profile and feature set cannot split — cannot tell which side the compile was",
                            unit.crate_name,
                            unit.version,
                        )),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stow_types::platform::{PanicStrategy, StripLevel};

    /// A profile as cargo's unit graph states it — the invocation side
    /// normalizes to the same fields.
    fn profile(
        opt_level: &str,
        debuginfo: u32,
        debug_assertions: bool,
        overflow_checks: bool,
    ) -> Profile {
        Profile {
            opt_level: opt_level.to_owned(),
            debuginfo,
            debug_assertions,
            overflow_checks,
            panic: PanicStrategy::Unwind,
            strip: StripLevel::None,
        }
    }

    /// Dev's target-side profile.
    fn dev() -> Profile {
        profile("0", 2, true, true)
    }

    /// The build-override profile under dev — what a host unit compiles
    /// with when it shares no target compile.
    fn host() -> Profile {
        profile("0", 0, true, true)
    }

    /// A release build-override — the host profile stow#978's
    /// host-release work states.
    fn release_host() -> Profile {
        profile("0", 0, false, false)
    }

    /// Release on the target side.
    fn release() -> Profile {
        profile("3", 0, false, false)
    }

    fn node<'a>(
        crate_name: &'a str,
        version: &'a Version,
        host_side: bool,
        features: &'a [String],
        profile: Option<&'a Profile>,
    ) -> NodeCoordinates<'a> {
        NodeCoordinates {
            crate_name,
            version,
            host_side,
            features,
            profile,
        }
    }

    fn evidence<'a>(
        crate_name: &'a str,
        version: &'a str,
        spelled_target: bool,
        feature_scan: &'a BTreeSet<String>,
        profile: Profile,
    ) -> UnitEvidence<'a> {
        UnitEvidence {
            crate_name,
            version,
            spelled_target,
            feature_scan,
            profile,
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
        let dev = dev();
        let nodes = [node("other", &version, false, &[], Some(&dev))];
        let error = resolve_unit_node(
            nodes,
            false,
            &evidence("missing", "1.0.0", false, &scan(&[]), dev.clone()),
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
        let dev = dev();
        let resolved = strings(&["default", "std"]);
        let nodes = [node("lexicon", &version, false, &resolved, Some(&dev))];
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
                dev.clone(),
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
        let dev = dev();
        let host = host();
        let host_features = strings(&["default", "f1"]);
        let target_features = strings(&[]);
        let nodes = [
            node("feat-a", &version, true, &host_features, Some(&host)),
            node("feat-a", &version, false, &target_features, Some(&dev)),
        ];
        let resolved_node = resolve_unit_node(
            nodes,
            true,
            &evidence("feat-a", "1.0.0", true, &scan(&[]), dev.clone()),
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
        let dev = dev();
        let host = host();
        let host_features = strings(&["default"]);
        let target_features = strings(&["default", "f1", "f2"]);
        let nodes = [
            node("both", &version, true, &host_features, Some(&host)),
            node("both", &version, false, &target_features, Some(&dev)),
        ];
        let resolved_node = resolve_unit_node(
            nodes,
            true,
            &evidence("both", "1.0.0", false, &scan(&["default"]), host.clone()),
        )
        .expect("flagless invocation under a target graph is host");
        assert!(resolved_node.host_side);
        assert_eq!(resolved_node.features, host_features.as_slice());
    }

    /// A native build's twin under dev: the two halves state different
    /// profiles — the target side's `debuginfo=2` against the host
    /// side's build-override `0` — so each compile resolves to its own
    /// node however the scan reads.
    #[test]
    fn a_native_build_twin_resolves_by_its_stated_profile() {
        let version = Version::parse("1.0.0").unwrap();
        let dev = dev();
        let host = host();
        let features = strings(&["default"]);
        let nodes = [
            node("both", &version, true, &features, Some(&host)),
            node("both", &version, false, &features, Some(&dev)),
        ];
        let resolved_node = resolve_unit_node(
            nodes,
            false,
            &evidence("both", "1.0.0", false, &scan(&["default"]), host.clone()),
        )
        .expect("the build-override compile resolves host");
        assert!(resolved_node.host_side);
        let resolved_node = resolve_unit_node(
            nodes,
            false,
            &evidence("both", "1.0.0", false, &scan(&["default"]), dev.clone()),
        )
        .expect("the dev compile resolves target");
        assert!(!resolved_node.host_side);
    }

    /// A twin pair under `CARGO_PROFILE_DEV_DEBUG=0`: both halves
    /// state the same `debuginfo=0` profile, so the profile cannot
    /// split them — the resolved feature sets still can, by equality:
    /// the compile's `--cfg feature="…"` list IS the set cargo spelled
    /// from `unit.features` (stow#596).
    #[test]
    fn a_twin_under_a_debugless_dev_profile_resolves_by_equality() {
        let version = Version::parse("1.0.0").unwrap();
        let host_features = strings(&["default"]);
        let target_features = strings(&["default", "f1"]);
        let stripped = profile("0", 0, true, true);
        let nodes = [
            node("both", &version, true, &host_features, Some(&stripped)),
            node("both", &version, false, &target_features, Some(&stripped)),
        ];
        // The common shape: the host set is a strict subset of the
        // target set, but each compile's scan IS its own set, so the
        // host compile equals the host set and the target compile
        // equals the target set.
        let resolved_node = resolve_unit_node(
            nodes,
            false,
            &evidence(
                "both",
                "1.0.0",
                false,
                &scan(&["default"]),
                stripped.clone(),
            ),
        )
        .expect("the host compile's scan equals the host set");
        assert!(resolved_node.host_side);
        let resolved_node = resolve_unit_node(
            nodes,
            false,
            &evidence(
                "both",
                "1.0.0",
                false,
                &scan(&["default", "f1"]),
                stripped.clone(),
            ),
        )
        .expect("the target compile's scan equals the target set");
        assert!(!resolved_node.host_side);
    }

    /// Disjoint feature sets split by equality the same way.
    #[test]
    fn a_twin_with_disjoint_feature_sets_resolves_by_equality() {
        let version = Version::parse("1.0.0").unwrap();
        let host_features = strings(&["host-only"]);
        let target_features = strings(&["target-only"]);
        let stripped = profile("0", 0, true, true);
        let nodes = [
            node("both", &version, true, &host_features, Some(&stripped)),
            node("both", &version, false, &target_features, Some(&stripped)),
        ];
        let resolved_node = resolve_unit_node(
            nodes,
            false,
            &evidence(
                "both",
                "1.0.0",
                false,
                &scan(&["host-only"]),
                stripped.clone(),
            ),
        )
        .expect("the host scan resolves host");
        assert!(resolved_node.host_side);
        let resolved_node = resolve_unit_node(
            nodes,
            false,
            &evidence(
                "both",
                "1.0.0",
                false,
                &scan(&["target-only"]),
                stripped.clone(),
            ),
        )
        .expect("the target scan resolves target");
        assert!(!resolved_node.host_side);
    }

    /// A twin pair under a release build-override on host units: the
    /// host half states `opt-level=0` against the target's `3`, so the
    /// profiles alone split them — the comparison is over full profiles,
    /// not a dev assumption (stow#596).
    #[test]
    fn a_twin_under_a_release_host_override_resolves_by_profile() {
        let version = Version::parse("1.0.0").unwrap();
        let release = release();
        let release_host = release_host();
        let features = strings(&["default"]);
        let nodes = [
            node("both", &version, true, &features, Some(&release_host)),
            node("both", &version, false, &features, Some(&release)),
        ];
        let resolved_node = resolve_unit_node(
            nodes,
            false,
            &evidence(
                "both",
                "1.0.0",
                false,
                &scan(&["default"]),
                release_host.clone(),
            ),
        )
        .expect("the release host profile resolves host");
        assert!(resolved_node.host_side);
        let resolved_node = resolve_unit_node(
            nodes,
            false,
            &evidence("both", "1.0.0", false, &scan(&["default"]), release.clone()),
        )
        .expect("the release profile resolves target");
        assert!(!resolved_node.host_side);
    }

    /// A `--release` consumer whose host/target pair cargo merged into
    /// one unit: the resolver mints two nodes but cargo ran a single
    /// compile — the target node's — so the host node states no profile
    /// and the merged compile resolves to the target node (stow#596).
    #[test]
    fn a_merged_twin_resolves_to_the_target_node() {
        let version = Version::parse("1.0.0").unwrap();
        let features = strings(&["default", "std"]);
        let merged = release();
        let nodes = [
            node("libc", &version, true, &features, None),
            node("libc", &version, false, &features, Some(&merged)),
        ];
        let resolved_node = resolve_unit_node(
            nodes,
            false,
            &evidence(
                "libc",
                "1.0.0",
                false,
                &scan(&["default", "std"]),
                merged.clone(),
            ),
        )
        .expect("the merged compile is the target node's");
        assert!(!resolved_node.host_side);
        assert_eq!(resolved_node.features, features.as_slice());
    }

    /// An invocation whose profile no node's stated profile matches is
    /// an error naming the crate — never a guessed side (stow#596).
    #[test]
    fn a_compile_matching_no_nodes_profile_is_an_error() {
        let version = Version::parse("1.0.0").unwrap();
        let dev = dev();
        let host = host();
        let features = strings(&["default"]);
        let nodes = [
            node("both", &version, true, &features, Some(&host)),
            node("both", &version, false, &features, Some(&dev)),
        ];
        let error = resolve_unit_node(
            nodes,
            false,
            &evidence("both", "1.0.0", false, &scan(&["default"]), release()),
        )
        .expect_err("no matching profile errors");
        assert!(
            error.to_string().contains("both 1.0.0"),
            "the error names the unit: {error}"
        );
    }

    /// A twin whose stated profiles tie and whose scan equals neither
    /// node's set — a kept-apart same-feature pair under a debugless
    /// profile, or a build-script-inflated scan — is an error, not a
    /// guess (stow#596).
    #[test]
    fn a_twin_nothing_distinguishes_is_an_error() {
        let version = Version::parse("1.0.0").unwrap();
        let features = strings(&["default"]);
        let stripped = profile("0", 0, true, true);
        let nodes = [
            node("both", &version, true, &features, Some(&stripped)),
            node("both", &version, false, &features, Some(&stripped)),
        ];
        let error = resolve_unit_node(
            nodes,
            false,
            &evidence(
                "both",
                "1.0.0",
                false,
                &scan(&["default", "extra"]),
                stripped.clone(),
            ),
        )
        .expect_err("an unsplittable twin errors");
        assert!(
            error.to_string().contains("both 1.0.0"),
            "the error names the unit: {error}"
        );
    }

    /// A native build's twin where the scan covers both resolved sets:
    /// under dev the profiles still differ, so the invocation's own
    /// profile picks its side — the build-script `cargo:rustc-cfg`
    /// inflation cannot hide it (stow#615, stow#596).
    #[test]
    fn a_scan_covering_both_sides_falls_to_the_profiles() {
        let version = Version::parse("1.0.0").unwrap();
        let dev = dev();
        let host = host();
        let host_features = strings(&["winapi-x", "default"]);
        let target_features = strings(&["winapi-x", "default", "winapi-y"]);
        let nodes = [
            node("winapi", &version, true, &host_features, Some(&host)),
            node("winapi", &version, false, &target_features, Some(&dev)),
        ];
        // The build script's `cargo:rustc-cfg` output inflates the scan
        // past both resolved sets.
        let inflated = scan(&["winapi-x", "default", "winapi-y", "winapi-z"]);
        let resolved_node = resolve_unit_node(
            nodes,
            false,
            &evidence("winapi", "1.0.0", false, &inflated, host.clone()),
        )
        .expect("the profile arbitrates");
        assert!(resolved_node.host_side);
        let nodes = [
            node("winapi", &version, true, &host_features, Some(&host)),
            node("winapi", &version, false, &target_features, Some(&dev)),
        ];
        let resolved_node = resolve_unit_node(
            nodes,
            false,
            &evidence("winapi", "1.0.0", false, &inflated, dev.clone()),
        )
        .expect("the profile arbitrates");
        assert!(!resolved_node.host_side);
    }
}
