//! Unit-graph emission — the port of the vendored resolver's
//! `emit_units`, verbatim semantics over the published crate's types.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use cargo::CargoResult;
use cargo::core::compiler::CompileKind;
use cargo::core::dependency::DepKind;
use cargo::core::resolver::features::{FeaturesFor, PackageFeaturesKey};
use cargo::core::{Package, PackageSet, Workspace};
use cargo::core::{PackageId, PackageIdSpec};

use crate::edges::SideEdge;
use crate::units::{
    SpecsAndResolvedFeatures, StowDep, StowSide, StowUnit, StowUnitKey, StowUnitKind,
};

/// Which cargo side a dep edge lands on: build deps and proc-macros live
/// on the host, artifact deps on their own target, and every other edge
/// inherits the side of the unit it leaves. This is the edge kind, not
/// the feature namespace — under a `resolver = "1"` workspace cargo
/// unifies all features under `FeaturesFor::NormalOrDev` while still
/// compiling host deps for the host.
fn edge_side(side: StowSide, edge: &SideEdge, dep_fk: FeaturesFor) -> StowSide {
    if edge.dep_kind == DepKind::Build || edge.proc_macro {
        StowSide::Host
    } else if let FeaturesFor::ArtifactDep(_) = dep_fk {
        StowSide::Artifact
    } else {
        side
    }
}

/// The triple a `CompileKind` compiles on.
fn kind_triple(kind: &CompileKind, host_triple: &str) -> String {
    match kind {
        CompileKind::Host => host_triple.to_string(),
        CompileKind::Target(t) => t.short_name().to_string(),
    }
}

/// The platform a dep edge lands on.
fn dep_platform(
    parent_platform: &str,
    edge: &SideEdge,
    dep_fk: FeaturesFor,
    host_triple: &str,
) -> String {
    if edge.dep_kind == DepKind::Build || edge.proc_macro {
        host_triple.to_string()
    } else if let FeaturesFor::ArtifactDep(target) = dep_fk {
        target.short_name().to_string()
    } else {
        parent_platform.to_string()
    }
}

/// Builds the unit graph from the resolved per-side edges.
///
/// Platform derivation follows cargo's unit construction:
/// - a member's own `lib` compiles on the requested target — unless the
///   member is a proc-macro crate, whose lib compiles on the host;
/// - a dep edge lands on the host when the dep is a build dep or a
///   proc-macro; on the artifact target for `ArtifactDep`; otherwise on
///   the parent unit's platform (host propagates: deps of host units are
///   host units);
/// - every package with a `build.rs` gets a host `CustomBuild` unit per
///   side, and its build-deps are that unit's edges, not the lib's —
///   matching the unit graph's `RunCustomBuild` wiring.
///
/// `Development` dep edges are dropped: they exist only for `cargo test`,
/// which stow never builds.
#[allow(clippy::too_many_lines)] // one pass over the graph; split hurts the port's shape
pub fn emit_units(
    ws: &Workspace<'_>,
    pkg_set: &PackageSet<'_>,
    specs_and_features: &[SpecsAndResolvedFeatures],
    requested_kinds: &[CompileKind],
    host_triple: &str,
    members_are_crates_io: bool,
) -> CargoResult<(Vec<StowUnit>, Vec<StowUnitKey>)> {
    // Stow splits cargo's unit identity one step further: cargo interns
    // one unit per (pkg, platform, feature set) inside a build, but a
    // package serving both dep roles compiles as two units at two
    // profiles — under `resolver = "1"` the feature set is even the same
    // — so each is its own node and the side joins the traversal
    // identity. A dual-use package emits one unit per side; edges to it
    // point at the side that edge needs (stow#367).
    type UnitId = (PackageId, String, FeaturesFor, StowSide);

    #[allow(clippy::too_many_arguments)]
    fn seed(
        visited: &mut BTreeSet<UnitId>,
        queue: &mut VecDeque<UnitId>,
        roots: &mut Vec<StowUnitKey>,
        pkg_id: PackageId,
        platform: String,
        fk: FeaturesFor,
        side: StowSide,
        is_member_lib: bool,
    ) {
        let id = (pkg_id, platform.clone(), fk, side);
        if !visited.insert(id.clone()) {
            return;
        }
        queue.push_back(id);
        if is_member_lib {
            roots.push(StowUnitKey {
                pkg: pkg_id.to_spec(),
                platform,
                side,
                kind: StowUnitKind::Lib,
            });
        }
    }

    let package_map: BTreeMap<PackageId, &Package> = pkg_set
        .packages()
        .map(|pkg| (pkg.package_id(), pkg))
        .collect();
    let pkg_by_id = |id: PackageId| -> CargoResult<&Package> {
        package_map
            .get(&id)
            .copied()
            .ok_or_else(|| anyhow::format_err!("{id} was resolved but not downloaded"))
    };

    // Multiple `specs` entries each produce their own `ResolvedFeatures`;
    // union their activated sets and edges into one view.
    let mut all_features: HashMap<PackageFeaturesKey, BTreeSet<String>> = HashMap::new();
    let mut all_edges: HashMap<PackageFeaturesKey, Vec<SideEdge>> = HashMap::new();
    for spec_f in specs_and_features {
        for ((pkg, fk), feats) in &spec_f.resolved_features.activated_features {
            all_features
                .entry((*pkg, *fk))
                .or_default()
                .extend(feats.iter().map(std::string::ToString::to_string));
        }
        for (key, edges) in &spec_f.edges {
            all_edges
                .entry(*key)
                .or_default()
                .extend(edges.iter().cloned());
        }
    }

    let mut visited: BTreeSet<UnitId> = BTreeSet::new();
    let mut units: Vec<StowUnit> = Vec::new();
    let mut roots: Vec<StowUnitKey> = Vec::new();
    let mut queue: VecDeque<UnitId> = VecDeque::new();
    // One build-script *compile* per distinct feature set — cargo shares
    // it across sides when the sides resolve to the same features, and
    // emits a second compile unit only when they differ. The run units
    // are always per-side.
    let mut compiles: HashMap<(PackageId, Vec<String>), StowUnitKey> = HashMap::new();

    for member in ws.default_members() {
        let member_id = member.package_id();
        // cargo's unit graph keys a proc-macro member's lib on the host
        // with its `HostDep` features — `do_resolve` activates that side
        // whenever the resolver tracks a host split. Only the lib
        // target's `proc-macro` flag counts: a proc-macro example or test
        // never changes where the lib compiles. A resolve that unified
        // everything (host tracking off) reports the same features under
        // the normal side.
        let proc_macro_lib = member
            .library()
            .is_some_and(cargo::core::Target::proc_macro);
        let host_side_active = all_features.contains_key(&(member_id, FeaturesFor::HostDep))
            || all_edges.contains_key(&(member_id, FeaturesFor::HostDep));
        // A proc-macro lib is a host unit by construction; every other
        // member lib lives on the requested (target) side.
        let (platform, fk, side) = if proc_macro_lib {
            (
                host_triple.to_string(),
                if host_side_active {
                    FeaturesFor::HostDep
                } else {
                    FeaturesFor::NormalOrDev
                },
                StowSide::Host,
            )
        } else {
            // A lib member compiles once per requested kind; without a lib
            // target the member still seeds the graph (its bin/example
            // units are intentionally absent — binaries are not units in
            // stow).
            (
                requested_kinds.first().map_or_else(
                    || host_triple.to_string(),
                    |kind| kind_triple(kind, host_triple),
                ),
                FeaturesFor::NormalOrDev,
                StowSide::Target,
            )
        };
        seed(
            &mut visited,
            &mut queue,
            &mut roots,
            member_id,
            platform.clone(),
            fk,
            side,
            member.library().is_some(),
        );
        // A member bin-only package still resolves deps for every
        // requested kind; seed the remaining kinds without emitting roots.
        for kind in requested_kinds.iter().skip(1) {
            seed(
                &mut visited,
                &mut queue,
                &mut roots,
                member_id,
                kind_triple(kind, host_triple),
                FeaturesFor::NormalOrDev,
                StowSide::Target,
                false,
            );
        }
    }

    while let Some((pkg_id, platform, fk, side)) = queue.pop_front() {
        let pkg = pkg_by_id(pkg_id)?;
        let features: Vec<String> = all_features
            .get(&(pkg_id, fk))
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default();
        let edges: &[SideEdge] = all_edges.get(&(pkg_id, fk)).map_or(&[], Vec::as_slice);

        // Partition dep edges the way cargo's unit construction does:
        // normal deps feed the lib unit; build deps feed the build-script
        // compile unit, and only exist at all when the package has a
        // build script (a proc-macro without `build.rs` never compiles
        // its declared build-deps); dev deps never exist in `cargo
        // build`'s graph.
        let mut lib_deps = Vec::new();
        let mut build_deps = Vec::new();
        let mut run_deps = Vec::new();
        let has_custom_build = pkg.has_custom_build();
        for edge in edges {
            if edge.dep_kind == DepKind::Development {
                continue;
            }
            if edge.dep_kind == DepKind::Build && !has_custom_build {
                continue;
            }
            let (dep_id, dep_fk) = edge.to;
            let dep_platform = dep_platform(&platform, edge, dep_fk, host_triple);
            let dep_side = edge_side(side, edge, dep_fk);
            seed(
                &mut visited,
                &mut queue,
                &mut roots,
                dep_id,
                dep_platform.clone(),
                dep_fk,
                dep_side,
                false,
            );
            let dep_pkg = pkg_by_id(dep_id)?;
            let dep = StowDep {
                key: StowUnitKey {
                    pkg: dep_id.to_spec(),
                    platform: dep_platform.clone(),
                    side: dep_side,
                    kind: StowUnitKind::Lib,
                },
                name: dep_id.name().to_string(),
                version: dep_id.version().to_string(),
                dep_kind: edge.dep_kind,
            };
            if edge.dep_kind == DepKind::Build {
                build_deps.push(dep);
            } else {
                // `run-custom-build` units depend on the run units of
                // sibling deps that declare `links` — build script outputs
                // of linkable deps feed the dependent's build script.
                let links_dep = dep_pkg.manifest().links().is_some()
                    && dep_pkg
                        .library()
                        .is_some_and(cargo::core::Target::is_linkable);
                if links_dep {
                    run_deps.push(StowDep {
                        key: StowUnitKey {
                            pkg: dep_id.to_spec(),
                            platform: dep_platform.clone(),
                            side: dep_side,
                            kind: StowUnitKind::RunBuildScript,
                        },
                        name: dep_id.name().to_string(),
                        version: dep_id.version().to_string(),
                        dep_kind: edge.dep_kind,
                    });
                }
                lib_deps.push(dep);
            }
        }

        let is_crates_io =
            pkg_id.source_id().is_crates_io() || (members_are_crates_io && ws.is_member_id(pkg_id));
        let push_unit = |platform: String,
                         side: StowSide,
                         kind: StowUnitKind,
                         deps: Vec<StowDep>|
         -> StowUnit {
            StowUnit {
                key: StowUnitKey {
                    pkg: pkg_id.to_spec(),
                    platform,
                    side,
                    kind,
                },
                name: pkg_id.name().to_string(),
                version: pkg_id.version().to_string(),
                unit_kind: kind,
                features: features.clone(),
                is_crates_io,
                deps,
            }
        };

        if has_custom_build {
            // lib -> run -> compile, as cargo's `run-custom-build` wiring;
            // the run also follows the run of each links-bearing dep.
            let is_new = !compiles.contains_key(&(pkg_id, features.clone()));
            let build_key = compiles
                .entry((pkg_id, features.clone()))
                .or_insert_with(|| StowUnitKey {
                    pkg: pkg_id.to_spec(),
                    platform: host_triple.to_string(),
                    side: StowSide::Host,
                    kind: StowUnitKind::BuildScript,
                })
                .clone();
            let mut run_dep_list = vec![StowDep {
                key: build_key,
                name: pkg_id.name().to_string(),
                version: pkg_id.version().to_string(),
                dep_kind: DepKind::Build,
            }];
            run_dep_list.extend(run_deps);
            units.push(push_unit(
                platform.clone(),
                side,
                StowUnitKind::RunBuildScript,
                run_dep_list,
            ));
            if is_new {
                units.push(push_unit(
                    host_triple.to_string(),
                    StowSide::Host,
                    StowUnitKind::BuildScript,
                    build_deps,
                ));
            }
            lib_deps.push(StowDep {
                key: StowUnitKey {
                    pkg: pkg_id.to_spec(),
                    platform: platform.clone(),
                    side,
                    kind: StowUnitKind::RunBuildScript,
                },
                name: pkg_id.name().to_string(),
                version: pkg_id.version().to_string(),
                dep_kind: DepKind::Build,
            });
        }
        if pkg.library().is_some() {
            units.push(push_unit(platform, side, StowUnitKind::Lib, lib_deps));
        }
    }

    emit_deduped_dep_edges(&mut units);
    units.sort_by(|a, b| a.key.cmp(&b.key));
    Ok((units, roots))
}

/// Mirror cargo's shared-dep dedup: a normal dep edge leaving a host
/// unit resolves to the dep's normal unit whenever a real `cargo build`
/// dedups the pair — the same package emitted at the same platform and
/// feature set under both sides. A native `cargo build` compiles the
/// dep once, at the normal unit, and hands the host parent's `--extern`
/// that artifact; a `--target`-spelled build keeps the side split and
/// resolves the edge to the host unit. Both edges are emitted so the
/// task's dep pins cover each spelling's resolution (stow#506).
fn emit_deduped_dep_edges(units: &mut [StowUnit]) {
    let unit_features: HashMap<(&PackageIdSpec, &str, StowSide), &Vec<String>> = units
        .iter()
        .filter(|unit| unit.key.kind == StowUnitKind::Lib)
        .map(|unit| {
            (
                (&unit.key.pkg, unit.key.platform.as_str(), unit.key.side),
                &unit.features,
            )
        })
        .collect();
    let mut deduped: Vec<(usize, StowDep)> = Vec::new();
    for (index, unit) in units.iter().enumerate() {
        if unit.key.side != StowSide::Host || unit.key.kind != StowUnitKind::Lib {
            continue;
        }
        for dep in &unit.deps {
            if dep.dep_kind != DepKind::Normal
                || dep.key.side != StowSide::Host
                || dep.key.kind != StowUnitKind::Lib
            {
                continue;
            }
            let dep_features = unit_features
                .get(&(&dep.key.pkg, dep.key.platform.as_str(), dep.key.side))
                .copied();
            let normal_features = unit_features
                .get(&(&dep.key.pkg, dep.key.platform.as_str(), StowSide::Target))
                .copied();
            if dep_features.is_some() && dep_features == normal_features {
                deduped.push((
                    index,
                    StowDep {
                        key: StowUnitKey {
                            pkg: dep.key.pkg.clone(),
                            platform: dep.key.platform.clone(),
                            side: StowSide::Target,
                            kind: StowUnitKind::Lib,
                        },
                        name: dep.name.clone(),
                        version: dep.version.clone(),
                        dep_kind: dep.dep_kind,
                    },
                ));
            }
        }
    }
    for (index, dep) in deduped {
        units[index].deps.push(dep);
    }
}
