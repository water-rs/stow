//! Per-side dependency edges of the resolved graph — the port of the
//! vendored resolver's `FeatureResolver::deps`/`edges` additions onto the
//! published `cargo` crate's public API.
//!
//! Cargo's [`FeatureResolver::resolve`] reports *feature* activations
//! only — `activated_dependencies` records optional-dep activations, not
//! the graph — so the edges are derived here from the same rules
//! `FeatureResolver::deps` applies: platform-gated edges are filtered
//! against the requested kinds, and an optional dep is an edge only when
//! it was activated under the applied feature key.

use std::collections::{BTreeSet, HashMap};

use anyhow::Context as _;
use cargo::CargoResult;
use cargo::core::compiler::CompileTarget;
use cargo::core::compiler::{CompileKind, RustcTargetData};
use cargo::core::dependency::{ArtifactTarget, DepKind};
use cargo::core::resolver::Resolve;
use cargo::core::resolver::ResolveBehavior;
use cargo::core::resolver::features::{
    FeaturesFor, ForceAllTargets, HasDevUnits, PackageFeaturesKey, ResolvedFeatures,
};
use cargo::core::{Dependency, PackageId, PackageSet, Workspace};

/// One resolved dependency edge out of a `(package, side)` node, as
/// decided by [`deps`]. `to` is the dep's own `(package, side)` key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SideEdge {
    /// The dependency node this edge points at.
    pub to: PackageFeaturesKey,
    /// `normal`, `dev`, or `build` — the dep's manifest kind.
    pub dep_kind: DepKind,
    /// Whether the dep's package has a proc-macro library target; such
    /// deps compile for the host platform regardless of the parent's
    /// platform.
    pub proc_macro: bool,
}

/// Orders a package's dependencies on one other package in manifest
/// order: normal, dev, and build dependencies; untargeted before
/// targeted; then by the name declared in the manifest. This tuple is
/// unique within a manifest.
fn manifest_order(a: &Dependency, b: &Dependency) -> std::cmp::Ordering {
    (a.kind(), a.platform(), a.name_in_toml()).cmp(&(b.kind(), b.platform(), b.name_in_toml()))
}

/// The `FeatureOpts` fields `deps`/`edges` read — recomputed because the
/// published crate keeps them private. Same derivation as
/// `FeatureOpts::new`: `-Zfeatures` flags first, then the workspace's
/// resolver behavior, then the dev/all-targets overrides.
#[derive(Debug, Default, Clone, Copy)]
pub struct EdgeOpts {
    /// Build deps and proc-macros do not share features with other dep
    /// kinds, and neither do artifact targets.
    decouple_host_deps: bool,
    /// Dev dep features are not activated unless needed.
    decouple_dev_deps: bool,
    /// Targets that are not in use do not activate features.
    ignore_inactive_targets: bool,
}

impl EdgeOpts {
    /// `FeatureOpts::new(ws, has_dev_units, force_all_targets)` without the
    /// `compare` flag, which nothing here reads.
    pub fn new(
        ws: &Workspace<'_>,
        has_dev_units: HasDevUnits,
        force_all_targets: ForceAllTargets,
    ) -> CargoResult<Self> {
        let mut opts = Self::default();
        let mut enable = |feat_opts: &[String]| -> CargoResult<()> {
            for opt in feat_opts {
                match opt.as_str() {
                    "build_dep" | "host_dep" => opts.decouple_host_deps = true,
                    "dev_dep" => opts.decouple_dev_deps = true,
                    "itarget" => opts.ignore_inactive_targets = true,
                    "all" => {
                        opts.decouple_host_deps = true;
                        opts.decouple_dev_deps = true;
                        opts.ignore_inactive_targets = true;
                    }
                    // `compare` and `ws` change nothing stow reads.
                    "compare" | "ws" => {}
                    s => anyhow::bail!("-Zfeatures flag `{s}` is not supported"),
                }
            }
            Ok(())
        };
        if let Some(feat_opts) = ws.gctx().cli_unstable().features.as_ref() {
            enable(feat_opts)?;
        }
        match ws.resolve_behavior() {
            ResolveBehavior::V1 => {}
            ResolveBehavior::V2 | ResolveBehavior::V3 => enable(&["all".to_owned()])?,
        }
        if has_dev_units == HasDevUnits::Yes {
            // Dev deps cannot be decoupled when they are in use.
            opts.decouple_dev_deps = false;
        }
        if force_all_targets == ForceAllTargets::Yes {
            opts.ignore_inactive_targets = false;
        }
        Ok(opts)
    }
}

/// Helper for determining if a platform is activated — verbatim from
/// `FeatureResolver::deps`.
fn platform_activated(
    dep: &Dependency,
    fk: FeaturesFor,
    target_data: &RustcTargetData<'_>,
    requested_targets: &[CompileKind],
) -> bool {
    // We always count platforms as activated if the target stems from an
    // artifact dependency's target specification. This triggers in
    // conjunction with `[target.'cfg(…)'.dependencies]` manifest sections.
    match (dep.is_build(), fk) {
        (true, _) | (_, FeaturesFor::HostDep) => {
            // We always care about build-dependencies, and they are always
            // Host. If we are computing dependencies "for a build script",
            // even normal dependencies are host-only.
            target_data.dep_platform_activated(dep, CompileKind::Host)
        }
        (_, FeaturesFor::NormalOrDev) => requested_targets
            .iter()
            .any(|kind| target_data.dep_platform_activated(dep, *kind)),
        (_, FeaturesFor::ArtifactDep(target)) => {
            target_data.dep_platform_activated(dep, CompileKind::Target(target))
        }
    }
}

/// Whether the given package is a proc macro lib target — useful for
/// checking if a dependency is a proc macro, as it is not possible to
/// depend on a non-lib target as a proc-macro.
fn has_proc_macro_lib(package_set: &PackageSet<'_>, package_id: PackageId) -> bool {
    package_set
        .get_one(package_id)
        .expect("packages downloaded")
        .library()
        .is_some_and(cargo::core::Target::proc_macro)
}

/// Returns the `FeaturesFor` needed for this dependency — verbatim from
/// `FeatureResolver::deps`'s `artifact_features_for`. This includes the
/// `FeaturesFor` for artifact dependencies, which might specify multiple
/// targets.
fn artifact_features_for(
    target_data: &mut RustcTargetData<'_>,
    requested_targets: &[CompileKind],
    pkg_id: PackageId,
    dep: &Dependency,
    lib_fk: FeaturesFor,
    unstable_json_spec: bool,
) -> CargoResult<Vec<FeaturesFor>> {
    let Some(artifact) = dep.artifact() else {
        return Ok(vec![lib_fk]);
    };
    let mut result = Vec::new();
    let host_triple = target_data.rustc.host;
    // Not all targets may be queried before resolution since artifact
    // dependencies and per-pkg-targets are not immediately known.
    let mut activate_target = |target| {
        let name = dep.name_in_toml();
        target_data
            .merge_compile_kind(CompileKind::Target(target))
            .with_context(|| {
                format!(
                    "failed to determine target information for target `{target}`.\n  \
                     Artifact dependency `{name}` in package `{pkg_id}` requires building \
                     for `{target}`",
                    target = target.rustc_target()
                )
            })
    };

    if let Some(target) = artifact.target() {
        match target {
            ArtifactTarget::Force(target) => {
                activate_target(target)?;
                result.push(FeaturesFor::ArtifactDep(target));
            }
            // FIXME: this needs to interact with the `default-target`
            // and `forced-target` values of the dependency
            ArtifactTarget::BuildDependencyAssumeTarget => {
                for kind in requested_targets {
                    let target = match kind {
                        CompileKind::Host => {
                            CompileTarget::new(host_triple.as_str(), unstable_json_spec).unwrap()
                        }
                        CompileKind::Target(target) => *target,
                    };
                    activate_target(target)?;
                    result.push(FeaturesFor::ArtifactDep(target));
                }
            }
        }
    }
    if artifact.is_lib() || artifact.target().is_none() {
        result.push(lib_fk);
    }
    Ok(result)
}

/// What [`deps`] returns per node: each activated dep with the
/// `FeaturesFor` sides it compiles under.
type DepEdgeList<'a> = Vec<(PackageId, Vec<(&'a Dependency, FeaturesFor)>)>;

/// The dependencies of one `(package, side)` node — `FeatureResolver::deps`
/// verbatim except the platform gate, which `unit_dependencies` applies
/// unconditionally (the `opts.ignore_inactive_targets` arm upstream is
/// the feature resolver's own).
///
/// `track_for_host` is `decouple_host_deps || ignore_inactive_targets` of
/// the same [`EdgeOpts`].
#[allow(clippy::too_many_arguments)] // the ported signature tracks cargo's context
fn deps<'a>(
    ws: &Workspace<'_>,
    target_data: &mut RustcTargetData<'_>,
    resolve: &'a Resolve,
    package_set: &PackageSet<'_>,
    requested_targets: &[CompileKind],
    opts: EdgeOpts,
    track_for_host: bool,
    pkg_id: PackageId,
    fk: FeaturesFor,
) -> CargoResult<DepEdgeList<'a>> {
    let unstable_json_spec = ws.gctx().cli_unstable().json_target_spec;
    let mut out = Vec::new();
    for (dep_id, deps) in resolve.deps(pkg_id) {
        let mut deps: Vec<&'a Dependency> = deps
            .iter()
            .filter(|dep| {
                // The compile-time edge set is `unit_dependencies`'s,
                // not the feature resolver's: upstream it evaluates
                // `dep_platform_activated` per unit kind
                // unconditionally, while `FeatureResolver::deps` gates
                // the same check on `ignore_inactive_targets` — a flag
                // a V1 workspace or a ForceAllTargets::Yes lane never
                // sets. Edges must spell what cargo builds, so the
                // platform gate applies always (stow#588 — a
                // cfg(windows) dep of a registry crate reached a Linux
                // task's children through the unfiltered lane).
                if dep.platform().is_some()
                    && !platform_activated(dep, fk, target_data, requested_targets)
                {
                    return false;
                }
                if opts.decouple_dev_deps && dep.kind() == DepKind::Development {
                    return false;
                }
                true
            })
            .collect();
        deps.sort_by(|a, b| manifest_order(a, b));
        let mut dep_results = Vec::new();
        for dep in deps {
            // Each `dep`endency can be built for multiple targets. For one,
            // it may be a library target which is built as initially
            // configured by `fk`. If it appears as build dependency, it
            // must be built for the host. It may also be an artifact
            // dependency, which could be built either for a specified (aka
            // 'forced') target (`dep = { …, target = <triple>` }`), as an
            // artifact for use in build dependencies that should build for
            // whichever `--target`s are specified, or like a library would
            // be built.
            let lib_fk = if fk != FeaturesFor::HostDep
                && track_for_host
                && (dep.is_build() || has_proc_macro_lib(package_set, dep_id))
            {
                FeaturesFor::HostDep
            } else {
                fk
            };
            dep_results.extend(
                artifact_features_for(
                    target_data,
                    requested_targets,
                    pkg_id,
                    dep,
                    lib_fk,
                    unstable_json_spec,
                )?
                .into_iter()
                .map(move |dep_fk| (dep, dep_fk)),
            );
        }
        if !dep_results.is_empty() {
            out.push((dep_id, dep_results));
        }
    }
    Ok(out)
}

/// Every `(pkg, fk)` side the feature resolver activated, mapped to the
/// deps it saw for that side — the port of the vendored
/// `FeatureResolver::edges`. A dep edge is emitted exactly when cargo
/// would compile it: platform-gated edges are filtered inside [`deps`],
/// and an optional dep is included only if it was activated for that
/// side (`ResolvedFeatures::is_dep_activated` applies the feature
/// namespace's opts internally).
pub fn edges<'a>(
    ws: &Workspace<'_>,
    target_data: &mut RustcTargetData<'_>,
    resolve: &'a Resolve,
    package_set: &PackageSet<'_>,
    resolved_features: &ResolvedFeatures,
    requested_targets: &[CompileKind],
    opts: EdgeOpts,
) -> CargoResult<HashMap<PackageFeaturesKey, Vec<SideEdge>>> {
    let track_for_host = opts.decouple_host_deps || opts.ignore_inactive_targets;
    let keys: Vec<PackageFeaturesKey> = resolved_features
        .activated_features
        .keys()
        .chain(resolved_features.activated_dependencies.keys())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    // `deps` is deterministic per (pkg, fk); memoize like the vendored
    // resolver so every caller sees the pair evaluate once.
    let mut deps_cache: HashMap<(PackageId, FeaturesFor), DepEdgeList<'a>> = HashMap::new();
    let mut edges: HashMap<PackageFeaturesKey, Vec<SideEdge>> = HashMap::new();
    for (pkg_id, fk) in keys {
        let dep_list = if let Some(cached) = deps_cache.get(&(pkg_id, fk)) {
            cached.clone()
        } else {
            let computed = deps(
                ws,
                target_data,
                resolve,
                package_set,
                requested_targets,
                opts,
                track_for_host,
                pkg_id,
                fk,
            )?;
            deps_cache.insert((pkg_id, fk), computed.clone());
            computed
        };
        for (dep_id, deps) in &dep_list {
            for (dep, dep_fk) in deps {
                if dep.is_optional()
                    && !resolved_features.is_dep_activated(pkg_id, fk, dep.name_in_toml())
                {
                    continue;
                }
                let edge = SideEdge {
                    to: (*dep_id, *dep_fk),
                    dep_kind: dep.kind(),
                    proc_macro: has_proc_macro_lib(package_set, *dep_id),
                };
                edges.entry((pkg_id, fk)).or_default().push(edge);
            }
        }
    }
    Ok(edges)
}
