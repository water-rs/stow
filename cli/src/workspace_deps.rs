use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use async_process::Command;
use cargo_lock::{Lockfile, package::SourceId};
use cargo_metadata::{Dependency, DependencyKind, FeatureName, Metadata, Package, PackageId};
use glob::glob;
use semver::{Version, VersionReq};
use serde::Deserialize;
use stow_types::api::{ResolvedDependencyGraphDependency, ResolvedDependencyGraphEntry};
use stow_types::error::Context;

use crate::cargo_cmd::MetadataArgs;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DirectDependency {
    pub(crate) crate_name: String,
    pub(crate) version: Version,
    pub(crate) source: Option<String>,
    pub(crate) features: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SelectedRegistryDependency {
    pub(crate) extern_name: String,
    pub(crate) crate_name: String,
    pub(crate) version: Version,
    pub(crate) features: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PackageKey {
    pub(crate) crate_name: String,
    pub(crate) version: Version,
    pub(crate) source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockfileGraph {
    pub(crate) direct_dependencies: Vec<DirectDependency>,
    pub(crate) workspace_packages: BTreeSet<PackageKey>,
    pub(crate) parents_by_package: BTreeMap<PackageKey, Vec<PackageKey>>,
}

/// The transitive resolve plus each visited package's feature surface —
/// the two facts the local index resolver derives from `cargo metadata`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExpandedDependencyGraph {
    /// The normalized expanded graph the resolver and the admissions
    /// request both consume.
    pub entries: Vec<ResolvedDependencyGraphEntry>,
    /// Per-package `[features]` table plus optional-dependency names,
    /// keyed the way [`crate::resolve::analyze_dependency_graph`] looks
    /// them up.
    pub feature_graphs: BTreeMap<crate::resolve::PackageKey, crate::resolve::PackageFeatureGraph>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceLayout {
    pub(crate) workspace_root: PathBuf,
    pub(crate) manifest_path: PathBuf,
}

pub fn resolve_workspace_layout(
    invocation_dir: &Path,
    manifest_override: Option<&Path>,
) -> stow_types::error::Result<WorkspaceLayout> {
    let selected_manifest = match manifest_override {
        Some(path) => canonicalize_or_original(path),
        None => find_nearest_manifest(invocation_dir)?,
    };
    let Some(selected_dir) = selected_manifest.parent() else {
        return Err(stow_types::stow_error!(
            "manifest path {} has no parent directory",
            selected_manifest.display()
        ));
    };

    if let Some(workspace_root) = find_workspace_root(&selected_manifest)? {
        return Ok(WorkspaceLayout {
            manifest_path: selected_manifest,
            workspace_root,
        });
    }

    Ok(WorkspaceLayout {
        workspace_root: selected_dir.to_path_buf(),
        manifest_path: selected_manifest,
    })
}

#[tracing::instrument(name = "stow.workspace.resolve_lockfile_graph", skip_all)]
pub fn resolve_lockfile_graph(
    workspace_root: &Path,
    manifest_path: &Path,
    args: &MetadataArgs,
) -> stow_types::error::Result<LockfileGraph> {
    let workspace_manifest_path = workspace_root.join("Cargo.toml");
    let workspace_manifest = load_manifest(&workspace_manifest_path)?;
    let workspace_members = expand_workspace_members(workspace_root, &workspace_manifest)?;
    let selected_manifest_path = canonicalize_or_original(manifest_path);
    let workspace_manifest_path = canonicalize_or_original(&workspace_manifest_path);
    let selected_members = if selected_manifest_path == workspace_manifest_path {
        workspace_members.clone()
    } else {
        BTreeSet::from([selected_manifest_path])
    };

    let lockfile_path = workspace_root.join("Cargo.lock");
    let lockfile = Lockfile::load(&lockfile_path).map_err(|error| {
        stow_types::stow_error!("load lockfile {}: {error}", lockfile_path.display())
    })?;
    let lock_packages = lockfile
        .packages
        .iter()
        .map(|package| {
            (
                PackageKey {
                    crate_name: package.name.to_string(),
                    version: package.version.clone(),
                    source: package.source.as_ref().map(ToString::to_string),
                },
                package,
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut workspace_packages = BTreeSet::<PackageKey>::new();
    for member_path in &workspace_members {
        let member_manifest = load_manifest(member_path)?;
        let package = member_manifest.package.as_ref().ok_or_else(|| {
            stow_types::stow_error!(
                "workspace member {} is missing [package]",
                member_path.display()
            )
        })?;
        let version = member_manifest
            .package_version(&workspace_manifest)
            .ok_or_else(|| {
                stow_types::stow_error!(
                    "workspace member {} package {} is missing version",
                    member_path.display(),
                    package.name
                )
            })?;
        workspace_packages.insert(PackageKey {
            crate_name: package.name.clone(),
            version: Version::parse(version).wrap_err_with(|| {
                format!(
                    "parse version `{version}` for workspace member {}",
                    member_path.display()
                )
            })?,
            source: None,
        });
    }

    let workspace_deps = workspace_manifest
        .workspace
        .as_ref()
        .and_then(|workspace| workspace.dependencies.as_ref());
    let mut merged_dependencies =
        BTreeMap::<(String, Version, Option<String>), BTreeSet<String>>::new();
    for member_path in &selected_members {
        let member_manifest = load_manifest(member_path)?;
        let member_package = member_manifest.package.as_ref().ok_or_else(|| {
            stow_types::stow_error!(
                "selected manifest {} is missing [package]",
                member_path.display()
            )
        })?;
        // The member's own lockfile entry records exactly which version cargo
        // assigned to each of its dependency edges — the only correct answer
        // when the lockfile pins several semver-compatible versions at once.
        // A stow-synthesized lockfile omits workspace members entirely (it
        // pins exactly one version per crate), so absence is a defined input
        // shape, not an error: edges then resolve by requirement match with
        // a uniqueness guarantee enforced in `resolve_lockfile_package`.
        let member_lock_package = lockfile.packages.iter().find(|package| {
            package.name.as_str() == member_package.name && package.source.is_none()
        });
        let feature_config = FeatureConfig::new(&member_manifest, &member_package.name, args);
        collect_dependency_section(
            member_manifest.dependencies.as_ref(),
            workspace_deps,
            &feature_config,
            member_lock_package,
            &lock_packages,
            &mut merged_dependencies,
        )?;
        // Build- and dev-dependencies compile in a different rustc context
        // (host triple, separate c_metadata chain) than the runtime closure
        // that the public artifact cache covers. Including them here makes
        // the lockfile-walker hard-fail when the synthesized stow lockfile
        // intentionally pins only the runtime graph — even though those
        // pins have no bearing on what the cache can serve. Skip them for
        // the cache-graph builder; cargo's own resolver still handles them
        // when it reads `Cargo.toml` directly.
    }

    let direct_dependencies = merged_dependencies
        .into_iter()
        .map(
            |((crate_name, version, source), features)| DirectDependency {
                crate_name,
                version,
                source,
                features: features.into_iter().collect(),
            },
        )
        .collect::<Vec<_>>();

    Ok(LockfileGraph {
        direct_dependencies,
        workspace_packages: workspace_packages.clone(),
        parents_by_package: build_parents_by_package(&lockfile, &workspace_packages),
    })
}

#[tracing::instrument(
    name = "stow.workspace.resolve_exact_dependency_graph",
    skip_all,
    fields(target = target)
)]
pub async fn resolve_exact_dependency_graph(
    workspace_root: &Path,
    manifest_path: &Path,
    args: &MetadataArgs,
    target: &str,
) -> stow_types::error::Result<ExpandedDependencyGraph> {
    let metadata = cargo_metadata(workspace_root, manifest_path, args, target).await?;
    let resolve = metadata.resolve.as_ref().ok_or_else(|| {
        stow_types::stow_error!("cargo metadata response is missing resolve graph")
    })?;
    let package_by_id = metadata
        .packages
        .iter()
        .map(|package| (package.id.clone(), package))
        .collect::<BTreeMap<_, _>>();
    let selected_package_ids = selected_package_ids(&metadata, manifest_path)?;

    // The walk keys every package on the side it compiles for: a
    // workspace's own units are target-side, except a proc-macro
    // member, which cargo always compiles for the host — the same rule
    // `dependency_sides` applies to each edge's target. A package
    // reachable on both sides is visited twice and posts two entries.
    let mut visited = BTreeSet::<(PackageId, bool)>::new();
    let mut queue: VecDeque<(PackageId, bool)> = selected_package_ids
        .iter()
        .map(|id| {
            (
                id.clone(),
                package_by_id.get(id).is_some_and(|package| {
                    package
                        .targets
                        .iter()
                        .any(cargo_metadata::Target::is_proc_macro)
                }),
            )
        })
        .collect();
    let mut entries = BTreeMap::<(String, Version, bool), ResolvedDependencyGraphEntry>::new();
    let mut feature_graphs =
        BTreeMap::<crate::resolve::PackageKey, crate::resolve::PackageFeatureGraph>::new();

    while let Some((package_id, host_side)) = queue.pop_front() {
        if !visited.insert((package_id.clone(), host_side)) {
            continue;
        }
        let package = package_by_id.get(&package_id).ok_or_else(|| {
            stow_types::stow_error!(
                "cargo metadata package index is missing package {}",
                package_id
            )
        })?;
        let node = resolve
            .nodes
            .iter()
            .find(|node| node.id == package_id)
            .ok_or_else(|| {
                stow_types::stow_error!(
                    "cargo metadata resolve graph is missing node {}",
                    package_id
                )
            })?;

        for dependency in &node.deps {
            for side in dependency_sides(dependency, host_side, &package_by_id) {
                queue.push_back((dependency.pkg.clone(), side));
            }
        }

        // Every visited package — registry or workspace/path — contributes
        // its real `[features]` table: the resolver canonicalizes manifest
        // seed features through it.
        if let Some((key, graph)) = package_feature_graph(package) {
            feature_graphs.insert(key, graph);
        }

        if !is_registry_package(package) {
            continue;
        }

        let mut features = node.features.clone();
        features.sort();
        features.dedup();
        let features = features
            .into_iter()
            .map(FeatureName::into_inner)
            .collect::<Vec<_>>();

        let dependencies = resolved_dependencies(node, host_side, &package_by_id);

        let entry_crate_name = stow_types::identity::CrateName::parse(package.name.as_str())
            .map_err(|error| {
                stow_types::stow_error!("workspace package name `{}`: {error}", package.name)
            })?;
        entries.insert(
            (
                package.name.clone().into_inner(),
                package.version.clone(),
                host_side,
            ),
            ResolvedDependencyGraphEntry {
                crate_name: entry_crate_name,
                version: package.version.clone(),
                features,
                host_side,
                dependencies,
            },
        );
    }

    Ok(ExpandedDependencyGraph {
        entries: entries.into_values().collect(),
        feature_graphs,
    })
}

/// The registry-dep edges one visited package emits on one side, keyed
/// the way [`dependency_sides`] classifies each `NodeDep`.
fn resolved_dependencies(
    node: &cargo_metadata::Node,
    host_side: bool,
    package_by_id: &BTreeMap<PackageId, &Package>,
) -> Vec<ResolvedDependencyGraphDependency> {
    let mut dependencies = node
        .deps
        .iter()
        .flat_map(|dependency| {
            let Some(dependency_package) = package_by_id.get(&dependency.pkg) else {
                return Vec::new();
            };
            if !is_registry_package(dependency_package) {
                return Vec::new();
            }
            let Ok(crate_name) =
                stow_types::identity::CrateName::parse(dependency_package.name.as_str())
            else {
                return Vec::new();
            };
            dependency_sides(dependency, host_side, package_by_id)
                .into_iter()
                .map(|dep_host_side| ResolvedDependencyGraphDependency {
                    crate_name: crate_name.clone(),
                    version: dependency_package.version.clone(),
                    host_side: dep_host_side,
                })
                .collect()
        })
        .collect::<Vec<_>>();
    dependencies.sort();
    dependencies.dedup();
    dependencies
}

/// The graph one build's compile observations mint misses from
/// (stow#317).
///
/// Every locally-compiled unit is a miss by definition and becomes a
/// node keyed `(crate, version, host_side)`, where `host_side` marks a
/// compile for the build's probed host — the host triple cargo never
/// passes `--target` for — rather than the consumer's target. The node
/// is still minted at the family host triple downstream; `build_host`
/// exists only to tell a host compile from a target one (stow#317).
/// A unit's `dependencies` are its invocation's `--extern` deps
/// named at each dep's own recorded identity; a dep the build served
/// rather than compiled joins as a leaf node at the artifact's recorded
/// feature set so every edge resolves to a node. A unit whose externs
/// do not all resolve to a recorded identity is not minted — a miss
/// whose deps cannot be named is a miss stow does not post.
pub struct ObservedMissGraph {
    /// The misses to enqueue: the observed (compiled-locally) units.
    pub roots: Vec<stow_types::api::DependencyGraphEntry>,
    /// The expanded graph their `depends_on` edges resolve against.
    pub expanded: Vec<ResolvedDependencyGraphEntry>,
}

/// Build the miss graph from the build's compile observations and the
/// dependency identities recorded in the artifact cache.
pub fn observed_miss_graph(
    observations: &[crate::artifact_cache::ObservedUnit],
    dep_identities: &BTreeMap<String, crate::artifact_cache::ObservedDepIdentity>,
    consumer_target: &str,
    build_host: &str,
) -> ObservedMissGraph {
    let mut entries = BTreeMap::<(String, String, bool), ResolvedDependencyGraphEntry>::new();
    let mut roots = Vec::new();
    // `(dep key, side)` pairs an observed edge needs a node for —
    // synthesized after the observed units so an observed node always
    // wins over a leaf.
    let mut referenced = BTreeSet::<(String, String, bool)>::new();
    let mut referenced_features = BTreeMap::<(String, String, bool), Vec<String>>::new();

    for observation in observations {
        let host_side = observation.target == build_host && observation.target != consumer_target;
        let (Ok(crate_name), Ok(version)) = (
            stow_types::identity::CrateName::parse(&observation.crate_name),
            Version::parse(&observation.crate_version),
        ) else {
            tracing::warn!(
                crate_name = %observation.crate_name,
                crate_version = %observation.crate_version,
                "observed unit's identity does not parse; not minting it as a miss"
            );
            continue;
        };
        let Some((mut dependencies, dep_nodes)) =
            observed_dep_edges(observation, dep_identities, consumer_target, build_host)
        else {
            continue;
        };
        // A skipped unit's deps must not mint orphan leaf nodes —
        // record the keys only once the unit's edges all resolved.
        for (dep_key, dep_features) in dep_nodes {
            referenced.insert(dep_key.clone());
            referenced_features.insert(dep_key, dep_features);
        }
        dependencies.sort();
        dependencies.dedup();
        let mut features = observation.features.clone();
        features.sort();
        features.dedup();
        let key = (
            observation.crate_name.clone(),
            observation.crate_version.clone(),
            host_side,
        );
        roots.push(stow_types::api::DependencyGraphEntry {
            crate_name: crate_name.clone(),
            version: version.clone(),
            features: features.clone(),
        });
        entries.insert(
            key,
            ResolvedDependencyGraphEntry {
                crate_name,
                version,
                features,
                host_side,
                dependencies,
            },
        );
    }

    roots.sort();
    roots.dedup();

    for (name, version, side) in referenced {
        entries
            .entry((name.clone(), version.clone(), side))
            .or_insert_with(|| {
                let crate_name = stow_types::identity::CrateName::parse(&name)
                    .expect("referenced dep name parses");
                ResolvedDependencyGraphEntry {
                    crate_name,
                    version: Version::parse(&version).expect("referenced dep version parses"),
                    features: referenced_features
                        .remove(&(name, version, side))
                        .unwrap_or_default(),
                    host_side: side,
                    dependencies: Vec::new(),
                }
            });
    }

    ObservedMissGraph {
        roots,
        expanded: entries.into_values().collect(),
    }
}

/// The `(name, version, host_side)` key a referenced dep mints its leaf
/// node under, plus the recorded feature set it carries there.
type DepNodeRef = ((String, String, bool), Vec<String>);

/// Resolve one observed unit's `--extern` deps into graph edges at each
/// dep's own recorded identity, returning the (name, version, side) keys
/// the graph must carry a node for alongside the edges. `None` — and
/// the unit is not minted — when any extern has no recorded identity:
/// a miss whose deps cannot be named is a miss stow does not post.
fn observed_dep_edges(
    observation: &crate::artifact_cache::ObservedUnit,
    dep_identities: &BTreeMap<String, crate::artifact_cache::ObservedDepIdentity>,
    consumer_target: &str,
    build_host: &str,
) -> Option<(Vec<ResolvedDependencyGraphDependency>, Vec<DepNodeRef>)> {
    let mut dependencies = Vec::new();
    let mut dep_nodes = Vec::new();
    for extern_dep in &observation.externs {
        let dep = dep_identities.get(&extern_dep.c_metadata).and_then(|dep| {
            Some((
                stow_types::identity::CrateName::parse(&dep.crate_name).ok()?,
                Version::parse(&dep.crate_version).ok()?,
                dep.features.clone(),
                dep.target.clone(),
            ))
        });
        let Some((dep_name, dep_version, dep_features, dep_target)) = dep else {
            tracing::warn!(
                crate_name = %observation.crate_name,
                c_metadata = %extern_dep.c_metadata,
                "observed unit's --extern dep has no recorded identity; not minting it as a miss"
            );
            return None;
        };
        let dep_side = dep_target == build_host && dep_target != consumer_target;
        dep_nodes.push((
            (
                dep_name.as_str().to_owned(),
                dep_version.to_string(),
                dep_side,
            ),
            dep_features,
        ));
        dependencies.push(ResolvedDependencyGraphDependency {
            crate_name: dep_name,
            version: dep_version,
            host_side: dep_side,
        });
    }
    Some((dependencies, dep_nodes))
}

/// The sides a resolve edge's target compiles for, matching cargo's
/// `HostDep` classification: everything a host-side package reaches is
/// host-side too; from the target side a dependency lands on the host
/// when it is a proc-macro (proc-macros always compile for the host) or
/// when an edge kind is `build`, and on the target for `normal` and
/// `dev` edges — dev-deps compile for the target, they are linked into
/// target test binaries. A dependency carrying both kinds — a
/// `build-dependencies` line that is also an ordinary dependency —
/// yields both nodes.
fn dependency_sides(
    dependency: &cargo_metadata::NodeDep,
    parent_host_side: bool,
    package_by_id: &BTreeMap<PackageId, &Package>,
) -> BTreeSet<bool> {
    if parent_host_side {
        return BTreeSet::from([true]);
    }
    if package_by_id.get(&dependency.pkg).is_some_and(|package| {
        package
            .targets
            .iter()
            .any(cargo_metadata::Target::is_proc_macro)
    }) {
        return BTreeSet::from([true]);
    }
    let mut sides = BTreeSet::new();
    for dep_kind in &dependency.dep_kinds {
        sides.insert(matches!(dep_kind.kind, DependencyKind::Build));
    }
    if sides.is_empty() {
        sides.insert(false);
    }
    sides
}

/// A package's feature surface keyed for the resolver: its `[features]`
/// table verbatim plus the manifest-spelled names of optional deps (each
/// grants an implicit selectable feature). `None` when the package name
/// cannot parse as a crates.io name — such a package can never be a
/// requested entry either, keeping the two key spaces identical.
fn package_feature_graph(
    package: &Package,
) -> Option<(
    crate::resolve::PackageKey,
    crate::resolve::PackageFeatureGraph,
)> {
    let crate_name = stow_types::identity::CrateName::parse(package.name.as_str()).ok()?;
    Some((
        crate::resolve::PackageKey {
            crate_name,
            version: package.version.clone(),
        },
        crate::resolve::PackageFeatureGraph {
            features: package
                .features
                .iter()
                .map(|(name, entries)| (name.clone(), entries.clone()))
                .collect(),
            optional_dependencies: package
                .dependencies
                .iter()
                .filter(|dependency| dependency.optional)
                .map(|dependency| dependency.name.clone())
                .collect(),
        },
    ))
}

pub async fn resolve_selected_registry_dependencies(
    workspace_root: &Path,
    manifest_path: &Path,
    args: &MetadataArgs,
    target: &str,
    include_dev_dependencies: bool,
) -> stow_types::error::Result<Vec<SelectedRegistryDependency>> {
    let metadata = cargo_metadata(workspace_root, manifest_path, args, target).await?;
    let resolve = metadata.resolve.as_ref().ok_or_else(|| {
        stow_types::stow_error!("cargo metadata response is missing resolve graph")
    })?;
    let package_by_id = metadata
        .packages
        .iter()
        .map(|package| (package.id.clone(), package))
        .collect::<BTreeMap<_, _>>();
    let selected_package_ids = selected_package_ids(&metadata, manifest_path)?;
    let mut dependencies = BTreeSet::<SelectedRegistryDependency>::new();

    for package_id in selected_package_ids {
        let package = package_by_id.get(&package_id).ok_or_else(|| {
            stow_types::stow_error!(
                "cargo metadata package index is missing selected package {}",
                package_id
            )
        })?;
        let node = resolve
            .nodes
            .iter()
            .find(|node| node.id == package_id)
            .ok_or_else(|| {
                stow_types::stow_error!(
                    "cargo metadata resolve graph is missing node {}",
                    package_id
                )
            })?;
        for dependency in &node.deps {
            if !dependency.dep_kinds.iter().any(|kind| {
                dependency_kind_is_top_crate_extern(kind.kind, include_dev_dependencies)
            }) {
                continue;
            }
            let manifest_dependency = find_manifest_dependency(package, dependency)?;
            if manifest_dependency.optional
                && !optional_dependency_is_enabled(
                    package,
                    &node.features,
                    dependency.name.as_str(),
                )
            {
                continue;
            }
            let dependency_package = package_by_id.get(&dependency.pkg).ok_or_else(|| {
                stow_types::stow_error!(
                    "cargo metadata package index is missing package {}",
                    dependency.pkg
                )
            })?;
            if !is_registry_package(dependency_package) {
                continue;
            }
            let dependency_node = resolve
                .nodes
                .iter()
                .find(|node| node.id == dependency.pkg)
                .ok_or_else(|| {
                    stow_types::stow_error!(
                        "cargo metadata resolve graph is missing node {}",
                        dependency.pkg
                    )
                })?;
            let mut features = dependency_node.features.clone();
            features.sort();
            features.dedup();
            let features = features.into_iter().map(FeatureName::into_inner).collect();
            dependencies.insert(SelectedRegistryDependency {
                extern_name: dependency.name.replace('-', "_"),
                crate_name: dependency_package.name.clone().into_inner(),
                version: dependency_package.version.clone(),
                features,
            });
        }
    }

    Ok(dependencies.into_iter().collect())
}

fn find_manifest_dependency<'a>(
    package: &'a Package,
    dependency: &cargo_metadata::NodeDep,
) -> stow_types::error::Result<&'a Dependency> {
    package
        .dependencies
        .iter()
        .find(|candidate| dependency_extern_name(candidate) == dependency.name)
        .ok_or_else(|| {
            stow_types::stow_error!(
                "cargo metadata node dependency {} is missing from package {} manifest dependencies",
                dependency.name,
                package.name
            )
        })
}

fn dependency_extern_name(dependency: &Dependency) -> String {
    dependency
        .rename
        .as_deref()
        .unwrap_or(dependency.name.as_str())
        .replace('-', "_")
}

fn optional_dependency_is_enabled(
    package: &Package,
    enabled_features: &[FeatureName],
    dependency_name: &str,
) -> bool {
    let enabled_features = enabled_features
        .iter()
        .map(|feature| feature.as_ref().to_owned())
        .collect::<Vec<String>>();
    if enabled_features
        .iter()
        .any(|feature| feature == dependency_name)
    {
        return true;
    }

    let mut pending = enabled_features;
    let mut seen = BTreeSet::new();
    while let Some(feature) = pending.pop() {
        if !seen.insert(feature.clone()) {
            continue;
        }
        let Some(entries) = package.features.get(&feature) else {
            continue;
        };
        for entry in entries {
            if feature_entry_enables_dependency(entry, dependency_name) {
                return true;
            }
            if package.features.contains_key(entry) {
                pending.push(entry.clone());
            }
        }
    }
    false
}

fn feature_entry_enables_dependency(entry: &str, dependency_name: &str) -> bool {
    if let Some(dependency) = entry.strip_prefix("dep:") {
        return dependency == dependency_name;
    }
    if let Some((dependency, _)) = entry.split_once('/') {
        return !dependency.ends_with('?') && dependency == dependency_name;
    }
    entry == dependency_name
}

const fn dependency_kind_is_top_crate_extern(
    kind: DependencyKind,
    include_dev_dependencies: bool,
) -> bool {
    match kind {
        DependencyKind::Normal => true,
        DependencyKind::Development => include_dev_dependencies,
        DependencyKind::Build | DependencyKind::Unknown => false,
    }
}

fn find_nearest_manifest(current_dir: &Path) -> stow_types::error::Result<PathBuf> {
    for ancestor in current_dir.ancestors() {
        let manifest_path = ancestor.join("Cargo.toml");
        if manifest_path.exists() {
            return Ok(canonicalize_or_original(&manifest_path));
        }
    }
    Err(stow_types::stow_error!(
        "could not find Cargo.toml by searching upward from {}",
        current_dir.display()
    ))
}

fn find_workspace_root(selected_manifest: &Path) -> stow_types::error::Result<Option<PathBuf>> {
    let Some(selected_dir) = selected_manifest.parent() else {
        return Err(stow_types::stow_error!(
            "manifest path {} has no parent directory",
            selected_manifest.display()
        ));
    };
    let selected_manifest = canonicalize_or_original(selected_manifest);
    for ancestor in selected_dir.ancestors() {
        let manifest_path = ancestor.join("Cargo.toml");
        if !manifest_path.exists() {
            continue;
        }
        let manifest = load_manifest(&manifest_path)?;
        if manifest.workspace.is_none() {
            continue;
        }
        if manifest_in_workspace(ancestor, &manifest, &selected_manifest)? {
            return Ok(Some(ancestor.to_path_buf()));
        }
    }
    Ok(None)
}

fn manifest_in_workspace(
    workspace_root: &Path,
    workspace_manifest: &Manifest,
    selected_manifest: &Path,
) -> stow_types::error::Result<bool> {
    let workspace_manifest_path = canonicalize_or_original(&workspace_root.join("Cargo.toml"));
    if workspace_manifest_path == selected_manifest {
        return Ok(true);
    }
    Ok(expand_workspace_members(workspace_root, workspace_manifest)?.contains(selected_manifest))
}

fn build_parents_by_package(
    lockfile: &Lockfile,
    workspace_packages: &BTreeSet<PackageKey>,
) -> BTreeMap<PackageKey, Vec<PackageKey>> {
    let mut parents_by_package = BTreeMap::<PackageKey, Vec<PackageKey>>::new();
    for package in &lockfile.packages {
        let parent_key = PackageKey {
            crate_name: package.name.to_string(),
            version: package.version.clone(),
            source: package.source.as_ref().map(ToString::to_string),
        };
        for dependency in &package.dependencies {
            let dependency_key = PackageKey {
                crate_name: dependency.name.to_string(),
                version: dependency.version.clone(),
                source: dependency.source.as_ref().map(ToString::to_string),
            };
            parents_by_package
                .entry(dependency_key)
                .or_default()
                .push(parent_key.clone());
        }
    }
    for parents in parents_by_package.values_mut() {
        parents.sort();
        parents.dedup();
    }
    for workspace_package in workspace_packages {
        parents_by_package
            .entry(workspace_package.clone())
            .or_default();
    }
    parents_by_package
}

fn collect_dependency_section(
    section: Option<&BTreeMap<String, DependencySpec>>,
    workspace_deps: Option<&BTreeMap<String, DependencySpec>>,
    feature_config: &FeatureConfig,
    member_lock_package: Option<&cargo_lock::Package>,
    lock_packages: &BTreeMap<PackageKey, &cargo_lock::Package>,
    merged_dependencies: &mut BTreeMap<(String, Version, Option<String>), BTreeSet<String>>,
) -> stow_types::error::Result<()> {
    let Some(section) = section else {
        return Ok(());
    };
    for (dependency_key, raw_spec) in section {
        let Some(spec) = resolve_dependency_spec(dependency_key, raw_spec, workspace_deps)? else {
            continue;
        };
        if spec.optional
            && !feature_config
                .enabled_optional_deps
                .contains(dependency_key)
        {
            continue;
        }
        let Some(version_req) = spec.version.as_deref() else {
            continue;
        };
        let package = resolve_lockfile_package(
            &spec.crate_name,
            version_req,
            member_lock_package,
            lock_packages,
        )?;
        if !package_is_crates_io(package) {
            continue;
        }
        let mut features = BTreeSet::<String>::new();
        if spec.default_features {
            features.insert("default".to_owned());
        }
        features.extend(spec.features);
        if let Some(extra_features) = feature_config.dependency_features.get(dependency_key) {
            features.extend(extra_features.iter().cloned());
        }
        merged_dependencies
            .entry((
                spec.crate_name,
                package.version.clone(),
                package.source.as_ref().map(ToString::to_string),
            ))
            .or_default()
            .extend(features);
    }
    Ok(())
}

fn resolve_dependency_spec(
    dependency_key: &str,
    raw_spec: &DependencySpec,
    workspace_deps: Option<&BTreeMap<String, DependencySpec>>,
) -> stow_types::error::Result<Option<ResolvedDependencySpec>> {
    let workspace_spec = if raw_spec.workspace() {
        Some(
            workspace_deps
                .and_then(|deps| deps.get(dependency_key))
                .ok_or_else(|| {
                    stow_types::stow_error!(
                        "workspace dependency `{dependency_key}` is missing from [workspace.dependencies]"
                    )
                })?,
        )
    } else {
        None
    };
    let crate_name = raw_spec
        .package()
        .or_else(|| workspace_spec.and_then(|spec| spec.package()))
        .unwrap_or(dependency_key)
        .to_owned();
    let version = raw_spec
        .version()
        .or_else(|| workspace_spec.and_then(|spec| spec.version()))
        .map(str::to_owned);
    let path = raw_spec
        .path()
        .or_else(|| workspace_spec.and_then(|spec| spec.path()));
    let git = raw_spec
        .git()
        .or_else(|| workspace_spec.and_then(|spec| spec.git()));
    let registry = raw_spec
        .registry()
        .or_else(|| workspace_spec.and_then(|spec| spec.registry()));
    let registry_index = raw_spec
        .registry_index()
        .or_else(|| workspace_spec.and_then(|spec| spec.registry_index()));
    if path.is_some() || git.is_some() || registry.is_some() || registry_index.is_some() {
        return Ok(None);
    }

    let mut features = workspace_spec
        .map(DependencySpec::features)
        .unwrap_or_default();
    features.extend(raw_spec.features());

    Ok(Some(ResolvedDependencySpec {
        crate_name,
        version,
        features,
        optional: raw_spec
            .optional()
            .or_else(|| workspace_spec.and_then(DependencySpec::optional))
            .unwrap_or(false),
        default_features: raw_spec
            .default_features()
            .or_else(|| workspace_spec.and_then(DependencySpec::default_features))
            .unwrap_or(true),
    }))
}

fn resolve_lockfile_package<'a>(
    crate_name: &str,
    version_req: &str,
    parent: Option<&cargo_lock::Package>,
    lock_packages: &'a BTreeMap<PackageKey, &cargo_lock::Package>,
) -> stow_types::error::Result<&'a cargo_lock::Package> {
    let version_req = VersionReq::parse(version_req).wrap_err_with(|| {
        format!("parse version requirement `{version_req}` for dependency `{crate_name}`")
    })?;
    // Without a member entry (stow-synthesized lockfiles omit workspace
    // members), resolve by requirement match — but demand uniqueness so a
    // lockfile pinning several compatible versions can never be silently
    // mis-resolved.
    let Some(parent) = parent else {
        let mut matching = lock_packages.iter().filter(|(key, package)| {
            key.crate_name == crate_name
                && version_req.matches(&key.version)
                && package_is_crates_io(package)
        });
        let package = matching.next().map(|(_, package)| *package).ok_or_else(|| {
            stow_types::stow_error!(
                "no lockfile package matched dependency `{crate_name}` requirement `{version_req}`"
            )
        })?;
        if matching.next().is_some() {
            return Err(stow_types::stow_error!(
                "dependency `{crate_name} {version_req}` matches multiple lockfile versions and the                  workspace member entry needed to disambiguate is absent"
            ));
        }
        return Ok(package);
    };
    // Cargo.lock records exactly which version this parent's edge resolved
    // to. Picking `max_by(version)` over all matching packages instead would
    // silently target the wrong artifact whenever the lockfile pins several
    // semver-compatible versions of the same crate.
    let edge = parent
        .dependencies
        .iter()
        .find(|dependency| {
            dependency.name.as_str() == crate_name && version_req.matches(&dependency.version)
        })
        .ok_or_else(|| {
            stow_types::stow_error!(
                "Cargo.lock entry for `{}` has no dependency edge matching `{crate_name} {version_req}`",
                parent.name
            )
        })?;
    if let Some(source) = edge.source.as_ref() {
        let key = PackageKey {
            crate_name: crate_name.to_owned(),
            version: edge.version.clone(),
            source: Some(source.to_string()),
        };
        return lock_packages.get(&key).copied().ok_or_else(|| {
            stow_types::stow_error!(
                "Cargo.lock dependency edge `{crate_name} {}` has no package entry",
                edge.version
            )
        });
    }
    // Lockfiles omit the dependency source when the (name, version) pair is
    // unambiguous; require exactly one package entry in that case.
    let mut matches = lock_packages
        .iter()
        .filter(|(key, _)| key.crate_name == crate_name && key.version == edge.version);
    let package = matches.next().map(|(_, package)| *package).ok_or_else(|| {
        stow_types::stow_error!(
            "Cargo.lock dependency edge `{crate_name} {}` has no package entry",
            edge.version
        )
    })?;
    if matches.next().is_some() {
        return Err(stow_types::stow_error!(
            "Cargo.lock dependency edge `{crate_name} {}` is ambiguous across multiple sources",
            edge.version
        ));
    }
    Ok(package)
}

fn package_is_crates_io(package: &cargo_lock::Package) -> bool {
    package
        .source
        .as_ref()
        .is_some_and(SourceId::is_default_registry)
}

/// The manifests of every workspace member, following cargo's rules: the
/// root package when the root manifest has one, every `[workspace].members`
/// glob match, and every path dependency of a member that lives under the
/// workspace root — minus `[workspace].exclude`. A `[workspace]` table with
/// no `members` key is a single-package workspace, not an error.
fn expand_workspace_members(
    workspace_root: &Path,
    workspace_manifest: &Manifest,
) -> stow_types::error::Result<BTreeSet<PathBuf>> {
    let root_manifest = canonicalize_or_original(&workspace_root.join("Cargo.toml"));
    let Some(workspace) = workspace_manifest.workspace.as_ref() else {
        return Ok(BTreeSet::from([root_manifest]));
    };
    let excluded = workspace
        .exclude
        .iter()
        .flatten()
        .map(|dir| canonicalize_or_original(&workspace_root.join(dir)))
        .collect::<BTreeSet<_>>();
    let is_excluded = |manifest: &Path| {
        manifest
            .parent()
            .is_some_and(|dir| excluded.iter().any(|excluded| dir.starts_with(excluded)))
    };

    let mut pending = VecDeque::<PathBuf>::new();
    if workspace_manifest.package.is_some() {
        pending.push_back(root_manifest);
    }
    for member in workspace.members.iter().flatten() {
        let pattern = workspace_root.join(member).join("Cargo.toml");
        let pattern = pattern.to_str().ok_or_else(|| {
            stow_types::stow_error!(
                "workspace member pattern {} is not UTF-8",
                pattern.display()
            )
        })?;
        let mut matched = false;
        for entry in glob(pattern)
            .wrap_err_with(|| format!("expand workspace member pattern `{pattern}`"))?
        {
            let path =
                entry.wrap_err_with(|| format!("expand workspace member pattern `{pattern}`"))?;
            matched = true;
            pending.push_back(canonicalize_or_original(&path));
        }
        if !matched {
            return Err(stow_types::stow_error!(
                "workspace member pattern `{member}` matched no Cargo.toml files"
            ));
        }
    }

    // Path dependencies under the workspace root are members too, and their
    // own path dependencies in turn, so walk to a fixpoint.
    let workspace_root = canonicalize_or_original(workspace_root);
    let mut members = BTreeSet::<PathBuf>::new();
    while let Some(manifest_path) = pending.pop_front() {
        if is_excluded(&manifest_path) || !members.insert(manifest_path.clone()) {
            continue;
        }
        let manifest = load_manifest(&manifest_path)?;
        let member_dir = manifest_path.parent().ok_or_else(|| {
            stow_types::stow_error!(
                "workspace member manifest {} has no parent directory",
                manifest_path.display()
            )
        })?;
        for path in manifest.path_dependencies() {
            let dependency_manifest =
                canonicalize_or_original(&member_dir.join(path).join("Cargo.toml"));
            if dependency_manifest.starts_with(&workspace_root) {
                pending.push_back(dependency_manifest);
            }
        }
    }
    Ok(members)
}

/// Returns the names of optional dependencies that the manifest's feature
/// graph activates under the given metadata args (default features unless
/// `--no-default-features` is set, plus any explicit `--features`).
///
/// This mirrors what cargo's resolver does when populating `Cargo.lock`:
/// optional deps gated by an inactive feature get no lockfile pin; ones
/// transitively enabled by `default` (e.g., bat's `default → application
/// → bugreport`) DO get pinned. The CLI's user-direct collection uses
/// this to only ship enabled-optional deps to the resolver — sending
/// every declared optional would block seed search on perfectly-cached
/// projects whose preheat closure intentionally skipped feature-disabled
/// optionals.
pub fn enabled_optional_dependency_names(
    manifest_path: &Path,
    args: &crate::cargo_cmd::MetadataArgs,
) -> stow_types::error::Result<BTreeSet<String>> {
    let manifest = load_manifest(manifest_path)?;
    let package_name = manifest
        .package
        .as_ref()
        .map(|package| package.name.clone())
        .unwrap_or_default();
    let feature_config = FeatureConfig::new(&manifest, &package_name, args);
    Ok(feature_config.enabled_optional_deps)
}

fn load_manifest(path: &Path) -> stow_types::error::Result<Manifest> {
    let contents = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("read Cargo.toml {}", path.display()))?;
    toml::from_str::<Manifest>(&contents)
        .wrap_err_with(|| format!("parse Cargo.toml {}", path.display()))
}

fn canonicalize_or_original(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

async fn cargo_metadata(
    workspace_root: &Path,
    manifest_path: &Path,
    args: &MetadataArgs,
    target: &str,
) -> stow_types::error::Result<Metadata> {
    let mut command = Command::new("cargo");
    command
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        // No `--locked`: a stow-mirror lockfile is the resolver's runtime
        // closure (no dev/build/optional pins), so `--locked` would error
        // on every absent entry. Without it, cargo augments from the
        // local index for whatever the resolver couldn't cover.
        //
        // `--offline` is non-negotiable: dropping it causes `cargo
        // metadata` to refresh the crates.io index on each invocation —
        // a multi-second blocking call that turns small projects (clap
        // ~1s vanilla) into 20-second stow runs and explodes the
        // no-slowdown budget. The local registry cache populated by any
        // prior `cargo` run is enough to resolve absent pins; if it's
        // missing entries entirely, this returns an error and the outer
        // pipeline falls back to vanilla cargo passthrough.
        .arg("--offline")
        .arg("--filter-platform")
        .arg(target)
        .arg("--manifest-path")
        .arg(manifest_path)
        .current_dir(workspace_root);
    if args.all_features {
        command.arg("--all-features");
    } else {
        if args.no_default_features {
            command.arg("--no-default-features");
        }
        if !args.features.is_empty() {
            command.arg("--features").arg(args.features.join(","));
        }
    }

    let output = command.output().await?;
    if !output.status.success() {
        return Err(stow_types::stow_error!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    serde_json::from_slice::<Metadata>(&output.stdout).wrap_err("parse cargo metadata JSON")
}

fn selected_package_ids(
    metadata: &Metadata,
    manifest_path: &Path,
) -> stow_types::error::Result<BTreeSet<PackageId>> {
    let selected_manifest = canonicalize_or_original(manifest_path);
    let workspace_root_manifest =
        canonicalize_or_original(&metadata.workspace_root.as_std_path().join("Cargo.toml"));
    if selected_manifest == workspace_root_manifest {
        return Ok(metadata.workspace_members.iter().cloned().collect());
    }

    let selected = metadata
        .packages
        .iter()
        .find(|package| {
            canonicalize_or_original(package.manifest_path.as_std_path()) == selected_manifest
        })
        .ok_or_else(|| {
            stow_types::stow_error!(
                "cargo metadata does not include selected manifest {}",
                selected_manifest.display()
            )
        })?;
    Ok(BTreeSet::from([selected.id.clone()]))
}

fn is_registry_package(package: &cargo_metadata::Package) -> bool {
    package
        .source
        .as_ref()
        .is_some_and(|source| source.to_string().starts_with("registry+"))
}

#[derive(Debug, Clone, Default)]
struct FeatureConfig {
    enabled_optional_deps: BTreeSet<String>,
    dependency_features: BTreeMap<String, BTreeSet<String>>,
}

impl FeatureConfig {
    fn new(manifest: &Manifest, package_name: &str, args: &MetadataArgs) -> Self {
        let feature_map = manifest.features.clone().unwrap_or_default();
        let dependency_names = manifest
            .dependencies
            .iter()
            .chain(manifest.build_dependencies.iter())
            .chain(manifest.dev_dependencies.iter())
            .flat_map(|deps| deps.keys().cloned())
            .collect::<BTreeSet<_>>();
        let mut activated_features = BTreeSet::<String>::new();
        let mut queue = VecDeque::<String>::new();
        let mut enabled_optional_deps = BTreeSet::<String>::new();
        let mut dependency_features = BTreeMap::<String, BTreeSet<String>>::new();

        if args.all_features {
            for feature in feature_map.keys() {
                if activated_features.insert(feature.clone()) {
                    queue.push_back(feature.clone());
                }
            }
        } else {
            if !args.no_default_features
                && let Some(default_items) = feature_map.get("default")
            {
                for item in default_items {
                    apply_feature_item(
                        item,
                        &feature_map,
                        &dependency_names,
                        &mut activated_features,
                        &mut queue,
                        &mut enabled_optional_deps,
                        &mut dependency_features,
                    );
                }
            }
            for raw_feature in args.features.iter().map(String::as_str) {
                if let Some((feature_package, feature_name)) = raw_feature.split_once('/') {
                    if feature_package != package_name {
                        continue;
                    }
                    let feature_name = feature_name.to_owned();
                    if activated_features.insert(feature_name.clone()) {
                        queue.push_back(feature_name);
                    }
                    continue;
                }
                let raw_feature = raw_feature.to_owned();
                if activated_features.insert(raw_feature.clone()) {
                    queue.push_back(raw_feature);
                }
            }
        }

        while let Some(feature) = queue.pop_front() {
            let Some(items) = feature_map.get(&feature) else {
                if dependency_names.contains(&feature) {
                    enabled_optional_deps.insert(feature);
                }
                continue;
            };
            for item in items {
                apply_feature_item(
                    item,
                    &feature_map,
                    &dependency_names,
                    &mut activated_features,
                    &mut queue,
                    &mut enabled_optional_deps,
                    &mut dependency_features,
                );
            }
        }

        Self {
            enabled_optional_deps,
            dependency_features,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_feature_item(
    item: &str,
    feature_map: &BTreeMap<String, Vec<String>>,
    dependency_names: &BTreeSet<String>,
    activated_features: &mut BTreeSet<String>,
    queue: &mut VecDeque<String>,
    enabled_optional_deps: &mut BTreeSet<String>,
    dependency_features: &mut BTreeMap<String, BTreeSet<String>>,
) {
    if let Some(dep_name) = item.strip_prefix("dep:") {
        enabled_optional_deps.insert(dep_name.to_owned());
        return;
    }
    if let Some((dependency_name, dependency_feature)) = item.split_once('/') {
        let conditional = dependency_name.ends_with('?');
        let dependency_name = dependency_name.trim_end_matches('?');
        if conditional && !enabled_optional_deps.contains(dependency_name) {
            return;
        }
        enabled_optional_deps.insert(dependency_name.to_owned());
        dependency_features
            .entry(dependency_name.to_owned())
            .or_default()
            .insert(dependency_feature.to_owned());
        return;
    }
    if feature_map.contains_key(item) {
        if activated_features.insert(item.to_owned()) {
            queue.push_back(item.to_owned());
        }
        return;
    }
    if dependency_names.contains(item) {
        enabled_optional_deps.insert(item.to_owned());
    }
}

#[derive(Debug, Clone)]
struct ResolvedDependencySpec {
    crate_name: String,
    version: Option<String>,
    features: BTreeSet<String>,
    optional: bool,
    default_features: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct Manifest {
    package: Option<PackageSection>,
    workspace: Option<WorkspaceSection>,
    features: Option<BTreeMap<String, Vec<String>>>,
    dependencies: Option<BTreeMap<String, DependencySpec>>,
    #[serde(rename = "build-dependencies")]
    build_dependencies: Option<BTreeMap<String, DependencySpec>>,
    #[serde(rename = "dev-dependencies")]
    dev_dependencies: Option<BTreeMap<String, DependencySpec>>,
}

#[derive(Debug, Clone, Deserialize)]
struct PackageSection {
    name: String,
    version: Option<InheritableString>,
}

/// A `[package]` field that may either carry a literal value or be inherited
/// from the workspace root with `version.workspace = true` — workspace
/// inheritance, stable since Rust 1.64 and used by most modern workspaces.
/// Declaring the field as a plain `String` made every such manifest fail to
/// parse, which aborted the whole command.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum InheritableString {
    Value(String),
    Inherited(WorkspaceInherited),
}

#[derive(Debug, Clone, Deserialize)]
struct WorkspaceInherited {
    workspace: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct WorkspaceSection {
    members: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    dependencies: Option<BTreeMap<String, DependencySpec>>,
    package: Option<WorkspacePackageSection>,
}

#[derive(Debug, Clone, Deserialize)]
struct WorkspacePackageSection {
    version: Option<String>,
}

impl Manifest {
    /// The `path` of every path dependency in this manifest's normal, build
    /// and dev dependency tables, relative to the manifest's directory.
    fn path_dependencies(&self) -> impl Iterator<Item = &str> {
        [
            self.dependencies.as_ref(),
            self.build_dependencies.as_ref(),
            self.dev_dependencies.as_ref(),
        ]
        .into_iter()
        .flatten()
        .flat_map(BTreeMap::values)
        .filter_map(DependencySpec::path)
    }

    /// This manifest's package version, resolving `version.workspace = true`
    /// against the workspace root's `[workspace.package]`.
    fn package_version<'a>(&'a self, workspace_manifest: &'a Self) -> Option<&'a str> {
        match self.package.as_ref()?.version.as_ref()? {
            InheritableString::Value(version) => Some(version.as_str()),
            InheritableString::Inherited(inherited) => {
                if !inherited.workspace {
                    return None;
                }
                workspace_manifest
                    .workspace
                    .as_ref()?
                    .package
                    .as_ref()?
                    .version
                    .as_deref()
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum DependencySpec {
    Simple(String),
    Detailed(DetailedDependencySpec),
}

impl DependencySpec {
    fn version(&self) -> Option<&str> {
        match self {
            Self::Simple(version) => Some(version.as_str()),
            Self::Detailed(spec) => spec.version.as_deref(),
        }
    }

    fn features(&self) -> BTreeSet<String> {
        match self {
            Self::Simple(_) => BTreeSet::new(),
            Self::Detailed(spec) => spec.features.iter().cloned().collect(),
        }
    }

    const fn optional(&self) -> Option<bool> {
        match self {
            Self::Simple(_) => None,
            Self::Detailed(spec) => spec.optional,
        }
    }

    const fn default_features(&self) -> Option<bool> {
        match self {
            Self::Simple(_) => None,
            Self::Detailed(spec) => spec.default_features,
        }
    }

    const fn workspace(&self) -> bool {
        match self {
            Self::Simple(_) => false,
            Self::Detailed(spec) => spec.workspace,
        }
    }

    fn package(&self) -> Option<&str> {
        match self {
            Self::Simple(_) => None,
            Self::Detailed(spec) => spec.package.as_deref(),
        }
    }

    fn path(&self) -> Option<&str> {
        match self {
            Self::Simple(_) => None,
            Self::Detailed(spec) => spec.path.as_deref(),
        }
    }

    fn git(&self) -> Option<&str> {
        match self {
            Self::Simple(_) => None,
            Self::Detailed(spec) => spec.git.as_deref(),
        }
    }

    fn registry(&self) -> Option<&str> {
        match self {
            Self::Simple(_) => None,
            Self::Detailed(spec) => spec.registry.as_deref(),
        }
    }

    fn registry_index(&self) -> Option<&str> {
        match self {
            Self::Simple(_) => None,
            Self::Detailed(spec) => spec.registry_index.as_deref(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct DetailedDependencySpec {
    version: Option<String>,
    #[serde(default)]
    features: Vec<String>,
    optional: Option<bool>,
    #[serde(rename = "default-features")]
    default_features: Option<bool>,
    #[serde(default)]
    workspace: bool,
    package: Option<String>,
    path: Option<String>,
    git: Option<String>,
    registry: Option<String>,
    #[serde(rename = "registry-index")]
    registry_index: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::feature_entry_enables_dependency;

    #[test]
    fn weak_dependency_feature_does_not_enable_optional_dependency() {
        assert!(!feature_entry_enables_dependency(
            "quinn?/rustls-aws-lc-rs",
            "quinn"
        ));
    }

    #[test]
    fn dependency_feature_and_dep_entry_enable_optional_dependency() {
        assert!(feature_entry_enables_dependency("dep:quinn", "quinn"));
        assert!(feature_entry_enables_dependency(
            "quinn/runtime-tokio",
            "quinn"
        ));
    }
}

#[cfg(test)]
mod workspace_inheritance_tests {
    use super::Manifest;

    fn parse(contents: &str) -> Manifest {
        toml::from_str::<Manifest>(contents).expect("parse manifest")
    }

    #[test]
    fn package_version_reads_a_literal_value() {
        let manifest = parse("[package]\nname = \"demo\"\nversion = \"1.2.3\"\n");
        assert_eq!(manifest.package_version(&manifest), Some("1.2.3"));
    }

    #[test]
    fn package_version_is_inherited_from_the_workspace_root() {
        // `version.workspace = true` is a table, not a string. Declaring the
        // field as `Option<String>` made this manifest fail to parse outright.
        let member = parse("[package]\nname = \"demo\"\nversion.workspace = true\n");
        let root = parse(
            "[workspace]\nmembers = [\"demo\"]\n\n[workspace.package]\nversion = \"4.5.6\"\n",
        );
        assert_eq!(member.package_version(&root), Some("4.5.6"));
    }

    #[test]
    fn a_root_package_can_inherit_from_its_own_workspace_table() {
        let manifest = parse(
            "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.package]\nversion = \"0.9.0\"\n\n\
             [package]\nname = \"demo\"\nversion.workspace = true\n",
        );
        assert_eq!(manifest.package_version(&manifest), Some("0.9.0"));
    }

    #[test]
    fn inheritance_without_a_workspace_package_version_is_absent_not_an_error() {
        let member = parse("[package]\nname = \"demo\"\nversion.workspace = true\n");
        let root = parse("[workspace]\nmembers = [\"demo\"]\n");
        assert_eq!(member.package_version(&root), None);
    }
}

#[cfg(test)]
mod workspace_member_tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use super::{Manifest, expand_workspace_members};

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("manifest parent")).expect("create dir");
        std::fs::write(path, contents).expect("write manifest");
    }

    fn members(root: &Path) -> BTreeSet<PathBuf> {
        let manifest = toml::from_str::<Manifest>(
            &std::fs::read_to_string(root.join("Cargo.toml")).expect("read root manifest"),
        )
        .expect("parse root manifest");
        expand_workspace_members(root, &manifest)
            .expect("expand members")
            .into_iter()
            .map(|path| {
                path.strip_prefix(std::fs::canonicalize(root).expect("canonical root"))
                    .expect("member under root")
                    .to_path_buf()
            })
            .collect()
    }

    fn paths(parts: &[&str]) -> BTreeSet<PathBuf> {
        parts.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn a_workspace_table_without_members_is_the_root_package_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            dir.path(),
            "Cargo.toml",
            "[workspace]\nresolver = \"2\"\n\n[package]\nname = \"solo\"\nversion = \"0.1.0\"\n",
        );
        assert_eq!(members(dir.path()), paths(&["Cargo.toml"]));
    }

    #[test]
    fn the_root_package_joins_its_listed_members() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            dir.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\"tools/*\"]\n\n[package]\nname = \"root\"\nversion = \"0.1.0\"\n",
        );
        write(
            dir.path(),
            "tools/a/Cargo.toml",
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
        );
        assert_eq!(
            members(dir.path()),
            paths(&["Cargo.toml", "tools/a/Cargo.toml"])
        );
    }

    #[test]
    fn path_dependencies_under_the_root_are_members_and_excludes_are_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            dir.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\"]\nexclude = [\"vendored\"]\n",
        );
        write(
            dir.path(),
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nderive = { path = \"../derive\" }\nvendored = { path = \"../vendored\" }\n",
        );
        write(
            dir.path(),
            "derive/Cargo.toml",
            "[package]\nname = \"derive\"\nversion = \"0.1.0\"\n\n[build-dependencies]\nhelper = { path = \"../helper\" }\n",
        );
        write(
            dir.path(),
            "helper/Cargo.toml",
            "[package]\nname = \"helper\"\nversion = \"0.1.0\"\n",
        );
        write(
            dir.path(),
            "vendored/Cargo.toml",
            "[package]\nname = \"vendored\"\nversion = \"0.1.0\"\n",
        );
        assert_eq!(
            members(dir.path()),
            paths(&["app/Cargo.toml", "derive/Cargo.toml", "helper/Cargo.toml"])
        );
    }
}

#[cfg(test)]
mod observed_miss_tests {
    use std::collections::BTreeMap;

    use super::{ObservedMissGraph, observed_miss_graph};
    use crate::artifact_cache::{DependencyCMetadataIdentity, ObservedDepIdentity, ObservedUnit};

    const HOST: &str = "x86_64-unknown-linux-gnu";

    fn observation(
        crate_name: &str,
        version: &str,
        target: &str,
        features: &[&str],
        externs: &[(&str, &str)],
    ) -> ObservedUnit {
        // `observed_miss_graph` reads the recorded compile triple, not
        // the flag; tests that exercise the drain set it themselves.
        ObservedUnit {
            crate_name: crate_name.to_owned(),
            crate_version: version.to_owned(),
            features: features
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect(),
            target: target.to_owned(),
            explicit_target: None,
            externs: externs
                .iter()
                .map(|(name, c_metadata)| DependencyCMetadataIdentity {
                    crate_name: (*name).to_owned(),
                    c_metadata: (*c_metadata).to_owned(),
                })
                .collect(),
        }
    }

    fn dep_identities(
        deps: &[(&str, &str, &str, &[&str], &str)],
    ) -> BTreeMap<String, ObservedDepIdentity> {
        deps.iter()
            .map(|(c_metadata, name, version, features, target)| {
                (
                    (*c_metadata).to_owned(),
                    ObservedDepIdentity {
                        crate_name: (*name).to_owned(),
                        crate_version: (*version).to_owned(),
                        features: features
                            .iter()
                            .map(|feature| (*feature).to_owned())
                            .collect(),
                        target: (*target).to_owned(),
                    },
                )
            })
            .collect()
    }

    fn node<'a>(
        graph: &'a ObservedMissGraph,
        crate_name: &str,
        host_side: bool,
    ) -> &'a stow_types::api::ResolvedDependencyGraphEntry {
        graph
            .expanded
            .iter()
            .find(|entry| entry.crate_name.as_str() == crate_name && entry.host_side == host_side)
            .unwrap_or_else(|| panic!("node {crate_name} host_side={host_side} exists"))
    }

    /// A native build: the consumer's target IS the family host triple,
    /// so every observed unit is target-side, and each `depends_on` names
    /// the dep's own recorded identity.
    #[test]
    fn native_build_mints_target_side_nodes_with_dep_edges() {
        let observations = vec![
            observation(
                "app",
                "1.0.0",
                HOST,
                &["full"],
                &[("serde", "aaaa0000aaaa0000")],
            ),
            observation("serde", "1.0.228", HOST, &["derive"], &[]),
        ];
        let dep_identities =
            dep_identities(&[("aaaa0000aaaa0000", "serde", "1.0.228", &["derive"], HOST)]);
        let graph = observed_miss_graph(&observations, &dep_identities, HOST, HOST);

        let app = node(&graph, "app", false);
        assert_eq!(app.features, vec!["full"]);
        assert_eq!(app.dependencies.len(), 1);
        assert_eq!(app.dependencies[0].crate_name.as_str(), "serde");
        assert!(!app.dependencies[0].host_side);
        assert_eq!(graph.roots.len(), 2);
    }

    /// A `--target wasm32` cross build: a unit recorded at the build
    /// host's triple is a host-side node, and the dependent's edge into
    /// it names the same side. The build host is what classifies — a
    /// build running on a host outside the CI family (say aarch64-linux
    /// for an aarch64-darwin family host) still reads host compiles
    /// correctly.
    #[test]
    fn cross_build_classifies_against_the_probed_build_host() {
        // An aarch64-linux machine building wasm32: the proc-macro
        // compiled at aarch64-linux, which is not the x86_64-linux
        // family host the minted node will land at — classifying
        // against the family host would mint it consumer-side.
        let build_host = "aarch64-unknown-linux-gnu";
        let mut serde = observation(
            "serde",
            "1.0.228",
            "wasm32-unknown-unknown",
            &["derive"],
            &[("serde_derive", "bbbb0000bbbb0000")],
        );
        serde.explicit_target = Some("wasm32-unknown-unknown".to_owned());
        let observations = vec![
            serde,
            observation("serde_derive", "1.0.228", build_host, &[], &[]),
        ];
        let dep_identities = dep_identities(&[(
            "bbbb0000bbbb0000",
            "serde_derive",
            "1.0.228",
            &[],
            build_host,
        )]);
        let graph = observed_miss_graph(
            &observations,
            &dep_identities,
            "wasm32-unknown-unknown",
            build_host,
        );

        let serde = node(&graph, "serde", false);
        assert_eq!(serde.dependencies[0].crate_name.as_str(), "serde_derive");
        assert!(serde.dependencies[0].host_side);
        node(&graph, "serde_derive", true);
        assert_eq!(graph.roots.len(), 2);
    }

    /// A `--target wasm32` cross build: a unit recorded at the family
    /// host triple is a host-side node, and the dependent's edge into it
    /// names the same side.
    #[test]
    fn cross_build_mints_host_side_nodes() {
        let mut serde = observation(
            "serde",
            "1.0.228",
            "wasm32-unknown-unknown",
            &["derive"],
            &[("serde_derive", "bbbb0000bbbb0000")],
        );
        serde.explicit_target = Some("wasm32-unknown-unknown".to_owned());
        let observations = vec![
            serde,
            observation("serde_derive", "1.0.228", HOST, &[], &[]),
        ];
        let dep_identities =
            dep_identities(&[("bbbb0000bbbb0000", "serde_derive", "1.0.228", &[], HOST)]);
        let graph = observed_miss_graph(
            &observations,
            &dep_identities,
            "wasm32-unknown-unknown",
            HOST,
        );

        let serde = node(&graph, "serde", false);
        assert_eq!(serde.dependencies[0].crate_name.as_str(), "serde_derive");
        assert!(serde.dependencies[0].host_side);
        node(&graph, "serde_derive", true);
        assert_eq!(graph.roots.len(), 2);
    }

    /// A served dep joins as a leaf node at its recorded identity so the
    /// observed unit's edge resolves to a node.
    #[test]
    fn served_dep_joins_as_a_leaf_node() {
        let observations = vec![observation(
            "app",
            "1.0.0",
            HOST,
            &[],
            &[("serde", "aaaa0000aaaa0000")],
        )];
        let dep_identities =
            dep_identities(&[("aaaa0000aaaa0000", "serde", "1.0.228", &["std"], HOST)]);
        let graph = observed_miss_graph(&observations, &dep_identities, HOST, HOST);

        let serde = node(&graph, "serde", false);
        assert_eq!(serde.features, vec!["std"]);
        assert!(serde.dependencies.is_empty());
        // The dep was served, not compiled — it is not a miss root.
        assert_eq!(graph.roots.len(), 1);
        assert_eq!(graph.roots[0].crate_name.as_str(), "app");
    }

    /// A unit skipped for an unresolvable `--extern` does not leave
    /// leaf nodes behind for the deps it did resolve.
    #[test]
    fn a_skipped_unit_mints_no_orphan_leaf_nodes() {
        let observations = vec![observation(
            "app",
            "1.0.0",
            HOST,
            &[],
            &[("serde", "aaaa0000aaaa0000"), ("lost", "ffff0000ffff0000")],
        )];
        // `serde` resolves; `lost` does not — the unit is skipped, and
        // the resolved dep joins nothing.
        let dep_identities =
            dep_identities(&[("aaaa0000aaaa0000", "serde", "1.0.228", &["std"], HOST)]);
        let graph = observed_miss_graph(&observations, &dep_identities, HOST, HOST);

        assert!(graph.roots.is_empty());
        assert!(graph.expanded.is_empty());
    }

    /// A unit whose `--extern` does not resolve to a recorded identity is
    /// not minted — no fabricated empty edge set.
    #[test]
    fn unresolvable_extern_skips_the_unit() {
        let observations = vec![
            observation("app", "1.0.0", HOST, &[], &[("serde", "ffff0000ffff0000")]),
            observation("serde", "1.0.228", HOST, &["derive"], &[]),
        ];
        let dep_identities = dep_identities(&[]);
        let graph = observed_miss_graph(&observations, &dep_identities, HOST, HOST);

        assert_eq!(graph.expanded.len(), 1);
        assert_eq!(graph.expanded[0].crate_name.as_str(), "serde");
        assert_eq!(graph.roots.len(), 1);
        assert_eq!(graph.roots[0].crate_name.as_str(), "serde");
    }
}
