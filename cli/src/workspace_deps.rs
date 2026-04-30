use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use async_process::Command;
use cargo_lock::{Lockfile, package::SourceId};
use cargo_metadata::{Dependency, DependencyKind, Metadata, Package, PackageId};
use glob::glob;
use semver::{Version, VersionReq};
use serde::Deserialize;
use stow_types::api::{ResolvedDependencyGraphDependency, ResolvedDependencyGraphEntry};
use stow_types::error::Context;

use crate::cargo_cmd::MetadataArgs;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DirectDependency {
    pub(crate) crate_name: String,
    pub(crate) version: Version,
    pub(crate) source: Option<String>,
    pub(crate) features: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SelectedRegistryDependency {
    pub(crate) extern_name: String,
    pub(crate) crate_name: String,
    pub(crate) version: Version,
    pub(crate) features: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PackageKey {
    pub(crate) crate_name: String,
    pub(crate) version: Version,
    pub(crate) source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LockfileGraph {
    pub(crate) direct_dependencies: Vec<DirectDependency>,
    pub(crate) workspace_packages: BTreeSet<PackageKey>,
    pub(crate) parents_by_package: BTreeMap<PackageKey, Vec<PackageKey>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceLayout {
    pub(crate) workspace_root: PathBuf,
    pub(crate) manifest_path: PathBuf,
}

pub(crate) fn resolve_workspace_layout(
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

pub(crate) fn resolve_lockfile_graph(
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
        let version = package.version.as_deref().ok_or_else(|| {
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
        let feature_config = FeatureConfig::new(&member_manifest, &member_package.name, args);
        collect_dependency_section(
            member_manifest.dependencies.as_ref(),
            workspace_deps,
            &feature_config,
            &lock_packages,
            &mut merged_dependencies,
        )?;
        collect_dependency_section(
            member_manifest.build_dependencies.as_ref(),
            workspace_deps,
            &feature_config,
            &lock_packages,
            &mut merged_dependencies,
        )?;
        collect_dependency_section(
            member_manifest.dev_dependencies.as_ref(),
            workspace_deps,
            &feature_config,
            &lock_packages,
            &mut merged_dependencies,
        )?;
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

pub(crate) async fn resolve_exact_dependency_graph(
    workspace_root: &Path,
    manifest_path: &Path,
    args: &MetadataArgs,
    target: &str,
) -> stow_types::error::Result<Vec<ResolvedDependencyGraphEntry>> {
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

    let mut visited = BTreeSet::<PackageId>::new();
    let mut queue = VecDeque::<PackageId>::from_iter(selected_package_ids);
    let mut entries = BTreeMap::<(String, Version), ResolvedDependencyGraphEntry>::new();

    while let Some(package_id) = queue.pop_front() {
        if !visited.insert(package_id.clone()) {
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
            queue.push_back(dependency.pkg.clone());
        }

        if !is_registry_package(package) {
            continue;
        }

        let mut features = node.features.clone();
        features.sort();
        features.dedup();

        let mut dependencies = node
            .deps
            .iter()
            .filter_map(|dependency| {
                let dependency_package = package_by_id.get(&dependency.pkg)?;
                if !is_registry_package(dependency_package) {
                    return None;
                }
                Some(ResolvedDependencyGraphDependency {
                    crate_name: dependency_package.name.to_owned(),
                    version: dependency_package.version.clone(),
                })
            })
            .collect::<Vec<_>>();
        dependencies.sort_by(|left, right| {
            left.crate_name
                .cmp(&right.crate_name)
                .then(left.version.cmp(&right.version))
        });
        dependencies.dedup();

        entries.insert(
            (package.name.to_owned(), package.version.clone()),
            ResolvedDependencyGraphEntry {
                crate_name: package.name.to_owned(),
                version: package.version.clone(),
                features,
                dependencies,
            },
        );
    }

    Ok(entries.into_values().collect())
}

pub(crate) async fn resolve_selected_registry_dependencies(
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
            dependencies.insert(SelectedRegistryDependency {
                extern_name: dependency.name.replace('-', "_"),
                crate_name: dependency_package.name.to_owned(),
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
    enabled_features: &[String],
    dependency_name: &str,
) -> bool {
    if enabled_features
        .iter()
        .any(|feature| feature == dependency_name)
    {
        return true;
    }

    let mut pending = enabled_features.to_vec();
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

fn dependency_kind_is_top_crate_extern(
    kind: DependencyKind,
    include_dev_dependencies: bool,
) -> bool {
    match kind {
        DependencyKind::Normal => true,
        DependencyKind::Development => include_dev_dependencies,
        DependencyKind::Build => false,
        DependencyKind::Unknown => false,
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
        let package = resolve_lockfile_package(&spec.crate_name, version_req, lock_packages)?;
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
            .or_else(|| workspace_spec.and_then(|spec| spec.optional()))
            .unwrap_or(false),
        default_features: raw_spec
            .default_features()
            .or_else(|| workspace_spec.and_then(|spec| spec.default_features()))
            .unwrap_or(true),
    }))
}

fn resolve_lockfile_package<'a>(
    crate_name: &str,
    version_req: &str,
    lock_packages: &'a BTreeMap<PackageKey, &cargo_lock::Package>,
) -> stow_types::error::Result<&'a cargo_lock::Package> {
    let version_req = VersionReq::parse(version_req).wrap_err_with(|| {
        format!("parse version requirement `{version_req}` for dependency `{crate_name}`")
    })?;
    lock_packages
        .iter()
        .filter(|(key, package)| {
            key.crate_name == crate_name
                && version_req.matches(&key.version)
                && package_is_crates_io(package)
        })
        .max_by(|(left_key, _), (right_key, _)| left_key.version.cmp(&right_key.version))
        .map(|(_, package)| *package)
        .ok_or_else(|| {
            stow_types::stow_error!(
                "no lockfile package matched dependency `{crate_name}` requirement `{version_req}`"
            )
        })
}

fn package_is_crates_io(package: &cargo_lock::Package) -> bool {
    package
        .source
        .as_ref()
        .is_some_and(SourceId::is_default_registry)
}

fn expand_workspace_members(
    workspace_root: &Path,
    workspace_manifest: &Manifest,
) -> stow_types::error::Result<BTreeSet<PathBuf>> {
    let Some(workspace) = workspace_manifest.workspace.as_ref() else {
        return Ok(BTreeSet::from([canonicalize_or_original(
            &workspace_root.join("Cargo.toml"),
        )]));
    };
    let members = workspace.members.as_ref().ok_or_else(|| {
        stow_types::stow_error!(
            "workspace manifest {} is missing [workspace].members",
            workspace_root.join("Cargo.toml").display()
        )
    })?;
    let mut paths = BTreeSet::<PathBuf>::new();
    for member in members {
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
            paths.insert(canonicalize_or_original(&path));
        }
        if !matched {
            return Err(stow_types::stow_error!(
                "workspace member pattern `{member}` matched no Cargo.toml files"
            ));
        }
    }
    Ok(paths)
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
        .arg("--locked")
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
    version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct WorkspaceSection {
    members: Option<Vec<String>>,
    dependencies: Option<BTreeMap<String, DependencySpec>>,
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

    fn optional(&self) -> Option<bool> {
        match self {
            Self::Simple(_) => None,
            Self::Detailed(spec) => spec.optional,
        }
    }

    fn default_features(&self) -> Option<bool> {
        match self {
            Self::Simple(_) => None,
            Self::Detailed(spec) => spec.default_features,
        }
    }

    fn workspace(&self) -> bool {
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
