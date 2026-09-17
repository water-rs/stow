//! The set of crates a task is allowed to publish artifacts for.
//!
//! The build job runs third-party build scripts and proc-macros, so nothing
//! it hands over can be trusted to describe which crates it compiled. The
//! publisher resolves the task crate's dependency graph itself, from a fresh
//! crates.io download it alone touched, with `cargo metadata` — which reads
//! manifests and the index but never executes crate code — and refuses any
//! planned artifact whose crate is not in that graph.
//!
//! The graph is the set of crates `cargo build` of the task crate compiles on
//! the task's platform: normal and build dependencies reachable from the task
//! crate, filtered to the task target. Dev-dependencies and dependencies of
//! other platforms are in `cargo metadata`'s full resolve but never compiled
//! by the trusted pipeline, so an artifact claiming one of them is a
//! fabrication and is rejected.

use std::collections::{BTreeMap, BTreeSet};

use async_process::Command;
use cargo_metadata::{DependencyKind, Metadata, PackageId, Resolve};
use stow_types::api::BuildTaskPayload;
use stow_types::error::Context;
use tempfile::TempDir;

use crate::task::{self, CargoFeatureArgs};

/// `(crate name, version)` pairs the task may publish.
#[derive(Debug)]
pub struct DependencyClosure {
    packages: BTreeSet<(String, semver::Version)>,
}

impl DependencyClosure {
    #[must_use]
    pub fn contains(&self, crate_name: &str, version: &semver::Version) -> bool {
        self.packages
            .contains(&(crate_name.to_owned(), version.clone()))
    }

    #[must_use]
    pub fn package_count(&self) -> usize {
        self.packages.len()
    }

    #[cfg(test)]
    pub(crate) const fn from_packages(packages: BTreeSet<(String, semver::Version)>) -> Self {
        Self { packages }
    }
}

/// Resolve the closure for `task` exactly the way the build job did — same
/// toolchain, same feature set, same lockfile policy — but from a pristine
/// source tree.
pub async fn resolve(task: &BuildTaskPayload) -> stow_types::error::Result<DependencyClosure> {
    let root = TempDir::new().wrap_err("create closure resolution workspace")?;
    let manifest_path = task::download_crate_manifest(task, root.path()).await?;
    let source_root = manifest_path.parent().ok_or_else(|| {
        stow_types::stow_error!(
            "crate manifest {} has no parent directory",
            manifest_path.display()
        )
    })?;
    if !task.preserve_lockfile {
        task::remove_bundled_lockfile(source_root)?;
    }

    let mut command = Command::new("cargo");
    command
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .arg("--filter-platform")
        .arg(task.target.as_str())
        .env("RUSTUP_TOOLCHAIN", task.rustc_version.as_str());
    if task.preserve_lockfile {
        command.arg("--locked");
    }
    CargoFeatureArgs::from_task(task).apply(&mut command);
    let output = command
        .output()
        .await
        .wrap_err("run cargo metadata for closure resolution")?;
    if !output.status.success() {
        return Err(stow_types::stow_error!(
            "cargo metadata failed while resolving the closure of {} {}: {}",
            task.crate_name,
            task.version,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let metadata: Metadata =
        serde_json::from_slice(&output.stdout).wrap_err("parse cargo metadata output")?;
    let resolve = metadata.resolve.ok_or_else(|| {
        stow_types::stow_error!(
            "cargo metadata returned no resolve graph for {}",
            task.crate_name
        )
    })?;

    let compiled_ids = compiled_packages(&resolve, task)?;
    let packages = metadata
        .packages
        .into_iter()
        .filter(|package| compiled_ids.contains(&package.id))
        .map(|package| (package.name.clone(), package.version))
        .collect::<BTreeSet<_>>();
    if !packages.contains(&(
        task.crate_name.as_str().to_owned(),
        task.version.as_semver().clone(),
    )) {
        return Err(stow_types::stow_error!(
            "resolved closure does not contain the task crate {} {}",
            task.crate_name,
            task.version
        ));
    }
    tracing::info!(
        crate_name = %task.crate_name,
        version = %task.version,
        packages = packages.len(),
        "resolved publishable dependency closure"
    );
    Ok(DependencyClosure { packages })
}

/// Packages `cargo build` of the task crate compiles: everything reachable
/// from the resolve root over normal and build edges. Development edges are
/// never followed, not even from the root, because the trusted pipeline
/// never builds tests.
fn compiled_packages(
    resolve: &Resolve,
    task: &BuildTaskPayload,
) -> stow_types::error::Result<BTreeSet<PackageId>> {
    let root = resolve.root.clone().ok_or_else(|| {
        stow_types::stow_error!(
            "cargo metadata returned no root package for {} {}",
            task.crate_name,
            task.version
        )
    })?;
    let nodes = resolve
        .nodes
        .iter()
        .map(|node| (&node.id, node))
        .collect::<BTreeMap<_, _>>();
    let mut compiled = BTreeSet::new();
    let mut frontier = vec![root];
    while let Some(id) = frontier.pop() {
        if !compiled.insert(id.clone()) {
            continue;
        }
        let node = nodes.get(&id).ok_or_else(|| {
            stow_types::stow_error!("resolve graph references {id} without a node for it")
        })?;
        for dep in &node.deps {
            let compiled_edge = dep
                .dep_kinds
                .iter()
                .any(|kind| kind.kind != DependencyKind::Development);
            if compiled_edge {
                frontier.push(dep.pkg.clone());
            }
        }
    }
    Ok(compiled)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use cargo_metadata::Resolve;
    use stow_types::api::BuildTaskPayload;
    use stow_types::identity::{
        CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
    };

    use super::compiled_packages;

    fn task() -> BuildTaskPayload {
        BuildTaskPayload {
            task_id: "task".to_owned(),
            crate_name: CrateName::parse("demo").unwrap(),
            version: CrateVersion::new(semver::Version::new(1, 0, 0)),
            features_json: FeaturesJson::default(),
            target: TargetTriple::parse("x86_64-unknown-linux-gnu").unwrap(),
            rustc_version: WireRustcVersion::parse("1.91.1").unwrap(),
            preserve_lockfile: false,
        }
    }

    #[test]
    fn dev_edges_are_never_compiled_but_build_edges_of_dependencies_are() {
        let resolve: Resolve =
            serde_json::from_str(include_str!("fixtures/resolve_with_dev_edges.json")).unwrap();
        let compiled = compiled_packages(&resolve, &task()).unwrap();
        let names = compiled
            .iter()
            .map(|id| {
                let (_, rest) = id.repr.split_once('#').unwrap();
                rest.split_once('@').unwrap().0.to_owned()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names,
            BTreeSet::from(["demo".to_owned(), "itoa".to_owned(), "cc".to_owned()])
        );
    }

    #[test]
    fn resolve_without_root_is_rejected() {
        let mut resolve: Resolve =
            serde_json::from_str(include_str!("fixtures/resolve_with_dev_edges.json")).unwrap();
        resolve.root = None;
        let error = compiled_packages(&resolve, &task()).unwrap_err();
        assert!(error.to_string().contains("no root package"), "{error}");
    }
}
