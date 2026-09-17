//! The set of crates a task is allowed to publish artifacts for.
//!
//! The build job runs third-party build scripts and proc-macros, so nothing
//! it hands over can be trusted to describe which crates it compiled. The
//! publisher resolves the task crate's dependency graph itself, from a fresh
//! crates.io download it alone touched, with `cargo metadata` — which reads
//! manifests and the index but never executes crate code — and refuses any
//! planned artifact whose crate is not in that graph.

use std::collections::BTreeSet;

use async_process::Command;
use cargo_metadata::Metadata;
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

    let resolved_ids = resolve
        .nodes
        .iter()
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    let packages = metadata
        .packages
        .into_iter()
        .filter(|package| resolved_ids.contains(&package.id))
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
