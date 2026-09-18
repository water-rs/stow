//! The set of crates a task is allowed to publish artifacts for.
//!
//! The build job runs third-party build scripts and proc-macros, so nothing
//! it hands over can be trusted to describe which crates it compiled. The
//! publisher resolves the task crate's dependency graph itself, from a fresh
//! crates.io download it alone touched, with `cargo tree` and
//! `cargo metadata` — which read manifests and the index but never execute
//! crate code — and refuses any planned artifact whose crate is not in that
//! graph.
//!
//! The graph is the set of crates `cargo build` of the task crate compiles on
//! the task's platform: normal and build dependencies reachable from the task
//! crate under the task's feature set, filtered to the task target. That set
//! comes from `cargo tree`, which runs cargo's feature resolver and so drops
//! an optional dependency that only a weak feature edge (`memchr?/std`)
//! names; `cargo metadata`'s resolve graph keeps such a crate even though
//! `cargo build` never compiles it, and is used here only for the package
//! descriptions (library targets). Dev-dependencies and dependencies of other
//! platforms are never compiled by the trusted pipeline, so an artifact
//! claiming one of them is a fabrication and is rejected.

use std::collections::BTreeSet;

use async_process::Command;
use cargo_metadata::Metadata;
use std::path::Path;
use stow_types::api::BuildTaskPayload;
use stow_types::error::Context;
use tempfile::TempDir;

use crate::dep_scan;
use crate::task::{self, CargoFeatureArgs};

/// `(crate name, version)` pairs the task may publish, plus the subset
/// whose library target the trusted pipeline compiles — the plan must carry
/// a build-phase artifact for each of those, not merely stay inside the
/// closure.
#[derive(Debug)]
pub struct DependencyClosure {
    packages: BTreeSet<(String, semver::Version)>,
    lib_packages: BTreeSet<(String, semver::Version)>,
}

impl DependencyClosure {
    #[must_use]
    pub fn contains(&self, crate_name: &str, version: &semver::Version) -> bool {
        self.packages
            .contains(&(crate_name.to_owned(), version.clone()))
    }

    /// `(crate name, version)` pairs whose library target `cargo build`
    /// compiles — each one must appear in the plan.
    #[must_use]
    pub const fn lib_packages(&self) -> &BTreeSet<(String, semver::Version)> {
        &self.lib_packages
    }

    #[must_use]
    pub fn package_count(&self) -> usize {
        self.packages.len()
    }

    #[cfg(test)]
    pub(crate) const fn from_packages(
        packages: BTreeSet<(String, semver::Version)>,
        lib_packages: BTreeSet<(String, semver::Version)>,
    ) -> Self {
        Self {
            packages,
            lib_packages,
        }
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

    let compiled = compiled_packages(task, &manifest_path).await?;
    let metadata = package_metadata(task, &manifest_path).await?;
    let task_features = dep_scan::task_feature_set(task);
    let mut packages = BTreeSet::new();
    let mut lib_packages = BTreeSet::new();
    for package in metadata.packages {
        let key = (package.name.clone().into_inner(), package.version.clone());
        if !compiled.contains(&key) {
            continue;
        }
        if dep_scan::package_has_library_target(&package, &task_features) {
            lib_packages.insert(key.clone());
        }
        packages.insert(key);
    }
    if let Some(missing) = compiled.difference(&packages).next() {
        return Err(stow_types::stow_error!(
            "cargo tree lists {} {} in the closure of {} {} but cargo metadata describes no such package",
            missing.0,
            missing.1,
            task.crate_name,
            task.version
        ));
    }
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
    Ok(DependencyClosure {
        packages,
        lib_packages,
    })
}

/// A cargo subcommand pointed at the task's manifest with the task's
/// toolchain, feature set and lockfile policy.
fn cargo_for_task(task: &BuildTaskPayload, manifest_path: &Path, subcommand: &str) -> Command {
    let mut command = Command::new("cargo");
    command
        .arg(subcommand)
        .arg("--manifest-path")
        .arg(manifest_path)
        .env("RUSTUP_TOOLCHAIN", task.rustc_version.as_str());
    if task.preserve_lockfile {
        command.arg("--locked");
    }
    CargoFeatureArgs::from_task(task).apply(&mut command);
    command
}

async fn run_cargo_for_task(
    mut command: Command,
    task: &BuildTaskPayload,
    what: &str,
) -> stow_types::error::Result<Vec<u8>> {
    let output = command
        .output()
        .await
        .wrap_err_with(|| format!("run cargo {what} for closure resolution"))?;
    if !output.status.success() {
        return Err(stow_types::stow_error!(
            "cargo {what} failed while resolving the closure of {} {}: {}",
            task.crate_name,
            task.version,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(output.stdout)
}

/// Packages `cargo build` of the task crate compiles, from `cargo tree`:
/// everything reachable from the root over normal and build edges under the
/// task's feature set, on the task's platform. Development edges are never
/// followed, not even from the root, because the trusted pipeline never
/// builds tests.
async fn compiled_packages(
    task: &BuildTaskPayload,
    manifest_path: &Path,
) -> stow_types::error::Result<BTreeSet<(String, semver::Version)>> {
    let mut command = cargo_for_task(task, manifest_path, "tree");
    command
        .arg("--edges")
        .arg("normal,build")
        .arg("--target")
        .arg(task.target.as_str())
        .arg("--prefix")
        .arg("none")
        .arg("--format")
        .arg("{p}");
    let stdout = run_cargo_for_task(command, task, "tree").await?;
    let stdout = String::from_utf8(stdout).wrap_err("cargo tree output is not UTF-8")?;
    parse_cargo_tree(&stdout)
}

/// Package descriptions for the crates in the resolve graph, from
/// `cargo metadata`; only the `packages` list is used.
async fn package_metadata(
    task: &BuildTaskPayload,
    manifest_path: &Path,
) -> stow_types::error::Result<Metadata> {
    let mut command = cargo_for_task(task, manifest_path, "metadata");
    command
        .arg("--format-version")
        .arg("1")
        .arg("--filter-platform")
        .arg(task.target.as_str());
    let stdout = run_cargo_for_task(command, task, "metadata").await?;
    serde_json::from_slice(&stdout).wrap_err("parse cargo metadata output")
}

/// Parse `cargo tree --prefix none --format {p}` output: one package per
/// line as `name vX.Y.Z`, optionally followed by the source in parentheses
/// and, for a package already printed above, by `(*)`.
fn parse_cargo_tree(
    stdout: &str,
) -> stow_types::error::Result<BTreeSet<(String, semver::Version)>> {
    let mut packages = BTreeSet::new();
    for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
        let mut words = line.split_whitespace();
        let (Some(name), Some(version)) = (words.next(), words.next()) else {
            return Err(stow_types::stow_error!(
                "cargo tree line has no package and version: {line:?}"
            ));
        };
        let version = version.strip_prefix('v').ok_or_else(|| {
            stow_types::stow_error!("cargo tree line has no `v`-prefixed version: {line:?}")
        })?;
        let version = semver::Version::parse(version)
            .wrap_err_with(|| format!("parse version in cargo tree line {line:?}"))?;
        packages.insert((name.to_owned(), version));
    }
    if packages.is_empty() {
        return Err(stow_types::stow_error!("cargo tree listed no packages"));
    }
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::parse_cargo_tree;

    #[test]
    fn cargo_tree_lines_parse_to_name_and_version() {
        let packages =
            parse_cargo_tree(include_str!("fixtures/cargo_tree_prefix_none.txt")).unwrap();
        let expected = [
            ("annotate-snippets", "0.12.16"),
            ("anstyle", "1.0.14"),
            ("unicode-width", "0.2.2"),
            ("proc-macro2", "1.0.107"),
            ("unicode-ident", "1.0.26"),
        ]
        .into_iter()
        .map(|(name, version)| (name.to_owned(), semver::Version::parse(version).unwrap()))
        .collect::<BTreeSet<_>>();
        assert_eq!(packages, expected);
    }

    #[test]
    fn a_line_without_a_version_is_rejected() {
        let error = parse_cargo_tree("annotate-snippets\n").unwrap_err();
        assert!(
            error.to_string().contains("no package and version"),
            "{error}"
        );
    }

    #[test]
    fn empty_output_is_rejected() {
        let error = parse_cargo_tree("\n").unwrap_err();
        assert!(error.to_string().contains("no packages"), "{error}");
    }
}
