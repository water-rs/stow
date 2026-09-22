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
//! crate under the task's feature set, with the same target split the phases
//! used — the task target for the library graph, the host for
//! build-dependency and proc-macro subgraphs. That set comes from
//! `cargo tree`, which runs cargo's feature resolver and so drops an
//! optional dependency that only a weak feature edge (`memchr?/std`) names;
//! `cargo metadata`'s resolve graph keeps such a crate even though
//! `cargo build` never compiles it, and is used here only for the package
//! descriptions (library targets). The publishable set is defined by the
//! `check` and `build` phases, so dev-dependencies and dependencies of other
//! platforms are outside it and an artifact claiming one is a fabrication.
//! (`STOW_BUILD_CARGO_SUBCOMMAND=test` compiles dev-dependencies as well;
//! their artifacts are not publishable and the closure rejects them.)
//!
//! Resolution happens in the workspace shape the build job compiled in, not
//! merely with its toolchain and features: a library crate is resolved as a
//! dependency of the same generated consumer package, a binary-only crate as
//! the root package. Cargo unifies a root package's dev-dependency feature
//! requests into the normal graph, so resolving a library crate as the root
//! activates optional dependencies — `digest`'s `blobby` behind the `dev`
//! feature `sha2` asks for — that the build, which compiles the crate as
//! somebody else's dependency, never compiles.

use std::collections::BTreeSet;
use std::path::Path;

use async_process::Command;
use cargo_metadata::{Metadata, Package};
use stow_types::api::BuildTaskPayload;
use stow_types::error::Context;
use tempfile::TempDir;

use crate::dep_scan;
use crate::task::{self, CargoFeatureArgs, WorkspaceKind};

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
    let (manifest_path, kind) = if let Some(source) = &task.project_source {
        // The publisher clones the project itself: the closure it checks
        // against must be resolved from the same pinned checkout the build
        // job compiled, never from what the build job claims it used.
        (
            task::clone_project_source(source, root.path()).await?,
            WorkspaceKind::Source,
        )
    } else {
        // A registry task resolves in the workspace shape the build job
        // compiled it in — a library crate as a dependency of the generated
        // consumer package — because the shape decides which packages cargo
        // resolves, not merely where they sit on disk.
        task::create_resolution_workspace(task, root.path()).await?
    };

    let compiled = compiled_packages(task, &manifest_path, kind).await?;
    let metadata = package_metadata(task, &manifest_path, kind).await?;
    let closure = build_closure(task, &compiled, &metadata.packages)?;
    tracing::info!(
        crate_name = %task.crate_name,
        version = %task.version,
        packages = closure.package_count(),
        "resolved publishable dependency closure"
    );
    Ok(closure)
}

/// Combine the packages `cargo tree` says the build compiles with the
/// package descriptions `cargo metadata` provides: every compiled package
/// joins the closure, and the ones with a library target join the subset
/// the plan must cover. `cargo metadata` describes the whole lockfile —
/// every platform, every optional dependency — so the `compiled` set is
/// the filter: a package `cargo metadata` describes that the build never
/// compiled is outside the closure, while one `cargo tree` lists that
/// `cargo metadata` does not describe means the two resolutions diverged
/// and is a hard error, never a silent drop.
fn build_closure(
    task: &BuildTaskPayload,
    compiled: &BTreeSet<(String, semver::Version)>,
    packages: &[Package],
) -> stow_types::error::Result<DependencyClosure> {
    let task_features = dep_scan::task_feature_set(task);
    let mut described = BTreeSet::new();
    let mut publishable = BTreeSet::new();
    let mut lib_packages = BTreeSet::new();
    for package in packages {
        let key = (package.name.clone().into_inner(), package.version.clone());
        if !compiled.contains(&key) {
            continue;
        }
        described.insert(key.clone());
        // A project-source checkout's own path and git members compile —
        // the divergence check above accounts for them — but their bytes
        // are not publishable: shipping a checkout's artifacts under a
        // crates.io identity would poison the cache. Registry tasks never
        // reach this branch because their compiled set is registry-only
        // already.
        let registry = package
            .source
            .as_ref()
            .is_some_and(|source| source.to_string().starts_with("registry+"));
        if task.project_source.is_some() && !registry {
            continue;
        }
        if dep_scan::package_has_library_target(package, &task_features) {
            lib_packages.insert(key.clone());
        }
        publishable.insert(key);
    }
    if let Some(missing) = compiled.difference(&described).next() {
        return Err(stow_types::stow_error!(
            "cargo tree lists {} {} in the closure of {} {} but cargo metadata describes no such package",
            missing.0,
            missing.1,
            task.crate_name,
            task.version
        ));
    }
    if !described.contains(&(
        task.crate_name.as_str().to_owned(),
        task.version.as_semver().clone(),
    )) {
        return Err(stow_types::stow_error!(
            "resolved closure does not contain the task crate {} {}",
            task.crate_name,
            task.version
        ));
    }
    Ok(DependencyClosure {
        packages: publishable,
        lib_packages,
    })
}

/// A cargo subcommand pointed at the task's manifest with the task's
/// toolchain, feature set and lockfile policy.
fn cargo_for_task(
    task: &BuildTaskPayload,
    manifest_path: &Path,
    kind: WorkspaceKind,
    subcommand: &str,
) -> Command {
    let mut command = Command::new("cargo");
    command
        .arg(subcommand)
        .arg("--manifest-path")
        .arg(manifest_path)
        .env("RUSTUP_TOOLCHAIN", task.rustc_version.as_str());
    if task.preserve_lockfile {
        command.arg("--locked");
    }
    command.args(feature_args(task, kind));
    command
}

/// The feature flags a cargo invocation carries in this workspace shape.
///
/// They name features of the task crate's own manifest. The generated
/// consumer package declares none of them and already encoded the selection
/// in its dependency declaration, so passing them there would either fail or
/// mean something else — which is why the build job withholds them too.
fn feature_args(task: &BuildTaskPayload, kind: WorkspaceKind) -> Vec<String> {
    if kind == WorkspaceKind::Consumer {
        Vec::new()
    } else {
        CargoFeatureArgs::from_task(task).args()
    }
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
/// followed, not even from the root: the publishable set is what `check` and
/// `build` compile.
async fn compiled_packages(
    task: &BuildTaskPayload,
    manifest_path: &Path,
    kind: WorkspaceKind,
) -> stow_types::error::Result<BTreeSet<(String, semver::Version)>> {
    let mut command = cargo_for_task(task, manifest_path, kind, "tree");
    command.arg("--edges").arg("normal,build");
    // A project-source build compiles the checkout's whole workspace; the
    // tree has to cover every member's cone or the closure disagrees with
    // the compilation it validates.
    if task.project_source.is_some() {
        command.arg("--workspace");
    }
    // Mirror the phases: `--target` only for a cross-compile. A host build
    // resolves one unsplit unit graph — host cfg everywhere — and the tree
    // has to resolve that same graph or the closure disagrees with the
    // compilation it validates.
    if !task::target_is_host(task.target.as_str()).await? {
        command.arg("--target").arg(task.target.as_str());
    }
    command
        .arg("--prefix")
        .arg("none")
        .arg("--format")
        .arg("{p}");
    let stdout = run_cargo_for_task(command, task, "tree").await?;
    let stdout = String::from_utf8(stdout).wrap_err("cargo tree output is not UTF-8")?;
    parse_cargo_tree(&stdout)
}

/// Package descriptions for every crate in the lockfile, from
/// `cargo metadata`; only the `packages` list is used. No
/// `--filter-platform`: it evaluates the whole graph — build-dependency
/// and proc-macro subgraphs included — against the target triple, but
/// cargo compiles those subgraphs for the host, so on a cross-compile it
/// would drop packages the build did compile and trip the tree/metadata
/// consistency check in `build_closure`. The `compiled` set already
/// carries the correct platform split.
async fn package_metadata(
    task: &BuildTaskPayload,
    manifest_path: &Path,
    kind: WorkspaceKind,
) -> stow_types::error::Result<Metadata> {
    let mut command = cargo_for_task(task, manifest_path, kind, "metadata");
    command.arg("--format-version").arg("1");
    let stdout = run_cargo_for_task(command, task, "metadata").await?;
    serde_json::from_slice(&stdout).wrap_err("parse cargo metadata output")
}

/// Parse `cargo tree --prefix none --format {p}` output: one package per
/// line as `name vX.Y.Z`, optionally followed by the source in parentheses
/// and, for a package already printed above, by `(*)`.
///
/// The generated consumer package is dropped: cargo prints it as the root
/// of the tree, and it is the publisher's own scaffolding, no more part of
/// the task's closure here than the build job's copy of it was part of the
/// plan.
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
        if name == task::CONSUMER_PACKAGE_NAME {
            continue;
        }
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

    use stow_types::api::BuildTaskPayload;
    use stow_types::identity::{
        CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
    };

    use super::{build_closure, feature_args, parse_cargo_tree};
    use crate::task::WorkspaceKind;

    fn task() -> BuildTaskPayload {
        BuildTaskPayload {
            task_id: "task".to_owned(),
            attempt: 1,
            crate_name: CrateName::parse("demo").unwrap(),
            version: CrateVersion::new(semver::Version::new(1, 0, 0)),
            features_json: FeaturesJson::default(),
            target: TargetTriple::parse("x86_64-unknown-linux-gnu").unwrap(),
            rustc_version: WireRustcVersion::parse("1.91.1").unwrap(),
            preserve_lockfile: false,
            project_source: None,
        }
    }

    /// A `cargo metadata` package description with one `lib` target — the
    /// shape every compiled library crate takes, whether it reached the
    /// lockfile through a `cfg`-gated or a feature-gated edge.
    fn package(name: &str, version: &str) -> cargo_metadata::Package {
        serde_json::from_value(serde_json::json!({
            "name": name,
            "version": version,
            "id": format!("registry+https://github.com/rust-lang/crates.io-index#{name}@{version}"),
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "edition": "2021",
            "authors": [],
            "dependencies": [],
            "features": {},
            "manifest_path": format!("/registry/{name}-{version}/Cargo.toml"),
            "targets": [{
                "kind": ["lib"],
                "crate_types": ["lib"],
                "name": name,
                "src_path": format!("/registry/{name}-{version}/src/lib.rs"),
                "edition": "2021",
            }],
        }))
        .expect("deserialize test package")
    }

    fn pairs(packages: &[(&str, &str)]) -> BTreeSet<(String, semver::Version)> {
        packages
            .iter()
            .map(|(name, version)| ((*name).to_owned(), semver::Version::parse(version).unwrap()))
            .collect()
    }

    #[test]
    fn a_cfg_gated_dependency_the_target_does_not_activate_is_not_demanded() {
        // `cargo metadata` describes the whole lockfile, so the windows-only
        // `winonly` is in its package list, but `cargo tree` filtered it out
        // for this target: it is not compiled, so the closure must neither
        // admit nor demand it.
        let closure = build_closure(
            &task(),
            &pairs(&[("demo", "1.0.0"), ("shared", "2.0.0")]),
            &[
                package("demo", "1.0.0"),
                package("shared", "2.0.0"),
                package("winonly", "3.1.0"),
            ],
        )
        .unwrap();
        let winonly = ("winonly".to_owned(), semver::Version::new(3, 1, 0));
        assert!(!closure.contains("winonly", &winonly.1));
        assert!(!closure.lib_packages().contains(&winonly));
    }

    #[test]
    fn a_feature_gated_optional_dependency_the_task_did_not_select_is_not_demanded() {
        // `optdep` sits in the lockfile behind a feature edge nothing the
        // task selected activates, so `cargo tree` does not list it; the
        // plan cannot be asked for an artifact that was never compiled.
        let closure = build_closure(
            &task(),
            &pairs(&[("demo", "1.0.0"), ("shared", "2.0.0")]),
            &[
                package("demo", "1.0.0"),
                package("shared", "2.0.0"),
                package("optdep", "2.8.3"),
            ],
        )
        .unwrap();
        let optdep = ("optdep".to_owned(), semver::Version::new(2, 8, 3));
        assert!(!closure.contains("optdep", &optdep.1));
        assert!(!closure.lib_packages().contains(&optdep));
    }

    #[test]
    fn a_compiled_library_package_lands_in_lib_packages() {
        // Every library package `cargo tree` lists must end up demanded —
        // this set is what makes a plan that drops a compiled crate fail
        // validation, the property the closure exists to enforce.
        let closure = build_closure(
            &task(),
            &pairs(&[("demo", "1.0.0"), ("helper", "2.0.0")]),
            &[package("demo", "1.0.0"), package("helper", "2.0.0")],
        )
        .unwrap();
        assert!(
            closure
                .lib_packages()
                .contains(&("helper".to_owned(), semver::Version::new(2, 0, 0)))
        );
    }

    #[test]
    fn a_package_the_tree_lists_but_metadata_omits_is_an_error() {
        // The two resolutions describing different package sets means the
        // environment diverged — never a silent drop.
        let error = build_closure(
            &task(),
            &pairs(&[("demo", "1.0.0"), ("ghost", "9.9.9")]),
            &[package("demo", "1.0.0")],
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("describes no such package"),
            "{error}"
        );
    }

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

    /// The consumer package roots the tree a library task resolves in. It
    /// is the publisher's own scaffolding: counting it would put a package
    /// no registry ever served into the closure the plan is checked
    /// against.
    #[test]
    fn the_generated_consumer_package_is_not_in_the_closure() {
        let packages = parse_cargo_tree(
            "stow-ci-task-consumer v0.0.0 (/tmp/closure/consumer)\nsha2 v0.10.8\ncfg-if v1.0.5\n",
        )
        .unwrap();
        let expected = [("sha2", "0.10.8"), ("cfg-if", "1.0.5")]
            .into_iter()
            .map(|(name, version)| (name.to_owned(), semver::Version::parse(version).unwrap()))
            .collect::<BTreeSet<_>>();
        assert_eq!(packages, expected);
    }

    /// The consumer package declares none of the task crate's features, so
    /// the flags that select them belong to the shapes where the task
    /// crate is the root package and nowhere else.
    #[test]
    fn a_consumer_workspace_resolves_without_the_task_feature_flags() {
        let mut task = task();
        task.features_json =
            FeaturesJson::canonicalize(vec!["serde".to_owned()]).expect("features");

        assert_eq!(
            feature_args(&task, WorkspaceKind::RootPackage),
            vec![
                "--no-default-features".to_owned(),
                "--features".to_owned(),
                "serde".to_owned(),
            ]
        );
        assert!(feature_args(&task, WorkspaceKind::Consumer).is_empty());
    }
}
