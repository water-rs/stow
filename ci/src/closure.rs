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
//! Resolution happens in the generated wrapper package the build job
//! compiled in, not merely with its toolchain and features: the task crate
//! resolves as the wrapper's `=<version>` registry dependency. Resolving it
//! as the root package would unify its dev-dependency feature requests into
//! the normal graph — `digest`'s `blobby` behind the `dev` feature `sha2`
//! asks for — and `cargo tree` would then list a package the build, which
//! compiles the crate as somebody else's dependency, never compiles.

use std::collections::BTreeSet;
use std::path::Path;

use async_process::Command;
use cargo_metadata::{DependencyKind, Metadata, PackageId, TargetKind};
use stow_types::api::BuildTaskPayload;
use stow_types::error::Context;
use tempfile::TempDir;

use crate::dep_scan;
use crate::task;

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
    // The task resolves as a dependency of the generated wrapper package,
    // exactly as the build job compiled it — the wrapper decides which
    // packages cargo resolves, not merely where they sit on disk.
    let manifest_path = task::create_resolution_workspace(task, root.path()).await?;

    let compiled = compiled_packages(task, &manifest_path).await?;
    let metadata = package_metadata(task, &manifest_path).await?;
    let closure = build_closure(task, &compiled, &metadata)?;
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
    metadata: &Metadata,
) -> stow_types::error::Result<DependencyClosure> {
    let packages = &metadata.packages;
    let task_features = dep_scan::task_feature_set(task);
    let built = packages_cargo_builds(metadata);
    let mut described = BTreeSet::new();
    let mut publishable = BTreeSet::new();
    let mut lib_packages = BTreeSet::new();
    for package in packages {
        let key = (package.name.clone().into_inner(), package.version.clone());
        if !compiled.contains(&key) {
            continue;
        }
        described.insert(key.clone());
        if dep_scan::package_has_library_target(package, &task_features)
            && built.contains(&package.id)
        {
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

/// The packages `cargo build` actually issues a rustc invocation for,
/// walked from the root of `cargo metadata`'s resolve graph.
///
/// `cargo tree --edges normal,build` is the feature-accurate answer to
/// *which* packages are in the graph, but it is not the answer to which
/// ones get compiled: cargo resolves a package's build dependencies into
/// the lockfile whether or not that package has a build script, and
/// compiles them only when it does. `derive_more-impl 2.1.1` publishes
/// `build = false` alongside `[build-dependencies.rustc_version]`, so
/// `cargo tree` lists `rustc_version` and `semver` while cargo never
/// compiles either — and requiring an artifact for them rejected the plan
/// of every task whose graph contained such a package.
///
/// So a build edge is followed only out of a package that has a
/// `custom-build` target, and a development edge is never followed, which
/// is the same set of edges `--edges normal,build` selects. The result
/// over-reports on the feature dimension exactly as the resolve graph
/// does; intersecting it with the `cargo tree` set removes that, and
/// neither source alone is the compiled set.
fn packages_cargo_builds(metadata: &Metadata) -> BTreeSet<PackageId> {
    let Some(resolve) = metadata.resolve.as_ref() else {
        // No resolve graph means nothing can be pruned; every package the
        // tree named stays required, which is the behaviour that predates
        // this walk.
        return metadata.packages.iter().map(|p| p.id.clone()).collect();
    };
    let Some(root) = resolve.root.as_ref() else {
        return metadata.packages.iter().map(|p| p.id.clone()).collect();
    };
    let nodes: std::collections::HashMap<&PackageId, &cargo_metadata::Node> =
        resolve.nodes.iter().map(|node| (&node.id, node)).collect();
    let has_build_script: std::collections::HashSet<&PackageId> = metadata
        .packages
        .iter()
        .filter(|package| {
            package
                .targets
                .iter()
                .any(|target| target.kind.contains(&TargetKind::CustomBuild))
        })
        .map(|package| &package.id)
        .collect();

    let mut built = BTreeSet::new();
    let mut queue = vec![root];
    while let Some(id) = queue.pop() {
        if !built.insert(id.clone()) {
            continue;
        }
        let Some(node) = nodes.get(id) else {
            continue;
        };
        let runs_a_build_script = has_build_script.contains(id);
        for dep in &node.deps {
            let followed = dep.dep_kinds.iter().any(|kind| match kind.kind {
                DependencyKind::Normal => true,
                DependencyKind::Build => runs_a_build_script,
                _ => false,
            });
            // An edge cargo reported without any kind at all predates the
            // `dep_kinds` field; treat it as normal rather than drop it.
            if followed || dep.dep_kinds.is_empty() {
                queue.push(&dep.pkg);
            }
        }
    }
    built
}

/// A cargo subcommand pointed at the task's manifest with the task's
/// toolchain — and nothing else the payload carries.
///
/// The resolution never takes `--locked`: the seeded wrapper lockfile is
/// not one cargo can be held to, because it carries the bundled lock's
/// entries verbatim — dev-dependency packages the wrapper graph cannot
/// reach included — and cargo must prune them, which `--locked` forbids
/// (`cannot update the lock file … because --locked was passed`). The
/// seeded pins still govern the resolution without it, which is the whole
/// reason they are seeded. Feature flags never reach the command line
/// either: the wrapper's dependency declaration already encodes the
/// selection, and the generated package declares none for them to mean.
fn cargo_for_task(task: &BuildTaskPayload, manifest_path: &Path, subcommand: &str) -> Command {
    let mut command = Command::new("cargo");
    command
        .arg(subcommand)
        .arg("--manifest-path")
        .arg(manifest_path)
        .env("RUSTUP_TOOLCHAIN", task.rustc_version.as_str());
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
/// followed, not even from the root: the publishable set is what `check` and
/// `build` compile.
async fn compiled_packages(
    task: &BuildTaskPayload,
    manifest_path: &Path,
) -> stow_types::error::Result<BTreeSet<(String, semver::Version)>> {
    let mut command = cargo_for_task(task, manifest_path, "tree");
    command.arg("--edges").arg("normal,build");
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
    parse_cargo_tree(without_wrapper_root(&stdout))
}

/// The tree without its root line — that root is always the generated
/// wrapper package.
///
/// The wrapper is the publisher's own scaffolding and belongs in no
/// closure, but it is only ever the root: dropping every line that carries
/// its name would silently remove a registry dependency that happened to be
/// called the same thing, and `build_closure` would then fail the publish
/// over a package the tree really did list.
fn without_wrapper_root(stdout: &str) -> &str {
    stdout.split_once('\n').map_or("", |(_root, rest)| rest)
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
) -> stow_types::error::Result<Metadata> {
    let mut command = cargo_for_task(task, manifest_path, "metadata");
    command.arg("--format-version").arg("1");
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
    use std::path::Path;

    use stow_types::api::BuildTaskPayload;
    use stow_types::identity::{
        CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
    };

    use super::{build_closure, cargo_for_task, parse_cargo_tree};

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

    fn package_id(name: &str, version: &str) -> String {
        format!("registry+https://github.com/rust-lang/crates.io-index#{name}@{version}")
    }

    /// A `cargo metadata` package description with one `lib` target and a
    /// build script, so a build edge leaving it is followed.
    fn package_with_build_script(name: &str, version: &str) -> cargo_metadata::Package {
        let mut package = package(name, version);
        let build_target: cargo_metadata::Target = serde_json::from_value(serde_json::json!({
            "kind": ["custom-build"],
            "crate_types": ["bin"],
            "name": "build-script-build",
            "src_path": format!("/registry/{name}-{version}/build.rs"),
            "edition": "2021",
        }))
        .expect("deserialize build script target");
        package.targets.push(build_target);
        package
    }

    /// `cargo metadata` output for `packages`, with a resolve graph built
    /// from `edges` — `(from, to, kind)` where kind is `"normal"` or
    /// `"build"` — rooted at `demo 1.0.0`.
    fn metadata_with_edges(
        packages: &[cargo_metadata::Package],
        edges: &[(&str, &str, &str)],
    ) -> cargo_metadata::Metadata {
        let nodes: Vec<serde_json::Value> = packages
            .iter()
            .map(|package| {
                let id = package.id.repr.clone();
                let deps: Vec<serde_json::Value> = edges
                    .iter()
                    .filter(|(from, _, _)| id == **from)
                    .map(|(_, to, kind)| {
                        serde_json::json!({
                            "name": to.split('@').next().unwrap_or(to),
                            "pkg": to,
                            "dep_kinds": [{ "kind": *kind }],
                        })
                    })
                    .collect();
                serde_json::json!({
                    "id": id,
                    "deps": deps,
                    "dependencies": [],
                    "features": [],
                })
            })
            .collect();
        serde_json::from_value(serde_json::json!({
            "packages": packages,
            "workspace_members": [package_id("demo", "1.0.0")],
            "workspace_root": "/workspace",
            "target_directory": "/workspace/target",
            "version": 1,
            "resolve": {
                "nodes": nodes,
                "root": package_id("demo", "1.0.0"),
            },
        }))
        .expect("deserialize test metadata")
    }

    /// Every package reachable from the root over normal edges — the shape
    /// the closure tests assumed before build edges were modelled.
    fn metadata(packages: &[cargo_metadata::Package]) -> cargo_metadata::Metadata {
        let root = package_id("demo", "1.0.0");
        let edges: Vec<(String, String, String)> = packages
            .iter()
            .filter(|package| package.id.repr != root)
            .map(|package| (root.clone(), package.id.repr.clone(), "normal".to_owned()))
            .collect();
        let borrowed: Vec<(&str, &str, &str)> = edges
            .iter()
            .map(|(from, to, kind)| (from.as_str(), to.as_str(), kind.as_str()))
            .collect();
        metadata_with_edges(packages, &borrowed)
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
            &metadata(&[
                package("demo", "1.0.0"),
                package("shared", "2.0.0"),
                package("winonly", "3.1.0"),
            ]),
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
            &metadata(&[
                package("demo", "1.0.0"),
                package("shared", "2.0.0"),
                package("optdep", "2.8.3"),
            ]),
        )
        .unwrap();
        let optdep = ("optdep".to_owned(), semver::Version::new(2, 8, 3));
        assert!(!closure.contains("optdep", &optdep.1));
        assert!(!closure.lib_packages().contains(&optdep));
    }

    /// `derive_more-impl 2.1.1` publishes `build = false` next to
    /// `[build-dependencies.rustc_version]`. Cargo resolves that edge into
    /// the lockfile, so `cargo tree --edges normal,build` lists
    /// `rustc_version`, but with no build script cargo never compiles it —
    /// and demanding an artifact for it rejected the plan of every task
    /// whose graph held such a package.
    #[test]
    fn a_build_dependency_of_a_package_without_a_build_script_is_not_demanded() {
        let packages = [
            package("demo", "1.0.0"),
            package("helper", "2.0.0"),
            package("rustc_version", "0.4.1"),
        ];
        let closure = build_closure(
            &task(),
            &pairs(&[
                ("demo", "1.0.0"),
                ("helper", "2.0.0"),
                ("rustc_version", "0.4.1"),
            ]),
            &metadata_with_edges(
                &packages,
                &[
                    (
                        &package_id("demo", "1.0.0"),
                        &package_id("helper", "2.0.0"),
                        "normal",
                    ),
                    (
                        &package_id("helper", "2.0.0"),
                        &package_id("rustc_version", "0.4.1"),
                        "build",
                    ),
                ],
            ),
        )
        .unwrap();

        let uncompiled = ("rustc_version".to_owned(), semver::Version::new(0, 4, 1));
        assert!(
            !closure.lib_packages().contains(&uncompiled),
            "a build dependency of a package with no build script is never compiled"
        );
        // Containment is a separate property and is not tightened here: the
        // package is in the task's graph, so an artifact naming it is not a
        // fabrication.
        assert!(closure.contains("rustc_version", &uncompiled.1));
    }

    /// The same edge out of a package that does have a build script: cargo
    /// compiles the dependency, so the plan must carry it.
    #[test]
    fn a_build_dependency_of_a_package_with_a_build_script_is_demanded() {
        let packages = [
            package("demo", "1.0.0"),
            package_with_build_script("helper", "2.0.0"),
            package("rustc_version", "0.4.1"),
        ];
        let closure = build_closure(
            &task(),
            &pairs(&[
                ("demo", "1.0.0"),
                ("helper", "2.0.0"),
                ("rustc_version", "0.4.1"),
            ]),
            &metadata_with_edges(
                &packages,
                &[
                    (
                        &package_id("demo", "1.0.0"),
                        &package_id("helper", "2.0.0"),
                        "normal",
                    ),
                    (
                        &package_id("helper", "2.0.0"),
                        &package_id("rustc_version", "0.4.1"),
                        "build",
                    ),
                ],
            ),
        )
        .unwrap();

        assert!(
            closure
                .lib_packages()
                .contains(&("rustc_version".to_owned(), semver::Version::new(0, 4, 1))),
            "a build dependency of a package that runs a build script is compiled"
        );
    }

    #[test]
    fn a_compiled_library_package_lands_in_lib_packages() {
        // Every library package `cargo tree` lists must end up demanded —
        // this set is what makes a plan that drops a compiled crate fail
        // validation, the property the closure exists to enforce.
        let closure = build_closure(
            &task(),
            &pairs(&[("demo", "1.0.0"), ("helper", "2.0.0")]),
            &metadata(&[package("demo", "1.0.0"), package("helper", "2.0.0")]),
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
            &metadata(&[package("demo", "1.0.0")]),
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

    /// The wrapper package roots every tree a task resolves in. It is the
    /// publisher's own scaffolding: counting it would put a package no
    /// registry ever served into the closure the plan is checked against.
    #[test]
    fn the_generated_wrapper_package_is_not_in_the_closure() {
        let tree = "stow-ci-wrapper v0.0.0 (/tmp/closure/wrapper)\nsha2 v0.10.8\ncfg-if v1.0.5\n";
        let packages = parse_cargo_tree(super::without_wrapper_root(tree)).unwrap();
        let expected = [("sha2", "0.10.8"), ("cfg-if", "1.0.5")]
            .into_iter()
            .map(|(name, version)| (name.to_owned(), semver::Version::parse(version).unwrap()))
            .collect::<BTreeSet<_>>();
        assert_eq!(packages, expected);
    }

    /// Only the root is scaffolding. A dependency that happens to carry
    /// the wrapper's name is a package the tree really lists, and
    /// dropping it would fail the publish over a crate the build compiled.
    #[test]
    fn a_dependency_sharing_the_wrapper_name_stays_in_the_closure() {
        let tree = "stow-ci-wrapper v0.0.0 (/tmp/closure/wrapper)\nstow-ci-wrapper v2.1.0\n";
        let packages = parse_cargo_tree(super::without_wrapper_root(tree)).unwrap();
        let expected = BTreeSet::from([(
            "stow-ci-wrapper".to_owned(),
            semver::Version::parse("2.1.0").unwrap(),
        )]);
        assert_eq!(packages, expected);
    }

    /// The seeded lockfile carries the bundled lock's unreachable
    /// dev-dependency entries and cargo must prune them, so the resolution
    /// never takes `--locked` — whatever `preserve_lockfile` says. The
    /// build job draws the same line.
    #[test]
    fn the_resolution_never_locks_the_seeded_lockfile() {
        let manifest_path = Path::new("/tmp/closure/wrapper/Cargo.toml");
        for preserve_lockfile in [true, false] {
            let task = BuildTaskPayload {
                preserve_lockfile,
                ..task()
            };
            let args = cargo_for_task(&task, manifest_path, "tree")
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert!(
                !args.iter().any(|arg| arg == "--locked"),
                "preserve_lockfile={preserve_lockfile}: {args:?}"
            );
        }
    }

    /// The wrapper's dependency declaration already encodes the task's
    /// feature selection and the generated package declares no features,
    /// so the flags never reach the cargo command line.
    #[test]
    fn the_resolution_never_carries_the_task_feature_flags() {
        let mut task = task();
        task.features_json =
            FeaturesJson::canonicalize(vec!["serde".to_owned()]).expect("features");
        let manifest_path = Path::new("/tmp/closure/wrapper/Cargo.toml");
        for subcommand in ["tree", "metadata"] {
            let args = cargo_for_task(&task, manifest_path, subcommand)
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                args,
                [
                    subcommand,
                    "--manifest-path",
                    manifest_path.to_str().unwrap()
                ],
                "{args:?}"
            );
        }
    }
}
